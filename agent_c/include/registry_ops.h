/*
 * registry_ops.h — Registry enumeration and manipulation for pentesting.
 *
 * Pentest use cases:
 *   - Enumerate autoruns (persistence discovery)
 *   - Find saved credentials (autologon, WinSCP, PuTTY, RDP)
 *   - List installed software (vulnerability surface)
 *   - Check security policies (UAC, LSA, firewall rules)
 *   - Service configuration audit (unquoted paths, weak perms)
 *   - Read/write for post-exploitation configuration changes
 *
 * All operations use RegOpenKeyExW/RegQueryValueExW — no spawning
 * reg.exe or powershell.
 */
#ifndef REGISTRY_OPS_H
#define REGISTRY_OPS_H

#include <windows.h>

/* ─── Registry operation types ─── */
typedef enum _REG_OP {
    REG_OP_QUERY_VALUE    = 0,   /* Read a single value */
    REG_OP_ENUM_VALUES    = 1,   /* List all values under a key */
    REG_OP_ENUM_SUBKEYS   = 2,   /* List all subkeys */
    REG_OP_SET_VALUE      = 3,   /* Write a value */
    REG_OP_DELETE_VALUE   = 4,   /* Delete a value */
    REG_OP_DELETE_KEY     = 5,   /* Delete a subkey */
    REG_OP_KEY_EXISTS     = 6,   /* Check if key exists */
} REG_OP;

/* ─── Single registry value ─── */
typedef struct _REG_VALUE_INFO {
    wchar_t  name[256];
    DWORD    type;           /* REG_SZ, REG_DWORD, REG_BINARY, etc. */
    unsigned char *data;     /* Heap-allocated value data */
    DWORD    dataLen;
} REG_VALUE_INFO;

/* ─── Registry query result ─── */
typedef struct _REG_RESULT {
    BOOL          success;
    int           count;         /* Number of values/subkeys returned */
    REG_VALUE_INFO *values;      /* Heap-allocated array (for ENUM_VALUES) */
    wchar_t      (*subkeys)[256]; /* Heap-allocated array (for ENUM_SUBKEYS) */
    DWORD         lastError;
    char          errorMsg[256];
} REG_RESULT;

/*
 * Parse a root key string to HKEY handle.
 * Accepts: "HKLM", "HKCU", "HKU", "HKCR", "HKCC",
 *          "HKEY_LOCAL_MACHINE", etc.
 */
HKEY reg_parse_root(const wchar_t *rootStr);

/*
 * Query a single registry value.
 * rootKey: "HKLM", "HKCU", etc.
 * subKey: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
 * valueName: specific value name, or NULL/empty for default value
 */
BOOL reg_query_value(const wchar_t *rootKey, const wchar_t *subKey,
                     const wchar_t *valueName, REG_RESULT *result);

/*
 * Enumerate all values under a key.
 */
BOOL reg_enum_values(const wchar_t *rootKey, const wchar_t *subKey,
                     REG_RESULT *result);

/*
 * Enumerate all subkeys under a key.
 */
BOOL reg_enum_subkeys(const wchar_t *rootKey, const wchar_t *subKey,
                      REG_RESULT *result);

/*
 * Set a registry value.
 */
BOOL reg_set_value(const wchar_t *rootKey, const wchar_t *subKey,
                   const wchar_t *valueName, DWORD type,
                   const unsigned char *data, DWORD dataLen);

/*
 * Delete a registry value.
 */
BOOL reg_delete_value(const wchar_t *rootKey, const wchar_t *subKey,
                      const wchar_t *valueName);

/*
 * Check if a key exists.
 */
BOOL reg_key_exists(const wchar_t *rootKey, const wchar_t *subKey);

/*
 * Free a REG_RESULT structure.
 */
void reg_free_result(REG_RESULT *result);

/* ═══════════════════════════════════════════════════════════════════
 *  Pentest-oriented convenience functions
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Enumerate common autorun locations.
 * Checks: Run, RunOnce, Services, Scheduled Tasks reg keys,
 * Winlogon, Explorer shell extensions, etc.
 *
 * outBuf/outBufSize: receives tab-delimited text output
 * Returns number of autorun entries found.
 */
int reg_enum_autoruns(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Search for saved credentials in common registry locations:
 *   - Autologon (DefaultPassword in Winlogon)
 *   - PuTTY saved sessions (proxy passwords)
 *   - WinSCP sessions
 *   - VNC passwords
 *   - SNMP community strings
 *
 * outBuf: receives tab-delimited text output
 * Returns number of credential entries found.
 */
int reg_find_saved_creds(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Enumerate installed software (Uninstall registry).
 * Returns DisplayName, DisplayVersion, Publisher, InstallLocation.
 *
 * outBuf: receives tab-delimited text output
 * Returns number of software entries found.
 */
int reg_enum_installed_software(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Check security-relevant policy settings:
 *   - UAC configuration
 *   - LSA protection settings
 *   - WDigest plaintext credential caching
 *   - PowerShell execution policy
 *   - Credential Guard status
 *   - LAPS configuration
 *   - Windows Firewall status
 *
 * outBuf: receives formatted text output
 */
int reg_check_security_policies(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

#endif /* REGISTRY_OPS_H */
