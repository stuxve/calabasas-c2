/*
 * registry_ops.c — Registry operations for pentest enumeration.
 */
#include "agent.h"
#include "registry_ops.h"

/* ─── Helpers ─── */

static void _set_err(REG_RESULT *r, const char *msg) {
    if (!r) return;
    r->success = FALSE;
    r->lastError = GetLastError();
    if (msg) {
        strncpy(r->errorMsg, msg, sizeof(r->errorMsg) - 1);
        r->errorMsg[sizeof(r->errorMsg) - 1] = '\0';
    }
}

static int _append(unsigned char *buf, DWORD bufSize, DWORD *offset, const char *fmt, ...) {
    if (!buf || !offset || *offset >= bufSize) return 0;
    va_list args;
    va_start(args, fmt);
    int written = _vsnprintf((char *)buf + *offset, bufSize - *offset, fmt, args);
    va_end(args);
    if (written > 0) *offset += written;
    return written > 0 ? written : 0;
}

HKEY reg_parse_root(const wchar_t *rootStr) {
    if (!rootStr) return NULL;
    if (_wcsicmp(rootStr, L"HKLM") == 0 || _wcsicmp(rootStr, L"HKEY_LOCAL_MACHINE") == 0)
        return HKEY_LOCAL_MACHINE;
    if (_wcsicmp(rootStr, L"HKCU") == 0 || _wcsicmp(rootStr, L"HKEY_CURRENT_USER") == 0)
        return HKEY_CURRENT_USER;
    if (_wcsicmp(rootStr, L"HKU") == 0 || _wcsicmp(rootStr, L"HKEY_USERS") == 0)
        return HKEY_USERS;
    if (_wcsicmp(rootStr, L"HKCR") == 0 || _wcsicmp(rootStr, L"HKEY_CLASSES_ROOT") == 0)
        return HKEY_CLASSES_ROOT;
    if (_wcsicmp(rootStr, L"HKCC") == 0 || _wcsicmp(rootStr, L"HKEY_CURRENT_CONFIG") == 0)
        return HKEY_CURRENT_CONFIG;
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Core operations
 * ═══════════════════════════════════════════════════════════════════ */

BOOL reg_query_value(const wchar_t *rootKey, const wchar_t *subKey,
                     const wchar_t *valueName, REG_RESULT *result)
{
    if (!result) return FALSE;
    memset(result, 0, sizeof(REG_RESULT));

    HKEY hRoot = reg_parse_root(rootKey);
    if (!hRoot) { _set_err(result, "Invalid root key"); return FALSE; }

    HKEY hKey;
    LONG ret = RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS) {
        result->lastError = ret;
        _set_err(result, "RegOpenKeyExW failed");
        return FALSE;
    }

    /* Query value size first */
    DWORD type, dataLen = 0;
    ret = RegQueryValueExW(hKey, valueName, NULL, &type, NULL, &dataLen);
    if (ret != ERROR_SUCCESS && ret != ERROR_MORE_DATA) {
        RegCloseKey(hKey);
        result->lastError = ret;
        _set_err(result, "RegQueryValueExW size query failed");
        return FALSE;
    }

    /* Allocate and read */
    result->values = (REG_VALUE_INFO *)HeapAlloc(GetProcessHeap(),
                                                  HEAP_ZERO_MEMORY, sizeof(REG_VALUE_INFO));
    if (!result->values) {
        RegCloseKey(hKey);
        _set_err(result, "HeapAlloc failed");
        return FALSE;
    }

    result->values[0].data = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, dataLen + 2);
    if (!result->values[0].data) {
        HeapFree(GetProcessHeap(), 0, result->values);
        result->values = NULL;
        RegCloseKey(hKey);
        _set_err(result, "HeapAlloc for data failed");
        return FALSE;
    }

    memset(result->values[0].data, 0, dataLen + 2);
    ret = RegQueryValueExW(hKey, valueName, NULL, &type, result->values[0].data, &dataLen);
    RegCloseKey(hKey);

    if (ret != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, result->values[0].data);
        HeapFree(GetProcessHeap(), 0, result->values);
        result->values = NULL;
        result->lastError = ret;
        _set_err(result, "RegQueryValueExW read failed");
        return FALSE;
    }

    if (valueName)
        wcsncpy(result->values[0].name, valueName, 255);
    result->values[0].type = type;
    result->values[0].dataLen = dataLen;
    result->count = 1;
    result->success = TRUE;
    return TRUE;
}

BOOL reg_enum_values(const wchar_t *rootKey, const wchar_t *subKey,
                     REG_RESULT *result)
{
    if (!result) return FALSE;
    memset(result, 0, sizeof(REG_RESULT));

    HKEY hRoot = reg_parse_root(rootKey);
    if (!hRoot) { _set_err(result, "Invalid root key"); return FALSE; }

    HKEY hKey;
    LONG ret = RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS) {
        result->lastError = ret;
        _set_err(result, "RegOpenKeyExW failed");
        return FALSE;
    }

    DWORD numValues, maxValueNameLen, maxValueDataLen;
    ret = RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL,
                            &numValues, &maxValueNameLen, &maxValueDataLen,
                            NULL, NULL);
    if (ret != ERROR_SUCCESS || numValues == 0) {
        RegCloseKey(hKey);
        if (numValues == 0) { result->success = TRUE; return TRUE; }
        _set_err(result, "RegQueryInfoKeyW failed");
        return FALSE;
    }

    result->values = (REG_VALUE_INFO *)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, numValues * sizeof(REG_VALUE_INFO));
    if (!result->values) {
        RegCloseKey(hKey);
        _set_err(result, "HeapAlloc failed");
        return FALSE;
    }

    for (DWORD i = 0; i < numValues; i++) {
        wchar_t name[256] = {0};
        DWORD nameLen = 256;
        DWORD type, dataLen = 0;

        /* Get size */
        ret = RegEnumValueW(hKey, i, name, &nameLen, NULL, &type, NULL, &dataLen);
        if (ret != ERROR_SUCCESS && ret != ERROR_MORE_DATA) continue;

        wcsncpy(result->values[result->count].name, name, 255);
        result->values[result->count].type = type;

        if (dataLen > 0 && dataLen < 1048576) {  /* Cap at 1MB per value */
            result->values[result->count].data =
                (unsigned char *)HeapAlloc(GetProcessHeap(), 0, dataLen + 2);
            if (result->values[result->count].data) {
                memset(result->values[result->count].data, 0, dataLen + 2);
                nameLen = 256;
                ret = RegEnumValueW(hKey, i, name, &nameLen, NULL, &type,
                                     result->values[result->count].data, &dataLen);
                if (ret == ERROR_SUCCESS) {
                    result->values[result->count].dataLen = dataLen;
                }
            }
        }
        result->count++;
    }

    RegCloseKey(hKey);
    result->success = TRUE;
    return TRUE;
}

BOOL reg_enum_subkeys(const wchar_t *rootKey, const wchar_t *subKey,
                      REG_RESULT *result)
{
    if (!result) return FALSE;
    memset(result, 0, sizeof(REG_RESULT));

    HKEY hRoot = reg_parse_root(rootKey);
    if (!hRoot) { _set_err(result, "Invalid root key"); return FALSE; }

    HKEY hKey;
    LONG ret = RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS) {
        result->lastError = ret;
        _set_err(result, "RegOpenKeyExW failed");
        return FALSE;
    }

    DWORD numSubKeys;
    ret = RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &numSubKeys,
                            NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (ret != ERROR_SUCCESS || numSubKeys == 0) {
        RegCloseKey(hKey);
        if (numSubKeys == 0) { result->success = TRUE; return TRUE; }
        _set_err(result, "RegQueryInfoKeyW failed");
        return FALSE;
    }

    result->subkeys = (wchar_t (*)[256])HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, numSubKeys * 256 * sizeof(wchar_t));
    if (!result->subkeys) {
        RegCloseKey(hKey);
        _set_err(result, "HeapAlloc failed");
        return FALSE;
    }

    for (DWORD i = 0; i < numSubKeys; i++) {
        DWORD nameLen = 256;
        ret = RegEnumKeyExW(hKey, i, result->subkeys[result->count],
                             &nameLen, NULL, NULL, NULL, NULL);
        if (ret == ERROR_SUCCESS)
            result->count++;
    }

    RegCloseKey(hKey);
    result->success = TRUE;
    return TRUE;
}

BOOL reg_set_value(const wchar_t *rootKey, const wchar_t *subKey,
                   const wchar_t *valueName, DWORD type,
                   const unsigned char *data, DWORD dataLen)
{
    HKEY hRoot = reg_parse_root(rootKey);
    if (!hRoot) return FALSE;

    HKEY hKey;
    LONG ret = RegOpenKeyExW(hRoot, subKey, 0, KEY_SET_VALUE, &hKey);
    if (ret != ERROR_SUCCESS) {
        /* Try creating the key */
        ret = RegCreateKeyExW(hRoot, subKey, 0, NULL, 0, KEY_SET_VALUE,
                               NULL, &hKey, NULL);
        if (ret != ERROR_SUCCESS) return FALSE;
    }

    ret = RegSetValueExW(hKey, valueName, 0, type, data, dataLen);
    RegCloseKey(hKey);
    return ret == ERROR_SUCCESS;
}

BOOL reg_delete_value(const wchar_t *rootKey, const wchar_t *subKey,
                      const wchar_t *valueName)
{
    HKEY hRoot = reg_parse_root(rootKey);
    if (!hRoot) return FALSE;

    HKEY hKey;
    LONG ret = RegOpenKeyExW(hRoot, subKey, 0, KEY_SET_VALUE, &hKey);
    if (ret != ERROR_SUCCESS) return FALSE;

    ret = RegDeleteValueW(hKey, valueName);
    RegCloseKey(hKey);
    return ret == ERROR_SUCCESS;
}

BOOL reg_key_exists(const wchar_t *rootKey, const wchar_t *subKey) {
    HKEY hRoot = reg_parse_root(rootKey);
    if (!hRoot) return FALSE;

    HKEY hKey;
    LONG ret = RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

void reg_free_result(REG_RESULT *result) {
    if (!result) return;
    if (result->values) {
        for (int i = 0; i < result->count; i++) {
            if (result->values[i].data) {
                SecureZeroMemory(result->values[i].data, result->values[i].dataLen);
                HeapFree(GetProcessHeap(), 0, result->values[i].data);
            }
        }
        HeapFree(GetProcessHeap(), 0, result->values);
    }
    if (result->subkeys) {
        HeapFree(GetProcessHeap(), 0, result->subkeys);
    }
    memset(result, 0, sizeof(REG_RESULT));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Pentest convenience: helper to read a string value safely
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL _read_sz(HKEY hRoot, const wchar_t *subKey, const wchar_t *valName,
                     char *out, int outLen)
{
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;

    wchar_t wBuf[1024] = {0};
    DWORD sz = sizeof(wBuf) - 2;
    DWORD type;
    LONG ret = RegQueryValueExW(hKey, valName, NULL, &type, (LPBYTE)wBuf, &sz);
    RegCloseKey(hKey);

    if (ret != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
        return FALSE;

    WideCharToMultiByte(CP_UTF8, 0, wBuf, -1, out, outLen, NULL, NULL);
    return TRUE;
}

static BOOL _read_dword(HKEY hRoot, const wchar_t *subKey, const wchar_t *valName,
                        DWORD *out)
{
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;

    DWORD val, sz = sizeof(val), type;
    LONG ret = RegQueryValueExW(hKey, valName, NULL, &type, (LPBYTE)&val, &sz);
    RegCloseKey(hKey);

    if (ret != ERROR_SUCCESS || type != REG_DWORD) return FALSE;
    *out = val;
    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Pentest convenience: Autorun enumeration
 * ═══════════════════════════════════════════════════════════════════ */

static const wchar_t *g_autorunKeys[] = {
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    NULL
};

int reg_enum_autoruns(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "HIVE\tKEY\tVALUE\tDATA\n");

    HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const char *rootNames[] = { "HKLM", "HKCU" };

    for (int r = 0; r < 2; r++) {
        for (int k = 0; g_autorunKeys[k] != NULL; k++) {
            HKEY hKey;
            if (RegOpenKeyExW(roots[r], g_autorunKeys[k], 0, KEY_READ, &hKey) != ERROR_SUCCESS)
                continue;

            DWORD numValues;
            RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL,
                              &numValues, NULL, NULL, NULL, NULL);

            for (DWORD i = 0; i < numValues; i++) {
                wchar_t name[256] = {0};
                DWORD nameLen = 256;
                wchar_t data[1024] = {0};
                DWORD dataLen = sizeof(data) - 2;
                DWORD type;

                if (RegEnumValueW(hKey, i, name, &nameLen, NULL, &type,
                                   (LPBYTE)data, &dataLen) == ERROR_SUCCESS)
                {
                    if (type == REG_SZ || type == REG_EXPAND_SZ) {
                        char keyPath[512], valName[256], valData[1024];
                        WideCharToMultiByte(CP_UTF8, 0, g_autorunKeys[k], -1, keyPath, 512, NULL, NULL);
                        WideCharToMultiByte(CP_UTF8, 0, name, -1, valName, 256, NULL, NULL);
                        WideCharToMultiByte(CP_UTF8, 0, data, -1, valData, 1024, NULL, NULL);
                        _append(outBuf, outBufSize, &off, "%s\t%s\t%s\t%s\n",
                                rootNames[r], keyPath, valName, valData);
                        total++;
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }

    /* Also enumerate services for unusual ones */
    HKEY hSvc;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hSvc) == ERROR_SUCCESS)
    {
        DWORD numSubs;
        RegQueryInfoKeyW(hSvc, NULL, NULL, NULL, &numSubs, NULL, NULL,
                          NULL, NULL, NULL, NULL, NULL);
        for (DWORD i = 0; i < numSubs && i < 500; i++) {
            wchar_t svcName[256] = {0};
            DWORD nameLen = 256;
            if (RegEnumKeyExW(hSvc, i, svcName, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                continue;

            /* Check ImagePath for non-standard paths */
            wchar_t svcKey[512];
            _snwprintf(svcKey, 512, L"SYSTEM\\CurrentControlSet\\Services\\%s", svcName);

            char imagePath[1024] = {0};
            if (_read_sz(HKEY_LOCAL_MACHINE, svcKey, L"ImagePath", imagePath, sizeof(imagePath))) {
                /* Flag services with paths outside System32/SysWOW64 */
                if (imagePath[0] && !strstr(imagePath, "System32") &&
                    !strstr(imagePath, "system32") && !strstr(imagePath, "SysWOW64"))
                {
                    char name[256];
                    WideCharToMultiByte(CP_UTF8, 0, svcName, -1, name, 256, NULL, NULL);
                    _append(outBuf, outBufSize, &off,
                            "HKLM\tServices\\%s\tImagePath\t%s\n", name, imagePath);
                    total++;
                }
            }
        }
        RegCloseKey(hSvc);
    }

    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Pentest convenience: Saved credentials discovery
 * ═══════════════════════════════════════════════════════════════════ */

int reg_find_saved_creds(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "SOURCE\tUSER/KEY\tVALUE\n");

    /* 1. Autologon credentials */
    char defUser[256] = {0}, defPass[256] = {0}, defDomain[256] = {0};
    _read_sz(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"DefaultUserName", defUser, sizeof(defUser));
    _read_sz(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"DefaultPassword", defPass, sizeof(defPass));
    _read_sz(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"DefaultDomainName", defDomain, sizeof(defDomain));

    if (defPass[0]) {
        _append(outBuf, outBufSize, &off, "Autologon\t%s\\%s\t%s\n",
                defDomain, defUser, defPass);
        total++;
    } else if (defUser[0]) {
        _append(outBuf, outBufSize, &off, "Autologon\t%s\\%s\t(no password stored)\n",
                defDomain, defUser);
    }

    /* 2. PuTTY saved sessions */
    HKEY hPutty;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"SOFTWARE\\SimonTatham\\PuTTY\\Sessions", 0, KEY_READ, &hPutty) == ERROR_SUCCESS)
    {
        DWORD numSubs;
        RegQueryInfoKeyW(hPutty, NULL, NULL, NULL, &numSubs, NULL, NULL,
                          NULL, NULL, NULL, NULL, NULL);
        for (DWORD i = 0; i < numSubs; i++) {
            wchar_t sessName[256] = {0};
            DWORD nameLen = 256;
            if (RegEnumKeyExW(hPutty, i, sessName, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                continue;

            wchar_t sessKey[512];
            _snwprintf(sessKey, 512, L"SOFTWARE\\SimonTatham\\PuTTY\\Sessions\\%s", sessName);

            char host[256] = {0}, user[256] = {0};
            _read_sz(HKEY_CURRENT_USER, sessKey, L"HostName", host, sizeof(host));
            _read_sz(HKEY_CURRENT_USER, sessKey, L"UserName", user, sizeof(user));

            if (host[0]) {
                char name[256];
                WideCharToMultiByte(CP_UTF8, 0, sessName, -1, name, 256, NULL, NULL);
                _append(outBuf, outBufSize, &off, "PuTTY\t%s@%s\t(session: %s)\n",
                        user, host, name);
                total++;
            }
        }
        RegCloseKey(hPutty);
    }

    /* 3. WinSCP saved sessions */
    HKEY hWinSCP;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions", 0, KEY_READ, &hWinSCP) == ERROR_SUCCESS)
    {
        DWORD numSubs;
        RegQueryInfoKeyW(hWinSCP, NULL, NULL, NULL, &numSubs, NULL, NULL,
                          NULL, NULL, NULL, NULL, NULL);
        for (DWORD i = 0; i < numSubs; i++) {
            wchar_t sessName[256] = {0};
            DWORD nameLen = 256;
            if (RegEnumKeyExW(hWinSCP, i, sessName, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                continue;

            wchar_t sessKey[512];
            _snwprintf(sessKey, 512, L"SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions\\%s", sessName);

            char host[256] = {0}, user[256] = {0}, pass[256] = {0};
            _read_sz(HKEY_CURRENT_USER, sessKey, L"HostName", host, sizeof(host));
            _read_sz(HKEY_CURRENT_USER, sessKey, L"UserName", user, sizeof(user));
            _read_sz(HKEY_CURRENT_USER, sessKey, L"Password", pass, sizeof(pass));

            if (host[0]) {
                _append(outBuf, outBufSize, &off, "WinSCP\t%s@%s\t%s\n",
                        user, host, pass[0] ? "(password saved)" : "(no password)");
                total++;
            }
        }
        RegCloseKey(hWinSCP);
    }

    /* 4. VNC passwords */
    const wchar_t *vncKeys[] = {
        L"SOFTWARE\\RealVNC\\vncserver",
        L"SOFTWARE\\TightVNC\\Server",
        L"SOFTWARE\\ORL\\WinVNC3",
        NULL
    };
    for (int v = 0; vncKeys[v]; v++) {
        HKEY hVnc;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, vncKeys[v], 0, KEY_READ, &hVnc) == ERROR_SUCCESS) {
            char keyPath[256];
            WideCharToMultiByte(CP_UTF8, 0, vncKeys[v], -1, keyPath, 256, NULL, NULL);
            _append(outBuf, outBufSize, &off, "VNC\t%s\t(encrypted password in registry)\n", keyPath);
            total++;
            RegCloseKey(hVnc);
        }
    }

    /* 5. SNMP community strings */
    HKEY hSnmp;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities",
        0, KEY_READ, &hSnmp) == ERROR_SUCCESS)
    {
        DWORD numValues;
        RegQueryInfoKeyW(hSnmp, NULL, NULL, NULL, NULL, NULL, NULL,
                          &numValues, NULL, NULL, NULL, NULL);
        for (DWORD i = 0; i < numValues; i++) {
            wchar_t name[256] = {0};
            DWORD nameLen = 256;
            if (RegEnumValueW(hSnmp, i, name, &nameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                char community[256];
                WideCharToMultiByte(CP_UTF8, 0, name, -1, community, 256, NULL, NULL);
                _append(outBuf, outBufSize, &off, "SNMP\tCommunity\t%s\n", community);
                total++;
            }
        }
        RegCloseKey(hSnmp);
    }

    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Installed software enumeration
 * ═══════════════════════════════════════════════════════════════════ */

int reg_enum_installed_software(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "NAME\tVERSION\tPUBLISHER\tINSTALL_PATH\n");

    const wchar_t *uninstallKeys[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        NULL
    };

    for (int u = 0; uninstallKeys[u]; u++) {
        HKEY hUninst;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, uninstallKeys[u], 0, KEY_READ, &hUninst) != ERROR_SUCCESS)
            continue;

        DWORD numSubs;
        RegQueryInfoKeyW(hUninst, NULL, NULL, NULL, &numSubs, NULL, NULL,
                          NULL, NULL, NULL, NULL, NULL);

        for (DWORD i = 0; i < numSubs; i++) {
            wchar_t subName[256] = {0};
            DWORD nameLen = 256;
            if (RegEnumKeyExW(hUninst, i, subName, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                continue;

            wchar_t fullKey[1024];
            _snwprintf(fullKey, 1024, L"%s\\%s", uninstallKeys[u], subName);

            char displayName[512] = {0}, version[128] = {0};
            char publisher[256] = {0}, installLoc[512] = {0};

            _read_sz(HKEY_LOCAL_MACHINE, fullKey, L"DisplayName", displayName, sizeof(displayName));
            if (!displayName[0]) continue;  /* Skip entries without display name */

            _read_sz(HKEY_LOCAL_MACHINE, fullKey, L"DisplayVersion", version, sizeof(version));
            _read_sz(HKEY_LOCAL_MACHINE, fullKey, L"Publisher", publisher, sizeof(publisher));
            _read_sz(HKEY_LOCAL_MACHINE, fullKey, L"InstallLocation", installLoc, sizeof(installLoc));

            _append(outBuf, outBufSize, &off, "%s\t%s\t%s\t%s\n",
                    displayName, version, publisher, installLoc);
            total++;
        }
        RegCloseKey(hUninst);
    }

    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Security policy check
 * ═══════════════════════════════════════════════════════════════════ */

int reg_check_security_policies(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "POLICY\tSTATUS\tDETAIL\n");

    /* UAC settings */
    DWORD val;
    if (_read_dword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"EnableLUA", &val))
    {
        _append(outBuf, outBufSize, &off, "UAC\t%s\tEnableLUA=%u\n",
                val ? "ENABLED" : "DISABLED", val);
        total++;
    }

    if (_read_dword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"ConsentPromptBehaviorAdmin", &val))
    {
        const char *desc = "Unknown";
        switch (val) {
            case 0: desc = "Elevate without prompting"; break;
            case 1: desc = "Prompt for credentials on secure desktop"; break;
            case 2: desc = "Prompt for consent on secure desktop"; break;
            case 3: desc = "Prompt for credentials"; break;
            case 4: desc = "Prompt for consent"; break;
            case 5: desc = "Prompt for consent (non-Windows)"; break;
        }
        _append(outBuf, outBufSize, &off, "UAC Admin Behavior\t%u\t%s\n", val, desc);
        total++;
    }

    /* WDigest plaintext credentials (UseLogonCredential) */
    if (_read_dword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
        L"UseLogonCredential", &val))
    {
        _append(outBuf, outBufSize, &off, "WDigest Plaintext\t%s\tUseLogonCredential=%u\n",
                val ? "ENABLED (cleartext creds in memory!)" : "DISABLED", val);
    } else {
        _append(outBuf, outBufSize, &off, "WDigest Plaintext\tDISABLED\t(key not present, default off)\n");
    }
    total++;

    /* LSA Protection (RunAsPPL) */
    if (_read_dword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"RunAsPPL", &val))
    {
        _append(outBuf, outBufSize, &off, "LSA Protection\t%s\tRunAsPPL=%u\n",
                val ? "ENABLED (LSASS protected)" : "DISABLED", val);
    } else {
        _append(outBuf, outBufSize, &off, "LSA Protection\tDISABLED\t(key not present)\n");
    }
    total++;

    /* Credential Guard */
    if (_read_dword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"LsaCfgFlags", &val))
    {
        const char *desc = "Unknown";
        switch (val) {
            case 0: desc = "Disabled"; break;
            case 1: desc = "Enabled with UEFI lock"; break;
            case 2: desc = "Enabled without lock"; break;
        }
        _append(outBuf, outBufSize, &off, "Credential Guard\t%s\tLsaCfgFlags=%u\n", desc, val);
    } else {
        _append(outBuf, outBufSize, &off, "Credential Guard\tNot configured\t(key not present)\n");
    }
    total++;

    /* PowerShell execution policy */
    char psPolicy[128] = {0};
    if (_read_sz(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",
        L"ExecutionPolicy", psPolicy, sizeof(psPolicy)))
    {
        _append(outBuf, outBufSize, &off, "PS ExecutionPolicy\t%s\tMachine-level\n", psPolicy);
        total++;
    }

    /* LAPS (Local Administrator Password Solution) */
    if (reg_key_exists(L"HKLM", L"SOFTWARE\\Policies\\Microsoft Services\\AdmPwd")) {
        _append(outBuf, outBufSize, &off, "LAPS\tINSTALLED\tCheck ms-Mcs-AdmPwd attribute in AD\n");
    } else {
        _append(outBuf, outBufSize, &off, "LAPS\tNot detected\t(AdmPwd key not present)\n");
    }
    total++;

    /* Windows Firewall */
    DWORD fwDomain = 0, fwPrivate = 0, fwPublic = 0;
    _read_dword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
        L"EnableFirewall", &fwDomain);
    _read_dword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        L"EnableFirewall", &fwPrivate);
    _read_dword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
        L"EnableFirewall", &fwPublic);

    _append(outBuf, outBufSize, &off, "Firewall\tDomain=%s Private=%s Public=%s\n",
            fwDomain ? "ON" : "OFF", fwPrivate ? "ON" : "OFF", fwPublic ? "ON" : "OFF");
    total++;

    /* AlwaysInstallElevated (privesc vector) */
    DWORD aieHKLM = 0, aieHKCU = 0;
    _read_dword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        L"AlwaysInstallElevated", &aieHKLM);
    _read_dword(HKEY_CURRENT_USER,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        L"AlwaysInstallElevated", &aieHKCU);

    if (aieHKLM && aieHKCU) {
        _append(outBuf, outBufSize, &off,
                "AlwaysInstallElevated\tVULNERABLE\tBoth HKLM and HKCU set to 1 — privesc via MSI!\n");
    } else {
        _append(outBuf, outBufSize, &off,
                "AlwaysInstallElevated\tNot vulnerable\tHKLM=%u HKCU=%u\n", aieHKLM, aieHKCU);
    }
    total++;

    *bytesWritten = off;
    return total;
}
