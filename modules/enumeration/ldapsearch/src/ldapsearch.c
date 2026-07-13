/*
 * ldapsearch.c — Raw LDAP search with user-specified filter and attributes.
 */
#include <windows.h>
#include <winldap.h>
#include "beacon_compat.h"

DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR  LDAPAPI WLDAP32$ldap_first_attributeW(LDAP*, LDAPMessage*, void**);
DECLSPEC_IMPORT PWSTR  LDAPAPI WLDAP32$ldap_next_attributeW(LDAP*, LDAPMessage*, void*);
DECLSPEC_IMPORT PWSTR* LDAPAPI WLDAP32$ldap_get_valuesW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_value_freeW(PWSTR*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP*);

DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameExW(int, LPWSTR, LPDWORD);

static void build_base_dn(const wchar_t *domain, wchar_t *dn, int dn_size) {
    dn[0] = L'\0';
    const wchar_t *p = domain;
    int first = 1;
    while (*p) {
        if (!first) wcscat(dn, L",");
        wcscat(dn, L"DC=");
        const wchar_t *dot = wcschr(p, L'.');
        if (dot) {
            int len = (int)(dot - p);
            int cur = (int)wcslen(dn);
            if (cur + len < dn_size - 1) {
                memcpy(dn + cur, p, len * sizeof(wchar_t));
                dn[cur + len] = L'\0';
            }
            p = dot + 1;
        } else {
            wcscat(dn, p);
            break;
        }
        first = 0;
    }
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *filter_a = BeaconDataExtract(&parser, NULL);
    char *attrs_a  = BeaconDataExtract(&parser, NULL);
    char *domain_a = BeaconDataExtract(&parser, NULL);
    char *server_a = BeaconDataExtract(&parser, NULL);
    int   limit    = BeaconDataInt(&parser);

    if (!filter_a || !*filter_a) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Filter is required");
        return;
    }

    wchar_t wDomain[256] = {0}, wFilter[2048] = {0}, wServer[256] = {0};

    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, filter_a, -1, wFilter, 2048);

    if (domain_a && *domain_a)
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, domain_a, -1, wDomain, 256);
    else {
        DWORD size = 256;
        KERNEL32$GetComputerNameExW(2, wDomain, &size);
    }

    if (server_a && *server_a)
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, server_a, -1, wServer, 256);

    LDAP *ld = WLDAP32$ldap_initW(wServer[0] ? wServer : wDomain, 389);
    if (!ld) { BeaconPrintf(CALLBACK_ERROR, "[-] ldap_init failed"); return; }

    if (WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_bind failed");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    wchar_t baseDN[512];
    build_base_dn(wDomain, baseDN, 512);

    LDAPMessage *results = NULL;
    if (WLDAP32$ldap_search_sW(ld, baseDN, LDAP_SCOPE_SUBTREE,
                                wFilter, NULL, 0, &results) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_search failed");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    int count = 0;
    LDAPMessage *entry = WLDAP32$ldap_first_entry(ld, results);

    while (entry) {
        if (limit > 0 && count >= limit) break;

        BeaconPrintf(CALLBACK_OUTPUT, "--- Entry %d ---", count + 1);

        /* Iterate all attributes for this entry */
        void *ber = NULL;
        wchar_t *attr = WLDAP32$ldap_first_attributeW(ld, entry, &ber);
        while (attr) {
            wchar_t **vals = WLDAP32$ldap_get_valuesW(ld, entry, attr);
            char attrN[256] = {0};
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0, attr, -1, attrN, 256, NULL, NULL);

            if (vals) {
                for (int i = 0; vals[i]; i++) {
                    char valN[1024] = {0};
                    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, vals[i], -1, valN, 1024, NULL, NULL);
                    BeaconPrintf(CALLBACK_OUTPUT, "  %s: %s", attrN, valN);
                }
                WLDAP32$ldap_value_freeW(vals);
            }

            attr = WLDAP32$ldap_next_attributeW(ld, entry, ber);
        }

        count++;
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d entries returned", count);
    WLDAP32$ldap_msgfree(results);
    WLDAP32$ldap_unbind(ld);
}
