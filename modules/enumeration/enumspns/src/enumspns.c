/*
 * enumspns.c — Enumerate accounts with Service Principal Names via LDAP.
 */
#include <windows.h>
#include <winldap.h>
#include "beacon_compat.h"

DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
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

    char *domain_a = BeaconDataExtract(&parser, NULL);
    char *server_a = BeaconDataExtract(&parser, NULL);
    int   limit    = BeaconDataInt(&parser);

    wchar_t wDomain[256] = {0}, wServer[256] = {0};

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

    /* Filter: user accounts with SPNs, excluding disabled */
    wchar_t *filter = L"(&(objectCategory=person)(objectClass=user)"
                      L"(servicePrincipalName=*)"
                      L"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    wchar_t *attrs[] = { L"sAMAccountName", L"servicePrincipalName",
                         L"distinguishedName", L"pwdLastSet", NULL };
    LDAPMessage *results = NULL;

    if (WLDAP32$ldap_search_sW(ld, baseDN, LDAP_SCOPE_SUBTREE,
                                filter, attrs, 0, &results) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_search failed");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    int count = 0;
    LDAPMessage *entry = WLDAP32$ldap_first_entry(ld, results);

    BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-50s", "Account", "SPN");
    BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-50s", "-------", "---");

    while (entry) {
        if (limit > 0 && count >= limit) break;

        wchar_t **samV = WLDAP32$ldap_get_valuesW(ld, entry, L"sAMAccountName");
        wchar_t **spnV = WLDAP32$ldap_get_valuesW(ld, entry, L"servicePrincipalName");

        char samN[128] = {0};
        if (samV && samV[0])
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0, samV[0], -1, samN, 128, NULL, NULL);

        /* Print each SPN for this account */
        if (spnV) {
            for (int i = 0; spnV[i]; i++) {
                char spnN[256] = {0};
                KERNEL32$WideCharToMultiByte(CP_UTF8, 0, spnV[i], -1, spnN, 256, NULL, NULL);
                BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-50s", i == 0 ? samN : "", spnN);
            }
        }

        if (samV) WLDAP32$ldap_value_freeW(samV);
        if (spnV) WLDAP32$ldap_value_freeW(spnV);

        count++;
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Found %d accounts with SPNs", count);
    WLDAP32$ldap_msgfree(results);
    WLDAP32$ldap_unbind(ld);
}
