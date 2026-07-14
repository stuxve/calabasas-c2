/*
 * enumdomainusers.c — Enumerate domain users via LDAP.
 *
 * Uses wldap32.dll directly:
 *   ldap_initW → ldap_bind_sW → ldap_search_sW →
 *   ldap_first_entry → ldap_next_entry → ldap_get_valuesW
 */
#include <windows.h>
#include <winldap.h>
#include "beacon_compat.h"

/* Dynamic imports from wldap32.dll */
DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR* LDAPAPI WLDAP32$ldap_get_valuesW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_value_freeW(PWSTR*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP*);

/* Dynamic imports for DC discovery */
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(
    LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, void**);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(
    UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(
    UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameExW(
    int, LPWSTR, LPDWORD);

DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcschr(const wchar_t*, wchar_t);
DECLSPEC_IMPORT size_t   __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);

/* Build base DN from domain name: corp.local -> DC=corp,DC=local */
static void build_base_dn(const wchar_t *domain, wchar_t *dn, int dn_size) {
    dn[0] = L'\0';
    const wchar_t *p = domain;
    int first = 1;

    while (*p) {
        if (!first) MSVCRT$wcscat(dn, L",");
        MSVCRT$wcscat(dn, L"DC=");

        const wchar_t *dot = MSVCRT$wcschr(p, L'.');
        if (dot) {
            int len = (int)(dot - p);
            int cur = (int)MSVCRT$wcslen(dn);
            if (cur + len < dn_size - 1) {
                memcpy(dn + cur, p, len * sizeof(wchar_t));
                dn[cur + len] = L'\0';
            }
            p = dot + 1;
        } else {
            MSVCRT$wcscat(dn, p);
            break;
        }
        first = 0;
    }
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *domain_a  = BeaconDataExtract(&parser, NULL);
    char *filter_a   = BeaconDataExtract(&parser, NULL);
    char *attrs_a    = BeaconDataExtract(&parser, NULL);
    char *server_a   = BeaconDataExtract(&parser, NULL);
    int   limit      = BeaconDataInt(&parser);

    /* Convert to wide strings */
    wchar_t wDomain[256] = {0};
    wchar_t wFilter[1024] = {0};
    wchar_t wServer[256] = {0};

    if (domain_a && *domain_a) {
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, domain_a, -1, wDomain, 256);
    } else {
        DWORD size = 256;
        KERNEL32$GetComputerNameExW(2 /* ComputerNameDnsDomain */, wDomain, &size);
    }

    if (filter_a && *filter_a) {
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, filter_a, -1, wFilter, 1024);
    } else {
        MSVCRT$wcscpy(wFilter, L"(&(objectCategory=person)(objectClass=user))");
    }

    if (server_a && *server_a) {
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, server_a, -1, wServer, 256);
    }

    /* Connect to LDAP */
    LDAP *ld = WLDAP32$ldap_initW(wServer[0] ? wServer : wDomain, 389);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_init failed for %S", wDomain);
        return;
    }

    ULONG result = WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_bind failed: %u", result);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    /* Build base DN */
    wchar_t baseDN[512];
    build_base_dn(wDomain, baseDN, 512);

    /* Execute search */
    wchar_t *search_attrs[] = {
        L"sAMAccountName", L"distinguishedName", L"description",
        L"lastLogon", L"userAccountControl", L"memberOf",
        L"pwdLastSet", L"mail", NULL
    };

    LDAPMessage *results = NULL;
    result = WLDAP32$ldap_search_sW(ld, baseDN, LDAP_SCOPE_SUBTREE,
                                     wFilter, search_attrs, 0, &results);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_search failed: %u", result);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    /* Iterate results */
    int count = 0;
    char narrow[512];
    LDAPMessage *entry = WLDAP32$ldap_first_entry(ld, results);

    BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-15s %-50s", "sAMAccountName", "UAC", "distinguishedName");
    BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-15s %-50s", "---------------", "---", "-------------------");

    while (entry) {
        if (limit > 0 && count >= limit) break;

        wchar_t **samValues = WLDAP32$ldap_get_valuesW(ld, entry, L"sAMAccountName");
        wchar_t **dnValues  = WLDAP32$ldap_get_valuesW(ld, entry, L"distinguishedName");
        wchar_t **uacValues = WLDAP32$ldap_get_valuesW(ld, entry, L"userAccountControl");

        char samNarrow[128] = {0};
        char dnNarrow[256] = {0};
        char uacNarrow[32] = {0};

        if (samValues && samValues[0])
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0, samValues[0], -1, samNarrow, 128, NULL, NULL);
        if (dnValues && dnValues[0])
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0, dnValues[0], -1, dnNarrow, 256, NULL, NULL);
        if (uacValues && uacValues[0])
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0, uacValues[0], -1, uacNarrow, 32, NULL, NULL);

        BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-15s %-50s", samNarrow, uacNarrow, dnNarrow);

        if (samValues) WLDAP32$ldap_value_freeW(samValues);
        if (dnValues)  WLDAP32$ldap_value_freeW(dnValues);
        if (uacValues) WLDAP32$ldap_value_freeW(uacValues);

        count++;
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Enumerated %d users", count);

    WLDAP32$ldap_msgfree(results);
    WLDAP32$ldap_unbind(ld);
}
