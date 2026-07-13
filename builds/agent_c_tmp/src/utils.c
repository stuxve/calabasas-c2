/*
 * utils.c — Base64/Base64URL encoding/decoding, buffer helpers.
 */
#include "agent.h"

/* ─── Dynamic buffer ─── */

void buf_init(Buffer *b, DWORD initial_cap) {
    b->cap = initial_cap ? initial_cap : 256;
    b->data = (unsigned char *)malloc(b->cap);
    b->len = 0;
}

void buf_append(Buffer *b, const void *data, DWORD len) {
    if (b->len + len > b->cap) {
        while (b->len + len > b->cap) b->cap *= 2;
        b->data = (unsigned char *)realloc(b->data, b->cap);
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
}

void buf_free(Buffer *b) {
    if (b->data) { free(b->data); b->data = NULL; }
    b->len = b->cap = 0;
}

void buf_reset(Buffer *b) {
    b->len = 0;
}

/* ─── Base64 standard ─── */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char b64url_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *b64_encode_impl(const unsigned char *data, DWORD len,
                             DWORD *out_len, const char *table, BOOL pad) {
    DWORD olen = 4 * ((len + 2) / 3);
    if (!pad) {
        olen = 4 * (len / 3);
        int rem = len % 3;
        if (rem == 1) olen += 2;
        else if (rem == 2) olen += 3;
    }

    char *out = (char *)malloc(olen + 1);
    DWORD i, j;

    for (i = 0, j = 0; i + 2 < len; i += 3) {
        unsigned int v = ((unsigned int)data[i] << 16) |
                         ((unsigned int)data[i+1] << 8) |
                         data[i+2];
        out[j++] = table[(v >> 18) & 0x3F];
        out[j++] = table[(v >> 12) & 0x3F];
        out[j++] = table[(v >> 6) & 0x3F];
        out[j++] = table[v & 0x3F];
    }

    if (i < len) {
        unsigned int v = (unsigned int)data[i] << 16;
        if (i + 1 < len) v |= (unsigned int)data[i+1] << 8;

        out[j++] = table[(v >> 18) & 0x3F];
        out[j++] = table[(v >> 12) & 0x3F];

        if (i + 1 < len) {
            out[j++] = table[(v >> 6) & 0x3F];
            if (pad) out[j++] = '=';
        } else {
            if (pad) { out[j++] = '='; out[j++] = '='; }
        }
    }

    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

static int b64_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static unsigned char *b64_decode_impl(const char *data, DWORD len, DWORD *out_len) {
    /* Strip padding and whitespace */
    while (len > 0 && (data[len-1] == '=' || data[len-1] == '\n' ||
                       data[len-1] == '\r' || data[len-1] == ' '))
        len--;

    DWORD olen = (len * 3) / 4;
    unsigned char *out = (unsigned char *)malloc(olen + 1);
    DWORD i = 0, j = 0;

    while (i + 3 < len) {
        int a = b64_char_val(data[i++]);
        int b = b64_char_val(data[i++]);
        int c = b64_char_val(data[i++]);
        int d = b64_char_val(data[i++]);
        if (a < 0 || b < 0 || c < 0 || d < 0) break;
        unsigned int v = (a << 18) | (b << 12) | (c << 6) | d;
        out[j++] = (v >> 16) & 0xFF;
        out[j++] = (v >> 8) & 0xFF;
        out[j++] = v & 0xFF;
    }

    /* Handle remaining bytes */
    if (i + 1 < len) {
        int a = b64_char_val(data[i++]);
        int b = b64_char_val(data[i++]);
        if (a >= 0 && b >= 0) {
            unsigned int v = (a << 18) | (b << 12);
            out[j++] = (v >> 16) & 0xFF;
            if (i < len) {
                int c = b64_char_val(data[i++]);
                if (c >= 0) {
                    v |= (c << 6);
                    out[j++] = (v >> 8) & 0xFF;
                }
            }
        }
    }

    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

char *base64_encode(const unsigned char *data, DWORD len, DWORD *out_len) {
    return b64_encode_impl(data, len, out_len, b64_table, TRUE);
}

unsigned char *base64_decode(const char *data, DWORD len, DWORD *out_len) {
    return b64_decode_impl(data, len, out_len);
}

char *base64url_encode(const unsigned char *data, DWORD len, DWORD *out_len) {
    return b64_encode_impl(data, len, out_len, b64url_table, FALSE);
}

unsigned char *base64url_decode(const char *data, DWORD len, DWORD *out_len) {
    return b64_decode_impl(data, len, out_len);
}
