/*
 * beacon_api.c — Beacon API compatibility layer for BOF execution.
 *
 * Implements the Cobalt Strike Beacon API functions that BOFs call:
 *   - BeaconPrintf / BeaconOutput  — write output to collection buffer
 *   - BeaconDataParse / Extract / Int / Short / Length — parse argument buffer
 *   - BeaconIsAdmin / BeaconUseToken / BeaconRevertToken — token helpers
 *   - BeaconGetSpawnTo — spawn-to process path
 *
 * Output is written to a global buffer (g_bof_output) that the COFF loader
 * collects after the BOF entry point returns.
 */
#include "agent.h"
#include <stdarg.h>

/* ─── Global output buffer ─── */

unsigned char *g_bof_output     = NULL;
int            g_bof_output_len = 0;
int            g_bof_output_cap = 0;

static void output_append(const void *data, int len) {
    if (!g_bof_output || len <= 0) return;

    /* Grow buffer if needed */
    while (g_bof_output_len + len > g_bof_output_cap) {
        int new_cap = g_bof_output_cap * 2;
        if (new_cap < g_bof_output_cap + len)
            new_cap = g_bof_output_cap + len + 4096;
        unsigned char *new_buf = (unsigned char *)realloc(g_bof_output, new_cap);
        if (!new_buf) return;
        g_bof_output = new_buf;
        g_bof_output_cap = new_cap;
    }

    memcpy(g_bof_output + g_bof_output_len, data, len);
    g_bof_output_len += len;
}

/* ─── Output functions ─── */

/*
 * Callback types (from Cobalt Strike):
 *   0x00 = CALLBACK_OUTPUT         — standard text
 *   0x0d = CALLBACK_ERROR          — error message
 *   0x1e = CALLBACK_OUTPUT_OEM     — OEM text
 *   0x20 = CALLBACK_OUTPUT_UTF8    — UTF-8 text
 */

void __cdecl BeaconPrintf(int type, const char *fmt, ...) {
    char buf[8192];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (len < 0) return;
    if (len >= (int)sizeof(buf)) len = sizeof(buf) - 1;

    /* Wrap in a simple output format: just append the text */
    output_append(buf, len);

    /* Add newline if not present */
    if (len > 0 && buf[len - 1] != '\n') {
        output_append("\n", 1);
    }

    (void)type;  /* Type is used by the operator for display routing */
}

void __cdecl BeaconOutput(int type, const char *data, int len) {
    if (data && len > 0)
        output_append(data, len);
    (void)type;
}

/* ─── Data parsing functions ─── */

/*
 * datap struct layout (matches Cobalt Strike BOF convention):
 *   char *original;   — pointer to start of buffer
 *   char *buffer;     — current read position
 *   int   length;     — remaining bytes
 *   int   size;       — total buffer size
 */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

void __cdecl BeaconDataParse(void *parser, char *buffer, int size) {
    datap *dp = (datap *)parser;
    dp->original = buffer;
    dp->buffer   = buffer;
    dp->length   = size;
    dp->size     = size;
}

char* __cdecl BeaconDataExtract(void *parser, int *out_size) {
    datap *dp = (datap *)parser;

    if (dp->length < 4)
        return NULL;

    /* Read 4-byte length prefix (LE) */
    int str_len;
    memcpy(&str_len, dp->buffer, 4);
    dp->buffer += 4;
    dp->length -= 4;

    if (str_len <= 0 || str_len > dp->length)
        return NULL;

    char *result = dp->buffer;
    dp->buffer += str_len;
    dp->length -= str_len;

    if (out_size)
        *out_size = str_len;

    return result;
}

int __cdecl BeaconDataInt(void *parser) {
    datap *dp = (datap *)parser;

    if (dp->length < 4)
        return 0;

    int val;
    memcpy(&val, dp->buffer, 4);
    dp->buffer += 4;
    dp->length -= 4;

    return val;
}

short __cdecl BeaconDataShort(void *parser) {
    datap *dp = (datap *)parser;

    if (dp->length < 2)
        return 0;

    short val;
    memcpy(&val, dp->buffer, 2);
    dp->buffer += 2;
    dp->length -= 2;

    return val;
}

int __cdecl BeaconDataLength(void *parser) {
    datap *dp = (datap *)parser;
    return dp->length;
}

/* ─── Token/privilege functions ─── */

void __cdecl BeaconUseToken(HANDLE token) {
    /* Impersonate the given token */
    ImpersonateLoggedOnUser(token);
}

void __cdecl BeaconRevertToken(void) {
    /* Revert to self */
    RevertToSelf();
}

BOOL __cdecl BeaconIsAdmin(void) {
    BOOL is_admin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID admin_group = NULL;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(NULL, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin;
}

/* ─── Spawn-to helper ─── */

void __cdecl BeaconGetSpawnTo(BOOL x86, char *buffer, int length) {
    const char *path;
    if (x86)
        path = "C:\\Windows\\SysWOW64\\rundll32.exe";
    else
        path = "C:\\Windows\\System32\\rundll32.exe";

    strncpy(buffer, path, length - 1);
    buffer[length - 1] = '\0';
}
