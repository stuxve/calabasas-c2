/*
 * portscan.c — Async TCP port scanner for internal network discovery.
 *
 * Uses non-blocking connect() with select() for timeout control.
 * Thread pool processes multiple targets concurrently.
 */
#include "agent.h"
#include "portscan.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

/* ─── Internal work item ─── */
typedef struct _SCAN_WORK {
    char    host[64];
    USHORT  port;
    int     timeoutMs;
    BOOL    grabBanner;
    int     bannerBytes;
} SCAN_WORK;

typedef struct _SCAN_THREAD_CTX {
    SCAN_WORK      *workQueue;
    volatile LONG   workIndex;
    int             workCount;
    SCAN_CALLBACK   callback;
    void           *cbCtx;
    volatile LONG  *openCount;

    /* Output buffer (shared, protected by lock) */
    unsigned char  *outBuf;
    DWORD           outBufSize;
    volatile LONG  *outOffset;
    CRITICAL_SECTION *outLock;
} SCAN_THREAD_CTX;

/* ─── Single port probe ─── */

static BOOL _probe_port(const SCAN_WORK *work, SCAN_RESULT *result) {
    memset(result, 0, sizeof(SCAN_RESULT));
    strncpy(result->host, work->host, sizeof(result->host) - 1);
    result->port = work->port;
    result->open = FALSE;

    /* Resolve host */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char portStr[8];
    _snprintf(portStr, sizeof(portStr), "%u", work->port);

    if (getaddrinfo(work->host, portStr, &hints, &res) != 0 || !res)
        return FALSE;

    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return FALSE;
    }

    /* Set non-blocking */
    u_long nonBlock = 1;
    ioctlsocket(sock, FIONBIO, &nonBlock);

    /* Time the connect */
    DWORD startMs = (DWORD)GetTickCount64();

    int connRet = connect(sock, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);

    if (connRet == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            /* Wait for connection with timeout */
            fd_set writeSet, exceptSet;
            FD_ZERO(&writeSet);
            FD_ZERO(&exceptSet);
            FD_SET(sock, &writeSet);
            FD_SET(sock, &exceptSet);

            struct timeval tv;
            tv.tv_sec = work->timeoutMs / 1000;
            tv.tv_usec = (work->timeoutMs % 1000) * 1000;

            int sel = select(0, NULL, &writeSet, &exceptSet, &tv);
            if (sel <= 0 || FD_ISSET(sock, &exceptSet)) {
                closesocket(sock);
                return FALSE;  /* Timeout or error = port closed/filtered */
            }

            /* Check if connect actually succeeded */
            int optVal = 0;
            int optLen = sizeof(optVal);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&optVal, &optLen);
            if (optVal != 0) {
                closesocket(sock);
                return FALSE;
            }
        } else {
            closesocket(sock);
            return FALSE;
        }
    }

    /* Port is open */
    result->open = TRUE;
    result->responseMs = (DWORD)GetTickCount64() - startMs;

    /* Banner grab if requested */
    if (work->grabBanner && work->bannerBytes > 0) {
        /* Set blocking with short timeout for banner read */
        u_long blocking = 0;
        ioctlsocket(sock, FIONBIO, &blocking);

        /* Set recv timeout */
        DWORD recvTimeout = 2000;  /* 2 second banner timeout */
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&recvTimeout, sizeof(recvTimeout));

        int maxRead = work->bannerBytes;
        if (maxRead > (int)sizeof(result->banner) - 1)
            maxRead = (int)sizeof(result->banner) - 1;

        int bytesRead = recv(sock, result->banner, maxRead, 0);
        if (bytesRead > 0) {
            result->bannerLen = bytesRead;
            /* Sanitize: replace non-printable chars with dots */
            for (int i = 0; i < bytesRead; i++) {
                unsigned char c = (unsigned char)result->banner[i];
                if (c < 0x20 || c > 0x7E)
                    result->banner[i] = '.';
            }
            result->banner[bytesRead] = '\0';
        }
    }

    closesocket(sock);
    return TRUE;
}

/* ─── Worker thread ─── */

static DWORD WINAPI _scan_worker(LPVOID param) {
    SCAN_THREAD_CTX *ctx = (SCAN_THREAD_CTX *)param;

    while (TRUE) {
        /* Grab next work item atomically */
        LONG idx = InterlockedIncrement(&ctx->workIndex) - 1;
        if (idx >= ctx->workCount)
            break;

        SCAN_RESULT result;
        _probe_port(&ctx->workQueue[idx], &result);

        if (result.open) {
            InterlockedIncrement(ctx->openCount);

            /* Call user callback */
            if (ctx->callback)
                ctx->callback(&result, ctx->cbCtx);

            /* Write to output buffer (TLV table row) */
            if (ctx->outBuf && ctx->outLock) {
                /*
                 * Build a table row:
                 *   host | port | banner | responseMs
                 */
                char row[1024];
                int rowLen = _snprintf(row, sizeof(row),
                    "%s\t%u\t%s\t%u\n",
                    result.host, result.port,
                    result.bannerLen > 0 ? result.banner : "",
                    result.responseMs);

                if (rowLen > 0) {
                    EnterCriticalSection(ctx->outLock);
                    LONG offset = *ctx->outOffset;
                    if (offset + rowLen < (LONG)ctx->outBufSize) {
                        memcpy(ctx->outBuf + offset, row, rowLen);
                        InterlockedAdd(ctx->outOffset, rowLen);
                    }
                    LeaveCriticalSection(ctx->outLock);
                }
            }
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  CIDR expansion
 * ═══════════════════════════════════════════════════════════════════ */

int portscan_expand_cidr(const char *cidr, char ipList[][64], int maxIps) {
    if (!cidr || !ipList || maxIps <= 0) return 0;

    /* Check for CIDR notation */
    const char *slash = strchr(cidr, '/');
    if (!slash) {
        /* Single IP */
        strncpy(ipList[0], cidr, 63);
        ipList[0][63] = '\0';
        return 1;
    }

    /* Parse base IP and prefix length */
    char baseIp[64] = {0};
    int prefixLen;
    int baseLen = (int)(slash - cidr);
    if (baseLen >= 64) return 0;
    strncpy(baseIp, cidr, baseLen);
    prefixLen = atoi(slash + 1);

    if (prefixLen < 8 || prefixLen > 32) return 0;

    /* Convert base IP to 32-bit integer */
    struct in_addr addr;
    if (inet_pton(AF_INET, baseIp, &addr) != 1) return 0;

    DWORD baseAddr = ntohl(addr.s_addr);
    DWORD mask = (prefixLen == 0) ? 0 : (~0U << (32 - prefixLen));
    DWORD network = baseAddr & mask;
    DWORD broadcast = network | ~mask;

    int count = 0;
    /* Skip network address and broadcast; start at +1, end at -1 */
    for (DWORD ip = network + 1; ip < broadcast && count < maxIps; ip++) {
        struct in_addr a;
        a.s_addr = htonl(ip);
        char *ipStr = inet_ntoa(a);
        if (ipStr) {
            strncpy(ipList[count], ipStr, 63);
            ipList[count][63] = '\0';
            count++;
        }
    }

    return count;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Port string parsing
 * ═══════════════════════════════════════════════════════════════════ */

int portscan_parse_ports(const char *portSpec, USHORT *ports, int maxPorts) {
    if (!portSpec || !ports || maxPorts <= 0) return 0;

    int count = 0;
    char buf[8192];
    strncpy(buf, portSpec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *token = strtok(buf, ",");
    while (token && count < maxPorts) {
        /* Trim whitespace */
        while (*token == ' ') token++;

        /* Check for range (e.g., "1-1024") */
        char *dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            int start = atoi(token);
            int end = atoi(dash + 1);
            if (start < 1) start = 1;
            if (end > 65535) end = 65535;
            for (int p = start; p <= end && count < maxPorts; p++) {
                ports[count++] = (USHORT)p;
            }
        } else {
            int p = atoi(token);
            if (p >= 1 && p <= 65535) {
                ports[count++] = (USHORT)p;
            }
        }

        token = strtok(NULL, ",");
    }

    return count;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Main scan entry point
 * ═══════════════════════════════════════════════════════════════════ */

int portscan_run(const SCAN_OPTS *opts, SCAN_CALLBACK callback, void *cbCtx,
                 unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten)
{
    if (!opts || !opts->targets || !opts->ports)
        return 0;

    if (bytesWritten) *bytesWritten = 0;

    /* Ensure Winsock initialized */
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    /* Parse targets */
    /* Support comma-separated list, each entry can be IP or CIDR */
    char targetBuf[4096];
    strncpy(targetBuf, opts->targets, sizeof(targetBuf) - 1);
    targetBuf[sizeof(targetBuf) - 1] = '\0';

    /* Expand all targets into IP list */
    #define MAX_IPS 4096
    char (*ipList)[64] = (char (*)[64])HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_IPS * 64);
    if (!ipList) return 0;

    int ipCount = 0;
    char *tok = strtok(targetBuf, ",");
    while (tok && ipCount < MAX_IPS) {
        while (*tok == ' ') tok++;
        if (strchr(tok, '/')) {
            ipCount += portscan_expand_cidr(tok, ipList + ipCount, MAX_IPS - ipCount);
        } else {
            strncpy(ipList[ipCount], tok, 63);
            ipCount++;
        }
        tok = strtok(NULL, ",");
    }

    /* Parse ports */
    #define MAX_PORTS 65536
    USHORT *portList = (USHORT *)HeapAlloc(GetProcessHeap(), 0, MAX_PORTS * sizeof(USHORT));
    if (!portList) {
        HeapFree(GetProcessHeap(), 0, ipList);
        return 0;
    }
    int portCount = portscan_parse_ports(opts->ports, portList, MAX_PORTS);

    if (ipCount == 0 || portCount == 0) {
        HeapFree(GetProcessHeap(), 0, ipList);
        HeapFree(GetProcessHeap(), 0, portList);
        return 0;
    }

    /* Build work queue: every (IP, port) combination */
    int workCount = ipCount * portCount;
    SCAN_WORK *workQueue = (SCAN_WORK *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, workCount * sizeof(SCAN_WORK));
    if (!workQueue) {
        HeapFree(GetProcessHeap(), 0, ipList);
        HeapFree(GetProcessHeap(), 0, portList);
        return 0;
    }

    int wi = 0;
    for (int i = 0; i < ipCount; i++) {
        for (int p = 0; p < portCount; p++) {
            strncpy(workQueue[wi].host, ipList[i], 63);
            workQueue[wi].port = portList[p];
            workQueue[wi].timeoutMs = opts->timeoutMs > 0 ? opts->timeoutMs : 1000;
            workQueue[wi].grabBanner = opts->grabBanner;
            workQueue[wi].bannerBytes = opts->bannerBytes > 0 ? opts->bannerBytes : 256;
            wi++;
        }
    }

    HeapFree(GetProcessHeap(), 0, ipList);
    HeapFree(GetProcessHeap(), 0, portList);

    /* Set up thread context */
    volatile LONG workIndex = 0;
    volatile LONG openCount = 0;
    volatile LONG outOffset = 0;
    CRITICAL_SECTION outLock;
    InitializeCriticalSection(&outLock);

    /* Write output header */
    if (outBuf && outBufSize > 0) {
        const char *header = "HOST\tPORT\tBANNER\tRESPONSE_MS\n";
        int hdrLen = (int)strlen(header);
        if ((DWORD)hdrLen < outBufSize) {
            memcpy(outBuf, header, hdrLen);
            outOffset = hdrLen;
        }
    }

    SCAN_THREAD_CTX threadCtx = {0};
    threadCtx.workQueue = workQueue;
    threadCtx.workIndex = 0;  /* Will use InterlockedIncrement via pointer */
    threadCtx.workCount = workCount;
    threadCtx.callback = callback;
    threadCtx.cbCtx = cbCtx;
    threadCtx.openCount = &openCount;
    threadCtx.outBuf = outBuf;
    threadCtx.outBufSize = outBufSize;
    threadCtx.outOffset = &outOffset;
    threadCtx.outLock = &outLock;

    /* Point workIndex in ctx to our shared counter */
    /* We need to use the address, but the struct has a copy. Fix: use the shared one. */
    /* The worker threads read from threadCtx directly; they use InterlockedIncrement on &threadCtx.workIndex */
    /* But workIndex is not a pointer in the struct — it's a LONG. Workers access ctx->workIndex. */
    /* Since all threads share the same threadCtx (passed by pointer), this is fine. */

    int numThreads = opts->threads > 0 ? opts->threads : 50;
    if (numThreads > 128) numThreads = 128;
    if (numThreads > workCount) numThreads = workCount;

    HANDLE *threads = (HANDLE *)HeapAlloc(
        GetProcessHeap(), 0, numThreads * sizeof(HANDLE));
    if (!threads) {
        HeapFree(GetProcessHeap(), 0, workQueue);
        DeleteCriticalSection(&outLock);
        return 0;
    }

    /* Launch worker threads */
    for (int t = 0; t < numThreads; t++) {
        threads[t] = CreateThread(NULL, 0, _scan_worker, &threadCtx, 0, NULL);
    }

    /* Wait for all threads to complete */
    WaitForMultipleObjects(numThreads, threads, TRUE, INFINITE);

    for (int t = 0; t < numThreads; t++) {
        if (threads[t]) CloseHandle(threads[t]);
    }

    if (bytesWritten) *bytesWritten = (DWORD)outOffset;

    HeapFree(GetProcessHeap(), 0, threads);
    HeapFree(GetProcessHeap(), 0, workQueue);
    DeleteCriticalSection(&outLock);

    return (int)openCount;
}
