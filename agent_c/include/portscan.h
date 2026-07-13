/*
 * portscan.h — Async TCP port scanner for internal network discovery.
 *
 * Pentest use: after gaining access to a host, scan internal subnets
 * to find live hosts, open services, and attack surface.
 *
 * Features:
 *   - Non-blocking connect() scan (no SYN scan — that needs raw sockets)
 *   - Configurable port lists with common presets
 *   - Configurable thread count and timeouts
 *   - Service banner grabbing on open ports
 *   - Structured table output for the operator
 */
#ifndef PORTSCAN_H
#define PORTSCAN_H

#include <windows.h>

/* ─── Port presets ─── */
#define PORTS_TOP_20    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
#define PORTS_AD        "53,88,135,139,389,445,464,636,3268,3269,5985,5986,9389"
#define PORTS_WEB       "80,443,8080,8443,8000,8888,3000,5000,9090,9443"
#define PORTS_DB        "1433,1521,3306,5432,6379,9200,27017,5984,8529"
#define PORTS_RDP_SSH   "22,3389,5900,5985,5986"
#define PORTS_TOP_100   "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111," \
                        "113,119,135,139,143,144,179,199,389,427,443,444,445," \
                        "465,513,514,515,543,544,548,554,587,631,636,646,873," \
                        "990,993,995,1025,1026,1027,1028,1029,1110,1433,1720," \
                        "1723,1755,1900,2000,2001,2049,2121,2717,3000,3128," \
                        "3306,3389,3986,4899,5000,5009,5051,5060,5101,5190," \
                        "5357,5432,5631,5666,5800,5900,5985,6000,6001,6646," \
                        "7070,8000,8008,8009,8080,8081,8443,8888,9100,9999," \
                        "10000,32768,49152,49153,49154,49155,49156,49157"

/* ─── Scan options ─── */
typedef struct _SCAN_OPTS {
    const char *targets;      /* Comma-separated IPs or CIDR (e.g. "10.0.0.1,10.0.0.0/24") */
    const char *ports;        /* Comma-separated ports or preset name */
    int         threads;      /* Concurrent connections (default 50) */
    int         timeoutMs;    /* Per-port connect timeout in ms (default 1000) */
    BOOL        grabBanner;   /* Attempt banner grab on open ports */
    int         bannerBytes;  /* Max bytes to read for banner (default 256) */
} SCAN_OPTS;

/* ─── Scan result per host:port ─── */
typedef struct _SCAN_RESULT {
    char    host[64];
    USHORT  port;
    BOOL    open;
    char    banner[512];    /* Service banner (if grabbed) */
    int     bannerLen;
    DWORD   responseMs;     /* Time to connect in milliseconds */
} SCAN_RESULT;

/* ─── Callback for each result (called from scan threads) ─── */
typedef void (*SCAN_CALLBACK)(const SCAN_RESULT *result, void *ctx);

/* ─── Scan context (returned by portscan_start, used to track progress) ─── */
typedef struct _SCAN_CTX {
    int      totalTargets;
    int      totalPorts;
    int      scanned;
    int      openPorts;
    BOOL     running;
    BOOL     cancelled;
} SCAN_CTX;

/*
 * Run a port scan synchronously (blocks until complete).
 * Results are delivered via callback as they're found.
 *
 * Also writes structured TLV output to outBuf for returning
 * to the operator as a table.
 *
 * Returns total number of open ports found.
 */
int portscan_run(const SCAN_OPTS *opts, SCAN_CALLBACK callback, void *cbCtx,
                 unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Parse a CIDR notation string into a list of IPs.
 * e.g. "10.0.0.0/24" → 10.0.0.1 through 10.0.0.254
 *
 * ipList: caller-allocated array of char[64]
 * maxIps: size of ipList
 * Returns number of IPs generated.
 */
int portscan_expand_cidr(const char *cidr, char ipList[][64], int maxIps);

/*
 * Parse a port specification string into an array of port numbers.
 * Supports: "80,443,8080" or "1-1024" or mixed "22,80,443,8000-9000"
 *
 * ports: caller-allocated USHORT array
 * maxPorts: size of ports array
 * Returns number of ports parsed.
 */
int portscan_parse_ports(const char *portSpec, USHORT *ports, int maxPorts);

#endif /* PORTSCAN_H */
