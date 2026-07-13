/*
 * net_enum.c — Network enumeration via iphlpapi.dll / dnsapi.dll.
 *
 * No child processes. All data from kernel tables via IP Helper API.
 */
#include "agent.h"
#include "net_enum.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* ─── Helpers ─── */

static int _append(unsigned char *buf, DWORD bufSize, DWORD *off, const char *fmt, ...) {
    if (!buf || !off || *off >= bufSize) return 0;
    va_list args;
    va_start(args, fmt);
    int w = _vsnprintf((char *)buf + *off, bufSize - *off, fmt, args);
    va_end(args);
    if (w > 0) *off += w;
    return w > 0 ? w : 0;
}

static const char *_tcp_state(DWORD state) {
    switch (state) {
        case 1:  return "CLOSED";
        case 2:  return "LISTEN";
        case 3:  return "SYN_SENT";
        case 4:  return "SYN_RCVD";
        case 5:  return "ESTAB";
        case 6:  return "FIN_WAIT1";
        case 7:  return "FIN_WAIT2";
        case 8:  return "CLOSE_WAIT";
        case 9:  return "CLOSING";
        case 10: return "LAST_ACK";
        case 11: return "TIME_WAIT";
        case 12: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  TCP connections
 * ═══════════════════════════════════════════════════════════════════ */

int net_enum_tcp(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "PROTO\tLOCAL_ADDR\tREMOTE_ADDR\tSTATE\tPID\n");

    /* IPv4 TCP */
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size > 0) {
        MIB_TCPTABLE_OWNER_PID *table =
            (MIB_TCPTABLE_OWNER_PID *)HeapAlloc(GetProcessHeap(), 0, size);
        if (table) {
            if (GetExtendedTcpTable(table, &size, TRUE, AF_INET,
                                     TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            {
                for (DWORD i = 0; i < table->dwNumEntries; i++) {
                    MIB_TCPROW_OWNER_PID *row = &table->table[i];
                    struct in_addr localA, remoteA;
                    localA.s_addr = row->dwLocalAddr;
                    remoteA.s_addr = row->dwRemoteAddr;

                    char localStr[32], remoteStr[32];
                    strncpy(localStr, inet_ntoa(localA), 31);
                    strncpy(remoteStr, inet_ntoa(remoteA), 31);

                    _append(outBuf, outBufSize, &off, "TCPv4\t%s:%u\t%s:%u\t%s\t%u\n",
                            localStr, ntohs((u_short)row->dwLocalPort),
                            remoteStr, ntohs((u_short)row->dwRemotePort),
                            _tcp_state(row->dwState), row->dwOwningPid);
                    total++;
                }
            }
            HeapFree(GetProcessHeap(), 0, table);
        }
    }

    /* IPv6 TCP */
    size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size > 0) {
        MIB_TCP6TABLE_OWNER_PID *table6 =
            (MIB_TCP6TABLE_OWNER_PID *)HeapAlloc(GetProcessHeap(), 0, size);
        if (table6) {
            if (GetExtendedTcpTable(table6, &size, TRUE, AF_INET6,
                                     TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            {
                for (DWORD i = 0; i < table6->dwNumEntries; i++) {
                    MIB_TCP6ROW_OWNER_PID *row = &table6->table[i];
                    char localStr[INET6_ADDRSTRLEN], remoteStr[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, row->ucLocalAddr, localStr, sizeof(localStr));
                    inet_ntop(AF_INET6, row->ucRemoteAddr, remoteStr, sizeof(remoteStr));

                    _append(outBuf, outBufSize, &off, "TCPv6\t[%s]:%u\t[%s]:%u\t%s\t%u\n",
                            localStr, ntohs((u_short)row->dwLocalPort),
                            remoteStr, ntohs((u_short)row->dwRemotePort),
                            _tcp_state(row->dwState), row->dwOwningPid);
                    total++;
                }
            }
            HeapFree(GetProcessHeap(), 0, table6);
        }
    }

    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  UDP listeners
 * ═══════════════════════════════════════════════════════════════════ */

int net_enum_udp(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "PROTO\tLOCAL_ADDR\tPID\n");

    /* IPv4 UDP */
    DWORD size = 0;
    GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size > 0) {
        MIB_UDPTABLE_OWNER_PID *table =
            (MIB_UDPTABLE_OWNER_PID *)HeapAlloc(GetProcessHeap(), 0, size);
        if (table) {
            if (GetExtendedUdpTable(table, &size, TRUE, AF_INET,
                                     UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
            {
                for (DWORD i = 0; i < table->dwNumEntries; i++) {
                    MIB_UDPROW_OWNER_PID *row = &table->table[i];
                    struct in_addr a;
                    a.s_addr = row->dwLocalAddr;

                    _append(outBuf, outBufSize, &off, "UDPv4\t%s:%u\t%u\n",
                            inet_ntoa(a), ntohs((u_short)row->dwLocalPort),
                            row->dwOwningPid);
                    total++;
                }
            }
            HeapFree(GetProcessHeap(), 0, table);
        }
    }

    /* IPv6 UDP */
    size = 0;
    GetExtendedUdpTable(NULL, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (size > 0) {
        MIB_UDP6TABLE_OWNER_PID *table6 =
            (MIB_UDP6TABLE_OWNER_PID *)HeapAlloc(GetProcessHeap(), 0, size);
        if (table6) {
            if (GetExtendedUdpTable(table6, &size, TRUE, AF_INET6,
                                     UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
            {
                for (DWORD i = 0; i < table6->dwNumEntries; i++) {
                    MIB_UDP6ROW_OWNER_PID *row = &table6->table[i];
                    char addrStr[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, row->ucLocalAddr, addrStr, sizeof(addrStr));

                    _append(outBuf, outBufSize, &off, "UDPv6\t[%s]:%u\t%u\n",
                            addrStr, ntohs((u_short)row->dwLocalPort),
                            row->dwOwningPid);
                    total++;
                }
            }
            HeapFree(GetProcessHeap(), 0, table6);
        }
    }

    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  ARP table
 * ═══════════════════════════════════════════════════════════════════ */

int net_enum_arp(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "IP_ADDR\tMAC_ADDR\tTYPE\tIF_INDEX\n");

    DWORD size = 0;
    GetIpNetTable(NULL, &size, FALSE);
    if (size == 0) { *bytesWritten = off; return 0; }

    MIB_IPNETTABLE *table = (MIB_IPNETTABLE *)HeapAlloc(GetProcessHeap(), 0, size);
    if (!table) { *bytesWritten = off; return 0; }

    if (GetIpNetTable(table, &size, TRUE) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            MIB_IPNETROW *row = &table->table[i];
            struct in_addr a;
            a.s_addr = row->dwAddr;

            const char *type = "OTHER";
            switch (row->dwType) {
                case 1: type = "OTHER"; break;
                case 2: type = "INVALID"; break;
                case 3: type = "DYNAMIC"; break;
                case 4: type = "STATIC"; break;
            }

            _append(outBuf, outBufSize, &off,
                    "%s\t%02X-%02X-%02X-%02X-%02X-%02X\t%s\t%u\n",
                    inet_ntoa(a),
                    row->bPhysAddr[0], row->bPhysAddr[1], row->bPhysAddr[2],
                    row->bPhysAddr[3], row->bPhysAddr[4], row->bPhysAddr[5],
                    type, row->dwIndex);
            total++;
        }
    }

    HeapFree(GetProcessHeap(), 0, table);
    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Route table
 * ═══════════════════════════════════════════════════════════════════ */

int net_enum_routes(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "DESTINATION\tNETMASK\tGATEWAY\tIF_INDEX\tMETRIC\n");

    DWORD size = 0;
    GetIpForwardTable(NULL, &size, FALSE);
    if (size == 0) { *bytesWritten = off; return 0; }

    MIB_IPFORWARDTABLE *table =
        (MIB_IPFORWARDTABLE *)HeapAlloc(GetProcessHeap(), 0, size);
    if (!table) { *bytesWritten = off; return 0; }

    if (GetIpForwardTable(table, &size, TRUE) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            MIB_IPFORWARDROW *row = &table->table[i];
            struct in_addr dest, mask, gw;
            dest.s_addr = row->dwForwardDest;
            mask.s_addr = row->dwForwardMask;
            gw.s_addr = row->dwForwardNextHop;

            char destStr[32], maskStr[32], gwStr[32];
            strncpy(destStr, inet_ntoa(dest), 31);
            strncpy(maskStr, inet_ntoa(mask), 31);
            strncpy(gwStr, inet_ntoa(gw), 31);

            _append(outBuf, outBufSize, &off, "%s\t%s\t%s\t%u\t%u\n",
                    destStr, maskStr, gwStr,
                    row->dwForwardIfIndex, row->dwForwardMetric1);
            total++;
        }
    }

    HeapFree(GetProcessHeap(), 0, table);
    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  DNS client cache
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * DnsGetCacheDataTable is an undocumented export from dnsapi.dll.
 * It populates a linked list of DNS_CACHE_ENTRY structures.
 * We resolve it dynamically.
 */
typedef struct _DNS_CACHE_ENTRY {
    struct _DNS_CACHE_ENTRY *pNext;
    PWSTR                    pszName;
    WORD                     wType;
    WORD                     wDataLength;
    DWORD                    dwFlags;
} DNS_CACHE_ENTRY;

typedef BOOL (WINAPI *fn_DnsGetCacheDataTable)(DNS_CACHE_ENTRY **ppEntry);

static const char *_dns_type_name(WORD type) {
    switch (type) {
        case 1:   return "A";
        case 2:   return "NS";
        case 5:   return "CNAME";
        case 6:   return "SOA";
        case 12:  return "PTR";
        case 15:  return "MX";
        case 16:  return "TXT";
        case 28:  return "AAAA";
        case 33:  return "SRV";
        default:  return "OTHER";
    }
}

int net_enum_dns_cache(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    _append(outBuf, outBufSize, &off, "HOSTNAME\tTYPE\tDATA_LEN\n");

    HMODULE hDns = LoadLibraryW(L"dnsapi.dll");
    if (!hDns) { *bytesWritten = off; return 0; }

    fn_DnsGetCacheDataTable pDnsGetCache =
        (fn_DnsGetCacheDataTable)GetProcAddress(hDns, "DnsGetCacheDataTable");
    if (!pDnsGetCache) {
        FreeLibrary(hDns);
        *bytesWritten = off;
        return 0;
    }

    DNS_CACHE_ENTRY *head = NULL;
    if (pDnsGetCache(&head) && head) {
        DNS_CACHE_ENTRY *entry = head;
        while (entry) {
            if (entry->pszName) {
                char name[512];
                WideCharToMultiByte(CP_UTF8, 0, entry->pszName, -1,
                                     name, sizeof(name), NULL, NULL);
                _append(outBuf, outBufSize, &off, "%s\t%s\t%u\n",
                        name, _dns_type_name(entry->wType), entry->wDataLength);
                total++;
            }
            entry = entry->pNext;
        }
    }

    /* Note: the cache entries are freed by the system, we don't free them */
    FreeLibrary(hDns);
    *bytesWritten = off;
    return total;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Network interfaces
 * ═══════════════════════════════════════════════════════════════════ */

int net_enum_interfaces(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten) {
    if (!outBuf || !bytesWritten) return 0;
    *bytesWritten = 0;
    DWORD off = 0;
    int total = 0;

    DWORD flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    DWORD size = 0;
    GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &size);
    if (size == 0) return 0;

    IP_ADAPTER_ADDRESSES *addrs =
        (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), 0, size);
    if (!addrs) return 0;

    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addrs, &size) != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, addrs);
        return 0;
    }

    IP_ADAPTER_ADDRESSES *cur = addrs;
    while (cur) {
        /* Skip loopback and tunnel adapters */
        if (cur->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            cur = cur->Next;
            continue;
        }

        char name[256];
        WideCharToMultiByte(CP_UTF8, 0, cur->FriendlyName, -1,
                             name, sizeof(name), NULL, NULL);

        const char *status = "DOWN";
        if (cur->OperStatus == IfOperStatusUp) status = "UP";

        /* MAC address */
        char mac[32] = "(none)";
        if (cur->PhysicalAddressLength == 6) {
            _snprintf(mac, sizeof(mac), "%02X-%02X-%02X-%02X-%02X-%02X",
                      cur->PhysicalAddress[0], cur->PhysicalAddress[1],
                      cur->PhysicalAddress[2], cur->PhysicalAddress[3],
                      cur->PhysicalAddress[4], cur->PhysicalAddress[5]);
        }

        _append(outBuf, outBufSize, &off,
                "\n=== %s [%s] MAC: %s ===\n", name, status, mac);

        /* DNS suffix */
        if (cur->DnsSuffix && cur->DnsSuffix[0]) {
            char suffix[256];
            WideCharToMultiByte(CP_UTF8, 0, cur->DnsSuffix, -1,
                                 suffix, sizeof(suffix), NULL, NULL);
            _append(outBuf, outBufSize, &off, "  DNS Suffix: %s\n", suffix);
        }

        /* DHCP status */
        if (cur->Flags & IP_ADAPTER_DHCP_ENABLED)
            _append(outBuf, outBufSize, &off, "  DHCP: Enabled\n");
        else
            _append(outBuf, outBufSize, &off, "  DHCP: Disabled\n");

        /* IP addresses */
        IP_ADAPTER_UNICAST_ADDRESS *uni = cur->FirstUnicastAddress;
        while (uni) {
            char ipStr[INET6_ADDRSTRLEN] = {0};
            if (uni->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)uni->Address.lpSockaddr;
                inet_ntop(AF_INET, &sa->sin_addr, ipStr, sizeof(ipStr));
                _append(outBuf, outBufSize, &off, "  IPv4: %s/%u\n",
                        ipStr, uni->OnLinkPrefixLength);
            } else if (uni->Address.lpSockaddr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)uni->Address.lpSockaddr;
                inet_ntop(AF_INET6, &sa6->sin6_addr, ipStr, sizeof(ipStr));
                _append(outBuf, outBufSize, &off, "  IPv6: %s/%u\n",
                        ipStr, uni->OnLinkPrefixLength);
            }
            uni = uni->Next;
        }

        /* Gateway addresses */
        IP_ADAPTER_GATEWAY_ADDRESS *gw = cur->FirstGatewayAddress;
        while (gw) {
            char gwStr[INET6_ADDRSTRLEN] = {0};
            if (gw->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)gw->Address.lpSockaddr;
                inet_ntop(AF_INET, &sa->sin_addr, gwStr, sizeof(gwStr));
                _append(outBuf, outBufSize, &off, "  Gateway: %s\n", gwStr);
            }
            gw = gw->Next;
        }

        /* DNS servers */
        IP_ADAPTER_DNS_SERVER_ADDRESS *dns = cur->FirstDnsServerAddress;
        while (dns) {
            char dnsStr[INET6_ADDRSTRLEN] = {0};
            if (dns->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)dns->Address.lpSockaddr;
                inet_ntop(AF_INET, &sa->sin_addr, dnsStr, sizeof(dnsStr));
                _append(outBuf, outBufSize, &off, "  DNS: %s\n", dnsStr);
            }
            dns = dns->Next;
        }

        total++;
        cur = cur->Next;
    }

    HeapFree(GetProcessHeap(), 0, addrs);
    *bytesWritten = off;
    return total;
}
