/*
 * net_enum.h — Network enumeration for pentest discovery.
 *
 * Enumerates local network state without spawning any processes:
 *   - TCP/UDP connection table (netstat equivalent)
 *   - ARP cache (neighbor discovery)
 *   - Route table
 *   - DNS client cache
 *   - Network interface listing with IPs
 *   - Wi-Fi profiles (SSID + auth info)
 *
 * All via iphlpapi.dll / dnsapi.dll P/Invoke.
 */
#ifndef NET_ENUM_H
#define NET_ENUM_H

#include <windows.h>

/*
 * Enumerate TCP connections (IPv4 + IPv6).
 * Equivalent to `netstat -ano -p tcp`.
 * Returns PID, local/remote addresses, state.
 */
int net_enum_tcp(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Enumerate UDP listeners (IPv4 + IPv6).
 * Equivalent to `netstat -ano -p udp`.
 */
int net_enum_udp(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Enumerate ARP table.
 * Shows IP-to-MAC mappings — useful for host discovery.
 */
int net_enum_arp(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Enumerate routing table.
 * Shows network, gateway, metric — useful for identifying
 * network segments and pivoting opportunities.
 */
int net_enum_routes(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Enumerate DNS client cache.
 * Shows recently resolved names — reveals internal hostnames
 * the user/system has contacted.
 */
int net_enum_dns_cache(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Enumerate network interfaces with IP addresses.
 * Shows adapter name, MAC, IPs, subnet, gateway, DHCP, DNS servers.
 */
int net_enum_interfaces(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

#endif /* NET_ENUM_H */
