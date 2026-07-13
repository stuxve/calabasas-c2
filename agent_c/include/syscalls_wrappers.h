/*
 * syscalls_wrappers.h — Typed wrappers around indirect syscalls.
 *
 * Each wrapper pre-builds a trampoline (cached) and calls it with
 * the correct argument types. This avoids varargs issues and gives
 * the compiler full type checking.
 *
 * Usage:
 *   #include "syscalls_wrappers.h"
 *   // After syscall_init():
 *   NTSTATUS st = Sw_NtAllocateVirtualMemory(hProc, &base, 0, &sz, flags, prot);
 */
#ifndef SYSCALLS_WRAPPERS_H
#define SYSCALLS_WRAPPERS_H

#include "syscalls.h"

/* ─── Cached trampoline pointers (set by sw_init) ─── */
typedef struct _SW_CACHE {
    void *NtAllocateVirtualMemory;
    void *NtProtectVirtualMemory;
    void *NtWriteVirtualMemory;
    void *NtCreateThreadEx;
    void *NtOpenProcess;
    void *NtClose;
    void *NtQuerySystemInformation;
    void *NtQueryInformationProcess;
    void *NtCreateSection;
    void *NtMapViewOfSection;
    void *NtUnmapViewOfSection;
    void *NtQueueApcThread;
    void *NtResumeThread;
    void *NtSuspendThread;
    void *NtGetContextThread;
    void *NtSetContextThread;
    void *NtFreeVirtualMemory;
    void *NtReadVirtualMemory;
    void *NtWaitForSingleObject;
    void *NtDelayExecution;
    void *NtSetInformationThread;
} SW_CACHE;

extern SW_CACHE g_SwCache;

/* Initialize cached trampolines. Call after syscall_init(). */
int sw_init(void);

/* Cleanup all trampolines. */
void sw_cleanup(void);

/* ─── Typed function pointer typedefs ─── */

typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *pfnNtOpenProcess)(
    PHANDLE, ACCESS_MASK, PVOID, PVOID);
typedef NTSTATUS (NTAPI *pfnNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtCreateSection)(
    PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pfnNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfnNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *pfnNtQueueApcThread)(
    HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI *pfnNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *pfnNtSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *pfnNtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *pfnNtSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *pfnNtFreeVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *pfnNtReadVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pfnNtWaitForSingleObject)(
    HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pfnNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pfnNtSetInformationThread)(
    HANDLE, ULONG, PVOID, ULONG);

/* ─── Convenience macros ─── */
/* Falls back to direct ntdll call if trampoline unavailable */

#define Sw_NtAllocateVirtualMemory(...) \
    (g_SwCache.NtAllocateVirtualMemory \
        ? ((pfnNtAllocateVirtualMemory)g_SwCache.NtAllocateVirtualMemory)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtProtectVirtualMemory(...) \
    (g_SwCache.NtProtectVirtualMemory \
        ? ((pfnNtProtectVirtualMemory)g_SwCache.NtProtectVirtualMemory)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtWriteVirtualMemory(...) \
    (g_SwCache.NtWriteVirtualMemory \
        ? ((pfnNtWriteVirtualMemory)g_SwCache.NtWriteVirtualMemory)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtCreateThreadEx(...) \
    (g_SwCache.NtCreateThreadEx \
        ? ((pfnNtCreateThreadEx)g_SwCache.NtCreateThreadEx)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtOpenProcess(...) \
    (g_SwCache.NtOpenProcess \
        ? ((pfnNtOpenProcess)g_SwCache.NtOpenProcess)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtClose(h) \
    (g_SwCache.NtClose \
        ? ((pfnNtClose)g_SwCache.NtClose)(h) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtQuerySystemInformation(...) \
    (g_SwCache.NtQuerySystemInformation \
        ? ((pfnNtQuerySystemInformation)g_SwCache.NtQuerySystemInformation)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtCreateSection(...) \
    (g_SwCache.NtCreateSection \
        ? ((pfnNtCreateSection)g_SwCache.NtCreateSection)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtMapViewOfSection(...) \
    (g_SwCache.NtMapViewOfSection \
        ? ((pfnNtMapViewOfSection)g_SwCache.NtMapViewOfSection)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtUnmapViewOfSection(...) \
    (g_SwCache.NtUnmapViewOfSection \
        ? ((pfnNtUnmapViewOfSection)g_SwCache.NtUnmapViewOfSection)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtQueueApcThread(...) \
    (g_SwCache.NtQueueApcThread \
        ? ((pfnNtQueueApcThread)g_SwCache.NtQueueApcThread)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtResumeThread(...) \
    (g_SwCache.NtResumeThread \
        ? ((pfnNtResumeThread)g_SwCache.NtResumeThread)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtSuspendThread(...) \
    (g_SwCache.NtSuspendThread \
        ? ((pfnNtSuspendThread)g_SwCache.NtSuspendThread)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtGetContextThread(...) \
    (g_SwCache.NtGetContextThread \
        ? ((pfnNtGetContextThread)g_SwCache.NtGetContextThread)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtSetContextThread(...) \
    (g_SwCache.NtSetContextThread \
        ? ((pfnNtSetContextThread)g_SwCache.NtSetContextThread)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtFreeVirtualMemory(...) \
    (g_SwCache.NtFreeVirtualMemory \
        ? ((pfnNtFreeVirtualMemory)g_SwCache.NtFreeVirtualMemory)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtReadVirtualMemory(...) \
    (g_SwCache.NtReadVirtualMemory \
        ? ((pfnNtReadVirtualMemory)g_SwCache.NtReadVirtualMemory)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtWaitForSingleObject(...) \
    (g_SwCache.NtWaitForSingleObject \
        ? ((pfnNtWaitForSingleObject)g_SwCache.NtWaitForSingleObject)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtDelayExecution(...) \
    (g_SwCache.NtDelayExecution \
        ? ((pfnNtDelayExecution)g_SwCache.NtDelayExecution)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#define Sw_NtSetInformationThread(...) \
    (g_SwCache.NtSetInformationThread \
        ? ((pfnNtSetInformationThread)g_SwCache.NtSetInformationThread)(__VA_ARGS__) \
        : (NTSTATUS)0xC0000001)

#endif /* SYSCALLS_WRAPPERS_H */
