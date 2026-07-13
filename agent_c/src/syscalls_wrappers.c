/*
 * syscalls_wrappers.c — Build and cache trampolines for all syscalls.
 */
#include "syscalls.h"
#include "syscalls_wrappers.h"

SW_CACHE g_SwCache = {0};

int sw_init(void) {
    int failures = 0;

    struct {
        SYSCALL_ENTRY *entry;
        void **cache;
    } map[] = {
        { &g_SyscallTable.NtAllocateVirtualMemory,   &g_SwCache.NtAllocateVirtualMemory },
        { &g_SyscallTable.NtProtectVirtualMemory,    &g_SwCache.NtProtectVirtualMemory },
        { &g_SyscallTable.NtWriteVirtualMemory,      &g_SwCache.NtWriteVirtualMemory },
        { &g_SyscallTable.NtCreateThreadEx,          &g_SwCache.NtCreateThreadEx },
        { &g_SyscallTable.NtOpenProcess,             &g_SwCache.NtOpenProcess },
        { &g_SyscallTable.NtClose,                   &g_SwCache.NtClose },
        { &g_SyscallTable.NtQuerySystemInformation,  &g_SwCache.NtQuerySystemInformation },
        { &g_SyscallTable.NtQueryInformationProcess, &g_SwCache.NtQueryInformationProcess },
        { &g_SyscallTable.NtCreateSection,           &g_SwCache.NtCreateSection },
        { &g_SyscallTable.NtMapViewOfSection,        &g_SwCache.NtMapViewOfSection },
        { &g_SyscallTable.NtUnmapViewOfSection,      &g_SwCache.NtUnmapViewOfSection },
        { &g_SyscallTable.NtQueueApcThread,          &g_SwCache.NtQueueApcThread },
        { &g_SyscallTable.NtResumeThread,            &g_SwCache.NtResumeThread },
        { &g_SyscallTable.NtSuspendThread,           &g_SwCache.NtSuspendThread },
        { &g_SyscallTable.NtGetContextThread,        &g_SwCache.NtGetContextThread },
        { &g_SyscallTable.NtSetContextThread,        &g_SwCache.NtSetContextThread },
        { &g_SyscallTable.NtFreeVirtualMemory,       &g_SwCache.NtFreeVirtualMemory },
        { &g_SyscallTable.NtReadVirtualMemory,       &g_SwCache.NtReadVirtualMemory },
        { &g_SyscallTable.NtWaitForSingleObject,     &g_SwCache.NtWaitForSingleObject },
        { &g_SyscallTable.NtDelayExecution,          &g_SwCache.NtDelayExecution },
        { &g_SyscallTable.NtSetInformationThread,    &g_SwCache.NtSetInformationThread },
    };

    int count = sizeof(map) / sizeof(map[0]);
    for (int i = 0; i < count; i++) {
        *map[i].cache = syscall_make_trampoline(map[i].entry);
        if (!*map[i].cache)
            failures++;
    }

    return failures;
}

void sw_cleanup(void) {
    void **ptrs = (void **)&g_SwCache;
    int count = sizeof(SW_CACHE) / sizeof(void *);
    for (int i = 0; i < count; i++) {
        if (ptrs[i]) {
            syscall_free_trampoline(ptrs[i]);
            ptrs[i] = NULL;
        }
    }
}
