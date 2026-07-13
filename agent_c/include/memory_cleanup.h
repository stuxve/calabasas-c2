/*
 * memory_cleanup.h — Secure memory cleanup after module execution.
 *
 * Zeroes and frees all sensitive data left in memory after BOF/assembly
 * execution: payload bytes, argument buffers, output buffers, decrypted
 * strings, and any heap allocations from the COFF loader.
 *
 * Also provides heap scrubbing for paranoid cleanup (overwrites freed
 * heap blocks with random data before release).
 */
#ifndef MEMORY_CLEANUP_H
#define MEMORY_CLEANUP_H

#include <windows.h>

/*
 * Secure-zero a memory region. Uses SecureZeroMemory (compiler barrier)
 * to prevent optimizer from eliding the zeroing.
 */
void mem_secure_zero(void *ptr, SIZE_T len);

/*
 * Secure-free: zero then free a heap allocation.
 * Uses GetProcessHeap().
 */
void mem_secure_free(void *ptr, SIZE_T len);

/*
 * Secure-free for VirtualAlloc'd memory: zero, then VirtualFree.
 */
void mem_secure_vfree(void *ptr, SIZE_T len);

/*
 * Wipe the COFF loader's output buffer.
 * Called after results have been sent back to the operator.
 */
void mem_cleanup_coff_output(void);

/*
 * Cleanup after BOF execution:
 *   - Zero all section allocations
 *   - Free section memory (VirtualFree)
 *   - Zero and free indirect symbol pointers
 *   - Zero the argument buffer
 *   - Zero the output buffer
 *
 * This is called automatically by the COFF loader after execution.
 * The parameters match the internal state of the loader.
 */
typedef struct _COFF_CLEANUP_CTX {
    void  **sectionAddrs;       /* Array of VirtualAlloc'd section bases */
    DWORD  *sectionSizes;       /* Corresponding sizes */
    int     numSections;
    void  **indirectPtrs;       /* Array of Marshal.AllocHGlobal'd __imp_ pointers */
    int     numIndirects;
    void   *argBuffer;          /* Pinned argument buffer */
    SIZE_T  argBufferLen;
} COFF_CLEANUP_CTX;

void mem_cleanup_coff(COFF_CLEANUP_CTX *ctx);

/*
 * Cleanup after assembly execution:
 *   - Zero the assembly bytes in memory
 *   - Zero the captured output
 */
void mem_cleanup_assembly(void *assemblyBytes, SIZE_T assemblyLen,
                           void *outputBuf, SIZE_T outputLen);

/*
 * Scrub the process heap: walk committed heap blocks and overwrite
 * free blocks with random data. This is expensive and should only
 * be used before agent exit or after highly sensitive operations.
 */
void mem_scrub_heap(void);

/*
 * Track an allocation for deferred cleanup.
 * When mem_flush_tracked() is called, all tracked allocations are
 * securely zeroed and freed.
 *
 * Useful for tracking many small allocations across a module's
 * execution without passing cleanup context everywhere.
 */
void mem_track(void *ptr, SIZE_T len, BOOL isVirtual);

/*
 * Flush all tracked allocations: secure-zero and free.
 */
void mem_flush_tracked(void);

#endif /* MEMORY_CLEANUP_H */
