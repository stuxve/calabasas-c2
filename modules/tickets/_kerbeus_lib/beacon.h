/*
 * beacon.h — Kerbeus-BOF compatibility wrapper for calabasas-c2.
 *
 * Kerbeus-BOF's _include/ files do `#include "beacon.h"` expecting the
 * Cobalt Strike Beacon API header.  This wrapper pulls in calabasas-c2's
 * beacon_compat.h (which supplies the runtime-resolved declarations) and
 * adds the few extra declarations that Kerbeus-BOF relies on but
 * calabasas-c2 doesn't ship.
 *
 * The idea: keep ALL Kerbeus-BOF library code unmodified.
 */
#ifndef KERBEUS_BEACON_WRAPPER_H
#define KERBEUS_BEACON_WRAPPER_H

/* calabasas-c2's canonical BOF header */
#include "beacon_compat.h"

/* ─── Extra declarations expected by Kerbeus-BOF ─── */

/*
 * formatp — Kerbeus-BOF's code references the struct type even though
 * it never actually calls BeaconFormat* functions in the modules we use.
 * Provide the typedef so compilation succeeds.
 */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

/* BeaconDataPtr — used by some Kerbeus decode paths */
DECLSPEC_IMPORT char * __cdecl BeaconDataPtr(datap *parser, int size);

/* GetModuleHandleA / LoadLibraryA / GetProcAddress — Kerbeus-BOF's
 * LoadFunc() calls these directly (not via KERNEL32$ prefix) because
 * they're needed before the COFF import table is fully usable.
 * Our COFF loader resolves KERNEL32$ imports, so alias them. */
#define GetModuleHandleA  KERNEL32$GetModuleHandleA
#define LoadLibraryA      KERNEL32$LoadLibraryA
#define GetProcAddress    KERNEL32$GetProcAddress

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

#endif /* KERBEUS_BEACON_WRAPPER_H */
