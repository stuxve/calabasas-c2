/*
 * beacon_compat.h — BOF compatibility header.
 *
 * Include this in all BOF source files. Provides:
 *   - Beacon API function declarations
 *   - datap struct for argument parsing
 *   - DECLSPEC_IMPORT macro for DLL function resolution
 *   - Callback type constants
 *
 * BOFs compiled with this header work with our COFF loader,
 * which provides the Beacon API implementations.
 */
#ifndef BEACON_COMPAT_H
#define BEACON_COMPAT_H

#include <windows.h>

/* ─── Callback types ─── */
#define CALLBACK_OUTPUT       0x00
#define CALLBACK_OUTPUT_OEM   0x1e
#define CALLBACK_OUTPUT_UTF8  0x20
#define CALLBACK_ERROR        0x0d

/* ─── datap struct for argument parsing ─── */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

/* ─── Beacon API declarations ─── */
/* These are resolved by the COFF loader at load time */

DECLSPEC_IMPORT void   __cdecl BeaconPrintf(int type, const char *fmt, ...);
DECLSPEC_IMPORT void   __cdecl BeaconOutput(int type, const char *data, int len);
DECLSPEC_IMPORT void   __cdecl BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT char*  __cdecl BeaconDataExtract(datap *parser, int *out_size);
DECLSPEC_IMPORT int    __cdecl BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short  __cdecl BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int    __cdecl BeaconDataLength(datap *parser);
DECLSPEC_IMPORT BOOL   __cdecl BeaconIsAdmin(void);
DECLSPEC_IMPORT void   __cdecl BeaconRevertToken(void);
DECLSPEC_IMPORT void   __cdecl BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   __cdecl BeaconGetSpawnTo(BOOL x86, char *buffer, int length);

/* ─── Convenience macro for DLL function imports ─── */
/*
 * BOFs import Win32 functions using this convention:
 *   DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(...);
 *
 * The COFF loader resolves "KERNEL32$CreateFileW" by loading
 * kernel32.dll and calling GetProcAddress("CreateFileW").
 */

#endif /* BEACON_COMPAT_H */
