/*
 * testmod.c — Test module
 *
 * BOF module. Compiled with:
 *   x86_64-w64-mingw32-gcc -c -Os -fno-asynchronous-unwind-tables \
 *       -fno-ident -fpack-struct=8 -I../../shared/include \
 *       -o bin/testmod.x64.o src/testmod.c
 */
#include <windows.h>
#include "beacon_compat.h"

/* Add your DLL imports here, e.g.:
 * DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_initW(PWSTR, ULONG);
 */

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    /* Extract arguments */
    char *target = BeaconDataExtract(&parser, NULL);

    /* TODO: Implement module logic */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] testmod module executed");

    if (target && *target) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s", target);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Done");
}
