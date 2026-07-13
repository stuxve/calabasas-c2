"""
Column value transforms for module output parsing.
"""

from datetime import datetime


def windows_filetime_to_datetime(val: str) -> str:
    """Convert Windows FILETIME (100ns since 1601-01-01) to readable datetime."""
    try:
        ft = int(val)
        if ft == 0 or ft == 0x7FFFFFFFFFFFFFFF:
            return "Never"
        timestamp = (ft - 116444736000000000) / 10000000
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return val


def uac_to_enabled_bool(val: str) -> str:
    """Parse userAccountControl bitmask."""
    try:
        uac = int(val)
        flags = []
        UAC_FLAGS = {
            0x0002: "ACCOUNTDISABLE",
            0x0010: "LOCKOUT",
            0x0020: "PASSWD_NOTREQD",
            0x0200: "NORMAL_ACCOUNT",
            0x10000: "DONT_EXPIRE_PASSWORD",
            0x400000: "DONT_REQ_PREAUTH",
            0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
        }
        for flag_val, flag_name in UAC_FLAGS.items():
            if uac & flag_val:
                flags.append(flag_name)
        disabled = bool(uac & 0x0002)
        return f"{'Disabled' if disabled else 'Enabled'} ({', '.join(flags)})"
    except (ValueError, TypeError):
        return val


def epoch_to_datetime(val: str) -> str:
    """Convert Unix epoch to readable datetime."""
    try:
        ts = int(val)
        if ts == 0:
            return "Never"
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError):
        return val


def sid_to_name(val: str) -> str:
    """Placeholder — SID resolution requires AD context."""
    return val


# Transform registry
TRANSFORMS = {
    "windows_filetime_to_datetime": windows_filetime_to_datetime,
    "uac_to_enabled_bool": uac_to_enabled_bool,
    "epoch_to_datetime": epoch_to_datetime,
    "sid_to_name": sid_to_name,
}


def apply_transform(transform_name: str, value: str) -> str:
    fn = TRANSFORMS.get(transform_name)
    return fn(value) if fn else value
