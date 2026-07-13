"""
Argument packing compatible with Cobalt Strike's BeaconDataParse convention.

Pack types:
    'z' — UTF-8 string (4-byte LE length prefix including null, then bytes + null)
    'Z' — UTF-16LE string (4-byte LE length prefix including nulls, then bytes + double null)
    'i' — 32-bit LE unsigned integer
    's' — 16-bit LE unsigned short
    'b' — Binary blob (4-byte LE length prefix, then raw bytes)
"""

import struct
from typing import Any


def pack_args(arg_defs: list[dict], values: dict) -> bytes:
    """
    Pack arguments into a binary buffer matching BeaconDataParse format.

    arg_defs: list of dicts with keys 'name', 'pack_type', 'default'
    values: dict of argument name → value
    """
    buf = bytearray()

    for arg in arg_defs:
        name = arg["name"]
        pack_type = arg.get("pack_type", "z")
        val = values.get(name, arg.get("default", ""))

        if val is None:
            val = arg.get("default", "")

        if pack_type == "z":
            # UTF-8 string with null terminator
            encoded = str(val).encode("utf-8") + b"\x00"
            buf += struct.pack("<I", len(encoded))
            buf += encoded

        elif pack_type == "Z":
            # UTF-16LE string with double null terminator
            encoded = str(val).encode("utf-16-le") + b"\x00\x00"
            buf += struct.pack("<I", len(encoded))
            buf += encoded

        elif pack_type == "i":
            buf += struct.pack("<I", int(val) & 0xFFFFFFFF)

        elif pack_type == "s":
            buf += struct.pack("<H", int(val) & 0xFFFF)

        elif pack_type == "b":
            if isinstance(val, str):
                val = val.encode("utf-8")
            buf += struct.pack("<I", len(val))
            buf += val

        else:
            raise ValueError(f"Unknown pack_type '{pack_type}' for argument '{name}'")

    return bytes(buf)


def unpack_string(data: bytes, offset: int) -> tuple[str, int]:
    """Unpack a 'z' type string. Returns (string, new_offset)."""
    if offset + 4 > len(data):
        raise ValueError("Buffer too short for string length prefix")

    length = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    if offset + length > len(data):
        raise ValueError(f"Buffer too short for string data: need {length}, have {len(data) - offset}")

    raw = data[offset:offset + length]
    # Strip null terminator
    if raw and raw[-1:] == b"\x00":
        raw = raw[:-1]

    return raw.decode("utf-8", errors="replace"), offset + length


def unpack_int(data: bytes, offset: int) -> tuple[int, int]:
    """Unpack an 'i' type integer. Returns (value, new_offset)."""
    if offset + 4 > len(data):
        raise ValueError("Buffer too short for int")
    val = struct.unpack_from("<I", data, offset)[0]
    return val, offset + 4


def unpack_short(data: bytes, offset: int) -> tuple[int, int]:
    """Unpack an 's' type short. Returns (value, new_offset)."""
    if offset + 2 > len(data):
        raise ValueError("Buffer too short for short")
    val = struct.unpack_from("<H", data, offset)[0]
    return val, offset + 2


def unpack_binary(data: bytes, offset: int) -> tuple[bytes, int]:
    """Unpack a 'b' type binary blob. Returns (bytes, new_offset)."""
    if offset + 4 > len(data):
        raise ValueError("Buffer too short for binary length prefix")

    length = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    if offset + length > len(data):
        raise ValueError(f"Buffer too short for binary data: need {length}, have {len(data) - offset}")

    return data[offset:offset + length], offset + length
