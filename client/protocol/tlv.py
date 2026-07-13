"""
TLV (Type-Length-Value) builder and parser.

Wire format per entry:
    TYPE  (2 bytes, LE uint16)
    LEN   (4 bytes, LE uint32)
    VALUE (LEN bytes)
"""

import struct
from typing import Iterator, NamedTuple, Optional

from .commands import TlvType


class TlvEntry(NamedTuple):
    type: int
    value: bytes


class TlvBuilder:
    """Construct a TLV byte buffer incrementally."""

    def __init__(self):
        self._buf = bytearray()

    def add_raw(self, tlv_type: int, value: bytes) -> "TlvBuilder":
        self._buf += struct.pack("<HI", tlv_type, len(value))
        self._buf += value
        return self

    # ─── Typed convenience methods ───

    def add_bytes(self, tlv_type: int, value: bytes) -> "TlvBuilder":
        return self.add_raw(tlv_type, value)

    def add_string(self, tlv_type: int, value: str) -> "TlvBuilder":
        return self.add_raw(tlv_type, value.encode("utf-8"))

    def add_uint32(self, tlv_type: int, value: int) -> "TlvBuilder":
        return self.add_raw(tlv_type, struct.pack("<I", value & 0xFFFFFFFF))

    def add_uint16(self, tlv_type: int, value: int) -> "TlvBuilder":
        return self.add_raw(tlv_type, struct.pack("<H", value & 0xFFFF))

    def add_uint8(self, tlv_type: int, value: int) -> "TlvBuilder":
        return self.add_raw(tlv_type, struct.pack("<B", value & 0xFF))

    def add_uint64(self, tlv_type: int, value: int) -> "TlvBuilder":
        return self.add_raw(tlv_type, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def add_uuid(self, tlv_type: int, value: bytes) -> "TlvBuilder":
        """Add a 16-byte UUID."""
        if len(value) != 16:
            raise ValueError(f"UUID must be 16 bytes, got {len(value)}")
        return self.add_raw(tlv_type, value)

    def add_nested(self, tlv_type: int, nested: "TlvBuilder") -> "TlvBuilder":
        """Embed another TlvBuilder's content as the value of a TLV entry."""
        return self.add_raw(tlv_type, nested.build())

    def build(self) -> bytes:
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)


class TlvParser:
    """Parse a TLV byte buffer into entries."""

    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    def __iter__(self) -> Iterator[TlvEntry]:
        return self

    def __next__(self) -> TlvEntry:
        if self._offset >= len(self._data):
            raise StopIteration

        if self._offset + 6 > len(self._data):
            raise ValueError(
                f"Truncated TLV header at offset {self._offset}: "
                f"need 6 bytes, have {len(self._data) - self._offset}"
            )

        tlv_type, length = struct.unpack_from("<HI", self._data, self._offset)
        self._offset += 6

        if self._offset + length > len(self._data):
            raise ValueError(
                f"Truncated TLV value at offset {self._offset}: "
                f"type=0x{tlv_type:04X}, declared length={length}, "
                f"available={len(self._data) - self._offset}"
            )

        value = self._data[self._offset : self._offset + length]
        self._offset += length
        return TlvEntry(type=tlv_type, value=value)

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    def reset(self):
        self._offset = 0


def iter_tlv(data: bytes) -> Iterator[TlvEntry]:
    """Iterate over TLV entries in a byte buffer."""
    return TlvParser(data)


def find_tlv(data: bytes, tlv_type: int) -> Optional[bytes]:
    """Find the first TLV entry of the given type and return its value."""
    for entry in iter_tlv(data):
        if entry.type == tlv_type:
            return entry.value
    return None


def find_tlv_string(data: bytes, tlv_type: int) -> Optional[str]:
    val = find_tlv(data, tlv_type)
    return val.decode("utf-8") if val is not None else None


def find_tlv_uint32(data: bytes, tlv_type: int) -> Optional[int]:
    val = find_tlv(data, tlv_type)
    if val is not None and len(val) >= 4:
        return struct.unpack("<I", val[:4])[0]
    return None


def find_tlv_uint8(data: bytes, tlv_type: int) -> Optional[int]:
    val = find_tlv(data, tlv_type)
    if val is not None and len(val) >= 1:
        return val[0]
    return None
