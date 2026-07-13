"""
Packet framing: MAGIC (4B) + SIZE (4B) + MSG_ID (4B) + ENCRYPTED_PAYLOAD.

SIZE = total packet size including the 12-byte header.
"""

import struct
from typing import Tuple, Optional

from .commands import DEFAULT_MAGIC, HEADER_SIZE


def pack_packet(encrypted_payload: bytes, msg_id: int,
                magic: int = DEFAULT_MAGIC) -> bytes:
    """Frame an encrypted payload into a wire packet."""
    size = HEADER_SIZE + len(encrypted_payload)
    header = struct.pack("<III", magic, size, msg_id)
    return header + encrypted_payload


def unpack_packet_header(data: bytes) -> Tuple[int, int, int]:
    """
    Parse the 12-byte header from raw bytes.
    Returns (magic, size, msg_id).
    Raises ValueError if data is too short.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(
            f"Packet too short for header: {len(data)} < {HEADER_SIZE}"
        )
    return struct.unpack_from("<III", data, 0)


def validate_packet(data: bytes, expected_magic: int = DEFAULT_MAGIC) -> Optional[bytes]:
    """
    Validate a complete packet and return the encrypted payload.
    Returns None if magic doesn't match or packet is malformed.
    """
    if len(data) < HEADER_SIZE:
        return None

    magic, size, msg_id = unpack_packet_header(data)

    if magic != expected_magic:
        return None

    if size < HEADER_SIZE:
        return None

    if len(data) < size:
        return None  # Incomplete packet

    return data[HEADER_SIZE:size]


def pack_command(cmd: int, body: bytes) -> bytes:
    """
    Pack a decrypted payload: CMD (1B) + BODY_LEN (4B) + BODY.
    This is what gets encrypted before framing.
    """
    return struct.pack("<BI", cmd, len(body)) + body


def unpack_command(plaintext: bytes) -> Tuple[int, bytes]:
    """
    Unpack a decrypted payload into (cmd, body).
    """
    if len(plaintext) < 5:
        raise ValueError(f"Plaintext too short: {len(plaintext)} < 5")

    cmd = plaintext[0]
    body_len = struct.unpack_from("<I", plaintext, 1)[0]
    body = plaintext[5:5 + body_len]

    if len(body) < body_len:
        raise ValueError(
            f"Body truncated: declared {body_len}, got {len(body)}"
        )

    return cmd, body


class PacketAccumulator:
    """
    Accumulates raw bytes from a stream and yields complete packets.
    Useful for TCP channel where packets arrive in arbitrary chunks.
    """

    def __init__(self, expected_magic: int = DEFAULT_MAGIC):
        self._buf = bytearray()
        self._magic = expected_magic

    def feed(self, data: bytes) -> list[bytes]:
        """
        Feed raw bytes. Returns list of complete encrypted payloads.
        """
        self._buf.extend(data)
        packets = []

        while len(self._buf) >= HEADER_SIZE:
            magic, size, msg_id = struct.unpack_from("<III", self._buf, 0)

            if magic != self._magic:
                # Desync — try to find next magic
                idx = self._buf.find(struct.pack("<I", self._magic), 1)
                if idx == -1:
                    self._buf.clear()
                    break
                del self._buf[:idx]
                continue

            if size < HEADER_SIZE:
                # Invalid size — skip these 4 bytes
                del self._buf[:4]
                continue

            if len(self._buf) < size:
                break  # Wait for more data

            payload = bytes(self._buf[HEADER_SIZE:size])
            packets.append(payload)
            del self._buf[:size]

        return packets
