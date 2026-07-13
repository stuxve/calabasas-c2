"""
AES-256-GCM encryption/decryption.

Nonce format: 12 bytes = 4-byte agent_id_prefix + 8-byte counter.
Agent uses even counters, server uses odd counters.
"""

import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32


def encrypt(key: bytes, nonce: bytes, plaintext: bytes,
            associated_data: bytes = b"") -> bytes:
    """
    Encrypt with AES-256-GCM.
    Returns: NONCE (12B) + CIPHERTEXT + TAG (16B).
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    # cryptography lib appends the tag to ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data or None)

    return nonce + ct_with_tag


def decrypt(key: bytes, data: bytes,
            associated_data: bytes = b"") -> bytes:
    """
    Decrypt AES-256-GCM.
    Input: NONCE (12B) + CIPHERTEXT + TAG (16B).
    Returns plaintext.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError(f"Data too short: {len(data)} < {NONCE_SIZE + TAG_SIZE}")

    nonce = data[:NONCE_SIZE]
    ct_with_tag = data[NONCE_SIZE:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_with_tag, associated_data or None)


def make_nonce(agent_id_prefix: bytes, counter: int) -> bytes:
    """
    Build a 12-byte nonce from a 4-byte agent ID prefix and 8-byte counter.
    """
    if len(agent_id_prefix) != 4:
        raise ValueError(f"Agent ID prefix must be 4 bytes, got {len(agent_id_prefix)}")
    return agent_id_prefix + struct.pack("<Q", counter)


def generate_key() -> bytes:
    """Generate a random 256-bit key."""
    import os
    return os.urandom(KEY_SIZE)
