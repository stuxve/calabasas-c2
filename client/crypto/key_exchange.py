"""
ECDH P-256 key exchange with HKDF key derivation.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from typing import Tuple


CURVE = ec.SECP256R1()
SHARED_SECRET_SIZE = 32
SESSION_KEY_SIZE = 32


def generate_keypair() -> Tuple[ec.EllipticCurvePrivateKey, bytes]:
    """
    Generate an ECDH P-256 keypair.
    Returns (private_key, public_key_bytes).
    Public key is 65 bytes (uncompressed point format).
    """
    private_key = ec.generate_private_key(CURVE)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return private_key, public_bytes


def derive_session_key(private_key: ec.EllipticCurvePrivateKey,
                       peer_public_bytes: bytes,
                       salt: bytes,
                       info: bytes = b"c2_session") -> bytes:
    """
    Perform ECDH key agreement and derive a 256-bit session key via HKDF-SHA256.

    private_key: our ECDH private key
    peer_public_bytes: peer's 65-byte uncompressed public key
    salt: typically the agent_id bytes
    info: context string for HKDF
    """
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, peer_public_bytes)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_SIZE,
        salt=salt,
        info=info,
    ).derive(shared_secret)

    return session_key


def load_public_key_bytes(public_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Load an ECDH public key from 65-byte uncompressed point format."""
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, public_bytes)
