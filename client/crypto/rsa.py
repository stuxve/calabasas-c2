"""
RSA key management for initial key exchange envelope encryption.

The agent has the RSA public key baked in at compile time.
The server holds the private key for decryption.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from pathlib import Path
from typing import Tuple


KEY_SIZE = 2048


def generate_keypair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA-2048 keypair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
    )
    return private_key, private_key.public_key()


def save_keypair(private_key: rsa.RSAPrivateKey, private_path: Path, public_path: Path):
    """Save RSA keypair to PEM files."""
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    """Load RSA private key from PEM file."""
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    """Load RSA public key from PEM file."""
    return serialization.load_pem_public_key(path.read_bytes())


def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """Encrypt with RSA-OAEP-SHA256."""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decrypt with RSA-OAEP-SHA256."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def public_key_to_der(public_key: rsa.RSAPublicKey) -> bytes:
    """Export public key as DER bytes (for embedding in agent)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
