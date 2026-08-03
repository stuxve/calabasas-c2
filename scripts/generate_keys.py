#!/usr/bin/env python3
"""
Generate RSA-2048 keypair for C2 key exchange and
self-signed TLS certificate for the HTTPS listener.

The RSA private key stays on the operator side.
The RSA public key (DER format) is embedded into agent builds.
The TLS cert/key are passed to the listener via --cert / --key.
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from client.crypto.rsa import generate_keypair, save_keypair


def generate_tls_cert(certs_dir: Path):
    """Generate a self-signed TLS certificate + private key for the HTTPS listener."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "C2"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("*"),
                x509.IPAddress(
                    __import__("ipaddress").IPv4Address("0.0.0.0")
                ),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = certs_dir / "server.pem"
    key_path = certs_dir / "server.key"

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    return cert_path, key_path


def main():
    base_dir = Path(__file__).parent.parent

    # ── RSA keypair for agent key exchange ──
    keys_dir = base_dir / "keys"
    keys_dir.mkdir(exist_ok=True)

    if not (keys_dir / "server_priv.pem").exists():
        private_key, public_key = generate_keypair()
        save_keypair(
            private_key,
            private_path=keys_dir / "server_priv.pem",
            public_path=keys_dir / "server_pub.pem",
        )
        print(f"[*] RSA-2048 keypair generated:")
        print(f"    Private: {keys_dir / 'server_priv.pem'}")
        print(f"    Public:  {keys_dir / 'server_pub.pem'}")
    else:
        print(f"[*] RSA keypair already exists — skipping")

    # ── TLS certificate for HTTPS listener ──
    certs_dir = base_dir / "certs"
    certs_dir.mkdir(exist_ok=True)

    cert_path, key_path = generate_tls_cert(certs_dir)
    print(f"[*] TLS self-signed certificate generated:")
    print(f"    Cert: {cert_path}")
    print(f"    Key:  {key_path}")
    print()
    print(f"[*] Start listener with TLS:")
    print(f"    python -m client.main --cert {cert_path} --key {key_path} --listen-port 80")


if __name__ == "__main__":
    main()
