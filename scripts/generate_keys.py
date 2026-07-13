#!/usr/bin/env python3
"""
Generate RSA-2048 keypair for C2 key exchange.

The private key stays on the operator side.
The public key (DER format) is embedded into agent builds.
"""

import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from client.crypto.rsa import generate_keypair, save_keypair


def main():
    keys_dir = Path(__file__).parent.parent / "keys"
    keys_dir.mkdir(exist_ok=True)

    private_key, public_key = generate_keypair()
    save_keypair(
        private_key,
        private_path=keys_dir / "server_priv.pem",
        public_path=keys_dir / "server_pub.pem",
    )

    print(f"[*] RSA-2048 keypair generated:")
    print(f"    Private: {keys_dir / 'server_priv.pem'}")
    print(f"    Public:  {keys_dir / 'server_pub.pem'}")


if __name__ == "__main__":
    main()
