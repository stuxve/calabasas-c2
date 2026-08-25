"""
external_bof.py — import BOFs written for other frameworks (CobaltStrike,
TrustedSec CS-SA, Havoc, Nighthawk, plain COFF) into our registry as
first-class ModuleDefinition entries.

Once a BOF is registered here, everything else the CLI does with modules
(tab-completion of the module name, tab-completion of --arg flags,
`modules list`, `help <name>` panel, task dispatch) works with no
per-BOF plumbing — the registry is the single source of truth.

Three ways an external BOF can be described:

  1. Sibling `module.yaml` — same schema our native modules use. Preferred.
  2. Sibling `.cna` (Aggressor Script) — we parse `beacon_command_register`
     and `bof_pack(...)` to synthesize arguments. Best-effort; anything the
     regex misses can be corrected by writing a `module.yaml` next to it.
  3. Explicit CLI args to `bof-import`: --name, --args z,z,i, --desc "…".

Directory convention for auto-discovery:

  modules/external/<name>/<name>.x64.o
  modules/external/<name>/<name>.x86.o          (optional)
  modules/external/<name>/module.yaml           (any of these three)
  modules/external/<name>/<name>.cna
  modules/external/<name>/manifest.json

The `bof-import` runtime command drops files into that same layout so
imports survive across restarts (the startup discovery picks them up).
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from .module_registry import (
    ArgumentDef,
    Compatibility,
    ModuleDefinition,
    ManifestError,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def build_module_from_directory(dir_path: Path) -> ModuleDefinition:
    """
    Look at a directory containing an external BOF and produce a
    ModuleDefinition. The directory must contain at least one COFF file
    (<name>.x64.o or <name>.x86.o). Argument metadata comes from, in
    priority order: module.yaml, manifest.json, <name>.cna.
    """
    name = dir_path.name
    coff = _find_coff(dir_path, name)
    if coff is None:
        raise ManifestError(f"No .x64.o / .x86.o found in {dir_path}")

    # Try each metadata source in order.
    manifest_yaml = dir_path / "module.yaml"
    manifest_json = dir_path / "manifest.json"
    cna = _find_cna(dir_path, name)

    if manifest_yaml.exists():
        return _from_yaml(manifest_yaml, dir_path, coff, name)
    if manifest_json.exists():
        return _from_json(manifest_json, dir_path, coff, name)
    if cna is not None:
        return _from_cna(cna, dir_path, coff, name)

    # No metadata at all — register with an empty argument list. The
    # operator can still call the module and pass args via `bof <path>`
    # style if they know the pack format.
    return _bare_module(name, dir_path, coff)


def build_module_from_ofile(
    ofile: Path,
    *,
    name: Optional[str] = None,
    args_spec: Optional[str] = None,
    description: str = "",
    category: str = "external",
    external_root: Path,
) -> tuple[ModuleDefinition, Path]:
    """
    Import a single .o file that lives outside the modules tree.

    - Copies it under modules/external/<name>/<name>.x64.o so future
      startups auto-discover it.
    - Writes a module.yaml alongside so the arguments survive.
    - Returns (module_definition, persisted_dir).

    args_spec: comma-separated pack-type letters + names, e.g.
      "z:host,i:port,Z:command"     (lowercase = required, uppercase = optional)
      or a bare CobaltStrike-style format string "zzi" which maps to
      arg1..argN with generic names.
    """
    if not ofile.exists():
        raise ManifestError(f"BOF file not found: {ofile}")
    if ofile.suffix.lower() != ".o":
        raise ManifestError(f"Expected a .o file, got: {ofile.name}")

    if not name:
        # dcsync.x64.o → dcsync
        stem = ofile.stem
        if stem.endswith(".x64") or stem.endswith(".x86"):
            stem = stem.rsplit(".", 1)[0]
        name = stem

    arch = "x86" if ".x86" in ofile.name else "x64"
    dest_dir = external_root / name
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_o = dest_dir / f"{name}.{arch}.o"
    shutil.copy2(ofile, dest_o)

    arguments = _parse_args_spec(args_spec) if args_spec else []

    manifest = {
        "name": name,
        "category": category,
        "description": description or f"External BOF: {name}",
        "author": "imported",
        "version": "1.0.0",
        "execution_type": "bof",
        "bof_file": dest_o.name,
        "bof_arch": arch,
        "entry_point": "go",
        "compatibility": {
            "agent_min_version": "1.0.0",
            "dotnet_min_version": "native-c",
            "os": ["windows_server_2016", "windows_server_2019",
                   "windows_server_2022", "windows_10", "windows_11"],
        },
        "arguments": [
            {
                "name": a.name,
                "type": a.type,
                "required": a.required,
                "default": a.default,
                "description": a.description,
                "pack_type": a.pack_type,
            }
            for a in arguments
        ],
        "output_format": "raw",
        "opsec_level": "medium",
        "timeout": 300,
        "tags": ["external", "imported"],
    }
    (dest_dir / "module.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False)
    )

    # Now build the ModuleDefinition using the yaml we just wrote — that
    # way we go through the same code path as startup discovery.
    mod = _from_yaml(dest_dir / "module.yaml", dest_dir, dest_o, name)
    return mod, dest_dir


# ---------------------------------------------------------------------------
# Metadata parsers
# ---------------------------------------------------------------------------

def _from_yaml(yaml_path: Path, dir_path: Path,
               coff: Path, name: str) -> ModuleDefinition:
    raw = yaml.safe_load(yaml_path.read_text()) or {}
    return _finalize(raw, dir_path, coff, name)


def _from_json(json_path: Path, dir_path: Path,
               coff: Path, name: str) -> ModuleDefinition:
    raw = json.loads(json_path.read_text())
    # Normalize a couple of Havoc/Nighthawk-style fields to our schema.
    if "arguments" not in raw and "args" in raw:
        raw["arguments"] = raw["args"]
    if "bof_file" not in raw:
        raw["bof_file"] = coff.name
    return _finalize(raw, dir_path, coff, name)


def _from_cna(cna_path: Path, dir_path: Path,
              coff: Path, name: str) -> ModuleDefinition:
    """
    Extract what we can from an Aggressor Script. Two patterns matter:

      beacon_command_register("name", "short", "long")
        → description + argument hints from "long"

      bof_pack($1, "ziZ", $arg1, $arg2, $arg3)
        → argument pack format string. We treat this as authoritative.

    Anything more exotic (conditional packing, dynamic arg counts) is out
    of scope; a hand-written module.yaml overrides.
    """
    text = cna_path.read_text(errors="replace")

    description = ""
    m = re.search(
        r'beacon_command_register\s*\(\s*"[^"]*"\s*,'
        r'\s*"([^"]*)"\s*,\s*"([^"]*)"',
        text, re.DOTALL,
    )
    if m:
        short = m.group(1).strip()
        long_ = m.group(2).strip()
        description = short if not long_ else f"{short} — {long_}"

    fmt = None
    m = re.search(r'bof_pack\s*\(\s*\$1\s*,\s*"([a-zA-Z]+)"', text)
    if m:
        fmt = m.group(1)

    arguments: list[ArgumentDef] = []
    if fmt:
        for i, ch in enumerate(fmt, start=1):
            arg_type, pack_type = _cna_pack_char(ch)
            arguments.append(ArgumentDef(
                name=f"arg{i}",
                type=arg_type,
                pack_type=pack_type,
                required=(ch in "biszI"),  # lowercase / non-Z default = required
                default="" if arg_type == "string" else 0,
                description=f"arg{i} (CNA format '{ch}')",
            ))

    raw = {
        "name": name,
        "category": "external",
        "description": description or f"External BOF imported from {cna_path.name}",
        "author": "imported",
        "version": "1.0.0",
        "execution_type": "bof",
        "bof_file": coff.name,
        "bof_arch": "x86" if ".x86" in coff.name else "x64",
        "entry_point": "go",
        "arguments": [
            {
                "name": a.name,
                "type": a.type,
                "required": a.required,
                "default": a.default,
                "description": a.description,
                "pack_type": a.pack_type,
            }
            for a in arguments
        ],
        "output_format": "raw",
        "opsec_level": "medium",
        "tags": ["external", "cna", "imported"],
        "compatibility": {"dotnet_min_version": "native-c"},
    }
    return _finalize(raw, dir_path, coff, name)


def _bare_module(name: str, dir_path: Path, coff: Path) -> ModuleDefinition:
    raw = {
        "name": name,
        "category": "external",
        "description": f"External BOF: {name} (no manifest found)",
        "execution_type": "bof",
        "bof_file": coff.name,
        "bof_arch": "x86" if ".x86" in coff.name else "x64",
        "entry_point": "go",
        "arguments": [],
        "opsec_level": "medium",
        "compatibility": {"dotnet_min_version": "native-c"},
        "tags": ["external", "no-manifest"],
    }
    return _finalize(raw, dir_path, coff, name)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finalize(raw: dict, dir_path: Path,
              coff: Path, name: str) -> ModuleDefinition:
    """
    Turn a raw manifest dict into a validated ModuleDefinition.
    Reuses ModuleRegistry._parse_manifest logic via a lightweight inline
    build so we don't pull the whole registry class in here.
    """
    compat_raw = raw.get("compatibility", {}) or {}
    compat = Compatibility(
        agent_min_version=str(compat_raw.get("agent_min_version", "1.0.0")),
        agent_max_version=str(compat_raw.get("agent_max_version", "99.x")),
        dotnet_min_version=str(compat_raw.get("dotnet_min_version", "native-c")),
        dotnet_max_version=str(compat_raw.get("dotnet_max_version", "4.8.1")),
        os=compat_raw.get("os", []),
    )
    arguments = []
    for a in raw.get("arguments", []) or []:
        arguments.append(ArgumentDef(
            name=a["name"],
            type=a.get("type", "string"),
            pack_type=a.get("pack_type", _infer_pack(a.get("type", "string"))),
            required=a.get("required", False),
            default=a.get("default", ""),
            description=a.get("description", ""),
            example=a.get("example", ""),
        ))

    mod = ModuleDefinition(
        name=raw.get("name", name),
        category=raw.get("category", "external"),
        description=raw.get("description", "").strip(),
        author=raw.get("author", "imported"),
        version=raw.get("version", "1.0.0"),
        execution_type="bof",
        bof_file=raw.get("bof_file", coff.name),
        bof_arch=raw.get("bof_arch", "x64"),
        entry_point=raw.get("entry_point", "go"),
        compatibility=compat,
        arguments=arguments,
        output_format=raw.get("output_format", "raw"),
        opsec_level=raw.get("opsec_level", "medium"),
        opsec_notes=raw.get("opsec_notes", ""),
        timeout=raw.get("timeout", 300),
        tags=raw.get("tags", ["external"]),
        references=raw.get("references", []),
        base_path=dir_path,
    )
    _validate_coff(coff)
    return mod


def _find_coff(dir_path: Path, name: str) -> Optional[Path]:
    for candidate in (f"{name}.x64.o", f"{name}.x86.o"):
        p = dir_path / "bin" / candidate
        if p.exists():
            return p
        p = dir_path / candidate
        if p.exists():
            return p
    # fallback: any .o in the directory
    for p in list(dir_path.glob("*.o")) + list((dir_path / "bin").glob("*.o") if (dir_path / "bin").exists() else []):
        return p
    return None


def _find_cna(dir_path: Path, name: str) -> Optional[Path]:
    for candidate in (f"{name}.cna", "aggressor.cna", "script.cna"):
        p = dir_path / candidate
        if p.exists():
            return p
    for p in dir_path.glob("*.cna"):
        return p
    return None


def _validate_coff(path: Path) -> None:
    data = path.read_bytes()
    if len(data) < 20:
        raise ManifestError(f"COFF too small: {path}")
    machine = struct.unpack_from("<H", data, 0)[0]
    if machine not in (0x8664, 0x14C):
        raise ManifestError(
            f"Not a valid COFF object (magic=0x{machine:04X}): {path}"
        )


def _infer_pack(t: str) -> str:
    return {"string": "z", "int": "i", "short": "s", "bool": "i",
            "file_path": "z", "wstring": "Z", "bytes": "b"}.get(t, "z")


def _cna_pack_char(ch: str) -> tuple[str, str]:
    """Map one CobaltStrike bof_pack format char to (type_name, pack_type)."""
    table = {
        "b": ("int", "b"),   # binary data (with length prefix)
        "i": ("int", "i"),   # 4-byte int
        "s": ("short", "s"), # 2-byte short
        "z": ("string", "z"),# null-terminated ASCII
        "Z": ("wstring", "Z"),# null-terminated wide
    }
    return table.get(ch, ("string", "z"))


def _parse_args_spec(spec: str) -> list[ArgumentDef]:
    """
    Accept two shapes:

    "z:host,i:port,Z:command"     — explicit name per arg
    "zziZ"                         — CobaltStrike-style bare format string

    Case still matters in the bare form: lowercase = required, uppercase Z = optional wide-string.
    """
    args: list[ArgumentDef] = []
    if "," in spec or ":" in spec:
        for i, chunk in enumerate(spec.split(","), start=1):
            chunk = chunk.strip()
            if not chunk:
                continue
            if ":" in chunk:
                p, n = chunk.split(":", 1)
            else:
                p, n = chunk, f"arg{i}"
            t, pt = _cna_pack_char(p[0])
            args.append(ArgumentDef(
                name=n.strip(), type=t, pack_type=pt,
                required=(p[0] not in "Z"),
                default="" if t in ("string", "wstring") else 0,
                description=f"{n.strip()} (pack '{p}')",
            ))
    else:
        for i, ch in enumerate(spec, start=1):
            t, pt = _cna_pack_char(ch)
            args.append(ArgumentDef(
                name=f"arg{i}", type=t, pack_type=pt,
                required=(ch not in "Z"),
                default="" if t in ("string", "wstring") else 0,
                description=f"arg{i} (pack '{ch}')",
            ))
    return args
