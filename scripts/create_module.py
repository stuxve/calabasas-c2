#!/usr/bin/env python3
"""
Scaffold a new BOF module from template.

Usage:
    python scripts/create_module.py --name enumgpos --category enumeration
    python scripts/create_module.py --name dumpsam --category credentials --opsec high

Creates:
    modules/<category>/<name>/
        module.yaml
        src/<name>.c
        bin/          (empty, for compiled .o files)
"""

import argparse
import sys
from datetime import date
from pathlib import Path

MODULE_YAML_TEMPLATE = """---
name: {name}
category: {category}
description: >
  {description}

author: "operator"
version: "1.0.0"
created: "{date}"

execution_type: bof
bof_file: {name}.x64.o
entry_point: go
bof_arch: x64

compatibility:
  agent_min_version: "1.0.0"
  agent_max_version: "99.x"
  dotnet_min_version: "4.0"
  dotnet_max_version: "4.8.1"

arguments:
  - name: target
    type: string
    pack_type: z
    required: false
    default: ""
    description: "Target host or domain. Empty = current."

output_format: raw
opsec_level: {opsec}
opsec_notes: >
  TODO: Document OPSEC considerations.

timeout: 120
tags: [{tags}]
references: []
mitre_attack_id: ""
"""

BOF_C_TEMPLATE = """/*
 * {name}.c — {description}
 *
 * BOF module. Compiled with:
 *   x86_64-w64-mingw32-gcc -c -Os -fno-asynchronous-unwind-tables \\
 *       -fno-ident -fpack-struct=8 -I../../shared/include \\
 *       -o bin/{name}.x64.o src/{name}.c
 */
#include <windows.h>
#include "beacon_compat.h"

/* Add your DLL imports here, e.g.:
 * DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_initW(PWSTR, ULONG);
 */

void go(char *args, int args_len) {{
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    /* Extract arguments */
    char *target = BeaconDataExtract(&parser, NULL);

    /* TODO: Implement module logic */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] {name} module executed");

    if (target && *target) {{
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s", target);
    }}

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Done");
}}
"""


def main():
    parser = argparse.ArgumentParser(description="Scaffold a new BOF module")
    parser.add_argument("--name", required=True, help="Module name (lowercase)")
    parser.add_argument("--category", required=True,
                        choices=["enumeration", "credentials", "lateral_movement",
                                 "privesc", "persistence", "evasion", "tickets",
                                 "utility"],
                        help="Module category")
    parser.add_argument("--description", default="TODO: Add description",
                        help="Short module description")
    parser.add_argument("--opsec", default="low", choices=["low", "medium", "high"],
                        help="OPSEC risk level")
    parser.add_argument("--tags", default="", help="Comma-separated tags")

    args = parser.parse_args()

    # Determine project root
    project_root = Path(__file__).parent.parent
    modules_dir = project_root / "modules"

    # Create module directory
    mod_dir = modules_dir / args.category / args.name
    if mod_dir.exists():
        print(f"[!] Module already exists: {mod_dir}")
        sys.exit(1)

    src_dir = mod_dir / "src"
    bin_dir = mod_dir / "bin"
    src_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)

    # Generate tags
    tags = args.tags if args.tags else f"{args.category}, {args.name}"

    # Write module.yaml
    yaml_content = MODULE_YAML_TEMPLATE.format(
        name=args.name,
        category=args.category,
        description=args.description,
        date=date.today().isoformat(),
        opsec=args.opsec,
        tags=tags,
    )
    (mod_dir / "module.yaml").write_text(yaml_content.strip() + "\n")

    # Write source file
    c_content = BOF_C_TEMPLATE.format(
        name=args.name,
        description=args.description,
    )
    (src_dir / f"{args.name}.c").write_text(c_content.strip() + "\n")

    print(f"[*] Created module scaffold at {mod_dir}")
    print(f"    {mod_dir}/module.yaml")
    print(f"    {src_dir}/{args.name}.c")
    print(f"    {bin_dir}/  (empty, for compiled .o)")
    print()
    print(f"[*] To compile:")
    print(f"    cd modules && make {args.name}")
    print()
    print(f"[*] Add a build target to modules/Makefile:")
    print(f"    {args.name}:")
    print(f"    \t@mkdir -p {args.category}/{args.name}/bin")
    print(f"    \t$(CC) $(CFLAGS) $(INCLUDES) \\")
    print(f"    \t\t-o {args.category}/{args.name}/bin/{args.name}.$(ARCH).o \\")
    print(f"    \t\t{args.category}/{args.name}/src/{args.name}.c")


if __name__ == "__main__":
    main()
