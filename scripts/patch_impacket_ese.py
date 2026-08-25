#!/usr/bin/env python3
"""
Patch impacket's ese.py to handle empty/short tags on large-page (>8KB) ESE databases.

Bug: ESENT_PAGE.getTag() accesses tmpData[1] unconditionally for pages > 8192 bytes.
     On dirty-shutdown databases (e.g. raw-copied NTDS.dit), some tags have 0 or 1
     bytes of data, causing IndexError("bytearray index out of range").

Usage:
    python3 patch_impacket_ese.py
    # Then run secretsdump normally
"""
import importlib, sys, os

def find_ese_path():
    import impacket.ese
    return impacket.ese.__file__

def patch():
    path = find_ese_path()
    with open(path, 'r') as f:
        src = f.read()

    # Check if already patched
    if 'len(tmpData) >= 2' in src:
        print(f"[*] {path} is already patched")
        return

    # The buggy code block in getTag:
    old = """\
            tmpData = bytearray(self.data[baseOffset+valueOffset:][:valueSize])
            pageFlags = tmpData[1] >> 5
            tmpData[1] = tmpData[1:2][0] & 0x1f
            tmpData = bytes(tmpData)
            tagData = tmpData"""

    new = """\
            tmpData = bytearray(self.data[baseOffset+valueOffset:][:valueSize])
            if len(tmpData) >= 2:
                pageFlags = tmpData[1] >> 5
                tmpData[1] = tmpData[1:2][0] & 0x1f
            else:
                pageFlags = 0
            tmpData = bytes(tmpData)
            tagData = tmpData"""

    if old not in src:
        print(f"[-] Could not find target code block in {path}")
        print("    (impacket version may differ — try manual patch)")
        sys.exit(1)

    src = src.replace(old, new)
    with open(path, 'w') as f:
        f.write(src)
    print(f"[+] Patched {path}")
    print("[*] Now run: impacket-secretsdump -ntds ntds.bin -system system.bin LOCAL")

if __name__ == '__main__':
    patch()
