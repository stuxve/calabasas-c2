#!/bin/bash
# Build all BOF modules for x64
# Usage: ./scripts/build_bofs.sh
# Requires: x86_64-w64-mingw32-gcc (apt install gcc-mingw-w64-x86-64)

set -e

CC="x86_64-w64-mingw32-gcc"
CFLAGS="-c -Wall -Wextra -Os -fno-asynchronous-unwind-tables -fno-ident -fpack-struct=8"
INCLUDES="-I$(dirname "$0")/../shared/include"

MODULES_DIR="$(dirname "$0")/../modules"
SUCCESS=0
FAIL=0
TOTAL=0

echo "[*] Building BOF modules..."
echo ""

# Find all module source files
for src in $(find "$MODULES_DIR" -path "*/src/*.c" -type f | sort); do
    mod_dir=$(dirname $(dirname "$src"))
    mod_name=$(basename "$src" .c)
    bin_dir="$mod_dir/bin"
    out_file="$bin_dir/${mod_name}.x64.o"

    TOTAL=$((TOTAL + 1))
    mkdir -p "$bin_dir"

    printf "  %-30s " "$mod_name"
    if $CC $CFLAGS $INCLUDES -o "$out_file" "$src" 2>/tmp/bof_err_$$; then
        size=$(stat -c%s "$out_file" 2>/dev/null || stat -f%z "$out_file")
        printf "OK (%s bytes)\n" "$size"
        SUCCESS=$((SUCCESS + 1))
    else
        printf "FAILED\n"
        cat /tmp/bof_err_$$ | head -5 | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi
    rm -f /tmp/bof_err_$$
done

echo ""
echo "[*] Results: $SUCCESS/$TOTAL succeeded, $FAIL failed"

# Validate COFF headers
if [ $SUCCESS -gt 0 ]; then
    echo ""
    echo "[*] Validating COFF headers..."
    for obj in $(find "$MODULES_DIR" -name "*.x64.o" -type f | sort); do
        magic=$(xxd -l 2 -p "$obj")
        name=$(basename "$obj")
        if [ "$magic" = "6486" ]; then
            printf "  %-35s VALID (x64 COFF)\n" "$name"
        else
            printf "  %-35s INVALID (magic=%s)\n" "$name" "$magic"
        fi
    done
fi
