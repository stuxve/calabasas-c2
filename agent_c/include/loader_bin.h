/*
 * loader_bin.h — Reflective PE loader shellcode (placeholder).
 *
 * Generate the real shellcode with:
 *   ./scripts/compile_loader.sh
 *
 * This placeholder contains a minimal stub that does nothing,
 * allowing the agent to compile before the loader is built.
 * spawn will fail at runtime with an error message if this
 * placeholder is still in use.
 */
#ifndef LOADER_BIN_H
#define LOADER_BIN_H

/* Placeholder: single RET instruction. Replace with compile_loader.sh output. */
static const unsigned char reflective_loader_bin[] = {
    0xc3  /* ret */
};

#define REFLECTIVE_LOADER_SIZE sizeof(reflective_loader_bin)

/* Set to 0 when placeholder, 1 when real loader is compiled */
#define REFLECTIVE_LOADER_READY 0

#endif /* LOADER_BIN_H */
