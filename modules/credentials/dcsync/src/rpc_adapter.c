/*
 * rpc_adapter.c - MIDL memory allocation/deallocation for NdrClientCall2
 * Adapted from P0142/DCSync-Bof
 */

#include <windows.h>

DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* ptr);

void __RPC_FAR * __RPC_USER MIDL_user_allocate(size_t len) {
    return MSVCRT$malloc(len);
}

void __RPC_USER MIDL_user_free(void __RPC_FAR * ptr) {
    MSVCRT$free(ptr);
}
