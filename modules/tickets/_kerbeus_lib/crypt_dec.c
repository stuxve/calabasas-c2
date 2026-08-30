#pragma once
#include "functions.c"

BOOL decrypt(byte* key, DWORD eType, DWORD keyUsage, byte* data, int dataSize, byte** result, int* size) {
    PKERB_ECRYPT pCSystem;
    PVOID		 pContext;
    NTSTATUS	 status;

    status = CDLocateCSystem(eType, &pCSystem);
    if (!NT_SUCCESS(status)) {
        PRINT_OUT("[x] Failed to call CDLocateCSystem");
        return TRUE;
    }

    status = pCSystem->Initialize(key, pCSystem->KeySize, keyUsage, &pContext);
    if (!NT_SUCCESS(status)) {
        PRINT_OUT("[x] Failed to initialize crypto system");
        return TRUE;
    }

    *result = MemAlloc(dataSize);
    *size = dataSize;
    ULONG decSize = (ULONG)*size;
    status = pCSystem->Decrypt(pContext, data, dataSize, *result, &decSize);
    *size = (int)decSize;

    pCSystem->Finish(&pContext);
    return FALSE;
}