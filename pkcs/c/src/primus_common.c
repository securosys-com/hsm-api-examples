// SPDX-FileCopyrightText: Copyright 2025 Securosys SA
// SPDX-License-Identifier: Apache-2.0

#include <stdbool.h> // TODO: only needed because of bool in pkcs11.h header file
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "primus_common.h"
#include "pkcs11.h"

CK_RV SetupSession(CK_SESSION_HANDLE_PTR phSession)
{
    CK_RV rv = CKR_OK;

    CK_CHAR_PTR userPin = (CK_CHAR_PTR)getenv("P11_PIN");
    if (userPin == NULL_PTR)
    {
        printf("P11_PIN envvar not set\n");
        return CKR_GENERAL_ERROR;
    }

    CK_ULONG userPinLen = strlen((char *)userPin);

    rv = C_Initialize(NULL);
    if (rv != CKR_OK)
        return rv;

    CK_ULONG flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_SLOT_ID slotId = 0;
    rv = C_OpenSession(slotId, flags, NULL_PTR, NULL_PTR, phSession);
    if (rv != CKR_OK)
    {
        C_Finalize(NULL_PTR);
        return rv;
    }

    rv = C_Login(*phSession, CKU_USER, userPin, userPinLen);
    if (rv != CKR_OK)
    {
        C_CloseSession(*phSession);
        C_Finalize(NULL_PTR);
        return rv;
    }

    return rv;
}

void CloseSession(CK_SESSION_HANDLE hSession)
{
    C_Logout(hSession);
    C_CloseSession(hSession);
    C_Finalize(NULL_PTR);
}
