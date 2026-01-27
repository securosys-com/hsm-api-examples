/* SPDX-FileCopyrightText: Copyright 2025 Securosys SA */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pkcs11.h"

#ifndef __cplusplus

#undef NULL_PTR
#define NULL_PTR ((void *)0)

#endif

CK_RV SetupSession(CK_SESSION_HANDLE_PTR phSession);

void CloseSession(CK_SESSION_HANDLE hSession);
