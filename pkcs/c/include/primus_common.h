/* SPDX-FileCopyrightText: Copyright 2025 Securosys SA */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pkcs11.h"

#ifndef PRIMUS_COMMON_H
#define PRIMUS_COMMON_H

#define NUM_ATTR(x) (sizeof(x) / sizeof(CK_ATTRIBUTE))

#ifndef __cplusplus

#undef NULL_PTR
#define NULL_PTR ((void *)0)

#endif

#ifdef __cplusplus
extern "C" {
#endif

CK_RV SetupSession(CK_SESSION_HANDLE_PTR phSession);

void CloseSession(CK_SESSION_HANDLE hSession);

#ifdef __cplusplus
}
#endif

#endif /* PRIMUS_COMMON_H */
