/* SPDX-FileCopyrightText: Copyright 2026 Securosys SA */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pkcs11.h"

#include <botan/rsa.h>

CK_RV
ska_create_approval(Botan::RSA_PrivateKey &approver_sk,
                    CK_BYTE_PTR approvalTokBuf, CK_ULONG approvalTokBufLen,
                    CK_BYTE_PTR sigBuf, CK_ULONG_PTR sigBufLen);
