/* SPDX-FileCopyrightText: Copyright 2026 Securosys SA */
/* SPDX-License-Identifier: Apache-2.0 */

#include "pkcs11.h"

#include <botan/rsa.h>

CK_RV ska_create_all(CK_SESSION_HANDLE hSession, CK_BBOOL withTimeConstraints,
                     CK_OBJECT_HANDLE_PTR pubKey, CK_OBJECT_HANDLE_PTR skaKey,
                     Botan::RSA_PrivateKey &alice, Botan::RSA_PrivateKey &bob,
                     Botan::RSA_PrivateKey &carol,
                     Botan::RSA_PrivateKey &david);
