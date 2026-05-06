// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: SKA
 *
 * This example contains common code to:
 *
 * 1. Build a more complex SKA policy and serialize it.
 * 2. Generate an SKA key.
 *
 * This shared code is used by the sign/block/modify samples.
 */

#include "pkcs11.h"
#include "primus_common.h"

// Botan
#include <botan/auto_rng.h>
#include <botan/der_enc.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>

#define NUM_APPROVALS(x) (sizeof(x) / sizeof(CK_SKA_APPROVAL))

CK_RV ska_create_all(CK_SESSION_HANDLE hSession,
                     // Whether the finance officers' approval should have a
                     // timelock (delay) and a timeout
                     CK_BBOOL withTimeConstraints,
                     // The public and private key handles for the SKA key pair
                     // to be generated on the HSM
                     CK_OBJECT_HANDLE_PTR pubKey, CK_OBJECT_HANDLE_PTR skaKey,
                     // The in-memory private keys of the approvers
                     Botan::RSA_PrivateKey &alice, Botan::RSA_PrivateKey &bob,
                     Botan::RSA_PrivateKey &carol,
                     Botan::RSA_PrivateKey &david) {

  CK_RV rv = CKR_OK;

  CK_ULONG delay = 0;
  CK_ULONG timeout = 0;

  if (withTimeConstraints) {
    delay = 5;
    timeout = 5;
  }

  /**
   * Create policies for the SKA key
   */
  // Finance officers: approve usage of the SKA key (see `ska_sign.cpp`)
  std::string alice_name = "alice";
  std::string bob_name = "bob";
  auto alice_pk = alice.subject_public_key();
  auto bob_pk = bob.subject_public_key();

  CK_SKA_APPROVER financialOfficers[] = {
      {(CK_CHAR_PTR)alice_name.data(), alice_name.size(), CKAP_SIGNATURE,
       alice_pk.data(), alice_pk.size()},
      {(CK_CHAR_PTR)bob_name.data(), bob_name.size(), CKAP_SIGNATURE,
       bob_pk.data(), bob_pk.size()}};
  // Both FO's required to allow a transaction to be signed (2-of-2)
  CK_SKA_GROUP foGroup = {NULL, 0, 2, financialOfficers, 2};
  CK_SKA_TOKEN foToken = {NULL, 0, delay, timeout, &foGroup, 1};
  CK_SKA_POLICY usagePolicy = {&foToken, 1};

  // Risk manager: can block or unblock the SKA key (see `ska_block.cpp`)
  auto carol_pk = carol.subject_public_key();
  CK_SKA_APPROVER riskManager = {NULL, 0, CKAP_SIGNATURE, carol_pk.data(),
                                 carol_pk.size()};
  std::string riskName = "risk_officers";
  CK_SKA_GROUP riskGroup = {(CK_BYTE_PTR)riskName.data(), riskName.size(), 1,
                            &riskManager, 1};
  CK_SKA_TOKEN riskToken = {NULL, 0, 0, 0, &riskGroup, 1};
  CK_SKA_POLICY blockPolicy = {&riskToken, 1};

  // Modify manager: can modify policies of the SKA key (see `ska_modify.cpp`)
  std::string david_name = "david";
  auto david_pk = david.subject_public_key();
  CK_SKA_APPROVER modifyManager = {(CK_CHAR_PTR)david_name.data(),
                                   david_name.size(), CKAP_SIGNATURE,
                                   david_pk.data(), david_pk.size()};
  CK_SKA_GROUP modifyGroup = {NULL, 0, 1, &modifyManager, 1};
  CK_SKA_TOKEN modifyToken = {NULL, 0, 0, 0, &modifyGroup, 1};
  CK_SKA_POLICY modifyPolicy = {&modifyToken, 1};

  /**
   * Serialize the policies into buffers that can be passed to the HSM.
   */
  CK_ULONG upBufLen = 1024;
  CK_ULONG bpBufLen = 1024;
  CK_ULONG mpBufLen = 1024;
  CK_BYTE_PTR upBuf = (CK_BYTE_PTR)malloc(upBufLen);
  CK_BYTE_PTR bpBuf = (CK_BYTE_PTR)malloc(bpBufLen);
  CK_BYTE_PTR mpBuf = (CK_BYTE_PTR)malloc(mpBufLen);

  rv = C_SerializePolicy(&usagePolicy, upBuf, &upBufLen);
  printf("Serialized usage policy: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  rv = C_SerializePolicy(&blockPolicy, bpBuf, &bpBufLen);
  printf("Serialized un/block policy: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  rv = C_SerializePolicy(&modifyPolicy, mpBuf, &mpBufLen);
  printf("Serialized modify policy: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * Generate the SKA key
   */
  CK_BBOOL bTrue = CK_TRUE;
  CK_BBOOL bFalse = CK_FALSE;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_ULONG keySize = 2048;
  CK_BYTE rsaPublicExponent[] = {0x01, 0x00, 0x01};

  CK_ATTRIBUTE pubKeyAttributes[] = {
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      {CKA_VERIFY, &bTrue, sizeof(CK_BBOOL)},
      {CKA_TOKEN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_PRIVATE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODULUS_BITS, &keySize, sizeof(CK_ULONG)},
      {CKA_PUBLIC_EXPONENT, rsaPublicExponent, sizeof(rsaPublicExponent)}};

  CK_ATTRIBUTE skaKeyAttributes[] = {
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      {CKA_TOKEN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_SIGN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_PRIVATE, &bTrue, sizeof(CK_BBOOL)},
      // Vendor-specific attributes
      {CKA_SKA_USAGE_ACCESS_BLOB, upBuf, upBufLen},
      {CKA_SKA_BLOCK_ACCESS_BLOB, bpBuf, bpBufLen},
      {CKA_SKA_UNBLOCK_ACCESS_BLOB, bpBuf, bpBufLen},
      {CKA_SKA_MODIFY_ACCESS_BLOB, mpBuf, mpBufLen}};

  CK_MECHANISM mech;
  memset(&mech, 0, sizeof(CK_MECHANISM));
  mech.mechanism = CKM_SKA_RSA_PKCS_KEY_PAIR_GEN;

  rv = C_GenerateKeyPair(hSession, &mech, pubKeyAttributes,
                         NUM_ATTR(pubKeyAttributes), skaKeyAttributes,
                         NUM_ATTR(skaKeyAttributes), pubKey, skaKey);

  printf("Created SKA key: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  free(upBuf);
  free(bpBuf);
  free(mpBuf);

  return rv;
}
