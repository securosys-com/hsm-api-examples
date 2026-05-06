// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: SKA
 *
 * This example shows how to generate an SKA key pair.
 */

#include "pkcs11.h"
#include "primus_common.h"

// C++
#include <iostream>

// Botan
#include <botan/hex.h>

CK_RV ska_generate_key_pair(CK_SESSION_HANDLE hSession) {

  CK_RV rv = CKR_OK;

  /**
   * Choose the type of SKA key to generate (RSA, DSA, EC, ED).
   */
  CK_MECHANISM mech;
  memset(&mech, 0, sizeof(CK_MECHANISM));
  mech.mechanism = CKM_SKA_RSA_PKCS_KEY_PAIR_GEN;

  CK_BBOOL bTrue = CK_TRUE;
  CK_BBOOL bFalse = CK_FALSE;
  CK_KEY_TYPE keyType = CKK_RSA;

  /**
   * Public key attributes. Same as if a non-SKA RSA key pair was generated.
   */
  CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
  CK_ULONG keySize = 2048;
  CK_BYTE rsaPublicExponent[] = {0x01, 0x00, 0x01};
  CK_ATTRIBUTE pubKeyAttributes[] = {
      {CKA_CLASS, &pubKeyClass, sizeof(CK_OBJECT_CLASS)},
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      {CKA_TOKEN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_ENCRYPT, &bTrue, sizeof(CK_BBOOL)},
      {CKA_VERIFY, &bTrue, sizeof(CK_BBOOL)},
      {CKA_VERIFY_RECOVER, &bTrue, sizeof(CK_BBOOL)},
      {CKA_WRAP, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_PRIVATE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODULUS_BITS, &keySize, sizeof(CK_ULONG)},
      {CKA_PUBLIC_EXPONENT, rsaPublicExponent, sizeof(rsaPublicExponent)}};

  /**
   * Attributes of the private SKA key.
   *
   * In particular, we specify:
   *
   * - The public key is not blocked immediately after creation.
   * - The key is used for Bitcoin wallet.
   * - The corresponding public key is not sensitive.
   * - The four types of SKA policies: USAGE, BLOCK, UNBLOCK, MODIFY. All four
   * are required!
   *
   * USAGE: Who has to approve for the key to be used.
   * BLOCK/UNBLOCK: Who has to approve for the key to be (un)blocked.
   *     If the key is blocked, it cannot be used for signing/decrypting.
   * MODIFY: Who has to approve the modification of the key's policies.
   */
  CK_OBJECT_CLASS skaKeyClass = CKO_SKA_PRIVATE_KEY;
  CK_CRYPTOCURRENCY bitcoin = CKCC_BITCOIN;
  // Policy that requires no approvals (an "empty" policy).
  auto policy_vec =
      Botan::hex_decode("300000005900040001000000550004000000000055000400000000"
                        "005A000400010000005B000400000000000300040000000000");
  CK_BYTE_PTR policy = policy_vec.data();
  CK_ULONG policyLen = policy_vec.size();

  CK_ATTRIBUTE skaKeyAttributes[] = {
      {CKA_CLASS, &skaKeyClass, sizeof(CK_OBJECT_CLASS)},
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      {CKA_TOKEN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_DECRYPT, &bTrue, sizeof(CK_BBOOL)},
      {CKA_SIGN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_SIGN_RECOVER, &bTrue, sizeof(CK_BBOOL)},
      {CKA_UNWRAP, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_PRIVATE, &bTrue, sizeof(CK_BBOOL)},
      // Vendor-specific attributes
      {CKA_SKA_BLOCKED, &bFalse, sizeof(CK_BBOOL)},
      {CKA_SKA_CRYPTO_CURRENCY_TYPE, &bitcoin, sizeof(CK_CRYPTOCURRENCY)},
      {CKA_SKA_SENSITIVE_PUBLIC_KEY, &bFalse, sizeof(CK_BBOOL)},
      {CKA_SKA_USAGE_ACCESS_BLOB, policy, policyLen},
      {CKA_SKA_BLOCK_ACCESS_BLOB, policy, policyLen},
      {CKA_SKA_UNBLOCK_ACCESS_BLOB, policy, policyLen},
      {CKA_SKA_MODIFY_ACCESS_BLOB, policy, policyLen}};

  /**
   * Generate the key pair.
   * If SENSITIVE_PUBLIC_KEY is set to true in the private key attributes, the
   * pubKey output will be NULL.
   */
  CK_OBJECT_HANDLE pubKey, skaKey;
  rv = C_GenerateKeyPair(hSession, &mech, pubKeyAttributes,
                         NUM_ATTR(pubKeyAttributes), skaKeyAttributes,
                         NUM_ATTR(skaKeyAttributes), &pubKey, &skaKey);

  printf("Created SKA keypair: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * Clean up.
   */
  printf("Destroying private key...\n");
  rv = C_DestroyObject(hSession, skaKey);
  if (rv != CKR_OK)
    return rv;

  printf("Destroying public key...\n");
  rv = C_DestroyObject(hSession, pubKey);
  if (rv != CKR_OK)
    return rv;

  return rv;
}

int main() {
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session;

  rv = SetupSession(&session);
  if (rv != CKR_OK) {
    CloseSession(session);
    return rv;
  }

  rv = ska_generate_key_pair(session);
  if (rv != CKR_OK) {
    printf("Got return value 0x%lx\n", rv);
  }

  CloseSession(session);
  return rv;
}
