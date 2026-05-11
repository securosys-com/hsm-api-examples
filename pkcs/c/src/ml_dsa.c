// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: ML-DSA
 *
 * This example shows how to:
 *
 * - Generate an ML-DSA key pair
 * - Sign and verify with the ML-DSA key pair
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "pkcs11.h"
#include "primus_common.h"

#define HASH_MODE_PURE 1
#define HASH_MODE_PROVIDER 2
#define HASH_MODE_APP 3

// Change this to try a different variant
#define HASH_MODE HASH_MODE_PURE

CK_RV ml_dsa(CK_SESSION_HANDLE session) {

  CK_RV rv = CKR_OK;
  printf("\nGenerating ML-DSA key pair...\n");

  CK_UTF8CHAR label[] = "my-ml-dsa-key";

  CK_OBJECT_HANDLE privateKey, publicKey;
  CK_MECHANISM genMechanism = {CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_KEY_TYPE keyType = CKK_ML_DSA;

  CK_BBOOL bTrue = CK_TRUE;
  CK_BBOOL bFalse = CK_FALSE;

  // https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693747
  CK_ML_DSA_PARAMETER_SET_TYPE paramSet = CKP_ML_DSA_87;

  CK_ATTRIBUTE publicTemplate[] = {
      {CKA_TOKEN, &bTrue, sizeof(bTrue)},
      {CKA_PRIVATE, &bFalse, sizeof(bFalse)},
      {CKA_LABEL, &label, sizeof(label) - 1}, // must not be null-terminated
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      // ML-DSA-specific attributes
      {CKA_PARAMETER_SET, &paramSet, sizeof(paramSet)},
      // key attributes
      {CKA_VERIFY, &bTrue, sizeof(bTrue)},
  };

  CK_ATTRIBUTE privateTemplate[] = {
      {CKA_TOKEN, &bTrue, sizeof(bTrue)},
      {CKA_PRIVATE, &bTrue, sizeof(bTrue)},
      {CKA_LABEL, &label, sizeof(label) - 1},
      {CKA_EXTRACTABLE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      // key attributes
      {CKA_SIGN, &bTrue, sizeof(bTrue)},
  };

  rv = C_GenerateKeyPair(session, &genMechanism, publicTemplate,
                         NUM_ATTR(publicTemplate), privateTemplate,
                         NUM_ATTR(privateTemplate), &publicKey, &privateKey);
  if (rv != CKR_OK)
    return rv;

  printf("Signing with ML-DSA...\n");

  // Signature parameters
  CK_BYTE ctx[] = "optional-context-string";
  CK_HEDGE_TYPE hedgeType = CKH_HEDGE_REQUIRED;

#if HASH_MODE == HASH_MODE_PURE

  // Option 1: Pure (the message itself is signed)
  //
  // Section 6.67.5 ML-DSA Signature
  // https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693750

  printf("Using pure hash\n");
  CK_MECHANISM_TYPE sigMechType = CKM_ML_DSA;
  CK_SIGN_ADDITIONAL_CONTEXT params = {hedgeType, ctx, sizeof(ctx)};
  CK_BYTE message[] = "i like pizza";

#elif HASH_MODE == HASH_MODE_PROVIDER

  // Option 2: Pre-hashed by provider
  //
  // Section 6.67.6 HashML-DSA Signature
  // https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693751
  //
  // This is the pre-hash variant of ML-DSA. The PKCS#11 provider hashes the
  // message before sending it to the HSM.

  printf("Using pre-hashed by provider\n");
  CK_MECHANISM_TYPE sigMechType = CKM_HASH_ML_DSA_SHA256;
  CK_SIGN_ADDITIONAL_CONTEXT params = {hedgeType, ctx, sizeof(ctx)};
  CK_BYTE message[] = "i like pizza";

#elif HASH_MODE == HASH_MODE_APP

  // Option 3: Pre-hash by application
  //
  // Section 6.67.7 HashML-DSA Signature with hashing
  // https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693752
  //
  // This is also the pre-hash variant of ML-DSA. Here, the application has
  // already hashed the message.

  printf("Using pre-hashed by application\n");
  CK_MECHANISM_TYPE sigMechType = CKM_HASH_ML_DSA;
  CK_MECHANISM_TYPE hashMechType = CKM_SHA256;
  CK_HASH_SIGN_ADDITIONAL_CONTEXT params = {hedgeType, ctx, sizeof(ctx),
                                            hashMechType};
  // Get a 32-byte array, to simulate a SHA-256 hash
  // This must be the raw hash bytes, not any encoding (such as a hex string).
  CK_BYTE message[32];
  getrandom(message, sizeof(message), 0);

#else

#error "Unknown HASH_MODE"

#endif

  printf("messageLen: %lu\n", sizeof(message));
  CK_MECHANISM sigMechanism = {sigMechType, &params, sizeof(params)};

  CK_BYTE_PTR signature;
  CK_ULONG signatureLen = 0;

  rv = C_SignInit(session, &sigMechanism, privateKey);
  if (rv != CKR_OK) {
    C_DestroyObject(session, publicKey);
    C_DestroyObject(session, privateKey);
    return rv;
  }

  rv = C_Sign(session, message, sizeof(message), NULL_PTR, &signatureLen);
  if (rv != CKR_OK) {
    C_DestroyObject(session, publicKey);
    C_DestroyObject(session, privateKey);
    return rv;
  }

  printf("signatureLen: %lu\n", signatureLen);
  signature = calloc(signatureLen, sizeof(CK_BYTE));

  rv = C_Sign(session, message, sizeof(message), signature, &signatureLen);
  if (rv != CKR_OK) {
    free(signature);
    C_DestroyObject(session, publicKey);
    C_DestroyObject(session, privateKey);
    return rv;
  }

  printf("Verifying with ML-DSA...\n");

  rv = C_VerifyInit(session, &sigMechanism, publicKey);
  if (rv != CKR_OK) {
    free(signature);
    C_DestroyObject(session, publicKey);
    C_DestroyObject(session, privateKey);
    return rv;
  }

  rv = C_Verify(session, message, sizeof(message), signature, signatureLen);
  if (rv != CKR_OK) {
    free(signature);
    C_DestroyObject(session, publicKey);
    C_DestroyObject(session, privateKey);
    return rv;
  }

  printf("Signature verification successful!\n");

  free(signature);

  printf("Destroying key pair again...\n");
  C_DestroyObject(session, publicKey);
  C_DestroyObject(session, privateKey);

  return rv;
}

int main() {
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session;

  rv = SetupSession(&session);
  if (rv != CKR_OK)
    return rv;

  rv = ml_dsa(session);
  if (rv != CKR_OK) {
    printf("Got return value 0x%lx\n", rv);
    CloseSession(session);
    return rv;
  }

  CloseSession(session);
  return rv;
}
