// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: SKA
 *
 * This example shows how to sign with an SKA key that is protected by a
 * timelock and a timeout in its SKA policy.
 */

#include "pkcs11.h"
#include "primus_common.h"
#include "ska_create_approval.h"
#include "ska_create_common.h"

// C++
#include <chrono>
#include <thread>

// Botan
#include <botan/auto_rng.h>
#include <botan/der_enc.h>
#include <botan/rsa.h>

#define NUM_ATTR(x) (sizeof(x) / sizeof(CK_ATTRIBUTE))

CK_RV ska_sign(CK_SESSION_HANDLE hSession) {

  CK_RV rv = CKR_OK;
  Botan::AutoSeeded_RNG rng;

  /**
   * Create an SKA key with some approvers and an appropriate policy
   */
  CK_OBJECT_HANDLE pubKey, skaKey;
  Botan::RSA_PrivateKey alice(rng, 2048);
  Botan::RSA_PrivateKey bob(rng, 2048);
  Botan::RSA_PrivateKey carol(rng, 2048);
  Botan::RSA_PrivateKey david(rng, 2048);
  rv = ska_create_all(hSession, /* withTimeConstraints */ CK_TRUE, &pubKey,
                      &skaKey, alice, bob, carol, david);

  auto alice_pk = alice.subject_public_key();
  auto bob_pk = bob.subject_public_key();

  /**
   * Create a payload to be signed by the SKA key
   */
  CK_ULONG payloadSize = 32;
  CK_BYTE_PTR payloadBuffer = (uint8_t *)malloc(payloadSize);
  memset(payloadBuffer, 'A', payloadSize);

  /**
   * Generate a timestamping key. This key is required to get signed timestamps
   * from the HSM.
   */
  CK_BBOOL bTrue = CK_TRUE;
  CK_BBOOL bFalse = CK_FALSE;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_ULONG keySize = 2048;
  CK_BYTE rsaPublicExponent[] = {0x01, 0x00, 0x01};

  CK_ATTRIBUTE timestampingPubKeyAttr[] = {
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      {CKA_TOKEN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_VERIFY, &bTrue, sizeof(CK_BBOOL)},
      {CKA_PRIVATE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODULUS_BITS, &keySize, sizeof(CK_ULONG)},
      {CKA_PUBLIC_EXPONENT, rsaPublicExponent, sizeof(rsaPublicExponent)}};
  CK_ATTRIBUTE timestampingPrivKeyAttr[] = {
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      {CKA_TOKEN, &bTrue, sizeof(CK_BBOOL)},
      // Timestamping keys are not allowed be used for normal signing.
      {CKA_SIGN, &bFalse, sizeof(CK_BBOOL)},
      {CKA_SKA_TIMESTAMP_SIGN, &bTrue, sizeof(CK_BBOOL)}};

  CK_MECHANISM mech;
  memset(&mech, 0, sizeof(CK_MECHANISM));
  mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

  CK_OBJECT_HANDLE tsPubKey, tsPrivKey;
  rv = C_GenerateKeyPair(
      hSession, &mech, timestampingPubKeyAttr, NUM_ATTR(timestampingPubKeyAttr),
      timestampingPrivKeyAttr, NUM_ATTR(timestampingPrivKeyAttr), &tsPubKey,
      &tsPrivKey);

  printf("Created timestamping keypair: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * Ask the HSM for a signed timestamp.
   *
   * Note that this request includes the type of operation (CK_SKA_SIGN) and the
   * payload. The returned signature is later used to enforce the timelock
   * and/or timeout on this operation.
   */
  // The timestamp value
  CK_ULONG timestampLen = 1024;
  CK_BYTE_PTR timestampBuf = (CK_BYTE_PTR)malloc(timestampLen);
  // The signature
  CK_ULONG timestampSigLen = 1024;
  CK_BYTE_PTR timestampSigBuf = (CK_BYTE_PTR)malloc(timestampSigLen);

  memset(&mech, 0, sizeof(CK_MECHANISM));
  mech.mechanism = CKM_SHA256_RSA_PKCS;

  rv = C_GetTimestamp(hSession, CK_SKA_SIGN, &mech, tsPrivKey, payloadBuffer,
                      payloadSize, timestampBuf, &timestampLen, timestampSigBuf,
                      &timestampSigLen);
  printf("Got signed timestamp: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * DER-encode the raw signature.
   */
  auto timestampSigVec =
      std::vector<uint8_t>(timestampSigBuf, timestampSigBuf + timestampSigLen);
  std::vector<uint8_t> timestampSigEncoded;
  Botan::DER_Encoder(timestampSigEncoded)
      .start_cons(Botan::SEQUENCE)
      .encode(Botan::AlgorithmIdentifier(
          "RSA/EMSA3(SHA-256)", Botan::AlgorithmIdentifier::USE_NULL_PARAM))
      .encode(timestampSigVec, Botan::BIT_STRING)
      .end_cons();

  /**
   * The business application creates the "approval token".
   * This token must include the timestamp and the timestamp signature.
   */
  CK_ULONG approvalTokBufLen = 1024;
  CK_BYTE_PTR approvalTokBuf = (uint8_t *)malloc(approvalTokBufLen);
  rv = C_CreateApprovalToken(
      hSession, CK_SKA_SIGN, skaKey, payloadBuffer, payloadSize,
      // The timestamp value
      timestampBuf, timestampLen,
      // The DER-encoded timestamp signature
      timestampSigEncoded.data(), timestampSigEncoded.size(),
      // The output buffer
      approvalTokBuf, &approvalTokBufLen);

  printf("Created approval token: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * 2 finance officers sign the approval token, creating an "approval".
   */

  // Alice
  CK_ULONG aliceSigBufLen = 1024;
  CK_BYTE_PTR aliceSigBuf = (uint8_t *)malloc(aliceSigBufLen);
  rv = ska_create_approval(alice, approvalTokBuf, approvalTokBufLen,
                           aliceSigBuf, &aliceSigBufLen);

  CK_SKA_APPROVAL alice_approval{CKAP_SIGNATURE, aliceSigBuf, aliceSigBufLen,
                                 alice_pk.data(), alice_pk.size()};

  printf("Approved by Alice: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  // Bob
  CK_ULONG bobSigBufLen = 1024;
  CK_BYTE_PTR bobSigBuf = (uint8_t *)malloc(bobSigBufLen);
  rv = ska_create_approval(bob, approvalTokBuf, approvalTokBufLen, bobSigBuf,
                           &bobSigBufLen);

  CK_SKA_APPROVAL bob_approval{CKAP_SIGNATURE, bobSigBuf, bobSigBufLen,
                               bob_pk.data(), bob_pk.size()};

  printf("Approved by Bob: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * The application collects the approvals from the financial officers (or
   * rather, their mobile apps). The application then uses these approvals to
   * make the SKA signing request to the HSM.
   */
  CK_SKA_APPROVAL approvals[] = {alice_approval, bob_approval};
  CK_ULONG signatureBufferLen = 1024;
  CK_BYTE_PTR signatureBuffer = (CK_BYTE_PTR)malloc(signatureBufferLen);

  memset(&mech, 0, sizeof(CK_MECHANISM));
  mech.mechanism = CKM_RSA_PKCS;

  // Signing should fail, because the timelock delay has not yet passed.
  rv =
      C_SKASign(hSession, &mech, skaKey, approvalTokBuf, approvalTokBufLen,
                approvals, 2, signatureBuffer, &signatureBufferLen, NULL, NULL);
  printf("Signing too early should fail: %s\n", rv != CKR_OK ? "OK" : "NOT OK");
  if (rv == CKR_OK)
    return rv;

  std::this_thread::sleep_for(std::chrono::seconds(5));

  // After the timelock has passed, signing should work.
  rv =
      C_SKASign(hSession, &mech, skaKey, approvalTokBuf, approvalTokBufLen,
                approvals, 2, signatureBuffer, &signatureBufferLen, NULL, NULL);
  printf("Signed using SKA key: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  std::this_thread::sleep_for(std::chrono::seconds(5));

  // After the timeout has passed, signing should fail.
  rv =
      C_SKASign(hSession, &mech, skaKey, approvalTokBuf, approvalTokBufLen,
                approvals, 2, signatureBuffer, &signatureBufferLen, NULL, NULL);
  printf("Signing too late should fail: %s\n", rv != CKR_OK ? "OK" : "NOT OK");
  if (rv == CKR_OK)
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

  free(bobSigBuf);
  free(aliceSigBuf);
  free(signatureBuffer);
  free(approvalTokBuf);
  free(payloadBuffer);

  return 0;
}

int main() {
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session;

  rv = SetupSession(&session);
  if (rv != CKR_OK) {
    CloseSession(session);
    return rv;
  }

  rv = ska_sign(session);
  if (rv != CKR_OK) {
    printf("Got return value 0x%lx\n", rv);
  }
  CloseSession(session);
  return rv;
}
