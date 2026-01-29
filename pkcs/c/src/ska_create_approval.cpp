// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: SKA
 *
 * This example shows how to:
 *
 * 1. Create an approval token.
 * 2. Sign the approval token, thus creating an approval.
 */

#include "pkcs11.h"

#include <stdlib.h>

// Botan
#include <botan/auto_rng.h>
#include <botan/der_enc.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>

/**
 * High-level sample, not runnable.
 */
CK_RV ska_create_approval_example(CK_SESSION_HANDLE hSession) {
  CK_RV rv = CKR_OK;

  /**
   * SKA key to be used. Since it is an SKA key, its usage has to be approved
   * by one or more approvers according to the policy of the key.
   */
  CK_OBJECT_HANDLE hSkaKey;

  /**
   * The payload of the SKA key operation, e.g., some data to be signed by the
   * SKA private key.
   */
  CK_BYTE_PTR payload;
  CK_ULONG payloadSize;

  /**
   * The application that wants to use the SKA key creates an approval token to
   * be signed by the approver.
   */
  CK_ULONG approvalTokBufLen = 1024;
  CK_BYTE_PTR approvalTokBuf = (CK_BYTE_PTR)malloc(approvalTokBufLen);

  rv = C_CreateApprovalToken(
      hSession,
      // Type of operation to be performed by the SKA private key
      CK_SKA_SIGN,
      // The SKA private key handle
      hSkaKey,
      // Payload for the operation, in this case, the data to be signed
      payload, payloadSize,
      /**
       * We assume the approval is always valid in time, so no signed timestamp
       * is passed.
       */
      NULL, 0, NULL, 0,
      // Output buffer to store the approval token
      approvalTokBuf, &approvalTokBufLen);

  /**
   * The application has to send the approval token to an approver, which is
   * usually a different entity, who can then approve of the operation by
   * signing the token.
   */
  // Create structure to hold the signed approval
  CK_ULONG apprSignatureBufLen = 1024;
  CK_BYTE_PTR apprSignatureBuf = (CK_BYTE_PTR)malloc(apprSignatureBufLen);

  CK_ULONG signerInfoBufLen = 1024;
  CK_BYTE_PTR signerInfoBuf = (CK_BYTE_PTR)malloc(signerInfoBufLen);

  CK_SKA_APPROVAL approval = {CKAP_NOT_SPECIFIED, apprSignatureBuf,
                              apprSignatureBufLen, signerInfoBuf,
                              signerInfoBufLen};

  /**
   * Let the approver sign the approval token, confirming their approval.
   * This usually happens on an end-user device, such as a mobile app.
   * Here, we assume that `approver` is listed in the policy of `hSkaKey`.
   *
   * Approvers usually use custom code to sign an approval token and encode the
   * result (see the Botan sample further below). For debugging purposes, they
   * can use the C_SignApprovalToken helper function.
   */
  CK_SKA_APPROVER approver;
  CK_BYTE_PTR pKeyAlgo;
  CK_ULONG ulKeyAlgoLen;
  CK_BYTE_PTR pPrivateKey;
  CK_ULONG ulPrivateKeyLen;

  rv = C_SignApprovalToken(
      // BER-encoded algorithm used for the private key
      pKeyAlgo, ulKeyAlgoLen,
      // BER-encoded private key (value, not a handle!)
      pPrivateKey, ulPrivateKeyLen,
      // Approver specified in policy
      &approver,
      // Approval token to be signed
      approvalTokBuf, approvalTokBufLen,
      // approver must be able to create such an approval, i.e., must match
      // approval type in CK_SKA_APPROVER
      CKAP_SIGNATURE,
      // Output for the signed approval
      &approval);

  /**
   * The approver then sends the approval back to the application, who can use
   * it to call SKASign, SKADecrypt or SKAUnwrap to perform the operation using
   * the actual SKA key.
   */

  free(approvalTokBuf);
  free(apprSignatureBuf);
  free(signerInfoBuf);

  return rv;
}

/**
 * Helper function to sign an approval token.
 * This uses Botan explicitly, instead of using the C_SignApprovalToken helper.
 *
 * This example uses RSA. For an ECDSA example, see `ska_modify.cpp`.
 */
CK_RV ska_create_approval(
    // The private key of the approver that should sign the token
    Botan::RSA_PrivateKey &approver_sk,
    // The approval token to be signed
    CK_BYTE_PTR approvalTokBuf, CK_ULONG approvalTokBufLen,
    // The signature to be returned
    CK_BYTE_PTR sigBuf, CK_ULONG_PTR sigBufLen) {

  Botan::AutoSeeded_RNG rng;
  Botan::OID oid("1.2.840.113549.1.1.11"); // RSA/EMSA3(SHA-256)
  Botan::PK_Signer signer(approver_sk, rng, "EMSA3(SHA-256)"); // PKCS#1 v1.5

  // Sign the approval token
  std::vector<uint8_t> sig =
      signer.sign_message(approvalTokBuf, approvalTokBufLen, rng);

  // DER-encode the signature in the ASN.1 structure that the HSM expects
  std::vector<uint8_t> sig_der;
  Botan::DER_Encoder(sig_der)
      .start_cons(Botan::SEQUENCE)
      .encode(Botan::AlgorithmIdentifier(
          oid, Botan::AlgorithmIdentifier::USE_NULL_PARAM))
      .encode(sig, Botan::BIT_STRING)
      .end_cons();

  if (sig_der.size() > *sigBufLen) {
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(sigBuf, sig_der.data(), sig_der.size());
  *sigBufLen = sig_der.size();

  return CKR_OK;
}

int use_ska_create_approval() {
  // int main() {
  CK_RV rv = CKR_OK;

  // Generate the approver key
  Botan::AutoSeeded_RNG rng;
  Botan::RSA_PrivateKey alice(rng, 2048);
  auto alice_pk = alice.subject_public_key();

  /**
   * Create a dummy approval token. In reality, this should use
   * C_CreateApprovalToken.
   */
  CK_ULONG approvalTokBufLen = 32;
  CK_BYTE_PTR approvalTokBuf = (uint8_t *)malloc(approvalTokBufLen);
  memset(approvalTokBuf, 'A', approvalTokBufLen);

  /**
   * Sign the approval token, creating the approval.
   * This signals that they approve the SKA key usage with the payload (as
   * included in the token).
   *
   * Usually, this does NOT happen in the business application. Instead, it
   * happens on mobile apps where the approvers locally hold their private keys.
   */

  CK_ULONG sigBufLen = 1024;
  CK_BYTE_PTR sigBuf = (uint8_t *)malloc(sigBufLen);

  rv = ska_create_approval(alice, approvalTokBuf, approvalTokBufLen, sigBuf,
                           &sigBufLen);

  CK_SKA_APPROVAL alice_approval{CKAP_SIGNATURE, sigBuf, sigBufLen,
                                 alice_pk.data(), alice_pk.size()};

  printf("Created approval\n");

  free(approvalTokBuf);
  free(sigBuf);
  return rv;
}
