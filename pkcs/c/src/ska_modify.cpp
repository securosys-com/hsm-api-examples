// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: SKA
 *
 * This example shows how the modify manager (listed in the `modify` policy of
 * the SKA key) can modify the `usage` policy of the SKA key.
 */

#include "pkcs11.h"
#include "primus_common.h"
#include "ska_create_approval.h"
#include "ska_create_common.h"

// Botan
#include <botan/auto_rng.h>
#include <botan/der_enc.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>

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
  rv = ska_create_all(hSession, CK_FALSE, &pubKey, &skaKey, alice, bob, carol,
                      david);

  auto alice_pk = alice.subject_public_key();
  auto bob_pk = bob.subject_public_key();
  auto david_pk = david.subject_public_key();

  /**
   * Create a payload to be signed by the SKA key
   */
  CK_ULONG payloadSize = 32;
  CK_BYTE_PTR payloadBuffer = (uint8_t *)malloc(payloadSize);
  memset(payloadBuffer, 'A', payloadSize);

  /**
   * The business application creates the "approval token".
   */
  CK_ULONG approvalTokBufLen = 1024;
  CK_BYTE_PTR approvalTokBuf = (uint8_t *)malloc(approvalTokBufLen);
  rv = C_CreateApprovalToken(hSession, CK_SKA_SIGN, skaKey, payloadBuffer,
                             payloadSize, nullptr, 0, nullptr, 0,
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
   * The "modify manager" (listed in the SKA modify policy) decides to step in
   * and to change the "usage" policy. Alice and Bob have been fired, and we're
   * getting a new finance officer who can approve key usage all by themselves.
   *
   * The new finance officer gets a shiny EC key (instead of RSA).
   */
  std::string erin_name = "erin";
  Botan::ECDSA_PrivateKey erin(rng, Botan::EC_Group("secp256r1"));
  auto erin_pk = erin.subject_public_key();

  /**
   * Create the new "usage" policy.
   */
  CK_SKA_APPROVER newOfficer = {(CK_CHAR_PTR)erin_name.data(), erin_name.size(),
                                CKAP_SIGNATURE, erin_pk.data(), erin_pk.size()};
  CK_SKA_GROUP foGroup = {NULL, 0, 1, &newOfficer, 1};
  CK_SKA_TOKEN foToken = {NULL, 0, 0, 0, &foGroup, 1};
  CK_SKA_POLICY usagePolicy = {&foToken, 1};

  CK_ULONG modPayloadSize = 1024;
  CK_BYTE_PTR modPayload = (CK_BYTE_PTR)malloc(modPayloadSize);

  /*
   * Create the payload for the SKA policy modification request.
   *
   * Similar to how a policy has to be serialized into a blob before SKA key
   * generation, the modification payload has to be serialized. The payload
   * specifies a new policy for "usage". The "block", "unblock", and "modify"
   * policies are NULL, and thus remain unchanged.
   */
  rv = C_CreateModifyPayload(&usagePolicy, NULL, NULL, NULL, modPayload,
                             &modPayloadSize);

  /*
   * Create the "modify" approval token that the modify manager can sign.
   *
   * Note that the approval token includes the type of operation (CK_SKA_MODIFY)
   * and the payload.
   */
  CK_ULONG modifyTokBufLen = 1024;
  CK_BYTE_PTR modifyTokBuf = (uint8_t *)malloc(modifyTokBufLen);
  rv = C_CreateApprovalToken(hSession, CK_SKA_MODIFY, skaKey, modPayload,
                             modPayloadSize, nullptr, 0, nullptr, 0,
                             modifyTokBuf, &modifyTokBufLen);
  printf("Created modify token: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * The modify manager signs the "modify" approval token, thereby
   * approving the modification.
   */
  CK_ULONG davidSigBufLen = 1024;
  CK_BYTE_PTR davidSigBuf = (uint8_t *)malloc(davidSigBufLen);
  rv = ska_create_approval(david, modifyTokBuf, modifyTokBufLen, davidSigBuf,
                           &davidSigBufLen);
  CK_SKA_APPROVAL david_approval{CKAP_SIGNATURE, davidSigBuf, davidSigBufLen,
                                 david_pk.data(), david_pk.size()};

  printf("Modify approved by David: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * Using the approval, the business application can request the policy
   * modification.
   */
  rv = C_SKAModify(hSession, &skaKey, modifyTokBuf, modifyTokBufLen,
                   &david_approval, 1);
  printf("Key has been modified: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * The business application receives the approvals from the old finance
   * officers. But it cannot sign with these approvals because they're fired.
   */
  CK_SKA_APPROVAL approvals[] = {alice_approval, bob_approval};
  CK_ULONG signatureBufferLen = 1024;
  CK_BYTE_PTR signatureBuffer = (CK_BYTE_PTR)malloc(signatureBufferLen);

  CK_MECHANISM mech;
  memset(&mech, 0, sizeof(CK_MECHANISM));
  mech.mechanism = CKM_RSA_PKCS;
  rv =
      C_SKASign(hSession, &mech, skaKey, approvalTokBuf, approvalTokBufLen,
                approvals, 2, signatureBuffer, &signatureBufferLen, NULL, NULL);
  printf("Alice, Bob can no longer approve signing: %s\n",
         rv != CKR_OK ? "OK" : "NOT OK");
  if (rv == CKR_OK)
    return rv;

  /**
   * Instead, the new finance officer approves the sign operation.
   * Erin sends their approval signature to the business application.
   */
  CK_ULONG erinSigBufLen = 1024;
  CK_BYTE_PTR erinSigBuf = (uint8_t *)malloc(erinSigBufLen);

  Botan::PK_Signer signer(erin, rng, "EMSA1(SHA-256)",
                          Botan::Signature_Format::DER_SEQUENCE);
  std::vector<uint8_t> sig =
      signer.sign_message(approvalTokBuf, approvalTokBufLen, rng);

  std::vector<uint8_t> sig_der;
  Botan::DER_Encoder(sig_der)
      .start_cons(Botan::SEQUENCE)
      .encode(Botan::AlgorithmIdentifier(
          "ECDSA/EMSA1(SHA-256)", Botan::AlgorithmIdentifier::USE_NULL_PARAM))
      .encode(sig, Botan::BIT_STRING)
      .end_cons();

  if (sig_der.size() > erinSigBufLen) {
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(erinSigBuf, sig_der.data(), sig_der.size());
  erinSigBufLen = sig_der.size();

  CK_SKA_APPROVAL erin_approval{CKAP_SIGNATURE, erinSigBuf, erinSigBufLen,
                                erin_pk.data(), erin_pk.size()};

  printf("Approved by Erin: OK\n");

  /**
   * With Erin's approval, the SKA sign operation goes through successfully.
   */
  rv = C_SKASign(hSession, &mech, skaKey, approvalTokBuf, approvalTokBufLen,
                 &erin_approval, 1, signatureBuffer, &signatureBufferLen, NULL,
                 NULL);
  printf("Signed using SKA key: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
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

  free(modifyTokBuf);
  free(modPayload);
  free(erinSigBuf);
  free(davidSigBuf);
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
