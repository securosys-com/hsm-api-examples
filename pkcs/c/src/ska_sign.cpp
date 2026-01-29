// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: SKA
 *
 * This example shows how to:
 *
 * 1. Create an SKA key (with a policy and some approvers).
 * 2. Create an approval token.
 * 3. Sign the approval token, allowing a key usage with a certain payload.
 * 4. Using the SKA key to sign the approved payload.
 */

#include "pkcs11.h"
#include "primus_common.h"
#include "ska_create_approval.h"
#include "ska_create_common.h"

// Botan
#include <botan/auto_rng.h>
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

  /**
   * Create a payload to be signed by the SKA key
   */
  CK_ULONG payloadSize = 32;
  CK_BYTE_PTR payloadBuffer = (uint8_t *)malloc(payloadSize);
  memset(payloadBuffer, 'A', payloadSize);

  /**
   * The business application creates the "approval token".
   * It contains the type of operation to do with the SKA key
   * (here: CK_SKA_SIGN) and the payload for the operation.
   *
   * Optionally, for SKA keys with timelocks/timeouts, the approval token
   * also includes a signed timestamp. See `ska_sign_with_timestamp.cpp`.
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
   * This signals that they approve the SKA key usage with the given payload.
   *
   * Usually, this does NOT happen in the business application. Instead, it
   * happens on mobile apps where the approvers locally hold their private keys.
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

  CK_MECHANISM mech;
  memset(&mech, 0, sizeof(CK_MECHANISM));
  mech.mechanism = CKM_RSA_PKCS;

  rv =
      C_SKASign(hSession, &mech, skaKey, approvalTokBuf, approvalTokBufLen,
                approvals, 2, signatureBuffer, &signatureBufferLen, NULL, NULL);

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
