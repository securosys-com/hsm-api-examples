// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: SKA
 *
 * This example shows how the risk manager (listed in the `block` and `unblock`
 * policies of the SKA key) can block and unblock the `usage` policy of the SKA
 * key. This is useful to (temporarily) block a key from being used.
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
  auto carol_pk = carol.subject_public_key();

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
   * However, the risk manager decides to step in and block the key from
   * being used. The risk manager creates an "block" approval token, signs it,
   * and makes the C_SKABlock request to the HSM.
   */
  CK_ULONG blockTokBufLen = 1024;
  CK_BYTE_PTR blockTokBuf = (uint8_t *)malloc(blockTokBufLen);
  rv = C_CreateApprovalToken(hSession, CK_SKA_BLOCK, skaKey, payloadBuffer,
                             payloadSize, nullptr, 0, nullptr, 0, blockTokBuf,
                             &blockTokBufLen);
  printf("Created block token: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  // The risk manager signs the "block" approval token
  CK_ULONG carolSigBufLen = 1024;
  CK_BYTE_PTR carolSigBuf = (uint8_t *)malloc(carolSigBufLen);
  rv = ska_create_approval(carol, blockTokBuf, blockTokBufLen, carolSigBuf,
                           &carolSigBufLen);
  CK_SKA_APPROVAL carol_approval{CKAP_SIGNATURE, carolSigBuf, carolSigBufLen,
                                 carol_pk.data(), carol_pk.size()};

  printf("Carol approved to block key: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  // The business application sends the "block" request to the HSM
  rv = C_SKABlock(hSession, &skaKey, blockTokBuf, blockTokBufLen,
                  &carol_approval, 1);
  printf("Key has been blocked: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * The application receives the approvals from the financial officers.
   * But it cannot use them to sign because the key is blocked.
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
  printf("Key is blocked (signing fails): %s\n",
         rv != CKR_OK ? "OK" : "NOT OK");
  if (rv == CKR_OK)
    return rv;

  /**
   * The risk manager unblocks the key again.
   */
  CK_ULONG unblockTokBufLen = 1024;
  CK_BYTE_PTR unblockTokBuf = (uint8_t *)malloc(unblockTokBufLen);
  rv = C_CreateApprovalToken(hSession, CK_SKA_UNBLOCK, skaKey, payloadBuffer,
                             payloadSize, nullptr, 0, nullptr, 0, unblockTokBuf,
                             &unblockTokBufLen);
  printf("Created unblock token: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  rv = ska_create_approval(carol, unblockTokBuf, unblockTokBufLen, carolSigBuf,
                           &carolSigBufLen);
  CK_SKA_APPROVAL carol_approval_unblock{CKAP_SIGNATURE, carolSigBuf,
                                         carolSigBufLen, carol_pk.data(),
                                         carol_pk.size()};

  printf("Carol approved to unblock key: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  rv = C_SKAUnblock(hSession, &skaKey, unblockTokBuf, unblockTokBufLen,
                    &carol_approval_unblock, 1);
  printf("Key has been unblocked: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  /**
   * The application uses the approvals it already had to successfully sign the
   * payload. Note that the approvals are still valid (because the SKA policy
   * does not have a timeout).
   */
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

  free(blockTokBuf);
  free(unblockTokBuf);
  free(carolSigBuf);
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
