// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: SKA
 *
 * This example shows how to:
 *
 * 1. Create an SKA policy. A policy is a set of rules that have to be adhered
 *    to when an SKA key is to be used.
 * 2. Serialize the policy. This is needed to create or modify an SKA key.
 */

#include "pkcs11.h"

// C++
#include <iostream>

// Botan
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/x509cert.h>
#include <botan/x509self.h>

CK_RV ska_create_policy() {
  CK_RV rv = CKR_OK;

  Botan::AutoSeeded_RNG rng;

  /**
   * First of all, we have to know the public keys of the approvers. Approvers
   * possess public-private key pairs. Later, they sign approvals with their
   * private key. These can be verified with the public key. The public key is
   * listed in the SKA policy.
   */
  Botan::RSA_PrivateKey key1(rng, 2048);
  std::vector<uint8_t> approvalPubKey = key1.subject_public_key();

  /**
   * Approver 2 also has a public-private keypair.
   * Instead of a raw public key, policies can also include the public key in
   * form of a certificate. When using SKA as a SAM (for eIDAS use cases), using
   * certificates is required. The certificate needs to be PEM or DER-encoded.
   */
  Botan::RSA_PrivateKey key2(rng, 2048);
  Botan::X509_Cert_Options opts;
  opts.common_name = "approver_2";
  Botan::X509_Certificate cert =
      Botan::X509::create_self_signed_cert(opts, key2, "SHA-256", rng);
  std::vector<uint8_t> cert_der = cert.BER_encode();

  /**
   * Create a group of approvers. For a group to approve of an SKA key usage, a
   * quorum of approvers have to approve.
   */
  CK_SKA_APPROVER approvers[] = {
      // Approver 1
      {
          (CK_CHAR_PTR) "approver_1", 11, // The approver name
          CKAP_SIGNATURE, approvalPubKey.data(),
          approvalPubKey.size() // The public key.
      },
      // Approver 2
      {
          NULL, 0, // No approver name, because the subject name from the
                   // certificate will be used.
          CKAP_CERTIFICATE, cert_der.data(), cert_der.size() // The certificate.
      }};

  /**
   * The group contains two approvers, but the quorum is 1.
   * This makes it 1-of-2, meaning that either one of the two can approve an
   * SKA key usage.
   */
  CK_ULONG quorum = 1;
  CK_SKA_GROUP group = {
      (CK_CHAR_PTR) "group_1", 8, // Group name
      quorum,                     // Quorum
      approvers, 2                // List of approvers
  };

  /**
   * Add group to a token. A token is a "super-group", a group of groups.
   *
   * For a token to approve an SKA key usage, all groups within the token have
   * to approve (AND). It is possible to specify a delay/timelock and a timeout
   * for a token (i.e., a time window in which an approval is valid). If both
   * values are 0, an approval is valid forever.
   *
   * SKA policy tokens should not be confused with SKA approval tokens
   * (see the `ska_create_approval.cpp` sample and the `C_CreateApprovalToken`
   * function) or PKCS#11 tokens.
   */
  CK_ULONG delaySeconds = 10;
  CK_ULONG timeoutSeconds = 30;
  CK_SKA_TOKEN token = {// Token name
                        (CK_CHAR_PTR) "token_1", 8,
                        // Timelock and timeout
                        delaySeconds, timeoutSeconds,
                        // List of groups
                        &group, 1};

  /**
   * Finally, we can specify a policy.
   * A policy is met if any of the tokens approves (OR).
   */
  CK_SKA_POLICY policy = {&token, 1};

  /**
   * Serialize the policy into a buffer.
   *
   * This buffer will need to be specified when generating an SKA key or when
   * modifying the policies of already existing SKA key.
   */
  CK_ULONG policyBufLen = 2048UL;
  CK_BYTE_PTR policyBuf = (CK_BYTE_PTR)malloc(policyBufLen);

  rv = C_SerializePolicy(&policy, policyBuf, &policyBufLen);
  printf("Serialized policy: %s\n", rv == CKR_OK ? "OK" : "NOT OK");

  if (rv != CKR_OK)
    return rv;

  std::cout << "Policy: " << policyBufLen << ", "
            << Botan::hex_encode(policyBuf, policyBufLen) << std::endl;

  free(policyBuf);

  return rv;
}

int main() {
  CK_RV rv = ska_create_policy();
  if (rv != CKR_OK) {
    printf("Got return value 0x%lx\n", rv);
  }
  return rv;
}
