// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: SLIP-10 with SKA
 *
 * This example shows how to:
 *
 * - Generate a master key pair from a seed and with an SKA policy attached.
 * - Derive a child key pair with SLIP-10 and sign with it.
 *
 * This sample is simplified to show the interaction between SLIP-10 and SKA.
 * For more details on either of them, see the dedicated SLIP-10 and SKA
 * samples.
 */

#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

#include <botan/auto_rng.h>
#include <botan/rsa.h>

#include "pkcs11.h"
#include "primus_common.h"
#include "ska_create_approval.h"

CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

/**
 * Creates a master key pair from a given seed, as defined by SLIP-10.
 * Assigns an SKA policy to it.
 */
CK_RV createSlip10MasterKeyPair(CK_SESSION_HANDLE hSession,
                                std::vector<uint8_t> &approver_pk,
                                CK_OBJECT_HANDLE_PTR pubKey,
                                CK_OBJECT_HANDLE_PTR privKey) {
  CK_RV rv = CKR_OK;

  // Create simple policy with single token, single group and quorum size 1.
  // See the ska_xyz.cpp for more samples.
  CK_ULONG delay = 0;
  CK_ULONG timeout = 0;
  CK_SKA_APPROVER approvers = {nullptr, 0, CKAP_SIGNATURE, approver_pk.data(),
                               approver_pk.size()};
  CK_SKA_GROUP group = {NULL, 0, 1, &approvers, 1};
  CK_SKA_TOKEN policyToken = {NULL, 0, delay, timeout, &group, 1};
  CK_SKA_POLICY policy = {&policyToken, 1};

  // Serialize the policy into buffers that can be passed to the HSM.
  CK_ULONG policySize = 1024;
  std::vector<uint8_t> serialPolicy(policySize);
  rv = C_SerializePolicy(&policy, serialPolicy.data(), &policySize);
  if (rv != CKR_OK)
    return rv;
  serialPolicy.resize(policySize);

  // Define the parameters for the master key.
  // See slip10.cpp for details.
  CK_KEY_TYPE keyType = CKK_EC_SLIP10;
  CK_MECHANISM_TYPE mechType = CKM_SKA_EC_SLIP10_KEY_PAIR_GEN; // sic
  const std::vector<uint8_t> curveParams = {
      0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A}; // OID of secp256k1
  auto seed(Botan::AutoSeeded_RNG().random_vec(32));

  CK_MECHANISM mechanism{mechType, nullptr, 0};
  mechanism.pParameter =
      seed.size() ? const_cast<uint8_t *>(seed.data())
                  : nullptr; // If the seed is empty, the HSM will generate one.
  mechanism.ulParameterLen = seed.size();

  CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privKeyClass = CKO_SKA_PRIVATE_KEY; // sic
  CK_CRYPTOCURRENCY currency = CKCC_BITCOIN;          // sic

  // Public attributes are the same as for a normal, non-SKA SLIP-10 key.
  std::vector<CK_ATTRIBUTE> slip10PublicKeyAttr = {
      {CKA_CLASS, &pubKeyClass, sizeof(CK_OBJECT_CLASS)},
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      {CKA_TOKEN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_VERIFY, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_EC_PARAMS, const_cast<uint8_t *>(curveParams.data()),
       CK_ULONG(curveParams.size())}};

  // Private attributes are the same as for a normal SLIP-10 key, but with the
  // SKA policies added.
  std::vector<CK_ATTRIBUTE> slip10PrivateKeyAttr = {
      {CKA_CLASS, &privKeyClass, sizeof(CK_OBJECT_CLASS)},
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      {CKA_TOKEN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_SIGN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_EXTRACTABLE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_SENSITIVE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)},
      // SKA-specific attributes
      {CKA_SKA_USAGE_ACCESS_BLOB, serialPolicy.data(), serialPolicy.size()},
      {CKA_SKA_BLOCK_ACCESS_BLOB, serialPolicy.data(), serialPolicy.size()},
      {CKA_SKA_UNBLOCK_ACCESS_BLOB, serialPolicy.data(), serialPolicy.size()},
      {CKA_SKA_MODIFY_ACCESS_BLOB, serialPolicy.data(), serialPolicy.size()},
      {CKA_SKA_BLOCKED, &bFalse, sizeof(CK_BBOOL)},
      // Crypto-currency-specific attributes
      {CKA_SKA_CRYPTO_CURRENCY_TYPE, &currency, sizeof(CK_CRYPTOCURRENCY)},
      {CKA_SKA_SENSITIVE_PUBLIC_KEY, &bFalse, sizeof(CK_BBOOL)},
  };

  printf("Generating master key pair...\n");

  return C_GenerateKeyPair(hSession, &mechanism, slip10PublicKeyAttr.data(),
                           slip10PublicKeyAttr.size(),
                           slip10PrivateKeyAttr.data(),
                           slip10PrivateKeyAttr.size(), pubKey, privKey);
}

/**
 * Derives a child key pair from the given master private key using SLIP-10.
 * Same as in slip10.cpp.
 */
CK_RV deriveSlip10ChildKeyPair(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE masterPrivKey,
                               const std::vector<CK_ULONG> &path,
                               CK_OBJECT_HANDLE_PTR derivedPublicKey,
                               CK_OBJECT_HANDLE_PTR derivedPrivateKey) {
  CK_MECHANISM mechanism;
  memset(&mechanism, 0, sizeof(CK_MECHANISM));
  mechanism.mechanism = CKM_SLIP10_CHILD_DERIVE;

  CK_SLIP10_CHILD_DERIVE_PARAMS params;
  memset(&params, 0, sizeof(params));
  params.pulPathIndexes = const_cast<CK_ULONG_PTR>(path.data());
  params.ulIndexCount = path.size();

  mechanism.pParameter = &params;
  mechanism.ulParameterLen = sizeof(CK_SLIP10_CHILD_DERIVE_PARAMS);

  std::vector<CK_ATTRIBUTE> slip10PublicKeyAttr = {
      {CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_VERIFY, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)}};

  std::vector<CK_ATTRIBUTE> slip10PrivateKeyAttr = {
      {CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_SIGN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_EXTRACTABLE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_SENSITIVE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)}};

  printf("Deriving child key pair...\n");

  return C_DeriveKeyPair(
      hSession, &mechanism, masterPrivKey, slip10PublicKeyAttr.data(),
      slip10PublicKeyAttr.size(), slip10PrivateKeyAttr.data(),
      slip10PrivateKeyAttr.size(), derivedPublicKey, derivedPrivateKey);
}

/**
 * Sign with the child key pair.
 */
CK_RV signWithChildKeyPair(CK_SESSION_HANDLE hSession,
                           Botan::RSA_PrivateKey &approver_key,
                           CK_OBJECT_HANDLE derivedPublicKey,
                           CK_OBJECT_HANDLE derivedPrivateKey) {
  CK_RV rv = CKR_OK;
  auto data(Botan::AutoSeeded_RNG().random_vec(32));

  // Serialize the approval token that needs to be signed
  CK_ULONG approvalTokBufLen = 1024;
  std::vector<uint8_t> approvalTokBuf(approvalTokBufLen);
  rv = C_CreateApprovalToken(hSession, CK_SKA_SIGN, derivedPrivateKey,
                             data.data(), data.size(), nullptr, 0, nullptr, 0,
                             approvalTokBuf.data(), &approvalTokBufLen);

  printf("Created approval token: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  // Sign the approval
  std::vector<uint8_t> approver_pk = approver_key.subject_public_key();
  CK_ULONG approvalSigBufLen = 1024;
  std::vector<uint8_t> approvalSigBuf(approvalSigBufLen);
  rv = ska_create_approval(approver_key, approvalTokBuf.data(),
                           approvalTokBufLen, approvalSigBuf.data(),
                           &approvalSigBufLen);
  printf("Signed approval: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  // Build the signature request for the child key
  CK_SKA_APPROVAL approval{CKAP_SIGNATURE, approvalSigBuf.data(),
                           approvalSigBufLen, approver_pk.data(),
                           approver_pk.size()};
  std::vector<CK_SKA_APPROVAL> approvals = {approval};
  CK_MECHANISM signMech{CKM_ECDSA_SHA256, nullptr, 0};

  // Sign with the child key
  CK_ULONG signatureBufferLen = 0;
  rv = C_SKASign(hSession, &signMech, derivedPrivateKey, approvalTokBuf.data(),
                 approvalTokBufLen, approvals.data(), approvals.size(), nullptr,
                 &signatureBufferLen, NULL, NULL);
  if (rv != CKR_OK)
    return rv;

  std::vector<uint8_t> signatureBuffer(signatureBufferLen);
  rv = C_SKASign(hSession, &signMech, derivedPrivateKey, approvalTokBuf.data(),
                 approvalTokBufLen, approvals.data(), approvals.size(),
                 signatureBuffer.data(), &signatureBufferLen, NULL, NULL);

  printf("Signed using SKA key: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  // Verify the signature
  rv = C_VerifyInit(hSession, &signMech, derivedPublicKey);
  if (rv != CKR_OK)
    return rv;
  rv = C_Verify(hSession, data.data(), data.size(), signatureBuffer.data(),
                signatureBufferLen);

  printf("Verified: %s\n", rv == CKR_OK ? "OK" : "NOT OK");
  if (rv != CKR_OK)
    return rv;

  return rv;
}

CK_RV slip10(CK_SESSION_HANDLE hSession) {
  CK_RV rv = CKR_OK;

  // Create approver keypair
  Botan::AutoSeeded_RNG rng;
  Botan::RSA_PrivateKey approver_key(rng, 2048);
  std::vector<uint8_t> approver_pk = approver_key.subject_public_key();

  // Generate a master key
  CK_OBJECT_HANDLE masterPubKey, masterPrivKey;
  rv = createSlip10MasterKeyPair(hSession, approver_pk, &masterPubKey,
                                 &masterPrivKey);
  if (rv != CKR_OK)
    return rv;

  // Example path: "m/44'/0'/0'/0/1"
  // Hardened paths (with the apostrophe) start at 2^31.
  auto derivationPath =
      std::vector<CK_ULONG>{0x8000002C, 0x80000000, 0x80000000, 0, 1};

  // Derive a child key pair from the master key
  CK_OBJECT_HANDLE childPubKey, childPrivKey;
  rv = deriveSlip10ChildKeyPair(hSession, masterPrivKey, derivationPath,
                                &childPubKey, &childPrivKey);
  if (rv != CKR_OK)
    return rv;

  // SKA-sign with the derived key. Note that the SKA policy of the master key
  // applies.
  rv = signWithChildKeyPair(hSession, approver_key, childPubKey, childPrivKey);
  if (rv != CKR_OK)
    return rv;

  rv = C_DestroyObject(hSession, masterPubKey);
  rv = C_DestroyObject(hSession, masterPrivKey);
  rv = C_DestroyObject(hSession, childPubKey);
  rv = C_DestroyObject(hSession, childPrivKey);

  return rv;
}

int main() {
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session;

  rv = SetupSession(&session);
  if (rv != CKR_OK)
    return rv;

  rv = slip10(session);
  if (rv != CKR_OK) {
    printf("Got return value 0x%lx\n", rv);
    CloseSession(session);
    return rv;
  }

  CloseSession(session);
  return rv;
}
