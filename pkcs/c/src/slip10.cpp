// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: SLIP-10
 *
 * This example shows how to:
 *
 * - Generate a master key pair from a binary seed.
 * - Derive a child key pair from a master private key and a derivation path.
 *
 * This example uses ephemeral session objects to avoid polluting the keystore.
 * If you want to persist the master key or child keys, simply set a CKA_LABEL
 * and set CKA_TOKEN=true.
 *
 * ## References
 *
 * - <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
 * - <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>
 */

#include <iomanip>
#include <iostream>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

#include "pkcs11.h"
#include "primus_common.h"

// clang-format off
/**
 * Creates a master key pair from a given seed, as defined by SLIP-10.
 *
 * Input:
 *
 * For secp256k1:
 *    keyType: CKK_EC_SLIP10
 *    mech: CKM_EC_SLIP10_KEY_PAIR_GEN
 *    curveParams: std::vector<uint8_t>{ 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A }
 *
 * For secp256r1:
 *      keyType: CKK_EC_SLIP10
 *      mech: CKM_EC_SLIP10_KEY_PAIR_GEN
 *      curveParams: std::vector<uint8_t>{ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }
 *
 * For ed25519:
 *      keyType: CKK_EC_EDWARDS_SLIP10
 *      mech: CKM_EC_EDWARDS_SLIP10_KEY_PAIR_GEN
 *      curveParams: std::vector<uint8_t>{ 0x06, 0x03, 0x2B, 0x65, 0x70 }
 *
 * See also the list of curve OIDs:
 * https://docs.securosys.com/pkcs/Concepts/specifications/#supported-ecc-curves
 *
 * Output:
 * The generated master key pair: (pubKey, privKey)
 */
// clang-format on
CK_RV createSlip10MasterKeyPair(CK_SESSION_HANDLE hSession, CK_KEY_TYPE keyType,
                                CK_MECHANISM_TYPE mech,
                                const std::vector<uint8_t> &seed,
                                const std::vector<uint8_t> &curveParams,
                                CK_OBJECT_HANDLE_PTR pubKey,
                                CK_OBJECT_HANDLE_PTR privKey) {
  CK_MECHANISM mechanism;
  memset(&mechanism, 0, sizeof(CK_MECHANISM));
  mechanism.mechanism = mech;
  mechanism.pParameter =
      seed.size() ? const_cast<uint8_t *>(seed.data())
                  : nullptr; // If the seed is empty, the HSM will generate one.
  mechanism.ulParameterLen = seed.size();

  CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
  CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

  std::vector<CK_ATTRIBUTE> slip10PublicKeyAttr = {
      {CKA_CLASS, &pubKeyClass, sizeof(CK_OBJECT_CLASS)},
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      // Object is stored ephemeral in session object storage
      {CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
      // Key can be used to derive sub keys
      {CKA_DERIVE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_VERIFY, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)},
      // The curve OID
      {CKA_EC_PARAMS, const_cast<uint8_t *>(curveParams.data()),
       CK_ULONG(curveParams.size())}};

  std::vector<CK_ATTRIBUTE> slip10PrivateKeyAttr = {
      {CKA_CLASS, &privKeyClass, sizeof(CK_OBJECT_CLASS)},
      {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
      // Object is stored ephemeral in session object storage
      {CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
      // Key can be used to derive sub keys
      {CKA_DERIVE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_SIGN, &bTrue, sizeof(CK_BBOOL)},
      {CKA_EXTRACTABLE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_SENSITIVE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)}};

  printf("Generating master key pair...\n");

  return C_GenerateKeyPair(hSession, &mechanism, slip10PublicKeyAttr.data(),
                           slip10PublicKeyAttr.size(),
                           slip10PrivateKeyAttr.data(),
                           slip10PrivateKeyAttr.size(), pubKey, privKey);
}

/**
 * Derives a child key pair from the given master private key using SLIP-10.
 *
 * Inputs:
 *
 * - Master private key
 * - Derivation path
 *
 * Example derivation path: "m/44'/0'/0'/0/1"
 * ==> std::vector<CK_ULONG>{0x8000002C, 0x80000000, 0x80000000, 0, 1}
 *
 * Note: for ed25519 only hardened paths are allowed (> 0x80000000).
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

  CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

  std::vector<CK_ATTRIBUTE> slip10PublicKeyAttr = {
      {CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_VERIFY, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)}};

  std::vector<CK_ATTRIBUTE> slip10PrivateKeyAttr = {
      {CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_SIGN, &bTrue, sizeof(CK_BBOOL)},
      // If the parent is non-extractable, the child must also be
      // non-extractable.
      {CKA_EXTRACTABLE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_SENSITIVE, &bTrue, sizeof(CK_BBOOL)},
      {CKA_MODIFIABLE, &bTrue, sizeof(CK_BBOOL)}};

  printf("Deriving child key pair...\n");

  return C_DeriveKeyPair(
      hSession, &mechanism, masterPrivKey, slip10PublicKeyAttr.data(),
      slip10PublicKeyAttr.size(), slip10PrivateKeyAttr.data(),
      slip10PrivateKeyAttr.size(), derivedPublicKey, derivedPrivateKey);
}

CK_RV getSlip10Attributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE key) {
  CK_RV rv = CKR_OK;

  std::vector<char> label(32);
  // SLIP-10 defines the chain code to be always 32 bytes
  std::vector<uint8_t> chainCode(32);

  CK_ATTRIBUTE attr[] = {
      {CKA_LABEL, label.data(), label.size()},
      {CKA_SLIP10_CHAIN_CODE, chainCode.data(), chainCode.size()},
  };

  printf("Getting attributes...\n");

  rv = C_GetAttributeValue(hSession, key, attr, 2);
  if (rv != CKR_OK)
    return rv;

  // Since we didn't specify a label when creating the key, the HSM choose one.
  std::cout << "    Label: " << std::string(label.begin(), label.end())
            << std::endl;

  std::cout << "    Chain code:" << std::hex;
  for (uint8_t i : chainCode)
    std::cout << ' ' << static_cast<int>(i);
  std::cout << std::endl;

  return rv;
}

CK_RV slip10(CK_SESSION_HANDLE hSession) {
  CK_RV rv = CKR_OK;

  CK_OBJECT_HANDLE masterPubKey, masterPrivKey;

  // Seed must be between 128 and 512 bits
  auto seed = std::vector<uint8_t>(32, 0x41);
  printf("Seed length: %ld bits\n", seed.size() * 8);

  // OID of curve secp256k1
  // https://docs.securosys.com/pkcs/Concepts/specifications/#supported-ecc-curves
  // Note: not all of these curve are supported by SLIP-10!
  auto curveOid =
      std::vector<uint8_t>{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};

  // Generate a secp256k1 master key from the given seed
  rv = createSlip10MasterKeyPair(hSession, CKK_EC_SLIP10,
                                 CKM_EC_SLIP10_KEY_PAIR_GEN, seed, curveOid,
                                 &masterPubKey, &masterPrivKey);
  if (rv != CKR_OK)
    return rv;

  // Print some attributes
  rv = getSlip10Attributes(hSession, masterPrivKey);
  if (rv != CKR_OK)
    return rv;

  CK_OBJECT_HANDLE childPubKey, childPrivKey;

  // Example path: "m/44'/0'/0'/0/1"
  // Hardened paths (with the apostrophe) start at 2^31.
  auto derivationPath =
      std::vector<CK_ULONG>{0x8000002C, 0x80000000, 0x80000000, 0, 1};

  // Derive a child key pair from the master key
  rv = deriveSlip10ChildKeyPair(hSession, masterPrivKey, derivationPath,
                                &childPubKey, &childPrivKey);
  if (rv != CKR_OK)
    return rv;

  // Print some attributes
  rv = getSlip10Attributes(hSession, childPrivKey);

  return rv;
}

int main() {
  CK_RV rv = CKR_OK;

  CK_CHAR_PTR userPin = (CK_CHAR_PTR)getenv("P11_PIN");
  if (userPin == NULL_PTR) {
    printf("P11_PIN envvar not set\n");
    return CKR_GENERAL_ERROR;
  }

  CK_ULONG userPinLen = strlen((char *)userPin);
  CK_SESSION_HANDLE session;

  rv = SetupSession(&session, userPin, userPinLen);
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
