// SPDX-FileCopyrightText: Copyright 2025 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * # Securosys PKCS#11 example: Attestation
 *
 * This example shows how to:
 *
 * - Create an AES key
 * - Create an RSA attestation key pair
 * - Get an attestation
 * - Verify an attestation
 *
 * Note that attestation requires the Root Key Store (RKS) to be initialised on the HSM.
 *
 * This file uses C++ and Botan to verify the attestation.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// C++
#include <string>
#include <vector>

// Botan
#include <botan/data_src.h>
#include <botan/pubkey.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>

#include "pkcs11.h"
#include "primus_common.h"

#define NUM_ATTR(x) (sizeof(x) / sizeof(CK_ATTRIBUTE))

CK_RV attestation(CK_SESSION_HANDLE session)
{
    CK_RV rv = CKR_OK;

    CK_BOOL bTrue = CK_TRUE;
    CK_BOOL bFalse = CK_FALSE;

    printf("Generating AES key to be attested...\n");

    CK_OBJECT_HANDLE aesKey;
    CK_MECHANISM aesKeyGenMechanism = {
        CKM_AES_KEY_GEN, NULL_PTR, 0};
    CK_ULONG keySize = 32;
    CK_UTF8CHAR aesLabel[] = "my-c-aes-key";

    CK_ATTRIBUTE aesKeyAttr[] = {
        {CKA_TOKEN, &bTrue, sizeof(bTrue)},
        {CKA_LABEL, &aesLabel, sizeof(aesLabel) - 1}, // must not be null-terminated
        {CKA_VALUE_LEN, &keySize, sizeof(keySize)},
        // key attributes
        {CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
        {CKA_DECRYPT, &bTrue, sizeof(bTrue)},
        {CKA_WRAP, &bTrue, sizeof(bTrue)},
        {CKA_UNWRAP, &bTrue, sizeof(bTrue)},
        {CKA_SIGN, &bTrue, sizeof(bTrue)}, // for MAC
        {CKA_VERIFY, &bTrue, sizeof(bTrue)},
    };

    rv = C_GenerateKey(session, &aesKeyGenMechanism, aesKeyAttr, NUM_ATTR(aesKeyAttr), &aesKey);
    if (rv != CKR_OK)
        return rv;

    printf("Generating RSA attestation key pair...\n");

    CK_OBJECT_HANDLE privateKey, publicKey;

    CK_MECHANISM rsaGenMechanism = {
        CKM_RKS_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0}; // important
    CK_ULONG modulus_bits = 3072;
    CK_BYTE exponent[] = {0x01, 0x00, 0x01}; // 65537
    CK_UTF8CHAR rsaLabel[] = "my-c-attestation-key";

    CK_ATTRIBUTE publicTemplate[] = {
        {CKA_TOKEN, &bTrue, sizeof(bTrue)},
        {CKA_PRIVATE, &bFalse, sizeof(bFalse)},
        {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
        {CKA_PUBLIC_EXPONENT, &exponent, sizeof(exponent)},
        //{CKA_LABEL, &rsaLabel, sizeof(rsaLabel) - 1}, // must not be null-terminated
    };

    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_TOKEN, &bTrue, sizeof(bTrue)},
        {CKA_PRIVATE, &bTrue, sizeof(bTrue)},
        {CKA_LABEL, &rsaLabel, sizeof(rsaLabel) - 1},
        // key attributes
        {CKA_RKS_ATTESTATION_SIGN, &bTrue, sizeof(bTrue)}, // important
    };

    rv = C_GenerateKeyPair(
        session, &rsaGenMechanism,
        publicTemplate, NUM_ATTR(publicTemplate),
        privateTemplate, NUM_ATTR(privateTemplate),
        &publicKey, &privateKey);
    if (rv != CKR_OK)
    {
        C_DestroyObject(session, aesKey);
        return rv;
    }

    printf("Getting attestation...\n");

    // As of June 2025, the following mechanisms are supported for attestation:
    //
    // - CKM_SHA256_RSA_PKCS_PSS
    // - CKM_ECDSA_SHA256
    CK_MECHANISM attestMechanism = {CKM_SHA256_RSA_PKCS_PSS, NULL_PTR, 0};

    // Create large enough buffers.
    // C_RKSAttestKey() will return CKR_BUFFER_TOO_SMALL (0x150) when too small.
    CK_BYTE xmlBuffer[2048] = {0};
    CK_ULONG xmlBufferLen = sizeof(xmlBuffer);
    CK_BYTE sigBuffer[1024] = {0};
    CK_ULONG sigBufferLen = sizeof(sigBuffer);

    rv = C_RKSAttestKey(
        session, &attestMechanism,
        privateKey, aesKey,
        xmlBuffer, &xmlBufferLen,
        sigBuffer, &sigBufferLen);
    if (rv != CKR_OK)
    {
        C_DestroyObject(session, aesKey);
        C_DestroyObject(session, privateKey);
        C_DestroyObject(session, publicKey);
        return rv;
    }
    printf("xmlBufferLen: %lu\n", xmlBufferLen);
    printf("sigBufferLen: %lu\n", sigBufferLen);
    printf("Got xmlBuffer:\n%s\n\n", xmlBuffer);

    printf("Getting certificate chain of attestation key...\n");

    CK_ATTRIBUTE certChainAttr[] = {
        CKA_RKS_CERTIFICATE_CHAIN, NULL_PTR, 0};

    rv = C_GetAttributeValue(session, privateKey, certChainAttr, 1);
    if (rv != CKR_OK)
    {
        C_DestroyObject(session, aesKey);
        C_DestroyObject(session, privateKey);
        C_DestroyObject(session, publicKey);
        return rv;
    }

    CK_ULONG certChainLen = certChainAttr[0].ulValueLen;
    CK_BYTE_PTR certChain = (CK_BYTE_PTR)calloc(certChainLen, sizeof(CK_BYTE));
    certChainAttr[0].pValue = certChain;

    rv = C_GetAttributeValue(session, privateKey, certChainAttr, 1);
    if (rv != CKR_OK)
    {
        C_DestroyObject(session, aesKey);
        C_DestroyObject(session, privateKey);
        C_DestroyObject(session, publicKey);
        return rv;
    }

    printf("Got cert chain:\n%s\n\n", certChain);

    printf("Parsing cert chain...\n");

    std::string certChainString((char *)certChain, certChainLen);
    const std::string startMarker = "-----BEGIN CERTIFICATE-----";
    const std::string endMarker = "-----END CERTIFICATE-----";

    std::vector<Botan::X509_Certificate> certs;
    size_t pos = 0;

    while (true)
    {
        size_t begin = certChainString.find(startMarker, pos);
        if (begin == std::string::npos)
            break;

        size_t end = certChainString.find(endMarker, begin);
        if (begin == std::string::npos)
            break;
        end += endMarker.length();

        std::string certString = certChainString.substr(begin, end - begin);
        Botan::DataSource_Memory dataSrc = Botan::DataSource_Memory(certString);
        Botan::X509_Certificate cert = Botan::X509_Certificate(dataSrc);
        certs.emplace_back(cert);

        pos = end;
    }

    printf("Num certs: %lu \n", certs.size());
    for (Botan::X509_Certificate c : certs)
    {
        printf("SHA-256 fingerprint: %s \n", c.fingerprint("SHA-256").c_str());
    }

    printf("Validating cert chain...\n");

    Botan::X509_Certificate root = certs[2];
    Botan::Certificate_Store_In_Memory certStore = Botan::Certificate_Store_In_Memory(root);
    std::vector<Botan::Certificate_Store *> rootStores = {&certStore};
    Botan::Path_Validation_Restrictions restrictions; // unused

    Botan::Path_Validation_Result validationResult = Botan::x509_path_validate(certs, restrictions, rootStores);
    printf("Cert chain validation result: %s\n", validationResult.result_string().c_str());

    printf("Validating attestation...\n");

    Botan::X509_Certificate leaf = certs[0];
    Botan::Public_Key *leafPk = leaf.subject_public_key();
    Botan::PK_Verifier verifier(*leafPk, "PSS(SHA-256)");
    bool result = verifier.verify_message(xmlBuffer, xmlBufferLen, sigBuffer, sigBufferLen);

    printf("Attestation validation result: %s\n", result ? "OK" : "NOT OK");
    printf("Trust root fingerprint: %s\n", root.fingerprint("SHA-256").c_str());
    printf("Compare this fingerprint against the published list: https://support.securosys.com/external/knowledge-base/article/147 \n");

    printf("Destroying keys...\n");
    C_DestroyObject(session, aesKey);
    C_DestroyObject(session, publicKey);
    C_DestroyObject(session, privateKey);

    return rv;
}

int main()
{
    CK_RV rv = CKR_OK;

    CK_CHAR_PTR userPin = (CK_CHAR_PTR)getenv("P11_PIN");
    if (userPin == NULL_PTR)
    {
        printf("P11_PIN envvar not set\n");
        return CKR_GENERAL_ERROR;
    }

    CK_ULONG userPinLen = strlen((char *)userPin);
    CK_SESSION_HANDLE session;

    rv = SetupSession(&session, userPin, userPinLen);
    if (rv != CKR_OK)
        return rv;

    rv = attestation(session);
    if (rv != CKR_OK)
    {
        printf("Got return value 0x%lx\n", rv);
        CloseSession(session);
        return rv;
    }

    CloseSession(session);
    return rv;
}
