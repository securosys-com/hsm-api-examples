/**
 * # Securosys PKCS#11 example: RSA
 *
 * This example shows how to:
 *
 * - List keys
 * - Generate an RSA key pair
 * - Encrypt and decrypt with an RSA key pair
 */

#include <assert.h>
#include <stdbool.h> // TODO: only needed because of bool in pkcs11.h header file
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "primus_common.h"

#define NUM_ATTR(x) (sizeof(x) / sizeof(CK_ATTRIBUTE))

CK_RV list_private_keys(CK_SESSION_HANDLE session)
{
    CK_RV rv = CKR_OK;
    printf("\nListing private keys...\n");

    CK_OBJECT_HANDLE objects[10];
    CK_ULONG objectCount;

    // Search template
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)}};

    rv = C_FindObjectsInit(session, template, 1);
    if (rv != CKR_OK)
        return rv;

    while (1)
    {
        rv = C_FindObjects(session, objects, 10, &objectCount);
        if (rv != CKR_OK)
            return rv;

        if (objectCount == 0)
            break;

        printf("Getting attributes...\n");
        for (int i = 0; i < objectCount && i < 10; i++)
        {
            char label[64] = {0};  // if too small, will return CKR_BUFFER_TOO_SMALL
            CK_KEY_TYPE type = -1; // CKK_RSA == 0

            CK_ATTRIBUTE attr[] = {
                {CKA_LABEL, label, 64},
                {CKA_KEY_TYPE, &type, sizeof(CK_KEY_TYPE)},
            };

            // Ignore the return value and just continue with the next attribute
            C_GetAttributeValue(session, objects[i], attr, 2);

            printf("Label: %s\n", label);
            printf("Key type: %lu\n", type);
        }
    }

    rv = C_FindObjectsFinal(session);

    return rv;
}

CK_RV rsa(CK_SESSION_HANDLE session)
{
    CK_RV rv = CKR_OK;
    printf("\nGenerating RSA key pair...\n");

    CK_OBJECT_HANDLE privateKey, publicKey;
    CK_MECHANISM genMechanism = {
        CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_ULONG modulus_bits = 3072;
    CK_BYTE exponent[] = {0x01, 0x00, 0x01}; // 65537
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    CK_UTF8CHAR label[] = "my-c-key";

    CK_ATTRIBUTE publicTemplate[] = {
        {CKA_TOKEN, &bTrue, sizeof(bTrue)},
        {CKA_PRIVATE, &bFalse, sizeof(bFalse)},
        {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
        {CKA_PUBLIC_EXPONENT, &exponent, sizeof(exponent)},
        {CKA_LABEL, &label, sizeof(label) - 1}, // must not be null-terminated
        // key attributes
        {CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
        {CKA_VERIFY, &bFalse, sizeof(bFalse)},
    };

    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_TOKEN, &bTrue, sizeof(bTrue)},
        {CKA_PRIVATE, &bTrue, sizeof(bTrue)},
        {CKA_LABEL, &label, sizeof(label) - 1},
        // key attributes
        {CKA_DECRYPT, &bTrue, sizeof(bTrue)},
        {CKA_SIGN, &bFalse, sizeof(bFalse)},
    };

    rv = C_GenerateKeyPair(
        session, &genMechanism,
        publicTemplate, NUM_ATTR(publicTemplate),
        privateTemplate, NUM_ATTR(privateTemplate),
        &publicKey, &privateKey);
    if (rv != CKR_OK)
        return rv;

    printf("Encrypting with RSA...\n");

    CK_RSA_PKCS_OAEP_PARAMS params = {
        CKM_SHA256, CKG_MGF1_SHA256, 0, NULL_PTR, 0};
    CK_MECHANISM encMechanism = {
        CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
    CK_BYTE message[] = "i like pizza";
    CK_BYTE_PTR ciphertext;
    CK_ULONG ciphertextLen = 0;

    rv = C_EncryptInit(session, &encMechanism, publicKey);
    if (rv != CKR_OK)
    {
        C_DestroyObject(session, publicKey);
        C_DestroyObject(session, privateKey);
        return rv;
    }

    rv = C_Encrypt(session, message, sizeof(message), NULL_PTR, &ciphertextLen);
    if (rv != CKR_OK)
    {
        C_DestroyObject(session, publicKey);
        C_DestroyObject(session, privateKey);
        return rv;
    }

    printf("ciphertextLen: %lu\n", ciphertextLen);
    ciphertext = calloc(ciphertextLen, sizeof(CK_BYTE));

    rv = C_Encrypt(session, message, sizeof(message), ciphertext, &ciphertextLen);
    if (rv != CKR_OK)
    {
        free(ciphertext);
        C_DestroyObject(session, publicKey);
        C_DestroyObject(session, privateKey);
        return rv;
    }

    printf("Decrypting with RSA...\n");

    rv = C_DecryptInit(session, &encMechanism, privateKey);
    if (rv != CKR_OK)
    {
        free(ciphertext);
        C_DestroyObject(session, publicKey);
        C_DestroyObject(session, privateKey);
        return rv;
    }

    CK_BYTE_PTR plaintext;
    CK_ULONG plaintextLen = 0;

    rv = C_Decrypt(session, ciphertext, ciphertextLen, NULL_PTR, &plaintextLen);
    if (rv != CKR_OK)
    {
        free(ciphertext);
        C_DestroyObject(session, publicKey);
        C_DestroyObject(session, privateKey);
        return rv;
    }

    printf("plaintextLen: %lu\n", plaintextLen);
    plaintext = calloc(plaintextLen, sizeof(CK_BYTE));

    rv = C_Decrypt(session, ciphertext, ciphertextLen, plaintext, &plaintextLen);
    if (rv != CKR_OK)
    {
        free(plaintext);
        free(ciphertext);
        C_DestroyObject(session, publicKey);
        C_DestroyObject(session, privateKey);
        return rv;
    }

    assert(memcmp(message, plaintext, sizeof(message)) == 0);

    free(plaintext);
    free(ciphertext);

    rv = list_private_keys(session);
    if (rv != CKR_OK)
    {
        C_DestroyObject(session, publicKey);
        C_DestroyObject(session, privateKey);
        return rv;
    }

    printf("Destroying key pair again...\n");
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

    rv = list_private_keys(session);
    if (rv != CKR_OK)
    {
        printf("Got return value 0x%lx\n", rv);
        CloseSession(session);
        return rv;
    }

    rv = rsa(session);
    if (rv != CKR_OK)
    {
        printf("Got return value 0x%lx\n", rv);
        CloseSession(session);
        return rv;
    }

    CloseSession(session);
    return rv;
}
