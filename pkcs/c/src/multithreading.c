// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

/**
 * This example shows how to perform ECDSA signing concurrently using pthreads.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "primus_common.h"

CK_RV ec_sign(CK_SESSION_HANDLE session, int threadId) {
  CK_RV rv = CKR_OK;
  printf("[%d] Generating EC key pair...\n", threadId);

  CK_BBOOL bTrue = CK_TRUE;
  CK_BBOOL bFalse = CK_FALSE;

  CK_OBJECT_HANDLE privateKey, publicKey;
  CK_MECHANISM genMechanism = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};

  // OID for secp256r1, see
  // https://docs.securosys.com/pkcs/Concepts/specifications#supported-ecc-curves
  CK_BYTE ecParams[] = {0x06, 0x08, 0x2A, 0x86, 0x48,
                        0xCE, 0x3D, 0x03, 0x01, 0x07};

  CK_ATTRIBUTE publicTemplate[] = {
      {CKA_TOKEN, &bTrue, sizeof(bTrue)},
      {CKA_PRIVATE, &bFalse, sizeof(bFalse)},
      {CKA_EC_PARAMS, &ecParams, sizeof(ecParams)},
      // key attributes
      {CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
      {CKA_VERIFY, &bTrue, sizeof(bTrue)},
  };

  CK_ATTRIBUTE privateTemplate[] = {
      {CKA_TOKEN, &bTrue, sizeof(bTrue)},
      {CKA_PRIVATE, &bTrue, sizeof(bTrue)},
      {CKA_EXTRACTABLE, &bFalse, sizeof(CK_BBOOL)},
      {CKA_SENSITIVE, &bTrue, sizeof(CK_BBOOL)},
      // key attributes
      {CKA_DECRYPT, &bTrue, sizeof(bTrue)},
      {CKA_SIGN, &bTrue, sizeof(bTrue)},
  };

  rv = C_GenerateKeyPair(session, &genMechanism, publicTemplate,
                         NUM_ATTR(publicTemplate), privateTemplate,
                         NUM_ATTR(privateTemplate), &publicKey, &privateKey);
  if (rv != CKR_OK)
    return rv;

  printf("[%d] Signing with EC...\n", threadId);

  CK_MECHANISM sigMechanism = {CKM_ECDSA_SHA256, NULL, 0};
  CK_BYTE message[] = "i like pizza";
  CK_BYTE_PTR signature;
  CK_ULONG signatureLen = 0;

  rv = C_SignInit(session, &sigMechanism, privateKey);
  if (rv != CKR_OK) {
    C_DestroyObject(session, publicKey);
    C_DestroyObject(session, privateKey);
    return rv;
  }

  rv = C_Sign(session, message, sizeof(message), NULL_PTR, &signatureLen);
  if (rv != CKR_OK) {
    C_DestroyObject(session, publicKey);
    C_DestroyObject(session, privateKey);
    return rv;
  }

  // printf("signatureLen: %lu\n", signatureLen);
  signature = calloc(signatureLen, sizeof(CK_BYTE));

  rv = C_Sign(session, message, sizeof(message), signature, &signatureLen);
  if (rv != CKR_OK) {
    free(signature);
    C_DestroyObject(session, publicKey);
    C_DestroyObject(session, privateKey);
    return rv;
  }

  printf("[%d] Destroying key pair again...\n", threadId);
  free(signature);
  C_DestroyObject(session, publicKey);
  C_DestroyObject(session, privateKey);

  return rv;
}

typedef struct {
  size_t threadId;
  CK_SLOT_ID slotId;
} thread_args;

void *thread_func(void *arg) {
  CK_RV rv = CKR_OK;

  thread_args *args = (thread_args *)arg;
  printf("[%ld] Starting thread\n", args->threadId);

  // Open one session per thread. Intermediary state (e.g. during multi-part
  // operations) are bound to the session.
  CK_SESSION_HANDLE hSession;
  CK_ULONG flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
  rv = C_OpenSession(args->slotId, flags, NULL_PTR, NULL_PTR, &hSession);
  if (rv != CKR_OK) {
    printf("Failed to open session: 0x%lx\n", rv);
    free(args);
    return NULL;
  }

  // This session should already be logged in, since login state is per process
  // (and per slot).

  rv = ec_sign(hSession, args->threadId);
  if (rv != CKR_OK) {
    printf("Got return value 0x%lx\n", rv);
    free(args);
    C_CloseSession(hSession);
    return NULL;
  }

  free(args);
  C_CloseSession(hSession);
  return NULL;
}

int start_threads(int numThreads, CK_SLOT_ID slotId) {
  pthread_t *threads = calloc(numThreads, sizeof(pthread_t));

  for (size_t i = 0; i < numThreads; i++) {
    thread_args *args = calloc(1, sizeof(thread_args));
    args->threadId = i;
    args->slotId = slotId;

    int rv = pthread_create(&threads[i], NULL, thread_func, (void *)args);
    if (rv != 0) {
      perror("pthread_create");
      return 1;
    }
  }

  for (size_t i = 0; i < numThreads; i++) {
    pthread_join(threads[i], NULL);
  }

  free(threads);
  return 0;
}

int main() {
  CK_RV rv = CKR_OK;

  // Change according to your primus.cfg.
  CK_SLOT_ID slotId = 0;

  // Get User PIN
  CK_CHAR_PTR userPin = (CK_CHAR_PTR)getenv("P11_PIN");
  if (userPin == NULL_PTR) {
    printf("P11_PIN envvar not set\n");
    return CKR_GENERAL_ERROR;
  }
  CK_ULONG userPinLen = strlen((char *)userPin);

  // Initialize the library. This is done once per process.
  rv = C_Initialize(NULL);
  if (rv != CKR_OK)
    return rv;

  // Open a session (because we need a session for logging in)
  CK_SESSION_HANDLE hSession;
  CK_ULONG flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
  rv = C_OpenSession(slotId, flags, NULL_PTR, NULL_PTR, &hSession);
  if (rv != CKR_OK) {
    C_Finalize(NULL_PTR);
    return rv;
  }

  // Log in as User. This is done once per process (and per slot), because login
  // state is shared across all sessions. See section 5.6 Session management
  // functions" of the PKCS#11 v3.2 standard:
  // https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc234407109
  rv = C_Login(hSession, CKU_USER, userPin, userPinLen);
  if (rv != CKR_OK) {
    C_CloseSession(hSession);
    C_Finalize(NULL_PTR);
    return rv;
  }

  rv = start_threads(4, slotId);

  // Logout is per-process. This also logs out all other sessions.
  C_Logout(hSession);

  C_CloseSession(hSession);
  C_Finalize(NULL_PTR);

  return rv;
}
