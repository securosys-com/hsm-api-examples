#include "pkcs11.h"

#ifndef __cplusplus

#undef NULL_PTR
#define NULL_PTR ((void *)0)

#endif

CK_RV SetupSession(CK_SESSION_HANDLE_PTR phSession, CK_CHAR_PTR userPin, CK_ULONG userPinLen);

void CloseSession(CK_SESSION_HANDLE hSession);
