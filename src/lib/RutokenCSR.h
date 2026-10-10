#ifndef SOFTHSM_RUTOKEN_CSR_H
#define SOFTHSM_RUTOKEN_CSR_H

#include "cryptoki.h"
#include "rutoken.h"

namespace RutokenCSR {

// C_EX_CreateCSR: a PKCS #10 request for a token key pair, built and signed
// the way the reference Rutoken builds it (JOURNAL, 10 October 2026).
CK_RV create(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publicKey,
             CK_CHAR_PTR* dn, CK_ULONG dnLength, CK_BYTE_PTR* csr,
             CK_ULONG_PTR csrLength, CK_OBJECT_HANDLE privateKey,
             CK_CHAR_PTR* attributes, CK_ULONG attributesLength,
             CK_CHAR_PTR* extensions, CK_ULONG extensionsLength);

}

#endif
