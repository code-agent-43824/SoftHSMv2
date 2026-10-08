#ifndef SOFTHSM_RUTOKEN_CMS_H
#define SOFTHSM_RUTOKEN_CMS_H

#include "cryptoki.h"
#include "rutoken.h"

namespace RutokenCMS {

CK_RV sign(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG dataLen,
           CK_OBJECT_HANDLE cert, CK_BYTE_PTR* envelope, CK_ULONG_PTR envelopeLen,
           CK_OBJECT_HANDLE privateKey, CK_OBJECT_HANDLE_PTR chain,
           CK_ULONG chainLen, CK_ULONG flags);
CK_RV verifyInit(CK_SESSION_HANDLE session, CK_BYTE_PTR cms, CK_ULONG cmsLen,
                 CK_VENDOR_X509_STORE_PTR store, CK_VENDOR_CRL_MODE crlMode,
                 CK_FLAGS flags);
CK_RV verify(CK_SESSION_HANDLE session, CK_BYTE_PTR_PTR data,
             CK_ULONG_PTR dataLen, CK_VENDOR_BUFFER_PTR_PTR signers,
             CK_ULONG_PTR signerCount);
CK_RV verifyUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG dataLen);
CK_RV verifyFinal(CK_SESSION_HANDLE session, CK_VENDOR_BUFFER_PTR_PTR signers,
                  CK_ULONG_PTR signerCount);
void clear(CK_SESSION_HANDLE session);
void clearAll();

}

#endif
