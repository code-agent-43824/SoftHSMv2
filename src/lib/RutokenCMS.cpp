#include "config.h"
#include "RutokenCMS.h"

#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <vector>

#ifdef WITH_OPENSSL
#include <openssl/cms.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <memory>
#endif

namespace RutokenCMS {
namespace {

constexpr CK_ULONG maxCms = 16UL * 1024 * 1024;
constexpr CK_ULONG maxData = 64UL * 1024 * 1024;
constexpr CK_ULONG maxCertificate = 1024UL * 1024;

struct VerifyState {
    std::vector<unsigned char> cms;
    std::vector<unsigned char> data;
    std::vector<std::vector<unsigned char>> trusted;
    std::vector<std::vector<unsigned char>> certificates;
    std::vector<std::vector<unsigned char>> crls;
    CK_VENDOR_CRL_MODE crlMode = OPTIONAL_CRL_CHECK;
    CK_FLAGS flags = 0;
    bool updated = false;
};
std::mutex stateMutex;
std::map<CK_SESSION_HANDLE, VerifyState> states;

CK_RV userSession(CK_SESSION_HANDLE session)
{
    CK_SESSION_INFO info;
    CK_RV rv = C_GetSessionInfo(session, &info);
    if (rv != CKR_OK) return rv;
    if (info.state != CKS_RO_USER_FUNCTIONS && info.state != CKS_RW_USER_FUNCTIONS)
        return CKR_USER_NOT_LOGGED_IN;
    return CKR_OK;
}

CK_RV attribute(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                CK_ATTRIBUTE_TYPE type, std::vector<unsigned char>& bytes,
                CK_ULONG maximum = maxCertificate)
{
    CK_ATTRIBUTE attr = { type, NULL_PTR, 0 };
    CK_RV rv = C_GetAttributeValue(session, object, &attr, 1);
    if (rv != CKR_OK) return rv;
    if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION || attr.ulValueLen > maximum)
        return CKR_ATTRIBUTE_VALUE_INVALID;
    bytes.resize(attr.ulValueLen);
    attr.pValue = bytes.empty() ? NULL_PTR : bytes.data();
    rv = C_GetAttributeValue(session, object, &attr, 1);
    if (rv != CKR_OK) return rv;
    bytes.resize(attr.ulValueLen);
    return CKR_OK;
}

CK_RV objectClass(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                  CK_OBJECT_CLASS expected)
{
    CK_OBJECT_CLASS type = CKO_VENDOR_DEFINED;
    CK_ATTRIBUTE attr = { CKA_CLASS, &type, sizeof(type) };
    CK_RV rv = C_GetAttributeValue(session, object, &attr, 1);
    return rv != CKR_OK ? rv : type == expected ? CKR_OK : CKR_OBJECT_HANDLE_INVALID;
}

CK_RV copyBuffers(CK_VENDOR_BUFFER_PTR source, CK_ULONG count,
                  std::vector<std::vector<unsigned char>>& target)
{
    if (count > 256 || (count && !source)) return CKR_ARGUMENTS_BAD;
    for (CK_ULONG i = 0; i < count; ++i) {
        if (source[i].ulSize > maxCertificate ||
            (source[i].ulSize && !source[i].pData)) return CKR_ARGUMENTS_BAD;
        if (source[i].ulSize)
            target.emplace_back(source[i].pData,
                                source[i].pData + source[i].ulSize);
        else
            target.emplace_back();
    }
    return CKR_OK;
}

#ifdef WITH_OPENSSL
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using CmsPtr = std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using StorePtr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using RsaPtr = std::unique_ptr<RSA, decltype(&RSA_free)>;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
struct CertStackDeleter {
    void operator()(STACK_OF(X509)* certs) const { sk_X509_pop_free(certs, X509_free); }
};
using CertStack = std::unique_ptr<STACK_OF(X509), CertStackDeleter>;
struct SignerStackDeleter {
    void operator()(STACK_OF(X509)* certs) const { sk_X509_free(certs); }
};
using SignerStack = std::unique_ptr<STACK_OF(X509), SignerStackDeleter>;

X509Ptr decodeCertificate(const std::vector<unsigned char>& der)
{
    const unsigned char* cursor = der.data();
    X509Ptr cert(d2i_X509(NULL, &cursor, static_cast<long>(der.size())), X509_free);
    if (!cert || cursor != der.data() + der.size()) return X509Ptr(nullptr, X509_free);
    return cert;
}

CmsPtr decodeCms(const std::vector<unsigned char>& der)
{
    const unsigned char* cursor = der.data();
    CmsPtr cms(d2i_CMS_ContentInfo(NULL, &cursor, static_cast<long>(der.size())),
               CMS_ContentInfo_free);
    if (!cms || cursor != der.data() + der.size() ||
        OBJ_obj2nid(CMS_get0_type(cms.get())) != NID_pkcs7_signed)
        return CmsPtr(nullptr, CMS_ContentInfo_free);
    return cms;
}

struct SignContext {
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    CK_RV error = CKR_OK;
};
thread_local SignContext* activeSign = nullptr;

int tokenRsaPrivateEncrypt(int length, const unsigned char* input,
                           unsigned char* output, RSA* rsa, int padding)
{
    SignContext* context = activeSign;
    if (!context || padding != RSA_PKCS1_PADDING || length <= 0) return -1;
    CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
    context->error = C_SignInit(context->session, &mechanism, context->key);
    if (context->error != CKR_OK) return -1;
    CK_ULONG outputLen = static_cast<CK_ULONG>(RSA_size(rsa));
    context->error = C_Sign(context->session,
                            const_cast<CK_BYTE_PTR>(input), length,
                            output, &outputLen);
    return context->error == CKR_OK ? static_cast<int>(outputLen) : -1;
}

RSA_METHOD* tokenRsaMethod()
{
    static RSA_METHOD* method = [] {
        RSA_METHOD* result = RSA_meth_dup(RSA_get_default_method());
        if (result && RSA_meth_set_priv_enc(result, tokenRsaPrivateEncrypt) != 1) {
            RSA_meth_free(result);
            return static_cast<RSA_METHOD*>(nullptr);
        }
        return result;
    }();
    return method;
}

KeyPtr tokenSigningKey(X509* cert)
{
    KeyPtr publicKey(X509_get_pubkey(cert), EVP_PKEY_free);
    if (!publicKey || EVP_PKEY_base_id(publicKey.get()) != EVP_PKEY_RSA ||
        !tokenRsaMethod()) return KeyPtr(nullptr, EVP_PKEY_free);
    BIGNUM *modulus = nullptr, *exponent = nullptr;
    if (EVP_PKEY_get_bn_param(publicKey.get(), OSSL_PKEY_PARAM_RSA_N, &modulus) != 1 ||
        EVP_PKEY_get_bn_param(publicKey.get(), OSSL_PKEY_PARAM_RSA_E, &exponent) != 1) {
        BN_free(modulus);
        BN_free(exponent);
        return KeyPtr(nullptr, EVP_PKEY_free);
    }
    BnPtr n(modulus, BN_free), e(exponent, BN_free);
    RsaPtr rsa(RSA_new(), RSA_free);
    if (!rsa || RSA_set0_key(rsa.get(), n.get(), e.get(), nullptr) != 1)
        return KeyPtr(nullptr, EVP_PKEY_free);
    n.release(); e.release();
    if (RSA_set_method(rsa.get(), tokenRsaMethod()) != 1)
        return KeyPtr(nullptr, EVP_PKEY_free);
    RSA_set_flags(rsa.get(), RSA_FLAG_EXT_PKEY);
    KeyPtr key(EVP_PKEY_new(), EVP_PKEY_free);
    if (!key || EVP_PKEY_assign_RSA(key.get(), rsa.get()) != 1)
        return KeyPtr(nullptr, EVP_PKEY_free);
    rsa.release();
    return key;
}

CK_RV findPrivateKey(CK_SESSION_HANDLE session,
                     const std::vector<unsigned char>& id,
                     CK_OBJECT_HANDLE& key)
{
    CK_OBJECT_CLASS type = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE query[] = {
        { CKA_CLASS, &type, sizeof(type) },
        { CKA_ID, const_cast<unsigned char*>(id.data()), static_cast<CK_ULONG>(id.size()) }
    };
    CK_RV rv = C_FindObjectsInit(session, query, 2);
    if (rv != CKR_OK) return rv;
    CK_ULONG count = 0;
    rv = C_FindObjects(session, &key, 1, &count);
    CK_RV finish = C_FindObjectsFinal(session);
    if (rv != CKR_OK) return rv;
    if (finish != CKR_OK) return finish;
    return count ? CKR_OK : CKR_KEY_HANDLE_INVALID;
}

CK_RV addCertificates(X509_STORE* store,
                      const std::vector<std::vector<unsigned char>>& ders)
{
    for (const auto& der : ders) {
        X509Ptr cert = decodeCertificate(der);
        if (!cert) return CKR_DATA_INVALID;
        if (X509_STORE_add_cert(store, cert.get()) != 1) {
            // The caller may pass a duplicate trust anchor.
            unsigned long error = ERR_peek_last_error();
            if (ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
                return CKR_FUNCTION_FAILED;
            ERR_clear_error();
        }
    }
    return CKR_OK;
}

CK_RV verifyCms(const VerifyState& state, bool detached,
                CK_BYTE_PTR_PTR data, CK_ULONG_PTR dataLen,
                CK_VENDOR_BUFFER_PTR_PTR signers, CK_ULONG_PTR signerCount)
{
    CmsPtr cms = decodeCms(state.cms);
    if (!cms) return CKR_SIGNATURE_INVALID;
    if (!!CMS_is_detached(cms.get()) != detached) return CKR_ARGUMENTS_BAD;
    CertStack extra(sk_X509_new_null());
    if (!extra) return CKR_HOST_MEMORY;
    for (const auto& der : state.certificates) {
        X509Ptr cert = decodeCertificate(der);
        if (!cert) return CKR_DATA_INVALID;
        if (!sk_X509_push(extra.get(), cert.get())) return CKR_HOST_MEMORY;
        cert.release();
    }
    StorePtr store(X509_STORE_new(), X509_STORE_free);
    if (!store) return CKR_HOST_MEMORY;
    CK_RV rv = addCertificates(store.get(), state.trusted);
    if (rv != CKR_OK) return rv;
    for (const auto& der : state.crls) {
        const unsigned char* cursor = der.data();
        std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl(
            d2i_X509_CRL(NULL, &cursor, static_cast<long>(der.size())), X509_CRL_free);
        if (!crl || cursor != der.data() + der.size()) return CKR_DATA_INVALID;
        if (X509_STORE_add_crl(store.get(), crl.get()) != 1) return CKR_FUNCTION_FAILED;
    }
    if (state.crlMode != OPTIONAL_CRL_CHECK) {
        unsigned long crlFlags = X509_V_FLAG_CRL_CHECK;
        if (state.crlMode == ALL_CRL_CHECK) crlFlags |= X509_V_FLAG_CRL_CHECK_ALL;
        X509_STORE_set_flags(store.get(), crlFlags);
    }
    if (state.flags & CKF_VENDOR_ALLOW_PARTIAL_CHAINS)
        X509_STORE_set_flags(store.get(), X509_V_FLAG_PARTIAL_CHAIN);
    unsigned int cmsFlags = CMS_BINARY;
    if (state.flags & CKF_VENDOR_DO_NOT_USE_INTERNAL_CMS_CERTS) cmsFlags |= CMS_NOINTERN;
    auto input = [&]() -> BioPtr {
        return BioPtr(detached ? BIO_new_mem_buf(state.data.data(),
                    static_cast<int>(state.data.size())) : nullptr, BIO_free);
    };
    BioPtr signedInput = input();
    BioPtr recovered(BIO_new(BIO_s_mem()), BIO_free);
    if (detached && !signedInput) return CKR_HOST_MEMORY;
    if (!recovered) return CKR_HOST_MEMORY;
    if (CMS_verify(cms.get(), extra.get(), nullptr, signedInput.get(),
                   recovered.get(), cmsFlags | CMS_NO_SIGNER_CERT_VERIFY) != 1)
        return CKR_SIGNATURE_INVALID;
    CK_RV result = CKR_OK;
    if (!(state.flags & CKF_VENDOR_CHECK_SIGNATURE_ONLY)) {
        BioPtr chainInput = input();
        BioPtr ignored(BIO_new(BIO_s_mem()), BIO_free);
        if (detached && !chainInput) return CKR_HOST_MEMORY;
        if (!ignored) return CKR_HOST_MEMORY;
        if (state.trusted.empty() ||
            CMS_verify(cms.get(), extra.get(), store.get(), chainInput.get(),
                       ignored.get(), cmsFlags) != 1)
            result = CKR_CERT_CHAIN_NOT_VERIFIED;
    }
    STACK_OF(X509)* signerList = CMS_get0_signers(cms.get());
    SignerStack signerOwner(signerList);
    if (!signerList || sk_X509_num(signerList) <= 0) return CKR_SIGNATURE_INVALID;
    const int count = sk_X509_num(signerList);
    CK_VENDOR_BUFFER_PTR signerOutput = static_cast<CK_VENDOR_BUFFER_PTR>(
        calloc(static_cast<size_t>(count), sizeof(CK_VENDOR_BUFFER)));
    if (!signerOutput) return CKR_HOST_MEMORY;
    for (int i = 0; i < count; ++i) {
        X509* cert = sk_X509_value(signerList, i);
        int length = i2d_X509(cert, nullptr);
        if (length <= 0) { rv = CKR_FUNCTION_FAILED; break; }
        signerOutput[i].pData = static_cast<CK_BYTE_PTR>(malloc(length));
        if (!signerOutput[i].pData) { rv = CKR_HOST_MEMORY; break; }
        unsigned char* cursor = signerOutput[i].pData;
        if (i2d_X509(cert, &cursor) != length) { rv = CKR_FUNCTION_FAILED; break; }
        signerOutput[i].ulSize = length;
    }
    if (rv != CKR_OK) {
        for (int i = 0; i < count; ++i) free(signerOutput[i].pData);
        free(signerOutput);
        return rv;
    }
    if (data) {
        BUF_MEM* content = nullptr;
        BIO_get_mem_ptr(recovered.get(), &content);
        if (!content || content->length > maxData) {
            for (int i = 0; i < count; ++i) free(signerOutput[i].pData);
            free(signerOutput);
            return CKR_DATA_LEN_RANGE;
        }
        CK_BYTE_PTR output = static_cast<CK_BYTE_PTR>(malloc(content->length ? content->length : 1));
        if (!output) {
            for (int i = 0; i < count; ++i) free(signerOutput[i].pData);
            free(signerOutput);
            return CKR_HOST_MEMORY;
        }
        memcpy(output, content->data, content->length);
        *data = output;
        *dataLen = static_cast<CK_ULONG>(content->length);
    }
    *signers = signerOutput;
    *signerCount = static_cast<CK_ULONG>(count);
    return result;
}
#endif
}

CK_RV sign(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG dataLen,
           CK_OBJECT_HANDLE certHandle, CK_BYTE_PTR* envelope, CK_ULONG_PTR envelopeLen,
           CK_OBJECT_HANDLE privateKey, CK_OBJECT_HANDLE_PTR chain,
           CK_ULONG chainLen, CK_ULONG flags)
{
#ifndef WITH_OPENSSL
    (void)session; (void)data; (void)dataLen; (void)certHandle; (void)envelope;
    (void)envelopeLen; (void)privateKey; (void)chain; (void)chainLen; (void)flags;
    return CKR_FUNCTION_NOT_SUPPORTED;
#else
    try {
        if (!envelope || !envelopeLen || (dataLen && !data) ||
            dataLen > maxData || chainLen > 256 || (chainLen && !chain) ||
            (flags & ~(PKCS7_DETACHED_SIGNATURE | USE_HARDWARE_HASH)))
            return CKR_ARGUMENTS_BAD;
        *envelope = nullptr; *envelopeLen = 0;
        CK_RV rv = userSession(session);
        if (rv != CKR_OK) return rv;
        rv = objectClass(session, certHandle, CKO_CERTIFICATE);
        if (rv != CKR_OK) return rv;
        std::vector<unsigned char> der, id;
        rv = attribute(session, certHandle, CKA_VALUE, der);
        if (rv != CKR_OK) return rv;
        X509Ptr cert = decodeCertificate(der);
        if (!cert) return CKR_DATA_INVALID;
        rv = attribute(session, certHandle, CKA_ID, id, 256);
        if (rv != CKR_OK) return rv;
        if (privateKey == CK_INVALID_HANDLE) {
            rv = findPrivateKey(session, id, privateKey);
            if (rv != CKR_OK) return rv;
        }
        rv = objectClass(session, privateKey, CKO_PRIVATE_KEY);
        if (rv != CKR_OK) return rv;
        KeyPtr signingKey = tokenSigningKey(cert.get());
        if (!signingKey) return CKR_MECHANISM_INVALID;
        const unsigned int cmsFlags = CMS_BINARY |
            (flags & PKCS7_DETACHED_SIGNATURE ? CMS_DETACHED : 0);
        CmsPtr cms(CMS_sign(nullptr, nullptr, nullptr, nullptr,
                            CMS_PARTIAL | cmsFlags), CMS_ContentInfo_free);
        if (!cms) return CKR_FUNCTION_FAILED;
        if (!CMS_add1_signer(cms.get(), cert.get(), signingKey.get(),
                             EVP_sha256(), CMS_NOSMIMECAP))
            return CKR_FUNCTION_FAILED;
        for (CK_ULONG i = 0; i < chainLen; ++i) {
            rv = objectClass(session, chain[i], CKO_CERTIFICATE);
            if (rv != CKR_OK) return rv;
            std::vector<unsigned char> chainDer;
            rv = attribute(session, chain[i], CKA_VALUE, chainDer);
            if (rv != CKR_OK) return rv;
            X509Ptr chainCert = decodeCertificate(chainDer);
            if (!chainCert) return CKR_DATA_INVALID;
            if (CMS_add1_cert(cms.get(), chainCert.get()) != 1)
                return CKR_FUNCTION_FAILED;
        }
        unsigned char empty = 0;
        BioPtr content(BIO_new_mem_buf(dataLen ? data : &empty,
                                       static_cast<int>(dataLen)), BIO_free);
        if (!content) return CKR_HOST_MEMORY;
        SignContext context;
        context.session = session;
        context.key = privateKey;
        std::vector<unsigned char> tokenDigest;
        if (flags & USE_HARDWARE_HASH) {
            CK_MECHANISM digestMechanism = { CKM_SHA256, NULL_PTR, 0 };
            rv = C_DigestInit(session, &digestMechanism);
            if (rv != CKR_OK) return rv;
            tokenDigest.resize(32);
            CK_ULONG digestLength = static_cast<CK_ULONG>(tokenDigest.size());
            rv = C_Digest(session, dataLen ? data : &empty, dataLen,
                          tokenDigest.data(), &digestLength);
            if (rv != CKR_OK) return rv;
            if (digestLength != tokenDigest.size()) return CKR_FUNCTION_FAILED;
        }
        SignContext* previous = activeSign;
        activeSign = &context;
        int completed = CMS_final(cms.get(), content.get(), nullptr, cmsFlags);
        activeSign = previous;
        if (context.error != CKR_OK) return context.error;
        if (completed != 1) return CKR_FUNCTION_FAILED;
        if (!tokenDigest.empty()) {
            STACK_OF(CMS_SignerInfo)* infos = CMS_get0_SignerInfos(cms.get());
            if (!infos || sk_CMS_SignerInfo_num(infos) != 1) return CKR_FUNCTION_FAILED;
            auto* digest = static_cast<ASN1_OCTET_STRING*>(
                CMS_signed_get0_data_by_OBJ(sk_CMS_SignerInfo_value(infos, 0),
                    OBJ_nid2obj(NID_pkcs9_messageDigest), -3, V_ASN1_OCTET_STRING));
            if (!digest || digest->length != static_cast<int>(tokenDigest.size()) ||
                memcmp(digest->data, tokenDigest.data(), tokenDigest.size()) != 0)
                return CKR_DATA_INVALID;
        }
        BioPtr detachedInput(flags & PKCS7_DETACHED_SIGNATURE ?
            BIO_new_mem_buf(dataLen ? data : &empty, static_cast<int>(dataLen)) : nullptr,
            BIO_free);
        if ((flags & PKCS7_DETACHED_SIGNATURE) && !detachedInput)
            return CKR_HOST_MEMORY;
        if (CMS_verify(cms.get(), nullptr, nullptr, detachedInput.get(), nullptr,
                       CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) != 1)
            return CKR_KEY_HANDLE_INVALID;
        int length = i2d_CMS_ContentInfo(cms.get(), nullptr);
        if (length <= 0 || static_cast<CK_ULONG>(length) > maxCms)
            return CKR_FUNCTION_FAILED;
        CK_BYTE_PTR output = static_cast<CK_BYTE_PTR>(malloc(length));
        if (!output) return CKR_HOST_MEMORY;
        unsigned char* cursor = output;
        if (i2d_CMS_ContentInfo(cms.get(), &cursor) != length) {
            free(output);
            return CKR_FUNCTION_FAILED;
        }
        *envelope = output; *envelopeLen = length;
        return CKR_OK;
    } catch (const std::bad_alloc&) { return CKR_HOST_MEMORY; }
    catch (...) { return CKR_FUNCTION_FAILED; }
#endif
}

CK_RV verifyInit(CK_SESSION_HANDLE session, CK_BYTE_PTR cms, CK_ULONG cmsLen,
                 CK_VENDOR_X509_STORE_PTR store, CK_VENDOR_CRL_MODE crlMode,
                 CK_FLAGS flags)
{
#ifndef WITH_OPENSSL
    (void)session; (void)cms; (void)cmsLen; (void)store; (void)crlMode; (void)flags;
    return CKR_FUNCTION_NOT_SUPPORTED;
#else
    try {
        if (!cms || !cmsLen || cmsLen > maxCms ||
            crlMode > ALL_CRL_CHECK ||
            (flags & ~(CKF_VENDOR_DO_NOT_USE_INTERNAL_CMS_CERTS |
                       CKF_VENDOR_ALLOW_PARTIAL_CHAINS |
                       CKF_VENDOR_CHECK_SIGNATURE_ONLY |
                       CKF_VENDOR_USE_TRUSTED_CERTS_FROM_TOKEN)))
            return CKR_ARGUMENTS_BAD;
        CK_RV rv = userSession(session);
        if (rv != CKR_OK) return rv;
        VerifyState state;
        state.cms.assign(cms, cms + cmsLen);
        if (!decodeCms(state.cms)) return CKR_SIGNATURE_INVALID;
        state.crlMode = crlMode; state.flags = flags;
        if (store) {
            rv = copyBuffers(store->pTrustedCertificates,
                             store->ulTrustedCertificateCount, state.trusted);
            if (rv != CKR_OK) return rv;
            rv = copyBuffers(store->pCertificates,
                             store->ulCertificateCount, state.certificates);
            if (rv != CKR_OK) return rv;
            rv = copyBuffers(store->pCrls, store->ulCrlCount, state.crls);
            if (rv != CKR_OK) return rv;
        }
        if (flags & CKF_VENDOR_USE_TRUSTED_CERTS_FROM_TOKEN) {
            CK_OBJECT_CLASS type = CKO_CERTIFICATE;
            CK_BBOOL trusted = CK_TRUE;
            CK_ATTRIBUTE query[] = {
                { CKA_CLASS, &type, sizeof(type) },
                { CKA_TRUSTED, &trusted, sizeof(trusted) }
            };
            rv = C_FindObjectsInit(session, query, 2);
            if (rv != CKR_OK) return rv;
            CK_OBJECT_HANDLE object;
            CK_ULONG count;
            do {
                rv = C_FindObjects(session, &object, 1, &count);
                if (rv == CKR_OK && count) {
                    std::vector<unsigned char> der;
                    rv = attribute(session, object, CKA_VALUE, der);
                    if (rv == CKR_OK) state.trusted.push_back(std::move(der));
                }
            } while (rv == CKR_OK && count);
            CK_RV finish = C_FindObjectsFinal(session);
            if (rv != CKR_OK) return rv;
            if (finish != CKR_OK) return finish;
        }
        std::lock_guard<std::mutex> lock(stateMutex);
        if (states.count(session)) return CKR_OPERATION_ACTIVE;
        states.emplace(session, std::move(state));
        return CKR_OK;
    } catch (const std::bad_alloc&) { return CKR_HOST_MEMORY; }
    catch (...) { return CKR_FUNCTION_FAILED; }
#endif
}

CK_RV verify(CK_SESSION_HANDLE session, CK_BYTE_PTR_PTR data,
             CK_ULONG_PTR dataLen, CK_VENDOR_BUFFER_PTR_PTR signers,
             CK_ULONG_PTR signerCount)
{
#ifndef WITH_OPENSSL
    (void)session; (void)data; (void)dataLen; (void)signers; (void)signerCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
#else
    try {
        if (!data || !dataLen || !signers || !signerCount) return CKR_ARGUMENTS_BAD;
        *data = nullptr; *dataLen = 0; *signers = nullptr; *signerCount = 0;
        CK_RV rv = userSession(session);
        if (rv != CKR_OK) return rv;
        VerifyState state;
        {
            std::lock_guard<std::mutex> lock(stateMutex);
            auto it = states.find(session);
            if (it == states.end()) return CKR_OPERATION_NOT_INITIALIZED;
            state = std::move(it->second);
            states.erase(it);
        }
        if (state.updated) return CKR_ARGUMENTS_BAD;
        return verifyCms(state, false, data, dataLen, signers, signerCount);
    } catch (const std::bad_alloc&) { return CKR_HOST_MEMORY; }
    catch (...) { return CKR_FUNCTION_FAILED; }
#endif
}

CK_RV verifyUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG dataLen)
{
#ifndef WITH_OPENSSL
    (void)session; (void)data; (void)dataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
#else
    try {
        if (dataLen && !data) return CKR_ARGUMENTS_BAD;
        CK_RV rv = userSession(session);
        if (rv != CKR_OK) return rv;
        std::lock_guard<std::mutex> lock(stateMutex);
        auto it = states.find(session);
        if (it == states.end()) return CKR_OPERATION_NOT_INITIALIZED;
        if (dataLen > maxData - it->second.data.size()) return CKR_DATA_LEN_RANGE;
        if (dataLen) it->second.data.insert(it->second.data.end(), data, data + dataLen);
        it->second.updated = true;
        return CKR_OK;
    } catch (const std::bad_alloc&) { return CKR_HOST_MEMORY; }
    catch (...) { return CKR_FUNCTION_FAILED; }
#endif
}

CK_RV verifyFinal(CK_SESSION_HANDLE session, CK_VENDOR_BUFFER_PTR_PTR signers,
                  CK_ULONG_PTR signerCount)
{
#ifndef WITH_OPENSSL
    (void)session; (void)signers; (void)signerCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
#else
    try {
        if (!signers || !signerCount) return CKR_ARGUMENTS_BAD;
        *signers = nullptr; *signerCount = 0;
        CK_RV rv = userSession(session);
        if (rv != CKR_OK) return rv;
        VerifyState state;
        {
            std::lock_guard<std::mutex> lock(stateMutex);
            auto it = states.find(session);
            if (it == states.end()) return CKR_OPERATION_NOT_INITIALIZED;
            state = std::move(it->second);
            states.erase(it);
        }
        if (!state.updated) return CKR_ARGUMENTS_BAD;
        return verifyCms(state, true, nullptr, nullptr, signers, signerCount);
    } catch (const std::bad_alloc&) { return CKR_HOST_MEMORY; }
    catch (...) { return CKR_FUNCTION_FAILED; }
#endif
}

void clear(CK_SESSION_HANDLE session)
{
    std::lock_guard<std::mutex> lock(stateMutex);
    states.erase(session);
}

void clearAll()
{
    std::lock_guard<std::mutex> lock(stateMutex);
    states.clear();
}

}
