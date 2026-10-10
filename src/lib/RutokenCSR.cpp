#include "config.h"
#include "RutokenCSR.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <vector>

#ifdef WITH_OPENSSL
#include <openssl/asn1.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

// What the request looks like is taken from the reference device, probed on
// 10 October 2026 (JOURNAL): one RDN per name/value pair in the given order,
// string types from OpenSSL's table under the UTF8-only mask plus a
// NumericString for the legal-entity INN, x509v3 extension syntax in one
// extensionRequest attribute, an empty [0] when nothing is added, GOST keys
// signed over Streebog without signature parameters and RSA keys with the
// OIW sha1WithRSA.

namespace RutokenCSR {
#ifdef WITH_OPENSSL
namespace {

using Bytes = std::vector<unsigned char>;

// Bounds on what an application may pass; the device documents none.
constexpr CK_ULONG maxStrings = 1024;
constexpr size_t maxString = 64 * 1024;
constexpr CK_ULONG maxKeyAttribute = 64 * 1024;

const char* text(CK_CHAR_PTR value)
{
    return reinterpret_cast<const char*>(value);
}

// Name/value pairs: an odd count is refused, as on the device.
CK_RV checkStrings(CK_CHAR_PTR* strings, CK_ULONG count)
{
    if (count % 2 || count > maxStrings || (count && !strings)) return CKR_ARGUMENTS_BAD;
    for (CK_ULONG i = 0; i < count; ++i) {
        if (!strings[i]) return CKR_ARGUMENTS_BAD;
        size_t length = 0;
        while (length <= maxString && strings[i][length]) ++length;
        if (length > maxString) return CKR_ARGUMENTS_BAD;
    }
    return CKR_OK;
}

CK_RV userSession(CK_SESSION_HANDLE session)
{
    CK_SESSION_INFO info;
    CK_RV rv = C_GetSessionInfo(session, &info);
    if (rv != CKR_OK) return rv;
    if (info.state != CKS_RO_USER_FUNCTIONS && info.state != CKS_RW_USER_FUNCTIONS)
        return CKR_USER_NOT_LOGGED_IN;
    return CKR_OK;
}

template <typename T>
CK_RV scalar(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
             CK_ATTRIBUTE_TYPE type, T& value)
{
    CK_ATTRIBUTE attr = { type, &value, sizeof(value) };
    return C_GetAttributeValue(session, object, &attr, 1);
}

CK_RV attribute(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                CK_ATTRIBUTE_TYPE type, Bytes& value)
{
    CK_ATTRIBUTE attr = { type, NULL_PTR, 0 };
    CK_RV rv = C_GetAttributeValue(session, object, &attr, 1);
    if (rv != CKR_OK) return rv;
    if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION || attr.ulValueLen > maxKeyAttribute)
        return CKR_FUNCTION_FAILED;
    value.resize(attr.ulValueLen);
    if (value.empty()) return CKR_OK;
    attr.pValue = value.data();
    rv = C_GetAttributeValue(session, object, &attr, 1);
    if (rv != CKR_OK) return rv;
    value.resize(attr.ulValueLen);
    return CKR_OK;
}

Bytes tagged(unsigned char tag, const Bytes& body)
{
    Bytes result{tag};
    if (body.size() < 128) result.push_back(static_cast<unsigned char>(body.size()));
    else {
        Bytes length;
        size_t size = body.size();
        while (size) { length.push_back(static_cast<unsigned char>(size)); size >>= 8; }
        result.push_back(static_cast<unsigned char>(0x80 | length.size()));
        for (auto it = length.rbegin(); it != length.rend(); ++it) result.push_back(*it);
    }
    result.insert(result.end(), body.begin(), body.end());
    return result;
}

void append(Bytes& target, const Bytes& part)
{
    target.insert(target.end(), part.begin(), part.end());
}

bool isOid(const Bytes& der)
{
    return der.size() >= 3 && der[0] == 0x06 && der[1] < 0x80 &&
           static_cast<size_t>(der[1]) + 2 == der.size();
}

// A non-negative INTEGER from big-endian magnitude bytes.
Bytes derInteger(const Bytes& magnitude)
{
    size_t start = 0;
    while (start + 1 < magnitude.size() && magnitude[start] == 0) ++start;
    Bytes body;
    if (magnitude[start] & 0x80) body.push_back(0);
    body.insert(body.end(), magnitude.begin() + start, magnitude.end());
    return tagged(0x02, body);
}

struct PublicKey {
    CK_KEY_TYPE type = CKK_VENDOR_DEFINED;
    Bytes value;              // GOST: the point as the token stores it
    Bytes curve, digest;      // GOST: CKA_GOSTR3410_PARAMS, CKA_GOSTR3411_PARAMS
    Bytes modulus, exponent;  // RSA
    bool gost() const { return type == CKK_GOSTR3410 || type == CKK_GOSTR3410_512; }
    size_t bits() const { return type == CKK_GOSTR3410_512 ? 512 : 256; }
};

CK_RV readPublicKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE handle, PublicKey& key)
{
    CK_OBJECT_CLASS objectClass = CKO_VENDOR_DEFINED;
    CK_RV rv = scalar(session, handle, CKA_CLASS, objectClass);
    if (rv != CKR_OK) return rv;
    // The device answers a private key passed as the public one with this code.
    if (objectClass != CKO_PUBLIC_KEY) return CKR_KEY_TYPE_INCONSISTENT;
    rv = scalar(session, handle, CKA_KEY_TYPE, key.type);
    if (rv != CKR_OK) return rv;
    if (key.gost()) {
        rv = attribute(session, handle, CKA_VALUE, key.value);
        if (rv == CKR_OK) rv = attribute(session, handle, CKA_GOSTR3410_PARAMS, key.curve);
        if (rv == CKR_OK) {
            rv = attribute(session, handle, CKA_GOSTR3411_PARAMS, key.digest);
            if (rv == CKR_ATTRIBUTE_TYPE_INVALID) { key.digest.clear(); rv = CKR_OK; }
        }
        if (rv != CKR_OK) return rv;
        if (key.value.size() != key.bits() / 4 || !isOid(key.curve) ||
            (!key.digest.empty() && !isOid(key.digest))) return CKR_FUNCTION_FAILED;
        return CKR_OK;
    }
    if (key.type == CKK_RSA) {
        rv = attribute(session, handle, CKA_MODULUS, key.modulus);
        if (rv == CKR_OK) rv = attribute(session, handle, CKA_PUBLIC_EXPONENT, key.exponent);
        if (rv != CKR_OK) return rv;
        if (key.modulus.empty() || key.exponent.empty()) return CKR_FUNCTION_FAILED;
        return CKR_OK;
    }
    // The device was probed with GOST and RSA key pairs only.
    return CKR_KEY_TYPE_INCONSISTENT;
}

using RequestPtr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
using ConfPtr = std::unique_ptr<CONF, decltype(&NCONF_free)>;
using NamePtr = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using ObjectPtr = std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;
using StringPtr = std::unique_ptr<ASN1_STRING, decltype(&ASN1_STRING_free)>;
struct ExtensionsDeleter {
    void operator()(STACK_OF(X509_EXTENSION)* list) const
    { sk_X509_EXTENSION_pop_free(list, X509_EXTENSION_free); }
};
using ExtensionsPtr = std::unique_ptr<STACK_OF(X509_EXTENSION), ExtensionsDeleter>;

// OpenSSL errors raised while the request is built stay out of the
// application's view of the error queue.
struct ErrorMark {
    ErrorMark() { ERR_set_mark(); }
    ~ErrorMark() { ERR_pop_to_mark(); }
};

// The value of a name entry or attribute in the type the device gives it:
// OpenSSL's string table with the UTF8-only mask applied here, not taken from
// the library-wide default an application could change, and a NumericString
// for the legal-entity INN, which the table does not know.
StringPtr directoryString(const ASN1_OBJECT* type, const char* value)
{
    unsigned long mask = B_ASN1_UTF8STRING;
    long minimum = 0, maximum = 0;
    char dotted[80];
    const int nid = OBJ_obj2nid(type);
    ASN1_STRING_TABLE* entry = nid != NID_undef ? ASN1_STRING_TABLE_get(nid) : nullptr;
    if (OBJ_obj2txt(dotted, sizeof(dotted), type, 1) > 0 &&
        strcmp(dotted, "1.2.643.100.4") == 0)
        mask = B_ASN1_NUMERICSTRING;
    else if (entry) {
        mask = entry->flags & STABLE_NO_MASK ? entry->mask : entry->mask & B_ASN1_UTF8STRING;
        minimum = entry->minsize;
        maximum = entry->maxsize;
    }
    ASN1_STRING* result = nullptr;
    if (ASN1_mbstring_ncopy(&result, reinterpret_cast<const unsigned char*>(value), -1,
                            MBSTRING_UTF8, mask, minimum, maximum) <= 0)
        return StringPtr(nullptr, ASN1_STRING_free);
    return StringPtr(result, ASN1_STRING_free);
}

// Short names, long names and dotted OIDs are all accepted; "E" is not.
ObjectPtr typeObject(const char* name)
{
    return ObjectPtr(OBJ_txt2obj(name, 0), ASN1_OBJECT_free);
}

CK_RV appendNameEntry(X509_NAME* name, const char* type, const char* value)
{
    ObjectPtr object = typeObject(type);
    if (!object) return CKR_ARGUMENTS_BAD;
    StringPtr content = directoryString(object.get(), value);
    if (!content) return CKR_ARGUMENTS_BAD;
    if (X509_NAME_add_entry_by_OBJ(name, object.get(), ASN1_STRING_type(content.get()),
                                   ASN1_STRING_get0_data(content.get()),
                                   ASN1_STRING_length(content.get()), -1, 0) != 1)
        return CKR_ARGUMENTS_BAD;
    return CKR_OK;
}

CK_RV appendAttribute(X509_REQ* request, const char* type, const char* value)
{
    ObjectPtr object = typeObject(type);
    if (!object) return CKR_ARGUMENTS_BAD;
    StringPtr content = directoryString(object.get(), value);
    if (!content) return CKR_ARGUMENTS_BAD;
    if (X509_REQ_add1_attr_by_OBJ(request, object.get(), ASN1_STRING_type(content.get()),
                                  ASN1_STRING_get0_data(content.get()),
                                  ASN1_STRING_length(content.get())) != 1)
        return CKR_ARGUMENTS_BAD;
    return CKR_OK;
}

// OpenSSL's own reading of an extension value: an optional "critical,", then
// "ASN1:" or "DER:" for an encoding given directly.
bool encodingGiven(const char* value)
{
    if (strncmp(value, "critical,", 9) == 0) {
        value += 9;
        while (isspace(static_cast<unsigned char>(*value))) ++value;
    }
    return strncmp(value, "ASN1:", 5) == 0 || strncmp(value, "DER:", 4) == 0;
}

CK_RV appendExtension(STACK_OF(X509_EXTENSION)* list, CONF* conf, X509V3_CTX* context,
                      const char* name, const char* value)
{
    const int nid = OBJ_txt2nid(name);
    // The device takes subjectSignTool only as an encoding; OpenSSL 3 would
    // also read plain text for it.
    if (nid == NID_subjectSignTool && !encodingGiven(value)) return CKR_ARGUMENTS_BAD;
    X509_EXTENSION* extension = nid != NID_undef
        ? X509V3_EXT_nconf_nid(conf, context, nid, value)
        : X509V3_EXT_nconf(conf, context, name, value);
    if (!extension) return CKR_ARGUMENTS_BAD;
    if (!sk_X509_EXTENSION_push(list, extension)) {
        X509_EXTENSION_free(extension);
        return CKR_HOST_MEMORY;
    }
    return CKR_OK;
}

// The static OpenSSL of the portable build has no GOST provider, so the GOST
// public key goes into the request as encoded algorithm and key bits.
bool setPublicKey(X509_REQ* request, const PublicKey& key)
{
    X509_PUBKEY* spki = X509_REQ_get_X509_PUBKEY(request);
    if (!spki) return false;
    Bytes encoded;
    ObjectPtr algorithm(nullptr, ASN1_OBJECT_free);
    StringPtr parameters(nullptr, ASN1_STRING_free);
    int parameterType = V_ASN1_NULL;
    if (key.type == CKK_RSA) {
        Bytes numbers = derInteger(key.modulus);
        append(numbers, derInteger(key.exponent));
        encoded = tagged(0x30, numbers);
        algorithm.reset(OBJ_nid2obj(NID_rsaEncryption));
    } else {
        encoded = tagged(0x04, key.value);
        algorithm.reset(OBJ_txt2obj(key.type == CKK_GOSTR3410 ? "1.2.643.7.1.1.1.1"
                                                               : "1.2.643.7.1.1.1.2", 1));
        Bytes sequence = key.curve;
        append(sequence, key.digest);
        sequence = tagged(0x30, sequence);
        parameters.reset(ASN1_STRING_new());
        if (!parameters || ASN1_STRING_set(parameters.get(), sequence.data(),
                                           static_cast<int>(sequence.size())) != 1)
            return false;
        parameterType = V_ASN1_SEQUENCE;
    }
    if (!algorithm) return false;
    unsigned char* bits = static_cast<unsigned char*>(OPENSSL_malloc(encoded.size()));
    if (!bits) return false;
    memcpy(bits, encoded.data(), encoded.size());
    if (X509_PUBKEY_set0_param(spki, algorithm.get(), parameterType, parameters.get(),
                               bits, static_cast<int>(encoded.size())) != 1) {
        OPENSSL_free(bits);
        return false;
    }
    algorithm.release();
    parameters.release();
    return true;
}

CK_RV requestInfo(const PublicKey& key, CK_CHAR_PTR* dn, CK_ULONG dnLength,
                  CK_CHAR_PTR* attributes, CK_ULONG attributesLength,
                  CK_CHAR_PTR* extensions, CK_ULONG extensionsLength, Bytes& tbs)
{
    RequestPtr request(X509_REQ_new(), X509_REQ_free);
    NamePtr subject(X509_NAME_new(), X509_NAME_free);
    if (!request || !subject) return CKR_HOST_MEMORY;
    if (X509_REQ_set_version(request.get(), 0) != 1) return CKR_FUNCTION_FAILED;
    for (CK_ULONG i = 0; i < dnLength; i += 2) {
        CK_RV rv = appendNameEntry(subject.get(), text(dn[i]), text(dn[i + 1]));
        if (rv != CKR_OK) return rv;
    }
    if (X509_REQ_set_subject_name(request.get(), subject.get()) != 1)
        return CKR_FUNCTION_FAILED;
    if (!setPublicKey(request.get(), key)) return CKR_FUNCTION_FAILED;
    for (CK_ULONG i = 0; i < attributesLength; i += 2) {
        CK_RV rv = appendAttribute(request.get(), text(attributes[i]),
                                   text(attributes[i + 1]));
        if (rv != CKR_OK) return rv;
    }
    if (extensionsLength) {
        // An empty configuration: certificatePolicies, which the device
        // accepts, is read only with one present; "@section" finds nothing.
        ConfPtr conf(NCONF_new(nullptr), NCONF_free);
        if (!conf) return CKR_HOST_MEMORY;
        X509V3_CTX context;
        memset(&context, 0, sizeof(context));
        X509V3_set_ctx(&context, nullptr, nullptr, request.get(), nullptr, 0);
        X509V3_set_nconf(&context, conf.get());
        ExtensionsPtr list(sk_X509_EXTENSION_new_null());
        if (!list) return CKR_HOST_MEMORY;
        for (CK_ULONG i = 0; i < extensionsLength; i += 2) {
            CK_RV rv = appendExtension(list.get(), conf.get(), &context, text(extensions[i]),
                                       text(extensions[i + 1]));
            if (rv != CKR_OK) return rv;
        }
        if (X509_REQ_add_extensions(request.get(), list.get()) != 1)
            return CKR_ARGUMENTS_BAD;
    }
    int length = i2d_re_X509_REQ_tbs(request.get(), nullptr);
    if (length <= 0) return CKR_FUNCTION_FAILED;
    tbs.resize(length);
    unsigned char* cursor = tbs.data();
    if (i2d_re_X509_REQ_tbs(request.get(), &cursor) != length) return CKR_FUNCTION_FAILED;
    return CKR_OK;
}

CK_RV tokenSignature(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privateKey,
                     const PublicKey& key, const Bytes& tbs, Bytes& digest,
                     Bytes& signature)
{
    CK_RV rv;
    CK_ULONG length = 0;
    if (key.gost()) {
        CK_MECHANISM digestMechanism = {
            key.bits() == 256 ? CKM_GOSTR3411_12_256 : CKM_GOSTR3411_12_512, NULL_PTR, 0 };
        rv = C_DigestInit(session, &digestMechanism);
        if (rv != CKR_OK) return rv;
        digest.resize(key.bits() / 8);
        length = static_cast<CK_ULONG>(digest.size());
        rv = C_Digest(session, const_cast<CK_BYTE_PTR>(tbs.data()),
                      static_cast<CK_ULONG>(tbs.size()), digest.data(), &length);
        if (rv != CKR_OK) return rv;
        if (length != digest.size()) return CKR_FUNCTION_FAILED;
        CK_MECHANISM signMechanism = {
            key.bits() == 256 ? CKM_GOSTR3410 : CKM_GOSTR3410_512, NULL_PTR, 0 };
        rv = C_SignInit(session, &signMechanism, privateKey);
        if (rv != CKR_OK) return rv;
        signature.resize(key.bits() / 4);
        length = static_cast<CK_ULONG>(signature.size());
        rv = C_Sign(session, digest.data(), static_cast<CK_ULONG>(digest.size()),
                    signature.data(), &length);
        if (rv != CKR_OK) return rv;
        return length == signature.size() ? CKR_OK : CKR_FUNCTION_FAILED;
    }
    CK_MECHANISM mechanism = { CKM_SHA1_RSA_PKCS, NULL_PTR, 0 };
    rv = C_SignInit(session, &mechanism, privateKey);
    if (rv != CKR_OK) return rv;
    rv = C_Sign(session, const_cast<CK_BYTE_PTR>(tbs.data()),
                static_cast<CK_ULONG>(tbs.size()), NULL_PTR, &length);
    if (rv != CKR_OK) return rv;
    signature.resize(length);
    rv = C_Sign(session, const_cast<CK_BYTE_PTR>(tbs.data()),
                static_cast<CK_ULONG>(tbs.size()), signature.data(), &length);
    if (rv != CKR_OK) return rv;
    signature.resize(length);
    return CKR_OK;
}

// The signature checked against the public key of the request, through a
// session copy of it so that the original's CKA_VERIFY does not matter.
CK_RV checkSignature(CK_SESSION_HANDLE session, const PublicKey& key, const Bytes& tbs,
                     const Bytes& digest, const Bytes& signature)
{
    CK_OBJECT_CLASS objectClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = key.type;
    CK_BBOOL no = CK_FALSE, yes = CK_TRUE;
    std::vector<CK_ATTRIBUTE> attrs = {
        { CKA_CLASS, &objectClass, sizeof(objectClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_TOKEN, &no, sizeof(no) },
        { CKA_PRIVATE, &no, sizeof(no) },
        { CKA_VERIFY, &yes, sizeof(yes) }
    };
    auto add = [&attrs](CK_ATTRIBUTE_TYPE type, const Bytes& value) {
        attrs.push_back({ type, const_cast<unsigned char*>(value.data()),
                          static_cast<CK_ULONG>(value.size()) });
    };
    if (key.gost()) {
        add(CKA_VALUE, key.value);
        add(CKA_GOSTR3410_PARAMS, key.curve);
        if (!key.digest.empty()) add(CKA_GOSTR3411_PARAMS, key.digest);
    } else {
        add(CKA_MODULUS, key.modulus);
        add(CKA_PUBLIC_EXPONENT, key.exponent);
    }
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_RV rv = C_CreateObject(session, attrs.data(), static_cast<CK_ULONG>(attrs.size()),
                              &handle);
    if (rv != CKR_OK) return rv;
    CK_MECHANISM mechanism = { key.type == CKK_RSA ? CKM_SHA1_RSA_PKCS
                               : key.type == CKK_GOSTR3410 ? CKM_GOSTR3410
                               : CKM_GOSTR3410_512, NULL_PTR, 0 };
    const Bytes& input = key.gost() ? digest : tbs;
    rv = C_VerifyInit(session, &mechanism, handle);
    if (rv == CKR_OK)
        rv = C_Verify(session, const_cast<CK_BYTE_PTR>(input.data()),
                      static_cast<CK_ULONG>(input.size()),
                      const_cast<CK_BYTE_PTR>(signature.data()),
                      static_cast<CK_ULONG>(signature.size()));
    CK_RV destroyed = C_DestroyObject(session, handle);
    return rv != CKR_OK ? rv : destroyed;
}

Bytes certificationRequest(const PublicKey& key, const Bytes& tbs, const Bytes& signature)
{
    static const Bytes gost256 = { 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07,
                                   0x01, 0x01, 0x03, 0x02 };
    static const Bytes gost512 = { 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07,
                                   0x01, 0x01, 0x03, 0x03 };
    // The OIW sha1WithRSA (1.3.14.3.2.29), not PKCS #1 sha1WithRSAEncryption.
    static const Bytes sha1Rsa = { 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1d,
                                   0x05, 0x00 };
    Bytes body = tbs;
    append(body, key.type == CKK_RSA ? sha1Rsa : key.bits() == 256 ? gost256 : gost512);
    Bytes bits{0};
    append(bits, signature);
    append(body, tagged(0x03, bits));
    return tagged(0x30, body);
}

}
#endif

CK_RV create(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publicKey,
             CK_CHAR_PTR* dn, CK_ULONG dnLength, CK_BYTE_PTR* csr,
             CK_ULONG_PTR csrLength, CK_OBJECT_HANDLE privateKey,
             CK_CHAR_PTR* attributes, CK_ULONG attributesLength,
             CK_CHAR_PTR* extensions, CK_ULONG extensionsLength)
{
#ifndef WITH_OPENSSL
    (void)session; (void)publicKey; (void)dn; (void)dnLength; (void)csr;
    (void)csrLength; (void)privateKey; (void)attributes; (void)attributesLength;
    (void)extensions; (void)extensionsLength;
    return CKR_FUNCTION_NOT_SUPPORTED;
#else
    try {
        if (!csr || !csrLength) return CKR_ARGUMENTS_BAD;
        *csr = NULL_PTR;
        *csrLength = 0;
        CK_RV rv = checkStrings(dn, dnLength);
        if (rv == CKR_OK) rv = checkStrings(attributes, attributesLength);
        if (rv == CKR_OK) rv = checkStrings(extensions, extensionsLength);
        if (rv != CKR_OK) return rv;
        rv = userSession(session);
        if (rv != CKR_OK) return rv;
        PublicKey key;
        rv = readPublicKey(session, publicKey, key);
        if (rv != CKR_OK) return rv;
        CK_OBJECT_CLASS privateClass = CKO_VENDOR_DEFINED;
        rv = scalar(session, privateKey, CKA_CLASS, privateClass);
        if (rv != CKR_OK) return rv;
        if (privateClass != CKO_PRIVATE_KEY) return CKR_KEY_TYPE_INCONSISTENT;
        Bytes tbs;
        {
            ErrorMark mark;
            rv = requestInfo(key, dn, dnLength, attributes, attributesLength,
                             extensions, extensionsLength, tbs);
        }
        if (rv != CKR_OK) return rv;
        Bytes digest, signature;
        rv = tokenSignature(session, privateKey, key, tbs, digest, signature);
        if (rv != CKR_OK) return rv;
        // Keys of different pairs: the device signs nothing usable and says so.
        if (checkSignature(session, key, tbs, digest, signature) != CKR_OK)
            return CKR_FUNCTION_FAILED;
        Bytes der = certificationRequest(key, tbs, signature);
        CK_BYTE_PTR output = static_cast<CK_BYTE_PTR>(malloc(der.size()));
        if (!output) return CKR_HOST_MEMORY;
        memcpy(output, der.data(), der.size());
        *csr = output;
        *csrLength = static_cast<CK_ULONG>(der.size());
        return CKR_OK;
    } catch (const std::bad_alloc&) { return CKR_HOST_MEMORY; }
    catch (...) { return CKR_FUNCTION_FAILED; }
#endif
}

}
