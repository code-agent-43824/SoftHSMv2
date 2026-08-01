/*
 * Dependency-light portable package integration test.
 *
 * This client deliberately talks to the downloaded module through PKCS #11
 * only.  It does not link to SoftHSM or OpenSSL.  OpenSSL CLI is used by the
 * surrounding script as an independent CSR, CA, certificate, and CMS parser.
 */

#include "pkcs11.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;

static const Bytes kObjectId = {0x50, 0x4f, 0x52, 0x54, 0x41, 0x42, 0x4c, 0x45};
static const char kKeyLabel[] = "portable-ci-rsa";
static const char kTokenLabel[] = "portable-ci-token";

[[noreturn]] static void fail(const std::string& message)
{
    throw std::runtime_error(message);
}

static void check(CK_RV rv, CK_RV expected, const char* operation)
{
    if (rv != expected)
    {
        std::ostringstream out;
        out << operation << " failed: expected 0x" << std::hex << expected
            << ", got 0x" << rv;
        fail(out.str());
    }
}

static Bytes readFile(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) fail("cannot open " + path.string());
    return Bytes(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

static void writeFile(const fs::path& path, const Bytes& bytes)
{
    std::ofstream output(path, std::ios::binary);
    if (!output) fail("cannot create " + path.string());
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!output) fail("cannot write " + path.string());
}

static void append(Bytes& target, const Bytes& value)
{
    target.insert(target.end(), value.begin(), value.end());
}

static Bytes joined(const std::vector<Bytes>& values)
{
    Bytes result;
    for (const auto& value : values) append(result, value);
    return result;
}

static Bytes derLength(size_t length)
{
    if (length < 128) return {static_cast<unsigned char>(length)};
    Bytes encoded;
    while (length != 0)
    {
        encoded.push_back(static_cast<unsigned char>(length & 0xff));
        length >>= 8;
    }
    std::reverse(encoded.begin(), encoded.end());
    Bytes result = {static_cast<unsigned char>(0x80 | encoded.size())};
    append(result, encoded);
    return result;
}

static Bytes der(unsigned char tag, const Bytes& content)
{
    Bytes result = {tag};
    append(result, derLength(content.size()));
    append(result, content);
    return result;
}

static Bytes sequence(const std::vector<Bytes>& values) { return der(0x30, joined(values)); }

static Bytes sortedSet(std::vector<Bytes> values)
{
    std::sort(values.begin(), values.end());
    return der(0x31, joined(values));
}

static Bytes integer(Bytes value)
{
    while (value.size() > 1 && value.front() == 0 && (value[1] & 0x80) == 0) value.erase(value.begin());
    if (value.empty()) value.push_back(0);
    if ((value.front() & 0x80) != 0) value.insert(value.begin(), 0);
    return der(0x02, value);
}

static Bytes oid(std::initializer_list<unsigned char> body)
{
    return der(0x06, Bytes(body));
}

static Bytes nullValue() { return der(0x05, {}); }

static Bytes rsaAlgorithm()
{
    return sequence({oid({0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}), nullValue()});
}

static Bytes sha256Algorithm()
{
    return sequence({oid({0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}), nullValue()});
}

static Bytes sha256WithRsaAlgorithm()
{
    return sequence({oid({0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}), nullValue()});
}

static Bytes cmsDataOid() { return oid({0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}); }
static Bytes cmsSignedDataOid() { return oid({0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}); }

static std::string base64(const Bytes& input)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    for (size_t offset = 0; offset < input.size(); offset += 3)
    {
        uint32_t block = static_cast<uint32_t>(input[offset]) << 16;
        const size_t remaining = input.size() - offset;
        if (remaining > 1) block |= static_cast<uint32_t>(input[offset + 1]) << 8;
        if (remaining > 2) block |= input[offset + 2];
        output.push_back(alphabet[(block >> 18) & 63]);
        output.push_back(alphabet[(block >> 12) & 63]);
        output.push_back(remaining > 1 ? alphabet[(block >> 6) & 63] : '=');
        output.push_back(remaining > 2 ? alphabet[block & 63] : '=');
    }
    return output;
}

static void writePem(const fs::path& path, const char* label, const Bytes& derBytes)
{
    const std::string encoded = base64(derBytes);
    std::ofstream output(path, std::ios::binary);
    if (!output) fail("cannot create " + path.string());
    output << "-----BEGIN " << label << "-----\n";
    for (size_t offset = 0; offset < encoded.size(); offset += 64)
        output << encoded.substr(offset, 64) << '\n';
    output << "-----END " << label << "-----\n";
}

class Module
{
public:
    explicit Module(const fs::path& path)
    {
#ifdef _WIN32
        handle_ = LoadLibraryW(path.wstring().c_str());
        if (!handle_) fail("LoadLibrary failed for " + path.string());
        auto getter = reinterpret_cast<CK_C_GetFunctionList>(GetProcAddress(handle_, "C_GetFunctionList"));
#else
        handle_ = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!handle_) fail(std::string("dlopen failed: ") + dlerror());
        auto getter = reinterpret_cast<CK_C_GetFunctionList>(dlsym(handle_, "C_GetFunctionList"));
#endif
        if (!getter) fail("C_GetFunctionList was not exported");
        check(getter(&p11_), CKR_OK, "C_GetFunctionList");
        check(p11_->C_Initialize(nullptr), CKR_OK, "C_Initialize");
        initialized_ = true;
    }

    ~Module()
    {
        if (initialized_) p11_->C_Finalize(nullptr);
#ifdef _WIN32
        if (handle_) FreeLibrary(handle_);
#else
        if (handle_) dlclose(handle_);
#endif
    }

    CK_FUNCTION_LIST_PTR operator->() const { return p11_; }

private:
#ifdef _WIN32
    HMODULE handle_ = nullptr;
#else
    void* handle_ = nullptr;
#endif
    CK_FUNCTION_LIST_PTR p11_ = nullptr;
    bool initialized_ = false;
};

static std::vector<CK_SLOT_ID> slots(Module& module, CK_BBOOL tokenPresent)
{
    CK_ULONG count = 0;
    check(module->C_GetSlotList(tokenPresent, nullptr, &count), CKR_OK, "C_GetSlotList(size)");
    std::vector<CK_SLOT_ID> result(count);
    check(module->C_GetSlotList(tokenPresent, result.data(), &count), CKR_OK, "C_GetSlotList(data)");
    result.resize(count);
    if (result.empty()) fail("module exposed no slots");
    return result;
}

static CK_SLOT_ID initializedSlot(Module& module)
{
    for (CK_SLOT_ID slot : slots(module, CK_TRUE))
    {
        CK_TOKEN_INFO info{};
        if (module->C_GetTokenInfo(slot, &info) == CKR_OK && (info.flags & CKF_TOKEN_INITIALIZED) != 0)
            return slot;
    }
    fail("no initialized token was found");
}

static CK_SESSION_HANDLE openSession(Module& module, CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    check(module->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session),
          CKR_OK, "C_OpenSession");
    return session;
}

static Bytes attribute(Module& module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type)
{
    CK_ATTRIBUTE attr{type, nullptr, 0};
    check(module->C_GetAttributeValue(session, object, &attr, 1), CKR_OK, "C_GetAttributeValue(size)");
    if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION) fail("attribute is unavailable");
    Bytes value(attr.ulValueLen);
    attr.pValue = value.data();
    check(module->C_GetAttributeValue(session, object, &attr, 1), CKR_OK, "C_GetAttributeValue(data)");
    value.resize(attr.ulValueLen);
    return value;
}

static CK_OBJECT_HANDLE findOne(Module& module, CK_SESSION_HANDLE session, std::vector<CK_ATTRIBUTE> query)
{
    check(module->C_FindObjectsInit(session, query.data(), static_cast<CK_ULONG>(query.size())),
          CKR_OK, "C_FindObjectsInit");
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    CK_RV rv = module->C_FindObjects(session, &object, 1, &count);
    CK_RV finalRv = module->C_FindObjectsFinal(session);
    check(rv, CKR_OK, "C_FindObjects");
    check(finalRv, CKR_OK, "C_FindObjectsFinal");
    if (count != 1) fail("expected object was not found");
    return object;
}

static Bytes sign(Module& module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, const Bytes& data)
{
    CK_MECHANISM mechanism{CKM_SHA256_RSA_PKCS, nullptr, 0};
    check(module->C_SignInit(session, &mechanism, key), CKR_OK, "C_SignInit");
    CK_ULONG length = 0;
    check(module->C_Sign(session, const_cast<CK_BYTE_PTR>(data.data()), static_cast<CK_ULONG>(data.size()),
                         nullptr, &length), CKR_OK, "C_Sign(size)");
    Bytes signature(length);
    check(module->C_Sign(session, const_cast<CK_BYTE_PTR>(data.data()), static_cast<CK_ULONG>(data.size()),
                         signature.data(), &length), CKR_OK, "C_Sign(data)");
    signature.resize(length);
    return signature;
}

static Bytes digest(Module& module, CK_SESSION_HANDLE session, const Bytes& data)
{
    CK_MECHANISM mechanism{CKM_SHA256, nullptr, 0};
    check(module->C_DigestInit(session, &mechanism), CKR_OK, "C_DigestInit");
    CK_ULONG length = 32;
    Bytes result(length);
    check(module->C_Digest(session, const_cast<CK_BYTE_PTR>(data.data()), static_cast<CK_ULONG>(data.size()),
                           result.data(), &length), CKR_OK, "C_Digest");
    result.resize(length);
    if (result.size() != 32) fail("SHA-256 returned an unexpected size");
    return result;
}

struct Tlv
{
    unsigned char tag;
    size_t offset;
    size_t header;
    size_t length;
    size_t total() const { return header + length; }
    size_t content() const { return offset + header; }
};

static Tlv parseTlv(const Bytes& bytes, size_t offset)
{
    if (offset + 2 > bytes.size()) fail("truncated DER object");
    const unsigned char tag = bytes[offset];
    size_t cursor = offset + 1;
    size_t length = bytes[cursor++];
    if ((length & 0x80) != 0)
    {
        const size_t count = length & 0x7f;
        if (count == 0 || count > sizeof(size_t) || cursor + count > bytes.size()) fail("invalid DER length");
        length = 0;
        for (size_t i = 0; i < count; ++i) length = (length << 8) | bytes[cursor++];
    }
    if (cursor + length > bytes.size()) fail("DER value exceeds input");
    return {tag, offset, cursor - offset, length};
}

static Bytes encodedTlv(const Bytes& bytes, const Tlv& tlv)
{
    return Bytes(bytes.begin() + static_cast<std::ptrdiff_t>(tlv.offset),
                 bytes.begin() + static_cast<std::ptrdiff_t>(tlv.offset + tlv.total()));
}

struct CertificateFields
{
    Bytes issuer;
    Bytes serial;
    Bytes subject;
};

static CertificateFields certificateFields(const Bytes& certificate)
{
    Tlv outer = parseTlv(certificate, 0);
    if (outer.tag != 0x30 || outer.total() != certificate.size()) fail("certificate is not a DER sequence");
    Tlv tbs = parseTlv(certificate, outer.content());
    if (tbs.tag != 0x30) fail("certificate has no TBSCertificate");
    size_t cursor = tbs.content();
    Tlv value = parseTlv(certificate, cursor);
    if (value.tag == 0xa0)
    {
        cursor += value.total();
        value = parseTlv(certificate, cursor);
    }
    if (value.tag != 0x02) fail("certificate has no serial number");
    Bytes serial = encodedTlv(certificate, value);
    cursor += value.total();
    Tlv signatureAlgorithm = parseTlv(certificate, cursor);
    cursor += signatureAlgorithm.total();
    Tlv issuer = parseTlv(certificate, cursor);
    if (issuer.tag != 0x30) fail("certificate has no issuer name");
    cursor += issuer.total();
    Tlv validity = parseTlv(certificate, cursor);
    if (validity.tag != 0x30) fail("certificate has no validity sequence");
    cursor += validity.total();
    Tlv subject = parseTlv(certificate, cursor);
    if (subject.tag != 0x30) fail("certificate has no subject name");
    return {encodedTlv(certificate, issuer), serial, encodedTlv(certificate, subject)};
}

static Bytes buildCsr(Module& module, CK_SESSION_HANDLE session,
                      CK_OBJECT_HANDLE publicKey, CK_OBJECT_HANDLE privateKey)
{
    const Bytes modulus = attribute(module, session, publicKey, CKA_MODULUS);
    const Bytes exponent = attribute(module, session, publicKey, CKA_PUBLIC_EXPONENT);
    Bytes rsaPublic = sequence({integer(modulus), integer(exponent)});
    Bytes bitString = {0};
    append(bitString, rsaPublic);
    Bytes subjectPublicKeyInfo = sequence({rsaAlgorithm(), der(0x03, bitString)});

    Bytes commonName = sequence({
        oid({0x55, 0x04, 0x03}),
        der(0x0c, Bytes({'S','o','f','t','H','S','M',' ','P','o','r','t','a','b','l','e',' ','C','I'}))
    });
    Bytes subject = sequence({sortedSet({commonName})});
    Bytes requestInfo = sequence({integer({0}), subject, subjectPublicKeyInfo, der(0xa0, {})});
    Bytes signature = sign(module, session, privateKey, requestInfo);
    Bytes signatureBits = {0};
    append(signatureBits, signature);
    return sequence({requestInfo, sha256WithRsaAlgorithm(), der(0x03, signatureBits)});
}

static Bytes cmsAttribute(const Bytes& attributeOid, const Bytes& value)
{
    return sequence({attributeOid, sortedSet({value})});
}

static Bytes buildCms(Module& module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privateKey,
                      const Bytes& leaf, const Bytes& ca, const Bytes& payload)
{
    Bytes contentTypeAttribute = cmsAttribute(
        oid({0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03}), cmsDataOid());
    Bytes messageDigestAttribute = cmsAttribute(
        oid({0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04}),
        der(0x04, digest(module, session, payload)));
    std::vector<Bytes> attributes = {contentTypeAttribute, messageDigestAttribute};
    std::sort(attributes.begin(), attributes.end());
    Bytes attributeContent = joined(attributes);
    Bytes signature = sign(module, session, privateKey, der(0x31, attributeContent));

    CertificateFields identity = certificateFields(leaf);
    Bytes signerInfo = sequence({
        integer({1}),
        sequence({identity.issuer, identity.serial}),
        sha256Algorithm(),
        der(0xa0, attributeContent),
        rsaAlgorithm(),
        der(0x04, signature)
    });

    std::vector<Bytes> certificates = {leaf, ca};
    std::sort(certificates.begin(), certificates.end());
    Bytes signedData = sequence({
        integer({1}),
        sortedSet({sha256Algorithm()}),
        sequence({cmsDataOid()}),
        der(0xa0, joined(certificates)),
        sortedSet({signerInfo})
    });
    return sequence({cmsSignedDataOid(), der(0xa0, signedData)});
}

static void prepare(const fs::path& modulePath, const fs::path& work,
                    const std::string& soPin, const std::string& userPin)
{
    fs::create_directories(work);
    fs::current_path(work);
    Module module(modulePath);
    CK_SLOT_ID slot = slots(module, CK_TRUE).front();

    std::array<CK_UTF8CHAR, 32> label{};
    label.fill(' ');
    std::copy(kTokenLabel, kTokenLabel + sizeof(kTokenLabel) - 1, label.begin());
    check(module->C_InitToken(slot,
                              reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(soPin.data())),
                              static_cast<CK_ULONG>(soPin.size()), label.data()),
          CKR_OK, "C_InitToken");

    CK_SESSION_HANDLE session = openSession(module, slot);
    check(module->C_Login(session, CKU_SO,
                          reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(soPin.data())),
                          static_cast<CK_ULONG>(soPin.size())), CKR_OK, "C_Login(SO)");
    check(module->C_InitPIN(session,
                            reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(userPin.data())),
                            static_cast<CK_ULONG>(userPin.size())), CKR_OK, "C_InitPIN");
    check(module->C_Logout(session), CKR_OK, "C_Logout(SO)");
    check(module->C_Login(session, CKU_USER,
                          reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(userPin.data())),
                          static_cast<CK_ULONG>(userPin.size())), CKR_OK, "C_Login(USER)");

    CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ULONG bits = 2048;
    CK_BYTE exponent[] = {0x01, 0x00, 0x01};
    CK_ATTRIBUTE publicTemplate[] = {
        {CKA_CLASS, &publicClass, sizeof(publicClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &yes, sizeof(yes)},
        {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_VERIFY, &yes, sizeof(yes)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent)},
        {CKA_LABEL, const_cast<char*>(kKeyLabel), sizeof(kKeyLabel) - 1},
        {CKA_ID, const_cast<unsigned char*>(kObjectId.data()), static_cast<CK_ULONG>(kObjectId.size())}
    };
    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &yes, sizeof(yes)},
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &yes, sizeof(yes)},
        {CKA_SIGN, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &no, sizeof(no)},
        {CKA_LABEL, const_cast<char*>(kKeyLabel), sizeof(kKeyLabel) - 1},
        {CKA_ID, const_cast<unsigned char*>(kObjectId.data()), static_cast<CK_ULONG>(kObjectId.size())}
    };
    CK_MECHANISM mechanism{CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
    check(module->C_GenerateKeyPair(session, &mechanism,
                                    publicTemplate, sizeof(publicTemplate) / sizeof(publicTemplate[0]),
                                    privateTemplate, sizeof(privateTemplate) / sizeof(privateTemplate[0]),
                                    &publicKey, &privateKey), CKR_OK, "C_GenerateKeyPair");

    writePem(work / "request.pem", "CERTIFICATE REQUEST", buildCsr(module, session, publicKey, privateKey));
    check(module->C_Logout(session), CKR_OK, "C_Logout(USER)");
    check(module->C_CloseSession(session), CKR_OK, "C_CloseSession");
    std::cout << "PKCS #11 token initialized, RSA-2048 key generated, CSR written\n";
}

static void finish(const fs::path& modulePath, const fs::path& work, const std::string& userPin,
                   const fs::path& leafPath, const fs::path& caPath,
                   const fs::path& payloadPath, const fs::path& cmsPath)
{
    fs::current_path(work);
    const Bytes leaf = readFile(leafPath);
    const Bytes ca = readFile(caPath);
    const Bytes payload = readFile(payloadPath);
    const CertificateFields fields = certificateFields(leaf);
    Module module(modulePath);
    CK_SESSION_HANDLE session = openSession(module, initializedSlot(module));
    check(module->C_Login(session, CKU_USER,
                          reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(userPin.data())),
                          static_cast<CK_ULONG>(userPin.size())), CKR_OK, "C_Login(USER)");

    CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsa = CKK_RSA;
    std::vector<CK_ATTRIBUTE> privateQuery = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &rsa, sizeof(rsa)},
        {CKA_ID, const_cast<unsigned char*>(kObjectId.data()), static_cast<CK_ULONG>(kObjectId.size())}
    };
    CK_OBJECT_HANDLE privateKey = findOne(module, session, privateQuery);

    CK_OBJECT_CLASS certificateClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certificateType = CKC_X_509;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    const char certificateLabel[] = "portable-ci-certificate";
    CK_ATTRIBUTE certificateTemplate[] = {
        {CKA_CLASS, &certificateClass, sizeof(certificateClass)},
        {CKA_CERTIFICATE_TYPE, &certificateType, sizeof(certificateType)},
        {CKA_TOKEN, &yes, sizeof(yes)},
        {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_LABEL, const_cast<char*>(certificateLabel), sizeof(certificateLabel) - 1},
        {CKA_ID, const_cast<unsigned char*>(kObjectId.data()), static_cast<CK_ULONG>(kObjectId.size())},
        {CKA_VALUE, const_cast<unsigned char*>(leaf.data()), static_cast<CK_ULONG>(leaf.size())},
        {CKA_SUBJECT, const_cast<unsigned char*>(fields.subject.data()), static_cast<CK_ULONG>(fields.subject.size())},
        {CKA_ISSUER, const_cast<unsigned char*>(fields.issuer.data()), static_cast<CK_ULONG>(fields.issuer.size())},
        {CKA_SERIAL_NUMBER, const_cast<unsigned char*>(fields.serial.data()), static_cast<CK_ULONG>(fields.serial.size())}
    };
    CK_OBJECT_HANDLE certificate = CK_INVALID_HANDLE;
    check(module->C_CreateObject(session, certificateTemplate,
                                 sizeof(certificateTemplate) / sizeof(certificateTemplate[0]),
                                 &certificate), CKR_OK, "C_CreateObject(certificate)");

    std::vector<CK_ATTRIBUTE> certificateQuery = {
        {CKA_CLASS, &certificateClass, sizeof(certificateClass)},
        {CKA_ID, const_cast<unsigned char*>(kObjectId.data()), static_cast<CK_ULONG>(kObjectId.size())}
    };
    (void)findOne(module, session, certificateQuery);
    writeFile(cmsPath, buildCms(module, session, privateKey, leaf, ca, payload));

    check(module->C_Logout(session), CKR_OK, "C_Logout(USER)");
    check(module->C_CloseSession(session), CKR_OK, "C_CloseSession");
    std::cout << "Certificate imported, token key reopened, detached CMS written\n";
}

int main(int argc, char** argv)
{
    try
    {
        if (argc == 6 && std::string(argv[1]) == "prepare")
        {
            prepare(fs::absolute(argv[2]), fs::absolute(argv[3]), argv[4], argv[5]);
            return 0;
        }
        if (argc == 9 && std::string(argv[1]) == "finish")
        {
            finish(fs::absolute(argv[2]), fs::absolute(argv[3]), argv[4], fs::absolute(argv[5]),
                   fs::absolute(argv[6]), fs::absolute(argv[7]), fs::absolute(argv[8]));
            return 0;
        }
        std::cerr << "usage:\n"
                  << "  portable-token-e2e prepare <module> <work> <so-pin> <user-pin>\n"
                  << "  portable-token-e2e finish <module> <work> <user-pin> <leaf.der> <ca.der> <payload> <cms.der>\n";
        return 2;
    }
    catch (const std::exception& error)
    {
        std::cerr << "portable token E2E failure: " << error.what() << '\n';
        return 1;
    }
}
