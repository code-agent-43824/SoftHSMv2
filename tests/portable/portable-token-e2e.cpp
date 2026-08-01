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
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
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
static unsigned long long traceSequence = 0;

[[noreturn]] static void fail(const std::string& message)
{
    throw std::runtime_error(message);
}

static std::string hexNumber(CK_ULONG value)
{
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << value;
    return out.str();
}

static std::string hexBytes(const void* data, size_t length)
{
    if (data == nullptr) return "NULL_PTR";
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t index = 0; index < length; ++index)
        out << std::setw(2) << static_cast<unsigned int>(bytes[index]);
    return out.str();
}

static const char* rvName(CK_RV rv)
{
    switch (rv)
    {
        case CKR_OK: return "CKR_OK";
        case CKR_CANCEL: return "CKR_CANCEL";
        case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
        case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
        case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
        case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
        case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
        case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
        case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
        case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
        case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
        case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
        case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
        case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
        case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
        case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
        case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
        case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
        case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
        case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
        case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
        case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
        case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
        case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
        case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
        case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
        case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
        case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
        case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
        case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
        case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
        case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
        case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
        case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
        case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
        case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
        case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
        case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
        case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
        case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
        case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
        case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
        case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
        case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
        case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
        case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
        default: return "CKR_<unknown>";
    }
}

static void trace(const std::string& category, const std::string& message)
{
    std::cout << "[TRACE " << std::setw(4) << std::setfill('0') << ++traceSequence
              << "][" << category << "] " << message << '\n';
    std::cout.flush();
}

template<typename Function>
static CK_RV invoke(const char* operation, const std::string& parameters, Function function)
{
    trace("PKCS11", std::string("-> ") + operation + "(" + parameters + ")");
    const CK_RV rv = function();
    trace("PKCS11", std::string("<- ") + operation + " = " + rvName(rv) + " (" + hexNumber(rv) + ")");
    return rv;
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

template<typename Function>
static void callOk(const char* operation, const std::string& parameters, Function function)
{
    check(invoke(operation, parameters, function), CKR_OK, operation);
}

static std::string paddedText(const unsigned char* data, size_t length)
{
    std::string value(reinterpret_cast<const char*>(data), length);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\0')) value.pop_back();
    return value;
}

static std::string environment(const char* name, bool required = false)
{
    const char* value = std::getenv(name);
    if (value != nullptr && *value != '\0') return value;
    if (required) fail(std::string("required environment variable is missing: ") + name);
    return {};
}

static bool environmentYes(const char* name)
{
    std::string value = environment(name);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char character) { return static_cast<char>(std::toupper(character)); });
    if (value.empty() || value == "NO" || value == "FALSE" || value == "0") return false;
    if (value == "YES" || value == "TRUE" || value == "1") return true;
    fail(std::string(name) + " must be YES or NO");
}

static Bytes configuredObjectId()
{
    const std::string configured = environment("P11_TEST_OBJECT_ID_HEX");
    if (configured.empty()) return kObjectId;
    if (configured.size() % 2 != 0) fail("P11_TEST_OBJECT_ID_HEX must contain an even number of hex digits");
    Bytes result;
    for (size_t offset = 0; offset < configured.size(); offset += 2)
    {
        const std::string byte = configured.substr(offset, 2);
        char* end = nullptr;
        const unsigned long value = std::strtoul(byte.c_str(), &end, 16);
        if (end == nullptr || *end != '\0' || value > 0xff) fail("P11_TEST_OBJECT_ID_HEX is invalid");
        result.push_back(static_cast<unsigned char>(value));
    }
    return result;
}

static std::optional<CK_SLOT_ID> configuredSlot()
{
    const std::string configured = environment("P11_TEST_SLOT_ID");
    if (configured.empty()) return std::nullopt;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(configured.c_str(), &end, 0);
    if (end == nullptr || *end != '\0') fail("P11_TEST_SLOT_ID must be a decimal or 0x-prefixed number");
    if (value > static_cast<unsigned long long>(std::numeric_limits<CK_SLOT_ID>::max()))
        fail("P11_TEST_SLOT_ID does not fit CK_SLOT_ID on this platform");
    return static_cast<CK_SLOT_ID>(value);
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
        trace("MODULE", "loading PKCS #11 library: " + path.string());
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
        callOk("C_GetFunctionList", "ppFunctionList=&functionList", [&] { return getter(&p11_); });
        if (p11_ == nullptr) fail("C_GetFunctionList returned a null function list");
        trace("MODULE", "Cryptoki function-list version=" + std::to_string(p11_->version.major) + "." +
                        std::to_string(p11_->version.minor));
        callOk("C_Initialize", "pInitArgs=NULL_PTR (single-threaded client)",
               [&] { return p11_->C_Initialize(nullptr); });
        initialized_ = true;

        CK_INFO info{};
        callOk("C_GetInfo", "pInfo=&info", [&] { return p11_->C_GetInfo(&info); });
        trace("MODULE", "manufacturer=\"" + paddedText(info.manufacturerID, sizeof(info.manufacturerID)) +
                        "\", description=\"" + paddedText(info.libraryDescription, sizeof(info.libraryDescription)) +
                        "\", libraryVersion=" + std::to_string(info.libraryVersion.major) + "." +
                        std::to_string(info.libraryVersion.minor));
    }

    ~Module()
    {
        if (initialized_)
        {
            const CK_RV rv = invoke("C_Finalize", "pReserved=NULL_PTR", [&] { return p11_->C_Finalize(nullptr); });
            if (rv != CKR_OK)
                trace("WARNING", std::string("C_Finalize returned ") + rvName(rv) + " during cleanup");
        }
#ifdef _WIN32
        if (handle_)
        {
            FreeLibrary(handle_);
            trace("MODULE", "library unloaded with FreeLibrary");
        }
#else
        if (handle_)
        {
            dlclose(handle_);
            trace("MODULE", "library unloaded with dlclose");
        }
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
    std::vector<CK_SLOT_ID> result;
    for (;;)
    {
        CK_ULONG count = 0;
        callOk("C_GetSlotList", std::string("tokenPresent=") + (tokenPresent ? "CK_TRUE" : "CK_FALSE") +
               ", pSlotList=NULL_PTR, pulCount=&count",
               [&] { return module->C_GetSlotList(tokenPresent, nullptr, &count); });
        trace("PKCS11", "C_GetSlotList reported count=" + std::to_string(count));
        result.resize(count);
        CK_ULONG capacity = count;
        const CK_RV rv = invoke("C_GetSlotList",
            std::string("tokenPresent=") + (tokenPresent ? "CK_TRUE" : "CK_FALSE") +
            ", pSlotList=buffer[" + std::to_string(capacity) + "], pulCount=&count",
            [&] { return module->C_GetSlotList(tokenPresent, result.data(), &capacity); });
        if (rv == CKR_BUFFER_TOO_SMALL)
        {
            trace("PKCS11", "slot list changed between calls; retrying as required by the output-buffer convention");
            continue;
        }
        check(rv, CKR_OK, "C_GetSlotList(data)");
        result.resize(capacity);
        std::ostringstream listed;
        listed << "slot IDs=[";
        for (size_t index = 0; index < result.size(); ++index)
        {
            if (index != 0) listed << ", ";
            listed << result[index] << " (" << hexNumber(result[index]) << ")";
        }
        listed << ']';
        trace("PKCS11", listed.str());
        if (result.empty()) fail("module exposed no token-present slots");
        return result;
    }
}

static CK_TOKEN_INFO tokenInfo(Module& module, CK_SLOT_ID slot)
{
    CK_SLOT_INFO slotInfo{};
    callOk("C_GetSlotInfo", "slotID=" + std::to_string(slot) + ", pInfo=&slotInfo",
           [&] { return module->C_GetSlotInfo(slot, &slotInfo); });
    trace("SLOT", "slotID=" + std::to_string(slot) + ", description=\"" +
                  paddedText(slotInfo.slotDescription, sizeof(slotInfo.slotDescription)) +
                  "\", manufacturer=\"" + paddedText(slotInfo.manufacturerID, sizeof(slotInfo.manufacturerID)) +
                  "\", flags=" + hexNumber(slotInfo.flags));
    CK_TOKEN_INFO info{};
    callOk("C_GetTokenInfo", "slotID=" + std::to_string(slot) + ", pInfo=&tokenInfo",
           [&] { return module->C_GetTokenInfo(slot, &info); });
    trace("TOKEN", "slotID=" + std::to_string(slot) + ", label=\"" +
                   paddedText(info.label, sizeof(info.label)) + "\", manufacturer=\"" +
                   paddedText(info.manufacturerID, sizeof(info.manufacturerID)) + "\", model=\"" +
                   paddedText(reinterpret_cast<const unsigned char*>(info.model), sizeof(info.model)) +
                   "\", serial=\"" + paddedText(reinterpret_cast<const unsigned char*>(info.serialNumber),
                                                   sizeof(info.serialNumber)) +
                   "\", flags=" + hexNumber(info.flags));
    return info;
}

static CK_SLOT_ID selectSlot(Module& module, bool requireInitialized)
{
    const std::optional<CK_SLOT_ID> requestedSlot = configuredSlot();
    const std::string requestedLabel = environment("P11_TEST_TOKEN_LABEL");
    std::vector<CK_SLOT_ID> candidates;
    for (CK_SLOT_ID slot : slots(module, CK_TRUE))
    {
        const CK_TOKEN_INFO info = tokenInfo(module, slot);
        const bool initialized = (info.flags & CKF_TOKEN_INITIALIZED) != 0;
        const std::string label = paddedText(info.label, sizeof(info.label));
        if (requestedSlot && slot != *requestedSlot) continue;
        if (requireInitialized && !initialized) continue;
        if (requireInitialized && !requestedLabel.empty() && label != requestedLabel) continue;
        candidates.push_back(slot);
    }
    if (candidates.empty()) fail("no token matched the configured slot/label and initialization requirements");
    if (candidates.size() != 1)
        fail("multiple token-present slots matched; set P11_TEST_SLOT_ID explicitly before modifying a token");
    trace("TOKEN", "selected slotID=" + std::to_string(candidates.front()) +
                   " using standard C_GetSlotList/C_GetTokenInfo data");
    return candidates.front();
}

static CK_SESSION_HANDLE openSession(Module& module, CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    callOk("C_OpenSession", "slotID=" + std::to_string(slot) +
           ", flags=CKF_SERIAL_SESSION|CKF_RW_SESSION, pApplication=NULL_PTR, Notify=NULL_PTR, phSession=&session",
           [&] { return module->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                              nullptr, nullptr, &session); });
    trace("SESSION", "opened session handle=" + std::to_string(session));
    return session;
}

static const char* attributeName(CK_ATTRIBUTE_TYPE type)
{
    switch (type)
    {
        case CKA_CLASS: return "CKA_CLASS";
        case CKA_TOKEN: return "CKA_TOKEN";
        case CKA_PRIVATE: return "CKA_PRIVATE";
        case CKA_LABEL: return "CKA_LABEL";
        case CKA_VALUE: return "CKA_VALUE";
        case CKA_CERTIFICATE_TYPE: return "CKA_CERTIFICATE_TYPE";
        case CKA_CERTIFICATE_CATEGORY: return "CKA_CERTIFICATE_CATEGORY";
        case CKA_ISSUER: return "CKA_ISSUER";
        case CKA_SERIAL_NUMBER: return "CKA_SERIAL_NUMBER";
        case CKA_KEY_TYPE: return "CKA_KEY_TYPE";
        case CKA_ID: return "CKA_ID";
        case CKA_SENSITIVE: return "CKA_SENSITIVE";
        case CKA_ENCRYPT: return "CKA_ENCRYPT";
        case CKA_DECRYPT: return "CKA_DECRYPT";
        case CKA_SIGN: return "CKA_SIGN";
        case CKA_VERIFY: return "CKA_VERIFY";
        case CKA_MODULUS: return "CKA_MODULUS";
        case CKA_MODULUS_BITS: return "CKA_MODULUS_BITS";
        case CKA_PUBLIC_EXPONENT: return "CKA_PUBLIC_EXPONENT";
        case CKA_EXTRACTABLE: return "CKA_EXTRACTABLE";
        case CKA_SUBJECT: return "CKA_SUBJECT";
        default: return "CKA_<unknown>";
    }
}

static std::string objectClassName(CK_OBJECT_CLASS value)
{
    switch (value)
    {
        case CKO_DATA: return "CKO_DATA";
        case CKO_CERTIFICATE: return "CKO_CERTIFICATE";
        case CKO_PUBLIC_KEY: return "CKO_PUBLIC_KEY";
        case CKO_PRIVATE_KEY: return "CKO_PRIVATE_KEY";
        case CKO_SECRET_KEY: return "CKO_SECRET_KEY";
        default: return "CKO_<unknown>(" + hexNumber(value) + ")";
    }
}

static std::string keyTypeName(CK_KEY_TYPE value)
{
    if (value == CKK_RSA) return "CKK_RSA";
    return "CKK_<unknown>(" + hexNumber(value) + ")";
}

static std::string attributeValue(const CK_ATTRIBUTE& attribute)
{
    if (attribute.pValue == nullptr) return "NULL_PTR (query length)";
    if (attribute.type == CKA_CLASS && attribute.ulValueLen == sizeof(CK_OBJECT_CLASS))
        return objectClassName(*static_cast<const CK_OBJECT_CLASS*>(attribute.pValue));
    if (attribute.type == CKA_KEY_TYPE && attribute.ulValueLen == sizeof(CK_KEY_TYPE))
        return keyTypeName(*static_cast<const CK_KEY_TYPE*>(attribute.pValue));
    if (attribute.type == CKA_CERTIFICATE_TYPE && attribute.ulValueLen == sizeof(CK_CERTIFICATE_TYPE))
    {
        const CK_CERTIFICATE_TYPE value = *static_cast<const CK_CERTIFICATE_TYPE*>(attribute.pValue);
        return value == CKC_X_509 ? "CKC_X_509" : "CKC_<unknown>(" + hexNumber(value) + ")";
    }
    if (attribute.type == CKA_CERTIFICATE_CATEGORY && attribute.ulValueLen == sizeof(CK_CERTIFICATE_CATEGORY))
    {
        const CK_CERTIFICATE_CATEGORY value = *static_cast<const CK_CERTIFICATE_CATEGORY*>(attribute.pValue);
        if (value == CK_CERTIFICATE_CATEGORY_TOKEN_USER) return "CK_CERTIFICATE_CATEGORY_TOKEN_USER";
        if (value == CK_CERTIFICATE_CATEGORY_AUTHORITY) return "CK_CERTIFICATE_CATEGORY_AUTHORITY";
        if (value == CK_CERTIFICATE_CATEGORY_OTHER_ENTITY) return "CK_CERTIFICATE_CATEGORY_OTHER_ENTITY";
        return "CK_CERTIFICATE_CATEGORY_UNSPECIFIED";
    }
    if ((attribute.type == CKA_TOKEN || attribute.type == CKA_PRIVATE ||
         attribute.type == CKA_SENSITIVE || attribute.type == CKA_ENCRYPT ||
         attribute.type == CKA_DECRYPT || attribute.type == CKA_SIGN ||
         attribute.type == CKA_VERIFY || attribute.type == CKA_EXTRACTABLE) &&
        attribute.ulValueLen == sizeof(CK_BBOOL))
        return *static_cast<const CK_BBOOL*>(attribute.pValue) == CK_TRUE ? "CK_TRUE" : "CK_FALSE";
    if (attribute.type == CKA_MODULUS_BITS && attribute.ulValueLen == sizeof(CK_ULONG))
        return std::to_string(*static_cast<const CK_ULONG*>(attribute.pValue));
    if (attribute.type == CKA_LABEL)
        return "\"" + std::string(static_cast<const char*>(attribute.pValue), attribute.ulValueLen) + "\"";
    return "hex=" + hexBytes(attribute.pValue, attribute.ulValueLen);
}

static void traceTemplate(const std::string& name, const CK_ATTRIBUTE* attributes, CK_ULONG count)
{
    trace("TEMPLATE", name + " contains " + std::to_string(count) + " attributes");
    for (CK_ULONG index = 0; index < count; ++index)
    {
        const CK_ATTRIBUTE& attribute = attributes[index];
        trace("TEMPLATE", name + "[" + std::to_string(index) + "] " + attributeName(attribute.type) +
              " (type=" + hexNumber(attribute.type) + ", ulValueLen=" +
              std::to_string(attribute.ulValueLen) + ") = " + attributeValue(attribute));
    }
}

static const char* mechanismName(CK_MECHANISM_TYPE mechanism)
{
    switch (mechanism)
    {
        case CKM_RSA_PKCS_KEY_PAIR_GEN: return "CKM_RSA_PKCS_KEY_PAIR_GEN";
        case CKM_RSA_PKCS: return "CKM_RSA_PKCS";
        case CKM_SHA256_RSA_PKCS: return "CKM_SHA256_RSA_PKCS";
        case CKM_SHA256: return "CKM_SHA256";
        default: return "CKM_<unknown>";
    }
}

static void requireMechanism(Module& module, CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism,
                             CK_FLAGS requiredFlags, CK_ULONG keyBits = 0)
{
    CK_MECHANISM_INFO info{};
    callOk("C_GetMechanismInfo", "slotID=" + std::to_string(slot) + ", type=" +
           mechanismName(mechanism) + " (" + hexNumber(mechanism) + "), pInfo=&mechanismInfo",
           [&] { return module->C_GetMechanismInfo(slot, mechanism, &info); });
    trace("MECHANISM", std::string(mechanismName(mechanism)) + ": minKeySize=" +
                       std::to_string(info.ulMinKeySize) + ", maxKeySize=" +
                       std::to_string(info.ulMaxKeySize) + ", flags=" + hexNumber(info.flags));
    if ((info.flags & requiredFlags) != requiredFlags)
        fail(std::string(mechanismName(mechanism)) + " does not advertise required flags " +
             hexNumber(requiredFlags));
    if (keyBits != 0 && info.ulMinKeySize != 0 && keyBits < info.ulMinKeySize)
        fail(std::string(mechanismName(mechanism)) + " minimum key size exceeds requested size");
    if (keyBits != 0 && info.ulMaxKeySize != 0 && keyBits > info.ulMaxKeySize)
        fail(std::string(mechanismName(mechanism)) + " maximum key size is below requested size");
}

static Bytes attribute(Module& module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type)
{
    CK_ATTRIBUTE attr{type, nullptr, 0};
    traceTemplate("attribute length query", &attr, 1);
    callOk("C_GetAttributeValue", "hSession=" + std::to_string(session) + ", hObject=" +
           std::to_string(object) + ", pTemplate=&attribute, ulCount=1",
           [&] { return module->C_GetAttributeValue(session, object, &attr, 1); });
    if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION) fail("attribute is unavailable");
    Bytes value(attr.ulValueLen);
    attr.pValue = value.data();
    traceTemplate("attribute value query", &attr, 1);
    callOk("C_GetAttributeValue", "hSession=" + std::to_string(session) + ", hObject=" +
           std::to_string(object) + ", pTemplate=&attribute, ulCount=1",
           [&] { return module->C_GetAttributeValue(session, object, &attr, 1); });
    value.resize(attr.ulValueLen);
    trace("ATTRIBUTE", std::string(attributeName(type)) + " returned ulValueLen=" +
                       std::to_string(attr.ulValueLen) + ", hex=" + hexBytes(value.data(), value.size()));
    return value;
}

static CK_OBJECT_HANDLE findOne(Module& module, CK_SESSION_HANDLE session, std::vector<CK_ATTRIBUTE> query)
{
    traceTemplate("object search template", query.data(), static_cast<CK_ULONG>(query.size()));
    callOk("C_FindObjectsInit", "hSession=" + std::to_string(session) +
           ", pTemplate=searchTemplate, ulCount=" + std::to_string(query.size()),
           [&] { return module->C_FindObjectsInit(session, query.data(), static_cast<CK_ULONG>(query.size())); });
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    CK_RV rv = invoke("C_FindObjects", "hSession=" + std::to_string(session) +
                      ", phObject=&object, ulMaxObjectCount=1, pulObjectCount=&count",
                      [&] { return module->C_FindObjects(session, &object, 1, &count); });
    trace("OBJECT", "C_FindObjects returned count=" + std::to_string(count) +
                    (count == 1 ? ", handle=" + std::to_string(object) : ""));
    CK_OBJECT_HANDLE duplicate = CK_INVALID_HANDLE;
    CK_ULONG duplicateCount = 0;
    CK_RV duplicateRv = CKR_OK;
    if (rv == CKR_OK && count == 1)
    {
        duplicateRv = invoke("C_FindObjects", "hSession=" + std::to_string(session) +
                             ", phObject=&duplicate, ulMaxObjectCount=1, pulObjectCount=&duplicateCount",
                             [&] { return module->C_FindObjects(session, &duplicate, 1, &duplicateCount); });
        trace("OBJECT", "second C_FindObjects uniqueness check returned count=" +
                        std::to_string(duplicateCount));
    }
    CK_RV finalRv = invoke("C_FindObjectsFinal", "hSession=" + std::to_string(session),
                           [&] { return module->C_FindObjectsFinal(session); });
    check(rv, CKR_OK, "C_FindObjects");
    check(duplicateRv, CKR_OK, "C_FindObjects(uniqueness check)");
    check(finalRv, CKR_OK, "C_FindObjectsFinal");
    if (count != 1) fail("expected object was not found");
    if (duplicateCount != 0) fail("object search is ambiguous; choose a unique P11_TEST_OBJECT_ID_HEX");
    return object;
}

static Bytes sign(Module& module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, const Bytes& data)
{
    CK_MECHANISM mechanism{CKM_SHA256_RSA_PKCS, nullptr, 0};
    callOk("C_SignInit", "hSession=" + std::to_string(session) + ", pMechanism={mechanism=" +
           mechanismName(mechanism.mechanism) + ", pParameter=NULL_PTR, ulParameterLen=0}, hKey=" +
           std::to_string(key), [&] { return module->C_SignInit(session, &mechanism, key); });
    CK_ULONG length = 0;
    callOk("C_Sign", "hSession=" + std::to_string(session) + ", pData=hex:" +
           hexBytes(data.data(), data.size()) + ", ulDataLen=" + std::to_string(data.size()) +
           ", pSignature=NULL_PTR, pulSignatureLen=&length",
           [&] { return module->C_Sign(session, const_cast<CK_BYTE_PTR>(data.data()),
                                       static_cast<CK_ULONG>(data.size()), nullptr, &length); });
    trace("OUTPUT", "C_Sign length query returned " + std::to_string(length) + " bytes");
    Bytes signature(length);
    callOk("C_Sign", "hSession=" + std::to_string(session) + ", pData=hex:" +
           hexBytes(data.data(), data.size()) + ", ulDataLen=" + std::to_string(data.size()) +
           ", pSignature=buffer[" + std::to_string(signature.size()) + "], pulSignatureLen=&length",
           [&] { return module->C_Sign(session, const_cast<CK_BYTE_PTR>(data.data()),
                                       static_cast<CK_ULONG>(data.size()), signature.data(), &length); });
    signature.resize(length);
    trace("OUTPUT", "signature ulSignatureLen=" + std::to_string(signature.size()) +
                    ", hex=" + hexBytes(signature.data(), signature.size()));
    return signature;
}

static Bytes digest(Module& module, CK_SESSION_HANDLE session, const Bytes& data)
{
    CK_MECHANISM mechanism{CKM_SHA256, nullptr, 0};
    callOk("C_DigestInit", "hSession=" + std::to_string(session) + ", pMechanism={mechanism=" +
           mechanismName(mechanism.mechanism) + ", pParameter=NULL_PTR, ulParameterLen=0}",
           [&] { return module->C_DigestInit(session, &mechanism); });
    CK_ULONG length = 0;
    callOk("C_Digest", "hSession=" + std::to_string(session) + ", pData=hex:" +
           hexBytes(data.data(), data.size()) + ", ulDataLen=" + std::to_string(data.size()) +
           ", pDigest=NULL_PTR, pulDigestLen=&length",
           [&] { return module->C_Digest(session, const_cast<CK_BYTE_PTR>(data.data()),
                                         static_cast<CK_ULONG>(data.size()), nullptr, &length); });
    trace("OUTPUT", "C_Digest length query returned " + std::to_string(length) + " bytes");
    Bytes result(length);
    callOk("C_Digest", "hSession=" + std::to_string(session) + ", pData=hex:" +
           hexBytes(data.data(), data.size()) + ", ulDataLen=" + std::to_string(data.size()) +
           ", pDigest=buffer[" + std::to_string(result.size()) + "], pulDigestLen=&length",
           [&] { return module->C_Digest(session, const_cast<CK_BYTE_PTR>(data.data()),
                                         static_cast<CK_ULONG>(data.size()), result.data(), &length); });
    result.resize(length);
    if (result.size() != 32) fail("SHA-256 returned an unexpected size");
    trace("OUTPUT", "digest ulDigestLen=" + std::to_string(result.size()) +
                    ", hex=" + hexBytes(result.data(), result.size()));
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

static std::string configuredKeyLabel()
{
    const std::string value = environment("P11_TEST_KEY_LABEL");
    return value.empty() ? "portable-ci-rsa" : value;
}

static std::string configuredTokenLabel()
{
    const std::string value = environment("P11_TEST_TOKEN_LABEL");
    return value.empty() ? "portable-ci-token" : value;
}

static void login(Module& module, CK_SESSION_HANDLE session, CK_USER_TYPE userType, const std::string& pin)
{
    const char* userName = userType == CKU_SO ? "CKU_SO" : "CKU_USER";
    callOk("C_Login", "hSession=" + std::to_string(session) + ", userType=" + userName +
           ", pPin=<redacted>, ulPinLen=" + std::to_string(pin.size()),
           [&] { return module->C_Login(session, userType,
                       reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(pin.data())),
                       static_cast<CK_ULONG>(pin.size())); });
}

static void logout(Module& module, CK_SESSION_HANDLE session, const char* identity)
{
    callOk("C_Logout", "hSession=" + std::to_string(session) + " (current identity=" + identity + ")",
           [&] { return module->C_Logout(session); });
}

static void closeSession(Module& module, CK_SESSION_HANDLE session)
{
    callOk("C_CloseSession", "hSession=" + std::to_string(session),
           [&] { return module->C_CloseSession(session); });
}

static void prepare(const fs::path& modulePath, const fs::path& work)
{
    const bool initializeToken = environmentYes("P11_TEST_INITIALIZE_TOKEN");
    const std::string userPin = environment("P11_TEST_USER_PIN", true);
    const std::string soPin = initializeToken ? environment("P11_TEST_SO_PIN", true) : std::string();
    const std::string tokenLabel = configuredTokenLabel();
    const std::string keyLabel = configuredKeyLabel();
    const Bytes objectId = configuredObjectId();
    trace("CONFIG", std::string("initializeToken=") + (initializeToken ? "YES" : "NO") +
                    ", requestedSlot=" + (configuredSlot() ? std::to_string(*configuredSlot()) : "auto") +
                    ", tokenLabel=\"" + tokenLabel + "\", keyLabel=\"" + keyLabel +
                    "\", objectIdHex=" + hexBytes(objectId.data(), objectId.size()) +
                    ", soPin=" + (initializeToken ? "<redacted,length=" + std::to_string(soPin.size()) + ">" : "unused") +
                    ", userPin=<redacted,length=" + std::to_string(userPin.size()) + ">");
    fs::create_directories(work);
    fs::current_path(work);
    trace("FILESYSTEM", "scenario directory=" + work.string() + ", process current directory changed intentionally");
    Module module(modulePath);
    CK_SLOT_ID slot = selectSlot(module, !initializeToken);

    if (initializeToken)
    {
        if (tokenLabel.size() > 32) fail("P11_TEST_TOKEN_LABEL exceeds the standard 32-byte token label field");
        std::array<CK_UTF8CHAR, 32> label{};
        label.fill(' ');
        std::copy(tokenLabel.begin(), tokenLabel.end(), label.begin());
        trace("WARNING", "explicit destructive initialization enabled; C_InitToken may erase every object on slot " +
                         std::to_string(slot));
        callOk("C_InitToken", "slotID=" + std::to_string(slot) +
               ", pPin=<redacted>, ulPinLen=" + std::to_string(soPin.size()) +
               ", pLabel=32-byte blank-padded \"" + tokenLabel + "\"",
               [&] { return module->C_InitToken(slot,
                                 reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(soPin.data())),
                                 static_cast<CK_ULONG>(soPin.size()), label.data()); });
        (void)tokenInfo(module, slot);
    }

    CK_SESSION_HANDLE session = openSession(module, slot);
    if (initializeToken)
    {
        login(module, session, CKU_SO, soPin);
        callOk("C_InitPIN", "hSession=" + std::to_string(session) +
               ", pPin=<redacted>, ulPinLen=" + std::to_string(userPin.size()),
               [&] { return module->C_InitPIN(session,
                                 reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(userPin.data())),
                                 static_cast<CK_ULONG>(userPin.size())); });
        logout(module, session, "CKU_SO");
    }
    login(module, session, CKU_USER, userPin);

    requireMechanism(module, slot, CKM_RSA_PKCS_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR, 2048);
    requireMechanism(module, slot, CKM_SHA256_RSA_PKCS, CKF_SIGN, 2048);
    requireMechanism(module, slot, CKM_SHA256, CKF_DIGEST);

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
        {CKA_ENCRYPT, &no, sizeof(no)},
        {CKA_VERIFY, &yes, sizeof(yes)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent)},
        {CKA_LABEL, const_cast<char*>(keyLabel.data()), static_cast<CK_ULONG>(keyLabel.size())},
        {CKA_ID, const_cast<unsigned char*>(objectId.data()), static_cast<CK_ULONG>(objectId.size())}
    };
    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &yes, sizeof(yes)},
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &yes, sizeof(yes)},
        {CKA_DECRYPT, &no, sizeof(no)},
        {CKA_SIGN, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &no, sizeof(no)},
        {CKA_LABEL, const_cast<char*>(keyLabel.data()), static_cast<CK_ULONG>(keyLabel.size())},
        {CKA_ID, const_cast<unsigned char*>(objectId.data()), static_cast<CK_ULONG>(objectId.size())}
    };
    CK_MECHANISM mechanism{CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
    const CK_ULONG publicCount = sizeof(publicTemplate) / sizeof(publicTemplate[0]);
    const CK_ULONG privateCount = sizeof(privateTemplate) / sizeof(privateTemplate[0]);
    traceTemplate("RSA public-key generation template", publicTemplate, publicCount);
    traceTemplate("RSA private-key generation template", privateTemplate, privateCount);
    callOk("C_GenerateKeyPair", "hSession=" + std::to_string(session) +
           ", pMechanism={mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN, pParameter=NULL_PTR, ulParameterLen=0}" +
           ", pPublicKeyTemplate=publicTemplate, ulPublicKeyAttributeCount=" + std::to_string(publicCount) +
           ", pPrivateKeyTemplate=privateTemplate, ulPrivateKeyAttributeCount=" + std::to_string(privateCount) +
           ", phPublicKey=&publicKey, phPrivateKey=&privateKey",
           [&] { return module->C_GenerateKeyPair(session, &mechanism,
                            publicTemplate, publicCount, privateTemplate, privateCount,
                            &publicKey, &privateKey); });
    trace("OBJECT", "generated publicKey handle=" + std::to_string(publicKey) +
                    ", privateKey handle=" + std::to_string(privateKey));

    writePem(work / "request.pem", "CERTIFICATE REQUEST", buildCsr(module, session, publicKey, privateKey));
    trace("FILESYSTEM", "wrote PKCS#10 CSR: " + (work / "request.pem").string());
    logout(module, session, "CKU_USER");
    closeSession(module, session);
    std::cout << "PKCS #11 token initialized, RSA-2048 key generated, CSR written\n";
}

static void finish(const fs::path& modulePath, const fs::path& work,
                   const fs::path& leafPath, const fs::path& caPath,
                   const fs::path& payloadPath, const fs::path& cmsPath)
{
    const std::string userPin = environment("P11_TEST_USER_PIN", true);
    const Bytes objectId = configuredObjectId();
    trace("CONFIG", "finish phase tokenLabel=\"" + configuredTokenLabel() +
                    "\", objectIdHex=" + hexBytes(objectId.data(), objectId.size()) +
                    ", userPin=<redacted,length=" + std::to_string(userPin.size()) + ">");
    fs::current_path(work);
    const Bytes leaf = readFile(leafPath);
    const Bytes ca = readFile(caPath);
    const Bytes payload = readFile(payloadPath);
    trace("FILESYSTEM", "read leaf DER bytes=" + std::to_string(leaf.size()) +
                        ", CA DER bytes=" + std::to_string(ca.size()) +
                        ", payload bytes=" + std::to_string(payload.size()));
    const CertificateFields fields = certificateFields(leaf);
    Module module(modulePath);
    const CK_SLOT_ID slot = selectSlot(module, true);
    requireMechanism(module, slot, CKM_SHA256_RSA_PKCS, CKF_SIGN, 2048);
    requireMechanism(module, slot, CKM_SHA256, CKF_DIGEST);
    CK_SESSION_HANDLE session = openSession(module, slot);
    login(module, session, CKU_USER, userPin);

    CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsa = CKK_RSA;
    std::vector<CK_ATTRIBUTE> privateQuery = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &rsa, sizeof(rsa)},
        {CKA_ID, const_cast<unsigned char*>(objectId.data()), static_cast<CK_ULONG>(objectId.size())}
    };
    CK_OBJECT_HANDLE privateKey = findOne(module, session, privateQuery);

    CK_OBJECT_CLASS certificateClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certificateType = CKC_X_509;
    CK_CERTIFICATE_CATEGORY certificateCategory = CK_CERTIFICATE_CATEGORY_TOKEN_USER;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    const char certificateLabel[] = "portable-ci-certificate";
    CK_ATTRIBUTE certificateTemplate[] = {
        {CKA_CLASS, &certificateClass, sizeof(certificateClass)},
        {CKA_CERTIFICATE_TYPE, &certificateType, sizeof(certificateType)},
        {CKA_CERTIFICATE_CATEGORY, &certificateCategory, sizeof(certificateCategory)},
        {CKA_TOKEN, &yes, sizeof(yes)},
        {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_LABEL, const_cast<char*>(certificateLabel), sizeof(certificateLabel) - 1},
        {CKA_ID, const_cast<unsigned char*>(objectId.data()), static_cast<CK_ULONG>(objectId.size())},
        {CKA_VALUE, const_cast<unsigned char*>(leaf.data()), static_cast<CK_ULONG>(leaf.size())},
        {CKA_SUBJECT, const_cast<unsigned char*>(fields.subject.data()), static_cast<CK_ULONG>(fields.subject.size())},
        {CKA_ISSUER, const_cast<unsigned char*>(fields.issuer.data()), static_cast<CK_ULONG>(fields.issuer.size())},
        {CKA_SERIAL_NUMBER, const_cast<unsigned char*>(fields.serial.data()), static_cast<CK_ULONG>(fields.serial.size())}
    };
    CK_OBJECT_HANDLE certificate = CK_INVALID_HANDLE;
    const CK_ULONG certificateCount = sizeof(certificateTemplate) / sizeof(certificateTemplate[0]);
    traceTemplate("X.509 certificate creation template", certificateTemplate, certificateCount);
    callOk("C_CreateObject", "hSession=" + std::to_string(session) +
           ", pTemplate=certificateTemplate, ulCount=" + std::to_string(certificateCount) +
           ", phObject=&certificate",
           [&] { return module->C_CreateObject(session, certificateTemplate, certificateCount, &certificate); });
    trace("OBJECT", "created certificate handle=" + std::to_string(certificate));

    std::vector<CK_ATTRIBUTE> certificateQuery = {
        {CKA_CLASS, &certificateClass, sizeof(certificateClass)},
        {CKA_ID, const_cast<unsigned char*>(objectId.data()), static_cast<CK_ULONG>(objectId.size())}
    };
    (void)findOne(module, session, certificateQuery);
    writeFile(cmsPath, buildCms(module, session, privateKey, leaf, ca, payload));
    trace("FILESYSTEM", "wrote detached CMS DER: " + cmsPath.string());

    logout(module, session, "CKU_USER");
    closeSession(module, session);
    std::cout << "Certificate imported, token key reopened, detached CMS written\n";
}

int main(int argc, char** argv)
{
    try
    {
        if (argc == 4 && std::string(argv[1]) == "prepare")
        {
            prepare(fs::absolute(argv[2]), fs::absolute(argv[3]));
            return 0;
        }
        if (argc == 8 && std::string(argv[1]) == "finish")
        {
            finish(fs::absolute(argv[2]), fs::absolute(argv[3]), fs::absolute(argv[4]),
                   fs::absolute(argv[5]), fs::absolute(argv[6]), fs::absolute(argv[7]));
            return 0;
        }
        std::cerr << "usage:\n"
                  << "  portable-token-e2e prepare <module> <work>\n"
                  << "  portable-token-e2e finish <module> <work> <leaf.der> <ca.der> <payload> <cms.der>\n"
                  << "environment:\n"
                  << "  P11_TEST_USER_PIN=<required secret>\n"
                  << "  P11_TEST_INITIALIZE_TOKEN=YES|NO (default NO)\n"
                  << "  P11_TEST_SO_PIN=<required only when initialization is YES>\n"
                  << "  P11_TEST_SLOT_ID=<optional decimal or 0x-prefixed slot ID>\n"
                  << "  P11_TEST_TOKEN_LABEL=<optional exact token label>\n"
                  << "  P11_TEST_KEY_LABEL=<optional generated-key label>\n"
                  << "  P11_TEST_OBJECT_ID_HEX=<optional even-length hex CKA_ID>\n";
        return 2;
    }
    catch (const std::exception& error)
    {
        std::cerr << "portable token E2E failure: " << error.what() << '\n';
        return 1;
    }
}
