/*
 * Dependency-light portable package integration test.
 *
 * This client deliberately talks to the downloaded module through PKCS #11
 * only.  It does not link to SoftHSM or OpenSSL.  OpenSSL CLI is used by the
 * surrounding script as an independent CSR, CA, certificate, and CMS parser.
 */

#include "pkcs11.h"
#include "rutoken.h"

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
static const char kGostKeyLabel[] = "portable-ci-gost2012-256";
static const unsigned char kGostObjectIdSuffix = 0x47; // ASCII 'G'
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

static bool functionExcluded(const char* operation)
{
    const char* configured = std::getenv("P11_TEST_EXCLUDE_FUNCTIONS");
    if (configured == nullptr) return false;
    std::string name;
    for (const char character : std::string(configured) + ',')
    {
        if (character == ',' || character == ';' || std::isspace(static_cast<unsigned char>(character)))
        {
            if (name == operation) return true;
            name.clear();
        }
        else
        {
            name.push_back(character);
        }
    }
    return false;
}

template<typename Function>
static CK_RV invoke(const char* operation, const std::string& parameters, Function function)
{
    if (functionExcluded(operation))
    {
        trace("SAFETY", std::string("blocked excluded PKCS #11 function before invocation: ") + operation);
        fail(std::string(operation) + " is excluded by P11_TEST_EXCLUDE_FUNCTIONS");
    }
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

static void checkAttributeReadRejected(CK_RV rv, const char* operation)
{
    if (rv == CKR_OK)
        fail(std::string(operation) + " unexpectedly exposed private key material");

    trace("PORTABILITY", std::string(operation) + " was rejected with " + rvName(rv) +
                         " (" + hexNumber(rv) + "); the exact error is vendor-specific");
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

static Bytes gostObjectId(const Bytes& rsaObjectId)
{
    Bytes result = rsaObjectId;
    result.push_back(kGostObjectIdSuffix);
    return result;
}

static Bytes bytesFromHex(const std::string& encoded)
{
    if (encoded.size() % 2 != 0) fail("hex string must contain an even number of digits");
    Bytes result;
    result.reserve(encoded.size() / 2);
    for (size_t offset = 0; offset < encoded.size(); offset += 2)
    {
        const std::string byte = encoded.substr(offset, 2);
        char* end = nullptr;
        const unsigned long value = std::strtoul(byte.c_str(), &end, 16);
        if (end == nullptr || *end != '\0' || value > 0xff) fail("invalid hexadecimal test value");
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
    if (value > static_cast<unsigned long long>((std::numeric_limits<CK_SLOT_ID>::max)()))
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

    // Vendor extensions are reached by symbol, the way the applications this
    // profile targets reach them.
    void* symbol(const char* name) const
    {
#ifdef _WIN32
        return reinterpret_cast<void*>(GetProcAddress(handle_, name));
#else
        return dlsym(handle_, name);
#endif
    }

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

static CK_SLOT_ID selectSlotForInitialization(Module& module, const std::string& targetLabel)
{
    const std::optional<CK_SLOT_ID> requestedSlot = configuredSlot();
    std::vector<CK_SLOT_ID> existingTarget;
    std::vector<CK_SLOT_ID> uninitialized;
    const std::vector<CK_SLOT_ID> present = slots(module, CK_TRUE);
    for (CK_SLOT_ID slot : present)
    {
        if (requestedSlot && slot != *requestedSlot) continue;
        const CK_TOKEN_INFO info = tokenInfo(module, slot);
        if ((info.flags & CKF_TOKEN_INITIALIZED) != 0)
        {
            if (paddedText(info.label, sizeof(info.label)) == targetLabel)
                existingTarget.push_back(slot);
        }
        else
        {
            uninitialized.push_back(slot);
        }
    }
    if (existingTarget.size() == 1)
    {
        trace("TOKEN", "selected the existing test token for deterministic reinitialization");
        return existingTarget.front();
    }
    if (existingTarget.empty() && uninitialized.size() == 1)
    {
        trace("TOKEN", "selected the sole uninitialized slot for first-time initialization");
        return uninitialized.front();
    }
    if (!requestedSlot && existingTarget.empty() && uninitialized.empty() && present.size() == 1)
    {
        trace("TOKEN", "selected the sole presented token for explicit destructive reinitialization; its compatibility-profile label may mask the stored label");
        return present.front();
    }
    fail("initialization target is ambiguous; set P11_TEST_SLOT_ID or remove duplicate test-label tokens");
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
        case CKA_VALUE_LEN: return "CKA_VALUE_LEN";
        case CKA_CERTIFICATE_TYPE: return "CKA_CERTIFICATE_TYPE";
        case CKA_CERTIFICATE_CATEGORY: return "CKA_CERTIFICATE_CATEGORY";
        case CKA_ISSUER: return "CKA_ISSUER";
        case CKA_SERIAL_NUMBER: return "CKA_SERIAL_NUMBER";
        case CKA_KEY_TYPE: return "CKA_KEY_TYPE";
        case CKA_ID: return "CKA_ID";
        case CKA_SENSITIVE: return "CKA_SENSITIVE";
        case CKA_ENCRYPT: return "CKA_ENCRYPT";
        case CKA_DECRYPT: return "CKA_DECRYPT";
        case CKA_DERIVE: return "CKA_DERIVE";
        case CKA_SIGN: return "CKA_SIGN";
        case CKA_VERIFY: return "CKA_VERIFY";
        case CKA_MODULUS: return "CKA_MODULUS";
        case CKA_MODULUS_BITS: return "CKA_MODULUS_BITS";
        case CKA_PUBLIC_EXPONENT: return "CKA_PUBLIC_EXPONENT";
        case CKA_PRIVATE_EXPONENT: return "CKA_PRIVATE_EXPONENT";
        case CKA_PRIME_1: return "CKA_PRIME_1";
        case CKA_PRIME_2: return "CKA_PRIME_2";
        case CKA_EXPONENT_1: return "CKA_EXPONENT_1";
        case CKA_EXPONENT_2: return "CKA_EXPONENT_2";
        case CKA_COEFFICIENT: return "CKA_COEFFICIENT";
        case CKA_EXTRACTABLE: return "CKA_EXTRACTABLE";
        case CKA_ALWAYS_SENSITIVE: return "CKA_ALWAYS_SENSITIVE";
        case CKA_NEVER_EXTRACTABLE: return "CKA_NEVER_EXTRACTABLE";
        case CKA_LOCAL: return "CKA_LOCAL";
        case CKA_GOSTR3410_PARAMS: return "CKA_GOSTR3410_PARAMS";
        case CKA_GOSTR3411_PARAMS: return "CKA_GOSTR3411_PARAMS";
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
    if (value == CKK_GOSTR3410) return "CKK_GOSTR3410";
    if (value == CKK_MAGMA_TWIN_KEY) return "CKK_MAGMA_TWIN_KEY";
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
         attribute.type == CKA_VERIFY || attribute.type == CKA_EXTRACTABLE ||
         attribute.type == CKA_LOCAL || attribute.type == CKA_ALWAYS_SENSITIVE ||
         attribute.type == CKA_NEVER_EXTRACTABLE) &&
        attribute.ulValueLen == sizeof(CK_BBOOL))
        return *static_cast<const CK_BBOOL*>(attribute.pValue) == CK_TRUE ? "CK_TRUE" : "CK_FALSE";
    if (attribute.type == CKA_MODULUS_BITS && attribute.ulValueLen == sizeof(CK_ULONG))
        return std::to_string(*static_cast<const CK_ULONG*>(attribute.pValue));
    if (attribute.type == CKA_LABEL)
        return "\"" + std::string(static_cast<const char*>(attribute.pValue), attribute.ulValueLen) + "\"";
    return "hex=" + hexBytes(attribute.pValue, attribute.ulValueLen);
}

static bool privateKeyMaterial(CK_ATTRIBUTE_TYPE type)
{
    return type == CKA_VALUE || type == CKA_PRIVATE_EXPONENT || type == CKA_PRIME_1 ||
           type == CKA_PRIME_2 || type == CKA_EXPONENT_1 || type == CKA_EXPONENT_2 ||
           type == CKA_COEFFICIENT;
}

static void traceTemplate(const std::string& name, const CK_ATTRIBUTE* attributes, CK_ULONG count)
{
    bool privateKeyTemplate = false;
    for (CK_ULONG index = 0; index < count; ++index)
        if (attributes[index].type == CKA_CLASS && attributes[index].pValue != nullptr &&
            attributes[index].ulValueLen == sizeof(CK_OBJECT_CLASS) &&
            *static_cast<const CK_OBJECT_CLASS*>(attributes[index].pValue) == CKO_PRIVATE_KEY)
            privateKeyTemplate = true;
    trace("TEMPLATE", name + " contains " + std::to_string(count) + " attributes");
    for (CK_ULONG index = 0; index < count; ++index)
    {
        const CK_ATTRIBUTE& attribute = attributes[index];
        trace("TEMPLATE", name + "[" + std::to_string(index) + "] " + attributeName(attribute.type) +
              " (type=" + hexNumber(attribute.type) + ", ulValueLen=" +
              std::to_string(attribute.ulValueLen) + ") = " +
              (privateKeyTemplate && privateKeyMaterial(attribute.type) && attribute.pValue != nullptr
                   ? "<redacted private key material>" : attributeValue(attribute)));
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
        case CKM_GOSTR3410_KEY_PAIR_GEN: return "CKM_GOSTR3410_KEY_PAIR_GEN";
        case CKM_GOSTR3410: return "CKM_GOSTR3410";
        case CKM_GOSTR3410_WITH_GOSTR3411_2012_256: return "CKM_GOSTR3410_WITH_GOSTR3411_2012_256";
        case CKM_GOSTR3411_2012_256: return "CKM_GOSTR3411_2012_256";
        case CKM_GOST_KEG: return "CKM_GOST_KEG";
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

static Bytes attribute(Module& module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                       CK_ATTRIBUTE_TYPE type, bool redact = false)
{
    CK_ATTRIBUTE attr{type, nullptr, 0};
    traceTemplate("attribute length query", &attr, 1);
    callOk("C_GetAttributeValue", "hSession=" + std::to_string(session) + ", hObject=" +
           std::to_string(object) + ", pTemplate=&attribute, ulCount=1",
           [&] { return module->C_GetAttributeValue(session, object, &attr, 1); });
    if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION) fail("attribute is unavailable");
    Bytes value(attr.ulValueLen);
    attr.pValue = value.data();
    callOk("C_GetAttributeValue", "hSession=" + std::to_string(session) + ", hObject=" +
           std::to_string(object) + ", pTemplate=&attribute, ulCount=1",
           [&] { return module->C_GetAttributeValue(session, object, &attr, 1); });
    value.resize(attr.ulValueLen);
    trace("ATTRIBUTE", std::string(attributeName(type)) + " returned ulValueLen=" +
                       std::to_string(attr.ulValueLen) +
                       (redact ? ", value=<redacted private key material>"
                               : ", value=" + attributeValue(attr)));
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

static Bytes digest(Module& module, CK_SESSION_HANDLE session,
                    CK_MECHANISM_TYPE mechanismType, const Bytes& data, size_t expectedSize)
{
    CK_MECHANISM mechanism{mechanismType, nullptr, 0};
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
    if (result.size() != expectedSize)
        fail(std::string(mechanismName(mechanismType)) + " returned an unexpected size");
    trace("OUTPUT", "digest ulDigestLen=" + std::to_string(result.size()) +
                    ", hex=" + hexBytes(result.data(), result.size()));
    return result;
}

static Bytes digestMultipart(Module& module, CK_SESSION_HANDLE session,
                             CK_MECHANISM_TYPE mechanismType, const Bytes& data,
                             const std::vector<size_t>& partSizes, size_t expectedSize)
{
    CK_MECHANISM mechanism{mechanismType, nullptr, 0};
    callOk("C_DigestInit", "hSession=" + std::to_string(session) + ", pMechanism={mechanism=" +
           std::string(mechanismName(mechanism.mechanism)) + ", pParameter=NULL_PTR, ulParameterLen=0}",
           [&] { return module->C_DigestInit(session, &mechanism); });

    size_t offset = 0;
    for (size_t partSize : partSizes)
    {
        if (partSize > data.size() - offset) fail("multipart digest split exceeds input size");
        callOk("C_DigestUpdate", "hSession=" + std::to_string(session) + ", pPart=hex:" +
               hexBytes(data.data() + offset, partSize) + ", ulPartLen=" + std::to_string(partSize),
               [&] { return module->C_DigestUpdate(session,
                                  const_cast<CK_BYTE_PTR>(data.data() + offset),
                                  static_cast<CK_ULONG>(partSize)); });
        offset += partSize;
    }
    if (offset != data.size()) fail("multipart digest split does not cover all input bytes");

    CK_ULONG length = 0;
    callOk("C_DigestFinal", "hSession=" + std::to_string(session) +
           ", pDigest=NULL_PTR, pulDigestLen=&length",
           [&] { return module->C_DigestFinal(session, nullptr, &length); });
    trace("OUTPUT", "C_DigestFinal length query returned " + std::to_string(length) + " bytes");
    Bytes result(length);
    callOk("C_DigestFinal", "hSession=" + std::to_string(session) + ", pDigest=buffer[" +
           std::to_string(result.size()) + "], pulDigestLen=&length",
           [&] { return module->C_DigestFinal(session, result.data(), &length); });
    result.resize(length);
    if (result.size() != expectedSize)
        fail(std::string(mechanismName(mechanismType)) + " multipart digest returned an unexpected size");
    trace("OUTPUT", "multipart digest ulDigestLen=" + std::to_string(result.size()) +
                    ", hex=" + hexBytes(result.data(), result.size()));
    return result;
}

static void verifyStreebog256(Module& module, CK_SESSION_HANDLE session)
{
    // RFC 6986 section 10.1.2, message M1 and its 256-bit result.  The RFC
    // prints vectors as a_(n-1)..a_0; these are the corresponding octets in
    // normal byte-API order (the conventional published Streebog vector).
    const Bytes message = bytesFromHex(
        "3031323334353637383930313233343536373839303132333435363738393031"
        "32333435363738393031323334353637383930313233343536373839303132");
    const Bytes expected = bytesFromHex(
        "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");

    CK_BYTE invalidParameter = 0;
    CK_MECHANISM invalidMechanism{CKM_GOSTR3411_2012_256, &invalidParameter, 1};
    check(invoke("C_DigestInit", "hSession=" + std::to_string(session) +
                 ", pMechanism={mechanism=CKM_GOSTR3411_2012_256, pParameter=byte[1], ulParameterLen=1}",
                 [&] { return module->C_DigestInit(session, &invalidMechanism); }),
          CKR_MECHANISM_PARAM_INVALID, "C_DigestInit(non-empty Streebog parameters)");
    trace("STANDARD", "CKM_GOSTR3411_2012_256 rejects parameters as required by its parameterless definition");

    const Bytes oneShot = digest(module, session, CKM_GOSTR3411_2012_256,
                                 message, expected.size());
    if (oneShot != expected)
        fail("one-shot GOST R 34.11-2012/256 digest does not match RFC 6986");
    trace("REFERENCE", "one-shot GOST R 34.11-2012/256 matches RFC 6986 section 10.1.2");

    const Bytes multipart = digestMultipart(module, session, CKM_GOSTR3411_2012_256,
                                            message, {1, 7, 13, 42}, expected.size());
    if (multipart != expected)
        fail("multipart GOST R 34.11-2012/256 digest does not match RFC 6986");
    trace("REFERENCE", "multipart GOST R 34.11-2012/256 matches RFC 6986 section 10.1.2");
}

static CK_ULONG ulongAttribute(Module& module, CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type)
{
    const Bytes encoded = attribute(module, session, object, type);
    if (encoded.size() != sizeof(CK_ULONG))
        fail(std::string(attributeName(type)) + " has an unexpected size");
    CK_ULONG value = 0;
    std::memcpy(&value, encoded.data(), sizeof(value));
    return value;
}

struct GOST2012KeyPair
{
    CK_OBJECT_HANDLE publicKey;
    CK_OBJECT_HANDLE privateKey;
    Bytes publicPoint;
};

static GOST2012KeyPair verifyGOST2012KeyGeneration(Module& module, CK_SESSION_HANDLE session,
                                                    const Bytes& baseObjectId)
{
    CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_GOSTR3410;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    const std::string label = kGostKeyLabel;
    Bytes objectId = gostObjectId(baseObjectId);

    // The CryptoPro-A parameter set is deliberately used here because the
    // same standard template is accepted by rtpkcs11ecp.  Together with the
    // Streebog-256 digest parameter it denotes a 2012/256 key pair.
    Bytes curve = bytesFromHex("06072a850302022301");       // 1.2.643.2.2.35.1
    Bytes digestParam = bytesFromHex("06082a85030701010202"); // 1.2.643.7.1.1.2.2
    CK_ATTRIBUTE publicTemplate[] = {
        {CKA_CLASS, &publicClass, sizeof(publicClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &yes, sizeof(yes)},
        {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_VERIFY, &yes, sizeof(yes)},
        {CKA_GOSTR3410_PARAMS, curve.data(), static_cast<CK_ULONG>(curve.size())},
        {CKA_GOSTR3411_PARAMS, digestParam.data(), static_cast<CK_ULONG>(digestParam.size())},
        {CKA_LABEL, const_cast<char*>(label.data()), static_cast<CK_ULONG>(label.size())},
        {CKA_ID, objectId.data(), static_cast<CK_ULONG>(objectId.size())}
    };
    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &yes, sizeof(yes)},
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &yes, sizeof(yes)},
        {CKA_SIGN, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &no, sizeof(no)},
        {CKA_GOSTR3410_PARAMS, curve.data(), static_cast<CK_ULONG>(curve.size())},
        {CKA_GOSTR3411_PARAMS, digestParam.data(), static_cast<CK_ULONG>(digestParam.size())},
        {CKA_LABEL, const_cast<char*>(label.data()), static_cast<CK_ULONG>(label.size())},
        {CKA_ID, objectId.data(), static_cast<CK_ULONG>(objectId.size())}
    };
    const CK_ULONG publicCount = sizeof(publicTemplate) / sizeof(publicTemplate[0]);
    const CK_ULONG privateCount = sizeof(privateTemplate) / sizeof(privateTemplate[0]);
    traceTemplate("GOST R 34.10-2012/256 public-key generation template", publicTemplate, publicCount);
    traceTemplate("GOST R 34.10-2012/256 private-key generation template", privateTemplate, privateCount);

    CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
    CK_BYTE invalidParameter = 0;
    CK_MECHANISM invalidMechanism{CKM_GOSTR3410_KEY_PAIR_GEN, &invalidParameter, 1};
    check(invoke("C_GenerateKeyPair", "hSession=" + std::to_string(session) +
                 ", pMechanism={mechanism=CKM_GOSTR3410_KEY_PAIR_GEN, pParameter=byte[1], ulParameterLen=1}" +
                 ", pPublicKeyTemplate=publicTemplate, ulPublicKeyAttributeCount=" + std::to_string(publicCount) +
                 ", pPrivateKeyTemplate=privateTemplate, ulPrivateKeyAttributeCount=" + std::to_string(privateCount),
                 [&] { return module->C_GenerateKeyPair(session, &invalidMechanism,
                                  publicTemplate, publicCount, privateTemplate, privateCount,
                                  &publicKey, &privateKey); }),
          CKR_MECHANISM_PARAM_INVALID, "C_GenerateKeyPair(non-empty GOST parameters)");
    trace("STANDARD", "CKM_GOSTR3410_KEY_PAIR_GEN rejects non-empty mechanism parameters");

    CK_MECHANISM mechanism{CKM_GOSTR3410_KEY_PAIR_GEN, nullptr, 0};
    callOk("C_GenerateKeyPair", "hSession=" + std::to_string(session) +
           ", pMechanism={mechanism=CKM_GOSTR3410_KEY_PAIR_GEN, pParameter=NULL_PTR, ulParameterLen=0}" +
           ", pPublicKeyTemplate=publicTemplate, ulPublicKeyAttributeCount=" + std::to_string(publicCount) +
           ", pPrivateKeyTemplate=privateTemplate, ulPrivateKeyAttributeCount=" + std::to_string(privateCount) +
           ", phPublicKey=&publicKey, phPrivateKey=&privateKey",
           [&] { return module->C_GenerateKeyPair(session, &mechanism,
                            publicTemplate, publicCount, privateTemplate, privateCount,
                            &publicKey, &privateKey); });
    trace("OBJECT", "generated GOST publicKey handle=" + std::to_string(publicKey) +
                    ", privateKey handle=" + std::to_string(privateKey));
    if (publicKey == CK_INVALID_HANDLE || privateKey == CK_INVALID_HANDLE || publicKey == privateKey)
        fail("GOST key generation returned invalid handles");

    if (ulongAttribute(module, session, publicKey, CKA_KEY_TYPE) != CKK_GOSTR3410)
        fail("generated GOST public key has the wrong key type");
    const Bytes local = attribute(module, session, publicKey, CKA_LOCAL);
    if (local.size() != sizeof(CK_BBOOL) || local[0] != CK_TRUE)
        fail("generated GOST public key is not marked local");
    if (attribute(module, session, publicKey, CKA_GOSTR3410_PARAMS) != curve ||
        attribute(module, session, publicKey, CKA_GOSTR3411_PARAMS) != digestParam)
        fail("generated GOST public key parameter OIDs changed");
    const Bytes point = attribute(module, session, publicKey, CKA_VALUE);
    if (point.size() != 64 || std::all_of(point.begin(), point.end(), [](unsigned char byte) { return byte == 0; }))
        fail("generated GOST public key is not a non-zero 256-bit X || Y point");

    CK_ATTRIBUTE privateValue{CKA_VALUE, nullptr, 0};
    checkAttributeReadRejected(
        invoke("C_GetAttributeValue", "hSession=" + std::to_string(session) +
               ", hObject=" + std::to_string(privateKey) +
               ", pTemplate={CKA_VALUE,NULL_PTR,0}, ulCount=1",
               [&] { return module->C_GetAttributeValue(session, privateKey, &privateValue, 1); }),
        "C_GetAttributeValue(private GOST CKA_VALUE)");
    trace("SECURITY", "generated GOST private scalar is non-extractable through C_GetAttributeValue");

    std::vector<CK_ATTRIBUTE> publicQuery = {
        {CKA_CLASS, &publicClass, sizeof(publicClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_ID, objectId.data(), static_cast<CK_ULONG>(objectId.size())}
    };
    std::vector<CK_ATTRIBUTE> privateQuery = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_ID, objectId.data(), static_cast<CK_ULONG>(objectId.size())}
    };
    if (findOne(module, session, publicQuery) != publicKey ||
        findOne(module, session, privateQuery) != privateKey)
        fail("generated GOST key pair was not persisted under its standard CKA_ID");
    trace("KEYGEN", "GOST R 34.10-2012/256 key pair generation and persisted attributes verified");
    return {publicKey, privateKey, point};
}

struct U256
{
    std::array<std::uint64_t, 4> limb{};
};

static bool operator==(const U256& left, const U256& right) { return left.limb == right.limb; }
static bool isZero(const U256& value) { return value == U256{}; }

static int compare(const U256& left, const U256& right)
{
    for (size_t index = 4; index-- > 0;)
    {
        if (left.limb[index] < right.limb[index]) return -1;
        if (left.limb[index] > right.limb[index]) return 1;
    }
    return 0;
}

static U256 addRaw(const U256& left, const U256& right)
{
    U256 result;
    std::uint64_t carry = 0;
    for (size_t index = 0; index < 4; ++index)
    {
        const std::uint64_t first = left.limb[index] + carry;
        const std::uint64_t firstCarry = first < left.limb[index];
        result.limb[index] = first + right.limb[index];
        const std::uint64_t secondCarry = result.limb[index] < first;
        carry = firstCarry | secondCarry;
    }
    return result;
}

static U256 subtractRaw(const U256& left, const U256& right)
{
    U256 result;
    std::uint64_t borrow = 0;
    for (size_t index = 0; index < 4; ++index)
    {
        const std::uint64_t first = left.limb[index] - borrow;
        const std::uint64_t firstBorrow = first > left.limb[index];
        result.limb[index] = first - right.limb[index];
        const std::uint64_t secondBorrow = result.limb[index] > first;
        borrow = firstBorrow | secondBorrow;
    }
    return result;
}

static U256 addMod(const U256& left, const U256& right, const U256& modulus)
{
    const U256 gap = subtractRaw(modulus, right);
    return compare(left, gap) >= 0 ? subtractRaw(left, gap) : addRaw(left, right);
}

static U256 subtractMod(const U256& left, const U256& right, const U256& modulus)
{
    return compare(left, right) >= 0 ? subtractRaw(left, right)
                                    : subtractRaw(modulus, subtractRaw(right, left));
}

static bool bit(const U256& value, size_t index)
{
    return ((value.limb[index / 64] >> (index % 64)) & 1U) != 0;
}

static U256 multiplyMod(U256 left, const U256& right, const U256& modulus)
{
    U256 result;
    for (size_t index = 0; index < 256; ++index)
    {
        if (bit(right, index)) result = addMod(result, left, modulus);
        left = addMod(left, left, modulus);
    }
    return result;
}

static U256 powerMod(U256 base, const U256& exponent, const U256& modulus)
{
    U256 result;
    result.limb[0] = 1;
    for (size_t index = 256; index-- > 0;)
    {
        result = multiplyMod(result, result, modulus);
        if (bit(exponent, index)) result = multiplyMod(result, base, modulus);
    }
    return result;
}

static U256 inverseMod(const U256& value, const U256& modulus)
{
    U256 two;
    two.limb[0] = 2;
    return powerMod(value, subtractRaw(modulus, two), modulus);
}

static U256 fromBigEndian(const unsigned char* bytes, size_t length)
{
    if (length > 32) fail("U256 input exceeds 32 bytes");
    U256 result;
    for (size_t index = 0; index < length; ++index)
    {
        const size_t reverse = length - 1 - index;
        result.limb[index / 8] |= static_cast<std::uint64_t>(bytes[reverse]) << ((index % 8) * 8);
    }
    return result;
}

static U256 fromLittleEndian(const unsigned char* bytes, size_t length)
{
    if (length > 32) fail("U256 input exceeds 32 bytes");
    U256 result;
    for (size_t index = 0; index < length; ++index)
        result.limb[index / 8] |= static_cast<std::uint64_t>(bytes[index]) << ((index % 8) * 8);
    return result;
}

static U256 u256Hex(const char* value)
{
    return fromBigEndian(bytesFromHex(value).data(), std::strlen(value) / 2);
}

struct AffinePoint
{
    U256 x;
    U256 y;
    bool infinity = true;
};

struct JacobianPoint
{
    U256 x;
    U256 y;
    U256 z;
    bool infinity = true;
};

static U256 smallMod(const U256& value, unsigned int factor, const U256& modulus)
{
    U256 result;
    for (unsigned int index = 0; index < factor; ++index) result = addMod(result, value, modulus);
    return result;
}

static JacobianPoint doublePoint(const JacobianPoint& point, const U256& prime, const U256& curveA)
{
    if (point.infinity || isZero(point.y)) return {};
    const U256 xx = multiplyMod(point.x, point.x, prime);
    const U256 yy = multiplyMod(point.y, point.y, prime);
    const U256 yyyy = multiplyMod(yy, yy, prime);
    const U256 zz = multiplyMod(point.z, point.z, prime);
    U256 s = multiplyMod(addMod(point.x, yy, prime), addMod(point.x, yy, prime), prime);
    s = smallMod(subtractMod(subtractMod(s, xx, prime), yyyy, prime), 2, prime);
    const U256 zz2 = multiplyMod(zz, zz, prime);
    const U256 m = addMod(smallMod(xx, 3, prime), multiplyMod(curveA, zz2, prime), prime);
    const U256 x3 = subtractMod(multiplyMod(m, m, prime), smallMod(s, 2, prime), prime);
    const U256 y3 = subtractMod(multiplyMod(m, subtractMod(s, x3, prime), prime),
                                smallMod(yyyy, 8, prime), prime);
    const U256 z3 = subtractMod(subtractMod(
        multiplyMod(addMod(point.y, point.z, prime), addMod(point.y, point.z, prime), prime),
        yy, prime), zz, prime);
    return {x3, y3, z3, false};
}

static JacobianPoint addMixed(const JacobianPoint& left, const AffinePoint& right,
                              const U256& prime, const U256& curveA)
{
    if (left.infinity) return {right.x, right.y, U256{{1, 0, 0, 0}}, right.infinity};
    if (right.infinity) return left;
    const U256 z1z1 = multiplyMod(left.z, left.z, prime);
    const U256 u2 = multiplyMod(right.x, z1z1, prime);
    const U256 s2 = multiplyMod(right.y, multiplyMod(left.z, z1z1, prime), prime);
    const U256 h = subtractMod(u2, left.x, prime);
    if (isZero(h))
    {
        if (s2 == left.y) return doublePoint(left, prime, curveA);
        return {};
    }
    const U256 hh = multiplyMod(h, h, prime);
    const U256 i = smallMod(hh, 4, prime);
    const U256 j = multiplyMod(h, i, prime);
    const U256 r = smallMod(subtractMod(s2, left.y, prime), 2, prime);
    const U256 v = multiplyMod(left.x, i, prime);
    const U256 x3 = subtractMod(subtractMod(multiplyMod(r, r, prime), j, prime),
                                smallMod(v, 2, prime), prime);
    const U256 y3 = subtractMod(multiplyMod(r, subtractMod(v, x3, prime), prime),
                                smallMod(multiplyMod(left.y, j, prime), 2, prime), prime);
    const U256 zPlusH = addMod(left.z, h, prime);
    const U256 z3 = subtractMod(subtractMod(multiplyMod(zPlusH, zPlusH, prime), z1z1, prime),
                                hh, prime);
    return {x3, y3, z3, false};
}

static AffinePoint affine(const JacobianPoint& point, const U256& prime)
{
    if (point.infinity) return {};
    const U256 zInverse = inverseMod(point.z, prime);
    const U256 zInverse2 = multiplyMod(zInverse, zInverse, prime);
    return {multiplyMod(point.x, zInverse2, prime),
            multiplyMod(point.y, multiplyMod(zInverse2, zInverse, prime), prime), false};
}

static AffinePoint scalarMultiply(const U256& scalar, const AffinePoint& point,
                                  const U256& prime, const U256& curveA)
{
    JacobianPoint result;
    for (size_t index = 256; index-- > 0;)
    {
        result = doublePoint(result, prime, curveA);
        if (bit(scalar, index)) result = addMixed(result, point, prime, curveA);
    }
    return affine(result, prime);
}

static AffinePoint addAffine(const AffinePoint& left, const AffinePoint& right,
                             const U256& prime, const U256& curveA)
{
    JacobianPoint jacobian{left.x, left.y, U256{{1, 0, 0, 0}}, left.infinity};
    return affine(addMixed(jacobian, right, prime, curveA), prime);
}

static bool verifyGOST2012Signature(const Bytes& publicPoint, const Bytes& digestValue,
                                    const Bytes& signature)
{
    if (publicPoint.size() != 64 || digestValue.size() != 32 || signature.size() != 64) return false;
    const U256 prime = u256Hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97");
    const U256 curveA = u256Hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94");
    const U256 curveB = u256Hex("a6");
    const U256 order = u256Hex("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893");
    const AffinePoint generator{u256Hex("01"),
        u256Hex("8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14"), false};
    const AffinePoint publicKey{fromLittleEndian(publicPoint.data(), 32),
                                fromLittleEndian(publicPoint.data() + 32, 32), false};

    const U256 y2 = multiplyMod(publicKey.y, publicKey.y, prime);
    const U256 x2 = multiplyMod(publicKey.x, publicKey.x, prime);
    const U256 curveRight = addMod(addMod(multiplyMod(x2, publicKey.x, prime),
                                          multiplyMod(curveA, publicKey.x, prime), prime),
                                   curveB, prime);
    if (!(y2 == curveRight)) return false;

    const U256 s = fromBigEndian(signature.data(), 32);
    const U256 r = fromBigEndian(signature.data() + 32, 32);
    if (isZero(r) || isZero(s) || compare(r, order) >= 0 || compare(s, order) >= 0) return false;
    U256 e = fromLittleEndian(digestValue.data(), digestValue.size());
    while (compare(e, order) >= 0) e = subtractRaw(e, order);
    if (isZero(e)) e.limb[0] = 1;
    const U256 v = inverseMod(e, order);
    const U256 z1 = multiplyMod(s, v, order);
    const U256 z2 = multiplyMod(subtractRaw(order, r), v, order);
    const AffinePoint result = addAffine(scalarMultiply(z1, generator, prime, curveA),
                                         scalarMultiply(z2, publicKey, prime, curveA),
                                         prime, curveA);
    if (result.infinity) return false;
    U256 x = result.x;
    while (compare(x, order) >= 0) x = subtractRaw(x, order);
    return x == r;
}

static Bytes gostSign(Module& module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                      CK_MECHANISM_TYPE mechanismType, const Bytes& data)
{
    CK_MECHANISM mechanism{mechanismType, nullptr, 0};
    callOk("C_SignInit", "hSession=" + std::to_string(session) + ", pMechanism={mechanism=" +
           mechanismName(mechanismType) + ", pParameter=NULL_PTR, ulParameterLen=0}, hKey=" +
           std::to_string(key), [&] { return module->C_SignInit(session, &mechanism, key); });
    CK_ULONG length = 0;
    callOk("C_Sign", "hSession=" + std::to_string(session) + ", pData=hex:" +
           hexBytes(data.data(), data.size()) + ", ulDataLen=" + std::to_string(data.size()) +
           ", pSignature=NULL_PTR, pulSignatureLen=&length",
           [&] { return module->C_Sign(session, const_cast<CK_BYTE_PTR>(data.data()),
                                       static_cast<CK_ULONG>(data.size()), nullptr, &length); });
    if (length != 64) fail("GOST C_Sign length query did not return 64 bytes");
    Bytes signature(length);
    callOk("C_Sign", "hSession=" + std::to_string(session) + ", pData=hex:" +
           hexBytes(data.data(), data.size()) + ", ulDataLen=" + std::to_string(data.size()) +
           ", pSignature=buffer[64], pulSignatureLen=&length",
           [&] { return module->C_Sign(session, const_cast<CK_BYTE_PTR>(data.data()),
                                       static_cast<CK_ULONG>(data.size()), signature.data(), &length); });
    signature.resize(length);
    trace("OUTPUT", std::string(mechanismName(mechanismType)) + " signature hex=" +
                    hexBytes(signature.data(), signature.size()));
    return signature;
}

static Bytes gostSignMultipart(Module& module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                               const Bytes& data, const std::vector<size_t>& chunks)
{
    CK_MECHANISM mechanism{CKM_GOSTR3410_WITH_GOSTR3411_2012_256, nullptr, 0};
    callOk("C_SignInit", "hSession=" + std::to_string(session) +
           ", pMechanism={mechanism=CKM_GOSTR3410_WITH_GOSTR3411_2012_256, pParameter=NULL_PTR, ulParameterLen=0}, hKey=" +
           std::to_string(key), [&] { return module->C_SignInit(session, &mechanism, key); });
    size_t offset = 0;
    for (size_t chunk : chunks)
    {
        if (offset + chunk > data.size()) fail("GOST multipart signature chunk exceeds input");
        callOk("C_SignUpdate", "hSession=" + std::to_string(session) + ", pPart=hex:" +
               hexBytes(data.data() + offset, chunk) + ", ulPartLen=" + std::to_string(chunk),
               [&] { return module->C_SignUpdate(session,
                           const_cast<CK_BYTE_PTR>(data.data() + offset), static_cast<CK_ULONG>(chunk)); });
        offset += chunk;
    }
    if (offset != data.size()) fail("GOST multipart signature chunks do not cover input");
    CK_ULONG length = 0;
    callOk("C_SignFinal", "hSession=" + std::to_string(session) +
           ", pSignature=NULL_PTR, pulSignatureLen=&length",
           [&] { return module->C_SignFinal(session, nullptr, &length); });
    if (length != 64) fail("GOST C_SignFinal length query did not return 64 bytes");
    Bytes signature(length);
    callOk("C_SignFinal", "hSession=" + std::to_string(session) +
           ", pSignature=buffer[64], pulSignatureLen=&length",
           [&] { return module->C_SignFinal(session, signature.data(), &length); });
    signature.resize(length);
    trace("OUTPUT", "multipart GOST signature hex=" + hexBytes(signature.data(), signature.size()));
    return signature;
}

static void verifyGOST2012Signing(Module& module, CK_SESSION_HANDLE session,
                                  const GOST2012KeyPair& keyPair)
{
    // Reuse RFC 6986 section 10.1.2 so the combined mechanism is checked
    // against a published digest, not merely against another call into the
    // same implementation.
    const std::string text = "012345678901234567890123456789012345678901234567890123456789012";
    const Bytes message(text.begin(), text.end());
    const Bytes referenceDigest = bytesFromHex(
        "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");
    const Bytes digestValue = digest(module, session, CKM_GOSTR3411_2012_256, message, 32);
    if (digestValue != referenceDigest) fail("signing input digest does not match RFC 6986");

    CK_BYTE invalidParameter = 0;
    CK_MECHANISM invalid{CKM_GOSTR3410_WITH_GOSTR3411_2012_256, &invalidParameter, 1};
    check(invoke("C_SignInit", "hSession=" + std::to_string(session) +
                 ", pMechanism={mechanism=CKM_GOSTR3410_WITH_GOSTR3411_2012_256, pParameter=byte[1], ulParameterLen=1}, hKey=" +
                 std::to_string(keyPair.privateKey),
                 [&] { return module->C_SignInit(session, &invalid, keyPair.privateKey); }),
          CKR_MECHANISM_PARAM_INVALID, "C_SignInit(non-empty GOST parameters)");

    CK_MECHANISM rawMechanism{CKM_GOSTR3410, nullptr, 0};
    callOk("C_SignInit", "hSession=" + std::to_string(session) +
           ", pMechanism={mechanism=CKM_GOSTR3410, pParameter=NULL_PTR, ulParameterLen=0}, hKey=" +
           std::to_string(keyPair.privateKey),
           [&] { return module->C_SignInit(session, &rawMechanism, keyPair.privateKey); });
    Bytes shortDigest(31, 0x5a);
    Bytes rejectedSignature(64);
    CK_ULONG rejectedLength = static_cast<CK_ULONG>(rejectedSignature.size());
    check(invoke("C_Sign", "hSession=" + std::to_string(session) +
                 ", pData=hex:" + hexBytes(shortDigest.data(), shortDigest.size()) +
                 ", ulDataLen=31, pSignature=buffer[64], pulSignatureLen=&length",
                 [&] { return module->C_Sign(session, shortDigest.data(),
                                             static_cast<CK_ULONG>(shortDigest.size()),
                                             rejectedSignature.data(), &rejectedLength); }),
          CKR_DATA_LEN_RANGE, "C_Sign(31-byte raw GOST digest)");
    trace("STANDARD", "raw CKM_GOSTR3410 rejects inputs other than one 32-byte digest");

    const Bytes rawSignature = gostSign(module, session, keyPair.privateKey, CKM_GOSTR3410, digestValue);
    if (!verifyGOST2012Signature(keyPair.publicPoint, digestValue, rawSignature))
        fail("independent GOST verifier rejected CKM_GOSTR3410 signature");
    trace("REFERENCE", "independent GOST R 34.10-2012 equation verified raw C_Sign signature");

    const Bytes combinedSignature = gostSign(module, session, keyPair.privateKey,
                                              CKM_GOSTR3410_WITH_GOSTR3411_2012_256, message);
    if (!verifyGOST2012Signature(keyPair.publicPoint, digestValue, combinedSignature))
        fail("independent GOST verifier rejected combined one-shot signature");
    trace("REFERENCE", "independent verifier confirmed combined C_Sign uses Streebog-256");

    const Bytes multipartSignature = gostSignMultipart(module, session, keyPair.privateKey,
                                                        message, {1, 7, 13, 42});
    if (!verifyGOST2012Signature(keyPair.publicPoint, digestValue, multipartSignature))
        fail("independent GOST verifier rejected multipart signature");
    trace("REFERENCE", "independent verifier confirmed C_SignUpdate/C_SignFinal signature");
}

static CK_OBJECT_HANDLE createObject(Module& module, CK_SESSION_HANDLE session,
                                     const std::string& name, CK_ATTRIBUTE* attributes,
                                     CK_ULONG count)
{
    traceTemplate(name, attributes, count);
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    callOk("C_CreateObject", "hSession=" + std::to_string(session) +
           ", pTemplate=" + name + ", ulCount=" + std::to_string(count) +
           ", phObject=&object",
           [&] { return module->C_CreateObject(session, attributes, count, &object); });
    if (object == CK_INVALID_HANDLE) fail("C_CreateObject returned CK_INVALID_HANDLE for " + name);
    trace("OBJECT", "C_CreateObject created " + name + " handle=" + std::to_string(object));
    return object;
}

static void destroyObject(Module& module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
    callOk("C_DestroyObject", "hSession=" + std::to_string(session) +
           ", hObject=" + std::to_string(object),
           [&] { return module->C_DestroyObject(session, object); });
}

static void requireBooleanAttribute(Module& module, CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
                                    CK_BBOOL expected)
{
    const Bytes value = attribute(module, session, object, type);
    if (value.size() != sizeof(CK_BBOOL) || value[0] != expected)
        fail(std::string(attributeName(type)) + " has an unexpected value");
}

static void verifyGOSTCreateObjectRoundTrip(Module& module, CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_GOSTR3410;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    Bytes curve = bytesFromHex("06072a850302022301");
    Bytes digestParam = bytesFromHex("06082a85030701010202");
    const std::string generatedLabel = "portable-ci-exportable-gost";
    CK_ATTRIBUTE publicTemplate[] = {
        {CKA_CLASS, &publicClass, sizeof(publicClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_VERIFY, &yes, sizeof(yes)},
        {CKA_GOSTR3410_PARAMS, curve.data(), static_cast<CK_ULONG>(curve.size())},
        {CKA_GOSTR3411_PARAMS, digestParam.data(), static_cast<CK_ULONG>(digestParam.size())},
        {CKA_LABEL, const_cast<char*>(generatedLabel.data()), static_cast<CK_ULONG>(generatedLabel.size())}
    };
    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &no, sizeof(no)},
        {CKA_SIGN, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_GOSTR3410_PARAMS, curve.data(), static_cast<CK_ULONG>(curve.size())},
        {CKA_GOSTR3411_PARAMS, digestParam.data(), static_cast<CK_ULONG>(digestParam.size())},
        {CKA_LABEL, const_cast<char*>(generatedLabel.data()), static_cast<CK_ULONG>(generatedLabel.size())}
    };
    const CK_ULONG publicCount = sizeof(publicTemplate) / sizeof(publicTemplate[0]);
    const CK_ULONG privateCount = sizeof(privateTemplate) / sizeof(privateTemplate[0]);
    traceTemplate("exportable GOST public-key generation template", publicTemplate, publicCount);
    traceTemplate("exportable GOST private-key generation template", privateTemplate, privateCount);
    CK_MECHANISM mechanism{CKM_GOSTR3410_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE generatedPublic = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE generatedPrivate = CK_INVALID_HANDLE;
    callOk("C_GenerateKeyPair", "hSession=" + std::to_string(session) +
           ", pMechanism={mechanism=CKM_GOSTR3410_KEY_PAIR_GEN, pParameter=NULL_PTR, ulParameterLen=0}" +
           ", pPublicKeyTemplate=exportablePublicTemplate, ulPublicKeyAttributeCount=" +
           std::to_string(publicCount) + ", pPrivateKeyTemplate=exportablePrivateTemplate" +
           ", ulPrivateKeyAttributeCount=" + std::to_string(privateCount),
           [&] { return module->C_GenerateKeyPair(session, &mechanism, publicTemplate, publicCount,
                                                   privateTemplate, privateCount,
                                                   &generatedPublic, &generatedPrivate); });

    const Bytes point = attribute(module, session, generatedPublic, CKA_VALUE);
    const Bytes scalar = attribute(module, session, generatedPrivate, CKA_VALUE, true);
    if (point.size() != 64 || scalar.size() != 32)
        fail("exportable GOST key pair has unexpected component sizes");

    const std::string importedLabel = "portable-ci-imported-gost";
    CK_ATTRIBUTE importedPublicTemplate[] = {
        {CKA_CLASS, &publicClass, sizeof(publicClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_VERIFY, &yes, sizeof(yes)},
        {CKA_VALUE, const_cast<unsigned char*>(point.data()), static_cast<CK_ULONG>(point.size())},
        {CKA_GOSTR3410_PARAMS, curve.data(), static_cast<CK_ULONG>(curve.size())},
        {CKA_GOSTR3411_PARAMS, digestParam.data(), static_cast<CK_ULONG>(digestParam.size())},
        {CKA_LABEL, const_cast<char*>(importedLabel.data()), static_cast<CK_ULONG>(importedLabel.size())}
    };
    CK_ATTRIBUTE importedPrivateTemplate[] = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &no, sizeof(no)},
        {CKA_SIGN, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_VALUE, const_cast<unsigned char*>(scalar.data()), static_cast<CK_ULONG>(scalar.size())},
        {CKA_GOSTR3410_PARAMS, curve.data(), static_cast<CK_ULONG>(curve.size())},
        {CKA_GOSTR3411_PARAMS, digestParam.data(), static_cast<CK_ULONG>(digestParam.size())},
        {CKA_LABEL, const_cast<char*>(importedLabel.data()), static_cast<CK_ULONG>(importedLabel.size())}
    };
    const CK_ULONG importedPublicCount = sizeof(importedPublicTemplate) / sizeof(importedPublicTemplate[0]);
    const CK_ULONG importedPrivateCount = sizeof(importedPrivateTemplate) / sizeof(importedPrivateTemplate[0]);
    const CK_OBJECT_HANDLE importedPublic = createObject(module, session, "imported GOST public-key template",
                                                          importedPublicTemplate, importedPublicCount);
    const CK_OBJECT_HANDLE importedPrivate = createObject(module, session, "imported GOST private-key template",
                                                           importedPrivateTemplate, importedPrivateCount);

    if (attribute(module, session, importedPublic, CKA_VALUE) != point ||
        attribute(module, session, importedPrivate, CKA_VALUE, true) != scalar ||
        attribute(module, session, importedPrivate, CKA_GOSTR3410_PARAMS) != curve ||
        attribute(module, session, importedPrivate, CKA_GOSTR3411_PARAMS) != digestParam)
        fail("GOST C_CreateObject/C_GetAttributeValue round trip changed key material");
    requireBooleanAttribute(module, session, importedPrivate, CKA_EXTRACTABLE, CK_TRUE);
    requireBooleanAttribute(module, session, importedPrivate, CKA_SENSITIVE, CK_FALSE);
    requireBooleanAttribute(module, session, importedPrivate, CKA_LOCAL, CK_FALSE);

    const Bytes message = bytesFromHex("00112233445566778899aabbccddeeff");
    const Bytes digestValue = digest(module, session, CKM_GOSTR3411_2012_256, message, 32);
    const Bytes signature = gostSign(module, session, importedPrivate, CKM_GOSTR3410, digestValue);
    if (!verifyGOST2012Signature(point, digestValue, signature))
        fail("imported GOST private key produced a signature that does not match its imported public key");

    destroyObject(module, session, importedPrivate);
    destroyObject(module, session, importedPublic);
    destroyObject(module, session, generatedPrivate);
    destroyObject(module, session, generatedPublic);
    trace("IMPORT", "GOST exportable generation, C_GetAttributeValue, two-object C_CreateObject import, re-export and signing verified");
}

static void verifyGOSTKEG(Module& module, CK_SESSION_HANDLE session)
{
    // Independent KEG vector for id-tc26-gost-3410-2012-256-paramSetA. The
    // imported private scalar uses SoftHSM's big-endian storage convention;
    // the peer point is the PKCS #11 little-endian X || Y representation.
    Bytes privateValue = bytesFromHex(
        "0debb7875a83206ad1b4167c0a3e35c3c3a75b0aefebcc01d81a18ff9f8e7d9f");
    Bytes publicValue = bytesFromHex(
        "c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888"
        "8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602");
    Bytes ukm = bytesFromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const Bytes expected = bytesFromHex(
        "bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900"
        "39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b");
    Bytes curve = bytesFromHex("06092a8503070102010101");
    Bytes digestParam = bytesFromHex("06082a85030701010202");
    CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE gostType = CKK_GOSTR3410;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &gostType, sizeof(gostType)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &no, sizeof(no)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_DERIVE, &yes, sizeof(yes)},
        {CKA_VALUE, privateValue.data(), static_cast<CK_ULONG>(privateValue.size())},
        {CKA_GOSTR3410_PARAMS, curve.data(), static_cast<CK_ULONG>(curve.size())},
        {CKA_GOSTR3411_PARAMS, digestParam.data(), static_cast<CK_ULONG>(digestParam.size())}
    };
    const CK_OBJECT_HANDLE baseKey = createObject(
        module, session, "GOST KEG private-key vector", privateTemplate,
        sizeof(privateTemplate) / sizeof(privateTemplate[0]));

    CK_ECDH1_DERIVE_PARAMS params{CKD_NULL, static_cast<CK_ULONG>(ukm.size()), ukm.data(),
                                  static_cast<CK_ULONG>(publicValue.size()), publicValue.data()};
    CK_MECHANISM mechanism{CKM_GOST_KEG, &params, sizeof(params)};
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE twinType = CKK_MAGMA_TWIN_KEY;
    CK_ULONG valueLen = 64;
    CK_ATTRIBUTE outputTemplate[] = {
        {CKA_CLASS, &secretClass, sizeof(secretClass)},
        {CKA_KEY_TYPE, &twinType, sizeof(twinType)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_SENSITIVE, &no, sizeof(no)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)}
    };
    CK_OBJECT_HANDLE twinKey = CK_INVALID_HANDLE;
    traceTemplate("GOST KEG known-answer output template", outputTemplate,
                  sizeof(outputTemplate) / sizeof(outputTemplate[0]));
    callOk("C_DeriveKey", "hSession=" + std::to_string(session) +
           ", pMechanism={mechanism=CKM_GOST_KEG, params=CK_ECDH1_DERIVE_PARAMS}"
           ", hBaseKey=" + std::to_string(baseKey) +
           ", pTemplate=GOST KEG known-answer output template, ulCount=7, phKey=&twinKey",
           [&] { return module->C_DeriveKey(session, &mechanism, baseKey, outputTemplate,
                                             sizeof(outputTemplate) / sizeof(outputTemplate[0]), &twinKey); });
    if (attribute(module, session, twinKey, CKA_VALUE) != expected)
        fail("CKM_GOST_KEG output does not match the independent known-answer vector");
    if (ulongAttribute(module, session, twinKey, CKA_KEY_TYPE) != CKK_MAGMA_TWIN_KEY ||
        ulongAttribute(module, session, twinKey, CKA_VALUE_LEN) != 64)
        fail("CKM_GOST_KEG created an object with unexpected key type or size");
    requireBooleanAttribute(module, session, twinKey, CKA_LOCAL, CK_FALSE);
    destroyObject(module, session, twinKey);

    CK_ATTRIBUTE pluginTemplate[] = {
        {CKA_CLASS, &secretClass, sizeof(secretClass)},
        {CKA_KEY_TYPE, &twinType, sizeof(twinType)},
        {CKA_TOKEN, &no, sizeof(no)}
    };
    twinKey = CK_INVALID_HANDLE;
    callOk("C_DeriveKey", "plugin-shaped CKM_GOST_KEG call; output template has class, key type and token only",
           [&] { return module->C_DeriveKey(session, &mechanism, baseKey, pluginTemplate,
                                             sizeof(pluginTemplate) / sizeof(pluginTemplate[0]), &twinKey); });
    if (ulongAttribute(module, session, twinKey, CKA_KEY_TYPE) != CKK_MAGMA_TWIN_KEY ||
        ulongAttribute(module, session, twinKey, CKA_VALUE_LEN) != 64)
        fail("plugin-shaped CKM_GOST_KEG call created an invalid twin key");
    // Creating the key is not the point - the caller derives it in order to
    // read it, and this template says nothing about sensitivity, so the value
    // has to come back on the module's defaults alone. Checking only the type
    // and the length here let the owner's finding through: the key was built
    // correctly and was still unreadable.
    if (attribute(module, session, twinKey, CKA_VALUE) != expected)
        fail("a plugin-shaped CKM_GOST_KEG key does not read back as the same "
             "64 bytes the explicit template produced");
    destroyObject(module, session, twinKey);

    params.kdf = CKD_SHA1_KDF;
    twinKey = CK_INVALID_HANDLE;
    check(invoke("C_DeriveKey", "CKM_GOST_KEG with unsupported kdf",
                 [&] { return module->C_DeriveKey(session, &mechanism, baseKey, pluginTemplate,
                                                   sizeof(pluginTemplate) / sizeof(pluginTemplate[0]), &twinKey); }),
          CKR_MECHANISM_PARAM_INVALID, "C_DeriveKey(CKM_GOST_KEG unsupported kdf)");
    if (twinKey != CK_INVALID_HANDLE) fail("failed CKM_GOST_KEG call returned a key handle");

    destroyObject(module, session, baseKey);
    trace("REFERENCE", "CKM_GOST_KEG matched the independent 64-byte Magma twin-key vector and plugin call shape");
}

static void verifyRSACreateObjectRoundTrip(Module& module, CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ULONG bits = 2048;
    CK_BYTE exponent[] = {0x01, 0x00, 0x01};
    CK_ATTRIBUTE publicTemplate[] = {
        {CKA_CLASS, &publicClass, sizeof(publicClass)}, {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &no, sizeof(no)}, {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_VERIFY, &yes, sizeof(yes)}, {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent)}
    };
    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)}, {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &no, sizeof(no)}, {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &no, sizeof(no)}, {CKA_SIGN, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)}
    };
    const CK_ULONG publicCount = sizeof(publicTemplate) / sizeof(publicTemplate[0]);
    const CK_ULONG privateCount = sizeof(privateTemplate) / sizeof(privateTemplate[0]);
    traceTemplate("exportable RSA public-key generation template", publicTemplate, publicCount);
    traceTemplate("exportable RSA private-key generation template", privateTemplate, privateCount);
    CK_MECHANISM mechanism{CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE generatedPublic = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE generatedPrivate = CK_INVALID_HANDLE;
    callOk("C_GenerateKeyPair", "hSession=" + std::to_string(session) +
           ", pMechanism={mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN, pParameter=NULL_PTR, ulParameterLen=0}" +
           ", pPublicKeyTemplate=exportablePublicTemplate, ulPublicKeyAttributeCount=" +
           std::to_string(publicCount) + ", pPrivateKeyTemplate=exportablePrivateTemplate" +
           ", ulPrivateKeyAttributeCount=" + std::to_string(privateCount),
           [&] { return module->C_GenerateKeyPair(session, &mechanism, publicTemplate, publicCount,
                                                   privateTemplate, privateCount,
                                                   &generatedPublic, &generatedPrivate); });

    const Bytes modulus = attribute(module, session, generatedPrivate, CKA_MODULUS);
    const Bytes publicExponent = attribute(module, session, generatedPrivate, CKA_PUBLIC_EXPONENT);
    const Bytes privateExponent = attribute(module, session, generatedPrivate, CKA_PRIVATE_EXPONENT, true);
    const Bytes prime1 = attribute(module, session, generatedPrivate, CKA_PRIME_1, true);
    const Bytes prime2 = attribute(module, session, generatedPrivate, CKA_PRIME_2, true);
    const Bytes exponent1 = attribute(module, session, generatedPrivate, CKA_EXPONENT_1, true);
    const Bytes exponent2 = attribute(module, session, generatedPrivate, CKA_EXPONENT_2, true);
    const Bytes coefficient = attribute(module, session, generatedPrivate, CKA_COEFFICIENT, true);

    CK_ATTRIBUTE importedPublicTemplate[] = {
        {CKA_CLASS, &publicClass, sizeof(publicClass)}, {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &no, sizeof(no)}, {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_VERIFY, &yes, sizeof(yes)},
        {CKA_MODULUS, const_cast<unsigned char*>(modulus.data()), static_cast<CK_ULONG>(modulus.size())},
        {CKA_PUBLIC_EXPONENT, const_cast<unsigned char*>(publicExponent.data()), static_cast<CK_ULONG>(publicExponent.size())}
    };
    CK_ATTRIBUTE importedPrivateTemplate[] = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)}, {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &no, sizeof(no)}, {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &no, sizeof(no)}, {CKA_SIGN, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_MODULUS, const_cast<unsigned char*>(modulus.data()), static_cast<CK_ULONG>(modulus.size())},
        {CKA_PUBLIC_EXPONENT, const_cast<unsigned char*>(publicExponent.data()), static_cast<CK_ULONG>(publicExponent.size())},
        {CKA_PRIVATE_EXPONENT, const_cast<unsigned char*>(privateExponent.data()), static_cast<CK_ULONG>(privateExponent.size())},
        {CKA_PRIME_1, const_cast<unsigned char*>(prime1.data()), static_cast<CK_ULONG>(prime1.size())},
        {CKA_PRIME_2, const_cast<unsigned char*>(prime2.data()), static_cast<CK_ULONG>(prime2.size())},
        {CKA_EXPONENT_1, const_cast<unsigned char*>(exponent1.data()), static_cast<CK_ULONG>(exponent1.size())},
        {CKA_EXPONENT_2, const_cast<unsigned char*>(exponent2.data()), static_cast<CK_ULONG>(exponent2.size())},
        {CKA_COEFFICIENT, const_cast<unsigned char*>(coefficient.data()), static_cast<CK_ULONG>(coefficient.size())}
    };
    const CK_ULONG importedPublicCount = sizeof(importedPublicTemplate) / sizeof(importedPublicTemplate[0]);
    const CK_ULONG importedPrivateCount = sizeof(importedPrivateTemplate) / sizeof(importedPrivateTemplate[0]);
    const CK_OBJECT_HANDLE importedPublic = createObject(module, session, "imported RSA public-key template",
                                                          importedPublicTemplate, importedPublicCount);
    const CK_OBJECT_HANDLE importedPrivate = createObject(module, session, "imported RSA private-key template",
                                                           importedPrivateTemplate, importedPrivateCount);

    const std::pair<CK_ATTRIBUTE_TYPE, const Bytes*> privateComponents[] = {
        {CKA_MODULUS, &modulus}, {CKA_PUBLIC_EXPONENT, &publicExponent},
        {CKA_PRIVATE_EXPONENT, &privateExponent}, {CKA_PRIME_1, &prime1},
        {CKA_PRIME_2, &prime2}, {CKA_EXPONENT_1, &exponent1},
        {CKA_EXPONENT_2, &exponent2}, {CKA_COEFFICIENT, &coefficient}
    };
    for (const auto& component : privateComponents)
        if (attribute(module, session, importedPrivate, component.first,
                      privateKeyMaterial(component.first)) != *component.second)
            fail(std::string("RSA C_CreateObject/C_GetAttributeValue changed ") + attributeName(component.first));
    if (attribute(module, session, importedPublic, CKA_MODULUS) != modulus ||
        attribute(module, session, importedPublic, CKA_PUBLIC_EXPONENT) != publicExponent)
        fail("RSA public-key C_CreateObject/C_GetAttributeValue round trip changed key material");
    requireBooleanAttribute(module, session, importedPrivate, CKA_EXTRACTABLE, CK_TRUE);
    requireBooleanAttribute(module, session, importedPrivate, CKA_SENSITIVE, CK_FALSE);
    requireBooleanAttribute(module, session, importedPrivate, CKA_LOCAL, CK_FALSE);
    requireBooleanAttribute(module, session, importedPrivate, CKA_ALWAYS_SENSITIVE, CK_FALSE);
    requireBooleanAttribute(module, session, importedPrivate, CKA_NEVER_EXTRACTABLE, CK_FALSE);

    const Bytes message = bytesFromHex("52534120696d706f72742f6578706f727420726f756e642074726970");
    if (sign(module, session, generatedPrivate, message) != sign(module, session, importedPrivate, message))
        fail("imported RSA private key does not reproduce the generated key's deterministic signature");

    destroyObject(module, session, importedPrivate);
    destroyObject(module, session, importedPublic);
    destroyObject(module, session, generatedPrivate);
    destroyObject(module, session, generatedPublic);
    trace("IMPORT", "RSA exportable generation, eight-component C_GetAttributeValue, two-object C_CreateObject import, re-export and signing verified");
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
        der(0x04, digest(module, session, CKM_SHA256, payload, 32)));
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

static std::string configuredRSAKeyLabel()
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

static void removePriorTestObjects(Module& module, CK_SESSION_HANDLE session, const Bytes& id)
{
    CK_ATTRIBUTE query{CKA_ID, const_cast<unsigned char*>(id.data()), static_cast<CK_ULONG>(id.size())};
    callOk("C_FindObjectsInit", "remove prior test objects by CKA_ID=" + hexBytes(id.data(), id.size()),
           [&] { return module->C_FindObjectsInit(session, &query, 1); });
    std::vector<CK_OBJECT_HANDLE> objects;
    for (;;)
    {
        CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
        CK_ULONG count = 0;
        callOk("C_FindObjects", "enumerate prior test objects", [&] {
            return module->C_FindObjects(session, &object, 1, &count);
        });
        if (count == 0) break;
        objects.push_back(object);
    }
    callOk("C_FindObjectsFinal", "finish prior test-object enumeration",
           [&] { return module->C_FindObjectsFinal(session); });
    for (CK_OBJECT_HANDLE object : objects)
    {
        callOk("C_DestroyObject", "remove prior test object handle=" + std::to_string(object),
               [&] { return module->C_DestroyObject(session, object); });
    }
    trace("CLEANUP", "removed " + std::to_string(objects.size()) +
                     " prior test objects with CKA_ID=" + hexBytes(id.data(), id.size()));
}

static void prepare(const fs::path& modulePath, const fs::path& work)
{
    const bool initializeToken = environmentYes("P11_TEST_INITIALIZE_TOKEN");
    const std::string userPin = environment("P11_TEST_USER_PIN", true);
    const std::string soPin = initializeToken ? environment("P11_TEST_SO_PIN", true) : std::string();
    const std::string tokenLabel = configuredTokenLabel();
    const std::string rsaKeyLabel = configuredRSAKeyLabel();
    const Bytes rsaObjectId = configuredObjectId();
    const Bytes gostId = gostObjectId(rsaObjectId);
    trace("CONFIG", std::string("initializeToken=") + (initializeToken ? "YES" : "NO") +
                    ", excludedFunctions=\"" + environment("P11_TEST_EXCLUDE_FUNCTIONS") + "\"" +
                    ", requestedSlot=" + (configuredSlot() ? std::to_string(*configuredSlot()) : "auto") +
                    ", tokenLabel=\"" + tokenLabel + "\", rsaKeyLabel=\"" + rsaKeyLabel +
                    "\", rsaObjectIdHex=" + hexBytes(rsaObjectId.data(), rsaObjectId.size()) +
                    ", gostKeyLabel=\"" + kGostKeyLabel + "\", gostObjectIdHex=" +
                    hexBytes(gostId.data(), gostId.size()) +
                    ", soPin=" + (initializeToken ? "<redacted,length=" + std::to_string(soPin.size()) + ">" : "unused") +
                    ", userPin=<redacted,length=" + std::to_string(userPin.size()) + ">");
    fs::create_directories(work);
    fs::current_path(work);
    trace("FILESYSTEM", "scenario directory=" + work.string() + ", process current directory changed intentionally");
    Module module(modulePath);
    CK_SLOT_ID slot = initializeToken ? selectSlotForInitialization(module, tokenLabel) :
                                       selectSlot(module, true);

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
    removePriorTestObjects(module, session, rsaObjectId);
    removePriorTestObjects(module, session, gostId);

    trace("SCENARIO", "BEGIN GOST: digest, key generation, signing, and optional import/export capability; "
                      "keyLabel=\"" + std::string(kGostKeyLabel) + "\", objectIdHex=" +
                      hexBytes(gostId.data(), gostId.size()));
    requireMechanism(module, slot, CKM_GOSTR3411_2012_256, CKF_DIGEST);
    requireMechanism(module, slot, CKM_GOSTR3410_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR, 256);
    requireMechanism(module, slot, CKM_GOSTR3410, CKF_SIGN, 256);
    requireMechanism(module, slot, CKM_GOSTR3410_WITH_GOSTR3411_2012_256, CKF_SIGN, 256);
    verifyStreebog256(module, session);
    const GOST2012KeyPair gostKeyPair = verifyGOST2012KeyGeneration(module, session, rsaObjectId);
    verifyGOST2012Signing(module, session, gostKeyPair);
    const std::string requireGOSTImportExportSetting = environment("P11_TEST_REQUIRE_GOST_IMPORT_EXPORT");
    const bool requireGOSTImportExport = requireGOSTImportExportSetting.empty() ||
                                         environmentYes("P11_TEST_REQUIRE_GOST_IMPORT_EXPORT");
    if (requireGOSTImportExport)
    {
        verifyGOSTCreateObjectRoundTrip(module, session);
        verifyGOSTKEG(module, session);
    }
    else
    {
        trace("SKIP", "GOST private-key import/export round trip is optional for an external module; "
                      "normal GOST generation and signing remain required and passed");
    }
    trace("SCENARIO", "END GOST: all required GOST checks passed");

    trace("SCENARIO", "BEGIN RSA PREPARE: key generation, optional import/export, and CSR checks; "
                      "keyLabel=\"" + rsaKeyLabel + "\", objectIdHex=" +
                      hexBytes(rsaObjectId.data(), rsaObjectId.size()));
    requireMechanism(module, slot, CKM_RSA_PKCS_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR, 2048);
    requireMechanism(module, slot, CKM_SHA256_RSA_PKCS, CKF_SIGN, 2048);
    requireMechanism(module, slot, CKM_SHA256, CKF_DIGEST);
    const std::string requireRSAImportExportSetting = environment("P11_TEST_REQUIRE_RSA_IMPORT_EXPORT");
    const bool requireRSAImportExport = requireRSAImportExportSetting.empty() ||
                                        environmentYes("P11_TEST_REQUIRE_RSA_IMPORT_EXPORT");
    if (requireRSAImportExport)
    {
        verifyRSACreateObjectRoundTrip(module, session);
    }
    else
    {
        trace("SKIP", "RSA private-key import/export round trip is optional for an external module; "
                      "normal RSA generation, CSR, and CMS signing remain required");
    }

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
        {CKA_LABEL, const_cast<char*>(rsaKeyLabel.data()), static_cast<CK_ULONG>(rsaKeyLabel.size())},
        {CKA_ID, const_cast<unsigned char*>(rsaObjectId.data()), static_cast<CK_ULONG>(rsaObjectId.size())}
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
        {CKA_LABEL, const_cast<char*>(rsaKeyLabel.data()), static_cast<CK_ULONG>(rsaKeyLabel.size())},
        {CKA_ID, const_cast<unsigned char*>(rsaObjectId.data()), static_cast<CK_ULONG>(rsaObjectId.size())}
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

    CK_ATTRIBUTE privateExponent{CKA_PRIVATE_EXPONENT, nullptr, 0};
    checkAttributeReadRejected(
        invoke("C_GetAttributeValue", "hSession=" + std::to_string(session) +
               ", hObject=" + std::to_string(privateKey) +
               ", pTemplate={CKA_PRIVATE_EXPONENT,NULL_PTR,0}, ulCount=1",
               [&] { return module->C_GetAttributeValue(session, privateKey, &privateExponent, 1); }),
        "C_GetAttributeValue(non-extractable RSA CKA_PRIVATE_EXPONENT)");
    trace("SECURITY", "non-extractable RSA private components remain unavailable through C_GetAttributeValue");

    writePem(work / "request.pem", "CERTIFICATE REQUEST", buildCsr(module, session, publicKey, privateKey));
    trace("FILESYSTEM", "wrote PKCS#10 CSR: " + (work / "request.pem").string());
    trace("SCENARIO", "END RSA PREPARE: all required RSA key generation and CSR checks passed");
    logout(module, session, "CKU_USER");
    closeSession(module, session);
    std::cout << "PKCS #11 GOST checks passed, RSA-2048 key generated, CSR written\n";
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
    trace("SCENARIO", "BEGIN RSA FINISH: reopen RSA key, import certificate, and create CMS; "
                      "objectIdHex=" + hexBytes(objectId.data(), objectId.size()));

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
    trace("SCENARIO", "END RSA FINISH: RSA key reopen, certificate, and CMS checks passed");

    logout(module, session, "CKU_USER");
    closeSession(module, session);
    std::cout << "Certificate imported, token key reopened, detached CMS written\n";
}

static void verifyReadyToken(const fs::path& modulePath)
{
    const std::string userPin = environment("P11_TEST_USER_PIN", true);
    const Bytes rsaId = configuredObjectId();
    const Bytes gostId = gostObjectId(rsaId);
    Module module(modulePath);
    const CK_SLOT_ID slot = selectSlot(module, true);
    const CK_TOKEN_INFO info = tokenInfo(module, slot);
    if ((info.flags & CKF_TOKEN_INITIALIZED) == 0)
        fail("token is not initialized after the integration test");
    if ((info.flags & CKF_USER_PIN_INITIALIZED) == 0)
        fail("user PIN is not initialized after the integration test");

    CK_SESSION_HANDLE session = openSession(module, slot);
    login(module, session, CKU_USER, userPin);
    CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS certificateClass = CKO_CERTIFICATE;
    CK_KEY_TYPE rsa = CKK_RSA;
    CK_KEY_TYPE gost = CKK_GOSTR3410;
    std::vector<CK_ATTRIBUTE> rsaQuery = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &rsa, sizeof(rsa)},
        {CKA_ID, const_cast<unsigned char*>(rsaId.data()), static_cast<CK_ULONG>(rsaId.size())}
    };
    std::vector<CK_ATTRIBUTE> gostQuery = {
        {CKA_CLASS, &privateClass, sizeof(privateClass)},
        {CKA_KEY_TYPE, &gost, sizeof(gost)},
        {CKA_ID, const_cast<unsigned char*>(gostId.data()), static_cast<CK_ULONG>(gostId.size())}
    };
    std::vector<CK_ATTRIBUTE> certificateQuery = {
        {CKA_CLASS, &certificateClass, sizeof(certificateClass)},
        {CKA_ID, const_cast<unsigned char*>(rsaId.data()), static_cast<CK_ULONG>(rsaId.size())}
    };
    (void)findOne(module, session, rsaQuery);
    (void)findOne(module, session, gostQuery);
    (void)findOne(module, session, certificateQuery);
    logout(module, session, "CKU_USER");
    closeSession(module, session);
    trace("READY", "fresh module load logged in without C_InitToken/C_InitPIN/C_SetPIN and found persistent GOST/RSA/certificate objects");
}

// Confirm a value the module was told to keep private is not sitting in the
// token files in the clear. P11_TEST_STORE_DIR names the token directory; with
// it unset the check is skipped, because a caller pointed at someone else's
// store has no business reading it.
static void verifyStoredPrivately(const CK_BYTE* secret, size_t length, const char* what)
{
    const std::string storeDir = environment("P11_TEST_STORE_DIR");
    if (storeDir.empty())
    {
        trace("STORE", std::string("P11_TEST_STORE_DIR is unset; not checking that ") + what +
                       " is stored encrypted");
        return;
    }
    if (!fs::is_directory(storeDir)) fail("P11_TEST_STORE_DIR is not a directory: " + storeDir);

    size_t filesRead = 0;
    for (const fs::directory_entry& entry : fs::recursive_directory_iterator(storeDir))
    {
        if (!entry.is_regular_file()) continue;
        std::ifstream file(entry.path(), std::ios::binary);
        if (!file) continue;
        const std::string content((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
        filesRead++;
        if (content.find(std::string(reinterpret_cast<const char*>(secret), length)) !=
            std::string::npos)
            fail(std::string("the ") + what + " is in " + entry.path().string() +
                 " in the clear; a private object's attributes must be stored encrypted");
    }
    if (filesRead == 0) fail("P11_TEST_STORE_DIR holds no files: " + storeDir);
    trace("STORE", std::string("searched ") + std::to_string(filesRead) + " token files; " +
                   what + " is not among them in the clear");
}

// CKA_START_DATE and CKA_END_DATE on a private object. Attributes of a private
// object are stored encrypted, and these two used to be written in the clear,
// so every later read of them failed with CKR_GENERAL_ERROR - which took down
// any caller that enumerates keys and reads their validity, whatever else it
// was doing. Nothing here is Rutoken-specific; the defect is plain SoftHSM.
static void verifyPrivateObjectDates(Module& module, CK_SESSION_HANDLE session)
{
    // The private key's dates are deliberately unlike the public key's: the
    // on-disk check below looks for the private ones in the clear, and a
    // public object stores its own in the clear quite legitimately.
    const CK_DATE start{{'2', '7', '1', '8'}, {'0', '3'}, {'1', '4'}};
    const CK_DATE end{{'3', '1', '4', '1'}, {'0', '5'}, {'0', '9'}};
    CK_BBOOL yes = CK_TRUE;
    CK_ULONG bits = 2048;
    CK_BYTE exponent[] = {0x01, 0x00, 0x01};
    const Bytes id = {'d', 'a', 't', 'e', 's'};

    removePriorTestObjects(module, session, id);

    const CK_DATE publicStart{{'2', '0', '2', '0'}, {'0', '1'}, {'0', '1'}};
    const CK_DATE publicEnd{{'2', '0', '2', '1'}, {'0', '1'}, {'0', '1'}};
    CK_ATTRIBUTE publicTemplate[] = {
        {CKA_TOKEN, &yes, sizeof(yes)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent)},
        {CKA_ID, const_cast<unsigned char*>(id.data()), static_cast<CK_ULONG>(id.size())},
        {CKA_VERIFY, &yes, sizeof(yes)},
        {CKA_START_DATE, const_cast<CK_DATE*>(&publicStart), sizeof(publicStart)},
        {CKA_END_DATE, const_cast<CK_DATE*>(&publicEnd), sizeof(publicEnd)}
    };
    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_TOKEN, &yes, sizeof(yes)},
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_ID, const_cast<unsigned char*>(id.data()), static_cast<CK_ULONG>(id.size())},
        {CKA_SIGN, &yes, sizeof(yes)},
        {CKA_START_DATE, const_cast<CK_DATE*>(&start), sizeof(start)},
        {CKA_END_DATE, const_cast<CK_DATE*>(&end), sizeof(end)}
    };
    CK_MECHANISM mechanism{CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
    callOk("C_GenerateKeyPair", "CKM_RSA_PKCS_KEY_PAIR_GEN with CKA_START_DATE and CKA_END_DATE",
           [&] { return module->C_GenerateKeyPair(session, &mechanism, publicTemplate, 7,
                                                  privateTemplate, 6, &publicKey, &privateKey); });

    // Both keys must give the dates back, and give back what was written. The
    // public key never had the defect; it is read too so that a fix which
    // breaks the plain path cannot pass.
    struct Subject { CK_OBJECT_HANDLE object; const char* name; const CK_DATE* from; const CK_DATE* to; };
    const Subject subjects[] = {
        {privateKey, "private key", &start, &end},
        {publicKey, "public key", &publicStart, &publicEnd}
    };
    for (const Subject& subject : subjects)
    {
        CK_DATE readStart{};
        CK_DATE readEnd{};
        CK_ATTRIBUTE query[] = {
            {CKA_START_DATE, &readStart, sizeof(readStart)},
            {CKA_END_DATE, &readEnd, sizeof(readEnd)}
        };
        callOk("C_GetAttributeValue", std::string(subject.name) + ", CKA_START_DATE and CKA_END_DATE",
               [&] { return module->C_GetAttributeValue(session, subject.object, query, 2); });
        if (query[0].ulValueLen != sizeof(CK_DATE) || query[1].ulValueLen != sizeof(CK_DATE))
            fail(std::string("the ") + subject.name + " does not report both dates at their full length");
        if (memcmp(&readStart, subject.from, sizeof(CK_DATE)) != 0 ||
            memcmp(&readEnd, subject.to, sizeof(CK_DATE)) != 0)
            fail(std::string("the ") + subject.name + " gives back dates other than the ones written");
    }

    // A private object's attributes are stored encrypted, so the date must not
    // be findable in the token files. Reading it back correctly does not prove
    // that: the module also accepts a date left in the clear by an older build,
    // which is what makes an old token still usable - and what would otherwise
    // hide a write path that never encrypted anything.
    verifyStoredPrivately(reinterpret_cast<const CK_BYTE*>(&start), sizeof(start),
                          "CKA_START_DATE of the private key");
    verifyStoredPrivately(reinterpret_cast<const CK_BYTE*>(&end), sizeof(end),
                          "CKA_END_DATE of the private key");

    // The same has to hold for a date written after the object exists, which
    // is a different code path into the same store.
    const CK_DATE later{{'2', '0', '3', '0'}, {'0', '1'}, {'0', '2'}};
    CK_ATTRIBUTE change{CKA_START_DATE, const_cast<CK_DATE*>(&later), sizeof(later)};
    callOk("C_SetAttributeValue", "private key, CKA_START_DATE moved forward",
           [&] { return module->C_SetAttributeValue(session, privateKey, &change, 1); });
    CK_DATE readBack{};
    CK_ATTRIBUTE query{CKA_START_DATE, &readBack, sizeof(readBack)};
    callOk("C_GetAttributeValue", "private key, CKA_START_DATE after the change",
           [&] { return module->C_GetAttributeValue(session, privateKey, &query, 1); });
    if (query.ulValueLen != sizeof(CK_DATE) || memcmp(&readBack, &later, sizeof(later)) != 0)
        fail("a date written with C_SetAttributeValue does not read back");

    // An empty date is legal and must stay readable as an empty one.
    CK_ATTRIBUTE clear{CKA_START_DATE, nullptr, 0};
    callOk("C_SetAttributeValue", "private key, CKA_START_DATE cleared",
           [&] { return module->C_SetAttributeValue(session, privateKey, &clear, 1); });
    CK_ATTRIBUTE size{CKA_START_DATE, nullptr, 0};
    callOk("C_GetAttributeValue", "private key, CKA_START_DATE size after clearing",
           [&] { return module->C_GetAttributeValue(session, privateKey, &size, 1); });
    if (size.ulValueLen != 0) fail("a cleared date does not read back as empty");

    // A date of the wrong length is still refused.
    CK_BYTE stub[3] = {'2', '0', '3'};
    CK_ATTRIBUTE tooShort{CKA_END_DATE, stub, sizeof(stub)};
    check(invoke("C_SetAttributeValue", "private key, CKA_END_DATE of three bytes",
                 [&] { return module->C_SetAttributeValue(session, privateKey, &tooShort, 1); }),
          CKR_ATTRIBUTE_VALUE_INVALID, "C_SetAttributeValue(date of the wrong length)");

    callOk("C_DestroyObject", "the private key of the date pair",
           [&] { return module->C_DestroyObject(session, privateKey); });
    callOk("C_DestroyObject", "the public key of the date pair",
           [&] { return module->C_DestroyObject(session, publicKey); });
}

// C_WaitForSlotEvent. An application that watches for a device being plugged
// in parks a thread in the blocking form, and a module that answers
// CKR_FUNCTION_NOT_SUPPORTED there looks broken to it. Threads are deliberately
// not used here: an event that is already pending satisfies the blocking form
// straight away, which exercises the same entry path without a race to lose.
// Returns the slot whose token it initialized on the way.
static CK_SLOT_ID verifySlotEvents(Module& module)
{
    CK_SLOT_ID slot = CK_INVALID_HANDLE;

    check(invoke("C_WaitForSlotEvent", "flags=CKF_DONT_BLOCK, pSlot=NULL_PTR",
                 [&] { return module->C_WaitForSlotEvent(CKF_DONT_BLOCK, nullptr, nullptr); }),
          CKR_ARGUMENTS_BAD, "C_WaitForSlotEvent(no pSlot)");
    check(invoke("C_WaitForSlotEvent", "flags=CKF_DONT_BLOCK, pReserved set",
                 [&] { return module->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, &slot); }),
          CKR_ARGUMENTS_BAD, "C_WaitForSlotEvent(pReserved not null)");

    // Drain whatever the run so far has raised, so the state below is known.
    while (invoke("C_WaitForSlotEvent", "flags=CKF_DONT_BLOCK, draining",
                  [&] { return module->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, nullptr); }) == CKR_OK)
        trace("SLOT", "drained a pending event on slot " + std::to_string(slot));
    check(invoke("C_WaitForSlotEvent", "flags=CKF_DONT_BLOCK, nothing pending",
                 [&] { return module->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, nullptr); }),
          CKR_NO_EVENT, "C_WaitForSlotEvent(nothing pending)");

    // SoftHSM keeps one spare slot holding an uninitialised token; filling it
    // is the one thing that happens here which a watcher would call an event.
    // The size-query form of C_GetSlotList is what tops the spare back up.
    CK_ULONG count = 0;
    callOk("C_GetSlotList", "tokenPresent=CK_FALSE, pSlotList=NULL_PTR",
           [&] { return module->C_GetSlotList(CK_FALSE, nullptr, &count); });
    std::vector<CK_SLOT_ID> all(count);
    callOk("C_GetSlotList", "tokenPresent=CK_FALSE, pSlotList=&slots",
           [&] { return module->C_GetSlotList(CK_FALSE, all.data(), &count); });
    if (count == 0) fail("C_GetSlotList reported no slots at all");
    const CK_SLOT_ID spare = all[count - 1];

    const std::string soPin = environment("P11_TEST_SO_PIN", true);
    std::array<CK_UTF8CHAR, 32> label{};
    label.fill(' ');
    const std::string spareLabel = "slot event token";
    std::copy(spareLabel.begin(), spareLabel.end(), label.begin());
    callOk("C_InitToken", "slotID=" + std::to_string(spare) + " (the spare slot)",
           [&] { return module->C_InitToken(spare,
                       reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(soPin.data())),
                       static_cast<CK_ULONG>(soPin.size()), label.data()); });

    // The blocking form, with the event already there: it must report that
    // slot and must not have to be asked with CKF_DONT_BLOCK to do it.
    slot = CK_INVALID_HANDLE;
    callOk("C_WaitForSlotEvent", "flags=0 (blocking), one event pending",
           [&] { return module->C_WaitForSlotEvent(0, &slot, nullptr); });
    if (slot != spare)
        fail("C_WaitForSlotEvent reported slot " + std::to_string(slot) + " where " +
             std::to_string(spare) + " was initialized");

    // An event is delivered once.
    check(invoke("C_WaitForSlotEvent", "flags=CKF_DONT_BLOCK, after the event was taken",
                 [&] { return module->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, nullptr); }),
          CKR_NO_EVENT, "C_WaitForSlotEvent(event already consumed)");

    // Re-initializing a token that already exists wipes it but inserts
    // nothing, so it is not an event.
    callOk("C_InitToken", "slotID=" + std::to_string(spare) + " again",
           [&] { return module->C_InitToken(spare,
                       reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(soPin.data())),
                       static_cast<CK_ULONG>(soPin.size()), label.data()); });
    check(invoke("C_WaitForSlotEvent", "flags=CKF_DONT_BLOCK, after a re-initialization",
                 [&] { return module->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, nullptr); }),
          CKR_NO_EVENT, "C_WaitForSlotEvent(re-initialization is not an insertion)");

    return spare;
}

// A key whose template says nothing about sensitivity must come back readable.
// Software that derives a session key names only its class, type and lifetime
// and then reads the value straight out, so a module that defaults to
// unreadable hands it CKR_ATTRIBUTE_SENSITIVE and the operation dies there.
// The pair of checks matters as much as the default: asking for a
// non-extractable key must still produce one, or the default has stopped being
// a default and become the only behaviour.
static void verifySilentTemplateKeyIsReadable(Module& module, CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_BBOOL no = CK_FALSE;
    CK_ULONG valueLen = 32;
    CK_MECHANISM mechanism{CKM_AES_KEY_GEN, nullptr, 0};

    CK_ATTRIBUTE silent[] = {
        {CKA_CLASS, &secretClass, sizeof(secretClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)}
    };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    traceTemplate("session key template that says nothing about sensitivity",
                  silent, 4);
    callOk("C_GenerateKey", "pTemplate=silent about CKA_SENSITIVE/CKA_EXTRACTABLE",
           [&] { return module->C_GenerateKey(session, &mechanism, silent, 4, &key); });

    requireBooleanAttribute(module, session, key, CKA_SENSITIVE, CK_FALSE);
    requireBooleanAttribute(module, session, key, CKA_EXTRACTABLE, CK_TRUE);
    requireBooleanAttribute(module, session, key, CKA_NEVER_EXTRACTABLE, CK_FALSE);

    std::vector<CK_BYTE> value(valueLen + 16, 0);
    CK_ATTRIBUTE read = {CKA_VALUE, value.data(), static_cast<CK_ULONG>(value.size())};
    callOk("C_GetAttributeValue", "CKA_VALUE of the silently generated key",
           [&] { return module->C_GetAttributeValue(session, key, &read, 1); });
    if (read.ulValueLen != valueLen)
        fail("a key generated from a silent template returned " +
             std::to_string(read.ulValueLen) + " bytes where " +
             std::to_string(valueLen) + " were generated");

    // The default is a default, not a policy: a template that asks for an
    // unreadable key still gets one, and it cannot be talked back out of it.
    CK_ATTRIBUTE guarded[] = {
        {CKA_CLASS, &secretClass, sizeof(secretClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},
        {CKA_EXTRACTABLE, &no, sizeof(no)}
    };
    CK_OBJECT_HANDLE sealed = CK_INVALID_HANDLE;
    callOk("C_GenerateKey", "pTemplate=CKA_EXTRACTABLE=CK_FALSE",
           [&] { return module->C_GenerateKey(session, &mechanism, guarded, 5, &sealed); });
    requireBooleanAttribute(module, session, sealed, CKA_EXTRACTABLE, CK_FALSE);
    CK_ATTRIBUTE denied = {CKA_VALUE, value.data(), static_cast<CK_ULONG>(value.size())};
    check(invoke("C_GetAttributeValue", "CKA_VALUE of a key asked to be unextractable",
                 [&] { return module->C_GetAttributeValue(session, sealed, &denied, 1); }),
          CKR_ATTRIBUTE_SENSITIVE, "C_GetAttributeValue(CKA_EXTRACTABLE=CK_FALSE key)");

    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE reopen = {CKA_EXTRACTABLE, &yes, sizeof(yes)};
    check(invoke("C_SetAttributeValue", "turn CKA_EXTRACTABLE back on",
                 [&] { return module->C_SetAttributeValue(session, sealed, &reopen, 1); }),
          CKR_ATTRIBUTE_READ_ONLY, "C_SetAttributeValue(CKA_EXTRACTABLE false to true)");
}

// Behaviour that has nothing to do with the Rutoken profile and has to hold
// with it switched off. Run against a token this mode initializes itself.
static void verifyCoreBehaviour(const fs::path& modulePath)
{
    Module module(modulePath);

    // The slot it initialized is the one to work on: SoftHSM reports every
    // slot as holding a token, spare ones included, so the last slot in the
    // list is a fresh empty one rather than this.
    const CK_SLOT_ID slot = verifySlotEvents(module);

    // Its user PIN still has to be set before anything can be stored there.
    const std::string soPin = environment("P11_TEST_SO_PIN", true);
    const std::string userPin = environment("P11_TEST_USER_PIN", true);

    CK_SESSION_HANDLE session = openSession(module, slot);
    login(module, session, CKU_SO, soPin);
    callOk("C_InitPIN", "hSession=session, pPin=<redacted>",
           [&] { return module->C_InitPIN(session,
                       reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(userPin.data())),
                       static_cast<CK_ULONG>(userPin.size())); });
    logout(module, session, "CKU_SO");
    login(module, session, CKU_USER, userPin);

    verifyPrivateObjectDates(module, session);
    verifySilentTemplateKeyIsReadable(module, session);

    closeSession(module, session);
    std::cout << "core PKCS #11 behaviour verified\n";
}

// The vendor hardware-feature object. Five of Rutoken Plugin's methods begin by
// searching for it, and read its capability attributes from it in one call
// with buffers already sized - so both the search and the exact lengths matter.
static void verifyRutokenHardwareFeature(Module& module)
{
    struct Expected { CK_ATTRIBUTE_TYPE type; bool isBool; CK_ULONG value; const char* name; };
    static const Expected expected[] = {
        {CKA_VENDOR_SECURE_MESSAGING_AVAILABLE,     true,  CK_FALSE, "SECURE_MESSAGING_AVAILABLE"},
        {CKA_VENDOR_CURRENT_SECURE_MESSAGING_MODE,  false, SECURE_MESSAGING_MODE_UNSUPPORTED,
                                                           "CURRENT_SECURE_MESSAGING_MODE"},
        {CKA_VENDOR_SUPPORTED_SECURE_MESSAGING_MODES, false, SECURE_MESSAGING_MODE_UNSUPPORTED,
                                                           "SUPPORTED_SECURE_MESSAGING_MODES"},
        {CKA_VENDOR_CURRENT_TOKEN_INTERFACE,        false, TOKEN_INTERFACE_USB,
                                                           "CURRENT_TOKEN_INTERFACE"},
        {CKA_VENDOR_SUPPORTED_TOKEN_INTERFACE,      false, 0x21, "SUPPORTED_TOKEN_INTERFACE"},
        {CKA_VENDOR_EXTERNAL_AUTHENTICATION,        true,  CK_FALSE, "EXTERNAL_AUTHENTICATION"},
        {CKA_VENDOR_BIOMETRIC_AUTHENTICATION,       false, 0, "BIOMETRIC_AUTHENTICATION"},
        {CKA_VENDOR_SUPPORT_CUSTOM_PIN,             true,  CK_TRUE, "SUPPORT_CUSTOM_PIN"},
        {CKA_VENDOR_CUSTOM_ADMIN_PIN,               true,  CK_FALSE, "CUSTOM_ADMIN_PIN"},
        {CKA_VENDOR_CUSTOM_USER_PIN,                true,  CK_FALSE, "CUSTOM_USER_PIN"},
        {CKA_VENDOR_SUPPORT_INTERNAL_TRUSTED_CERTS, true,  CK_TRUE,
                                                           "SUPPORT_INTERNAL_TRUSTED_CERTS"},
        {CKA_VENDOR_SUPPORT_FKC2,                   true,  CK_TRUE, "SUPPORT_FKC2"},
        {CKA_VENDOR_UNDOCUMENTED_300C,              true,  CK_FALSE, "0x8000300C"},
        {CKA_VENDOR_UNDOCUMENTED_300D,              true,  CK_TRUE,  "0x8000300D"},
        {CKA_VENDOR_UNDOCUMENTED_300E,              true,  CK_FALSE, "0x8000300E"},
        {CKA_VENDOR_UNDOCUMENTED_300F,              true,  CK_FALSE, "0x8000300F"},
        {CKA_VENDOR_UNDOCUMENTED_3011,              true,  CK_FALSE, "0x80003011"},
        {CKA_VENDOR_UNDOCUMENTED_3012,              true,  CK_TRUE,  "0x80003012"},
        {CKA_VENDOR_UNDOCUMENTED_800D,              true,  CK_FALSE, "0x8000800D"},
        {CKA_VENDOR_UNDOCUMENTED_800E,              false, 0, "0x8000800E"}
    };
    const size_t count = sizeof(expected) / sizeof(expected[0]);

    CK_OBJECT_CLASS featureClass = CKO_HW_FEATURE;
    CK_HW_FEATURE_TYPE featureType = CKH_VENDOR_TOKEN_INFO;
    CK_ATTRIBUTE search[2] = {
        {CKA_CLASS, &featureClass, sizeof(featureClass)},
        {CKA_HW_FEATURE_TYPE, &featureType, sizeof(featureType)}
    };

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    // The plugin reads this before logging in, so a public session must do.
    callOk("C_OpenSession", "slotID=0, flags=CKF_SERIAL_SESSION",
           [&] { return module->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session); });

    std::vector<CK_OBJECT_HANDLE> found(4);
    CK_ULONG foundCount = 0;
    callOk("C_FindObjectsInit", "pTemplate=CKO_HW_FEATURE/CKH_VENDOR_TOKEN_INFO",
           [&] { return module->C_FindObjectsInit(session, search, 2); });
    callOk("C_FindObjects", "ulMaxObjectCount=4",
           [&] { return module->C_FindObjects(session, found.data(),
                                              static_cast<CK_ULONG>(found.size()), &foundCount); });
    callOk("C_FindObjectsFinal", "hSession=session",
           [&] { return module->C_FindObjectsFinal(session); });
    if (foundCount != 1)
        fail("the profile must expose exactly one CKH_VENDOR_TOKEN_INFO object, found " +
             std::to_string(foundCount));
    const CK_OBJECT_HANDLE feature = found[0];

    // One call, buffers pre-sized, exactly as the plugin asks.
    std::vector<CK_ATTRIBUTE> query(count);
    std::vector<std::array<CK_BYTE, 8>> buffers(count);
    for (size_t i = 0; i < count; ++i)
    {
        buffers[i].fill(0);
        query[i].type = expected[i].type;
        query[i].pValue = buffers[i].data();
        query[i].ulValueLen = expected[i].isBool ? sizeof(CK_BBOOL) : sizeof(CK_ULONG);
    }
    callOk("C_GetAttributeValue",
           "all " + std::to_string(count) + " capability attributes at once",
           [&] { return module->C_GetAttributeValue(session, feature, query.data(),
                                                    static_cast<CK_ULONG>(count)); });
    for (size_t i = 0; i < count; ++i)
    {
        const CK_ULONG want = expected[i].isBool ? sizeof(CK_BBOOL) : sizeof(CK_ULONG);
        if (query[i].ulValueLen != want)
            fail(std::string("hardware feature ") + expected[i].name + " has length " +
                 std::to_string(query[i].ulValueLen) + " where " + std::to_string(want) +
                 " is expected");
        CK_ULONG got = 0;
        if (expected[i].isBool) got = buffers[i][0];
        else memcpy(&got, buffers[i].data(), sizeof(CK_ULONG));
        if (got != expected[i].value)
            fail(std::string("hardware feature ") + expected[i].name + " is " +
                 hexNumber(got) + " where " + hexNumber(expected[i].value) + " is expected");
    }

    // Rutoken Plugin hands eight bytes for every CK_ULONG-valued attribute,
    // which is more than a Windows CK_ULONG needs. The device answers with the
    // real length and leaves the rest of the buffer alone; so must we, or the
    // plugin reads a value that is right only by accident.
    for (size_t i = 0; i < count; ++i)
    {
        if (expected[i].isBool) continue;
        std::array<CK_BYTE, 8> wide;
        wide.fill(0xAA);
        CK_ATTRIBUTE roomy = {expected[i].type, wide.data(),
                              static_cast<CK_ULONG>(wide.size())};
        callOk("C_GetAttributeValue", std::string(expected[i].name) + ", buffer of 8",
               [&] { return module->C_GetAttributeValue(session, feature, &roomy, 1); });
        if (roomy.ulValueLen != sizeof(CK_ULONG))
            fail(std::string("hardware feature ") + expected[i].name +
                 " answered a roomy buffer with length " + std::to_string(roomy.ulValueLen));
        CK_ULONG got = 0;
        memcpy(&got, wide.data(), sizeof(CK_ULONG));
        if (got != expected[i].value)
            fail(std::string("hardware feature ") + expected[i].name +
                 " is " + hexNumber(got) + " in a roomy buffer");
        for (size_t b = sizeof(CK_ULONG); b < wide.size(); ++b)
            if (wide[b] != 0xAA)
                fail(std::string("hardware feature ") + expected[i].name +
                     " wrote past the length it reported");
    }

    // An attribute the object does not carry must be refused, not invented.
    CK_BYTE spare = 0;
    CK_ATTRIBUTE absent = {CKA_LABEL, &spare, sizeof(spare)};
    check(invoke("C_GetAttributeValue", "hardware feature, CKA_LABEL",
                 [&] { return module->C_GetAttributeValue(session, feature, &absent, 1); }),
          CKR_ATTRIBUTE_TYPE_INVALID, "C_GetAttributeValue(attribute the object lacks)");

    // 0x80003010 is the interesting refusal. Rutoken Control Center asks for
    // it by name and treats the refusal as an error, which reads like a gap on
    // our side - but a sweep of the whole vendor range on the reference device
    // found the device refusing it too. Answering would be the deviation, so
    // the refusal is pinned here rather than left to be helpfully "fixed".
    CK_BYTE room[64];
    CK_ATTRIBUTE modelName = {0x80003010UL, room, sizeof(room)};
    check(invoke("C_GetAttributeValue", "hardware feature, 0x80003010 - absent on the device too",
                 [&] { return module->C_GetAttributeValue(session, feature, &modelName, 1); }),
          CKR_ATTRIBUTE_TYPE_INVALID, "C_GetAttributeValue(0x80003010)");

    // It describes the device; it is not stored data and cannot be changed.
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE change = {CKA_VENDOR_SUPPORT_FKC2, &yes, sizeof(yes)};
    check(invoke("C_SetAttributeValue", "hardware feature, CKA_VENDOR_SUPPORT_FKC2",
                 [&] { return module->C_SetAttributeValue(session, feature, &change, 1); }),
          CKR_ATTRIBUTE_READ_ONLY, "C_SetAttributeValue(hardware feature)");
    check(invoke("C_DestroyObject", "hardware feature",
                 [&] { return module->C_DestroyObject(session, feature); }),
          CKR_ACTION_PROHIBITED, "C_DestroyObject(hardware feature)");

    closeSession(module, session);
}

// The Rutoken extension: applications decide the module is a Rutoken by finding
// C_EX_GetFunctionListExtended, so the symbol, the table and the one entry point
// that reports anything all have to hold up.
static void verifyRutokenExtension(Module& module, const CK_TOKEN_INFO& token)
{
    auto getList = reinterpret_cast<CK_C_EX_GetFunctionListExtended>(
        module.symbol("C_EX_GetFunctionListExtended"));
    if (getList == nullptr) fail("C_EX_GetFunctionListExtended was not exported");

    CK_FUNCTION_LIST_EXTENDED_PTR ex = nullptr;
    callOk("C_EX_GetFunctionListExtended", "ppFunctionList=&extendedList",
           [&] { return getList(&ex); });
    if (ex == nullptr) fail("C_EX_GetFunctionListExtended returned a null table");
    if (ex->version.major != CRYPTOKI_LEGACY_VERSION_MAJOR ||
        ex->version.minor != CRYPTOKI_LEGACY_VERSION_MINOR)
        fail("the extended function table reports an unexpected Cryptoki version");
    if (ex->C_EX_GetFunctionListExtended != getList)
        fail("the extended table does not point back at the exported symbol");

    // A null member crashes callers that index the table without checking.
    const size_t entries = (sizeof(CK_FUNCTION_LIST_EXTENDED) - sizeof(CK_VERSION)) / sizeof(void*);
    void* const* members = reinterpret_cast<void* const*>(
        reinterpret_cast<const char*>(ex) + sizeof(CK_VERSION));
    for (size_t i = 0; i < entries; ++i)
        if (members[i] == nullptr)
            fail("extended function table entry " + std::to_string(i) + " is null");
    trace("PKCS11", "extended function table has " + std::to_string(entries) + " non-null entries");

    CK_TOKEN_INFO_EXTENDED extended{};
    extended.ulSizeofThisStructure = sizeof(extended);
    callOk("C_EX_GetTokenInfoExtended", "slotID=0, pInfo=&extended",
           [&] { return ex->C_EX_GetTokenInfoExtended(0, &extended); });
    if (extended.ulSizeofThisStructure != sizeof(extended))
        fail("C_EX_GetTokenInfoExtended did not report the size it filled");
    if (extended.ulTokenType != TOKEN_TYPE_RUTOKEN_ECP ||
        extended.ulTokenClass != TOKEN_CLASS_ECP)
        fail("C_EX_GetTokenInfoExtended does not report a Rutoken ECP");
    if (extended.ulMinUserPinLen == 0 || extended.ulMaxUserPinLen < extended.ulMinUserPinLen ||
        extended.ulMinAdminPinLen == 0 || extended.ulMaxAdminPinLen < extended.ulMinAdminPinLen)
        fail("C_EX_GetTokenInfoExtended reports an impossible PIN length range");
    if (extended.ulUserRetryCountLeft > extended.ulMaxUserRetryCount ||
        extended.ulAdminRetryCountLeft > extended.ulMaxAdminRetryCount)
        fail("C_EX_GetTokenInfoExtended reports more retries left than the maximum");
    if (extended.ulATRLen > sizeof(extended.ATR))
        fail("C_EX_GetTokenInfoExtended reports an ATR longer than its own field");

    // The two views of the token must agree on the serial number: the extended
    // field is the device's binary serial, big endian and right aligned, and
    // the string C_GetTokenInfo prints is that number in hex. Rendering the
    // bytes back as hex therefore has to reproduce the printed string.
    std::string fromText;
    for (size_t i = 0; i < sizeof(token.serialNumber); ++i)
    {
        const unsigned char c = static_cast<unsigned char>(token.serialNumber[i]);
        if (std::isxdigit(c)) fromText.push_back(static_cast<char>(std::tolower(c)));
    }
    std::string fromBytes;
    for (size_t i = 0; i < sizeof(extended.serialNumber); ++i)
    {
        static const char* const hex = "0123456789abcdef";
        fromBytes.push_back(hex[extended.serialNumber[i] >> 4]);
        fromBytes.push_back(hex[extended.serialNumber[i] & 0x0F]);
    }
    if (fromText.empty() || fromText.size() > fromBytes.size() ||
        fromBytes.substr(fromBytes.size() - fromText.size()) != fromText ||
        fromBytes.find_first_not_of('0') < fromBytes.size() - fromText.size())
        fail("C_GetTokenInfo and C_EX_GetTokenInfoExtended disagree about the serial number");

    // A caller compiled against a different structure has to be told, not fed
    // a partially filled buffer.
    CK_TOKEN_INFO_EXTENDED mismatched{};
    mismatched.ulSizeofThisStructure = sizeof(mismatched) - 1;
    check(invoke("C_EX_GetTokenInfoExtended", "slotID=0, ulSizeofThisStructure=wrong",
                 [&] { return ex->C_EX_GetTokenInfoExtended(0, &mismatched); }),
          CKR_BUFFER_TOO_SMALL, "C_EX_GetTokenInfoExtended(wrong structure size)");

    // C_EX_GetTokenName. Rutoken Control Center calls it right after
    // C_EX_GetTokenInfoExtended and closes the session if it is refused, so
    // both passes of the two-pass call have to work.
    if ((token.flags & CKF_TOKEN_INITIALIZED) != 0)
    {
        const std::string expected =
            paddedText(token.label, sizeof(token.label));
        CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
        callOk("C_OpenSession", "slotID=0, flags=CKF_SERIAL_SESSION",
               [&] { return module->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr,
                                                  &session); });

        CK_ULONG length = 0;
        callOk("C_EX_GetTokenName", "pLabel=NULL_PTR (the size pass)",
               [&] { return ex->C_EX_GetTokenName(session, nullptr, &length); });
        if (length != expected.size())
            fail("C_EX_GetTokenName reports length " + std::to_string(length) + " where the " +
                 std::to_string(expected.size()) + " of the token's label is expected");

        std::vector<CK_CHAR> name(length + 8, 0);
        CK_ULONG got = static_cast<CK_ULONG>(name.size());
        callOk("C_EX_GetTokenName", "pLabel=&buffer (the value pass)",
               [&] { return ex->C_EX_GetTokenName(session, name.data(), &got); });
        if (got != length ||
            std::string(reinterpret_cast<const char*>(name.data()), got) != expected)
            fail("C_EX_GetTokenName and C_GetTokenInfo disagree about the token's name");

        if (length > 0)
        {
            // Not "small": rpcndr.h, which windows.h drags in, defines that as
            // a macro for char, and the declaration stops being one.
            CK_ULONG tooShort = length - 1;
            check(invoke("C_EX_GetTokenName", "pLabel=&buffer one byte short",
                         [&] { return ex->C_EX_GetTokenName(session, name.data(), &tooShort); }),
                  CKR_BUFFER_TOO_SMALL, "C_EX_GetTokenName(buffer one byte short)");
            if (tooShort != length)
                fail("C_EX_GetTokenName does not report the size a short buffer needed");
        }

        check(invoke("C_EX_GetTokenName", "hSession=CK_INVALID_HANDLE",
                     [&] { return ex->C_EX_GetTokenName(CK_INVALID_HANDLE, name.data(), &got); }),
              CKR_SESSION_HANDLE_INVALID, "C_EX_GetTokenName(bad session)");

        closeSession(module, session);
    }

    // Everything else is advertised but not implemented, and has to say so.
    check(invoke("C_EX_UnblockUserPIN", "hSession=0",
                 [&] { return ex->C_EX_UnblockUserPIN(0); }),
          CKR_FUNCTION_NOT_SUPPORTED, "C_EX_UnblockUserPIN(unimplemented extension)");
    check(invoke("C_EX_FreeBuffer", "pBuffer=NULL_PTR",
                 [&] { return ex->C_EX_FreeBuffer(nullptr); }),
          CKR_FUNCTION_NOT_SUPPORTED, "C_EX_FreeBuffer(unimplemented extension)");
}

static CK_OBJECT_HANDLE createGOSTSecret(Module& module, CK_SESSION_HANDLE session,
                                         CK_KEY_TYPE type, const Bytes& value,
                                         bool wrap = false, bool unwrap = false)
{
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL no = CK_FALSE, yes = CK_TRUE;
    std::vector<CK_ATTRIBUTE> attributes = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &type, sizeof(type)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_VALUE, const_cast<unsigned char*>(value.data()), static_cast<CK_ULONG>(value.size())},
        {CKA_ENCRYPT, &yes, sizeof(yes)},
        {CKA_DECRYPT, &yes, sizeof(yes)},
        {CKA_SIGN, &yes, sizeof(yes)},
        {CKA_VERIFY, &yes, sizeof(yes)},
        {CKA_WRAP, wrap ? &yes : &no, sizeof(yes)},
        {CKA_UNWRAP, unwrap ? &yes : &no, sizeof(yes)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)}
    };
    Bytes gostParameters;
    if (type == CKK_GOST28147)
    {
        gostParameters = bytesFromHex("06072a850302021f01");
        attributes.push_back({CKA_GOST28147_PARAMS, gostParameters.data(),
                              static_cast<CK_ULONG>(gostParameters.size())});
    }
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    callOk("C_CreateObject", "GOST symmetric session key type=" + hexNumber(type),
           [&] { return module->C_CreateObject(session, attributes.data(),
                         static_cast<CK_ULONG>(attributes.size()), &key); });
    return key;
}

static CK_OBJECT_HANDLE generateGOSTSecret(Module& module, CK_SESSION_HANDLE session,
                                           CK_MECHANISM_TYPE mechanismType,
                                           CK_KEY_TYPE type)
{
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL no = CK_FALSE;
    CK_MECHANISM mechanism{mechanismType, nullptr, 0};
    std::vector<CK_ATTRIBUTE> attributes = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &type, sizeof(type)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_PRIVATE, &no, sizeof(no)}
    };
    Bytes gostParameters;
    if (type == CKK_GOST28147)
    {
        gostParameters = bytesFromHex("06072a850302021f01");
        attributes.push_back({CKA_GOST28147_PARAMS, gostParameters.data(),
                              static_cast<CK_ULONG>(gostParameters.size())});
    }
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    callOk("C_GenerateKey", "TC26 symmetric key type=" + hexNumber(type),
           [&] { return module->C_GenerateKey(session, &mechanism, attributes.data(),
                         static_cast<CK_ULONG>(attributes.size()), &key); });
    if (attribute(module, session, key, CKA_VALUE).size() != 32)
        fail("generated TC26 symmetric key is not 256 bits");
    return key;
}

static Bytes encryptOneShot(Module& module, CK_SESSION_HANDLE session,
                            CK_OBJECT_HANDLE key, CK_MECHANISM& mechanism,
                            const Bytes& plain)
{
    callOk("C_EncryptInit", "GOST symmetric known-answer operation",
           [&] { return module->C_EncryptInit(session, &mechanism, key); });
    CK_ULONG length = 0;
    callOk("C_Encrypt", "GOST symmetric length query",
           [&] { return module->C_Encrypt(session, const_cast<unsigned char*>(plain.data()),
                                           static_cast<CK_ULONG>(plain.size()), nullptr, &length); });
    Bytes result(length);
    callOk("C_Encrypt", "GOST symmetric data operation",
           [&] { return module->C_Encrypt(session, const_cast<unsigned char*>(plain.data()),
                                           static_cast<CK_ULONG>(plain.size()), result.data(), &length); });
    result.resize(length);
    return result;
}

static Bytes decryptOneShot(Module& module, CK_SESSION_HANDLE session,
                            CK_OBJECT_HANDLE key, CK_MECHANISM& mechanism,
                            const Bytes& cipherText)
{
    callOk("C_DecryptInit", "GOST symmetric decrypt operation",
           [&] { return module->C_DecryptInit(session, &mechanism, key); });
    CK_ULONG length = static_cast<CK_ULONG>(cipherText.size());
    Bytes result(length);
    callOk("C_Decrypt", "GOST symmetric decrypt data",
           [&] { return module->C_Decrypt(session, const_cast<unsigned char*>(cipherText.data()),
                                           static_cast<CK_ULONG>(cipherText.size()), result.data(), &length); });
    result.resize(length);
    return result;
}

static Bytes signOneShot(Module& module, CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE key, CK_MECHANISM_TYPE mechanismType,
                         const Bytes& data)
{
    CK_MECHANISM mechanism{mechanismType, nullptr, 0};
    callOk("C_SignInit", "GOST symmetric MAC",
           [&] { return module->C_SignInit(session, &mechanism, key); });
    CK_ULONG length = 0;
    callOk("C_Sign", "GOST symmetric MAC length query",
           [&] { return module->C_Sign(session, const_cast<unsigned char*>(data.data()),
                                       static_cast<CK_ULONG>(data.size()), nullptr, &length); });
    Bytes signature(length);
    callOk("C_Sign", "GOST symmetric MAC",
           [&] { return module->C_Sign(session, const_cast<unsigned char*>(data.data()),
                                       static_cast<CK_ULONG>(data.size()), signature.data(), &length); });
    signature.resize(length);
    return signature;
}

static void verifyOneShot(Module& module, CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE key, CK_MECHANISM_TYPE mechanismType,
                          const Bytes& data, const Bytes& signature)
{
    CK_MECHANISM mechanism{mechanismType, nullptr, 0};
    callOk("C_VerifyInit", "GOST symmetric MAC",
           [&] { return module->C_VerifyInit(session, &mechanism, key); });
    callOk("C_Verify", "GOST symmetric MAC",
           [&] { return module->C_Verify(session, const_cast<unsigned char*>(data.data()),
                         static_cast<CK_ULONG>(data.size()),
                         const_cast<unsigned char*>(signature.data()),
                         static_cast<CK_ULONG>(signature.size())); });
}

static void verifyGOSTSymmetric(Module& module, CK_SESSION_HANDLE session)
{
    generateGOSTSecret(module, session, CKM_GOST28147_KEY_GEN, CKK_GOST28147);
    generateGOSTSecret(module, session, CKM_KUZNECHIK_KEY_GEN, CKK_KUZNECHIK);
    generateGOSTSecret(module, session, CKM_MAGMA_KEY_GEN, CKK_MAGMA);

    const Bytes kuzKey = bytesFromHex(
        "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
    const Bytes magmaKey = bytesFromHex(
        "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const CK_OBJECT_HANDLE kuz = createGOSTSecret(module, session, CKK_KUZNECHIK, kuzKey);
    const CK_OBJECT_HANDLE magma = createGOSTSecret(module, session, CKK_MAGMA, magmaKey);

    CK_MECHANISM kuzEcb{CKM_KUZNECHIK_ECB, nullptr, 0};
    const Bytes kuzPlain = bytesFromHex("1122334455667700ffeeddccbbaa9988");
    const Bytes kuzCipher = encryptOneShot(module, session, kuz, kuzEcb, kuzPlain);
    if (kuzCipher != bytesFromHex("7f679d90bebc24305a468d42b9d4edcd") ||
        decryptOneShot(module, session, kuz, kuzEcb, kuzCipher) != kuzPlain)
        fail("CKM_KUZNECHIK_ECB does not match RFC 7801");

    CK_MECHANISM magmaEcb{CKM_MAGMA_ECB, nullptr, 0};
    const Bytes magmaPlain = bytesFromHex("fedcba9876543210");
    const Bytes magmaCipher = encryptOneShot(module, session, magma, magmaEcb, magmaPlain);
    if (magmaCipher != bytesFromHex("4ee901e5c2d8ca3d") ||
        decryptOneShot(module, session, magma, magmaEcb, magmaCipher) != magmaPlain)
        fail("CKM_MAGMA_ECB does not match RFC 8891");

    Bytes mgmKeyBytes = bytesFromHex(
        "99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88");
    const CK_OBJECT_HANDLE mgmKey = createGOSTSecret(module, session, CKK_MAGMA, mgmKeyBytes);
    Bytes icn = bytesFromHex("0077665544332211");
    CK_MGM_PARAMS mgmParams{icn.data(), static_cast<CK_ULONG>(icn.size()), 64,
                            nullptr, 0, 64};
    CK_MECHANISM mgm{CKM_MAGMA_MGM, &mgmParams, sizeof(mgmParams)};
    const Bytes mgmPlain = bytesFromHex("22334455667700ff");
    const Bytes mgmCipher = encryptOneShot(module, session, mgmKey, mgm, mgmPlain);
    if (mgmCipher != bytesFromHex("6a95e1426b259d4e334ee270450bec9e") ||
        decryptOneShot(module, session, mgmKey, mgm, mgmCipher) != mgmPlain)
        fail("CKM_MAGMA_MGM does not match RFC 9058");
    Bytes damaged = mgmCipher;
    damaged.back() ^= 1;
    callOk("C_DecryptInit", "CKM_MAGMA_MGM tampered tag",
           [&] { return module->C_DecryptInit(session, &mgm, mgmKey); });
    CK_ULONG damagedLength = static_cast<CK_ULONG>(damaged.size());
    Bytes damagedOutput(damagedLength);
    check(invoke("C_Decrypt", "CKM_MAGMA_MGM tampered tag",
                 [&] { return module->C_Decrypt(session, damaged.data(),
                             static_cast<CK_ULONG>(damaged.size()), damagedOutput.data(), &damagedLength); }),
          CKR_ENCRYPTED_DATA_INVALID, "C_Decrypt(CKM_MAGMA_MGM tampered tag)");

    Bytes kuzMgmIcn = bytesFromHex("1122334455667700ffeeddccbbaa9988");
    Bytes kuzMgmAad = bytesFromHex(
        "0202020202020202010101010101010104040404040404040303030303030303"
        "ea0505050505050505");
    CK_MGM_PARAMS kuzMgmParams{kuzMgmIcn.data(), static_cast<CK_ULONG>(kuzMgmIcn.size()),
                               128, kuzMgmAad.data(),
                               static_cast<CK_ULONG>(kuzMgmAad.size()), 128};
    CK_MECHANISM kuzMgm{CKM_KUZNECHIK_MGM, &kuzMgmParams, sizeof(kuzMgmParams)};
    const Bytes kuzMgmPlain = bytesFromHex(
        "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"
        "112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011"
        "aabbcc");
    const Bytes kuzMgmExpected = bytesFromHex(
        "a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39"
        "497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb"
        "2c7552cf5d656f40c34f5c46e8bb0e29fcdb4c");
    const Bytes kuzMgmCipher = encryptOneShot(module, session, kuz, kuzMgm, kuzMgmPlain);
    if (kuzMgmCipher != kuzMgmExpected ||
        decryptOneShot(module, session, kuz, kuzMgm, kuzMgmCipher) != kuzMgmPlain)
        fail("CKM_KUZNECHIK_MGM does not match RFC 9058");

    Bytes acpkmParams = bytesFromHex("000000100102030405060708");
    CK_MECHANISM acpkm{CKM_KUZNECHIK_CTR_ACPKM, acpkmParams.data(),
                       static_cast<CK_ULONG>(acpkmParams.size())};
    const Bytes streamPlain = bytesFromHex(
        "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f55");
    const Bytes streamCipher = encryptOneShot(module, session, kuz, acpkm, streamPlain);
    if (decryptOneShot(module, session, kuz, acpkm, streamCipher) != streamPlain)
        fail("CKM_KUZNECHIK_CTR_ACPKM round trip failed");

    const Bytes kuzMacData = bytesFromHex(
        "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"
        "112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011");
    const Bytes kuzMac = signOneShot(module, session, kuz, CKM_KUZNECHIK_MAC, kuzMacData);
    if (kuzMac != bytesFromHex("336f4d296059fbe3"))
        fail("CKM_KUZNECHIK_MAC does not match GOST R 34.13-2015");
    verifyOneShot(module, session, kuz, CKM_KUZNECHIK_MAC, kuzMacData, kuzMac);

    const Bytes magmaMacData = bytesFromHex(
        "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
    const Bytes magmaMac = signOneShot(module, session, magma, CKM_MAGMA_MAC, magmaMacData);
    if (magmaMac != bytesFromHex("154e7210"))
        fail("CKM_MAGMA_MAC does not match GOST R 34.13-2015");
    verifyOneShot(module, session, magma, CKM_MAGMA_MAC, magmaMacData, magmaMac);

    const Bytes gostKeyBytes = bytesFromHex(
        "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1");
    const CK_OBJECT_HANDLE gost = createGOSTSecret(module, session, CKK_GOST28147,
                                                   gostKeyBytes, true, true);
    CK_MECHANISM gostEcb{CKM_GOST28147_ECB, nullptr, 0};
    const Bytes gostPlain = bytesFromHex("1020304050607080");
    const Bytes gostCipher = encryptOneShot(module, session, gost, gostEcb, gostPlain);
    if (gostCipher != bytesFromHex("2685b30ddb497d05") ||
        decryptOneShot(module, session, gost, gostEcb, gostCipher) != gostPlain)
        fail("CKM_GOST28147_ECB does not match the CryptoPro-A vector");

    const Bytes gostCfbKeyBytes = bytesFromHex(
        "8d5a2c83a7c70a61d61b34b51fdf42686671a35d874cfd84993663b61ed60dad");
    const CK_OBJECT_HANDLE gostCfbKey = createGOSTSecret(module, session, CKK_GOST28147,
                                                         gostCfbKeyBytes);
    Bytes gostCfbIv = bytesFromHex("46606f0d8834235a");
    CK_MECHANISM gostCfb{CKM_GOST28147, gostCfbIv.data(),
                         static_cast<CK_ULONG>(gostCfbIv.size())};
    const Bytes gostCfbPlain = bytesFromHex("d2fdf83ac1b439232eaacc980a02da33");
    const Bytes gostCfbCipher = encryptOneShot(module, session, gostCfbKey, gostCfb,
                                               gostCfbPlain);
    if (gostCfbCipher != bytesFromHex("88b7751674a5ee2d14fe9167d05ccc40") ||
        decryptOneShot(module, session, gostCfbKey, gostCfb, gostCfbCipher) != gostCfbPlain)
        fail("CKM_GOST28147 CFB does not match the CryptoPro-A vector");

    const Bytes gostMacKeyBytes = bytesFromHex(
        "9d05b79e90cad00a2cdad22ef4e86f5cf5dc37681985b3bfaa18c1c3050a91a2");
    const CK_OBJECT_HANDLE gostMacKey = createGOSTSecret(module, session, CKK_GOST28147,
                                                         gostMacKeyBytes);
    const Bytes gostMacData = bytesFromHex("b5a1f0e3ce2f021d676194345c41e36e");
    const Bytes gostMac = signOneShot(module, session, gostMacKey, CKM_GOST28147_MAC,
                                      gostMacData);
    if (gostMac != bytesFromHex("f81f08a3"))
        fail("CKM_GOST28147_MAC does not match the CryptoPro-A vector");
    verifyOneShot(module, session, gostMacKey, CKM_GOST28147_MAC, gostMacData, gostMac);

    const Bytes twinBytes = bytesFromHex(
        "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
        "ffeeddccbbaa998877665544332211000123456789abcdef1032547698badcfe");
    const CK_OBJECT_HANDLE twin = createGOSTSecret(module, session,
                                                   CKK_KUZNECHIK_TWIN_KEY,
                                                   twinBytes, true, true);
    Bytes ukm = bytesFromHex("1234567890abcdef");
    CK_MECHANISM kexp{CKM_KUZNECHIK_KEXP_15_WRAP, ukm.data(),
                      static_cast<CK_ULONG>(ukm.size())};
    CK_ULONG wrappedLength = 0;
    callOk("C_WrapKey", "CKM_KUZNECHIK_KEXP_15_WRAP length query",
           [&] { return module->C_WrapKey(session, &kexp, twin, kuz, nullptr, &wrappedLength); });
    if (wrappedLength != 48) fail("Kuznechik KExp15 returned an unexpected length");
    Bytes wrapped(wrappedLength);
    callOk("C_WrapKey", "CKM_KUZNECHIK_KEXP_15_WRAP",
           [&] { return module->C_WrapKey(session, &kexp, twin, kuz,
                                           wrapped.data(), &wrappedLength); });
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE kuzType = CKK_KUZNECHIK;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE unwrapTemplate[] = {
        {CKA_CLASS, &secretClass, sizeof(secretClass)},
        {CKA_KEY_TYPE, &kuzType, sizeof(kuzType)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_PRIVATE, &no, sizeof(no)}
    };
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    callOk("C_UnwrapKey", "CKM_KUZNECHIK_KEXP_15_WRAP",
           [&] { return module->C_UnwrapKey(session, &kexp, twin, wrapped.data(),
                         static_cast<CK_ULONG>(wrapped.size()), unwrapTemplate,
                         sizeof(unwrapTemplate) / sizeof(unwrapTemplate[0]), &unwrapped); });
    if (attribute(module, session, unwrapped, CKA_VALUE) != kuzKey)
        fail("Kuznechik KExp15 did not restore the wrapped key");
    wrapped.back() ^= 1;
    check(invoke("C_UnwrapKey", "CKM_KUZNECHIK_KEXP_15_WRAP tampered tag",
                 [&] { return module->C_UnwrapKey(session, &kexp, twin, wrapped.data(),
                             static_cast<CK_ULONG>(wrapped.size()), unwrapTemplate,
                             sizeof(unwrapTemplate) / sizeof(unwrapTemplate[0]), &unwrapped); }),
          CKR_WRAPPED_KEY_INVALID, "C_UnwrapKey(KExp15 tampered tag)");

    const CK_OBJECT_HANDLE magmaTwin = createGOSTSecret(module, session,
                                                        CKK_MAGMA_TWIN_KEY,
                                                        twinBytes, true, true);
    Bytes magmaUkm = bytesFromHex("12345678");
    CK_MECHANISM magmaKexp{CKM_MAGMA_KEXP_15_WRAP, magmaUkm.data(),
                           static_cast<CK_ULONG>(magmaUkm.size())};
    wrappedLength = 0;
    callOk("C_WrapKey", "CKM_MAGMA_KEXP_15_WRAP length query",
           [&] { return module->C_WrapKey(session, &magmaKexp, magmaTwin, magma,
                                           nullptr, &wrappedLength); });
    if (wrappedLength != 40) fail("Magma KExp15 returned an unexpected length");
    Bytes magmaWrapped(wrappedLength);
    callOk("C_WrapKey", "CKM_MAGMA_KEXP_15_WRAP",
           [&] { return module->C_WrapKey(session, &magmaKexp, magmaTwin, magma,
                                           magmaWrapped.data(), &wrappedLength); });
    CK_KEY_TYPE magmaType = CKK_MAGMA;
    unwrapTemplate[1] = {CKA_KEY_TYPE, &magmaType, sizeof(magmaType)};
    unwrapped = CK_INVALID_HANDLE;
    callOk("C_UnwrapKey", "CKM_MAGMA_KEXP_15_WRAP",
           [&] { return module->C_UnwrapKey(session, &magmaKexp, magmaTwin,
                         magmaWrapped.data(), static_cast<CK_ULONG>(magmaWrapped.size()),
                         unwrapTemplate, sizeof(unwrapTemplate) / sizeof(unwrapTemplate[0]),
                         &unwrapped); });
    if (attribute(module, session, unwrapped, CKA_VALUE) != magmaKey)
        fail("Magma KExp15 did not restore the wrapped key");

    const Bytes genericKeyBytes = bytesFromHex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const CK_OBJECT_HANDLE genericKey = createGOSTSecret(module, session,
                                                          CKK_GENERIC_SECRET,
                                                          genericKeyBytes);
    wrappedLength = 0;
    callOk("C_WrapKey", "CKM_KUZNECHIK_KEXP_15_WRAP generic-secret length query",
           [&] { return module->C_WrapKey(session, &kexp, twin, genericKey,
                                           nullptr, &wrappedLength); });
    Bytes genericWrapped(wrappedLength);
    callOk("C_WrapKey", "CKM_KUZNECHIK_KEXP_15_WRAP generic secret",
           [&] { return module->C_WrapKey(session, &kexp, twin, genericKey,
                                           genericWrapped.data(), &wrappedLength); });
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    unwrapTemplate[1] = {CKA_KEY_TYPE, &genericType, sizeof(genericType)};
    unwrapped = CK_INVALID_HANDLE;
    callOk("C_UnwrapKey", "CKM_KUZNECHIK_KEXP_15_WRAP generic secret",
           [&] { return module->C_UnwrapKey(session, &kexp, twin, genericWrapped.data(),
                         static_cast<CK_ULONG>(genericWrapped.size()), unwrapTemplate,
                         sizeof(unwrapTemplate) / sizeof(unwrapTemplate[0]), &unwrapped); });
    if (attribute(module, session, unwrapped, CKA_VALUE) != genericKeyBytes)
        fail("Kuznechik KExp15 did not restore CKK_GENERIC_SECRET");

    const Bytes wrappedGostKeyBytes = bytesFromHex(
        "ffeeddccbbaa99887766554433221100112233445566778899aabbccddeeff00");
    const CK_OBJECT_HANDLE wrappedGostKey = createGOSTSecret(module, session,
                                                              CKK_GOST28147,
                                                              wrappedGostKeyBytes);
    CK_MECHANISM gostWrap{CKM_GOST28147_KEY_WRAP, nullptr, 0};
    wrappedLength = 0;
    callOk("C_WrapKey", "CKM_GOST28147_KEY_WRAP length query",
           [&] { return module->C_WrapKey(session, &gostWrap, gost, wrappedGostKey,
                                           nullptr, &wrappedLength); });
    if (wrappedLength != 36) fail("GOST 28147 key wrap returned an unexpected length");
    Bytes gostWrapped(wrappedLength);
    callOk("C_WrapKey", "CKM_GOST28147_KEY_WRAP",
           [&] { return module->C_WrapKey(session, &gostWrap, gost, wrappedGostKey,
                                           gostWrapped.data(), &wrappedLength); });
    CK_KEY_TYPE gostType = CKK_GOST28147;
    Bytes unwrapGostParameters = bytesFromHex("06072a850302021f01");
    CK_ATTRIBUTE gostUnwrapTemplate[] = {
        {CKA_CLASS, &secretClass, sizeof(secretClass)},
        {CKA_KEY_TYPE, &gostType, sizeof(gostType)},
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_GOST28147_PARAMS, unwrapGostParameters.data(),
         static_cast<CK_ULONG>(unwrapGostParameters.size())}
    };
    unwrapped = CK_INVALID_HANDLE;
    callOk("C_UnwrapKey", "CKM_GOST28147_KEY_WRAP",
           [&] { return module->C_UnwrapKey(session, &gostWrap, gost, gostWrapped.data(),
                         static_cast<CK_ULONG>(gostWrapped.size()), gostUnwrapTemplate,
                         sizeof(gostUnwrapTemplate) / sizeof(gostUnwrapTemplate[0]), &unwrapped); });
    if (attribute(module, session, unwrapped, CKA_VALUE) != wrappedGostKeyBytes)
        fail("GOST 28147 key wrap did not restore the wrapped key");
    gostWrapped.back() ^= 1;
    check(invoke("C_UnwrapKey", "CKM_GOST28147_KEY_WRAP tampered MAC",
                 [&] { return module->C_UnwrapKey(session, &gostWrap, gost, gostWrapped.data(),
                             static_cast<CK_ULONG>(gostWrapped.size()), gostUnwrapTemplate,
                             sizeof(gostUnwrapTemplate) / sizeof(gostUnwrapTemplate[0]), &unwrapped); }),
          CKR_WRAPPED_KEY_INVALID, "C_UnwrapKey(GOST 28147 tampered MAC)");

    trace("REFERENCE", "GOST 28147, Kuznechik and Magma PKCS #11 encryption, MGM and KExp15 verified");
}

static void verifyRutokenProfile(const fs::path& modulePath)
{
    Module module(modulePath);
    CK_INFO library{};
    callOk("C_GetInfo", "pInfo=&library", [&] { return module->C_GetInfo(&library); });
    if (library.cryptokiVersion.major != 2 || library.cryptokiVersion.minor != 40 ||
        paddedText(library.manufacturerID, sizeof(library.manufacturerID)) != "Aktiv Co." ||
        paddedText(library.libraryDescription, sizeof(library.libraryDescription)) !=
            "Rutoken ECP PKCS #11 library" ||
        library.libraryVersion.major != 2 || library.libraryVersion.minor != 19)
        fail("C_GetInfo does not match the Rutoken ECP 2.19 reference profile");

    const std::vector<CK_SLOT_ID> allSlots = slots(module, CK_FALSE);
    const std::vector<CK_SLOT_ID> presentSlots = slots(module, CK_TRUE);
    if (allSlots.size() != 15 || presentSlots != std::vector<CK_SLOT_ID>{0})
        fail("Rutoken profile must expose slots 0..14 with a token only in slot 0");
    for (size_t i = 0; i < allSlots.size(); ++i)
        if (allSlots[i] != static_cast<CK_SLOT_ID>(i)) fail("Rutoken slot IDs are not contiguous 0..14");

    CK_SLOT_INFO slot{};
    callOk("C_GetSlotInfo", "slotID=0, pInfo=&slot", [&] { return module->C_GetSlotInfo(0, &slot); });
    if (paddedText(slot.slotDescription, sizeof(slot.slotDescription)) != "Aktiv Rutoken ECP 0" ||
        paddedText(slot.manufacturerID, sizeof(slot.manufacturerID)) != "Aktiv Co." ||
        (slot.flags & (CKF_HW_SLOT | CKF_REMOVABLE_DEVICE | CKF_TOKEN_PRESENT)) !=
            (CKF_HW_SLOT | CKF_REMOVABLE_DEVICE | CKF_TOKEN_PRESENT) ||
        slot.hardwareVersion.major != 60 || slot.hardwareVersion.minor != 1 ||
        slot.firmwareVersion.major != 30 || slot.firmwareVersion.minor != 2)
        fail("slot 0 information does not match the Rutoken ECP reference profile");

    const CK_TOKEN_INFO token = tokenInfo(module, 0);
    const std::string serial = paddedText(reinterpret_cast<const unsigned char*>(token.serialNumber),
                                          sizeof(token.serialNumber));
    // A Rutoken with no label of its own reports "Rutoken ECP <no label>"; a
    // labelled one reports its label.  The caller states which of the two the
    // backing store should produce.
    const std::string expectedLabel = environment("P11_PROFILE_EXPECTED_LABEL").empty() ?
        configuredTokenLabel() : environment("P11_PROFILE_EXPECTED_LABEL");
    if (paddedText(token.label, sizeof(token.label)) != expectedLabel ||
        paddedText(token.manufacturerID, sizeof(token.manufacturerID)) != "Aktiv Co." ||
        paddedText(reinterpret_cast<const unsigned char*>(token.model), sizeof(token.model)) != "Rutoken ECP" ||
        serial.size() != 8 || !std::all_of(serial.begin(), serial.end(), [](char c) {
            return c >= '0' && c <= '9';
        }) || token.ulMinPinLen != 6 || token.ulMaxPinLen != 249 ||
        token.hardwareVersion.major != 60 || token.hardwareVersion.minor != 1 ||
        token.firmwareVersion.major != 30 || token.firmwareVersion.minor != 2)
        fail("token information does not match the Rutoken ECP reference profile");
    if ((token.flags & (CKF_RNG | CKF_LOGIN_REQUIRED)) != (CKF_RNG | CKF_LOGIN_REQUIRED) ||
        (token.flags & (CKF_SO_PIN_TO_BE_CHANGED | CKF_USER_PIN_TO_BE_CHANGED)) != 0)
        fail("Rutoken token flags differ from the reference device");

    CK_TOKEN_INFO absent{};
    check(invoke("C_GetTokenInfo", "slotID=1, pInfo=&absent",
                 [&] { return module->C_GetTokenInfo(1, &absent); }),
          CKR_TOKEN_NOT_PRESENT, "C_GetTokenInfo(empty Rutoken slot)");

    CK_ULONG mechanismCount = 0;
    callOk("C_GetMechanismList", "slotID=0, pMechanismList=NULL_PTR, pulCount=&count",
           [&] { return module->C_GetMechanismList(0, nullptr, &mechanismCount); });
    std::vector<CK_MECHANISM_TYPE> mechanisms(mechanismCount);
    callOk("C_GetMechanismList", "slotID=0, pMechanismList=buffer, pulCount=&count",
           [&] { return module->C_GetMechanismList(0, mechanisms.data(), &mechanismCount); });
    // The whole mechanism list of a reference Rutoken ECP, in its order and
    // with its key sizes and flags.  Applications decide compatibility from
    // this list, so the profile reproduces it exactly, including mechanisms
    // this build does not implement yet; calling one of those still fails.
    static const struct { CK_MECHANISM_TYPE type; CK_ULONG minKeySize, maxKeySize; CK_FLAGS flags; } reference[] = {
        {CKM_RSA_PKCS_KEY_PAIR_GEN, 512, 4096,
         CKF_HW | CKF_GENERATE_KEY_PAIR},
        {CKM_RSA_PKCS, 512, 4096,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY},
        {CKM_RSA_X_509, 512, 4096,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY},
        {CKM_RSA_PKCS_OAEP, 512, 4096,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
        {CKM_RSA_PKCS_PSS, 512, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_MD5_RSA_PKCS, 512, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_SHA1_RSA_PKCS, 512, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_SHA224_RSA_PKCS, 512, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_SHA256_RSA_PKCS, 512, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_SHA384_RSA_PKCS, 768, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_SHA512_RSA_PKCS, 768, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_SHA1_RSA_PKCS_PSS, 512, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_SHA224_RSA_PKCS_PSS, 512, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_SHA256_RSA_PKCS_PSS, 512, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_SHA384_RSA_PKCS_PSS, 768, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_SHA512_RSA_PKCS_PSS, 768, 4096,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_MD5, 0, 0,
         CKF_DIGEST},
        {CKM_SHA_1, 0, 0,
         CKF_DIGEST},
        {CKM_SHA224, 0, 0,
         CKF_DIGEST},
        {CKM_SHA256, 0, 0,
         CKF_DIGEST},
        {CKM_SHA384, 0, 0,
         CKF_DIGEST},
        {CKM_SHA512, 0, 0,
         CKF_DIGEST},
        {CKM_GOSTR3410_KEY_PAIR_GEN, 0, 0,
         CKF_HW | CKF_GENERATE_KEY_PAIR},
        {CKM_GOSTR3410, 0, 0,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_GOSTR3410_DERIVE, 0, 0,
         CKF_HW | CKF_DERIVE},
        {CKM_GOSTR3410_512_KEY_PAIR_GEN, 0, 0,
         CKF_HW | CKF_GENERATE_KEY_PAIR},
        {CKM_GOSTR3410_512, 0, 0,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_GOSTR3410_12_DERIVE, 0, 0,
         CKF_HW | CKF_DERIVE},
        {0xD4321038UL, 0, 0,
         CKF_HW | CKF_DERIVE},
        {CKM_GOSTR3411, 0, 0,
         CKF_HW | CKF_DIGEST},
        {CKM_GOSTR3411_12_256, 0, 0,
         CKF_HW | CKF_DIGEST},
        {CKM_GOSTR3411_12_512, 0, 0,
         CKF_HW | CKF_DIGEST},
        {CKM_GOSTR3410_WITH_GOSTR3411, 0, 0,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_GOSTR3410_WITH_GOSTR3411_12_256, 0, 0,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_GOSTR3410_WITH_GOSTR3411_12_512, 0, 0,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_GOST28147_KEY_WRAP, 0, 0,
         CKF_HW | CKF_WRAP | CKF_UNWRAP},
        {CKM_GOST28147_ECB, 0, 0,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
        {0x8000000BUL, 0, 0,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
        {CKM_GOST28147, 0, 0,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
        {CKM_GOST28147_KEY_GEN, 0, 0,
         CKF_HW | CKF_GENERATE},
        {CKM_GOST28147_MAC, 0, 0,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {0xD4321034UL, 0, 0,
         CKF_HW | CKF_GENERATE},
        {0xD4321030UL, 0, 0,
         CKF_HW | CKF_GENERATE},
        {0xD4321035UL, 0, 0,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
        {0xD4321031UL, 0, 0,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
        {0xD4321036UL, 0, 0,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
        {0xD4321032UL, 0, 0,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
        {0xD432102EUL, 0, 0,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
        {0xD432102DUL, 0, 0,
         CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
        {0xD4321037UL, 0, 0,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {0xD4321033UL, 0, 0,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_GOSTR3411_12_256_HMAC, 0, 0,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_GOSTR3411_12_512_HMAC, 0, 0,
         CKF_HW | CKF_SIGN | CKF_VERIFY},
        {CKM_GOSTR3411_HMAC, 0, 0,
         CKF_SIGN | CKF_VERIFY},
        {CKM_ECDSA_KEY_PAIR_GEN, 256, 256,
         CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
        {CKM_ECDSA, 256, 256,
         CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
        {CKM_ECDSA_SHA1, 256, 256,
         CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
        {CKM_ECDSA_SHA224, 256, 256,
         CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
        {CKM_ECDSA_SHA256, 256, 256,
         CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
        {CKM_ECDSA_SHA384, 256, 256,
         CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
        {CKM_ECDSA_SHA512, 256, 256,
         CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
        {0xD4321028UL, 0, 0,
         CKF_HW | CKF_DERIVE},
        {CKM_CONCATENATE_BASE_AND_KEY, 0, 0,
         CKF_HW | CKF_DERIVE},
        {0xD432102AUL, 0, 0,
         CKF_HW | CKF_DERIVE},
        {CKM_GOST_KEG, 0, 0,
         CKF_HW | CKF_DERIVE},
        {CKM_ECDH1_DERIVE, 255, 512,
         CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
        {0xD432102BUL, 0, 0,
         CKF_HW | CKF_WRAP | CKF_UNWRAP},
        {0xD432102CUL, 0, 0,
         CKF_HW | CKF_WRAP | CKF_UNWRAP},
        {0x80000003UL, 0, 0,
         CKF_HW | CKF_UNWRAP},
        {CKM_GENERIC_SECRET_KEY_GEN, 80, 2048,
         CKF_GENERATE | CKF_GENERATE_KEY_PAIR | CKF_DERIVE},
    };
    const size_t referenceCount = sizeof(reference) / sizeof(reference[0]);
    if (mechanisms.size() != referenceCount)
        fail("Rutoken profile advertises " + std::to_string(mechanisms.size()) +
             " mechanisms instead of the reference " + std::to_string(referenceCount));
    for (size_t i = 0; i < referenceCount; ++i)
    {
        if (mechanisms[i] != reference[i].type)
            fail("Rutoken mechanism " + std::to_string(i) + " is " + hexNumber(mechanisms[i]) +
                 " where the reference device reports " + hexNumber(reference[i].type));
        CK_MECHANISM_INFO info{};
        callOk("C_GetMechanismInfo", "slotID=0, type=" + hexNumber(mechanisms[i]) + ", pInfo=&info",
               [&] { return module->C_GetMechanismInfo(0, mechanisms[i], &info); });
        if (info.ulMinKeySize != reference[i].minKeySize ||
            info.ulMaxKeySize != reference[i].maxKeySize || info.flags != reference[i].flags)
            fail("Rutoken mechanism " + hexNumber(mechanisms[i]) +
                 " metadata differs from the reference device");
    }
    CK_MECHANISM_INFO absentMechanism{};
    check(invoke("C_GetMechanismInfo", "slotID=0, type=CKM_AES_KEY_GEN, pInfo=&info",
                 [&] { return module->C_GetMechanismInfo(0, CKM_AES_KEY_GEN, &absentMechanism); }),
          CKR_MECHANISM_INVALID, "C_GetMechanismInfo(mechanism absent from the reference device)");

    verifyRutokenExtension(module, token);

    if ((token.flags & CKF_TOKEN_INITIALIZED) != 0)
    {
        // Needs a session, and SoftHSM opens none on a token that was never
        // initialized - so this part only runs where a token exists.
        verifyRutokenHardwareFeature(module);

        CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
        callOk("C_OpenSession", "slotID=0, flags=CKF_SERIAL_SESSION|CKF_RW_SESSION",
               [&] { return module->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                                  nullptr, nullptr, &session); });
        CK_SESSION_INFO sessionInfo{};
        callOk("C_GetSessionInfo", "hSession=session, pInfo=&sessionInfo",
               [&] { return module->C_GetSessionInfo(session, &sessionInfo); });
        if (sessionInfo.slotID != 0) fail("Rutoken facade leaked its backing SoftHSM slot ID");

        const std::string userPin = environment("P11_TEST_USER_PIN", true);
        login(module, session, CKU_USER, userPin);
        verifyGOSTSymmetric(module, session);
        logout(module, session, "CKU_USER");

        closeSession(module, session);
    }
    std::cout << "Rutoken ECP compatibility profile verified\n";
}

int main(int argc, char** argv)
{
    try
    {
        if (argc == 3 && std::string(argv[1]) == "probe")
        {
            Module module(fs::absolute(argv[2]));
            (void)slots(module, CK_FALSE);
            std::cout << "PKCS #11 module initialized and enumerated successfully\n";
            return 0;
        }
        if (argc == 3 && std::string(argv[1]) == "rutoken-profile")
        {
            verifyRutokenProfile(fs::absolute(argv[2]));
            return 0;
        }
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
        if (argc == 3 && std::string(argv[1]) == "ready")
        {
            verifyReadyToken(fs::absolute(argv[2]));
            return 0;
        }
        if (argc == 3 && std::string(argv[1]) == "core-behaviour")
        {
            verifyCoreBehaviour(fs::absolute(argv[2]));
            return 0;
        }
        std::cerr << "usage:\n"
                  << "  portable-token-e2e probe <module>\n"
                  << "  portable-token-e2e rutoken-profile <module>\n"
                  << "  portable-token-e2e prepare <module> <work>\n"
                  << "  portable-token-e2e finish <module> <work> <leaf.der> <ca.der> <payload> <cms.der>\n"
                  << "  portable-token-e2e ready <module>\n"
                  << "  portable-token-e2e core-behaviour <module>\n"
                  << "environment:\n"
                  << "  P11_TEST_USER_PIN=<required secret>\n"
                  << "  P11_TEST_INITIALIZE_TOKEN=YES|NO (default NO)\n"
                  << "  P11_TEST_SO_PIN=<required only when initialization is YES>\n"
                  << "  P11_TEST_EXCLUDE_FUNCTIONS=<optional comma-separated C_* names>\n"
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
