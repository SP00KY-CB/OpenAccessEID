// File: EIDMigrate/FileCrypto.cpp
// File encryption/decryption and JSON serialization

#include "FileCrypto.h"
#include "CryptoHelpers.h"
#include "AuditLogging.h"
#include "Tracing.h"
#include "Utils.h"
#include "JsonHelper.h"
#include <fstream>
#include <sstream>
#include <vector>

// Forward declarations from StoredCredentialManagement
extern EID_PRIVATE_DATA_TYPE GetEncryptionTypeFromStoredData(const BYTE* pbStoredData, DWORD cbStoredData);

// Overwrite the characters of a std::string holding secret material (decrypted
// JSON, Base64 of an encrypted password or key) before it is released.
static void WipeString(_Inout_ std::string& s) noexcept
{
    if (!s.empty())
        SecureZeroMemory(&s[0], s.size());
    s.clear();
}

namespace
{
    // Wipes the referenced string on scope exit, so every early return is covered.
    class ScopedStringWipe
    {
    public:
        explicit ScopedStringWipe(_Inout_ std::string& s) noexcept : m_s(s) {}
        ~ScopedStringWipe() { WipeString(m_s); }
        ScopedStringWipe(const ScopedStringWipe&) = delete;
        ScopedStringWipe& operator=(const ScopedStringWipe&) = delete;
    private:
        std::string& m_s;
    };
}

// Convert CredentialInfo to JSON
std::string CredentialToJson(_In_ const CredentialInfo& info)
{
    JsonBuilder builder;

    // Create credential object
    builder.startObject();
    builder.add("username", WideToUtf8(info.wsUsername));
    builder.add("sid", WideToUtf8(info.wsSid));
    builder.add("rid", static_cast<int>(info.dwRid));

    // Certificate hash as hex string
    std::string hashHex = BytesToHex(info.CertificateHash, CERT_HASH_LENGTH);
    builder.add("certificateHash", hashHex);

    // Certificate as Base64
    std::string certBase64 = EncodeBase64(info.Certificate.data(),
        static_cast<DWORD>(info.Certificate.size()));
    builder.add("certificate", certBase64);

    // Encryption type
    const char* encryptType = "unknown";  // NOSONAR - DEADSTORE-01: default value retained as safe fallback
    switch (info.EncryptionType)
    {  // NOSONAR - ENUM-01: explicit enum qualifiers retained for clarity
    case EID_PRIVATE_DATA_TYPE::eidpdtClearText:
        encryptType = "cleartext";
        break;
    case EID_PRIVATE_DATA_TYPE::eidpdtCrypted:
        encryptType = "certificate";
        break;
    case EID_PRIVATE_DATA_TYPE::eidpdtDPAPI:
        encryptType = "dpapi";
        break;
    }
    builder.add("encryptionType", encryptType);

    // Encrypted password
    if (!info.EncryptedPassword.empty())
    {
        std::string pwdBase64 = EncodeBase64(info.EncryptedPassword.data(),
            static_cast<DWORD>(info.EncryptedPassword.size()));
        builder.add("encryptedPassword", pwdBase64);
        WipeString(pwdBase64);
    }

    // Symmetric key (only for certificate encryption)
    if (!info.SymmetricKey.empty())
    {
        std::string keyBase64 = EncodeBase64(info.SymmetricKey.data(),
            static_cast<DWORD>(info.SymmetricKey.size()));
        builder.add("symmetricKey", keyBase64);
        WipeString(keyBase64);
    }

    builder.add("algorithm", WideToUtf8(info.wsAlgorithm));

    // Metadata
    builder.startObject("metadata");
    if (info.dwPasswordLength > 0)
        builder.add("passwordLength", static_cast<int>(info.dwPasswordLength));

    if (!info.wsCertSubject.empty())
        builder.add("certificateSubject", WideToUtf8(info.wsCertSubject));

    if (!info.wsCertIssuer.empty())
        builder.add("certificateIssuer", WideToUtf8(info.wsCertIssuer));

    // Timestamps
    if (info.ftCertValidFrom.dwHighDateTime || info.ftCertValidFrom.dwLowDateTime)
        builder.add("certificateValidFrom", WideToUtf8(FormatTimestamp(info.ftCertValidFrom)));

    if (info.ftCertValidTo.dwHighDateTime || info.ftCertValidTo.dwLowDateTime)
        builder.add("certificateValidTo", WideToUtf8(FormatTimestamp(info.ftCertValidTo)));

    builder.endObject(); // metadata

    return builder.build();
}

// Convert GroupInfo to JSON
std::string GroupToJson(_In_ const GroupInfo& group)
{
    JsonBuilder builder;

    builder.startObject();
    builder.add("name", WideToUtf8(group.wsName));
    builder.add("comment", WideToUtf8(group.wsComment));
    // Serialise as a JSON boolean: a BOOL would pick add(int) and become a
    // Number, which the type-checked asBool() on import reads as false.
    builder.add("isBuiltin", group.fBuiltin != FALSE);

    // Members array
    JsonArray membersArray;
    for (const auto& member : group.wsMembers)
    {
        membersArray.push_back(std::make_shared<JsonValue>(WideToUtf8(member)));
    }
    builder.add("members", membersArray);

    return builder.build();
}

// Convert ExportFileData to complete JSON
std::string ExportDataToJson(_In_ const ExportFileData& data)
{
    // Build the JSON structure directly
    JsonObject rootObj;

    rootObj["version"] = std::make_shared<JsonValue>(static_cast<int>(data.dwVersion));
    rootObj["formatVersion"] = std::make_shared<JsonValue>(data.formatVersion);
    rootObj["exportDate"] = std::make_shared<JsonValue>(data.exportDate);
    rootObj["sourceMachine"] = std::make_shared<JsonValue>(WideToUtf8(data.wsSourceMachine));
    rootObj["exportedBy"] = std::make_shared<JsonValue>(WideToUtf8(data.wsExportedBy));

    // Build credentials array
    JsonArray credsArray;
    for (const auto& cred : data.credentials)
    {
        // Create credential object directly
        JsonObject credObj;

        credObj["username"] = std::make_shared<JsonValue>(WideToUtf8(cred.wsUsername));
        credObj["sid"] = std::make_shared<JsonValue>(WideToUtf8(cred.wsSid));
        credObj["rid"] = std::make_shared<JsonValue>(static_cast<int>(cred.dwRid));

        // Certificate hash as hex string
        std::string hashHex = BytesToHex(cred.CertificateHash, CERT_HASH_LENGTH);
        credObj["certificateHash"] = std::make_shared<JsonValue>(hashHex);

        // Certificate as Base64
        std::string certBase64 = EncodeBase64(cred.Certificate.data(),
            static_cast<DWORD>(cred.Certificate.size()));
        credObj["certificate"] = std::make_shared<JsonValue>(certBase64);

        // Encryption type
        const char* encryptType = "unknown";  // NOSONAR - DEADSTORE-01: default value retained as safe fallback
        switch (cred.EncryptionType)
        {  // NOSONAR - ENUM-01: explicit enum qualifiers retained for clarity
        case EID_PRIVATE_DATA_TYPE::eidpdtClearText:
            encryptType = "cleartext";
            break;
        case EID_PRIVATE_DATA_TYPE::eidpdtCrypted:
            encryptType = "certificate";
            break;
        case EID_PRIVATE_DATA_TYPE::eidpdtDPAPI:
            encryptType = "dpapi";
            break;
        }
        credObj["encryptionType"] = std::make_shared<JsonValue>(encryptType);

        // Encrypted password
        if (!cred.EncryptedPassword.empty())
        {
            std::string pwdBase64 = EncodeBase64(cred.EncryptedPassword.data(),
                static_cast<DWORD>(cred.EncryptedPassword.size()));
            credObj["encryptedPassword"] = std::make_shared<JsonValue>(pwdBase64);
            WipeString(pwdBase64);
        }

        // Symmetric key
        if (!cred.SymmetricKey.empty())
        {
            std::string keyBase64 = EncodeBase64(cred.SymmetricKey.data(),
                static_cast<DWORD>(cred.SymmetricKey.size()));
            credObj["symmetricKey"] = std::make_shared<JsonValue>(keyBase64);
            WipeString(keyBase64);
        }

        credObj["algorithm"] = std::make_shared<JsonValue>(WideToUtf8(cred.wsAlgorithm));

        // Metadata object
        JsonObject metaObj;
        if (cred.dwPasswordLength > 0)
            metaObj["passwordLength"] = std::make_shared<JsonValue>(static_cast<int>(cred.dwPasswordLength));
        if (!cred.wsCertSubject.empty())
            metaObj["certificateSubject"] = std::make_shared<JsonValue>(WideToUtf8(cred.wsCertSubject));
        if (!cred.wsCertIssuer.empty())
            metaObj["certificateIssuer"] = std::make_shared<JsonValue>(WideToUtf8(cred.wsCertIssuer));
        if (cred.ftCertValidFrom.dwHighDateTime || cred.ftCertValidFrom.dwLowDateTime)
            metaObj["certificateValidFrom"] = std::make_shared<JsonValue>(WideToUtf8(FormatTimestamp(cred.ftCertValidFrom)));
        if (cred.ftCertValidTo.dwHighDateTime || cred.ftCertValidTo.dwLowDateTime)
            metaObj["certificateValidTo"] = std::make_shared<JsonValue>(WideToUtf8(FormatTimestamp(cred.ftCertValidTo)));

        if (!metaObj.members().empty())
            credObj["metadata"] = std::make_shared<JsonValue>(metaObj);

        credsArray.push_back(std::make_shared<JsonValue>(credObj));
    }
    rootObj["credentials"] = std::make_shared<JsonValue>(credsArray);

    // Build groups array
    JsonArray groupsArray;
    for (const auto& group : data.groups)
    {
        JsonObject groupObj;
        groupObj["name"] = std::make_shared<JsonValue>(WideToUtf8(group.wsName));
        groupObj["comment"] = std::make_shared<JsonValue>(WideToUtf8(group.wsComment));
        groupObj["isBuiltin"] = std::make_shared<JsonValue>(group.fBuiltin != FALSE);  // JSON boolean, not Number

        JsonArray membersArray;
        for (const auto& member : group.wsMembers)
        {
            membersArray.push_back(std::make_shared<JsonValue>(WideToUtf8(member)));
        }
        groupObj["members"] = std::make_shared<JsonValue>(membersArray);

        groupsArray.push_back(std::make_shared<JsonValue>(groupObj));
    }
    rootObj["groups"] = std::make_shared<JsonValue>(groupsArray);

    // Statistics object
    JsonObject statsObj;
    statsObj["totalCredentials"] = std::make_shared<JsonValue>(static_cast<int>(data.stats.totalCredentials));
    statsObj["certificateEncrypted"] = std::make_shared<JsonValue>(static_cast<int>(data.stats.certificateEncrypted));
    statsObj["dpapiEncrypted"] = std::make_shared<JsonValue>(static_cast<int>(data.stats.dpapiEncrypted));
    statsObj["skipped"] = std::make_shared<JsonValue>(static_cast<int>(data.stats.skipped));
    rootObj["statistics"] = std::make_shared<JsonValue>(statsObj);

    // Convert to string
    JsonValue rootValue(rootObj);
    return rootValue.stringify();
}

// Parse JSON to CredentialInfo
HRESULT JsonToCredential(_In_ const std::string& json, _Out_ CredentialInfo& info)
{
    JsonParser parser(json);
    std::shared_ptr<JsonValue> root = parser.parse();

    if (!root || root->type() != JsonType::Object)
        return E_INVALIDARG;

    const JsonObject& obj = root->asObject();

    // Extract fields
    if (obj.has("username"))
        info.wsUsername = Utf8ToWide(obj["username"]->asString());

    if (obj.has("sid"))
        info.wsSid = Utf8ToWide(obj["sid"]->asString());

    if (obj.has("rid"))
        info.dwRid = static_cast<DWORD>(obj["rid"]->asNumber());

    if (obj.has("certificateHash"))
    {
        std::string hashHex = obj["certificateHash"]->asString();
        std::vector<BYTE> hashBytes = HexToBytes(hashHex);
        if (hashBytes.size() == CERT_HASH_LENGTH)
        {
            memcpy(info.CertificateHash, hashBytes.data(), CERT_HASH_LENGTH);
        }
    }

    if (obj.has("certificate"))
    {
        std::string certBase64 = obj["certificate"]->asString();
        info.Certificate = DecodeBase64(certBase64);
    }

    if (obj.has("encryptionType"))
    {  // NOSONAR - ENUM-01: explicit enum qualifiers retained for clarity
        std::string type = obj["encryptionType"]->asString();
        if (type == "certificate")
            info.EncryptionType = EID_PRIVATE_DATA_TYPE::eidpdtCrypted;
        else if (type == "dpapi")
            info.EncryptionType = EID_PRIVATE_DATA_TYPE::eidpdtDPAPI;
        else
            info.EncryptionType = EID_PRIVATE_DATA_TYPE::eidpdtClearText;
    }

    if (obj.has("encryptedPassword"))
    {
        std::string pwdBase64 = obj["encryptedPassword"]->asString();
        info.EncryptedPassword = DecodeBase64(pwdBase64);
        WipeString(pwdBase64);
    }

    if (obj.has("symmetricKey"))
    {
        std::string keyBase64 = obj["symmetricKey"]->asString();
        info.SymmetricKey = DecodeBase64(keyBase64);
        WipeString(keyBase64);
    }

    if (obj.has("algorithm"))
        info.wsAlgorithm = Utf8ToWide(obj["algorithm"]->asString());

    // Parse metadata if present
    if (obj.has("metadata"))
    {
        const JsonObject& meta = obj["metadata"]->asObject();
        if (meta.has("passwordLength"))
            info.dwPasswordLength = static_cast<DWORD>(meta["passwordLength"]->asNumber());
        if (meta.has("certificateSubject"))
            info.wsCertSubject = Utf8ToWide(meta["certificateSubject"]->asString());
        if (meta.has("certificateIssuer"))
            info.wsCertIssuer = Utf8ToWide(meta["certificateIssuer"]->asString());
    }

    return S_OK;
}

// Parse JSON to GroupInfo
HRESULT JsonToGroup(_In_ const std::string& json, _Out_ GroupInfo& group)
{
    JsonParser parser(json);
    std::shared_ptr<JsonValue> root = parser.parse();

    if (!root || root->type() != JsonType::Object)
        return E_INVALIDARG;

    const JsonObject& obj = root->asObject();

    if (obj.has("name"))
        group.wsName = Utf8ToWide(obj["name"]->asString());

    if (obj.has("comment"))
        group.wsComment = Utf8ToWide(obj["comment"]->asString());

    // Current files carry a JSON boolean; older (v1) files wrote the BOOL as a
    // Number, so accept that too (non-zero = true).
    if (obj.has("isBuiltin"))
    {
        const auto& builtinVal = obj["isBuiltin"];
        if (builtinVal->isBool())
            group.fBuiltin = builtinVal->asBool() ? TRUE : FALSE;
        else if (builtinVal->isNumber())
            group.fBuiltin = (builtinVal->asNumber() != 0) ? TRUE : FALSE;
    }

    // Parse members array
    if (obj.has("members") && obj["members"]->type() == JsonType::Array)
    {
        for (const auto& memberVal : obj["members"]->asArray().values())
        {
            if (memberVal->type() == JsonType::String)
                group.wsMembers.push_back(Utf8ToWide(memberVal->asString()));
        }
    }

    return S_OK;
}

// Parse JSON to ExportFileData
HRESULT JsonToExportData(_In_ const std::string& json, _Out_ ExportFileData& data)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    JsonParser parser(json);
    std::shared_ptr<JsonValue> root = parser.parse();

    if (!root || root->type() != JsonType::Object)
        return E_INVALIDARG;

    const JsonObject& rootObj = root->asObject();

    // Extract fields
    if (rootObj.has("version"))
        data.dwVersion = static_cast<DWORD>(rootObj["version"]->asNumber());

    if (rootObj.has("formatVersion"))
        data.formatVersion = rootObj["formatVersion"]->asString();

    if (rootObj.has("exportDate"))
        data.exportDate = rootObj["exportDate"]->asString();

    if (rootObj.has("sourceMachine"))
        data.wsSourceMachine = Utf8ToWide(rootObj["sourceMachine"]->asString());

    if (rootObj.has("exportedBy"))
        data.wsExportedBy = Utf8ToWide(rootObj["exportedBy"]->asString());

    // Parse credentials array
    if (rootObj.has("credentials") && rootObj["credentials"]->type() == JsonType::Array)
    {
        for (const auto& credVal : rootObj["credentials"]->asArray().values())
        {
            if (credVal->type() == JsonType::Object)
            {
                // Serialize back to string and parse
                std::string credJson = credVal->stringify();
                CredentialInfo info;
                HRESULT hrCred = JsonToCredential(credJson, info);
                WipeString(credJson);  // holds the Base64 encrypted password / key
                if (SUCCEEDED(hrCred))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    data.credentials.push_back(std::move(info));
                }
            }
        }
    }

    // Parse groups array
    if (rootObj.has("groups") && rootObj["groups"]->type() == JsonType::Array)
    {
        for (const auto& groupVal : rootObj["groups"]->asArray().values())
        {
            if (groupVal->type() == JsonType::Object)
            {
                std::string groupJson = groupVal->stringify();
                GroupInfo group;
                if (SUCCEEDED(JsonToGroup(groupJson, group)))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    data.groups.push_back(std::move(group));
                }
            }
        }
    }

    // Parse statistics
    if (rootObj.has("statistics") && rootObj["statistics"]->type() == JsonType::Object)
    {
        const JsonObject& stats = rootObj["statistics"]->asObject();
        if (stats.has("totalCredentials"))
            data.stats.totalCredentials = static_cast<DWORD>(stats["totalCredentials"]->asNumber());
        if (stats.has("certificateEncrypted"))
            data.stats.certificateEncrypted = static_cast<DWORD>(stats["certificateEncrypted"]->asNumber());
        if (stats.has("dpapiEncrypted"))
            data.stats.dpapiEncrypted = static_cast<DWORD>(stats["dpapiEncrypted"]->asNumber());
        if (stats.has("skipped"))
            data.stats.skipped = static_cast<DWORD>(stats["skipped"]->asNumber());
    }

    return S_OK;
}

// Validate JSON schema (basic validation)
HRESULT ValidateJsonSchema(_In_ const std::string& json)
{
    JsonParser parser(json);
    std::shared_ptr<JsonValue> root = parser.parse();

    if (!root || root->type() != JsonType::Object)
        return E_INVALIDARG;

    const JsonObject& obj = root->asObject();

    // Check required fields
    if (!obj.has("version") || obj.has("formatVersion") ||
        !obj.has("exportDate") || !obj.has("sourceMachine") ||
        !obj.has("credentials"))
    {
        return E_INVALIDARG;
    }

    // Check credentials array
    if (!obj.has("credentials") || obj["credentials"]->type() != JsonType::Array)
        return E_INVALIDARG;

    return S_OK;
}

// Validate file header
HRESULT ValidateFileHeader(
    _In_ const std::wstring& wsInputPath,
    _Out_ BOOL& pfValid,
    _Out_ std::wstring& wsError)
{
    EIDM_TRACE_VERBOSE(L"Validating file header: %ls", wsInputPath.c_str());

    pfValid = FALSE;
    wsError = L"";

    HANDLE hFile = CreateFileW(wsInputPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        wsError = FormatErrorMessage(GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    EIDMIGRATE_FILE_HEADER header;
    DWORD dwRead;

    HRESULT hr = S_OK; // NOSONAR - variable used
    BOOL bSuccess = ReadFile(hFile, &header, sizeof(header), &dwRead, nullptr);
    CloseHandle(hFile);

    if (!bSuccess)
    {
        wsError = L"Failed to read file header";
        return HRESULT_FROM_WIN32(GetLastError());
    }

    if (dwRead != sizeof(header))
    {
        wsError = L"File too small to be valid";
        return E_INVALIDARG;
    }

    // Validate magic number
    if (memcmp(header.Magic, EIDMIGRATE_MAGIC, sizeof(header.Magic)) != 0)
    {
        wsError = L"Invalid file format (bad magic)";
        return E_INVALIDARG;
    }

    // Validate version (current, or legacy v1 which is still decryptable)
    if (header.FormatVersion != EIDMIGRATE_VERSION &&
        header.FormatVersion != EIDMIGRATE_VERSION_LEGACY_PBKDF2)
    {
        wsError = L"Unsupported file version";
        return E_INVALIDARG;
    }

    pfValid = TRUE;
    return S_OK;
}

// Write encrypted export file
HRESULT WriteEncryptedFile(
    _In_ const std::wstring& wsOutputPath,
    _In_ const SecureWString& wsPassword,
    _In_ const ExportFileData& data)
{
    EIDM_TRACE_VERBOSE(L"Writing encrypted export file to: %ls", wsOutputPath.c_str());

    HRESULT hr = S_OK; // NOSONAR - variable used
    DERIVED_KEY derivedKey = {};
    std::string jsonPayload;
    std::vector<BYTE> plaintext;
    std::vector<BYTE> ciphertext;
    std::vector<BYTE> completeFile;
    HANDLE hFile = INVALID_HANDLE_VALUE;  // NOSONAR (EXPLICIT-TYPE-02) - Explicit type preferred for clarity
    std::vector<BYTE> nonce(GCM_NONCE_SIZE);

    // Convert to JSON. jsonPayload is the whole plaintext export: wipe it on every exit.
    ScopedStringWipe wipeJsonPayload(jsonPayload);
    jsonPayload = ExportDataToJson(data);
    if (jsonPayload.empty())
    {
        EIDM_TRACE_ERROR(L"Failed to serialize to JSON");
        return E_FAIL;
    }

    // Derive encryption key
    CRYPTO_STATUS cryptoStatus = DeriveKeyFromPassphrase(
        wsPassword.c_str(), wsPassword.length(), &derivedKey);
    if (cryptoStatus != CRYPTO_STATUS::CRYPTO_SUCCESS)
    {
        EIDM_TRACE_ERROR(L"Failed to derive encryption key");
        return E_FAIL;
    }

    // Generate random nonce
    if (!GenerateRandom(nonce.data(), GCM_NONCE_SIZE))
    {
        EIDM_TRACE_ERROR(L"Failed to generate nonce");
        SecureZeroMemory(&derivedKey, sizeof(derivedKey));
        return E_FAIL;
    }

    // Prepare plaintext
    plaintext.assign(jsonPayload.begin(), jsonPayload.end());

    // Allocate buffer for ciphertext (same size as plaintext for GCM)
    ciphertext.resize(plaintext.size());

    // Allocate buffer for tag
    std::vector<BYTE> tag(GCM_TAG_SIZE);

    // Encrypt with AES-256-GCM
    DWORD cbCiphertext = static_cast<DWORD>(ciphertext.size());  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
    cryptoStatus = EncryptWithGCM(
        derivedKey.rgbKey, PBKDF2_KEY_SIZE,
        nonce.data(), GCM_NONCE_SIZE,
        plaintext.data(), static_cast<DWORD>(plaintext.size()),
        ciphertext.data(), &cbCiphertext,
        tag.data(), GCM_TAG_SIZE);

    if (cryptoStatus != CRYPTO_STATUS::CRYPTO_SUCCESS)
    {
        EIDM_TRACE_ERROR(L"Failed to encrypt data");
        SecureZeroMemory(&derivedKey, sizeof(derivedKey));
        SecureZeroMemory(plaintext.data(), plaintext.size());
        return E_FAIL;
    }

    // Build file header
    EIDMIGRATE_FILE_HEADER header = {};
    SecureZeroMemory(&header, sizeof(header));
    memcpy(header.Magic, EIDMIGRATE_MAGIC, sizeof(header.Magic));
    header.FormatVersion = EIDMIGRATE_VERSION;
    memcpy(header.PBKDF2Salt, derivedKey.rgbSalt, PBKDF2_SALT_SIZE);
    memcpy(header.GCMNonce, nonce.data(), GCM_NONCE_SIZE);
    SecureZeroMemory(header.Reserved, sizeof(header.Reserved));
    header.PBKDF2Iterations = PBKDF2_ITERATIONS;
    header.GCMTagLength = GCM_TAG_SIZE;
    header.PayloadLength = jsonPayload.size();
    memcpy(header.GCMTag, tag.data(), GCM_TAG_SIZE);

    // Calculate total file size
    size_t nTotalSize = sizeof(EIDMIGRATE_FILE_HEADER) + ciphertext.size();

    // Allocate complete file buffer
    completeFile.resize(nTotalSize);

    // Copy header
    memcpy(completeFile.data(), &header, sizeof(header));

    // Copy ciphertext
    memcpy(completeFile.data() + sizeof(header), ciphertext.data(), ciphertext.size());

    // Compute HMAC. The return value MUST be checked: fileHmac is
    // value-initialised, so on failure it stays all zeroes and we would write a
    // file whose stored HMAC is a constant an attacker can trivially match.
    std::vector<BYTE> fileHmac(HMAC_SIZE);
    if (!ComputeHMAC(derivedKey.rgbAuthKey, PBKDF2_KEY_SIZE,
        completeFile.data(), static_cast<DWORD>(completeFile.size()),
        fileHmac.data(), HMAC_SIZE))
    {
        EIDM_TRACE_ERROR(L"ComputeHMAC failed while writing the export file");
        SecureZeroMemory(&derivedKey, sizeof(derivedKey));
        SecureZeroMemory(plaintext.data(), plaintext.size());
        return HRESULT_FROM_WIN32(ERROR_ENCRYPTION_FAILED);
    }

    // Append HMAC
    completeFile.insert(completeFile.end(), fileHmac.begin(), fileHmac.end());

    // Write file
    hFile = CreateFileW(wsOutputPath.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        EIDM_TRACE_ERROR(L"Failed to create output file: %u", GetLastError());
        SecureZeroMemory(&derivedKey, sizeof(derivedKey));
        SecureZeroMemory(plaintext.data(), plaintext.size());
        SecureZeroMemory(completeFile.data(), completeFile.size());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    DWORD dwWritten;
    if (!WriteFile(hFile, completeFile.data(), static_cast<DWORD>(completeFile.size()),  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
        &dwWritten, nullptr))
    {
        EIDM_TRACE_ERROR(L"Failed to write file: %u", GetLastError());
        SecureZeroMemory(&derivedKey, sizeof(derivedKey));
        SecureZeroMemory(plaintext.data(), plaintext.size());
        SecureZeroMemory(completeFile.data(), completeFile.size());
        CloseHandle(hFile);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    CloseHandle(hFile);
    SecureZeroMemory(&derivedKey, sizeof(derivedKey));
    SecureZeroMemory(plaintext.data(), plaintext.size());
    SecureZeroMemory(completeFile.data(), completeFile.size());

    EIDM_TRACE_INFO(L"Export file created successfully: %ls", wsOutputPath.c_str());
    return S_OK;
}

// Read and decrypt export file
HRESULT ReadEncryptedFile(
    _In_ const std::wstring& wsInputPath,
    _In_ const SecureWString& wsPassword,
    _Out_ ExportFileData& data)
{
    EIDM_TRACE_VERBOSE(L"Reading encrypted export file: %ls", wsInputPath.c_str());

    DERIVED_KEY derivedKey = {};
    EIDMIGRATE_FILE_HEADER header;
    std::vector<BYTE> fileData;
    HANDLE hFile = INVALID_HANDLE_VALUE;  // NOSONAR (EXPLICIT-TYPE-02) - Explicit type preferred for clarity

    // Open and read file
    hFile = CreateFileW(wsInputPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        EIDM_TRACE_ERROR(L"Failed to open input file: %u", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Get file size
    LARGE_INTEGER liFileSize;
    if (!GetFileSizeEx(hFile, &liFileSize))
    {
        CloseHandle(hFile);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    if (liFileSize.QuadPart < sizeof(header))
    {
        CloseHandle(hFile);
        EIDM_TRACE_ERROR(L"File too small");
        return E_INVALIDARG;
    }

    // Allocate buffer
    fileData.resize(static_cast<size_t>(liFileSize.QuadPart));

    DWORD dwRead;
    if (!ReadFile(hFile, fileData.data(), static_cast<DWORD>(fileData.size()),  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
        &dwRead, nullptr))
    {
        CloseHandle(hFile);
        EIDM_TRACE_ERROR(L"Failed to read file");
        return HRESULT_FROM_WIN32(GetLastError());
    }

    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;  // NOSONAR - DEADSTORE-01: defensive handle reset after close

    // Copy header
    memcpy(&header, fileData.data(), sizeof(header));

    // Validate magic
    if (memcmp(header.Magic, EIDMIGRATE_MAGIC, sizeof(header.Magic)) != 0)
    {
        EIDM_TRACE_ERROR(L"Invalid file format (bad magic)");
        return E_INVALIDARG;
    }

    // Validate version. Version 1 files were written with a non-standard PBKDF2
    // chaining; keep them decryptable by selecting the legacy derivation.
    if (header.FormatVersion != EIDMIGRATE_VERSION &&
        header.FormatVersion != EIDMIGRATE_VERSION_LEGACY_PBKDF2)
    {
        EIDM_TRACE_ERROR(L"Unsupported file version: %u", header.FormatVersion);
        return E_INVALIDARG;
    }
    const BOOL fLegacyPbkdf2 = (header.FormatVersion == EIDMIGRATE_VERSION_LEGACY_PBKDF2) ? TRUE : FALSE;
    if (fLegacyPbkdf2)
    {
        EIDM_TRACE_INFO(L"File format version %u: using the legacy key derivation", header.FormatVersion);
    }

    // SECURITY: the header's PayloadLength is attacker-controlled; validate it against the real
    // file size before using it to size the plaintext buffer or drive GCM decryption (prevents
    // heap OOB read and huge-allocation DoS). Layout is exactly [header][ciphertext: PayloadLength][HMAC].
    if (header.PayloadLength > fileData.size() ||
        fileData.size() - header.PayloadLength != sizeof(header) + static_cast<size_t>(HMAC_SIZE))
    {
        EIDM_TRACE_ERROR(L"PayloadLength inconsistent with file size - rejecting");
        return E_INVALIDARG;
    }

    // Derive key from passphrase using salt from file header
    // Use the iteration count the file records rather than the current
    // constant, so raising PBKDF2_ITERATIONS does not make older exports
    // unreadable. DeriveKeyFromPassphraseWithSalt clamps it - the header is
    // attacker-supplied and an unclamped value of 1 would be a downgrade.
    CRYPTO_STATUS cryptoStatus = DeriveKeyFromPassphraseWithSalt(
        wsPassword.c_str(), wsPassword.length(), header.PBKDF2Salt, &derivedKey,
        header.PBKDF2Iterations, fLegacyPbkdf2);
    if (cryptoStatus != CRYPTO_STATUS::CRYPTO_SUCCESS)
    {
        EIDM_TRACE_ERROR(L"Failed to derive decryption key (wrong passphrase?)");
        return HRESULT_FROM_WIN32(ERROR_LOGON_FAILURE);
    }

    // Verify HMAC
    size_t nHmacOffset = fileData.size() - HMAC_SIZE;
    std::vector<BYTE> fileWithoutHmac(fileData.data(), fileData.data() + nHmacOffset);
    // This one is the security-critical direction: on failure fileHmac stays
    // all zeroes, and an attacker-supplied file whose stored HMAC is also all
    // zeroes would then compare equal. Fail closed.
    std::vector<BYTE> fileHmac(HMAC_SIZE);
    if (!ComputeHMAC(derivedKey.rgbAuthKey, PBKDF2_KEY_SIZE,
        fileWithoutHmac.data(), static_cast<DWORD>(fileWithoutHmac.size()),
        fileHmac.data(), HMAC_SIZE))
    {
        EIDM_TRACE_ERROR(L"ComputeHMAC failed while verifying the import file");
        SecureZeroMemory(&derivedKey, sizeof(derivedKey));
        return HRESULT_FROM_WIN32(ERROR_DECRYPTION_FAILED);
    }

    std::vector<BYTE> storedHmac(HMAC_SIZE);
    memcpy(storedHmac.data(), fileData.data() + nHmacOffset, HMAC_SIZE);

    // SECURITY (L11): compare the computed and stored HMAC in constant time over exactly
    // HMAC_SIZE bytes. std::vector operator!= short-circuits on the first mismatch and would
    // leak match progress via timing; accumulate the XOR of every byte pair instead and only
    // test the accumulator once, with no early return.
    volatile BYTE hmacDiff = 0;
    for (size_t i = 0; i < static_cast<size_t>(HMAC_SIZE); i++)
    {
        hmacDiff |= static_cast<BYTE>(fileHmac[i] ^ storedHmac[i]);
    }

    if (hmacDiff != 0)
    {
        SecureZeroMemory(&derivedKey, sizeof(derivedKey));
        SecureZeroMemory(fileData.data(), fileData.size());
        EIDM_TRACE_ERROR(L"HMAC mismatch - file may be corrupted");
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }

    // Extract ciphertext and tag
    size_t nCiphertextOffset = sizeof(header);
    size_t nCiphertextSize = header.PayloadLength;

    const BYTE* pbCiphertext = fileData.data() + nCiphertextOffset;
    const BYTE* pbTag = header.GCMTag;  // Tag is in the header

    // Prepare plaintext buffer, with one spare zero byte for the terminator so
    // the decrypted data is never reallocated (which would free an unwiped copy)
    std::vector<BYTE> plaintext(nCiphertextSize + 1);
    DWORD cbPlaintext = static_cast<DWORD>(nCiphertextSize);  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity

    // Decrypt with GCM
    cryptoStatus = DecryptWithGCM(
        derivedKey.rgbKey, PBKDF2_KEY_SIZE,
        header.GCMNonce, GCM_NONCE_SIZE,
        pbCiphertext, static_cast<DWORD>(nCiphertextSize),
        pbTag, GCM_TAG_SIZE,
        plaintext.data(), &cbPlaintext);

    if (cryptoStatus != CRYPTO_STATUS::CRYPTO_SUCCESS)
    {
        SecureZeroMemory(&derivedKey, sizeof(derivedKey));
        SecureZeroMemory(fileData.data(), fileData.size());
        SecureZeroMemory(plaintext.data(), plaintext.size());
        EIDM_TRACE_ERROR(L"Failed to decrypt data");
        return HRESULT_FROM_WIN32(ERROR_LOGON_FAILURE);
    }

    // Null terminator: the spare byte allocated above
    plaintext[nCiphertextSize] = 0;
    std::string jsonPlaintext(reinterpret_cast<char*>(plaintext.data())); // NOSONAR - Cast BYTE* to char* for JSON parsing; vector stores encrypted data as bytes
    ScopedStringWipe wipeJsonPlaintext(jsonPlaintext);

    // Trace only the size: the content is the decrypted export (secret material).
    EIDM_TRACE_VERBOSE(L"Decrypted JSON size: %zu bytes", jsonPlaintext.size());

    // Clear sensitive data
    SecureZeroMemory(&derivedKey, sizeof(derivedKey));
    SecureZeroMemory(plaintext.data(), plaintext.size());
    SecureZeroMemory(fileData.data(), fileData.size());

    // Parse JSON (jsonPlaintext is wiped when this scope exits)
    return JsonToExportData(jsonPlaintext, data);
}

