// File: EIDMigrate/List.cpp
// List credentials functionality

#include "List.h"
#include "LsaClient.h"
#include "FileCrypto.h"
#include "CryptoHelpers.h"
#include "Tracing.h"
#include "Utils.h"

HRESULT CommandList(_In_ const COMMAND_OPTIONS& options)
{
    LIST_OPTIONS opts;
    opts.fLocal = options.ListLocal;
    opts.fInputFile = !options.InputFile.empty();
    opts.wsInputPath = options.InputFile;
    opts.fVerbose = (options.Verbosity >= VERBOSITY::VERBOSE);

    return ListCredentials(opts);
}

HRESULT ListCredentials(_In_ const LIST_OPTIONS& options)
{
    if (options.fLocal)
    {
        return ListLocalCredentials(options.fVerbose);
    }
    else if (options.fInputFile)
    {
        return ListImportFileCredentials(options.wsInputPath, options.fVerbose);
    }

    return E_INVALIDARG;
}

HRESULT ListLocalCredentials(_In_ BOOL fVerbose)
{
    EIDM_TRACE_INFO(L"Listing local EID credentials...");

    std::vector<CredentialInfo> credentials;
    HRESULT hr = EnumerateLsaCredentials(credentials);

    if (hr == S_OK)
    {
        if (credentials.empty())
        {
            EIDM_TRACE_INFO(L"No EID credentials found.");
        }
        else
        {
            EIDM_TRACE_INFO(L"Found %zu credential(s):", credentials.size());

            for (const auto& cred : credentials)
            {
                DisplayCredentialSummary(cred, fVerbose);
            }
        }
    }
    else
    {
        EIDM_TRACE_ERROR(L"Failed to enumerate credentials: 0x%08X", hr);
        PCWSTR pwszError = GetErrorCodeString(hr);
        EIDM_TRACE_ERROR(L"Error: %ls", pwszError);
    }

    return hr;
}

HRESULT ListImportFileCredentials(_In_ const std::wstring& wsInputPath, _In_ BOOL fVerbose)
{
    EIDM_TRACE_INFO(L"Listing credentials from: %ls", wsInputPath.c_str());

    // Get password for decryption
    SecureWString wsPassword = PromptForPassphrase(L"Enter passphrase for export file: ", FALSE);
    if (wsPassword.empty())
    {
        EIDM_TRACE_ERROR(L"Passphrase is required to list credentials.");
        return E_INVALIDARG;
    }

    // Read and decrypt the export file
    ExportFileData data;
    HRESULT hr = ReadEncryptedFile(wsInputPath, wsPassword, data);

    if (FAILED(hr))
    {
        EIDM_TRACE_ERROR(L"Failed to read export file: 0x%08X", hr);
        PCWSTR pwszError = GetErrorCodeString(hr);
        EIDM_TRACE_ERROR(L"Error: %ls", pwszError);
        return hr;
    }

    // Display file metadata
    EIDM_TRACE_INFO(L"");
    EIDM_TRACE_INFO(L"=== Export File Information ===");
    EIDM_TRACE_INFO(L"Format Version: %S", data.formatVersion.c_str());
    EIDM_TRACE_INFO(L"Export Date: %S", data.exportDate.c_str());
    if (!data.wsSourceMachine.empty())
    {
        EIDM_TRACE_INFO(L"Source Machine: %ls", data.wsSourceMachine.c_str());
    }
    if (!data.wsExportedBy.empty())
    {
        EIDM_TRACE_INFO(L"Exported By: %ls", data.wsExportedBy.c_str());
    }
    EIDM_TRACE_INFO(L"");

    // Display credentials
    if (data.credentials.empty())
    {
        EIDM_TRACE_INFO(L"No credentials found in export file.");
    }
    else
    {
        EIDM_TRACE_INFO(L"Found %zu credential(s):", data.credentials.size());
        EIDM_TRACE_INFO(L"");

        for (const auto& cred : data.credentials)
        {
            DisplayCredentialSummary(cred, fVerbose);
            EIDM_TRACE_INFO(L"");
        }
    }

    // Display groups
    if (!data.groups.empty())
    {
        EIDM_TRACE_INFO(L"Found %zu group(s):", data.groups.size());
        EIDM_TRACE_INFO(L"");

        for (const auto& group : data.groups)
        {
            EIDM_TRACE_INFO(L"  Group: %ls", group.wsName.c_str());

            if (!group.wsMembers.empty())
            {
                EIDM_TRACE_INFO(L"    Members (%zu):", group.wsMembers.size());
                for (const auto& member : group.wsMembers)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    EIDM_TRACE_INFO(L"      - %ls", member.c_str());
                }
            }
            EIDM_TRACE_INFO(L"");
        }
    }

    // Display statistics
    EIDM_TRACE_INFO(L"=== Statistics ===");
    EIDM_TRACE_INFO(L"Total Credentials: %u", data.stats.totalCredentials);
    EIDM_TRACE_INFO(L"Certificate Encrypted: %u", data.stats.certificateEncrypted);
    EIDM_TRACE_INFO(L"DPAPI Encrypted: %u", data.stats.dpapiEncrypted);
    EIDM_TRACE_INFO(L"Skipped: %u", data.stats.skipped);

    return S_OK;
}

void DisplayCredentialSummary(_In_ const CredentialInfo& info, _In_ BOOL fVerbose)
{
    const wchar_t* wszEncryptionType = L"Unknown";  // NOSONAR - INIT-01: default retained for enum values without an explicit case
    switch (info.EncryptionType)
    {  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
    case EID_PRIVATE_DATA_TYPE::eidpdtClearText:
        wszEncryptionType = L"None";
        break;
    case EID_PRIVATE_DATA_TYPE::eidpdtCrypted:
        wszEncryptionType = L"Certificate";
        break;
    case EID_PRIVATE_DATA_TYPE::eidpdtDPAPI:
        wszEncryptionType = L"DPAPI";
        break;
    }

    EIDM_TRACE_INFO(L"  User: %ls (RID: %u)", info.wsUsername.c_str(), info.dwRid);
    EIDM_TRACE_INFO(L"    Encryption: %ls", wszEncryptionType);

    if (fVerbose)
    {
        // Display certificate presence and size
        if (!info.Certificate.empty())
        {
            EIDM_TRACE_INFO(L"    Certificate: %zu bytes", info.Certificate.size());
        }
        else
        {
            EIDM_TRACE_INFO(L"    Certificate: (none)");
        }

        // Display certificate hash
        std::string sHash = BytesToHex(info.CertificateHash, CERT_HASH_LENGTH);
        EIDM_TRACE_INFO(L"    Certificate Hash: %S", sHash.c_str());

        // Display certificate subject if available
        if (!info.wsCertSubject.empty())
        {
            EIDM_TRACE_INFO(L"    Subject: %ls", info.wsCertSubject.c_str());
        }

        // Display certificate issuer if available
        if (!info.wsCertIssuer.empty())
        {
            EIDM_TRACE_INFO(L"    Issuer: %ls", info.wsCertIssuer.c_str());
        }

        // Display certificate expiry if available
        if (info.ftCertValidTo.dwLowDateTime != 0 || info.ftCertValidTo.dwHighDateTime != 0)
        {
            // Convert FILETIME to readable string
            SYSTEMTIME st = {0};
            if (FileTimeToSystemTime(&info.ftCertValidTo, &st))
            {
                EIDM_TRACE_INFO(L"    Expires: %04u-%02u-%02u %02u:%02u:%02u",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            }
        }

        // Display symmetric key info
        if (!info.SymmetricKey.empty())
        {
            EIDM_TRACE_INFO(L"    Symmetric Key: %zu bytes", info.SymmetricKey.size());
        }

        // Display encrypted password info
        if (!info.EncryptedPassword.empty())
        {
            EIDM_TRACE_INFO(L"    Encrypted Password: %zu bytes", info.EncryptedPassword.size());
        }

        // Display SID if available
        if (!info.wsSid.empty())
        {
            EIDM_TRACE_INFO(L"    SID: %ls", info.wsSid.c_str());
        }
    }
}

HRESULT DisplayCredentialsAsJson(_In_ const std::vector<CredentialInfo>& credentials)
{
    if (credentials.empty())
    {
        EIDM_TRACE_INFO(L"[]");
        return S_OK;
    }

    std::string json = "[\n";

    for (size_t i = 0; i < credentials.size(); i++)
    {
        const auto& cred = credentials[i];
        json += CredentialToJson(cred);

        if (i < credentials.size() - 1)
        {
            json += ",";
        }
        json += "\n";
    }

    json += "]";

    EIDM_TRACE_INFO(L"%S", json.c_str());
    return S_OK;
}
