// File: EIDMigrate/Validate.cpp
// Import file validation functionality

#include "Validate.h"
#include "FileCrypto.h"
#include "AuditLogging.h"
#include "Tracing.h"
#include "Utils.h"
#include "PinPrompt.h"
#include "LsaClient.h"

HRESULT CommandValidate(_In_ const COMMAND_OPTIONS& options)
{
    // Get passphrase
    SecureWString wsPassword;
    if (options.Password.empty())
    {
        wsPassword = PromptForPassphrase(L"Enter export passphrase: ", FALSE);
        if (wsPassword.empty())
        {
            EIDM_TRACE_ERROR(L"Passphrase is required.");
            return E_FAIL;
        }
    }
    else
    {
        wsPassword = SecureWString(options.Password.c_str());
    }

    VALIDATE_OPTIONS opts;
    opts.wsInputPath = options.InputFile;
    opts.fRequireSmartCard = options.ValidateCerts;
    opts.fVerbose = (options.Verbosity >= VERBOSITY::VERBOSE);

    VALIDATION_RESULT result;
    HRESULT hr = ValidateImportFile(options.InputFile, wsPassword, opts, result);

    if (SUCCEEDED(hr))
    {
        DisplayValidationReport(result);
    }

    return hr;
}

HRESULT ValidateImportFile(
    _In_ const std::wstring& wsInputPath,
    _In_ const SecureWString& wsPassword,
    _In_ const VALIDATE_OPTIONS& options,
    _Out_ VALIDATION_RESULT& result)
{
    EIDM_TRACE_INFO(L"Validating import file: %ls", wsInputPath.c_str());

    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - HRESULT visible for security audit

    // Validate file format first
    hr = ValidateFileFormat(wsInputPath, result);
    if (FAILED(hr))
    {
        EIDM_TRACE_ERROR(L"File validation failed: 0x%08X", hr);
        return hr;
    }

    // Decrypt and parse JSON structure
    hr = ValidateEncryptedContent(wsInputPath, wsPassword, options, result);
    if (FAILED(hr))
    {
        EIDM_TRACE_ERROR(L"Content validation failed: 0x%08X", hr);
        return hr;
    }

    // Validate each certificate if requested
    if (options.fRequireSmartCard && !result.credentials.empty())
    {
        hr = ValidateCertificates(result);
        if (FAILED(hr))
        {
            EIDM_TRACE_WARN(L"Certificate validation produced warnings");
        }
    }

    if (result.errors.empty() && result.warnings.empty())
    {
        result.fValidFormat = TRUE;
        result.fValidJson = TRUE;
        result.fAllCertsTrusted = TRUE;
    }

    return hr;
}

HRESULT ValidateFileFormat(
    _In_ const std::wstring& wsInputPath,
    _Out_ VALIDATION_RESULT& result)
{
    std::wstring wsError;
    BOOL fValid = FALSE;

    HRESULT hr = ValidateFileHeader(wsInputPath, fValid, wsError);

    result.fValidHeader = fValid;

    if (!fValid)
    {
        result.errors.push_back(std::move(wsError));
    }

    return hr;
}

HRESULT ValidateEncryptedContent(
    _In_ const std::wstring& wsInputPath,
    _In_ const SecureWString& wsPassword,
    _In_ const VALIDATE_OPTIONS& options,
    _Out_ VALIDATION_RESULT& result)
{
    UNREFERENCED_PARAMETER(options);

    EIDM_TRACE_VERBOSE(L"Validating encrypted content...");

    // Read and decrypt the file
    ExportFileData data;
    HRESULT hr = ReadEncryptedFile(wsInputPath, wsPassword, data);

    if (FAILED(hr))
    {
        if (hr == HRESULT_FROM_WIN32(ERROR_LOGON_FAILURE))
        {
            result.errors.emplace_back(L"Invalid passphrase or corrupted file");
            result.fValidHmac = FALSE;
        }
        else if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_DATA))
        {
            result.errors.emplace_back(L"HMAC validation failed - file may be corrupted");
            result.fValidHmac = FALSE;
        }
        else
        {
            result.errors.push_back(L"Failed to decrypt file: " + FormatHResult(hr));
        }
        return hr;
    }

    result.fValidHmac = TRUE;
    result.fValidJson = TRUE;

    // Store credential count
    result.dwCredentialCount = static_cast<DWORD>(data.credentials.size());

    // Store groups count for info
    result.dwWarningCount = static_cast<DWORD>(data.groups.size());

    // Store credential details for validation
    result.credentials = std::move(data.credentials);

    // Store metadata
    result.wsSourceMachine = data.wsSourceMachine;
    result.wsExportDate = Utf8ToWide(data.exportDate);
    result.wsExportedBy = data.wsExportedBy;

    EIDM_TRACE_INFO(L"Decrypted successfully: %u credentials, %u groups",
        result.dwCredentialCount, result.dwWarningCount);

    return S_OK;
}

HRESULT ValidateCertificates(_Out_ VALIDATION_RESULT& result)
{
    for (const auto& cred : result.credentials)
    {
        if (cred.Certificate.empty())
        {
            std::wstring wsWarning = L"No certificate for user: " + cred.wsUsername;
            result.warnings.push_back(std::move(wsWarning));
            result.fAllCertsTrusted = FALSE;
            continue;
        }

        // Check certificate validity
        FILETIME ftNow;
        GetSystemTimeAsFileTime(&ftNow);

        // Decode certificate to check validity
        // For now, just check the metadata from export
        if (cred.ftCertValidTo.dwHighDateTime || cred.ftCertValidTo.dwLowDateTime)
        {
            if (CompareFileTime(&cred.ftCertValidTo, &ftNow) < 0)  // NOSONAR - CONTROL-01: nested if kept for clarity
            {
                // NOSONAR - Nested if for clarity: check timestamp exists, then check expiry
                std::wstring wsWarning = L"Certificate expired for user: " + cred.wsUsername;
                result.warnings.push_back(std::move(wsWarning));
                result.fAllCertsTrusted = FALSE;
            }
        }

        if (cred.ftCertValidFrom.dwHighDateTime || cred.ftCertValidFrom.dwLowDateTime)
        {
            if (CompareFileTime(&cred.ftCertValidFrom, &ftNow) > 0)  // NOSONAR - CONTROL-01: nested if kept for clarity
            {
                std::wstring wsWarning = L"Certificate not yet valid for user: " + cred.wsUsername;
                result.warnings.push_back(std::move(wsWarning));
                result.fAllCertsTrusted = FALSE;
            }
        }
    }

    return S_OK;
}

void DisplayValidationReport(_In_ const VALIDATION_RESULT& result)
{
    EIDM_TRACE_INFO(L"\n=== Validation Report ===\n");

    EIDM_TRACE_INFO(L"File Format: %ls", result.fValidFormat ? L"Valid" : L"Invalid");
    EIDM_TRACE_INFO(L"Header: %ls", result.fValidHeader ? L"Valid" : L"Invalid");
    EIDM_TRACE_INFO(L"HMAC: %ls", result.fValidHmac ? L"Valid" : L"Invalid");
    EIDM_TRACE_INFO(L"JSON: %ls", result.fValidJson ? L"Valid" : L"Invalid");
    EIDM_TRACE_INFO(L"All Certificates Trusted: %ls", result.fAllCertsTrusted ? L"Yes" : L"No");

    EIDM_TRACE_INFO(L"\nFile Information:");
    if (!result.wsSourceMachine.empty())
        EIDM_TRACE_INFO(L"  Source Machine: %ls", result.wsSourceMachine.c_str());
    if (!result.wsExportDate.empty())
        EIDM_TRACE_INFO(L"  Export Date: %ls", result.wsExportDate.c_str());
    if (!result.wsExportedBy.empty())
        EIDM_TRACE_INFO(L"  Exported By: %ls", result.wsExportedBy.c_str());

    EIDM_TRACE_INFO(L"\nCredentials: %u", result.dwCredentialCount);
    EIDM_TRACE_INFO(L"Warnings: %u", static_cast<DWORD>(result.warnings.size()));
    EIDM_TRACE_INFO(L"Errors: %u", static_cast<DWORD>(result.errors.size()));

    if (result.dwCredentialCount > 0)
    {
        EIDM_TRACE_INFO(L"\nCredential Details:");
        for (const auto& cred : result.credentials)
        {
            EIDM_TRACE_INFO(L"  - User: %ls (RID: %u)", cred.wsUsername.c_str(), cred.dwRid);

            const char* encryptType = "unknown";  // NOSONAR - INIT-01: default fallback retained for unmatched enum values
            switch (cred.EncryptionType)
            {  // NOSONAR - ENUM-01: enum kept for readability
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
            EIDM_TRACE_INFO(L"    Encryption: %S", encryptType);

            if (!cred.Certificate.empty())
            {
                EIDM_TRACE_INFO(L"    Certificate: %u bytes", static_cast<DWORD>(cred.Certificate.size()));
            }
            else
            {
                EIDM_TRACE_INFO(L"    Certificate: (none)");
            }
        }
    }

    if (!result.warnings.empty())
    {
        EIDM_TRACE_INFO(L"\nWarnings:");
        for (const auto& wsWarning : result.warnings)
        {
            EIDM_TRACE_INFO(L"  - %ls", wsWarning.c_str());
        }
    }

    if (!result.errors.empty())
    {
        EIDM_TRACE_INFO(L"\nErrors:");
        for (const auto& wsError : result.errors)
        {
            EIDM_TRACE_INFO(L"  - %ls", wsError.c_str());
        }
    }

    EIDM_TRACE_INFO(L"\nOverall: %ls\n", result.IsValid() ? L"PASSED" : L"FAILED");
}
