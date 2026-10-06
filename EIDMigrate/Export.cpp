// File: EIDMigrate/Export.cpp
// Credential export functionality

#include "Export.h"
#include "CryptoHelpers.h"
#include "LsaClient.h"
#include "GroupManagement.h"
#include "FileCrypto.h"
#include "AuditLogging.h"
#include "Tracing.h"
#include "Utils.h"
#include <fstream>

HRESULT CommandExport(_In_ const COMMAND_OPTIONS& options)
{
    EIDM_TRACE_INFO(L"Exporting credentials to: %ls", options.OutputFile.c_str());

    // Get passphrase
    SecureWString wsPassword;
    if (options.Password.empty())
    {
        wsPassword = PromptForPassphrase(L"Enter export passphrase (min 16 characters): ", TRUE);
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

    if (!ValidatePassphraseStrength(wsPassword.c_str()))
    {
        EIDM_TRACE_ERROR(L"Passphrase must be at least 16 characters.");
        return E_INVALIDARG;
    }

    EXPORT_OPTIONS opts;
    opts.fValidateCerts = options.ValidateCerts;
    opts.wsSourceMachine = GetComputerName();
    opts.fIncludeGroups = TRUE;
    opts.SelectedGroups = options.SelectedGroups;

    EXPORT_STATS stats;
    HRESULT hr = ExportCredentials(options.OutputFile, wsPassword, opts, stats);

    if (SUCCEEDED(hr))
    {
        EIDM_TRACE_INFO(L"Export complete:");
        EIDM_TRACE_INFO(L"  Total credentials: %u", stats.dwTotalCredentials);
        EIDM_TRACE_INFO(L"  Certificate-encrypted: %u", stats.dwCertificateEncrypted);
        EIDM_TRACE_INFO(L"  DPAPI-encrypted (skipped): %u", stats.dwDpapiEncrypted);
        EIDM_TRACE_INFO(L"  Groups exported: %u", stats.dwGroupsExported);
    }

    return hr;
}

HRESULT ExportCredentials(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    _In_ const std::wstring& wsOutputPath,
    _In_ const SecureWString& wsPassword,
    _In_ const EXPORT_OPTIONS& options,
    _Out_ EXPORT_STATS& stats)
{
    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - Explicit type preferred for HRESULT clarity

    // Enumerate credentials
    std::vector<CredentialInfo> credentials;
    hr = EnumerateEidCredentials(credentials);
    if (FAILED(hr))
    {
        EIDM_TRACE_ERROR(L"Failed to enumerate credentials: 0x%08X", hr);
        return hr;
    }

    stats.dwTotalCredentials = static_cast<DWORD>(credentials.size());

    // Enumerate groups
    std::vector<LocalGroupInfo> groups;
    if (options.fIncludeGroups)
    {
        hr = EnumerateLocalGroups(groups);
        if (SUCCEEDED(hr))
        {
            // Filter groups if specific selection provided
            if (!options.SelectedGroups.empty())
            {
                std::vector<LocalGroupInfo> filteredGroups;
                for (const auto& group : groups)
                {
                    for (const auto& wsSelected : options.SelectedGroups)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                    {
                        if (_wcsicmp(group.wsName.c_str(), wsSelected.c_str()) == 0)
                        {
                            filteredGroups.push_back(group);
                            break;
                        }
                    }
                }
                groups = filteredGroups;
                EIDM_TRACE_INFO(L"Filtered to %u selected groups", static_cast<DWORD>(groups.size()));
            }
            stats.dwGroupsExported = static_cast<DWORD>(groups.size());
        }
        else
        {
            EIDM_TRACE_WARN(L"Warning: Could not enumerate local groups: 0x%08X", hr);
            // Continue anyway
        }
    }

    // Build export data
    ExportFileData data;
    data.dwVersion = EIDMIGRATE_VERSION;
    data.formatVersion = "1.0";
    data.exportDate = GetExportDate();
    data.wsSourceMachine = options.wsSourceMachine;
    data.wsExportedBy = GetUserName();
    data.credentials = std::move(credentials);  // not used after this point
    data.stats.totalCredentials = 0;
    data.stats.certificateEncrypted = 0;
    data.stats.dpapiEncrypted = 0;
    data.stats.skipped = 0;

    // Convert groups (LocalGroupInfo to GroupInfo)
    for (const auto& localGroup : groups)
    {
        GroupInfo groupInfo;
        groupInfo.wsName = localGroup.wsName;
        groupInfo.wsComment = localGroup.wsComment;
        groupInfo.wsMembers = localGroup.wsMembers;
        groupInfo.fBuiltin = localGroup.fBuiltin;
        data.groups.push_back(groupInfo);
    }

    // Filter out DPAPI credentials
    auto it = data.credentials.begin();
    while (it != data.credentials.end())
    {
        if (it->EncryptionType == EID_PRIVATE_DATA_TYPE::eidpdtDPAPI)
        {
            stats.dwDpapiEncrypted++;
            EIDM_TRACE_VERBOSE(L"Skipping DPAPI credential for user: %ls", it->wsUsername.c_str());
            it = data.credentials.erase(it);
        }
        else
        {
            stats.dwCertificateEncrypted++;
            ++it;
        }
    }

    data.stats.totalCredentials = stats.dwCertificateEncrypted;
    data.stats.certificateEncrypted = stats.dwCertificateEncrypted;
    data.stats.dpapiEncrypted = stats.dwDpapiEncrypted;
    data.stats.skipped = stats.dwSkipped;

    if (data.credentials.empty())
    {
        EIDM_TRACE_WARN(L"Warning: No exportable credentials found.");
        return S_FALSE;
    }

    // Build JSON and check size
    // Only the size is traced: the payload carries the encrypted passwords and keys.
    std::string jsonPayload = ExportDataToJson(data);
    EIDM_TRACE_INFO(L"JSON payload size: %zu bytes", jsonPayload.size());
    if (!jsonPayload.empty())
        SecureZeroMemory(&jsonPayload[0], jsonPayload.size());

    // Write encrypted file
    hr = WriteEncryptedFile(wsOutputPath, wsPassword, data);
    if (FAILED(hr))
    {
        EIDM_TRACE_ERROR(L"Failed to write export file: 0x%08X", hr);
        return hr;
    }

    return hr;
}

HRESULT EnumerateEidCredentials(_Out_ std::vector<CredentialInfo>& credentials)
{
    EIDM_TRACE_VERBOSE(L"Enumerating EID credentials...");

    HRESULT hr = EnumerateLsaCredentials(credentials);
    if (SUCCEEDED(hr))
    {
        EIDM_TRACE_INFO(L"Found %u EID credentials", static_cast<DWORD>(credentials.size()));
    }

    return hr;
}

HRESULT ExportSingleCredential(_In_ DWORD dwRid, _Out_ CredentialInfo& info)
{
    EIDM_TRACE_VERBOSE(L"Exporting credential for RID %u", dwRid);
    return ExportLsaCredential(dwRid, info);
}

HRESULT ValidateCertificateForExport(
    _In_ PCCERT_CONTEXT pCertContext,
    _Out_ BOOL& pfTrusted,
    _Out_ std::wstring& wsWarning)
{
    if (!pCertContext)
    {
        pfTrusted = FALSE;
        wsWarning = L"No certificate provided";
        return E_INVALIDARG;
    }

    pfTrusted = TRUE;
    wsWarning.clear();

    // Get certificate validity period
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);

    // Check if certificate is expired
    if (CompareFileTime(&pCertContext->pCertInfo->NotAfter, &ftNow) < 0)
    {
        wsWarning = L"Certificate has expired";
        pfTrusted = FALSE;
        return S_OK;
    }

    // Check if certificate is not yet valid
    if (CompareFileTime(&pCertContext->pCertInfo->NotBefore, &ftNow) > 0)
    {
        wsWarning = L"Certificate is not yet valid";
        pfTrusted = FALSE;
        return S_OK;
    }

    // Check for expiration within 30 days
    FILETIME ftThirtyDays;
    ULARGE_INTEGER uli;
    memcpy(&uli.QuadPart, &ftNow, sizeof(uli.QuadPart));  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
    uli.QuadPart += ULONGLONG(30) * 24 * 60 * 60 * 10000000; // 30 days in 100ns units
    memcpy(&ftThirtyDays, &uli.QuadPart, sizeof(ftThirtyDays));  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified

    if (CompareFileTime(&pCertContext->pCertInfo->NotAfter, &ftThirtyDays) < 0)
    {
        wsWarning = L"Certificate expires within 30 days";
        pfTrusted = TRUE; // Still trusted, just warning
    }

    return S_OK;
}

HRESULT EnumerateLocalGroups(_Out_ std::vector<GroupInfo>& groups)
{
    EIDM_TRACE_VERBOSE(L"Enumerating local groups...");

    std::vector<LocalGroupInfo> localGroups;
    HRESULT hr = ::EnumerateLocalGroups(localGroups);

    if (SUCCEEDED(hr))
    {
        // Convert LocalGroupInfo to GroupInfo
        for (const auto& localGroup : localGroups)
        {
            GroupInfo info;
            info.wsName = localGroup.wsName;
            info.wsComment = localGroup.wsComment;
            info.wsMembers = localGroup.wsMembers;
            info.fBuiltin = localGroup.fBuiltin;
            groups.push_back(info);
        }

        EIDM_TRACE_VERBOSE(L"Enumerated %u groups", static_cast<DWORD>(groups.size()));
    }

    return hr;
}

HRESULT GetUserGroupMemberships(_In_ DWORD dwRid, _Out_ std::vector<std::wstring>& groupNames)
{
    groupNames.clear();

    // Get username from RID
    std::wstring wsUsername = LookupUsernameByRid(dwRid);
    if (wsUsername.empty())
    {
        EIDM_TRACE_WARN(L"Could not find username for RID %u", dwRid);
        return HRESULT_FROM_WIN32(ERROR_NO_SUCH_USER);
    }

    // Get user's local groups
    HRESULT hr = GetUserGroups(wsUsername, groupNames);
    if (SUCCEEDED(hr))
    {
        EIDM_TRACE_VERBOSE(L"User %ls is in %u groups", wsUsername.c_str(),
            static_cast<DWORD>(groupNames.size()));
    }

    return hr;
}

// Get current date/time in ISO 8601 format for export
std::string GetExportDate()
{
    return WideToUtf8(FormatCurrentTimestamp());
}
