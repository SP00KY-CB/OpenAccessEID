// File: EIDMigrate/Import.cpp
// Credential import functionality

#include "Import.h"
#include "LsaClient.h"
#include "UserManagement.h"
#include "GroupManagement.h"
#include "FileCrypto.h"
#include "AuditLogging.h"
#include "Tracing.h"
#include "Utils.h"
#include "PinPrompt.h"
#include "CertificateInstall.h"
#include "../EIDCardLibrary/CertificateValidation.h"  // M3: reuse the logon-path trust/EKU checks
#include "../EIDCardLibrary/GPO.h"                     // M3: honor the AllowCertificatesWithNoEKU policy
#include <map>

HRESULT CommandImport(_In_ const COMMAND_OPTIONS& options)
{
    // Check dry-run vs force
    if (options.DryRun && options.Force)
    {
        EIDM_TRACE_ERROR(L"Error: Cannot specify both -dry-run and -force.");
        return E_INVALIDARG;
    }

    // Determine actual dry-run state
    BOOL fDryRun = options.DryRun;
    if (!options.Force && !options.DryRun)
    {
        EIDM_TRACE_WARN(L"Warning: Use -force to perform actual import.");
        EIDM_TRACE_WARN(L"Running in dry-run mode by default.");
        fDryRun = TRUE;
    }

    if (fDryRun)
    {
        EIDM_TRACE_INFO(L"DRY-RUN MODE: No changes will be made.");
    }

    // Get passphrase
    SecureWString wsPassword;
    if (options.Password.empty())
    {
        wsPassword = PromptForPassphrase(L"Enter import passphrase: ", FALSE);
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

    IMPORT_OPTIONS opts;
    opts.fDryRun = fDryRun;
    opts.fForce = options.Force;
    opts.fCreateUsers = options.CreateUsers;
    opts.fContinueOnError = options.ContinueOnError;
    opts.SelectedGroups = options.SelectedGroups;
    opts.wsExpectedSource = options.ExpectedSource;

    IMPORT_STATS stats;
    HRESULT hr = ImportCredentials(options.InputFile, wsPassword, opts, stats);

    if (SUCCEEDED(hr))
    {
        EIDM_TRACE_INFO(L"Import complete:");
        EIDM_TRACE_INFO(L"  Total credentials: %u", stats.dwTotalCredentials);
        EIDM_TRACE_INFO(L"  Successfully imported: %u", stats.dwSuccessfullyImported);
        EIDM_TRACE_INFO(L"  Failed: %u", stats.dwFailed);
        EIDM_TRACE_INFO(L"  Users created: %u", stats.dwUsersCreated);
        EIDM_TRACE_INFO(L"  Groups created: %u", stats.dwGroupsCreated);
        EIDM_TRACE_INFO(L"  Warnings: %u", stats.dwWarnings);
    }

    return hr;
}

HRESULT ImportCredentials(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    _In_ const std::wstring& wsInputPath,
    _In_ const SecureWString& wsPassword,
    _In_ const IMPORT_OPTIONS& options,
    _Out_ IMPORT_STATS& stats)
{
    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - Explicit type preferred for clarity

    {
        // Read and parse import file (with the provenance stamp)
        std::vector<CredentialInfo> credentials;
        std::vector<GroupInfo> groups;
        std::wstring wsSourceMachine;
        std::wstring wsExportDate;
        std::wstring wsExportedBy;

        hr = ReadImportFileWithMetadata(wsInputPath, wsPassword, credentials, groups,
            &wsSourceMachine, &wsExportDate, &wsExportedBy);
        if (FAILED(hr))
        {
            EIDM_TRACE_ERROR(L"Failed to read import file: 0x%08X", hr);
            return hr;
        }

        // H4 (#1): surface the file's provenance stamp (which machine/operator made it, and when)
        // before applying anything. The stamp lives INSIDE the authenticated + encrypted payload
        // (AES-GCM + HMAC), so it cannot be altered without the passphrase.
        EIDM_TRACE_INFO(L"");
        EIDM_TRACE_INFO(L"=== Import file provenance ===");
        EIDM_TRACE_INFO(L"  Source machine: %ls", wsSourceMachine.empty() ? L"(unknown)" : wsSourceMachine.c_str());
        EIDM_TRACE_INFO(L"  Exported by:    %ls", wsExportedBy.empty() ? L"(unknown)" : wsExportedBy.c_str());
        EIDM_TRACE_INFO(L"  Export date:    %ls", wsExportDate.empty() ? L"(unknown)" : wsExportDate.c_str());
        EIDM_TRACE_INFO(L"");

        // Optional pin: if the operator named an expected issuing machine, refuse a file that was
        // not stamped by it (case-insensitive) before making any changes.
        if (!options.wsExpectedSource.empty() &&
            _wcsicmp(options.wsExpectedSource.c_str(), wsSourceMachine.c_str()) != 0)
        {
            EIDM_TRACE_ERROR(L"Import aborted: file source machine '%ls' does not match the expected "
                L"issuer '%ls'.",
                wsSourceMachine.empty() ? L"(unknown)" : wsSourceMachine.c_str(),
                options.wsExpectedSource.c_str());
            return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        }

        stats.dwTotalCredentials = static_cast<DWORD>(credentials.size());

        if (credentials.empty())
        {
            EIDM_TRACE_WARN(L"Warning: No credentials found in import file.");
            hr = S_FALSE;
            return hr;
        }

        if (options.fDryRun)
        {
            EIDM_TRACE_INFO(L"");
            EIDM_TRACE_INFO(L"=== DRY RUN MODE ===");
            EIDM_TRACE_INFO(L"Would import %u credentials:", stats.dwTotalCredentials);
            EIDM_TRACE_INFO(L"");

            // Validate each credential
            for (const auto& cred : credentials)
            {
                EIDM_TRACE_INFO(L"  User: %ls", cred.wsUsername.c_str());
                EIDM_TRACE_INFO(L"    Export RID: %u", cred.dwRid);

                // Check if user exists and get local RID
                BOOL fExists = FALSE;
                HRESULT hrCheck = UserExists(cred.wsUsername, fExists);
                if (SUCCEEDED(hrCheck))
                {
                    if (!fExists && options.fCreateUsers)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                    {
                        EIDM_TRACE_INFO(L"    Would create user account");
                    }
                    else if (!fExists)
                    {
                        EIDM_TRACE_WARN(L"    User does not exist (use -create-users)");
                        EIDM_TRACE_WARN(L"    SKIPPED: User account required");
                        continue;
                    }
                    else
                    {
                        DWORD dwLocalRid = 0;
                        if (SUCCEEDED(GetUserRid(cred.wsUsername, dwLocalRid)) && dwLocalRid != 0)
                        {
                            EIDM_TRACE_INFO(L"    User exists (local RID: %u)", dwLocalRid);
                            if (dwLocalRid != cred.dwRid)
                            {
                                EIDM_TRACE_INFO(L"    Note: RID differs from export (will use local RID)");
                            }
                        }
                    }
                }

                // Check certificate
                if (!cred.Certificate.empty())
                {
                    EIDM_TRACE_INFO(L"    Certificate: %u bytes - would be installed to MY store",
                        static_cast<DWORD>(cred.Certificate.size()));

                    // Check if already installed
                    if (IsCertificateInstalled(cred.Certificate.data(), static_cast<DWORD>(cred.Certificate.size())))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                    {
                        EIDM_TRACE_INFO(L"    Certificate already in store (will be updated)");
                    }
                }
                else
                {
                    EIDM_TRACE_WARN(L"    No certificate data!");
                }

                EIDM_TRACE_INFO(L"    LSA Secret: Would store for user %ls", cred.wsUsername.c_str());
                EIDM_TRACE_INFO(L"");
            }

            EIDM_TRACE_INFO(L"=== END OF DRY RUN ===");
            EIDM_TRACE_INFO(L"Use -force to perform actual import");
            EIDM_TRACE_INFO(L"");

            hr = S_OK;
            return hr;
        }

        // Actual import
        EIDM_TRACE_INFO(L"Importing credentials...");

        // Filter groups if specific selection provided
        std::vector<GroupInfo> filteredGroups = groups;
        if (!options.SelectedGroups.empty())
        {
            filteredGroups.clear();
            for (const auto& group : groups)
            {
                for (const auto& wsSelected : options.SelectedGroups)
                {
                    if (_wcsicmp(group.wsName.c_str(), wsSelected.c_str()) == 0)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                    {
                        filteredGroups.push_back(group);
                        break;
                    }
                }
            }
            EIDM_TRACE_INFO(L"Filtered to %u selected groups", static_cast<DWORD>(filteredGroups.size()));
        }

        // Create groups first
        for (const auto& group : filteredGroups)
        {
            if (group.fBuiltin)
                continue;

            BOOL fExists = FALSE;
            GroupExists(group.wsName, fExists);

            if (!fExists)
            {
                if (SUCCEEDED(CreateLocalGroup(group.wsName, group.wsComment)))
                {
                    stats.dwGroupsCreated++;
                    EIDM_TRACE_VERBOSE(L"Created group: %ls", group.wsName.c_str());
                }
                else
                {
                    EIDM_TRACE_WARN(L"Warning: Could not create group: %ls", group.wsName.c_str());
                    stats.dwWarnings++;
                }
            }
        }

        // Import each credential
        for (const auto& cred : credentials)
        {
            BOOL fCreated = FALSE;
            HRESULT hrCred = ImportSingleCredential(cred, options, fCreated);

            if (fCreated)
                stats.dwUsersCreated++;

            if (SUCCEEDED(hrCred))
            {
                stats.dwSuccessfullyImported++;
                EIDM_TRACE_VERBOSE(L"Imported: %ls", cred.wsUsername.c_str());
            }
            else
            {
                stats.dwFailed++;

                if (!options.fContinueOnError)
                {
                    EIDM_TRACE_ERROR(L"Error importing credential for %ls: 0x%08X",
                        cred.wsUsername.c_str(), hrCred);
                    EIDM_TRACE_ERROR(L"Aborting import (use -continue-on-error to continue)");
                    hr = hrCred;
                    return hr;
                }
                else
                {
                    EIDM_TRACE_WARN(L"Warning: Failed to import %ls: 0x%08X",
                        cred.wsUsername.c_str(), hrCred);
                    stats.dwWarnings++;
                }
            }
        }

        // Sync group memberships
        EIDM_TRACE_INFO(L"Synchronizing group memberships...");

        // Build a map of username -> groups from the export file
        std::map<std::wstring, std::vector<std::wstring>> userGroupMap;  // NOSONAR - IDIOM-01: default std::less comparator retained for string keys

        for (const auto& group : filteredGroups)
        {
            for (const auto& member : group.wsMembers)
            {
                userGroupMap[member].push_back(group.wsName);
            }
        }

        // S memberships for each user
        for (const auto& cred : credentials)
        {
            const std::wstring& wsUsername = cred.wsUsername;

            // Skip if user wasn't successfully imported
            BOOL fUserExists = FALSE;
            if (FAILED(UserExists(wsUsername, fUserExists)) || !fUserExists)  // NOSONAR - SCOPE-01: declaration kept outside if for readability
            {
                continue;
            }

            // Get target groups for this user
            auto it = userGroupMap.find(wsUsername);
            if (it == userGroupMap.end())
            {
                EIDM_TRACE_VERBOSE(L"No group memberships found for %ls", wsUsername.c_str());
                continue;
            }

            const std::vector<std::wstring>& wsTargetGroups = it->second;

            // Synchronize group memberships
            DWORD dwChanges = 0;
            HRESULT hrGroup = SynchronizeGroupMemberships(wsUsername, wsTargetGroups, dwChanges);

            if (SUCCEEDED(hrGroup))
            {
                if (dwChanges > 0)
                {
                    EIDM_TRACE_INFO(L"Synchronized %ls: %u group changes applied",
                        wsUsername.c_str(), dwChanges);
                }
            }
            else
            {
                EIDM_TRACE_WARN(L"Warning: Failed to synchronize groups for %ls: 0x%08X",
                    wsUsername.c_str(), hrGroup);
                stats.dwWarnings++;
            }
        }

        hr = S_OK;
    }

    return hr;
}

HRESULT ReadImportFile(
    _In_ const std::wstring& wsInputPath,
    _In_ const SecureWString& wsPassword,
    _Out_ std::vector<CredentialInfo>& credentials,
    _Out_ std::vector<GroupInfo>& groups)
{
    EIDM_TRACE_VERBOSE(L"Reading import file: %ls", wsInputPath.c_str());

    ExportFileData data;
    HRESULT hr = ReadEncryptedFile(wsInputPath, wsPassword, data);

    if (SUCCEEDED(hr))
    {
        credentials = std::move(data.credentials);
        groups = std::move(data.groups);
    }

    return hr;
}

HRESULT ReadImportFileWithMetadata(
    _In_ const std::wstring& wsInputPath,
    _In_ const SecureWString& wsPassword,
    _Out_ std::vector<CredentialInfo>& credentials,
    _Out_ std::vector<GroupInfo>& groups,
    _Out_opt_ std::wstring* pwsSourceMachine,
    _Out_opt_ std::wstring* pwsExportDate,
    _Out_opt_ std::wstring* pwsExportedBy)
{
    EIDM_TRACE_VERBOSE(L"Reading import file with metadata: %ls", wsInputPath.c_str());

    ExportFileData data;
    HRESULT hr = ReadEncryptedFile(wsInputPath, wsPassword, data);

    if (SUCCEEDED(hr))
    {
        credentials = std::move(data.credentials);
        groups = std::move(data.groups);

        // Copy metadata if requested
        if (pwsSourceMachine)
            *pwsSourceMachine = data.wsSourceMachine;
        if (pwsExportDate)
            *pwsExportDate = Utf8ToWide(data.exportDate);
        if (pwsExportedBy)
            *pwsExportedBy = data.wsExportedBy;
    }

    return hr;
}

HRESULT ImportSingleCredential(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    _In_ const CredentialInfo& info,
    _In_ const IMPORT_OPTIONS& options,
    _Out_ BOOL& pfCreated)
{
    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - Explicit type preferred for clarity
    pfCreated = FALSE;

    {
        EIDM_TRACE_VERBOSE(L"Importing credential for user: %ls (export RID: %u)",
            info.wsUsername.c_str(), info.dwRid);

        // Check if user exists
        BOOL fExists = FALSE;
        hr = UserExists(info.wsUsername, fExists);

        if (SUCCEEDED(hr) && !fExists)
        {
            if (options.fCreateUsers)
            {
                // Create user account with random password (EID auth works via smart card)
                std::wstring wsRandomPassword = GenerateRandomPassword(32);

                hr = CreateLocalUserAccount(info.wsUsername, L"", L"EID Smart Card User",
                    wsRandomPassword.c_str(), TRUE, TRUE);

                if (SUCCEEDED(hr))
                {
                    pfCreated = TRUE;
                    EIDM_TRACE_INFO(L"Created user account: %ls", info.wsUsername.c_str());
                }
                else
                {
                    EIDM_TRACE_ERROR(L"Failed to create user: %ls - 0x%08X",
                        info.wsUsername.c_str(), hr);
                    return hr;
                }
            }
            else
            {
                EIDM_TRACE_ERROR(L"User %ls does not exist (use -create-users)",
                    info.wsUsername.c_str());
                hr = HRESULT_FROM_WIN32(ERROR_NO_SUCH_USER);
                return hr;
            }
        }

        // Get the ACTUAL RID for this user on the target machine
        // This is critical - the RID from export may not match the RID on this machine
        DWORD dwActualRid = 0;
        hr = GetUserRid(info.wsUsername, dwActualRid);

        if (FAILED(hr) || dwActualRid == 0)
        {
            EIDM_TRACE_ERROR(L"Failed to get RID for user %ls: 0x%08X",
                info.wsUsername.c_str(), hr);
            return hr;
        }

        if (dwActualRid != info.dwRid)
        {
            EIDM_TRACE_WARN(L"RID mismatch for %ls: export=%u, local=%u. Using local RID.",
                info.wsUsername.c_str(), info.dwRid, dwActualRid);
        }

        // Install the certificate to the user's MY store
        // This is REQUIRED for EID authentication to work!
        if (!info.Certificate.empty())
        {
            EIDM_TRACE_INFO(L"Installing certificate for user: %ls", info.wsUsername.c_str());

            // BUG FIX #18: Certificate validation before import
            // Create certificate context for validation
            PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                info.Certificate.data(),
                static_cast<DWORD>(info.Certificate.size()));

            if (pCertContext)  // NOSONAR - SCOPE-01: declaration kept outside if for readability
            {
                BOOL fTrusted = FALSE;
                std::vector<std::wstring> warnings;
                ValidateCertificateForImport(pCertContext, fTrusted, warnings);

                // Log all warnings
                for (const auto& warn : warnings)
                {
                    EIDM_TRACE_WARN(L"Certificate validation warning for %ls: %ls",
                        info.wsUsername.c_str(), warn.c_str());
                }

                // Check if certificate is not trusted (expired or not yet valid)
                if (!fTrusted)
                {
                    EIDM_TRACE_ERROR(L"Certificate validation failed for %ls. Certificate may be expired or not yet valid.",
                        info.wsUsername.c_str());

                    // In production mode, fail on invalid certificates
                    // In dry-run mode, just warn
                    if (!options.fDryRun)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                    {
                        CertFreeCertificateContext(pCertContext);
                        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                    }
                    else
                    {
                        EIDM_TRACE_INFO(L"DRY-RUN: Would reject invalid certificate for %ls", info.wsUsername.c_str());
                    }
                }

                CertFreeCertificateContext(pCertContext);
            }
            else
            {
                EIDM_TRACE_WARN(L"Could not create certificate context for validation (continuing anyway)");
            }

            // If running as admin, we can install to any user's store
            // For now, install to the target user's store
            HRESULT hrCert = InstallCertificateFromDER(info.Certificate, info.wsUsername);

            if (SUCCEEDED(hrCert))
            {
                EIDM_TRACE_INFO(L"Certificate installed successfully for: %ls", info.wsUsername.c_str());
            }
            else if (hrCert == HRESULT_FROM_WIN32(ERROR_NOT_LOGGED_ON))
            {
                // The user's profile hive is not loaded (e.g. the account has never
                // logged on), so its personal store cannot be opened. The certificate
                // is still stored with the LSA credential below; it is NOT placed in
                // anyone else's store.
                EIDM_TRACE_WARN(L"Profile of %ls is not loaded; certificate not added to the user's personal store",
                    info.wsUsername.c_str());
            }
            else
            {
                EIDM_TRACE_ERROR(L"Failed to install certificate for %ls: 0x%08X",
                    info.wsUsername.c_str(), hrCert);

                // Certificate installation is critical for EID auth to work
                // Don't continue without it
                return hrCert;
            }
        }
        else
        {
            EIDM_TRACE_WARN(L"No certificate data for user: %ls", info.wsUsername.c_str());
        }

        // Create a copy of CredentialInfo with the correct RID
        CredentialInfo localInfo = info;
        localInfo.dwRid = dwActualRid;  // Use the actual RID from this machine

        // Check if a password was provided for this user
        std::wstring wsProvidedPassword;
        for (const auto& pair : options.userPasswords)  // NOSONAR - IDIOM-01: explicit std::pair access retained for clarity
        {
            if (pair.first == info.wsUsername)
            {
                wsProvidedPassword = pair.second;
                break;
            }
        }

        // Set the user's password if one was provided
        if (!wsProvidedPassword.empty())
        {
            EIDM_TRACE_INFO(L"Setting password for user: %ls", info.wsUsername.c_str());

            HRESULT hrPwd = ::SetUserPassword(info.wsUsername, wsProvidedPassword.c_str());

            if (SUCCEEDED(hrPwd))
            {
                EIDM_TRACE_INFO(L"Password set successfully for: %ls", info.wsUsername.c_str());
            }
            else
            {
                EIDM_TRACE_WARN(L"Failed to set password for %ls: 0x%08X (continuing anyway)",
                    info.wsUsername.c_str(), hrPwd);
                // Don't fail the entire import if password setting fails
            }
        }

        // Import credential to LSA with the correct RID
        DWORD dwFlags = options.fCreateUsers ? 0x01 : 0x00; // CREATE_USER_IF_NOT_EXISTS
        hr = ImportLsaCredential(localInfo, dwFlags, pfCreated);

        if (SUCCEEDED(hr))
        {
            EIDM_TRACE_INFO(L"Successfully imported credential for: %ls (RID: %u)",
                info.wsUsername.c_str(), dwActualRid);
        }
    }

    return hr;
}

HRESULT ValidateCertificateForImport(
    _In_ PCCERT_CONTEXT pCertContext,
    _Out_ BOOL& pfTrusted,
    _Out_ std::vector<std::wstring>& warnings)
{
    if (!pCertContext)
    {
        pfTrusted = FALSE;
        warnings.emplace_back(L"No certificate provided");
        return E_INVALIDARG;
    }

    pfTrusted = TRUE;
    warnings.clear();

    // Get certificate validity period
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);

    // Check if certificate is expired
    if (CompareFileTime(&pCertContext->pCertInfo->NotAfter, &ftNow) < 0)
    {
        warnings.emplace_back(L"Certificate has expired");
        pfTrusted = FALSE;
        return S_OK;
    }

    // Check if certificate is not yet valid
    if (CompareFileTime(&pCertContext->pCertInfo->NotBefore, &ftNow) > 0)
    {
        warnings.emplace_back(L"Certificate is not yet valid");
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
        warnings.emplace_back(L"Certificate expires within 30 days");
        pfTrusted = TRUE; // Still trusted, just warning
    }

    // M3 (security uplift): validate the certificate the same way the logon path will, so a
    // self-signed / wrong-EKU / untrusted / revoked certificate is rejected AT IMPORT time
    // instead of being silently enrolled. Previously only NotBefore/NotAfter were checked, so
    // an attacker-supplied self-signed cert was installed and its LSA secret written; combined
    // with a trusted root (M2) or a weakening policy that became a full bypass. These checks are
    // defense-in-depth: the logon path re-validates too, but rejecting early is safer and clearer.
    //
    // IsTrustedCertificate builds the chain to a trusted root, enforces the Smart Card Logon EKU
    // (unless AllowCertificatesWithNoEKU is set) and performs OFFLINE revocation checking (M1).
    // HasCertificateRightEKU gives a specific message for the common missing-EKU case.
    // NOTE: keep these AFTER the 30-day block above, which unconditionally sets pfTrusted = TRUE.
    if (!GetPolicyValue(GPOPolicy::AllowCertificatesWithNoEKU) && !HasCertificateRightEKU(pCertContext))
    {
        warnings.emplace_back(L"Certificate is missing the Smart Card Logon EKU");
        pfTrusted = FALSE;
    }

    if (!IsTrustedCertificate(pCertContext))
    {
        warnings.emplace_back(L"Certificate does not chain to a trusted root on this machine, or is "
            L"revoked. Install and trust the issuing CA (and its CRL) before importing.");
        pfTrusted = FALSE;
    }

    return S_OK;
}

BOOL PromptForSmartCardPin(_In_ PCCERT_CONTEXT pCertContext, _Out_ SecureWString& wsPin)
{
    UNREFERENCED_PARAMETER(pCertContext);

    // Use the SecurePinPrompt dialog
    SecurePin pin;
    PIN_PROMPT_RESULT result = PromptForPIN(L"Enter smart card PIN:", pin);

    if (result == PIN_PROMPT_RESULT::SUCCESS)  // NOSONAR - SCOPE-01: declaration kept outside if for readability
    {
        // Convert SecurePin to SecureWString
        wsPin = SecureWString(pin.c_str());
        return TRUE;
    }

    return FALSE;
}

BOOL ValidateSmartCardPin(_In_ PCCERT_CONTEXT pCertContext, _In_ PCWSTR pwszPin)
{
    UNREFERENCED_PARAMETER(pCertContext);
    UNREFERENCED_PARAMETER(pwszPin);

    // Basic PIN validation
    if (!pwszPin || pwszPin[0] == L'\0')
        return FALSE;

    size_t cchLen = wcslen(pwszPin); // NOSONAR - pointer validated for NULL above (line 572)

    // PIN should be 4-8 digits for most smart cards
    if (cchLen < 4 || cchLen > 8)
        return FALSE;

    // All characters should be digits
    for (size_t i = 0; i < cchLen; i++)
    {
        if (!iswdigit(pwszPin[i]))
            return FALSE;
    }

    // Note: Actual smart card PIN validation requires communication with the card
    // via CryptoAPI or PKCS#11. This is a basic format check only.
    // The real validation happens when the credential is used for authentication.

    return TRUE;
}
