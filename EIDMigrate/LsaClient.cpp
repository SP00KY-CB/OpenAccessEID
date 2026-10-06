// File: EIDMigrate/LsaClient.cpp
// LSA IPC client functions

#include "LsaClient.h"
#include "Tracing.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"  // For EID_PRIVATE_DATA
#include "../EIDCardLibrary/InputValidation.h"  // Canonical EID_PRIVATE_DATA layout rule
#include <lm.h>  // NOSONAR - INCLUDE-01: include order/casing significant for Windows SDK
#include <ntstatus.h>
#include <sddl.h>  // For ConvertSidToStringSidW
#include <intsafe.h>  // For SizeTToUShort (BUG 9: checked narrowing to EID_PRIVATE_DATA's USHORT fields)
#include <vector>

#pragma comment(lib, "netapi32.lib")

// Forward declarations from EIDCardLibrary/Package.h
extern PTSTR GetUsernameFromRid(__in DWORD dwRid);
extern DWORD GetRidFromUsername(LPTSTR szUsername);

// Forward declarations for IPC functions from EIDCardLibrary/Package.cpp
HRESULT LsaEIDEnumerateCredentials(_Out_ std::vector<EIDM_CREDENTIAL_SUMMARY>& summaries);
HRESULT LsaEIDExportCredential(_In_ DWORD dwRid, _Out_ PEIDM_EXPORT_RESPONSE* ppResponse);
HRESULT LsaEIDImportCredential(
    _In_ const EIDM_IMPORT_REQUEST* pRequest,
    _In_reads_bytes_(cbPrivateData) const BYTE* pbPrivateData,
    _In_ DWORD cbPrivateData,
    _In_reads_bytes_(cbCertificate) const BYTE* pbCertificate,
    _In_ DWORD cbCertificate,
    _In_reads_bytes_(cbPassword) const BYTE* pbPassword,
    _In_ DWORD cbPassword,
    _Out_ PEIDM_IMPORT_RESPONSE* ppResponse);

// NT_SUCCESS macro
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Enumerate all EID credentials from LSA
// Uses direct LSA access instead of the authentication package IPC
HRESULT EnumerateLsaCredentials(_Out_ std::vector<CredentialInfo>& credentials, _Out_opt_ DWORD* pdwUnreadable)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    // Accounts skipped because their credential state could not be read
    // (lookup/allocation failure, unreadable or malformed secret). Listing
    // and export tolerate these; the import binding check must not.
    DWORD dwUnreadable = 0;
    if (pdwUnreadable)
    {
        *pdwUnreadable = 0;
    }
    // BUG FIX #19: C++ exception handling for LSA operations
    // Ensures proper cleanup even if C++ exceptions occur
    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
    HANDLE hLsa = nullptr;
    LPUSER_INFO_0 pUserInfoArray = nullptr;

    try
    {
        EIDM_TRACE_VERBOSE(L"Enumerating LSA credentials via direct LSA access...");

        NTSTATUS status;
        LSA_OBJECT_ATTRIBUTES objectAttributes = {};
        objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

        // Open LSA policy with access to read private data
        status = LsaOpenPolicy(
            nullptr,
            &objectAttributes,
            POLICY_GET_PRIVATE_INFORMATION | POLICY_VIEW_LOCAL_INFORMATION,
            &hLsa);

        if (!NT_SUCCESS(status))
        {
            EIDM_TRACE_ERROR(L"Failed to open LSA policy: 0x%08X", status);
            return HRESULT_FROM_NT(status);
        }

        // Enumerate local users
        DWORD dwEntriesRead = 0;
        DWORD dwTotalEntries = 0;

        DWORD dwNetStatus = NetUserEnum(nullptr, 0, FILTER_NORMAL_ACCOUNT,
            reinterpret_cast<LPBYTE*>(&pUserInfoArray), // NOSONAR - Windows Net API requires LPBYTE* for output parameter
            MAX_PREFERRED_LENGTH,
            &dwEntriesRead,
            &dwTotalEntries,
            nullptr);

        if (dwNetStatus != NERR_Success)
        {
            EIDM_TRACE_ERROR(L"Failed to enumerate users: %u", dwNetStatus);
            hr = HRESULT_FROM_WIN32(dwNetStatus);
            goto cleanup;
        }

        EIDM_TRACE_VERBOSE(L"Found %u local user(s) to check for credentials", dwEntriesRead);

    // Check each user for EID credentials
    for (DWORD i = 0; i < dwEntriesRead; i++)
    {
        if (!pUserInfoArray[i].usri0_name)
            continue;

        EIDM_TRACE_VERBOSE(L"Checking user '%ls'", pUserInfoArray[i].usri0_name);

        // Get SID for this user
        DWORD dwSidSize = 0;
        DWORD dwDomainSize = 0;
        SID_NAME_USE use = SidTypeUser;
        PSID pSid = nullptr;

        // First call to get SID size
        if (!LookupAccountNameW(nullptr, pUserInfoArray[i].usri0_name, nullptr, &dwSidSize,
            nullptr, &dwDomainSize, &use))
        {
            // Expected to fail, but should set buffer sizes
        }

        if (dwSidSize == 0)
        {
            EIDM_TRACE_WARN(L"Failed to get SID size for user '%ls'", pUserInfoArray[i].usri0_name);
            dwUnreadable++;
            continue;
        }

        pSid = static_cast<PSID>(malloc(dwSidSize)); // NOSONAR - LookupAccountNameW requires malloc/free for SID buffer
        if (!pSid)
        {
            EIDM_TRACE_ERROR(L"Failed to allocate %u bytes for SID", dwSidSize);
            dwUnreadable++;
            continue;
        }
        SecureZeroMemory(pSid, dwSidSize);

        // Allocate domain buffer
        PWSTR pwszDomain = static_cast<PWSTR>(malloc(dwDomainSize * sizeof(WCHAR))); // NOSONAR - LookupAccountNameW requires malloc/free for domain buffer
        if (!pwszDomain)
        {
            EIDM_TRACE_ERROR(L"Failed to allocate domain buffer");
            free(pSid);  // NOSONAR - ALLOC-01: malloc paired with existing free/Win32 alloc
            dwUnreadable++;
            continue;
        }

        // Second call to get actual SID
        if (!LookupAccountNameW(nullptr, pUserInfoArray[i].usri0_name, pSid, &dwSidSize,
            pwszDomain, &dwDomainSize, &use))
        {
            EIDM_TRACE_WARN(L"LookupAccountNameW failed for '%ls'", pUserInfoArray[i].usri0_name);
            free(pSid);  // NOSONAR - ALLOC-01: malloc paired with existing free/Win32 alloc
            free(pwszDomain);  // NOSONAR - ALLOC-01: malloc paired with existing free/Win32 alloc
            dwUnreadable++;
            continue;
        }
        free(pwszDomain);  // NOSONAR - ALLOC-01: malloc paired with existing free/Win32 alloc

        // Validate the SID structure
        if (!IsValidSid(pSid))
        {
            EIDM_TRACE_ERROR(L"Invalid SID returned for '%ls'", pUserInfoArray[i].usri0_name);
            free(pSid);  // NOSONAR - ALLOC-01: malloc paired with existing free/Win32 alloc
            dwUnreadable++;
            continue;
        }

        // Extract RID from SID
        DWORD dwSubAuthCount = *GetSidSubAuthorityCount(pSid);
        if (dwSubAuthCount == 0)
        {
            EIDM_TRACE_ERROR(L"SID has no subauthorities for '%ls'", pUserInfoArray[i].usri0_name);
            free(pSid);  // NOSONAR - ALLOC-01: malloc paired with existing free/Win32 alloc
            dwUnreadable++;
            continue;
        }

        DWORD dwRid = *GetSidSubAuthority(pSid, dwSubAuthCount - 1);
        free(pSid);  // NOSONAR - ALLOC-01: malloc paired with existing free/Win32 alloc

        EIDM_TRACE_VERBOSE(L"Checking user '%ls' (RID %u)", pUserInfoArray[i].usri0_name, dwRid);

        // Check if LSA secret exists for this RID
        // Format must match StoredCredentialManagement.cpp: L"%s_%08X" where CREDENTIAL_LSAPREFIX = L"L$_EID_"
        // Result: L$_EID__<RID> (note: double underscore since CREDENTIAL_LSAPREFIX already ends with _)
        WCHAR wszSecretName[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
        swprintf_s(wszSecretName, ARRAYSIZE(wszSecretName), L"L$_EID__%08X", dwRid);

        LSA_UNICODE_STRING lsaSecretName;
        lsaSecretName.Buffer = wszSecretName;
        lsaSecretName.Length = static_cast<USHORT>(wcslen(wszSecretName) * sizeof(WCHAR)); // NOSONAR - wszSecretName is stack-allocated buffer, never NULL
        lsaSecretName.MaximumLength = lsaSecretName.Length + sizeof(WCHAR);

        PLSA_UNICODE_STRING pSecretData = nullptr;
        status = LsaRetrievePrivateData(hLsa, &lsaSecretName, &pSecretData);

        if (NT_SUCCESS(status) && pSecretData && pSecretData->Buffer)
        {
            EIDM_TRACE_INFO(L"Found credential for RID %u (%ls)", dwRid, pUserInfoArray[i].usri0_name);

            CredentialInfo info;
            info.dwRid = dwRid;
            info.wsUsername = pUserInfoArray[i].usri0_name;

            // Get SID separately (outside the secret parsing context)
            info.wsSid = LookupSidByUsername(info.wsUsername);
            if (info.wsSid.empty())
            {
                EIDM_TRACE_WARN(L"Could not lookup SID for '%ls'", info.wsUsername.c_str());
            }

            // Parse the secret data to get certificate hash and encryption type
            // The secret format is: EID_PRIVATE_DATA structure
            // SECURITY: one layout rule, shared with EIDCardLibrary and the fuzz
            // harness (EIDValidatePrivateDataLayout in InputValidation.cpp).
            //
            // What used to be here was a third, divergent implementation: it
            // required sizeof(EID_PRIVATE_DATA) rather than FIELD_OFFSET(...Data)
            // as the minimum, bounded the certificate against the ABSOLUTE
            // pSecretData->Length while bounding the key and password against
            // "Length - sizeof(EID_PRIVATE_DATA)", and did each check inline at
            // the point of use. Three rules for one invariant is how they drift.
            PEID_PRIVATE_DATA pPrivateData = reinterpret_cast<PEID_PRIVATE_DATA>(pSecretData->Buffer); // NOSONAR - Cast from PBYTE* to PEID_PRIVATE_DATA required for LSA private data structure
            if (EIDValidatePrivateDataLayout(pPrivateData, pSecretData->Length))
            {
                // Every region below is now known to lie inside the blob, so the
                // per-region bounds checks that used to wrap each extraction are
                // gone rather than duplicated.

                // Validate structure fields before accessing
                if (pPrivateData->dwType >= static_cast<EID_PRIVATE_DATA_TYPE>(1) &&  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                    pPrivateData->dwType <= static_cast<EID_PRIVATE_DATA_TYPE>(3))
                {
                    info.EncryptionType = pPrivateData->dwType;
                }
                else
                {
                    EIDM_TRACE_WARN(L"Invalid encryption type %d for RID %u", pPrivateData->dwType, dwRid);
                    info.EncryptionType = static_cast<EID_PRIVATE_DATA_TYPE>(0);
                }

                // Hash sits inside the fixed header, which the validator has
                // already established is fully present, so it copies whole.
                constexpr DWORD dwHashCopySize = CERT_HASH_LENGTH;
                memcpy(info.CertificateHash, pPrivateData->Hash, dwHashCopySize);

                // BUG FIX #13: Extract certificate, key, and password data from LSA secret
                // Previously, enumeration only extracted hash and type, causing exports
                // to have empty certificate fields. This prevented successful import.
                //
                // IMPORTANT: The offsets in EID_PRIVATE_DATA are relative to the Data field,
                // NOT the beginning of the structure!
                // - dwCertificatOffset = 0 means certificate starts at pPrivateData->Data
                // - dwSymetricKeyOffset is relative to Data field
                // - dwPasswordOffset is relative to Data field
                //
                // Extract certificate from the Data field at dwCertificatOffset
                if (pPrivateData->dwCertificatSize > 0)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    // Certificate offset is relative to Data field, which is at pPrivateData->Data
                    BYTE* pCertificate = pPrivateData->Data + pPrivateData->dwCertificatOffset;
                    info.Certificate.assign(pCertificate, pCertificate + pPrivateData->dwCertificatSize);
                    EIDM_TRACE_VERBOSE(L"Extracted certificate: %u bytes at offset %u",
                        pPrivateData->dwCertificatSize, pPrivateData->dwCertificatOffset);

                    // Verify it looks like a DER certificate (starts with 0x30)
                    if (pCertificate[0] == 0x30)
                    {
                        EIDM_TRACE_VERBOSE(L"Certificate data verified (DER format)");
                    }
                    else
                    {
                        EIDM_TRACE_WARN(L"Certificate data doesn't look like DER (starts with 0x%02X)", pCertificate[0]);
                    }
                }

                // Extract symmetric key
                // IMPORTANT: Offsets are relative to Data field, not struct start
                if (pPrivateData->dwSymetricKeySize > 0)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    BYTE* pKey = pPrivateData->Data + pPrivateData->dwSymetricKeyOffset;
                    info.SymmetricKey.assign(pKey, pKey + pPrivateData->dwSymetricKeySize);
                    EIDM_TRACE_VERBOSE(L"Extracted symmetric key: %u bytes", pPrivateData->dwSymetricKeySize);
                }

                // Extract encrypted password
                // IMPORTANT: Offsets are relative to Data field, not struct start
                if (pPrivateData->usPasswordLen > 0)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    BYTE* pPassword = pPrivateData->Data + pPrivateData->dwPasswordOffset;
                    info.EncryptedPassword.assign(pPassword, pPassword + pPrivateData->usPasswordLen);
                    EIDM_TRACE_VERBOSE(L"Extracted encrypted password: %u bytes", pPrivateData->usPasswordLen);
                }

                EIDM_TRACE_VERBOSE(L"Parsed credential: type=%d, hash_size=%u, cert_size=%zu",
                    info.EncryptionType, dwHashCopySize, info.Certificate.size());
            }
            else
            {
                EIDM_TRACE_ERROR(L"EID_PRIVATE_DATA layout invalid (%u bytes) for RID %u", pSecretData->Length, dwRid);
                LsaFreeMemory(pSecretData);
                dwUnreadable++;
                continue;
            }

            credentials.push_back(std::move(info));
            LsaFreeMemory(pSecretData);
        }
        else if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            EIDM_TRACE_VERBOSE(L"No credential for RID %u", dwRid);
        }
        else
        {
            // Access denied, an empty secret, or any other failure: whether
            // this account holds a credential is unknown.
            EIDM_TRACE_WARN(L"Could not read the credential secret for RID %u: 0x%08X", dwRid, status);
            if (pSecretData)
            {
                LsaFreeMemory(pSecretData);
            }
            dwUnreadable++;
        }
    }

    hr = S_OK;
    if (pdwUnreadable)
    {
        *pdwUnreadable = dwUnreadable;
    }
    }
    catch (...)  // NOSONAR - EXCEPTION-01: catch-all is intentional guard
    {
        EIDM_TRACE_ERROR(L"Exception occurred during LSA enumeration");
        hr = E_FAIL;
    }

cleanup:
    // Cleanup: always executed regardless of exception
    if (pUserInfoArray)
    {
        NetApiBufferFree(pUserInfoArray);
    }
    if (hLsa)
    {
        LsaClose(hLsa);
    }

    EIDM_TRACE_INFO(L"Enumeration complete: %zu credential(s) found", credentials.size());
    return hr;
}

// Export a single credential from LSA by RID
HRESULT ExportLsaCredential(_In_ DWORD dwRid, _Out_ CredentialInfo& info)
{
    EIDM_TRACE_VERBOSE(L"Exporting credential for RID %u via direct LSA access...", dwRid);

    NTSTATUS status;
    HANDLE hLsa = nullptr;
    LSA_OBJECT_ATTRIBUTES objectAttributes = {};
    objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

    // Open LSA policy
    status = LsaOpenPolicy(
        nullptr,
        &objectAttributes,
        POLICY_GET_PRIVATE_INFORMATION,
        &hLsa);

    if (!NT_SUCCESS(status))
    {
        EIDM_TRACE_ERROR(L"[ERROR] LsaOpenPolicy failed: 0x%08X", status);
        return HRESULT_FROM_NT(status);
    }

    // Retrieve the LSA secret for this RID
    // Format: L$_EID__<RID> (double underscore)
    WCHAR wszSecretName[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    swprintf_s(wszSecretName, ARRAYSIZE(wszSecretName), L"L$_EID__%08X", dwRid);

    LSA_UNICODE_STRING lsaSecretName;
    lsaSecretName.Buffer = wszSecretName;
    lsaSecretName.Length = static_cast<USHORT>(wcslen(wszSecretName) * sizeof(WCHAR)); // NOSONAR - wszSecretName is stack-allocated buffer, never NULL
    lsaSecretName.MaximumLength = lsaSecretName.Length + sizeof(WCHAR);

    PLSA_UNICODE_STRING pSecretData = nullptr;
    status = LsaRetrievePrivateData(hLsa, &lsaSecretName, &pSecretData);

    if (NT_SUCCESS(status) && pSecretData && pSecretData->Buffer)
    {
        PEID_PRIVATE_DATA pPrivateData = reinterpret_cast<PEID_PRIVATE_DATA>(pSecretData->Buffer);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified

        // Same single layout rule as the enumeration path above. This was the
        // second divergent copy: it also used sizeof(EID_PRIVATE_DATA) as both
        // the minimum size and the data-region base, which double-counts the
        // Data[4] placeholder and its padding.
        if (!EIDValidatePrivateDataLayout(pPrivateData, pSecretData->Length))
        {
            EIDM_TRACE_WARN(L"ExportLsaCredential: EID_PRIVATE_DATA layout invalid (%u bytes) - rejecting", pSecretData->Length);
            LsaFreeMemory(pSecretData);
            LsaClose(hLsa);
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }

        info.dwRid = dwRid;
        info.EncryptionType = pPrivateData->dwType;
        memcpy(info.CertificateHash, pPrivateData->Hash, CERT_HASH_LENGTH);

        // Get username from RID
        info.wsUsername = LookupUsernameByRid(dwRid);
        info.wsSid = LookupSidByUsername(info.wsUsername);

        // Offsets are relative to the Data field and are all validated above,
        // so each extraction is a straight copy.
        if (pPrivateData->dwCertificatSize > 0)
        {
            BYTE* pCertificate = pPrivateData->Data + pPrivateData->dwCertificatOffset;
            info.Certificate.assign(pCertificate, pCertificate + pPrivateData->dwCertificatSize);
            EIDM_TRACE_VERBOSE(L"ExportLsaCredential: Extracted certificate: %u bytes", pPrivateData->dwCertificatSize);
        }

        if (pPrivateData->dwSymetricKeySize > 0)
        {
            BYTE* pKey = pPrivateData->Data + pPrivateData->dwSymetricKeyOffset;
            info.SymmetricKey.assign(pKey, pKey + pPrivateData->dwSymetricKeySize);
            EIDM_TRACE_VERBOSE(L"ExportLsaCredential: Extracted symmetric key: %u bytes", pPrivateData->dwSymetricKeySize);
        }

        if (pPrivateData->usPasswordLen > 0)
        {
            BYTE* pPassword = pPrivateData->Data + pPrivateData->dwPasswordOffset;
            info.EncryptedPassword.assign(pPassword, pPassword + pPrivateData->usPasswordLen);
            EIDM_TRACE_VERBOSE(L"ExportLsaCredential: Extracted encrypted password: %u bytes", pPrivateData->usPasswordLen);
        }

        LsaFreeMemory(pSecretData);
        LsaClose(hLsa);
        return S_OK;
    }
    else
    {
        LsaClose(hLsa);
        return HRESULT_FROM_NT(status);
    }
}

// Check if user has stored EID credential
HRESULT HasStoredCredential(_In_ DWORD dwRid, _Out_ BOOL& pfHasCredential)
{
    pfHasCredential = FALSE;

    if (dwRid == 0)
    {
        return E_INVALIDARG;
    }

    HANDLE hLsa = nullptr;
    LSA_OBJECT_ATTRIBUTES objectAttributes = {};
    objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

    NTSTATUS status = LsaOpenPolicy(
        nullptr,
        &objectAttributes,
        POLICY_GET_PRIVATE_INFORMATION,
        &hLsa);

    if (!NT_SUCCESS(status))
    {
        EIDM_TRACE_ERROR(L"HasStoredCredential: LsaOpenPolicy failed: 0x%08X", status);
        return HRESULT_FROM_NT(status);
    }

    // Secret name must match StoredCredentialManagement.cpp's format
    // ("%s_%08X" with CREDENTIAL_LSAPREFIX = L"L$_EID_") -> L$_EID__<RID>.
    WCHAR wszSecretName[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    swprintf_s(wszSecretName, ARRAYSIZE(wszSecretName), L"L$_EID__%08X", dwRid);

    LSA_UNICODE_STRING lsaSecretName;
    lsaSecretName.Buffer = wszSecretName;
    lsaSecretName.Length = static_cast<USHORT>(wcslen(wszSecretName) * sizeof(WCHAR));
    lsaSecretName.MaximumLength = lsaSecretName.Length + sizeof(WCHAR);

    PLSA_UNICODE_STRING pSecretData = nullptr;
    status = LsaRetrievePrivateData(hLsa, &lsaSecretName, &pSecretData);

    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
    if (NT_SUCCESS(status) && pSecretData && pSecretData->Buffer && pSecretData->Length > 0)
    {
        pfHasCredential = TRUE;
    }
    else if (status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        // Expected when user has no EID credential - not an error.
        pfHasCredential = FALSE;
    }
    else if (!NT_SUCCESS(status))
    {
        EIDM_TRACE_WARN(L"HasStoredCredential: LsaRetrievePrivateData returned 0x%08X for RID %u", status, dwRid);
        hr = HRESULT_FROM_NT(status);
    }

    if (pSecretData)
    {
        LsaFreeMemory(pSecretData);
    }
    LsaClose(hLsa);

    return hr;
}

std::wstring LookupUsernameByRid(_In_ DWORD dwRid)
{
    PTSTR pszUsername = ::GetUsernameFromRid(dwRid);
    if (pszUsername)
    {
        std::wstring wsResult(pszUsername);
        ::EIDFree(pszUsername);  // GetUsernameFromRid returns EIDAlloc'd memory
        return wsResult;
    }
    return std::wstring();
}

DWORD LookupRidByUsername(_In_ const std::wstring& wsUsername)
{
    return ::GetRidFromUsername(const_cast<PWSTR>(wsUsername.c_str()));  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
}

std::wstring LookupSidByUsername(_In_ const std::wstring& wsUsername)
{
    // Get required buffer size
    DWORD dwSidSize = 0;
    DWORD dwDomainSize = 0;
    SID_NAME_USE use;

    BOOL fResult = LookupAccountNameW(nullptr, wsUsername.c_str(), nullptr, &dwSidSize,  // NOSONAR - IDIOM-01: two-call Win32 size-probe; first result intentionally overwritten
        nullptr, &dwDomainSize, &use);

    // After first call, check if we got the size
    if (dwSidSize == 0 || dwDomainSize == 0)
    {
        EIDM_TRACE_WARN(L"LookupAccountNameW failed to get buffer sizes for '%ls'", wsUsername.c_str());
        return std::wstring();
    }

    // Allocate SID buffer
    std::vector<BYTE> sidBytes(dwSidSize);
    std::vector<WCHAR> domainBuffer(dwDomainSize);

    // Zero out buffers to avoid uninitialized memory issues
    SecureZeroMemory(sidBytes.data(), dwSidSize);
    SecureZeroMemory(domainBuffer.data(), dwDomainSize * sizeof(WCHAR));

    fResult = LookupAccountNameW(nullptr, wsUsername.c_str(),
        reinterpret_cast<PSID>(sidBytes.data()), &dwSidSize,  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
        domainBuffer.data(), &dwDomainSize, &use);

    if (!fResult)
    {
        EIDM_TRACE_WARN(L"LookupAccountNameW failed for '%ls'", wsUsername.c_str());
        return std::wstring();
    }

    // Validate the SID before using it
    if (!IsValidSid(reinterpret_cast<PSID>(sidBytes.data())))  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
    {
        EIDM_TRACE_ERROR(L"Invalid SID returned for '%ls'", wsUsername.c_str());
        return std::wstring();
    }

    // Convert SID to string
    LPWSTR pwszSid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sidBytes.data()), &pwszSid))  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
    {
        EIDM_TRACE_ERROR(L"ConvertSidToStringSidW failed for '%ls'", wsUsername.c_str());
        return std::wstring();
    }

    std::wstring wsResult(pwszSid);
    LocalFree(pwszSid);
    return wsResult;
}

// SECURITY: one certificate, one account. CStoredCredentialManager::CreateCredential
// refuses to bind a certificate already held by another account's stored
// credential (IsCertificateBoundToOtherRid), because logon maps a card to the
// FIRST account holding its certificate. Import writes the LSA secret directly
// and so bypasses that rule; apply the same comparison here - same DER, or a
// stored hash equal to the SHA-256 of the incoming certificate (or to the hash
// carried in the import file) - against every OTHER local account's credential.
// Fails closed: if the existing credentials cannot be enumerated, refuse.
static HRESULT CheckCertificateNotBoundToOtherRid(_In_ const CredentialInfo& info)
{
    BYTE bComputedHash[CERT_HASH_LENGTH] = {};  // NOSONAR - LSASS-01: C-style buffer, matches EID_PRIVATE_DATA::Hash
    DWORD dwHashSize = sizeof(bComputedHash);
    BOOL fHaveComputedHash = FALSE;
    if (!info.Certificate.empty() &&
        CryptHashCertificate(0, CALG_SHA_256, 0, info.Certificate.data(),
            static_cast<DWORD>(info.Certificate.size()), bComputedHash, &dwHashSize) &&
        dwHashSize == CERT_HASH_LENGTH)
    {
        fHaveComputedHash = TRUE;
    }

    // An all-zero hash in the import file means "not provided"; never match on it.
    BOOL fHaveFileHash = FALSE;
    for (DWORD i = 0; i < CERT_HASH_LENGTH; i++)
    {
        if (info.CertificateHash[i] != 0)
        {
            fHaveFileHash = TRUE;
            break;
        }
    }

    std::vector<CredentialInfo> existing;
    DWORD dwUnreadable = 0;
    HRESULT hr = EnumerateLsaCredentials(existing, &dwUnreadable);  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
    if (FAILED(hr))
    {
        EIDM_TRACE_ERROR(L"[ERROR] Cannot enumerate existing credentials to check certificate binding for RID %u: 0x%08X - refusing import", info.dwRid, hr);
        return hr;
    }
    if (dwUnreadable != 0)
    {
        // Fail closed: an account whose credential could not be read might
        // already hold this certificate.
        EIDM_TRACE_ERROR(L"[ERROR] %u local account(s) could not be checked for an existing credential - refusing import of RID %u", dwUnreadable, info.dwRid);
        return HRESULT_FROM_WIN32(ERROR_CAN_NOT_COMPLETE);
    }

    for (const CredentialInfo& other : existing)
    {
        if (other.dwRid == info.dwRid)
        {
            continue;  // re-importing / replacing this account's own credential
        }
        const bool fSameDer = !info.Certificate.empty() && other.Certificate == info.Certificate;
        const bool fSameComputedHash = fHaveComputedHash &&
            memcmp(other.CertificateHash, bComputedHash, CERT_HASH_LENGTH) == 0;
        const bool fSameFileHash = fHaveFileHash &&
            memcmp(other.CertificateHash, info.CertificateHash, CERT_HASH_LENGTH) == 0;
        if (fSameDer || fSameComputedHash || fSameFileHash)
        {
            EIDM_TRACE_ERROR(L"[ERROR] Certificate for RID %u (%ls) is already bound to another local account (RID %u, %ls) - refusing import: a certificate may be enrolled to only one account",
                info.dwRid, info.wsUsername.c_str(), other.dwRid, other.wsUsername.c_str());
            return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
        }
    }
    return S_OK;
}

HRESULT ImportLsaCredential(
    _In_ const CredentialInfo& info,
    _In_ [[maybe_unused]] DWORD dwFlags,
    _Out_ BOOL& pfUserCreated)
{
    EIDM_TRACE_VERBOSE(L"Importing credential for RID %u via direct LSA access...", info.dwRid);

    pfUserCreated = FALSE;

    // SECURITY (H3): when the RequireCardBoundCredentials policy is enabled, refuse to import a
    // non-card-wrapped (DPAPI/ClearText) credential - its password would be recoverable without
    // the card. Read the policy directly to avoid a link dependency on EIDCardLibrary.
    if (info.EncryptionType != EID_PRIVATE_DATA_TYPE::eidpdtCrypted)
    {
        DWORD dwRequireCardBound = 0;
        DWORD dwSize = sizeof(dwRequireCardBound);
        if (RegGetValueW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider",
                L"RequireCardBoundCredentials", RRF_RT_REG_DWORD, nullptr,
                &dwRequireCardBound, &dwSize) == ERROR_SUCCESS && dwRequireCardBound != 0)
        {
            EIDM_TRACE_ERROR(L"RequireCardBoundCredentials policy set: refusing to import non-crypted credential for RID %u", info.dwRid);
            return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        }
    }

    // SECURITY: enforce the one-certificate-per-account rule that the LSA
    // package applies at enrolment (see CheckCertificateNotBoundToOtherRid).
    {
        const HRESULT hrBinding = CheckCertificateNotBoundToOtherRid(info);
        if (FAILED(hrBinding))
        {
            return hrBinding;
        }
    }

    NTSTATUS status;
    HANDLE hLsa = nullptr;
    LSA_OBJECT_ATTRIBUTES objectAttributes = {};
    objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

    // Open LSA policy
    status = LsaOpenPolicy(
        nullptr,
        &objectAttributes,
        POLICY_CREATE_SECRET,
        &hLsa);

    if (!NT_SUCCESS(status))
    {
        EIDM_TRACE_ERROR(L"[ERROR] LsaOpenPolicy failed: 0x%08X", status);
        return HRESULT_FROM_NT(status);
    }

    // Build EID_PRIVATE_DATA structure
    // Calculate total size needed
    DWORD dwPrivateDataSize = sizeof(EID_PRIVATE_DATA) +
        static_cast<DWORD>(info.Certificate.size()) +
        static_cast<DWORD>(info.SymmetricKey.size()) +
        static_cast<DWORD>(info.EncryptedPassword.size());

    // SECURITY/ROBUSTNESS (BUG 9): dwCertificatSize, dwSymetricKeySize, usPasswordLen, and
    // lsaSecretData.Length below are all USHORT fields. Validate each source length (and the
    // combined total) fits before the narrowing assignments, otherwise a field >= 65536 bytes
    // would silently wrap and produce a corrupt LSA secret.
    USHORT usCertificateSize = 0;
    USHORT usSymmetricKeySize = 0;
    USHORT usPasswordLen = 0;
    USHORT usTotalSize = 0;
    HRESULT hrSize = SizeTToUShort(info.Certificate.size(), &usCertificateSize);
    if (SUCCEEDED(hrSize))
        hrSize = SizeTToUShort(info.SymmetricKey.size(), &usSymmetricKeySize);
    if (SUCCEEDED(hrSize))
        hrSize = SizeTToUShort(info.EncryptedPassword.size(), &usPasswordLen);
    if (SUCCEEDED(hrSize))
        hrSize = SizeTToUShort(dwPrivateDataSize, &usTotalSize);
    if (FAILED(hrSize))
    {
        EIDM_TRACE_ERROR(L"[ERROR] Credential field(s) for RID %u exceed USHORT limits for LSA secret storage: 0x%08X", info.dwRid, hrSize);
        LsaClose(hLsa);
        return hrSize;
    }

    // H2: the symmetric key is replayed as the decryption challenge inside LSASS, where it must
    // fit one cipher block of the card's private key. Fitting a USHORT is not enough of a bound -
    // reject anything larger than a 16384-bit modulus (4x the largest key any supported card holds).
    constexpr USHORT usMaxSymmetricKeySize = 2048;
    if (usSymmetricKeySize > usMaxSymmetricKeySize)
    {
        EIDM_TRACE_ERROR(L"[ERROR] Symmetric key for RID %u is %u bytes, exceeding the %u-byte maximum", info.dwRid, usSymmetricKeySize, usMaxSymmetricKeySize);
        LsaClose(hLsa);
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }

    std::vector<BYTE> buffer(dwPrivateDataSize);
    PEID_PRIVATE_DATA pPrivateData = reinterpret_cast<PEID_PRIVATE_DATA>(buffer.data());  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified

    // Fill in the structure
    // IMPORTANT: All offsets are relative to the Data field, starting at 0
    // This matches the format used by StoredCredentialManagement.cpp
    pPrivateData->dwType = info.EncryptionType;

    // Certificate always at offset 0
    pPrivateData->dwCertificatOffset = 0;
    pPrivateData->dwCertificatSize = usCertificateSize;

    // Symmetric key follows certificate
    pPrivateData->dwSymetricKeyOffset = pPrivateData->dwCertificatOffset + pPrivateData->dwCertificatSize;
    pPrivateData->dwSymetricKeySize = usSymmetricKeySize;

    // Encrypted password follows symmetric key
    pPrivateData->dwPasswordOffset = pPrivateData->dwSymetricKeyOffset + pPrivateData->dwSymetricKeySize;
    pPrivateData->usPasswordLen = usPasswordLen;

    memcpy(pPrivateData->Hash, info.CertificateHash, CERT_HASH_LENGTH);

    // Copy certificate, key, and password to Data field
    // Use the offsets we just calculated
    if (!info.Certificate.empty())
    {
        memcpy(pPrivateData->Data + pPrivateData->dwCertificatOffset,
               info.Certificate.data(), info.Certificate.size());
    }
    if (!info.SymmetricKey.empty())
    {
        memcpy(pPrivateData->Data + pPrivateData->dwSymetricKeyOffset,
               info.SymmetricKey.data(), info.SymmetricKey.size());
    }
    if (!info.EncryptedPassword.empty())
    {
        memcpy(pPrivateData->Data + pPrivateData->dwPasswordOffset,
               info.EncryptedPassword.data(), info.EncryptedPassword.size());
    }

    // Store the LSA secret
    // Format: L$_EID__<RID> (double underscore)
    WCHAR wszSecretName[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    swprintf_s(wszSecretName, ARRAYSIZE(wszSecretName), L"L$_EID__%08X", info.dwRid);

    LSA_UNICODE_STRING lsaSecretName;
    lsaSecretName.Buffer = wszSecretName;
    lsaSecretName.Length = static_cast<USHORT>(wcslen(wszSecretName) * sizeof(WCHAR)); // NOSONAR - wszSecretName is stack-allocated buffer, never NULL
    lsaSecretName.MaximumLength = lsaSecretName.Length + sizeof(WCHAR);

    LSA_UNICODE_STRING lsaSecretData;
    lsaSecretData.Buffer = reinterpret_cast<PWSTR>(buffer.data());  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
    lsaSecretData.Length = usTotalSize;  // BUG 9: validated above via SizeTToUShort, no truncation
    lsaSecretData.MaximumLength = lsaSecretData.Length;

    status = LsaStorePrivateData(hLsa, &lsaSecretName, &lsaSecretData);

    LsaClose(hLsa);

    if (NT_SUCCESS(status))
    {
        EIDM_TRACE_ERROR(L"[DEBUG] Credential stored successfully for RID %u", info.dwRid);
        return S_OK;
    }
    else
    {
        EIDM_TRACE_ERROR(L"[ERROR] LsaStorePrivateData failed: 0x%08X", status);
        return HRESULT_FROM_NT(status);
    }
}
