#pragma once

// File: EIDMigrate/LsaClient.h
// LSA IPC client functions for credential enumeration and export

#include "EIDMigrate.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include <vector>
#include <utility>

// Credential summary information (data members; see CredentialInfo below)
struct CredentialInfoData
{
    DWORD dwRid;
    std::wstring wsUsername;
    std::wstring wsSid;
    UCHAR CertificateHash[32];
    EID_PRIVATE_DATA_TYPE EncryptionType;
    std::vector<BYTE> Certificate;
    std::vector<BYTE> EncryptedPassword;
    std::vector<BYTE> SymmetricKey;  // Only for certificate encryption
    std::wstring wsAlgorithm;

    // Optional metadata
    std::wstring wsCertSubject;
    std::wstring wsCertIssuer;
    FILETIME ftCertValidFrom;
    FILETIME ftCertValidTo;
    DWORD dwPasswordLength;

    CredentialInfoData() :
        dwRid(0),  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
        EncryptionType(EID_PRIVATE_DATA_TYPE::eidpdtClearText),  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
        wsAlgorithm(L"AES-256-CBC"),  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
        dwPasswordLength(0)  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
    {
        SecureZeroMemory(CertificateHash, sizeof(CertificateHash));
        ftCertValidFrom.dwHighDateTime = 0;
        ftCertValidFrom.dwLowDateTime = 0;
        ftCertValidTo.dwHighDateTime = 0;
        ftCertValidTo.dwLowDateTime = 0;
    }
};

// CredentialInfo carries the encrypted password and the symmetric key of an
// EID credential. Wipe them when the object dies or is overwritten, so the
// buffers are not returned to the heap with secret contents. Copy and move
// keep their member-wise semantics (the data lives in CredentialInfoData, so
// adding a member there needs no change here); a moved-from object's vectors
// are empty and need no wiping.
struct CredentialInfo : CredentialInfoData
{
    CredentialInfo() = default;
    CredentialInfo(const CredentialInfo&) = default;
    CredentialInfo(CredentialInfo&&) noexcept = default;

    CredentialInfo& operator=(const CredentialInfo& other)
    {
        if (this != &other)
        {
            WipeSecrets();
            CredentialInfoData::operator=(other);
        }
        return *this;
    }

    CredentialInfo& operator=(CredentialInfo&& other) noexcept
    {
        if (this != &other)
        {
            WipeSecrets();
            CredentialInfoData::operator=(std::move(other));
        }
        return *this;
    }

    ~CredentialInfo()
    {
        WipeSecrets();
    }

    void WipeSecrets() noexcept
    {
        if (!EncryptedPassword.empty())
            SecureZeroMemory(EncryptedPassword.data(), EncryptedPassword.size());
        if (!SymmetricKey.empty())
            SecureZeroMemory(SymmetricKey.data(), SymmetricKey.size());
        EncryptedPassword.clear();
        SymmetricKey.clear();
    }
};

// Group information
struct GroupInfo
{
    std::wstring wsName;
    std::wstring wsComment;
    std::vector<std::wstring> wsMembers;
    BOOL fBuiltin;

    GroupInfo() :
        fBuiltin(FALSE)  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
    {}
};

// Enumerate all EID credentials from LSA
HRESULT EnumerateLsaCredentials(
    _Out_ std::vector<CredentialInfo>& credentials,
    _Out_opt_ DWORD* pdwUnreadable = nullptr);

// Export a single credential from LSA by RID
HRESULT ExportLsaCredential(
    _In_ DWORD dwRid,
    _Out_ CredentialInfo& info);

// Check if user has stored EID credential
HRESULT HasStoredCredential(
    _In_ DWORD dwRid,
    _Out_ BOOL& pfHasCredential);

// Get username from RID
std::wstring LookupUsernameByRid(_In_ DWORD dwRid);

// Get RID from username
DWORD LookupRidByUsername(_In_ const std::wstring& wsUsername);

// Get SID from username
std::wstring LookupSidByUsername(_In_ const std::wstring& wsUsername);

// Import credential to LSA
HRESULT ImportLsaCredential(
    _In_ const CredentialInfo& info,
    _In_ DWORD dwFlags,
    _Out_ BOOL& pfUserCreated);
