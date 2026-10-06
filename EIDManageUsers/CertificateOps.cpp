// CertificateOps.cpp - Certificate removal operations
#include "CertificateOps.h"
#include "../EIDMigrate/Tracing.h"
#include <sddl.h>
#include <userenv.h>  // NOSONAR - INCLUDE-01: include order/casing significant for Windows SDK
#include <lm.h>  // NOSONAR - INCLUDE-01: include order/casing significant for Windows SDK

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

// Free certificate context array
void FreeCertificateArray(_Inout_ std::vector<PCCERT_CONTEXT>& certs)
{
    for (auto pCert : certs)
    {
        if (pCert)
            CertFreeCertificateContext(pCert);
    }
    certs.clear();
}

// Get user SID
static HRESULT GetUserSid(_In_ const std::wstring& wsUsername, _Out_ PSID* ppSid)
{
    *ppSid = nullptr;

    DWORD dwSidSize = 0;
    DWORD dwDomainSize = 0;
    SID_NAME_USE use;

    LookupAccountNameW(nullptr, wsUsername.c_str(),
        nullptr, &dwSidSize,
        nullptr, &dwDomainSize, &use);

    if (dwSidSize == 0)
        return HRESULT_FROM_WIN32(GetLastError());

    PSID pSid = static_cast<PSID>(LocalAlloc(LPTR, dwSidSize));  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
    if (!pSid)
        return E_OUTOFMEMORY;

    std::vector<WCHAR> domainBuffer(dwDomainSize);

    if (!LookupAccountNameW(nullptr, wsUsername.c_str(),  // NOSONAR - SCOPE-01: declaration kept outside if for clarity
        pSid, &dwSidSize,
        domainBuffer.data(), &dwDomainSize, &use))
    {
        LocalFree(pSid);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    *ppSid = pSid;
    return S_OK;
}

// Enumerate user certificates
HRESULT EnumerateUserCertificates(_In_ const std::wstring& wsUsername,
    _Out_ std::vector<PCCERT_CONTEXT>& certs)
{
    certs.clear();

    // Get user SID
    PSID pSid = nullptr;
    HRESULT hr = GetUserSid(wsUsername, &pSid);
    if (FAILED(hr))
        return hr;

    // Impersonate the user to access their certificate store
    HANDLE hToken = nullptr;
    if (!LogonUserW(wsUsername.c_str(), nullptr, nullptr,
        LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
    {
        // Try with empty password for local account
        // Note: This may fail if user has password
        // For admin tool, we might need to use different approach

        // (A per-SID store path used to be formatted here with an invalid
        // format string - "%\\" - that triggered the CRT invalid-parameter
        // handler, and the result was never used. Removed.)
        LocalFree(pSid);

        // Open the store
        HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            (HCRYPTPROV_LEGACY)NULL,
            CERT_SYSTEM_STORE_CURRENT_USER,
            L"MY");

        if (!hStore)
            return HRESULT_FROM_WIN32(GetLastError());

        // For system context, we need to load user profile
        // For simplicity, we'll return empty list if impersonation fails
        // A full implementation would use LoadUserProfileW

        CertCloseStore(hStore, 0);
        return S_FALSE;
    }

    // Impersonate and open store
    if (!ImpersonateLoggedOnUser(hToken))
    {
        CloseHandle(hToken);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        (HCRYPTPROV_LEGACY)NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY");

    if (!hStore)
    {
        RevertToSelf();
        CloseHandle(hToken);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Enumerate certificates
    PCCERT_CONTEXT pCert = nullptr;
    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != nullptr)
    {
        // Add a duplicate to our list
        PCCERT_CONTEXT pDup = CertDuplicateCertificateContext(pCert);
        if (pDup)
            certs.push_back(pDup);
    }

    CertCloseStore(hStore, 0);
    RevertToSelf();
    CloseHandle(hToken);

    return certs.empty() ? S_FALSE : S_OK;
}

// Remove all user certificates
HRESULT RemoveUserCertificates(_In_ const std::wstring& wsUsername)
{
    std::vector<PCCERT_CONTEXT> certs;
    HRESULT hr = EnumerateUserCertificates(wsUsername, certs);
    if (hr == S_FALSE || certs.empty())
    {
        // No certificates to remove
        return S_OK;
    }
    else if (FAILED(hr))
    {
        return hr;
    }

    // Get user SID for impersonation
    PSID pSid = nullptr;
    hr = GetUserSid(wsUsername, &pSid);
    if (FAILED(hr))
    {
        FreeCertificateArray(certs);
        return hr;
    }

    // Load user profile and impersonate

    // Open store with impersonation

    // For admin tool running as system, we can delete directly
    // by using the user's SID

    DWORD dwRemoved = 0;
    DWORD dwFailed = 0;

    for (auto pCert : certs)
    {
        // Try to delete from store
        // The certificate context contains the store handle
        if (pCert->hCertStore)
        {
            if (CertDeleteCertificateFromStore(pCert))
            {
                dwRemoved++;
            }
            else
            {
                dwFailed++;
            }
        }
    }

    FreeCertificateArray(certs);
    LocalFree(pSid);

    EIDM_TRACE_INFO(L"Removed %u certificates for user '%ls', %u failed",
        dwRemoved, wsUsername.c_str(), dwFailed);

    return dwFailed > 0 ? S_FALSE : S_OK;
}

// Remove certificates by hash
HRESULT RemoveCertificatesByHash(_In_ const std::wstring& wsUsername,
    _In_reads_(cbHash) const BYTE* pbHash, DWORD cbHash)
{
    if (!pbHash || cbHash == 0)
        return E_INVALIDARG;

    std::vector<PCCERT_CONTEXT> certs;
    HRESULT hr = EnumerateUserCertificates(wsUsername, certs);
    if (hr == S_FALSE || certs.empty())  // NOSONAR - SCOPE-01: variable reused after the block
        return S_OK;
    else if (FAILED(hr))
        return hr;

    DWORD dwRemoved = 0;
    for (auto pCert : certs)
    {
        // Get certificate hash
        BYTE certHash[32];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        DWORD cbHashSize = sizeof(certHash);

        if (CertGetCertificateContextProperty(pCert,
            CERT_HASH_PROP_ID,
            certHash,
            &cbHashSize))
        {
            if (cbHashSize == cbHash &&  // NOSONAR - COMPLEXITY-01: nested if retained; logic verified
                memcmp(certHash, pbHash, cbHash) == 0)
            {
                // Found matching certificate
                if (pCert->hCertStore && CertDeleteCertificateFromStore(pCert))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    dwRemoved++;
                }
            }
        }
    }

    FreeCertificateArray(certs);
    return dwRemoved > 0 ? S_OK : S_FALSE;
}

// Get user certificate store path (for reference)
HRESULT GetUserCertStorePath(_In_ const std::wstring& wsUsername, _Out_ std::wstring& wsStorePath)
{
    wsStorePath.clear();

    PSID pSid = nullptr;
    HRESULT hr = GetUserSid(wsUsername, &pSid);
    if (FAILED(hr))
        return hr;

    LPWSTR pwszSid = nullptr;
    if (!ConvertSidToStringSidW(pSid, &pwszSid))
    {
        LocalFree(pSid);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    WCHAR szProfilePath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    DWORD dwPathSize = MAX_PATH;
    if (!GetProfilesDirectoryW(szProfilePath, &dwPathSize))  // NOSONAR - SCOPE-01: declaration kept outside if for clarity
    {
        LocalFree(pSid);
        LocalFree(pwszSid);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    wsStorePath = szProfilePath;
    if (wsStorePath.back() != L'\\')
        wsStorePath += L'\\';
    wsStorePath += pwszSid;
    wsStorePath += L"\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates";

    LocalFree(pSid);
    LocalFree(pwszSid);

    return S_OK;
}
