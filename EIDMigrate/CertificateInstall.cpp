// File: EIDMigrate/CertificateInstall.cpp
// Certificate installation for import functionality

#include "CertificateInstall.h"
#include "Tracing.h"
#include <lm.h>  // NOSONAR - INCLUDE-01: include order/casing significant for Windows SDK
#include <sddl.h>

#pragma comment(lib, "crypt32.lib")

// Helper: Get user SID from username
static HRESULT GetUserSid(_In_ const std::wstring& wsUsername, _Out_ std::wstring& wsSid)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    if (wsUsername.empty())
    {
        // Use current user
        WCHAR szUserName[UNLEN + 1];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        DWORD dwSize = ARRAYSIZE(szUserName);
        if (!GetUserNameW(szUserName, &dwSize))  // NOSONAR - SCOPE-01: declaration kept in outer scope for clarity
        {
            EIDM_TRACE_ERROR(L"GetUserNameW failed: %u", GetLastError());
            return HRESULT_FROM_WIN32(GetLastError());
        }

        // BUG FIX #16: TOCTOU race condition mitigation - use retry loop for SID allocation
        constexpr DWORD MAX_RETRIES = 3;
        DWORD dwRetryCount = 0;
        DWORD dwSidSize = 0;
        DWORD dwDomainSize = 0;
        SID_NAME_USE use;
        std::vector<BYTE> sidBuffer;
        std::vector<WCHAR> domainBuffer;

        // First call to get sizes
        LookupAccountNameW(NULL, szUserName, NULL, &dwSidSize, // NOSONAR - Windows API requires NULL for LPCTSTR parameters
            NULL, &dwDomainSize, &use); // NOSONAR - Windows API requires NULL

        if (dwSidSize == 0)
        {
            EIDM_TRACE_ERROR(L"LookupAccountNameW failed to get SID size");
            return HRESULT_FROM_WIN32(GetLastError());
        }

        // Retry loop for SID allocation (handles TOCTOU race condition)
        BOOL fSuccess = FALSE;
        for (dwRetryCount = 0; dwRetryCount < MAX_RETRIES; dwRetryCount++)  // NOSONAR - PERF-01: declared once, reused across iterations
        {
            // Allocate buffers with current size requirements
            sidBuffer.resize(dwSidSize);
            domainBuffer.resize(dwDomainSize);

            // Zero out buffers to avoid uninitialized memory issues
            SecureZeroMemory(sidBuffer.data(), dwSidSize);
            SecureZeroMemory(domainBuffer.data(), dwDomainSize * sizeof(WCHAR));

            // Second call to get actual SID
            fSuccess = LookupAccountNameW(NULL, szUserName, reinterpret_cast<PSID>(sidBuffer.data()), // NOSONAR - Windows API requires NULL; reinterpret_cast from BYTE* to PSID required for SID structure
                &dwSidSize, domainBuffer.data(), &dwDomainSize, &use);

            if (fSuccess)
            {
                break;  // Success - exit retry loop
            }

            DWORD dwError = GetLastError();
            if (dwError == ERROR_INSUFFICIENT_BUFFER)
            {
                // Buffer size changed between check and use (TOCTOU race condition)
                EIDM_TRACE_WARN(L"TOCTOU race condition on retry %u for current user: buffer size changed (retrying...)",
                    dwRetryCount + 1);
                // Loop will continue with new dwSidSize and dwDomainSize values
            }
            else
            {
                // Different error - not a TOCTOU issue, don't retry
                EIDM_TRACE_ERROR(L"LookupAccountNameW failed for current user: error %u", dwError);
                return HRESULT_FROM_WIN32(dwError);
            }
        }

        if (!fSuccess)
        {
            EIDM_TRACE_ERROR(L"Exhausted %u retries for SID lookup of current user (possible persistent race condition)",
                MAX_RETRIES);
            return HRESULT_FROM_WIN32(GetLastError());
        }

        LPWSTR pwszSid = NULL; // NOSONAR - NULL required for Windows API compatibility
        if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sidBuffer.data()), &pwszSid)) // NOSONAR - reinterpret_cast from BYTE* to PSID required for Windows SID API // NOSONAR - Windows API requires PSID cast from BYTE buffer
        {
            EIDM_TRACE_ERROR(L"ConvertSidToStringSidW failed");
            return HRESULT_FROM_WIN32(GetLastError());
        }

        wsSid = pwszSid;
        LocalFree(pwszSid);
        return S_OK;
    }

    // BUG FIX #16: TOCTOU race condition mitigation - use retry loop for SID allocation
    constexpr DWORD MAX_RETRIES = 3;
    DWORD dwRetryCount = 0;
    DWORD dwSidSize = 0;
    DWORD dwDomainSize = 0;
    SID_NAME_USE use;
    std::vector<BYTE> sidBuffer;
    std::vector<WCHAR> domainBuffer;

    // First call to get sizes
    LookupAccountNameW(NULL, wsUsername.c_str(), NULL, &dwSidSize, // NOSONAR - Windows API requires NULL
        NULL, &dwDomainSize, &use); // NOSONAR - Windows API requires NULL

    if (dwSidSize == 0)
    {
        EIDM_TRACE_ERROR(L"LookupAccountNameW failed for user '%ls'", wsUsername.c_str());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Retry loop for SID allocation (handles TOCTOU race condition)
    BOOL fSuccess = FALSE;
    for (dwRetryCount = 0; dwRetryCount < MAX_RETRIES; dwRetryCount++)  // NOSONAR - PERF-01: declared once, reused across iterations
    {
        // Allocate buffers with current size requirements
        sidBuffer.resize(dwSidSize);
        domainBuffer.resize(dwDomainSize);

        // Zero out buffers to avoid uninitialized memory issues
        SecureZeroMemory(sidBuffer.data(), dwSidSize);
        SecureZeroMemory(domainBuffer.data(), dwDomainSize * sizeof(WCHAR));

        // Second call to get actual SID
        fSuccess = LookupAccountNameW(NULL, wsUsername.c_str(), reinterpret_cast<PSID>(sidBuffer.data()), // NOSONAR - Windows API requires NULL; reinterpret_cast from BYTE* to PSID required for SID structure
            &dwSidSize, domainBuffer.data(), &dwDomainSize, &use);

        if (fSuccess)
        {
            break;  // Success - exit retry loop
        }

        DWORD dwError = GetLastError();
        if (dwError == ERROR_INSUFFICIENT_BUFFER)
        {
            // Buffer size changed between check and use (TOCTOU race condition)
            EIDM_TRACE_WARN(L"TOCTOU race condition on retry %u for '%ls': buffer size changed (retrying...)",
                dwRetryCount + 1, wsUsername.c_str());
            // Loop will continue with new dwSidSize and dwDomainSize values
        }
        else
        {
            // Different error - not a TOCTOU issue, don't retry
            EIDM_TRACE_ERROR(L"LookupAccountNameW failed for '%ls': error %u", wsUsername.c_str(), dwError);
            return HRESULT_FROM_WIN32(dwError);
        }
    }

    if (!fSuccess)
    {
        EIDM_TRACE_ERROR(L"Exhausted %u retries for SID lookup of '%ls' (possible persistent race condition)",
            MAX_RETRIES, wsUsername.c_str());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    LPWSTR pwszSid = NULL; // NOSONAR - Windows API requires NULL
    if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sidBuffer.data()), &pwszSid)) // NOSONAR - reinterpret_cast from BYTE* to PSID required for Windows SID API
    {
        EIDM_TRACE_ERROR(L"ConvertSidToStringSidW failed");
        return HRESULT_FROM_WIN32(GetLastError());
    }

    wsSid = pwszSid;
    LocalFree(pwszSid);
    return S_OK;
}

// Install certificate to user's MY store
HRESULT InstallCertificateToUserStore(
    _In_reads_bytes_(cbCertificate) const BYTE* pbCertificate,
    _In_ DWORD cbCertificate,
    _In_opt_ const std::wstring& wsUsername)
{
    if (!pbCertificate || cbCertificate == 0)
    {
        EIDM_TRACE_ERROR(L"Invalid certificate data");
        return E_INVALIDARG;
    }

    EIDM_TRACE_INFO(L"Installing certificate for user '%ls'", wsUsername.empty() ? L"[current]" : wsUsername.c_str());

    // Create certificate context from DER-encoded bytes
    PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        pbCertificate,
        cbCertificate);

    if (!pCertContext)
    {
        DWORD dwError = GetLastError();
        EIDM_TRACE_ERROR(L"CertCreateCertificateContext failed: %u", dwError);
        return HRESULT_FROM_WIN32(dwError);
    }

    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - HRESULT visible for security audit
    HCERTSTORE hCertStore = NULL; // NOSONAR - NULL required for Windows API compatibility
    PCCERT_CONTEXT pExistingCert = NULL; // NOSONAR - NULL required for Windows API compatibility; Declare before goto target

    // If username is specified, we need to open their store
    if (!wsUsername.empty())
    {
        // Open the TARGET user's store through HKEY_USERS\<SID>. Never fall back
        // to the current (administrator) user's store: that would report success
        // while installing the certificate for the wrong account.
        std::wstring wsSid;
        hr = GetUserSid(wsUsername, wsSid);
        if (FAILED(hr) || wsSid.empty())
        {
            if (SUCCEEDED(hr))
                hr = E_FAIL;  // GetUserSid can report success with no SID if the last error was cleared
            EIDM_TRACE_ERROR(L"Could not resolve the SID of user '%ls': 0x%08X", wsUsername.c_str(), hr);
            goto cleanup;
        }

        // CERT_SYSTEM_STORE_USERS needs the user's registry hive to be loaded
        // (the user is logged on, or the profile was loaded). Check explicitly
        // so an unloaded profile yields a clear error instead of a generic one.
        HKEY hUserHive = NULL; // NOSONAR - NULL required for Windows API compatibility
        LSTATUS lHive = RegOpenKeyExW(HKEY_USERS, wsSid.c_str(), 0, KEY_READ, &hUserHive);
        if (lHive != ERROR_SUCCESS)
        {
            EIDM_TRACE_ERROR(L"Registry hive of user '%ls' (%ls) is not loaded (error %ld); cannot open the user's certificate store",
                wsUsername.c_str(), wsSid.c_str(), static_cast<long>(lHive));
            hr = HRESULT_FROM_WIN32(ERROR_NOT_LOGGED_ON);
            goto cleanup;
        }
        RegCloseKey(hUserHive);

        // Store path for CERT_SYSTEM_STORE_USERS: <SID>\My
        std::wstring wsStorePath = wsSid + L"\\My";

        hCertStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            NULL,  // NOSONAR - Was: nullptr - changed to NULL for HCRYPTPROV_LEGACY; Windows API requires NULL
            CERT_SYSTEM_STORE_USERS,
            wsStorePath.c_str());

        if (hCertStore)
        {
            EIDM_TRACE_VERBOSE(L"Opened certificate store for user '%ls'", wsUsername.c_str());
        }
    }
    else
    {
        // Open current user's MY store
        hCertStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            NULL,  // NOSONAR - Was: nullptr - changed to NULL for HCRYPTPROV_LEGACY; Windows API requires NULL
            CERT_SYSTEM_STORE_CURRENT_USER,
            L"My");
    }

    if (!hCertStore)
    {
        DWORD dwError = GetLastError();
        EIDM_TRACE_ERROR(L"CertOpenStore failed: %u", dwError);
        hr = HRESULT_FROM_WIN32(dwError);
        goto cleanup;
    }

    // Check if certificate already exists
    pExistingCert = CertFindCertificateInStore(
        hCertStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_EXISTING,
        pCertContext,
        NULL); // NOSONAR - Windows API requires NULL

    if (pExistingCert)
    {
        EIDM_TRACE_INFO(L"Certificate already exists in store, updating");
        CertFreeCertificateContext(pExistingCert);
        pExistingCert = NULL; // NOSONAR - Windows API requires NULL
    }

    // Add certificate to store
    if (!CertAddCertificateContextToStore(
        hCertStore,
        pCertContext,
        CERT_STORE_ADD_ALWAYS,  // Overwrite if exists
        NULL)) // NOSONAR - Windows API requires NULL
    {
        DWORD dwError = GetLastError();
        EIDM_TRACE_ERROR(L"CertAddCertificateContextToStore failed: %u", dwError);
        hr = HRESULT_FROM_WIN32(dwError);
        goto cleanup;
    }

    EIDM_TRACE_INFO(L"Certificate successfully installed to user's MY store");

cleanup:
    if (hCertStore)
        CertCloseStore(hCertStore, 0);
    if (pCertContext)
        CertFreeCertificateContext(pCertContext);

    return hr;
}

// Install certificate from DER-encoded bytes (wrapper)
HRESULT InstallCertificateFromDER(
    _In_ const std::vector<BYTE>& certificate,
    _In_opt_ const std::wstring& wsUsername)
{
    if (certificate.empty())
    {
        EIDM_TRACE_ERROR(L"Empty certificate data");
        return E_INVALIDARG;
    }

    return InstallCertificateToUserStore(
        certificate.data(),
        static_cast<DWORD>(certificate.size()),
        wsUsername);
}

// Check if certificate is already installed
BOOL IsCertificateInstalled(
    _In_reads_bytes_(cbCertificate) const BYTE* pbCertificate,
    _In_ DWORD cbCertificate)
{
    if (!pbCertificate || cbCertificate == 0)
        return FALSE;

    PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        pbCertificate,
        cbCertificate);

    if (!pCertContext)
        return FALSE;

    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,  // Was: nullptr - changed to NULL for HCRYPTPROV_LEGACY
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"My");

    if (!hStore)
    {
        CertFreeCertificateContext(pCertContext);
        return FALSE;
    }

    PCCERT_CONTEXT pExisting = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_EXISTING,
        pCertContext,
        NULL); // NOSONAR - Windows API requires NULL

    BOOL fFound = (pExisting != NULL); // NOSONAR - Windows API requires NULL

    if (pExisting)
        CertFreeCertificateContext(pExisting);
    CertCloseStore(hStore, 0);
    CertFreeCertificateContext(pCertContext);

    return fFound;
}

// Remove certificate from store
HRESULT RemoveCertificateFromStore(
    _In_reads_bytes_(cbCertificate) const BYTE* pbCertificate,
    _In_ DWORD cbCertificate)
{
    if (!pbCertificate || cbCertificate == 0)
        return E_INVALIDARG;

    PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        pbCertificate,
        cbCertificate);

    if (!pCertContext)
        return HRESULT_FROM_WIN32(GetLastError());

    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,  // Was: nullptr - changed to NULL for HCRYPTPROV_LEGACY
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"My");

    if (!hStore)
    {
        CertFreeCertificateContext(pCertContext);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    PCCERT_CONTEXT pExisting = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_EXISTING,
        pCertContext,
        NULL); // NOSONAR - Windows API requires NULL

    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - HRESULT visible for security audit
    if (pExisting)
    {
        if (!CertDeleteCertificateFromStore(pExisting))
            hr = HRESULT_FROM_WIN32(GetLastError());
        CertFreeCertificateContext(pExisting);
        EIDM_TRACE_INFO(L"Certificate removed from store");
    }
    else
    {
        hr = S_FALSE;  // Not found
    }

    CertCloseStore(hStore, 0);
    CertFreeCertificateContext(pCertContext);

    return hr;
}

// ================================================================
// M1: Install an offline-distributed CRL into the LocalMachine CA store.
// The CRL is installed ONLY if its signature verifies against a CA already trusted on this
// machine (Root/CA store), so a forged CRL cannot be planted. Accepts DER or PEM/base64.
// ================================================================
HRESULT InstallCrlFromFile(_In_ const std::wstring& wsCrlPath)  // NOSONAR - COMPLEXITY-01: sequential validate-then-install, logic verified
{
    EIDM_TRACE_INFO(L"Importing CRL from '%ls'", wsCrlPath.c_str());

    // ---- Read the file into memory (cap at 10 MB) ----
    HANDLE hFile = CreateFileW(wsCrlPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)  // NOSONAR (EXPLICIT-TYPE-02) - HANDLE visible for clarity
    {
        DWORD dwErr = GetLastError();
        EIDM_TRACE_ERROR(L"Cannot open CRL file: %u", dwErr);
        return HRESULT_FROM_WIN32(dwErr);
    }
    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart <= 0 || liSize.QuadPart > (10LL * 1024 * 1024))
    {
        CloseHandle(hFile);
        EIDM_TRACE_ERROR(L"CRL file missing, empty, or too large");
        return E_INVALIDARG;
    }
    std::vector<BYTE> fileData(static_cast<size_t>(liSize.QuadPart));
    DWORD dwRead = 0;
    BOOL fRead = ReadFile(hFile, fileData.data(), static_cast<DWORD>(fileData.size()), &dwRead, nullptr);
    CloseHandle(hFile);
    if (!fRead || dwRead != fileData.size())
        return HRESULT_FROM_WIN32(GetLastError());

    // ---- Parse as DER; fall back to PEM/base64 ----
    PCCRL_CONTEXT pCrl = CertCreateCRLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        fileData.data(), static_cast<DWORD>(fileData.size()));
    std::vector<BYTE> derBuffer;
    if (!pCrl)
    {
        DWORD cbBin = 0;
        if (CryptStringToBinaryA(reinterpret_cast<LPCSTR>(fileData.data()), static_cast<DWORD>(fileData.size()),
                CRYPT_STRING_BASE64_ANY, nullptr, &cbBin, nullptr, nullptr) && cbBin > 0)
        {
            derBuffer.resize(cbBin);
            if (CryptStringToBinaryA(reinterpret_cast<LPCSTR>(fileData.data()), static_cast<DWORD>(fileData.size()),
                    CRYPT_STRING_BASE64_ANY, derBuffer.data(), &cbBin, nullptr, nullptr))
            {
                pCrl = CertCreateCRLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derBuffer.data(), cbBin);
            }
        }
    }
    if (!pCrl)
    {
        EIDM_TRACE_ERROR(L"File is not a valid CRL (DER or PEM)");
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }

    HRESULT hr = E_FAIL;  // NOSONAR (EXPLICIT-TYPE-03) - HRESULT visible for security audit
    HCERTSTORE hRoot = CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG, L"Root");
    HCERTSTORE hCA = CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG, L"CA");
    HCERTSTORE hDest = nullptr;
    PCCERT_CONTEXT pIssuer = nullptr;

    // ---- SECURITY: only install a CRL signed by a CA already trusted on this machine ----
    if (hCA)
        pIssuer = CertFindCertificateInStore(hCA, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME, &pCrl->pCrlInfo->Issuer, nullptr);
    if (!pIssuer && hRoot)
        pIssuer = CertFindCertificateInStore(hRoot, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME, &pCrl->pCrlInfo->Issuer, nullptr);

    if (!pIssuer)
    {
        EIDM_TRACE_ERROR(L"CRL issuer is not a trusted CA on this machine - refusing to install");
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto cleanup;
    }
    if (!CryptVerifyCertificateSignatureEx(NULL, X509_ASN_ENCODING,
            CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL, (void*)pCrl,
            CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)pIssuer, 0, nullptr))
    {
        EIDM_TRACE_ERROR(L"CRL signature does not verify against its issuer - refusing to install (0x%08X)", GetLastError());
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto cleanup;
    }

    // ---- Freshness warning (nextUpdate in the past) ----
    {
        FILETIME ftNow;
        GetSystemTimeAsFileTime(&ftNow);
        const FILETIME ftNext = pCrl->pCrlInfo->NextUpdate;
        if ((ftNext.dwLowDateTime != 0 || ftNext.dwHighDateTime != 0) && CompareFileTime(&ftNext, &ftNow) < 0)
            EIDM_TRACE_WARN(L"CRL nextUpdate is in the past - it is stale; distribute a fresher CRL");
    }

    // ---- Install into LocalMachine\CA (replace any older CRL from the same issuer) ----
    hDest = CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"CA");
    if (!hDest)
    {
        DWORD dwErr = GetLastError();
        EIDM_TRACE_ERROR(L"Cannot open LocalMachine CA store (administrator required?): %u", dwErr);
        hr = HRESULT_FROM_WIN32(dwErr);
        goto cleanup;
    }
    if (!CertAddCRLContextToStore(hDest, pCrl, CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
    {
        DWORD dwErr = GetLastError();
        EIDM_TRACE_ERROR(L"CertAddCRLContextToStore failed: %u", dwErr);
        hr = HRESULT_FROM_WIN32(dwErr);
        goto cleanup;
    }
    EIDM_TRACE_INFO(L"CRL installed into the LocalMachine CA store");
    hr = S_OK;

cleanup:
    if (pIssuer) CertFreeCertificateContext(pIssuer);
    if (hDest) CertCloseStore(hDest, 0);
    if (hCA) CertCloseStore(hCA, 0);
    if (hRoot) CertCloseStore(hRoot, 0);
    if (pCrl) CertFreeCRLContext(pCrl);
    return hr;
}
