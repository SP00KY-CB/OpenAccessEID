/*
    OpenAccess EID - Smart card authentication for Windows
    Copyright (C) 2009 Vincent Le Toux
    Copyright (C) 2026 Contributors

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, see <https://www.gnu.org/licenses/>.
*/


#include <Windows.h>
#include <tchar.h>
#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "GPO.h"
#include "CertificateValidation.h"
#include "CertificateUtilities.h"
#include "InputValidation.h"

#pragma comment(lib,"Crypt32")

// Non-const copy for Windows API compatibility (params.EnhkeyUsage.rgpszUsageIdentifier is LPSTR*)
// With /Zc:strictStrings (enabled by default in C++23), string literals are const and cannot
// be implicitly converted to non-const LPSTR. This static array provides writable storage.
static char s_szOidSmartCardLogon[] = szOID_KP_SMARTCARD_LOGON;       // NOSONAR - GLOBAL-01: Runtime-initialized LSA state

//=============================================================================
// HELPER FUNCTIONS FOR COMPLEXITY REDUCTION
// These helpers extract chain validation logic to reduce cognitive complexity
// in IsTrustedCertificate and MakeTrustedCertificate functions.
//=============================================================================

namespace {

// Build the certificate chain using CertGetCertificateChain
// Returns the chain context on success, nullptr on failure
// Complexity reduction helper for certificate validation (Phase 36-01)
PCCERT_CHAIN_CONTEXT BuildCertificateChain(
    __in HCERTCHAINENGINE hChainEngine,
    __in PCCERT_CONTEXT pCertContext,
    __in PCERT_CHAIN_PARA pChainPara,
    __in DWORD dwChainFlags)
{
    PCCERT_CHAIN_CONTEXT pChainContext = nullptr;

    if (!CertGetCertificateChain(hChainEngine, pCertContext, nullptr, nullptr,
                                  pChainPara, dwChainFlags, nullptr, &pChainContext))
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Error 0x%08x returned by CertGetCertificateChain",
                            GetLastError());
        return nullptr;
    }

    return pChainContext;
}

// Verify chain policy using CertVerifyCertificateChainPolicy
// Returns TRUE if policy verification succeeded, FALSE otherwise
// Complexity reduction helper for certificate validation (Phase 36-01)
BOOL VerifyChainPolicy(
    __in PCCERT_CHAIN_CONTEXT pChainContext,
    __in PCERT_CHAIN_POLICY_PARA pChainPolicy,
    __out PCERT_CHAIN_POLICY_STATUS pPolicyStatus)
{
    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, pChainContext,
                                           pChainPolicy, pPolicyStatus))
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Certificate chain policy verification failed");
        EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"CertVerifyCertificateChainPolicy error 0x%08x",
                            GetLastError());
        return FALSE;
    }
    return TRUE;
}

// Check chain trust status and determine if there are hard failures
// Returns TRUE if chain has only soft failures (acceptable), FALSE if hard failures exist
// Complexity reduction helper for certificate validation (Phase 36-01)
BOOL CheckChainTrustStatus(__in PCCERT_CHAIN_CONTEXT pChainContext, __out DWORD* pdwError)
{
    *pdwError = 0;

    if (!pChainContext->TrustStatus.dwErrorStatus)
    {
        return TRUE;  // No errors
    }

    DWORD dwStatus = pChainContext->TrustStatus.dwErrorStatus;

    // Soft failures: non-security-critical conditions that allow continuation.
    //   IS_NOT_TIME_NESTED         : a non-root cert expires after its issuer - harmless.
    //   REVOCATION_STATUS_UNKNOWN  : no CRL/OCSP reachable - expected on air-gapped hosts.
    //   IS_OFFLINE_REVOCATION      : the revocation server was unreachable / no cached CRL -
    //     Windows raises this alongside REVOCATION_STATUS_UNKNOWN on a host with no cached CRL
    //     (the default), so it must be tolerated in lockstep with UNKNOWN.
    //   HAS_NOT_SUPPORTED_NAME_CONSTRAINT, HAS_NOT_DEFINED_NAME_CONSTRAINT:
    //     constraint types Windows can't evaluate - treat as unknown rather than failure.
    //
    // NOT soft-failed (intentional):
    //   HAS_NOT_PERMITTED_NAME_CONSTRAINT - cert names a subject outside the
    //     permitted subtree of an issuer above it.
    //   HAS_EXCLUDED_NAME_CONSTRAINT      - cert names a subject inside the
    //     excluded subtree of an issuer above it.
    //   Both indicate an explicit PKI policy violation; honour them.
    DWORD dwSoftFailures = CERT_TRUST_IS_NOT_TIME_NESTED |
                           CERT_TRUST_REVOCATION_STATUS_UNKNOWN |
                           CERT_TRUST_IS_OFFLINE_REVOCATION |
                           CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT |
                           CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT;

    // M1: when RequireRevocationCheck is set, an unproven revocation state - "revocation status
    // unknown" AND "offline revocation" (no reachable/cached CRL) - becomes a HARD failure: the
    // card is refused unless a current CRL proves it is not revoked (fail closed). Default (policy
    // off) keeps soft-failing both so isolated machines without a CRL still log on (fail open).
    if (GetPolicyValue(GPOPolicy::RequireRevocationCheck) != 0)
        dwSoftFailures &= ~(CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION);

    if (DWORD dwHardFailures = dwStatus & ~dwSoftFailures; dwHardFailures != 0)
    {
        *pdwError = dwStatus;
        // A revoked card is a high-signal security event - audit it (structured, for SIEM).
        if (dwStatus & CERT_TRUST_IS_REVOKED)
            EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[CERT_REVOKED] Smart card certificate is revoked (chain status 0x%08x) - logon refused", dwStatus);
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Error %s (0x%08x) returned by CertGetCertificateChain",
                            GetTrustErrorText(dwStatus), dwStatus);
        return FALSE;
    }

    // Soft failures only - log and continue
    EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Chain has soft failures (0x%08x) - continuing", dwStatus);
    return TRUE;
}

// Log chain validation error with descriptive text
// Complexity reduction helper for certificate validation (Phase 36-01)
void LogChainValidationError(__in DWORD dwError)
{
    LPCTSTR pszErrorText = GetTrustErrorText(dwError);
    if (pszErrorText)
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Chain validation error: %s (0x%08x)",
                            pszErrorText, dwError);
    }
    else
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Chain validation error: 0x%08x", dwError);
    }
}

// Check if chain depth exceeds reasonable limits
// Returns TRUE if depth is acceptable, FALSE if chain is too deep
// Complexity reduction helper for certificate validation (Phase 36-01)
BOOL CheckChainDepth(__in PCCERT_CHAIN_CONTEXT pChainContext, __out DWORD* pdwError)
{
    *pdwError = 0;

    // Typical chains are 2-3 levels (Root -> [Intermediate] -> End Entity)
    constexpr DWORD MAX_CHAIN_DEPTH = 5;

    if (pChainContext->cChain > 0 && pChainContext->rgpChain[0]->cElement > MAX_CHAIN_DEPTH)  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
    {
        *pdwError = static_cast<DWORD>(CERT_E_CHAINING);
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Certificate chain depth %d exceeds maximum %d",
                            pChainContext->rgpChain[0]->cElement, MAX_CHAIN_DEPTH);
        return FALSE;
    }

    return TRUE;
}

// Check if policy status error is a soft failure that can be ignored
// Returns TRUE if policy check should continue, FALSE if it's a hard failure
// Complexity reduction helper for certificate validation (Phase 36-01)
BOOL IsPolicySoftFailure(__in DWORD dwPolicyError)
{
    // Validity-period nesting is always a soft failure for self-managed PKI.
    if (dwPolicyError == CERT_E_VALIDITYPERIODNESTING)
        return TRUE;

    // M1: revocation could not be performed (no CRL cached / offline). Soft-fail by default so
    // isolated machines without a distributed CRL still work; hard-fail when RequireRevocationCheck
    // demands positive proof the certificate is not revoked.
    if (dwPolicyError == CRYPT_E_NO_REVOCATION_CHECK || dwPolicyError == CRYPT_E_REVOCATION_OFFLINE)
        return GetPolicyValue(GPOPolicy::RequireRevocationCheck) == 0;

    return FALSE;
}

} // anonymous namespace

void InitChainValidationParams(ChainValidationParams* params)
{
    params->EnhkeyUsage.cUsageIdentifier = 0;
    params->EnhkeyUsage.rgpszUsageIdentifier = nullptr;
    params->CertUsage.dwType = USAGE_MATCH_TYPE_AND;
    params->CertUsage.Usage = params->EnhkeyUsage;
    
    memset(&params->ChainPara, 0, sizeof(CERT_CHAIN_PARA));
    params->ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    params->ChainPara.RequestedUsage = params->CertUsage;
    
    memset(&params->ChainPolicy, 0, sizeof(CERT_CHAIN_POLICY_PARA));
    params->ChainPolicy.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
    
    memset(&params->PolicyStatus, 0, sizeof(CERT_CHAIN_POLICY_STATUS));
    params->PolicyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);
    params->PolicyStatus.lChainIndex = -1;
    params->PolicyStatus.lElementIndex = -1;
}

// Internal function using Result<T> for type-safe error handling
// Marked noexcept for LSASS compatibility
// Note: EIDImpersonate/EIDRevertToSelf must be called by the wrapper for proper cleanup
[[nodiscard]] EID::Result<PCCERT_CONTEXT> GetCertificateFromCspInfoInternal(
    __in PEID_SMARTCARD_CSP_INFO pCspInfo, __in ULONG dwCspDataLength) noexcept
{
	// for TS Smart Card redirection
	PCCERT_CONTEXT pCertContext = nullptr;
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"GetCertificateFromCspInfoInternal");
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL

	// Offset validation is centralised in EIDValidateCspInfo. The previous
	// inline check here bounded the offsets against dwCspInfoLen - a field
	// inside the same attacker-supplied buffer, so it could be inflated at
	// will - and it compared BYTE counts against offsets that are then used to
	// index bBuffer, which is TCHAR[]. That mismatch allowed a read of up to
	// twice the declared bound. EIDValidateCspInfo does the arithmetic in WCHAR
	// units and requires each string to terminate inside the buffer.
	if (!EIDValidateCspInfo(pCspInfo, dwCspDataLength))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"GetCertificateFromCspInfoInternal: CSP info layout rejected (CspDataLength=%u)",
			dwCspDataLength);
		return EID::make_unexpected(E_INVALIDARG);
	}
	LPCTSTR szContainerName = EIDCspInfoStringAt(pCspInfo, dwCspDataLength, pCspInfo->nContainerNameOffset);
	LPCTSTR szProviderName = EIDCspInfoStringAt(pCspInfo, dwCspDataLength, pCspInfo->nCSPNameOffset);
	if (!szProviderName || !szContainerName)
	{
		// Both are required. A null container name is NOT equivalent to "field
		// absent" here: CryptAcquireContext reads nullptr as "use the provider's
		// DEFAULT container", which is precisely the PIV fallback performed
		// below only after the named lookup fails. Letting an absent field
		// silently select that path would turn a malformed request into a
		// different, weaker lookup. Every writer in this repo emits both names.
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"GetCertificateFromCspInfoInternal: CSP name or container name absent");
		return EID::make_unexpected(E_INVALIDARG);
	}

	BYTE Data[4096];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD DataSize = ARRAYSIZE(Data);
	HCRYPTKEY phUserKey = NULL;  // Windows handle type - keep as NULL
	BOOL fResult;

	// check input
	if (GetPolicyValue(GPOPolicy::AllowSignatureOnlyKeys) == 0 && pCspInfo->KeySpec == AT_SIGNATURE)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Policy denies AT_SIGNATURE Key");
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED));
	}
	// Security: Validate CSP provider before loading
	if (!IsAllowedCSPProvider(szProviderName))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"CSP provider '%s' not allowed", szProviderName);
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED));
	}
	fResult = CryptAcquireContext(&hProv, szContainerName, szProviderName, PROV_RSA_FULL, CRYPT_SILENT);
	if (!fResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CryptAcquireContext : 0x%08x container='%s' provider='%s'", GetLastError(), szContainerName, szProviderName);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"PIV fallback");
		fResult = CryptAcquireContext(&hProv, nullptr, szProviderName, PROV_RSA_FULL, CRYPT_SILENT);
		if (!fResult)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CryptAcquireContext : 0x%08x", GetLastError());
			return EID::make_unexpected(HRESULT_FROM_WIN32(GetLastError()));
		}
	}
	if (!CryptGetUserKey(hProv, pCspInfo->KeySpec, &phUserKey))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CryptGetUserKey : 0x%08x", GetLastError());
		CryptReleaseContext(hProv, 0);
		return EID::make_unexpected(HRESULT_FROM_WIN32(GetLastError()));
	}
	if (!CryptGetKeyParam(phUserKey, KP_CERTIFICATE, (BYTE*)Data, &DataSize, 0))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CryptGetKeyParam : 0x%08x", GetLastError());
		CryptDestroyKey(phUserKey);
		CryptReleaseContext(hProv, 0);
		return EID::make_unexpected(HRESULT_FROM_WIN32(GetLastError()));
	}
	pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, Data, DataSize);
	if (!pCertContext)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CertCreateCertificateContext : 0x%08x", GetLastError());
		CryptDestroyKey(phUserKey);
		CryptReleaseContext(hProv, 0);
		return EID::make_unexpected(HRESULT_FROM_WIN32(GetLastError()));
	}
	// The certificate context releases hProv when it is freed, so it needs a reference of its own.
	// Take that reference BEFORE handing hProv to the certificate context: once the
	// key-context property is set, freeing the certificate releases hProv, so taking the
	// reference afterwards meant a failed AddRef released the caller's handle twice.
	if (!CryptContextAddRef(hProv, nullptr, 0))
	{
		HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CryptContextAddRef 0x%08x", hr);
		CertFreeCertificateContext(pCertContext);
		CryptDestroyKey(phUserKey);
		CryptReleaseContext(hProv, 0);
		return EID::make_unexpected(hr);
	}
	// save reference to CSP (else we can't access private key)
	if (!SetupCertificateContextWithKeyInfo(pCertContext, hProv, szProviderName, szContainerName, pCspInfo->KeySpec))
	{
		HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
		CertFreeCertificateContext(pCertContext);
		CryptDestroyKey(phUserKey);
		CryptReleaseContext(hProv, 0);	// undo the AddRef above
		CryptReleaseContext(hProv, 0);
		return EID::make_unexpected(hr);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"Certificate OK");

	// Cleanup key handle - the provider handle is referenced by the certificate
	CryptDestroyKey(phUserKey);
	// The certificate now owns the reference taken above and releases it when it is freed;
	// drop ours, or every call leaks a CSP context (and its card handle) in LSASS.
	CryptReleaseContext(hProv, 0);

	return pCertContext;
}

// Exported wrapper maintaining PCCERT_CONTEXT return type with SetLastError
PCCERT_CONTEXT GetCertificateFromCspInfo(__in PEID_SMARTCARD_CSP_INFO pCspInfo, __in ULONG dwCspDataLength)
{
	EIDImpersonate();
	auto result = GetCertificateFromCspInfoInternal(pCspInfo, dwCspDataLength);
	EIDRevertToSelf();

	if (result.has_value())
	{
		SetLastError(ERROR_SUCCESS);
		return *result;
	}
	SetLastError(static_cast<DWORD>(result.error()));
	return nullptr;
}

#define ERRORTOTEXT(ERROR) case ERROR: pszName = TEXT(#ERROR);                 break;
LPCTSTR GetTrustErrorText(DWORD Status)
{
    LPCTSTR pszName = nullptr;
    switch(Status)
    {
		ERRORTOTEXT(CERT_E_EXPIRED)
		ERRORTOTEXT(CERT_E_VALIDITYPERIODNESTING)
		ERRORTOTEXT(CERT_E_ROLE)
		ERRORTOTEXT(CERT_E_PATHLENCONST)
		ERRORTOTEXT(CERT_E_CRITICAL)
		ERRORTOTEXT(CERT_E_PURPOSE)
		ERRORTOTEXT(CERT_E_ISSUERCHAINING)
		ERRORTOTEXT(CERT_E_MALFORMED)
		ERRORTOTEXT(CERT_E_UNTRUSTEDROOT)
		ERRORTOTEXT(CERT_E_CHAINING)
		ERRORTOTEXT(TRUST_E_FAIL)
		ERRORTOTEXT(CERT_E_REVOKED)
		ERRORTOTEXT(CERT_E_UNTRUSTEDTESTROOT)
		ERRORTOTEXT(CERT_E_REVOCATION_FAILURE)
		ERRORTOTEXT(CERT_E_CN_NO_MATCH)
		ERRORTOTEXT(CERT_E_WRONG_USAGE)
		ERRORTOTEXT(CERT_TRUST_NO_ERROR)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_TIME_VALID)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_TIME_NESTED)
		ERRORTOTEXT(CERT_TRUST_IS_REVOKED)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_SIGNATURE_VALID)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
		ERRORTOTEXT(CERT_TRUST_IS_UNTRUSTED_ROOT)
		ERRORTOTEXT(CERT_TRUST_REVOCATION_STATUS_UNKNOWN)
		ERRORTOTEXT(CERT_TRUST_IS_CYCLIC)
		ERRORTOTEXT(CERT_TRUST_IS_PARTIAL_CHAIN)
		ERRORTOTEXT(CERT_TRUST_CTL_IS_NOT_TIME_VALID)
		ERRORTOTEXT(CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID)
		ERRORTOTEXT(CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE)
		default:                            
			pszName = nullptr;                      break;
    }
	return pszName;
} 
#undef ERRORTOTEXT


// Internal function using Result<T> for type-safe error handling
// Marked noexcept for LSASS compatibility
[[nodiscard]] EID::ResultVoid HasCertificateRightEKUInternal(
    __in PCCERT_CONTEXT pCertContext) noexcept
{
	if (GetPolicyValue(GPOPolicy::AllowCertificatesWithNoEKU) != 0)
	{
		// Policy allows certificates without EKU - success
		return {};
	}

	// Check EKU SmartCardLogon
	DWORD dwSize = 0;
	if (!CertGetEnhancedKeyUsage(pCertContext, 0, nullptr, &dwSize))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Error 0x%08x returned by CertGetEnhancedKeyUsage", GetLastError());
		return EID::make_unexpected(HRESULT_FROM_WIN32(GetLastError()));
	}

	auto pCertUsage = static_cast<PCERT_ENHKEY_USAGE>(EIDAlloc(dwSize));
	if (!pCertUsage)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Error 0x%08x returned by EIDAlloc", GetLastError());
		return EID::make_unexpected(E_OUTOFMEMORY);
	}

	// Use RAII-style cleanup
	struct CertUsageDeleter {
		PCERT_ENHKEY_USAGE p;
		explicit CertUsageDeleter(PCERT_ENHKEY_USAGE ptr) : p(ptr) {}
		~CertUsageDeleter() { if (p) EIDFree(p); }
		// Delete copy/move - this manages a resource
		CertUsageDeleter(const CertUsageDeleter&) = delete;
		CertUsageDeleter& operator=(const CertUsageDeleter&) = delete;
	};
	CertUsageDeleter cleanup(pCertUsage);

	if (!CertGetEnhancedKeyUsage(pCertContext, 0, pCertUsage, &dwSize))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Error 0x%08x returned by CertGetEnhancedKeyUsage", GetLastError());
		return EID::make_unexpected(HRESULT_FROM_WIN32(GetLastError()));
	}

	for (DWORD dwI = 0; dwI < pCertUsage->cUsageIdentifier; dwI++)
	{
		if (strcmp(pCertUsage->rgpszUsageIdentifier[dwI], szOID_KP_SMARTCARD_LOGON) == 0)
		{
			// Found SmartCard Logon EKU
			return {};
		}
	}

	EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"No EKU found in end certificate");
	return EID::make_unexpected(CERT_TRUST_IS_NOT_VALID_FOR_USAGE);
}

// Exported wrapper maintaining BOOL + GetLastError pattern for API compatibility
BOOL HasCertificateRightEKU(__in PCCERT_CONTEXT pCertContext)
{
	return EID::to_bool(HasCertificateRightEKUInternal(pCertContext));
}

BOOL IsCertificateInComputerTrustedPeopleStore(__in PCCERT_CONTEXT pCertContext)
{
	BOOL fReturn = FALSE;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Testing trusted certificate");
	HCERTSTORE hTrustedPeople = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,_T("TrustedPeople"));
	if (hTrustedPeople)  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
	{

		PCCERT_CONTEXT pCertificateFound = CertFindCertificateInStore(hTrustedPeople, pCertContext->dwCertEncodingType, 0, CERT_FIND_EXISTING, pCertContext, nullptr);
		if (pCertificateFound)  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Certificate found in trusted people store");
			fReturn = TRUE;
			CertFreeCertificateContext(pCertificateFound);
		}
		CertCloseStore(hTrustedPeople, 0);
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"unable to open store 0x%08x", GetLastError());
	}
	return fReturn;
}

BOOL IsTrustedCertificate(__in PCCERT_CONTEXT pCertContext, __in_opt DWORD dwFlag)
{
	// Refactored for complexity reduction (Phase 36-01)
	// Uses helper functions BuildCertificateChain, VerifyChainPolicy, etc.

	BOOL fValidation = FALSE;
	PCCERT_CHAIN_CONTEXT pChainContext = nullptr;
	ChainValidationParams params;
	LPSTR szOid;
	HCERTCHAINENGINE hChainEngine = HCCE_LOCAL_MACHINE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	DWORD dwError = 0;

	// Initialize data structures for chain building
	InitChainValidationParams(&params);

	if (dwFlag & EID_CERTIFICATE_FLAG_USERSTORE)
	{
		hChainEngine = HCCE_CURRENT_USER;
	}

	__try
	{
		// Always enforce Smart Card Logon EKU - certificates without this EKU must not authenticate
		params.EnhkeyUsage.cUsageIdentifier = 1;
		szOid = s_szOidSmartCardLogon;
		params.EnhkeyUsage.rgpszUsageIdentifier = &szOid;
		params.CertUsage.dwType = USAGE_MATCH_TYPE_OR;

		if (!HasCertificateRightEKU(pCertContext))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Error 0x%08x returned by HasCertificateRightEKU", dwError);
			__leave;
		}

		// Build certificate chain using helper.
		// Revocation (M1): check the chain (excluding the root) using ONLY locally cached/installed
		// CRLs - CACHE_ONLY_URL_RETRIEVAL never touches the network, so this works on isolated
		// machines where CRLs are distributed offline (e.g. via "EIDMigrate import-crl"). A revoked
		// cert then fails hard (CERT_TRUST_IS_REVOKED); "revocation unknown" (no CRL cached) is
		// soft-failed unless the RequireRevocationCheck policy is set (see CheckChainTrustStatus /
		// IsPolicySoftFailure).
		DWORD dwChainFlags = CERT_CHAIN_ENABLE_PEER_TRUST
			| CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
			| CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
		pChainContext = BuildCertificateChain(hChainEngine, pCertContext, &params.ChainPara, dwChainFlags);
		if (!pChainContext)
		{
			dwError = GetLastError();
			__leave;
		}

		// Check chain depth using helper
		if (!CheckChainDepth(pChainContext, &dwError))
		{
			__leave;
		}

		// Check chain trust status using helper
		if (!CheckChainTrustStatus(pChainContext, &dwError))
		{
			__leave;
		}

		// Verify chain policy using helper
		if (!VerifyChainPolicy(pChainContext, &params.ChainPolicy, &params.PolicyStatus))
		{
			dwError = GetLastError();
			__leave;
		}

		// Check policy status
		if (params.PolicyStatus.dwError)
		{
			if (IsPolicySoftFailure(params.PolicyStatus.dwError))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Policy soft failure (0x%08x) - continuing",
				                    params.PolicyStatus.dwError);
			}
			else
			{
				dwError = params.PolicyStatus.dwError;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Certificate chain policy check failed");
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Policy error %s (0x%08x)",
				                    GetTrustErrorText(params.PolicyStatus.dwError), params.PolicyStatus.dwError);
				__leave;
			}
		}

		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"Chain validated");

		// Always enforce time validity - expired certificates must not authenticate
		if (LPFILETIME pTimeToVerify = nullptr; CertVerifyTimeValidity(pTimeToVerify, pCertContext->pCertInfo))
		{
			dwError = static_cast<DWORD>(CERT_E_EXPIRED);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Certificate time validity check failed");
			__leave;
		}

		fValidation = TRUE;
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"Valid");
	}
	__finally
	{
		if (pChainContext)
			CertFreeCertificateChain(pChainContext);
	}

	SetLastError(dwError);
	return fValidation;
}

BOOL MakeTrustedCertifcate(PCCERT_CONTEXT pCertContext)
{

	BOOL fReturn = FALSE;
	PCCERT_CHAIN_CONTEXT     pChainContext     = nullptr;
	ChainValidationParams     params;
	LPSTR					szOid;
	HCERTSTORE hRootStore = nullptr;
	HCERTSTORE hTrustStore = nullptr;
	HCERTSTORE hTrustedPeople = nullptr;
	// because machine cert are trusted by user,
	// build the chain in user context (if used certifcates are trusted only by the user
	// - think about program running in user space)
	HCERTCHAINENGINE		hChainEngine		= HCCE_CURRENT_USER;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	DWORD dwError = 0;

	//---------------------------------------------------------
    // Initialize data structures for chain building.
	InitChainValidationParams(&params);

	if (GetPolicyValue(GPOPolicy::AllowCertificatesWithNoEKU))
	{
		params.EnhkeyUsage.cUsageIdentifier = 0;
		params.EnhkeyUsage.rgpszUsageIdentifier = nullptr;
	}
	else
	{
		params.EnhkeyUsage.cUsageIdentifier = 1;
		szOid = s_szOidSmartCardLogon;
		params.EnhkeyUsage.rgpszUsageIdentifier = &szOid;
	}

	   //-------------------------------------------------------------------
    // Build a chain using CertGetCertificateChain
    __try
	{
		fReturn = CertGetCertificateChain(hChainEngine,pCertContext,nullptr,nullptr,&params.ChainPara,CERT_CHAIN_ENABLE_PEER_TRUST,nullptr,&pChainContext);
		if (!fReturn)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateChain", dwError);
			__leave;
		}
		// pChainContext->cChain -1 is the final chain num
		DWORD dwCertificateCount = pChainContext->rgpChain[pChainContext->cChain -1]->cElement;
		if (dwCertificateCount == 1)
		{
			hTrustedPeople = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("TrustedPeople"));
			if (!hTrustedPeople)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertOpenStore", dwError);
				fReturn = FALSE;
				__leave;
			}
			fReturn = CertAddCertificateContextToStore(hTrustedPeople,
					pChainContext->rgpChain[pChainContext->cChain -1]->rgpElement[0]->pCertContext,
					CERT_STORE_ADD_USE_EXISTING,nullptr);
		}
		else
		{
			hRootStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("Root"));
			if (!hRootStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertOpenStore", dwError);
				fReturn = FALSE;
				__leave;
			}
			hTrustStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("CA"));
			if (!hTrustStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertOpenStore", dwError);
				fReturn = FALSE;
				__leave;
			}
			for (DWORD i = dwCertificateCount - 1 ; i > 0 ; i--)
			{
				if (i < dwCertificateCount - 1)
				{
					// second & so on don't have to be trusted
					fReturn = CertAddCertificateContextToStore(hTrustStore,
						pChainContext->rgpChain[pChainContext->cChain -1]->rgpElement[i]->pCertContext,
						CERT_STORE_ADD_USE_EXISTING,nullptr);
				}
				else
				{
					// first must be trusted
					fReturn = CertAddCertificateContextToStore(hRootStore,
						pChainContext->rgpChain[pChainContext->cChain -1]->rgpElement[i]->pCertContext,
						CERT_STORE_ADD_USE_EXISTING,nullptr);
				}
				if (!fReturn)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertAddCertificateContextToStore", dwError);
					__leave;
				}
			}
		}
	}
	__finally
	{
		if (hTrustedPeople)
			CertCloseStore(hTrustedPeople,0);
		if (hRootStore)
			CertCloseStore(hRootStore,0);
		if (hTrustStore)
			CertCloseStore(hTrustStore,0);
		if (pChainContext)
			CertFreeCertificateChain(pChainContext);
	}
	SetLastError(dwError);
	return fReturn;
}

// CSP provider whitelist validation
// Returns TRUE if the provider is a known legitimate smart card CSP
// This prevents malicious certificates from loading arbitrary code via CSP injection
BOOL IsAllowedCSPProvider(__in LPCWSTR pwszProviderName)
{
	if (pwszProviderName == nullptr)
	{
		EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"CSP validation failed: NULL provider name");
		return FALSE;
	}

	// Whitelist of known legitimate smart card CSP providers
	// These are the standard Microsoft and common third-party smart card CSPs
	static LPCWSTR AllowedProviders[] = {  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		// Microsoft Base Smart Card CSPs
		L"Microsoft Base Smart Card Crypto Provider",
		L"Microsoft Smart Card Key Storage Provider",
		// Legacy Microsoft CSPs that may be used with smart cards
		L"Microsoft Enhanced RSA and AES Cryptographic Provider",
		L"Microsoft Enhanced Cryptographic Provider v1.0",
		L"Microsoft Strong Cryptographic Provider",
		L"Microsoft Base Cryptographic Provider v1.0",
		// Common third-party smart card CSPs
		L"SafeNet RSA Full Cryptographic Provider",
		L"Gemalto Classic Card CSP",
		L"Thales eSecurity SafeNet Authentication Client",
		L"PIVKey Minidriver",
		L"YubiKey Smart Card Minidriver",
		L"Feitian ePass CSP",
		// NULL terminator
		nullptr
	};

	// Check if the provider matches any in the whitelist
	for (int i = 0; AllowedProviders[i] != nullptr; i++)
	{
		if (_wcsicmp(pwszProviderName, AllowedProviders[i]) == 0)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"CSP validation: '%s' is allowed", pwszProviderName);
			return TRUE;
		}
	}

	// Not in whitelist - log security warning
	EIDSecurityAudit(SECURITY_AUDIT_WARNING, L"Unknown CSP provider '%s' - not in whitelist", pwszProviderName);

	// Behaviour is gated by the EnforceCSPWhitelist GPO:
	//   policy = 1 : block unknown providers (high-assurance)
	//   policy = 0 : allow unknown providers, audit-only (Windows default behaviour)
	// The default of 0 preserves interoperability with third-party smart-card
	// CSPs that legitimately exist but are not on our whitelist. Turn the
	// policy on in environments where provider substitution is a concern.
	if (GetPolicyValue(GPOPolicy::EnforceCSPWhitelist))
	{
		EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"CSP provider '%s' blocked by EnforceCSPWhitelist policy", pwszProviderName);
		return FALSE;
	}

	return TRUE;
}