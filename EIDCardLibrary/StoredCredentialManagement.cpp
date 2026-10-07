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


#include <ntstatus.h>
#define WIN32_NO_STATUS  // NOSONAR - MACRO-02: Windows SDK configuration, prevents ntstatus.h conflicts
#include <Windows.h>
#include <tchar.h>
#define SECURITY_WIN32
#include <sspi.h>

#include <ShlObj.h>
#include <NTSecAPI.h>
#include <LM.h>

#include <NTSecPKG.h>
#include <strsafe.h>

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "CertificateValidation.h"
#include "StringConversion.h"
#include "CSVConfig.h"
#include "CSVLogger.h"
#include "GPO.h"
#include "InputValidation.h"
#include <string>
#include <span>
#include <array>
#include <climits>

constexpr LPCTSTR CREDENTIALPROVIDER = MS_ENH_RSA_AES_PROV;
constexpr DWORD CREDENTIALKEYLENGTH = 256;
// The validator rejects a challenge of any other length before it reaches the
// verifiers below, so the two constants must not drift apart.
static_assert(CREDENTIALKEYLENGTH == EID_CHALLENGE_LENGTH,
	"challenge length in InputValidation.h must match CREDENTIALKEYLENGTH");
constexpr ALG_ID CREDENTIALCRYPTALG = CALG_AES_256;
constexpr LPCWSTR CREDENTIAL_LSAPREFIX = L"L$_EID_";

#pragma comment(lib,"Crypt32")
#pragma comment(lib,"advapi32")
#pragma comment(lib,"Netapi32")



extern "C"
{
	NTSTATUS WINAPI SystemFunction007 (PUNICODE_STRING string, LPBYTE hash);
}

// level 1
#include "StoredCredentialManagement.h"  // NOSONAR - INCLUDE-01: include order/casing significant for Windows SDK
#include <new>
CStoredCredentialManager *CStoredCredentialManager::theSingleInstance = nullptr;
static INIT_ONCE s_StoredCredentialManagerInitOnce = INIT_ONCE_STATIC_INIT;

// InitOnce serialises concurrent first calls (LSA calls in on many threads).
// The instance lives for the life of the process. Returning FALSE when the
// allocation fails leaves the INIT_ONCE open, so a later call tries again.
BOOL CALLBACK CStoredCredentialManager::CreateInstanceOnce(PINIT_ONCE, PVOID, PVOID*)
{
	theSingleInstance = new (std::nothrow) CStoredCredentialManager;  // NOSONAR - OWNERSHIP-01: singleton instance intentionally persists for process lifetime
	return theSingleInstance != nullptr;
}

CStoredCredentialManager* CStoredCredentialManager::Instance()
{
	if (!InitOnceExecuteOnce(&s_StoredCredentialManagerInitOnce, CreateInstanceOnce, nullptr, nullptr))
	{
		return nullptr;
	}
	return theSingleInstance;
}

//=============================================================================
// HELPER FUNCTIONS FOR COMPLEXITY REDUCTION
// These helpers extract encryption logic from CreateCredential to reduce
// cognitive complexity while maintaining SEH safety for LSASS compatibility.
// Placed after header include to have access to EID_PRIVATE_DATA types.
//=============================================================================

// Every offset/size triple in EID_PRIVATE_DATA is attacker-influenced: the blob comes
// straight out of an LSA secret that an administrator (or an imported .eidm) can write,
// and each consumer indexes Data[] with those values inside LSASS. Validate the whole
// layout once, at the single point where the blob is read, so no consumer has to.

// Scrub-and-free for a stored-credential blob. Every release of one of these
// must go through here: it carries the certificate, the RSA-wrapped symmetric
// key and the encrypted password, and four call sites previously freed it
// unscrubbed - two of them on every authentication - leaving that material in
// LSASS heap. Kept in this file rather than InputValidation.cpp because it
// needs EIDFree, and that translation unit must stay dependency-free so the
// fuzz targets can link it standalone.
static void EIDFreePrivateData(__in_opt PEID_PRIVATE_DATA pPrivateData, __in DWORD dwBlobSize)
{
	if (!pPrivateData)
	{
		return;
	}
	const DWORD dwSpan = EIDPrivateDataSpan(pPrivateData, dwBlobSize);
	// Fall back to the raw allocation size if the layout does not validate -
	// a malformed blob still holds whatever was read out of the LSA secret.
	SecureZeroMemory(pPrivateData, dwSpan ? dwSpan : dwBlobSize);
	EIDFree(pPrivateData);
}

// The layout rule now lives in InputValidation.cpp (EIDValidatePrivateDataLayout)
// so that this file, EIDMigrate\LsaClient.cpp and the fuzz harness all share one
// implementation. The version that used to sit here checked each region
// individually but not their sum, which is what let the cleanup zeroize below
// overrun; it also accepted usPasswordLen == 0, which underflows dwRoundNumber
// in GetPasswordFromCryptedChallengeResponse.

namespace {

// Calculate the total size needed for EID_PRIVATE_DATA buffer
// Returns the total allocation size in bytes, or 0 when the layout cannot be
// represented: every offset/size in EID_PRIVATE_DATA is a USHORT, and the blob
// size itself is passed around as a USHORT, so the sum is computed in size_t and
// refused (rather than silently wrapped) when it exceeds USHRT_MAX. A wrapped
// size here used to give a small allocation that BuildSecretData then overran
// with the full certificate - a heap overflow inside LSASS.
// Complexity reduction helper for CreateCredential (Phase 36-01)
USHORT CalculateSecretSize(bool fEncryptPassword, USHORT usEncryptedPasswordSize,
                           USHORT usSymmetricKeySize, DWORD cbCertEncoded) noexcept
{
    if (cbCertEncoded > USHRT_MAX)
    {
        return 0;
    }
    size_t cbTotal = sizeof(EID_PRIVATE_DATA) + static_cast<size_t>(usEncryptedPasswordSize) +
                     static_cast<size_t>(cbCertEncoded);
    if (fEncryptPassword)
    {
        // Certificate-based encryption: cert + symmetric key + encrypted password
        cbTotal += static_cast<size_t>(usSymmetricKeySize);
    }
    // DPAPI encryption: cert + encrypted data (no symmetric key)
    if (cbTotal > USHRT_MAX)
    {
        return 0;
    }
    return static_cast<USHORT>(cbTotal);
}

// Build the secret data buffer with certificate and encrypted password data
// For certificate-based encryption: cert + symmetric key + encrypted password
// For DPAPI: cert + encrypted password only
// Complexity reduction helper for CreateCredential (Phase 36-01)
void BuildSecretData(PEID_PRIVATE_DATA pSecret, PCCERT_CONTEXT pCertContext,
                     PBYTE pEncryptedPassword, USHORT usEncryptedPasswordSize,  // NOSONAR - API-01: signature dictated by Windows/callback API
                     PBYTE pSymmetricKey, USHORT usSymmetricKeySize,  // NOSONAR - API-01: signature dictated by Windows/callback API
                     bool fEncryptPassword) noexcept
{
    // Copy certificate hash
    DWORD dwHashSize = CERT_HASH_LENGTH;
    CryptHashCertificate(NULL, CALG_SHA_256, 0, pCertContext->pbCertEncoded,
                         pCertContext->cbCertEncoded, pSecret->Hash, &dwHashSize);

    // Set common fields
    pSecret->dwType = fEncryptPassword ? EID_PRIVATE_DATA_TYPE::eidpdtCrypted :
                                          EID_PRIVATE_DATA_TYPE::eidpdtDPAPI;
    pSecret->dwCertificatSize = static_cast<USHORT>(pCertContext->cbCertEncoded);
    pSecret->usPasswordLen = usEncryptedPasswordSize;

    // Certificate always at offset 0
    pSecret->dwCertificatOffset = 0;
    memcpy(pSecret->Data + pSecret->dwCertificatOffset, pCertContext->pbCertEncoded,
           pSecret->dwCertificatSize);

    if (fEncryptPassword)
    {
        // Certificate-based: symmetric key then encrypted password
        pSecret->dwSymetricKeySize = usSymmetricKeySize;
        pSecret->dwSymetricKeyOffset = pSecret->dwCertificatOffset + pSecret->dwCertificatSize;
        memcpy(pSecret->Data + pSecret->dwSymetricKeyOffset, pSymmetricKey, pSecret->dwSymetricKeySize);

        pSecret->dwPasswordOffset = pSecret->dwSymetricKeyOffset + usSymmetricKeySize;
        memcpy(pSecret->Data + pSecret->dwPasswordOffset, pEncryptedPassword, pSecret->usPasswordLen);
    }
    else
    {
        // DPAPI: no symmetric key, password follows certificate
        pSecret->dwSymetricKeySize = 0;
        pSecret->dwSymetricKeyOffset = pSecret->dwCertificatOffset + pSecret->dwCertificatSize;
        pSecret->dwPasswordOffset = pSecret->dwSymetricKeyOffset;
        memcpy(pSecret->Data + pSecret->dwPasswordOffset, pEncryptedPassword, pSecret->usPasswordLen);
    }
}

// Helper to encrypt password using DPAPI
// Returns encrypted data and size via output parameters
// Complexity reduction helper for CreateCredential (Phase 36-01)
BOOL EncryptPasswordWithDPAPI(__in PWSTR szPassword, __in USHORT usPasswordSize,
                              __out PBYTE* ppEncryptedData, __out PUSHORT pusEncryptedSize)
{
    DATA_BLOB DataIn;
    DATA_BLOB DataOut;

    DataIn.pbData = reinterpret_cast<BYTE*>(szPassword);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
    DataIn.cbData = usPasswordSize;

    if (!CryptProtectData(&DataIn, L"EID Credential", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE, &DataOut))
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CryptProtectData failed 0x%08x", GetLastError());
        return FALSE;
    }

    // The encrypted size is stored as a USHORT; refuse rather than truncate.
    if (DataOut.cbData > USHRT_MAX)
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CryptProtectData output too large (%u bytes)", DataOut.cbData);
        SecureZeroMemory(DataOut.pbData, DataOut.cbData);
        LocalFree(DataOut.pbData);
        SetLastError(ERROR_ARITHMETIC_OVERFLOW);
        return FALSE;
    }

    *ppEncryptedData = static_cast<PBYTE>(EIDAlloc(DataOut.cbData));
    if (!*ppEncryptedData)
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"EIDAlloc failed 0x%08x", GetLastError());
        LocalFree(DataOut.pbData);
        return FALSE;
    }

    memcpy(*ppEncryptedData, DataOut.pbData, DataOut.cbData);
    *pusEncryptedSize = static_cast<USHORT>(DataOut.cbData);
    LocalFree(DataOut.pbData);
    return TRUE;
}

// CryptAcquireCertificatePrivateKey errors after which the PIV fallback (the
// provider's default container) may be tried: the container named in the
// certificate's CERT_KEY_PROV_INFO does not exist on the card, which is how a
// PIV card whose container name differs from the enrolment-time one fails.
// Any other error (no card, wrong reader, provider failure, ...) must be
// reported as is: falling back on it used to open whatever card the provider
// picked by default and hand it the PIN.
bool IsPivFallbackError(DWORD dwError) noexcept
{
    return dwError == static_cast<DWORD>(NTE_BAD_KEYSET)
        || dwError == static_cast<DWORD>(NTE_KEYSET_NOT_DEF)
        || dwError == static_cast<DWORD>(SCARD_E_NO_KEY_CONTAINER);
}

} // anonymous namespace


// Every write of the per-RID stored credentials (enrolment, re-seal, removal) holds this lock
// across its read-check-write sequence, so two writers cannot interleave: two enrolments
// cannot bind one certificate to two accounts, and a re-seal cannot resurrect a credential
// removed meanwhile. Recursive (a critical section), because UpdateCredential holds it while
// calling CreateCredential. The password filter routes its re-seal through the package
// (EIDResealStoredCredential), so both LSASS modules use this one lock.
static CRITICAL_SECTION s_csStoredCredentials;
static INIT_ONCE s_StoredCredentialsLockInit = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK InitStoredCredentialsLock(PINIT_ONCE, PVOID, PVOID*)
{
	InitializeCriticalSection(&s_csStoredCredentials);
	return TRUE;
}

static void LockStoredCredentials()
{
	InitOnceExecuteOnce(&s_StoredCredentialsLockInit, InitStoredCredentialsLock, nullptr, nullptr);
	EnterCriticalSection(&s_csStoredCredentials);
}

static void UnlockStoredCredentials()
{
	LeaveCriticalSection(&s_csStoredCredentials);
}

// The CAPI work done here with the package's own provider - random challenges, importing a
// public key or an AES key, hashing, signature checks, encryption - needs no persistent key
// container. A verify context creates none; the shared named container "EIDCredential" that
// every call used to create and delete raced between concurrent calls.
static BOOL AcquireEphemeralProvider(HCRYPTPROV* phProv)
{
	return CryptAcquireContext(phProv, nullptr, CREDENTIALPROVIDER, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
}

// Keys accepted at enrolment: RSA, 1024 to 4096 bits, public exponent 3 to 65537. A huge
// modulus or exponent made every later signature check (and the per-RID scan) expensive.
constexpr DWORD EID_MIN_RSA_KEY_BITS = 1024;
constexpr DWORD EID_MAX_RSA_KEY_BITS = 4096;
constexpr DWORD EID_MAX_RSA_PUBLIC_EXPONENT = 65537;

static BOOL IsAcceptableCredentialKey(PCCERT_CONTEXT pCertContext)
{
	if (!pCertContext || !pCertContext->pCertInfo)
	{
		return FALSE;
	}
	PCERT_PUBLIC_KEY_INFO pKeyInfo = &pCertContext->pCertInfo->SubjectPublicKeyInfo;
	if (!pKeyInfo->Algorithm.pszObjId || strcmp(pKeyInfo->Algorithm.pszObjId, szOID_RSA_RSA) != 0)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"certificate key is not RSA");
		return FALSE;
	}
	const DWORD dwBits = CertGetPublicKeyLength(X509_ASN_ENCODING, pKeyInfo);
	if (dwBits < EID_MIN_RSA_KEY_BITS || dwBits > EID_MAX_RSA_KEY_BITS)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RSA key of %u bits refused (%u-%u)", dwBits, EID_MIN_RSA_KEY_BITS, EID_MAX_RSA_KEY_BITS);
		return FALSE;
	}
	DWORD cbBlob = 0;
	if (!CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pKeyInfo->PublicKey.pbData, pKeyInfo->PublicKey.cbData, 0, nullptr, &cbBlob)
		|| cbBlob < sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY))
	{
		return FALSE;
	}
	PBYTE pbBlob = static_cast<PBYTE>(EIDAlloc(cbBlob));
	if (!pbBlob)
	{
		return FALSE;
	}
	BOOL fAcceptable = FALSE;
	if (CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pKeyInfo->PublicKey.pbData, pKeyInfo->PublicKey.cbData, 0, pbBlob, &cbBlob)
		&& cbBlob >= sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY))
	{
		const RSAPUBKEY* pRsa = reinterpret_cast<const RSAPUBKEY*>(pbBlob + sizeof(PUBLICKEYSTRUC));
		fAcceptable = pRsa->pubexp >= 3 && pRsa->pubexp <= EID_MAX_RSA_PUBLIC_EXPONENT;
		if (!fAcceptable)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RSA public exponent %u refused", pRsa->pubexp);
		}
	}
	EIDFree(pbBlob);
	return fAcceptable;
}

// Enrolment proof of possession. The enrolment request carries a signature, made with the
// card's key, over EIDBuildEnrolmentStatement(dwRid, time, certificate) (Package.cpp). Without
// it, anyone could bind a certificate they do not hold - certificates are public - to their own
// account before its owner enrols it, so the owner's card would then log on to the wrong
// account and the owner could not enrol. The time must be within EID_ENROLMENT_PROOF_SKEW_MS.
constexpr ULONGLONG EID_ENROLMENT_PROOF_SKEW_MS = 5ULL * 60ULL * 1000ULL;

BOOL EIDVerifyEnrolmentProof(__in DWORD dwRid, __in PCCERT_CONTEXT pCertContext, __in const FILETIME* pftTime,
	__in_bcount(cbSignature) const BYTE* pbSignature, __in DWORD cbSignature)
{
	BOOL fReturn = FALSE;
	DWORD dwError = NTE_BAD_SIGNATURE;
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	HCRYPTKEY hKey = NULL;  // Windows handle type - keep as NULL
	HCRYPTHASH hHash = NULL;  // Windows handle type - keep as NULL
	BYTE rgbStatement[EID_ENROLMENT_STATEMENT_SIZE];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	__try
	{
		if (!pCertContext || !pftTime || !pbSignature || cbSignature == 0 || cbSignature > EID_MAX_ENROLMENT_SIGNATURE_SIZE)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"enrolment proof absent or malformed");
			__leave;
		}
		FILETIME ftNow;
		GetSystemTimeAsFileTime(&ftNow);
		ULARGE_INTEGER uNow;
		ULARGE_INTEGER uProof;
		uNow.LowPart = ftNow.dwLowDateTime;
		uNow.HighPart = ftNow.dwHighDateTime;
		uProof.LowPart = pftTime->dwLowDateTime;
		uProof.HighPart = pftTime->dwHighDateTime;
		const ULONGLONG ullSkew100ns = EID_ENROLMENT_PROOF_SKEW_MS * 10000ULL;
		const ULONGLONG ullDiff = (uNow.QuadPart > uProof.QuadPart) ? uNow.QuadPart - uProof.QuadPart : uProof.QuadPart - uNow.QuadPart;
		if (ullDiff > ullSkew100ns)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"enrolment proof time is outside the allowed window");
			__leave;
		}
		if (!EIDBuildEnrolmentStatement(dwRid, pftTime, pCertContext, rgbStatement, sizeof(rgbStatement)))
		{
			dwError = GetLastError();
			__leave;
		}
		if (!AcquireEphemeralProvider(&hProv))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		if (!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, &(pCertContext->pCertInfo->SubjectPublicKeyInfo), &hKey))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportPublicKeyInfo 0x%08x",dwError);
			__leave;
		}
		if (!CryptCreateHash(hProv, CALG_SHA, NULL, 0, &hHash)
			|| !CryptHashData(hHash, rgbStatement, sizeof(rgbStatement), 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"hash 0x%08x",dwError);
			__leave;
		}
		if (!CryptVerifySignature(hHash, pbSignature, cbSignature, hKey, nullptr, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"enrolment proof signature does not verify 0x%08x",dwError);
			__leave;
		}
		dwError = 0;
		fReturn = TRUE;
	}
	__finally
	{
		if (hHash)
			CryptDestroyHash(hHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
			CryptReleaseContext(hProv, 0);
	}
	SetLastError(dwError);
	return fReturn;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GetUsernameFromCertContext(__in PCCERT_CONTEXT pContext, __out PWSTR *pszUsername, __out PDWORD pdwRid)
{
	NET_API_STATUS Status;
	PUSER_INFO_3 pUserInfo = nullptr;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	BOOL fReturn = FALSE;
	PEID_PRIVATE_DATA pPrivateData = nullptr;
	DWORD dwError = 0;
	DWORD dwMatches = 0;
	__try
	{
		if (!pContext)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ppContext null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		if (!pszUsername)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"pszUsername null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		if (!pdwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"pdwRid null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		*pdwRid = 0;
		Status = NetUserEnum(nullptr, 3,0, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, nullptr);
		if (Status != NERR_Success)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			dwError = Status;
			__leave;
		}
		for (DWORD dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			// for each credential
			DWORD dwPrivateDataSize = 0;
			if (RetrievePrivateData(pUserInfo[dwI].usri3_user_id, &pPrivateData, &dwPrivateDataSize))
			{
				if (pPrivateData->dwCertificatSize == pContext->cbCertEncoded &&
					memcmp(pPrivateData->Data + pPrivateData->dwCertificatOffset, pContext->pbCertEncoded, pContext->cbCertEncoded) == 0)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					// found
					dwMatches++;
					if (dwMatches > 1)
					{
						// One certificate bound to two accounts: refuse rather than pick one.
						EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"certificate is bound to more than one account - refusing");
						EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_CERT_ERROR] Certificate is bound to rids 0x%x and 0x%x; logon refused", *pdwRid, pUserInfo[dwI].usri3_user_id);
						EIDFreePrivateData(pPrivateData, dwPrivateDataSize);
						pPrivateData = nullptr;
						if (*pszUsername)
						{
							EIDFree(*pszUsername);
							*pszUsername = nullptr;
						}
						*pdwRid = 0;
						fReturn = FALSE;
						dwError = ERROR_DUP_NAME;
						__leave;
					}
					*pdwRid = pUserInfo[dwI].usri3_user_id;
					PCWSTR Username = pUserInfo[dwI].usri3_name;
					*pszUsername = (PWSTR) EIDAlloc((DWORD)(wcslen(Username) +1) * sizeof(WCHAR));

					if (*pszUsername)
					{
						wcscpy_s(*pszUsername, wcslen(Username) +1, Username);
						EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Found 0x%x %s",*pdwRid, *pszUsername);
						fReturn = TRUE;
					}
					else
					{
						dwError = GetLastError();
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
					}
				}
				else if (pPrivateData->dwCertificatSize == pContext->cbCertEncoded)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"%d don't match", pUserInfo[dwI].usri3_user_id);
				}
				EIDFreePrivateData(pPrivateData, dwPrivateDataSize);
				pPrivateData = nullptr;
				// No break: keep scanning so a certificate bound to two accounts is refused.
			}
		}
		if (!fReturn)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not found");
		}
	}
	__finally
	{
		if (pPrivateData)
		{
			EIDFreePrivateData(pPrivateData, 0);
			pPrivateData = nullptr;
		}
		if (pUserInfo)
			NetApiBufferFree(pUserInfo);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::HasStoredCredential(__in PCCERT_CONTEXT pContext)
{
	DWORD dwRid;
	PWSTR szUsername = nullptr;
	if (GetUsernameFromCertContext(pContext, &szUsername, &dwRid))  // NOSONAR - SCOPE-01: variable declared before the block by design
	{
		EIDFree(szUsername);
		return TRUE;
	}
	return FALSE;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GetCertContextFromHash(__in PBYTE pbHash, __out PCCERT_CONTEXT* ppContext, __out PDWORD pdwRid)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	NET_API_STATUS Status;
	PUSER_INFO_3 pUserInfo = nullptr;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	BOOL fReturn = FALSE;
	PEID_PRIVATE_DATA pPrivateData = nullptr;
	DWORD dwError = 0;
	__try
	{
		if (!ppContext)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ppContext null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		if (!pdwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"pdwRid null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		Status = NetUserEnum(nullptr, 3,0, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, nullptr);
		if (Status != NERR_Success)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			dwError = Status;
			__leave;
		}
		for (DWORD dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			// for each credential
			DWORD dwPrivateDataSize = 0;
			if (RetrievePrivateData(pUserInfo[dwI].usri3_user_id, &pPrivateData, &dwPrivateDataSize))
			{
				const BOOL fMatched = (memcmp(pPrivateData->Hash, pbHash, CERT_HASH_LENGTH) == 0);
				if (fMatched)
				{
					// found
					*pdwRid = pUserInfo[dwI].usri3_user_id;
					*ppContext = CertCreateCertificateContext(X509_ASN_ENCODING,
								pPrivateData->Data + pPrivateData->dwCertificatOffset, pPrivateData->dwCertificatSize);
					if (*ppContext)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
					{
						fReturn = TRUE;
					}
					else
					{
						dwError = GetLastError();
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
					}
				}
				// CertCreateCertificateContext copies the encoded certificate,
				// so scrubbing the blob here does not disturb *ppContext.
				EIDFreePrivateData(pPrivateData, dwPrivateDataSize);
				pPrivateData = nullptr;
				if (fMatched)
				{
					break;
				}
			}
		}
	}
	__finally
	{
		if (pUserInfo)
			NetApiBufferFree(pUserInfo);
	}
	SetLastError(dwError);
	return fReturn;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GetCertContextFromRid(__in DWORD dwRid, __out PCCERT_CONTEXT* ppContext, __out PBOOL pfEncryptPassword)
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	PEID_PRIVATE_DATA pEidPrivateData = nullptr;
	DWORD dwPrivateDataSize = 0;
	DWORD dwError = 0;
	__try
	{
		if (!ppContext)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ppContext null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		// Initialise the out parameter before anything else can fail, so the
		// cleanup below never releases a caller's uninitialised pointer.
		*ppContext = nullptr;
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		if (!pfEncryptPassword)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"fEncryptPassword null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData,&dwPrivateDataSize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		*ppContext = CertCreateCertificateContext(X509_ASN_ENCODING,
						pEidPrivateData->Data + pEidPrivateData->dwCertificatOffset,
						pEidPrivateData->dwCertificatSize);
		if (!*ppContext) 
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
			__leave;
		}
		*pfEncryptPassword = (pEidPrivateData->dwType == EID_PRIVATE_DATA_TYPE::eidpdtCrypted);
		fReturn = TRUE;
	}
	__finally
	{
		// ppContext is NULL when the parameter check above failed.
		if (!fReturn && ppContext && *ppContext)
		{
			CertFreeCertificateContext(*ppContext);
			*ppContext = nullptr;
		}
		EIDFreePrivateData(pEidPrivateData, dwPrivateDataSize);
		pEidPrivateData = nullptr;
	}
	SetLastError(dwError);
	return fReturn;
}

// Returns TRUE when the check completed, with *pfBoundElsewhere set when the
// certificate (same DER, or same SHA-256 hash as stored in the blob) is already
// held by the stored credential of an account other than dwRid. Enumerates
// stored credentials the same way GetUsernameFromCertContext does.
// When dwRid already holds exactly this certificate the binding already exists
// and the enumeration is skipped: that is the re-seal path (UpdateCredential,
// reached from PasswordChangeNotify and SpAcceptCredentials), which must not
// start issuing SAM enumerations.
// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::IsCertificateBoundToOtherRid(__in DWORD dwRid, __in PCCERT_CONTEXT pContext, __out PBOOL pfBoundElsewhere)
{
	NET_API_STATUS Status;
	PUSER_INFO_3 pUserInfo = nullptr;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	BOOL fReturn = FALSE;
	BOOL fMatched = FALSE;
	PEID_PRIVATE_DATA pPrivateData = nullptr;
	DWORD dwPrivateDataSize = 0;
	DWORD dwError = 0;
	BYTE bHash[CERT_HASH_LENGTH] = {0};  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwHashSize = sizeof(bHash);
	__try
	{
		if (!pContext || !pfBoundElsewhere)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"pContext or pfBoundElsewhere null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		*pfBoundElsewhere = FALSE;
		if (!CryptHashCertificate(NULL, CALG_SHA_256, 0, pContext->pbCertEncoded, pContext->cbCertEncoded, bHash, &dwHashSize)
			|| dwHashSize != CERT_HASH_LENGTH)
		{
			dwError = GetLastError();
			if (dwError == 0)
			{
				dwError = ERROR_INVALID_DATA;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptHashCertificate 0x%08x",dwError);
			__leave;
		}
		// Fast path: this account already holds exactly this certificate.
		if (dwRid && RetrievePrivateData(dwRid, &pPrivateData, &dwPrivateDataSize))
		{
			fMatched = (pPrivateData->dwCertificatSize == pContext->cbCertEncoded &&
				memcmp(pPrivateData->Data + pPrivateData->dwCertificatOffset, pContext->pbCertEncoded, pContext->cbCertEncoded) == 0);
			EIDFreePrivateData(pPrivateData, dwPrivateDataSize);
			pPrivateData = nullptr;
			if (fMatched)
			{
				fReturn = TRUE;
				__leave;
			}
		}
		Status = NetUserEnum(nullptr, 3,0, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, nullptr);
		if (Status != NERR_Success)
		{
			// Fail closed: without the enumeration the binding cannot be checked.
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			dwError = Status;
			__leave;
		}
		for (DWORD dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			if (pUserInfo[dwI].usri3_user_id == dwRid)
			{
				continue;
			}
			dwPrivateDataSize = 0;
			if (RetrievePrivateData(pUserInfo[dwI].usri3_user_id, &pPrivateData, &dwPrivateDataSize))
			{
				fMatched = (pPrivateData->dwCertificatSize == pContext->cbCertEncoded &&
					memcmp(pPrivateData->Data + pPrivateData->dwCertificatOffset, pContext->pbCertEncoded, pContext->cbCertEncoded) == 0)
					|| memcmp(pPrivateData->Hash, bHash, CERT_HASH_LENGTH) == 0;
				EIDFreePrivateData(pPrivateData, dwPrivateDataSize);
				pPrivateData = nullptr;
				if (fMatched)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"certificate already enrolled to rid 0x%x", pUserInfo[dwI].usri3_user_id);
					*pfBoundElsewhere = TRUE;
					break;
				}
			}
			else
			{
				// "No stored credential for this account" is the normal case
				// (STATUS_OBJECT_NAME_NOT_FOUND maps to ERROR_FILE_NOT_FOUND).
				// Anything else - access denied, a corrupt blob, out of memory -
				// means this account's binding could not be checked: fail closed
				// rather than risk binding one certificate to two accounts.
				const DWORD dwRetrieveError = GetLastError();
				if (dwRetrieveError != ERROR_FILE_NOT_FOUND)
				{
					dwError = (dwRetrieveError != 0) ? dwRetrieveError : ERROR_INTERNAL_ERROR;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x for rid 0x%x - cannot verify certificate binding, refusing",
						dwError, pUserInfo[dwI].usri3_user_id);
					__leave;
				}
			}
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pPrivateData)
		{
			EIDFreePrivateData(pPrivateData, dwPrivateDataSize);
			pPrivateData = nullptr;
		}
		if (pUserInfo)
			NetApiBufferFree(pUserInfo);
	}
	SetLastError(dwError);
	return fReturn;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
// Uses helper functions CalculateSecretSize, BuildSecretData, EncryptPasswordWithDPAPI
// to reduce cognitive complexity while maintaining SEH safety.
BOOL CStoredCredentialManager::CreateCredential(__in DWORD dwRid, __in PCCERT_CONTEXT pCertContext, __in PWSTR szPassword, __in_opt USHORT usPasswordLen, __in BOOL fEncryptPassword, __in BOOL fCheckPassword)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
	// Refactored for complexity reduction (Phase 36-01)
	// Uses helper functions CalculateSecretSize, BuildSecretData, EncryptPasswordWithDPAPI
	// to reduce cognitive complexity while maintaining SEH safety.

	// SECURITY (H3): when the RequireCardBoundCredentials policy is set, refuse to create a
	// non-card-wrapped (DPAPI) credential - its password would be recoverable without the card.
	if (!fEncryptPassword && GetPolicyValue(GPOPolicy::RequireCardBoundCredentials))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RequireCardBoundCredentials: refusing to create non-crypted credential");
		EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[POLICY_DENY] RequireCardBoundCredentials: refused to create a non-card-bound credential for rid 0x%x", dwRid);
		SetLastError(ERROR_ACCESS_DENIED);
		return FALSE;
	}

	BOOL fReturn = FALSE;
	BOOL fStatus;
	DWORD dwError = 0;
	NTSTATUS Status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	HCRYPTKEY hKey = NULL;  // NOSONAR - HANDLE-01: HCRYPTKEY is ULONG_PTR, not pointer type
	HCRYPTKEY hSymetricKey = NULL;  // NOSONAR - HANDLE-01: HCRYPTKEY is ULONG_PTR, not pointer type
	PBYTE pSymetricKey = nullptr;
	USHORT usSymetricKeySize = 0;
	PBYTE pEncryptedPassword = nullptr;
	USHORT usEncryptedPasswordSize = 0;
	PEID_PRIVATE_DATA pbSecret = nullptr;
	USHORT usSecretSize = 0;
	USHORT usPasswordSize;
	HCRYPTPROV hProv = NULL;  // NOSONAR - HANDLE-01: HCRYPTPROV is ULONG_PTR, not pointer type
	PBYTE pbPublicKey = nullptr;
	DWORD dwSize = 0;
	BOOL fBoundElsewhere = FALSE;
	BOOL fLocked = FALSE;

	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Enter fEncryptPassword = %d", fEncryptPassword);

		// Validate RID parameter
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"dwRid 0x%08x", dwError);
			__leave;
		}

		// Refuse an oversized certificate up front: the stored blob uses USHORT
		// offsets/sizes, and a smart card logon certificate is a few KB.
		if (!pCertContext || pCertContext->cbCertEncoded > EID_MAX_CERTIFICATE_SIZE)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"certificate missing or too large (max %u bytes)", EID_MAX_CERTIFICATE_SIZE);
			__leave;
		}

		// A new enrolment (fCheckPassword: the untrusted call) must use an acceptable key. A
		// re-seal keeps the key that was already enrolled.
		if (fCheckPassword && !IsAcceptableCredentialKey(pCertContext))
		{
			dwError = NTE_BAD_KEY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"certificate key refused for rid 0x%x", dwRid);
			__leave;
		}

		// Check password if requested
		if (fCheckPassword)
		{
			Status = CheckPassword(dwRid, szPassword);
			if (Status != STATUS_SUCCESS)
			{
				dwError = LsaNtStatusToWinError(Status);
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CheckPassword 0x%08x", dwError);
				__leave;
			}
		}

		// SECURITY: one certificate, one account. Logon maps a card to an account
		// with GetUsernameFromCertContext / GetCertContextFromHash, which return
		// the FIRST stored credential holding the certificate. A certificate is
		// public, so a standard user could otherwise enrol an administrator's
		// certificate on their own account and, if their account enumerates
		// first, have the administrator's card log on to it. Refuse to bind a
		// certificate that is already bound to a different account; re-enrolling
		// or re-sealing the same account is unaffected.
		// Hold the stored-credential lock from this check to the store below.
		LockStoredCredentials();
		fLocked = TRUE;
		if (!IsCertificateBoundToOtherRid(dwRid, pCertContext, &fBoundElsewhere))
		{
			dwError = GetLastError();
			if (dwError == 0)
			{
				dwError = ERROR_INTERNAL_ERROR;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"IsCertificateBoundToOtherRid 0x%08x", dwError);
			__leave;
		}
		if (fBoundElsewhere)
		{
			dwError = ERROR_ALREADY_EXISTS;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"certificate already enrolled to another account - refusing enrolment for rid 0x%x", dwRid);
			EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[ENROL_REJECT] Refused to enrol a certificate for rid 0x%x: it is already bound to another account", dwRid);
			__leave;
		}

		// Calculate password size
		if (usPasswordLen > 0 && szPassword == nullptr)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"password length without a buffer");
			__leave;
		}
		if (usPasswordLen > 0)
		{
			usPasswordSize = usPasswordLen;
		}
		else if (szPassword != nullptr)  // STRPTR-01: Validate pointer before wcslen
		{
			// Bounded scan: anything reaching the cap is too long to store anyway.
			const size_t cchPassword = wcsnlen(szPassword, USHRT_MAX / sizeof(WCHAR) + 1);
			if (cchPassword > USHRT_MAX / sizeof(WCHAR))
			{
				dwError = ERROR_INVALID_PARAMETER;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"password too long");
				__leave;
			}
			usPasswordSize = static_cast<USHORT>(cchPassword * sizeof(WCHAR));
		}
		else
		{
			usPasswordSize = 0;
		}
		// A blank password cannot be sealed (enrolment already refuses it).
		// It used to reach EncryptPasswordAndSaveIt with a NULL buffer and
		// wcslen(NULL) there crashed LSASS - reachable by any user with an
		// enrolment who sets a blank password (SpAcceptCredentials /
		// PasswordChangeNotify -> UpdateCredential). Refuse instead; the stored
		// credential keeps the previous password until a non-blank one is set.
		if (usPasswordSize == 0)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"blank password refused");
			__leave;
		}

		// Use certificate-based encryption for all passwords (including empty)
		// This enables migration of credentials between machines - empty passwords
		// would otherwise use DPAPI which is machine-bound and non-portable.
		// if (!usPasswordSize) fEncryptPassword = FALSE;  // REMOVED: Force certificate encryption for migratability

		const bool fCrypted = (fEncryptPassword != FALSE);
		if (fCrypted)
		{
			// ========== Certificate-based encryption path ==========
			// Setup: decode public key, acquire crypto context, import key
			fStatus = CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
				pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
				pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
				0, nullptr, &dwSize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CryptDecodeObject 0x%08x", dwError);
				__leave;
			}

			pbPublicKey = static_cast<PBYTE>(EIDAlloc(dwSize));
			if (!pbPublicKey)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"EIDAlloc 0x%08x", dwError);
				__leave;
			}

			fStatus = CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
				pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
				pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
				0, pbPublicKey, &dwSize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CryptDecodeObject 0x%08x", dwError);
				__leave;
			}

			// Import the public key into hKey
			fStatus = AcquireEphemeralProvider(&hProv);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
				__leave;
			}

			fStatus = CryptImportKey(hProv, pbPublicKey, dwSize, NULL, 0, &hKey);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CryptImportKey 0x%08x", dwError);
				__leave;
			}

			// Create symmetric key and encrypt it with the public key
			fStatus = GenerateSymetricKeyAndEncryptIt(hProv, hKey, &hSymetricKey, &pSymetricKey, &usSymetricKeySize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GenerateSymetricKeyAndEncryptIt");
				__leave;
			}

			// Encrypt the password with the symmetric key
			fStatus = EncryptPasswordAndSaveIt(hSymetricKey, szPassword, usPasswordLen, &pEncryptedPassword, &usEncryptedPasswordSize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"EncryptPasswordAndSaveIt");
				__leave;
			}
		}
		else
		{
			// ========== DPAPI encryption path ==========
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Using DPAPI encryption for credential storage");

			// Encrypt password using DPAPI helper
			if (!EncryptPasswordWithDPAPI(szPassword, usPasswordSize, &pEncryptedPassword, &usEncryptedPasswordSize))
			{
				dwError = GetLastError();
				__leave;
			}
		}

		// Size, allocate and fill the secret (shared by both paths)
		usSecretSize = CalculateSecretSize(fCrypted, usEncryptedPasswordSize, fCrypted ? usSymetricKeySize : 0, static_cast<ULONG>(pCertContext->cbCertEncoded));
		if (!usSecretSize)
		{
			dwError = ERROR_ARITHMETIC_OVERFLOW;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"secret size overflow (cert %u bytes)", pCertContext->cbCertEncoded);
			__leave;
		}
		pbSecret = static_cast<PEID_PRIVATE_DATA>(EIDAlloc(usSecretSize));
		if (!pbSecret)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"EIDAlloc 0x%08x", dwError);
			__leave;
		}

		// Build secret data using helper
		BuildSecretData(pbSecret, pCertContext, pEncryptedPassword, usEncryptedPasswordSize,
		                fCrypted ? pSymetricKey : nullptr, fCrypted ? usSymetricKeySize : 0, fCrypted);

		// Save the encrypted credential data
		if (!StorePrivateData(dwRid, reinterpret_cast<PBYTE>(pbSecret), usSecretSize))  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"StorePrivateData");
			__leave;
		}

		fReturn = TRUE;
	}
	__finally
	{
		// Clean up all allocated resources
		if (pbPublicKey)
			EIDFree(pbPublicKey);
		if (pSymetricKey)
		{
			SecureZeroMemory(pSymetricKey, usSymetricKeySize);
			EIDFree(pSymetricKey);
		}
		if (pEncryptedPassword)
		{
			SecureZeroMemory(pEncryptedPassword, usEncryptedPasswordSize);
			EIDFree(pEncryptedPassword);
		}
		if (pbSecret)
		{
			SecureZeroMemory(pbSecret, usSecretSize);
			EIDFree(pbSecret);
		}
		if (hSymetricKey)
			CryptDestroyKey(hSymetricKey);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
		}
		if (fLocked)
		{
			UnlockStoredCredentials();
		}
	}

	SetLastError(dwError);
	return fReturn;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::UpdateCredential(__in PLUID pLuid, __in PUNICODE_STRING Password)
{
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData = nullptr;
	LSA_HANDLE hPolicy = nullptr;
	PPOLICY_ACCOUNT_DOMAIN_INFO pDomainInfo = nullptr;
	NTSTATUS status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	__try
	{
		if (!pLuid || !Password)
		{
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		status = LsaGetLogonSessionData(pLuid, &pLogonSessionData);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaGetLogonSessionData 0x%08x",status);
			__leave;
		}
		// Map the session to a RID by its SID, not its user name: only a SID in this machine's
		// account domain (domain SID + one RID) is a local account this package can hold.
		PSID pUserSid = pLogonSessionData->Sid;
		if (!pUserSid || !IsValidSid(pUserSid))
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"logon session has no SID");
			__leave;
		}
		LSA_OBJECT_ATTRIBUTES ObjectAttributes;
		memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
		status = LsaOpenPolicy(nullptr, &ObjectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaOpenPolicy 0x%08x",status);
			__leave;
		}
		status = LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, reinterpret_cast<PVOID*>(&pDomainInfo));
		if (status != STATUS_SUCCESS || !pDomainInfo || !pDomainInfo->DomainSid)
		{
			dwError = (status != STATUS_SUCCESS) ? LsaNtStatusToWinError(status) : ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaQueryInformationPolicy 0x%08x",status);
			__leave;
		}
		const UCHAR cDomain = *GetSidSubAuthorityCount(pDomainInfo->DomainSid);
		if (*GetSidSubAuthorityCount(pUserSid) != cDomain + 1
			|| memcmp(GetSidIdentifierAuthority(pUserSid), GetSidIdentifierAuthority(pDomainInfo->DomainSid), sizeof(SID_IDENTIFIER_AUTHORITY)) != 0)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"not a local account");
			__leave;
		}
		for (UCHAR i = 0; i < cDomain; i++)
		{
			if (*GetSidSubAuthority(pUserSid, i) != *GetSidSubAuthority(pDomainInfo->DomainSid, i))
			{
				dwError = ERROR_NONE_MAPPED;
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"not a local account");
				__leave;
			}
		}
		const DWORD dwRid = *GetSidSubAuthority(pUserSid, cDomain);
		if (Password->Length == 0 || !Password->Buffer)
		{
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		if (!UpdateCredential(dwRid, Password->Buffer, Password->Length))
		{
			dwError = GetLastError();
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pDomainInfo) LsaFreeMemory(pDomainInfo);
		if (hPolicy) LsaClose(hPolicy);
		if (pLogonSessionData) LsaFreeReturnBuffer(pLogonSessionData);
	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CStoredCredentialManager::UpdateCredential(__in DWORD dwRid, __in PWSTR szPassword, __in_opt USHORT usPasswordLen)
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	DWORD dwError = 0;
	PCCERT_CONTEXT pCertContext = nullptr;
	BOOL fEncrypt;
	BOOL fLocked = FALSE;
	__try
	{
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		// Read the stored certificate and re-seal under one lock: a credential removed after
		// the read must not be written back.
		LockStoredCredentials();
		fLocked = TRUE;
		fStatus = GetCertContextFromRid(dwRid, &pCertContext, &fEncrypt);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetCertContextFromRid 0x%08x",dwError);
			__leave;
		}
		fStatus = CreateCredential(dwRid, pCertContext, szPassword, usPasswordLen, fEncrypt, FALSE);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateCredential 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		// SECURITY FIX: Free certificate context to prevent memory leak (CWE-401 fix for #26)
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
		if (fLocked)
		{
			UnlockStoredCredentials();
		}
	}
	SetLastError(dwError);
	return fReturn;
}
// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GetChallenge(__in DWORD dwRid, __out PBYTE* ppChallenge, __out PDWORD pdwChallengeSize, __out PDWORD pType)
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	DWORD dwError = 0;
	PEID_PRIVATE_DATA pEidPrivateData = nullptr;
	DWORD dwPrivateDataSize = 0;   // allocation size, for the cleanup zeroize
	__try
	{
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		if (!ppChallenge)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ppChallenge null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData,&dwPrivateDataSize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		*pType = static_cast<DWORD>(pEidPrivateData->dwType);  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
		// SECURITY (H3): when policy requires card-bound credentials, refuse any non-crypted type.
		if (*pType != static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtCrypted) && GetPolicyValue(GPOPolicy::RequireCardBoundCredentials))
		{
			dwError = ERROR_ACCESS_DENIED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RequireCardBoundCredentials: refusing non-crypted credential type %d",*pType);
			EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[POLICY_DENY] RequireCardBoundCredentials: refused logon challenge for non-card-bound credential (type %d, rid 0x%x)", *pType, dwRid);
			__leave;
		}
		switch(*pType)
		{
		case static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtCrypted):  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"dwType = eidpdtCrypted");
			*pdwChallengeSize = pEidPrivateData->dwSymetricKeySize;
			*ppChallenge = (PBYTE) EIDAlloc(pEidPrivateData->dwSymetricKeySize);
			if (*ppChallenge == nullptr)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
				__leave;
			}
			memcpy(*ppChallenge, pEidPrivateData->Data + pEidPrivateData->dwSymetricKeyOffset, pEidPrivateData->dwSymetricKeySize); 
			break;
		case static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtClearText):  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"dwType = eidpdtClearText");
			fStatus = GetSignatureChallenge(ppChallenge, pdwChallengeSize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetSignatureChallenge 0x%08x",dwError);
				__leave;
			}
			break;
		case static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtDPAPI):  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"dwType = eidpdtDPAPI");
			fStatus = GetSignatureChallenge(ppChallenge, pdwChallengeSize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetSignatureChallenge 0x%08x",dwError);
				__leave;
			}
			break;
		default:
			dwError = ERROR_INVALID_DATA;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwType not implemented");
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pEidPrivateData)
		{
			// Holds the wrapped symmetric key; scrub before releasing, as the
			// other blob consumers do.
			EIDFreePrivateData(pEidPrivateData, dwPrivateDataSize);
			pEidPrivateData = nullptr;
		}
	}
	SetLastError(dwError);
	return fReturn;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GetSignatureChallenge(__out PBYTE* ppChallenge, __out PDWORD pdwChallengeSize)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	DWORD dwError = 0;
	__try
	{
		fStatus = AcquireEphemeralProvider(&hProv);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		*pdwChallengeSize = CREDENTIALKEYLENGTH;
		*ppChallenge = (PBYTE) EIDAlloc(CREDENTIALKEYLENGTH);
		if (*ppChallenge == nullptr)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
			__leave;
		}
		fStatus = CryptGenRandom(hProv, CREDENTIALKEYLENGTH, *ppChallenge);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGenRandom 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		// Never hand back a buffer that was not filled.
		if (!fReturn && ppChallenge && *ppChallenge)
		{
			SecureZeroMemory(*ppChallenge, CREDENTIALKEYLENGTH);
			EIDFree(*ppChallenge);
			*ppChallenge = nullptr;
		}
		if (!fReturn && pdwChallengeSize)
		{
			*pdwChallengeSize = 0;
		}

		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
		}
	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CStoredCredentialManager::RemoveStoredCredential(__in DWORD dwRid)
{
	LockStoredCredentials();
	const BOOL fReturn = StorePrivateData(dwRid, nullptr, 0);
	const DWORD dwError = GetLastError();
	UnlockStoredCredentials();
	SetLastError(dwError);
	return fReturn;
}
// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::RemoveAllStoredCredential()
{
	NET_API_STATUS Status;
	PUSER_INFO_3 pUserInfo = nullptr;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	BOOL fReturn = FALSE;
	__try
	{
		Status = NetUserEnum(nullptr, 3,0, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, nullptr);
		if (Status != NERR_Success)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			SetLastError(Status);
			__leave;
		}
		for (DWORD dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			RemoveStoredCredential(pUserInfo[dwI].usri3_user_id);
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pUserInfo)
			NetApiBufferFree(pUserInfo);
	}
	return fReturn;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GetPassword(__in DWORD dwRid, __in PCCERT_CONTEXT pContext, __in PWSTR szPin, __out PWSTR *pszPassword)
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	PBYTE pChallenge = nullptr;
	PBYTE pResponse = nullptr;
	DWORD dwResponseSize = 0;
	DWORD dwChallengeSize = 0;
	PBYTE pProofChallenge = nullptr;
	DWORD dwProofChallengeSize = 0;
	PBYTE pProofResponse = nullptr;
	DWORD dwProofResponseSize = 0;
	DWORD dwError = 0;
	DWORD type;
	__try
	{
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"GetChallenge");
		fStatus = GetChallenge(dwRid, &pChallenge, &dwChallengeSize, &type);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetChallenge 0x%08x",dwError);
			__leave;
		}
		// SECURITY (F1): for a crypted credential the card's only job used to be
		// unwrapping the stored AES key, and whatever bytes came back were imported
		// as that key. Nothing authenticates the result - the sole failure signal is
		// the CBC padding check, which random bytes pass about once in 256 tries -
		// so a programmable card presenting the victim's (public) certificate and
		// answering the decrypt with garbage logged on as the victim. Before any
		// password is recovered, make the card prove possession of the private key:
		// sign a fresh random nonce and verify it against the public key of the
		// certificate stored with the credential, exactly as the clear-text and
		// DPAPI types already do. GetResponseFromSignatureChallenge signs with the
		// key spec from the certificate's CERT_KEY_PROV_INFO, i.e. the same key
		// that performs the decrypt below.
		if (type == static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtCrypted))  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"GetSignatureChallenge (proof of possession)");
			fStatus = GetSignatureChallenge(&pProofChallenge, &dwProofChallengeSize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetSignatureChallenge 0x%08x",dwError);
				__leave;
			}
			EIDImpersonate();
			fStatus = GetResponseFromSignatureChallenge(pProofChallenge, dwProofChallengeSize, pContext, szPin, &pProofResponse, &dwProofResponseSize);
			EIDRevertToSelf();
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetResponseFromSignatureChallenge 0x%08x",dwError);
				__leave;
			}
			fStatus = VerifySignatureChallengeResponse(dwRid, pProofChallenge, dwProofChallengeSize, pProofResponse, dwProofResponseSize);
			if (!fStatus)
			{
				// VerifySignatureChallengeResponse does not preserve its error code
				// (its cleanup deletes the temporary key container), so report a
				// fixed one.
				dwError = (DWORD) NTE_BAD_SIGNATURE;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"VerifySignatureChallengeResponse failed - card does not hold the private key");
				EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[CARD_REJECT] Proof-of-possession signature did not verify for rid 0x%x - possible malicious card", dwRid);
				__leave;
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"GetResponseFromChallenge");
		EIDImpersonate();
		fStatus = GetResponseFromChallenge(pChallenge, dwChallengeSize, type, pContext, szPin, &pResponse, &dwResponseSize);
		EIDRevertToSelf();
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetResponseFromChallenge 0x%08x",dwError);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"GetPasswordFromChallengeResponse");
		fStatus = GetPasswordFromChallengeResponse(dwRid, pChallenge, dwChallengeSize, type, pResponse, dwResponseSize, pszPassword);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetPasswordFromChallengeResponse 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pChallenge)
		{
			SecureZeroMemory(pChallenge, dwChallengeSize);
			EIDFree(pChallenge);
		}
		if (pResponse)
		{
			SecureZeroMemory(pResponse, dwResponseSize);
			EIDFree(pResponse);
		}
		if (pProofChallenge)
		{
			SecureZeroMemory(pProofChallenge, dwProofChallengeSize);
			EIDFree(pProofChallenge);
		}
		if (pProofResponse)
		{
			SecureZeroMemory(pProofResponse, dwProofResponseSize);
			EIDFree(pProofResponse);
		}
	}
	SetLastError(dwError);
	return fReturn;
}
// level 2
////////////////////////////////////////////////////////////////////////////////
// LEVEL 1
////////////////////////////////////////////////////////////////////////////////

// Copies a counted string into a new LSA-heap buffer. Sets Length/MaximumLength only once the
// buffer exists, so a failed allocation never leaves a length with a NULL buffer.
static BOOL CopyLsaString(__out PLSA_UNICODE_STRING Destination, __in PCWSTR Source, __in USHORT Length, __in USHORT MaximumLength)
{
	Destination->Length = 0;
	Destination->MaximumLength = 0;
	Destination->Buffer = nullptr;
	if (MaximumLength == 0)
	{
		return TRUE;
	}
	PWSTR Buffer = (PWSTR) EIDAlloc(MaximumLength);
	if (!Buffer)
	{
		return FALSE;
	}
	memset(Buffer, 0, MaximumLength);
	if (Source && Length)
	{
		memcpy(Buffer, Source, Length);
	}
	Destination->Buffer = Buffer;
	Destination->Length = Length;
	Destination->MaximumLength = MaximumLength;
	return TRUE;
}

static void FreeLsaString(__inout PLSA_UNICODE_STRING String, BOOL fSecret)
{
	if (String->Buffer)
	{
		if (fSecret)
		{
			SecureZeroMemory(String->Buffer, String->MaximumLength);
		}
		EIDFree(String->Buffer);
	}
	String->Buffer = nullptr;
	String->Length = 0;
	String->MaximumLength = 0;
}

NTSTATUS CompletePrimaryCredential(__in PLSA_UNICODE_STRING AuthenticatingAuthority,  // NOSONAR - API-01: signature dictated by Windows/callback API
						__in PLSA_UNICODE_STRING AccountName,  // NOSONAR - API-01: signature dictated by Windows/callback API
						__in PSID UserSid,
						__in PLUID LogonId,  // NOSONAR - API-01: signature dictated by Windows/callback API
						__in PWSTR szPassword,  // NOSONAR - API-01: signature dictated by Windows/callback API
						__out  PSECPKG_PRIMARY_CRED PrimaryCredentials)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	memset(PrimaryCredentials, 0, sizeof(SECPKG_PRIMARY_CRED));
	if (!AuthenticatingAuthority || !AccountName || !UserSid || !LogonId || !szPassword)
	{
		return STATUS_INVALID_PARAMETER;
	}
	const size_t cchPassword = wcsnlen(szPassword, (USHRT_MAX / sizeof(WCHAR)) + 1);
	if (cchPassword > USHRT_MAX / sizeof(WCHAR))
	{
		return STATUS_INVALID_PARAMETER;
	}
	PrimaryCredentials->LogonId.HighPart = LogonId->HighPart;
	PrimaryCredentials->LogonId.LowPart = LogonId->LowPart;
	// the flag PRIMARY_CRED_INTERACTIVE_SMARTCARD_LOGON is used for the "force smart card policy"
	// the flag PRIMARY_CRED_CLEAR_PASSWORD is used to tell the password to DPAPI
	PrimaryCredentials->Flags = PRIMARY_CRED_CLEAR_PASSWORD | PRIMARY_CRED_INTERACTIVE_SMARTCARD_LOGON;
	// OldPassword, DnsDomainName and Upn stay empty: the password cannot be changed here.

	const USHORT cbPassword = static_cast<USHORT>(cchPassword * sizeof(WCHAR));
	const DWORD cbSid = GetLengthSid(UserSid);
	BOOL fOk = CopyLsaString(&PrimaryCredentials->DownlevelName, AccountName->Buffer, AccountName->Length, AccountName->MaximumLength)
		&& CopyLsaString(&PrimaryCredentials->DomainName, AuthenticatingAuthority->Buffer, AuthenticatingAuthority->Length, AuthenticatingAuthority->MaximumLength)
		&& CopyLsaString(&PrimaryCredentials->Password, szPassword, cbPassword, cbPassword)
		&& CopyLsaString(&PrimaryCredentials->LogonServer, AuthenticatingAuthority->Buffer, AuthenticatingAuthority->Length, AuthenticatingAuthority->MaximumLength);
	if (fOk)
	{
		PrimaryCredentials->UserSid = (PSID)EIDAlloc(cbSid);
		fOk = PrimaryCredentials->UserSid && CopySid(cbSid, PrimaryCredentials->UserSid, UserSid);
	}
	if (!fOk)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"out of memory building the primary credential");
		FreeLsaString(&PrimaryCredentials->DownlevelName, FALSE);
		FreeLsaString(&PrimaryCredentials->DomainName, FALSE);
		FreeLsaString(&PrimaryCredentials->Password, TRUE);
		FreeLsaString(&PrimaryCredentials->LogonServer, FALSE);
		if (PrimaryCredentials->UserSid)
		{
			EIDFree(PrimaryCredentials->UserSid);
			PrimaryCredentials->UserSid = nullptr;
		}
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return STATUS_SUCCESS;
}

BOOL CStoredCredentialManager::GetResponseFromChallenge(__in PBYTE pChallenge, __in DWORD dwChallengeSize,__in DWORD dwChallengeType, __in PCCERT_CONTEXT pCertContext, __in PWSTR Pin, __out PBYTE *pSymetricKey, __out DWORD *usSize)
{
	switch(dwChallengeType)
	{
	case static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtClearText):  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
		return GetResponseFromSignatureChallenge(pChallenge,dwChallengeSize,pCertContext,Pin,pSymetricKey,usSize);
	case static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtCrypted):  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
		return GetResponseFromCryptedChallenge(pChallenge,dwChallengeSize,pCertContext,Pin,pSymetricKey,usSize);
	case static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtDPAPI):  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
		// GetChallenge issues a signature challenge for DPAPI credentials and
		// GetPasswordFromDPAPIChallengeResponse verifies a signature, so the card
		// answers exactly as for the clear-text type. This case was missing, so
		// every DPAPI-credential logon failed here without an error code.
		return GetResponseFromSignatureChallenge(pChallenge,dwChallengeSize,pCertContext,Pin,pSymetricKey,usSize);
	default:
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Type not implemented");
		SetLastError(ERROR_INVALID_DATA);
		return FALSE;
	}
}
// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
// The Base CSP keeps the PIN set with CryptSetProvParam in a per-process cache (encrypted in
// memory). In LSASS that process serves every user, so drop it once the card operation that
// needed it is over. Clearing it by setting a NULL PIN is not documented for CryptSetProvParam,
// so this is limited to the Microsoft Base Smart Card CSP and its result is ignored.
static void PurgeBaseCspPinCache(HCRYPTPROV hProv, PCRYPT_KEY_PROV_INFO pProvInfo, DWORD dwKeySpec)
{
	if (!hProv || !pProvInfo || !pProvInfo->pwszProvName || _wcsicmp(pProvInfo->pwszProvName, MS_SCARD_PROV_W) != 0)
	{
		return;
	}
	CryptSetProvParam(hProv, (dwKeySpec == AT_KEYEXCHANGE ? PP_KEYEXCHANGE_PIN : PP_SIGNATURE_PIN), nullptr, 0);
}

BOOL CStoredCredentialManager::GetResponseFromCryptedChallenge(__in PBYTE pChallenge, __in DWORD dwChallengeSize, __in PCCERT_CONTEXT pCertContext, __in PWSTR Pin, __out PBYTE *pSymetricKey, __out DWORD *usSize)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
	BOOL fReturn = FALSE;
	// check private key
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	DWORD dwKeySpec;
	BOOL fCallerFreeProv = FALSE;
	LPSTR pbPin = nullptr;
	DWORD dwPinLen = 0;
	int cbPin = 0;
	HCRYPTKEY hKey = NULL;  // Windows handle type - keep as NULL
	DWORD dwSize;
	DWORD dwBlockLen = 20000;
	DWORD dwError = 0;
	PCRYPT_KEY_PROV_INFO pProvInfo = nullptr;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	__try
	{
		if (!pSymetricKey)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pSymetricKey NULL");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		*pSymetricKey = nullptr;
		// acquire context on private key
		dwSize = 0;
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		pProvInfo = (PCRYPT_KEY_PROV_INFO) EIDAlloc(dwSize);
		if (!pProvInfo)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pProvInfo null");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pProvInfo, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		dwKeySpec = pProvInfo->dwKeySpec;
		// Security: Validate CSP provider before loading
		if (!IsAllowedCSPProvider(pProvInfo->pwszProvName))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"CSP provider '%s' not allowed", pProvInfo->pwszProvName);
			dwError = ERROR_ACCESS_DENIED;
			__leave;
		}
		if (!CryptAcquireCertificatePrivateKey(pCertContext,CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,nullptr,&hProv,&dwKeySpec,&fCallerFreeProv))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptAcquireCertificatePrivateKey", dwError);
			// Only a missing key container may fall back to the provider's
			// default container; any other failure is reported unchanged.
			if (!IsPivFallbackError(dwError))
			{
				__leave;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"PIV fallback");
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Keyspec %S container %s provider %s", (pProvInfo->dwKeySpec == AT_SIGNATURE ?"AT_SIGNATURE":"AT_KEYEXCHANGE"),
					pProvInfo->pwszContainerName, pProvInfo->pwszProvName);
			dwKeySpec = pProvInfo->dwKeySpec;
			hProv = NULL;
			if (!CryptAcquireContext(&hProv, nullptr, pProvInfo->pwszProvName, pProvInfo->dwProvType, CRYPT_SILENT))
			{
				// Keep the original CryptAcquireCertificatePrivateKey error.
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptAcquireContext (PIV fallback)", GetLastError());
				hProv = NULL;
				__leave;
			}
			// This handle is ours, not cached on the certificate context:
			// without this it leaked from LSASS on every logon down this path.
			fCallerFreeProv = TRUE;
			dwError = 0;
		}

		if (!CryptGetUserKey(hProv, dwKeySpec, &hKey))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptGetUserKey", GetLastError());
			__leave;
		}
		// Size the UTF-8 PIN from the conversion itself: a non-ASCII character
		// takes up to three bytes, so wcslen(Pin)+1 was too small for it.
		cbPin = WideCharToMultiByte(CP_UTF8, 0, Pin, -1, nullptr, 0, nullptr, nullptr);
		if (cbPin <= 0)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by WideCharToMultiByte", dwError);
			__leave;
		}
		dwPinLen = static_cast<DWORD>(cbPin);
		pbPin = (LPSTR) EIDAlloc(dwPinLen);
		if (!pbPin)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
			__leave;
		}
		if (!WideCharToMultiByte(CP_UTF8, 0, Pin, -1, pbPin, cbPin, nullptr, nullptr))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by WideCharToMultiByte", GetLastError());
			__leave;
		}
		if (!CryptSetProvParam(hProv, (dwKeySpec == AT_KEYEXCHANGE?PP_KEYEXCHANGE_PIN:PP_SIGNATURE_PIN), (PBYTE) pbPin , 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptSetProvParam - correct PIN ?", GetLastError());
			__leave;
		}
		dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			dwBlockLen = 20000; 
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptGetKeyParam - using %d as KP_BLOCKLEN", GetLastError(), dwBlockLen);
			dwError = 0;
		}
		// H2: the challenge is the stored symmetric key, whose size is a USHORT read from the
		// LSA secret (up to 65535) while this buffer is only one cipher block. Copying it
		// unchecked corrupts the LSASS heap, so refuse anything that does not fit.
		if (dwChallengeSize > dwBlockLen)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Challenge size %d exceeds key block length %d", dwChallengeSize, dwBlockLen);
			EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[BOUNDS_REJECT] challenge size %d exceeds key block length %d", dwChallengeSize, dwBlockLen);
			__leave;
		}
		*pSymetricKey = (PBYTE) EIDAlloc(dwBlockLen);
		if (!*pSymetricKey)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
			__leave;
		}
		memcpy(*pSymetricKey, pChallenge, dwChallengeSize);
		dwSize = dwChallengeSize;
		if (!CryptDecrypt(hKey, NULL, TRUE, 0, *pSymetricKey, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptDecrypt", GetLastError());
			__leave;
		}
		*usSize = (USHORT) dwSize;

		
		fReturn = TRUE;
	}
	__finally
	{
		// pSymetricKey is NULL when the parameter check above failed.
		if (!fReturn && pSymetricKey && *pSymetricKey)
		{
			EIDFree(*pSymetricKey );
			*pSymetricKey = nullptr;
		}
		if (pbPin)
		{
			PurgeBaseCspPinCache(hProv, pProvInfo, dwKeySpec);
			SecureZeroMemory(pbPin , dwPinLen);
			EIDFree(pbPin);
		}
		if (hKey)
			CryptDestroyKey(hKey);
		if (fCallerFreeProv && hProv) 
			CryptReleaseContext(hProv,0);
		if (pProvInfo) 
			EIDFree(pProvInfo);
	}
	SetLastError(dwError);
	return fReturn;
}


// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GetResponseFromSignatureChallenge(__in PBYTE pbChallenge, __in DWORD dwChallengeSize, __in PCCERT_CONTEXT pCertContext, __in PWSTR szPin, __out PBYTE *ppResponse, __out PDWORD pdwResponseSize)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	UNREFERENCED_PARAMETER(dwChallengeSize);
	BOOL fReturn = FALSE;
	LPSTR pbPin = nullptr;
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	DWORD dwKeySpec;
	BOOL fCallerFreeProv = FALSE;
	HCRYPTHASH hHash = NULL;  // Windows handle type - keep as NULL
	DWORD dwPinLen = 0;
	int cbPin = 0;
	DWORD dwError = 0;
	LPCWSTR sDescription = L"";
	PCRYPT_KEY_PROV_INFO pKeyProvInfo = nullptr;
	__try
	{
		DWORD dwSize = 0;
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		pKeyProvInfo = (PCRYPT_KEY_PROV_INFO) EIDAlloc(dwSize);
		if (!pKeyProvInfo)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, (PBYTE) pKeyProvInfo, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		*pdwResponseSize = 0;
		dwKeySpec = pKeyProvInfo->dwKeySpec;
		// Security: validate the CSP provider before loading it, exactly as
		// GetResponseFromCryptedChallenge does (it used to be checked only on
		// the fallback below).
		if (!IsAllowedCSPProvider(pKeyProvInfo->pwszProvName))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"CSP provider '%s' not allowed", pKeyProvInfo->pwszProvName);
			dwError = ERROR_ACCESS_DENIED;
			__leave;
		}
		if (!CryptAcquireCertificatePrivateKey(pCertContext,CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,nullptr,&hProv,&dwKeySpec,&fCallerFreeProv))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptAcquireCertificatePrivateKey", dwError);
			// Same fallback as GetResponseFromCryptedChallenge, so that a card whose
			// encrypted credential can be unwrapped there can also answer the
			// proof-of-possession signature that GetPassword now requires for it.
			// Whatever key signs here is still checked against the stored
			// certificate's public key by the verifier. Only a missing key
			// container may fall back; any other failure is reported unchanged
			// rather than sending the PIN to the provider's default card.
			if (!IsPivFallbackError(dwError))
			{
				__leave;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"PIV fallback");
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Keyspec %S container %s provider %s", (pKeyProvInfo->dwKeySpec == AT_SIGNATURE ?"AT_SIGNATURE":"AT_KEYEXCHANGE"),
					pKeyProvInfo->pwszContainerName, pKeyProvInfo->pwszProvName);
			dwKeySpec = pKeyProvInfo->dwKeySpec;
			hProv = NULL;
			if (!CryptAcquireContext(&hProv, nullptr, pKeyProvInfo->pwszProvName, pKeyProvInfo->dwProvType, CRYPT_SILENT))
			{
				// Keep the original CryptAcquireCertificatePrivateKey error.
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptAcquireContext (PIV fallback)", GetLastError());
				hProv = NULL;
				__leave;
			}
			fCallerFreeProv = TRUE;
			dwError = 0;
		}
		// Size the UTF-8 PIN from the conversion itself: a non-ASCII character
		// takes up to three bytes, so wcslen(szPin)+1 was too small for it.
		cbPin = WideCharToMultiByte(CP_UTF8, 0, szPin, -1, nullptr, 0, nullptr, nullptr);
		if (cbPin <= 0)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by WideCharToMultiByte", dwError);
			__leave;
		}
		dwPinLen = static_cast<DWORD>(cbPin);
		pbPin = (LPSTR) EIDAlloc(dwPinLen);
		if (!pbPin)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!WideCharToMultiByte(CP_UTF8, 0, szPin, -1, pbPin, cbPin, nullptr, nullptr))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by WideCharToMultiByte", GetLastError());
			__leave;
		}
		if (!CryptSetProvParam(hProv, (dwKeySpec == AT_KEYEXCHANGE?PP_KEYEXCHANGE_PIN:PP_SIGNATURE_PIN), (PBYTE) pbPin , 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetProvParam - correct PIN ?", GetLastError());
			__leave;
		}
		if (!CryptCreateHash(hProv,CALG_SHA,NULL,0,&hHash))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptCreateHash", GetLastError());
			__leave;
		}
		if (!CryptSetHashParam(hHash, HP_HASHVAL, pbChallenge, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetHashParam", GetLastError());
			__leave;
		}
		if (!CryptSignHash(hHash,dwKeySpec, sDescription, 0, nullptr, pdwResponseSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSignHash1", GetLastError());
			__leave;
		}
		*ppResponse = (PBYTE) EIDAlloc(*pdwResponseSize);
		if (!*ppResponse)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!CryptSignHash(hHash,dwKeySpec, sDescription, 0, *ppResponse, pdwResponseSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSignHash2", GetLastError());
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pbPin)
		{
			PurgeBaseCspPinCache(hProv, pKeyProvInfo, dwKeySpec);
			SecureZeroMemory(pbPin , dwPinLen);
			EIDFree(pbPin);
		}
		if (pKeyProvInfo)
			EIDFree(pKeyProvInfo);
		if (hHash)
			CryptDestroyHash(hHash);
		if (fCallerFreeProv && hProv) 
			CryptReleaseContext(hProv,0);
	}
	SetLastError(dwError);
	return fReturn;
}


struct KEY_BLOB {
  BYTE   bType;
  BYTE   bVersion;
  WORD   reserved;
  ALG_ID aiKeyAlg;
  ULONG cb;
  BYTE Data[CREDENTIALKEYLENGTH/8];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
};

// create a symetric key which can be used to crypt data and
// which is saved and protected by the public key
// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GenerateSymetricKeyAndEncryptIt(__in HCRYPTPROV hProv, __in HCRYPTKEY hKey, __out HCRYPTKEY *phKey, __out PBYTE* pSymetricKey, __out USHORT *usSize)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	DWORD dwSize;
	KEY_BLOB bKey;
	DWORD dwError = 0;
	DWORD dwBlockLen = 0;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		*pSymetricKey = nullptr;
		*phKey = NULL;
		dwSize = sizeof(DWORD);
		// key is generated here
		bKey.bType = PLAINTEXTKEYBLOB;
		bKey.bVersion = CUR_BLOB_VERSION;
		bKey.reserved = 0;
		bKey.aiKeyAlg = CREDENTIALCRYPTALG;
		bKey.cb = CREDENTIALKEYLENGTH/8;
		fStatus = CryptGenRandom(hProv,bKey.cb,bKey.Data);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGenRandom 0x%08x",GetLastError());
			__leave;
		}
		fStatus = CryptImportKey(hProv,(PBYTE)&bKey,sizeof(KEY_BLOB),NULL,CRYPT_EXPORTABLE,phKey);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		// save
		dwBlockLen = 0;
		fStatus = CryptEncrypt(hKey, NULL,TRUE,0,nullptr,&dwBlockLen, 0);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptEncrypt 0x%08x",GetLastError());
			__leave;
		}
		// dwBlockLen is the RSA modulus size: it must hold the AES key plus PKCS#1 padding.
		if (dwBlockLen < CREDENTIALKEYLENGTH/8 + 11)
		{
			dwError = NTE_BAD_KEY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RSA block of %u bytes too small for the key",dwBlockLen);
			__leave;
		}
		*pSymetricKey = (PBYTE) EIDAlloc(dwBlockLen);
		if (!*pSymetricKey)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
			__leave;
		}
		memcpy(*pSymetricKey, bKey.Data, CREDENTIALKEYLENGTH/8);
		dwSize = CREDENTIALKEYLENGTH/8;
		fStatus = CryptEncrypt(hKey, NULL,TRUE,0,*pSymetricKey,&dwSize, dwBlockLen);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptEncrypt 0x%08x",GetLastError());
			__leave;
		}
		if (dwSize > USHRT_MAX)
		{
			dwError = ERROR_ARITHMETIC_OVERFLOW;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"encrypted key size overflow (%u)",dwSize);
			__leave;
		}
		*usSize = (USHORT) dwSize;
		// bKey is know encrypted
		
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pSymetricKey)
			{
				// May still hold the raw AES key if the encryption failed.
				SecureZeroMemory(*pSymetricKey, dwBlockLen);
				EIDFree(*pSymetricKey);
				*pSymetricKey = nullptr;
			}
			if (*phKey)
			{
				CryptDestroyKey(*phKey);
				*phKey = NULL;
			}
		}
		// L3: scrub the raw AES key material from the stack.
		SecureZeroMemory(&bKey, sizeof(bKey));
	}
	SetLastError(dwError);
	return fReturn;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::EncryptPasswordAndSaveIt(__in HCRYPTKEY hKey, __in PWSTR szPassword, __in_opt USHORT dwPasswordLen, __out PBYTE *pEncryptedPassword, __out USHORT *usSize)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	DWORD dwPasswordSize;
	DWORD dwSize;
	DWORD dwBlockLen;
	DWORD dwEncryptedSize;
	DWORD dwRoundNumber;
	DWORD dwError = 0;
	DWORD cbEncryptedBuffer = 0;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		if (!szPassword)
		{
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		dwPasswordSize = (DWORD) (dwPasswordLen?dwPasswordLen:wcslen(szPassword)* sizeof(WCHAR));
		dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptGetKeyParam", GetLastError());
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"dwBlockLen = %d",dwBlockLen);
		if (dwBlockLen == 0)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetKeyParam returned a zero block length");
			__leave;
		}
		// block size = 256             100 => 1     256 => 1      257  => 2
		dwRoundNumber = (dwPasswordSize/dwBlockLen) + ((dwPasswordSize%dwBlockLen) ? 1 : 0);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"dwRoundNumber = %d",dwRoundNumber);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"dwPasswordSize = %d",dwPasswordSize);
		// Mirror of the guard on the decrypt side. An empty password gives
		// dwRoundNumber == 0, and *usSize below computes
		// (dwRoundNumber - 1) * dwBlockLen + dwEncryptedSize, which underflows
		// to ~0xFFFFFF80 and truncates to 0xFF80 in the USHORT. The caller then
		// allocates from the truncated size but copies usPasswordLen (65408)
		// bytes out of this much smaller buffer - a heap overread plus a ~64 KB
		// overwrite at enrolment time. Refuse instead; a blank password has
		// nothing to seal, and the read side rejects a zero-length blob anyway.
		if (dwRoundNumber == 0)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"empty password cannot be sealed (dwPasswordSize=%u)",dwPasswordSize);
			__leave;
		}
		if (dwRoundNumber > MAXDWORD / dwBlockLen)
		{
			dwError = ERROR_ARITHMETIC_OVERFLOW;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"encrypted password size overflow (%lu rounds)",dwRoundNumber);
			__leave;
		}
		// One extra dwBlockLen of headroom. CBC with PKCS padding always emits a
		// trailing pad block, so when the final round encrypts a FULL block (the
		// exact-multiple case fixed below) the output is longer than the input
		// and CryptEncrypt would otherwise fail with ERROR_MORE_DATA.
		DWORD cbEncrypted = dwRoundNumber * dwBlockLen;
		if (cbEncrypted > MAXDWORD - dwBlockLen)
		{
			dwError = ERROR_ARITHMETIC_OVERFLOW;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"encrypted password size overflow");
			__leave;
		}
		cbEncryptedBuffer = cbEncrypted + dwBlockLen;
		*pEncryptedPassword = (PBYTE) EIDAlloc(cbEncryptedBuffer);
		if (!*pEncryptedPassword)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",GetLastError());
			__leave;
		}
		memset(*pEncryptedPassword, 0, cbEncryptedBuffer);
		memcpy(*pEncryptedPassword, szPassword, dwPasswordSize);
		
		dwEncryptedSize = 0;
		for (DWORD dwI = 0; dwI < dwRoundNumber; dwI++)
		{
			const BOOL fLastRound = (dwI == dwRoundNumber - 1);
			// A remainder of zero means the password exactly fills the last
			// round - the final block is FULL, not empty. Passing 0 here made
			// CryptEncrypt emit nothing but a pad block, so a 64- or
			// 128-character password was silently stored truncated while
			// enrolment still reported success. Verified against CryptoAPI:
			// KP_BLOCKLEN reports 128 (BITS) for AES, so "exact multiple" means
			// a 128-byte plaintext, i.e. exactly 64 WCHARs.
			const DWORD dwRemainder = dwPasswordSize % dwBlockLen;
			dwEncryptedSize = fLastRound ? (dwRemainder ? dwRemainder : dwBlockLen) : dwBlockLen;
			fStatus = CryptEncrypt(hKey, NULL, fLastRound, 0,
						*pEncryptedPassword + dwI * dwBlockLen,
						&dwEncryptedSize, cbEncryptedBuffer - dwI * dwBlockLen);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptEncrypt 0x%08x round = %d",GetLastError(), dwI);
				__leave;
			}
		}
		// The size is stored as a USHORT in EID_PRIVATE_DATA; refuse instead of truncating.
		const DWORD cbEncryptedTotal = (dwRoundNumber -1 ) * dwBlockLen + dwEncryptedSize;
		if (cbEncryptedTotal > USHRT_MAX)
		{
			dwError = ERROR_ARITHMETIC_OVERFLOW;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"encrypted password size overflow (%u)",cbEncryptedTotal);
			__leave;
		}
		*usSize = (USHORT) cbEncryptedTotal;
		// szPassword is know encrypted

		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pEncryptedPassword)  // NOSONAR - CONTROL-01: nested if kept for cleanup clarity
			{
				// Holds the plaintext password if encryption failed part-way.
				SecureZeroMemory(*pEncryptedPassword, cbEncryptedBuffer);
				EIDFree(*pEncryptedPassword);
				*pEncryptedPassword = nullptr;
			}
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::GetPasswordFromChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in DWORD dwChallengeType, __in PBYTE pResponse, __in DWORD dwResponseSize, PWSTR *pszPassword)
{
	// SECURITY (H3): when policy requires card-bound credentials, only crypted may be recovered.
	if (dwChallengeType != static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtCrypted) && GetPolicyValue(GPOPolicy::RequireCardBoundCredentials))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RequireCardBoundCredentials: refusing non-crypted credential type %d",dwChallengeType);
		EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[POLICY_DENY] RequireCardBoundCredentials: refused password recovery for non-card-bound credential (type %d, rid 0x%x)", dwChallengeType, dwRid);
		SetLastError(ERROR_ACCESS_DENIED);
		return FALSE;
	}
	switch(dwChallengeType)
	{  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
	case static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtClearText):  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
		return GetPasswordFromSignatureChallengeResponse(dwRid,ppChallenge,dwChallengeSize,pResponse,dwResponseSize,pszPassword);
	case static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtCrypted):  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
		return GetPasswordFromCryptedChallengeResponse(dwRid,ppChallenge,dwChallengeSize,pResponse,dwResponseSize,pszPassword);
	case static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtDPAPI):  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
		return GetPasswordFromDPAPIChallengeResponse(dwRid,ppChallenge,dwChallengeSize,pResponse,dwResponseSize,pszPassword);
	default:
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Type not implemented");
		SetLastError(ERROR_INVALID_DATA);
		return FALSE;
	}
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GetPasswordFromCryptedChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize, PWSTR *pszPassword)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
	UNREFERENCED_PARAMETER(ppChallenge);
	UNREFERENCED_PARAMETER(dwChallengeSize);
	BOOL fReturn = FALSE;
	BOOL fStatus;
	DWORD dwSize;
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	HCRYPTKEY hKey = NULL;  // Windows handle type - keep as NULL
	KEY_BLOB bKey;
	*pszPassword = nullptr;
	DWORD dwBlockLen;
	DWORD dwRoundNumber;
	DWORD dwError = 0;
	DWORD cbPasswordAlloc = 0;     // size of *pszPassword, for the cleanup zeroize
	PEID_PRIVATE_DATA pEidPrivateData = nullptr;
	DWORD dwPrivateDataSize = 0;   // allocation size, for the cleanup zeroize
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		// read the encrypted password
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData,&dwPrivateDataSize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		if (pEidPrivateData->dwSymetricKeySize != dwChallengeSize)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwChallengeSize = 0x%08x",dwChallengeSize);
			__leave;
		}
		// key is generated here
		bKey.bType = PLAINTEXTKEYBLOB;
		bKey.bVersion = CUR_BLOB_VERSION;
		bKey.reserved = 0;
		bKey.aiKeyAlg = CREDENTIALCRYPTALG;
		// SECURITY: pResponse/dwResponseSize come from the card CSP (or a GINA-response caller);
		// bound them to the fixed AES key buffer to prevent a stack overflow in LSASS.
		if (dwResponseSize > sizeof(bKey.Data))
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwResponseSize 0x%x exceeds key buffer size 0x%x",dwResponseSize,(DWORD)sizeof(bKey.Data));
			EIDSecurityAudit(SECURITY_AUDIT_WARNING, L"[CARD_REJECT] Rejected oversized card response (0x%x bytes) for rid 0x%x - possible malicious CSP/card", dwResponseSize, dwRid);
			__leave;
		}
		bKey.cb = dwResponseSize;
		memcpy(bKey.Data, pResponse, dwResponseSize);
		// import the aes key
		fStatus = AcquireEphemeralProvider(&hProv);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		fStatus = CryptImportKey(hProv,(PBYTE) &bKey,sizeof(KEY_BLOB),0,CRYPT_EXPORTABLE,&hKey);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		// decode it
		dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptGetKeyParam", GetLastError());
			__leave;
		}
		if (dwBlockLen == 0)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetKeyParam returned a zero block length");
			__leave;
		}
		dwRoundNumber = (pEidPrivateData->usPasswordLen / dwBlockLen) +
			((pEidPrivateData->usPasswordLen % dwBlockLen) ? 1 : 0);
		// EIDValidatePrivateDataLayout rejects usPasswordLen == 0, which is the
		// only way dwRoundNumber can be zero. Re-check anyway: the terminator
		// write below indexes with (dwRoundNumber - 1), so a zero here would
		// underflow to ~0xFFFFFFFF and write roughly 4 GB past the allocation.
		if (dwRoundNumber == 0)
		{
			dwError = ERROR_INVALID_DATA;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRoundNumber zero (usPasswordLen=%u)",pEidPrivateData->usPasswordLen);
			__leave;
		}
		// usPasswordLen is USHORT, so this product always fits a DWORD
		cbPasswordAlloc = dwRoundNumber * dwBlockLen + sizeof(WCHAR);
		*pszPassword = (PWSTR) EIDAlloc(cbPasswordAlloc);
		if (!*pszPassword)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x", GetLastError());
			__leave;
		}
		// Zero it all: a failed CryptDecrypt leaves before the terminator is written, and the
		// cleanup below must not depend on the buffer holding a terminated string.
		SecureZeroMemory(*pszPassword, cbPasswordAlloc);
		memcpy(*pszPassword, pEidPrivateData->Data + pEidPrivateData->dwPasswordOffset, pEidPrivateData->usPasswordLen);

		for (DWORD dwI = 0; dwI < dwRoundNumber ; dwI++)
		{
			const BOOL fLastRound = (dwI == dwRoundNumber - 1);
			// Mirror of the encrypt-side fix, and the more damaging half of the
			// bug: a stored length that is an exact multiple of dwBlockLen gave
			// a final round of length 0, and CryptDecrypt rejects that outright
			// with NTE_BAD_LEN. Since the ciphertext is the padded plaintext,
			// that happens for any password whose padded length lands on the
			// boundary - 57 to 63 characters, a thoroughly ordinary length.
			// Such an account enrolled successfully and could then NEVER log in.
			const DWORD dwRemainder = pEidPrivateData->usPasswordLen % dwBlockLen;
			dwSize = fLastRound ? (dwRemainder ? dwRemainder : dwBlockLen) : dwBlockLen;
			fStatus = CryptDecrypt(hKey, NULL, fLastRound, 0,
				((PBYTE) *pszPassword) + dwI * dwBlockLen,&dwSize);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptDecrypt 0x%08x",GetLastError());
				__leave;
			}
		}
		// Defence in depth (F1): the plaintext is a WCHAR password without its
		// terminator. A wrong key that happens to pass the padding check yields a
		// length unrelated to that, so refuse anything empty, odd-sized, longer
		// than the stored ciphertext, or whose first WCHAR is already NUL.
		// Terminate first (in bounds: cbPlaintext <= cbPasswordBuffer) so the
		// cleanup wcslen() is bounded on every path below.
		const DWORD cbPlaintext = (dwRoundNumber-1) * dwBlockLen + dwSize;
		(*pszPassword)[cbPlaintext/sizeof(WCHAR)] = '\0';
		if (cbPlaintext == 0 || (cbPlaintext % sizeof(WCHAR)) != 0 || cbPlaintext > pEidPrivateData->usPasswordLen)
		{
			dwError = ERROR_INVALID_DATA;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"decrypted password length %u invalid (usPasswordLen=%u)",cbPlaintext,pEidPrivateData->usPasswordLen);
			__leave;
		}
		if ((*pszPassword)[0] == L'\0')
		{
			dwError = ERROR_INVALID_DATA;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"decrypted password is empty");
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pszPassword)  // NOSONAR - CONTROL-01: nested if kept for cleanup clarity
			{
				// Scrub by the allocation size, never by wcslen: on a decrypt failure the
				// buffer is not a terminated string.
				SecureZeroMemory(*pszPassword, cbPasswordAlloc);
				EIDFree(*pszPassword);
				*pszPassword = nullptr;
			}
		}
		if (pEidPrivateData)
		{
			// Zero the blob, bounded by its ALLOCATION rather than by the sum of
			// the region sizes it declares. The regions are each validated to
			// fit, but their sum is not bounded by anything: three regions
			// overlapping at offset 0 produced a length up to three times the
			// allocation and this write ran off the end of the heap block.
			// EIDPrivateDataSpan returns header + highest region end, and 0 if
			// the blob does not validate.
			EIDFreePrivateData(pEidPrivateData, dwPrivateDataSize);
			pEidPrivateData = nullptr;
		}
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
		}
		// L3: scrub the raw AES key material from the stack.
		SecureZeroMemory(&bKey, sizeof(bKey));
	}
	SetLastError(dwError);
	return fReturn;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GetPasswordFromSignatureChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize, PWSTR *pszPassword)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	DWORD dwError = 0;
	PEID_PRIVATE_DATA pEidPrivateData = nullptr;
	DWORD dwPrivateDataSize = 0;   // allocation size, for the cleanup zeroize
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	HCRYPTKEY hKey = NULL;  // Windows handle type - keep as NULL
	HCRYPTHASH hHash = NULL;  // Windows handle type - keep as NULL
	PCCERT_CONTEXT pCertContextVerif = nullptr;
	PCRYPT_KEY_PROV_INFO pKeyProvInfo = nullptr;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		// read the encrypted password
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		if (CREDENTIALKEYLENGTH != dwChallengeSize)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwChallengeSize = 0x%08x",dwChallengeSize);
			__leave;
		}
		if (pszPassword == nullptr)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pszPassword null");
			__leave;
		}
		*pszPassword = nullptr;
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData,&dwPrivateDataSize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		pCertContextVerif = CertCreateCertificateContext(X509_ASN_ENCODING,
			(PBYTE)pEidPrivateData->Data + pEidPrivateData->dwCertificatOffset, pEidPrivateData->dwCertificatSize);
		if (!pCertContextVerif)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
			__leave;
		}
		// import the public key
		fStatus = AcquireEphemeralProvider(&hProv);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		fStatus = CryptImportPublicKeyInfo(hProv, pCertContextVerif->dwCertEncodingType, &(pCertContextVerif->pCertInfo->SubjectPublicKeyInfo),&hKey);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		if (!CryptCreateHash(hProv,CALG_SHA,NULL,0,&hHash))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptCreateHash", GetLastError());
			__leave;
		}
		if (!CryptSetHashParam(hHash, HP_HASHVAL, ppChallenge, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetHashParam", GetLastError());
			__leave;
		}

		if (!CryptVerifySignature(hHash, pResponse, dwResponseSize, hKey, L"", 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptVerifySignature", GetLastError());
			__leave;
		}
		*pszPassword = (PWSTR) EIDAlloc(pEidPrivateData->usPasswordLen + sizeof(WCHAR));
		if (!*pszPassword)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x", GetLastError());
			__leave;
		}
		memcpy(*pszPassword, (PBYTE)pEidPrivateData->Data + pEidPrivateData->dwPasswordOffset,pEidPrivateData->usPasswordLen);
		(*pszPassword)[pEidPrivateData->usPasswordLen / sizeof(WCHAR)] = '\0';
		fReturn = TRUE;

	}
	__finally
	{
		if (!fReturn && pszPassword && *pszPassword)
		{
			SecureZeroMemory(*pszPassword, wcslen(*pszPassword) * sizeof(WCHAR));
			EIDFree(*pszPassword);
			*pszPassword = nullptr;
		}
		if (pEidPrivateData)
		{
			// Zero the blob, bounded by its ALLOCATION rather than by the sum of
			// the region sizes it declares. The regions are each validated to
			// fit, but their sum is not bounded by anything: three regions
			// overlapping at offset 0 produced a length up to three times the
			// allocation and this write ran off the end of the heap block.
			// EIDPrivateDataSpan returns header + highest region end, and 0 if
			// the blob does not validate.
			EIDFreePrivateData(pEidPrivateData, dwPrivateDataSize);
			pEidPrivateData = nullptr;
		}
		if (pKeyProvInfo)
			EIDFree(pKeyProvInfo);
		if (pCertContextVerif)
			CertFreeCertificateContext(pCertContextVerif);
		if (hHash)
			CryptDestroyHash(hHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
		}
	}
	// LsaApLogonUserEx2 maps the failure from GetLastError().
	SetLastError(dwError);
	return fReturn;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::GetPasswordFromDPAPIChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize, PWSTR *pszPassword)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	DWORD dwError = 0;
	PEID_PRIVATE_DATA pEidPrivateData = nullptr;
	DWORD dwPrivateDataSize = 0;   // allocation size, for the cleanup zeroize
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	HCRYPTKEY hKey = NULL;  // Windows handle type - keep as NULL
	HCRYPTHASH hHash = NULL;  // Windows handle type - keep as NULL
	PCCERT_CONTEXT pCertContextVerif = nullptr;
	DATA_BLOB DataIn = {0};
	DATA_BLOB DataOut = {0};
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		// read the encrypted password
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		if (CREDENTIALKEYLENGTH != dwChallengeSize)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwChallengeSize = 0x%08x",dwChallengeSize);
			__leave;
		}
		if (pszPassword == nullptr)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pszPassword null");
			__leave;
		}
		*pszPassword = nullptr;
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData,&dwPrivateDataSize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		pCertContextVerif = CertCreateCertificateContext(X509_ASN_ENCODING,
			(PBYTE)pEidPrivateData->Data + pEidPrivateData->dwCertificatOffset, pEidPrivateData->dwCertificatSize);
		if (!pCertContextVerif)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
			__leave;
		}
		// import the public key
		fStatus = AcquireEphemeralProvider(&hProv);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		fStatus = CryptImportPublicKeyInfo(hProv, pCertContextVerif->dwCertEncodingType, &(pCertContextVerif->pCertInfo->SubjectPublicKeyInfo),&hKey);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		if (!CryptCreateHash(hProv,CALG_SHA,NULL,0,&hHash))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptCreateHash", GetLastError());
			__leave;
		}
		if (!CryptSetHashParam(hHash, HP_HASHVAL, ppChallenge, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetHashParam", GetLastError());
			__leave;
		}

		if (!CryptVerifySignature(hHash, pResponse, dwResponseSize, hKey, L"", 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptVerifySignature", GetLastError());
			__leave;
		}

		// Signature verified - now decrypt the password using DPAPI
		DataIn.pbData = (PBYTE)pEidPrivateData->Data + pEidPrivateData->dwPasswordOffset;
		DataIn.cbData = pEidPrivateData->usPasswordLen;

		if (!CryptUnprotectData(&DataIn, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &DataOut))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptUnprotectData failed 0x%08x", dwError);
			__leave;
		}

		*pszPassword = (PWSTR) EIDAlloc(DataOut.cbData + sizeof(WCHAR));
		if (!*pszPassword)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x", GetLastError());
			__leave;
		}
		memcpy(*pszPassword, DataOut.pbData, DataOut.cbData);
		(*pszPassword)[DataOut.cbData / sizeof(WCHAR)] = L'\0';
		fReturn = TRUE;

	}
	__finally
	{
		if (!fReturn && pszPassword && *pszPassword)
		{
			SecureZeroMemory(*pszPassword, wcslen(*pszPassword) * sizeof(WCHAR));
			EIDFree(*pszPassword);
			*pszPassword = nullptr;
		}
		if (DataOut.pbData)
		{
			SecureZeroMemory(DataOut.pbData, DataOut.cbData);
			LocalFree(DataOut.pbData);
		}
		if (pEidPrivateData)
		{
			// Zero the blob, bounded by its ALLOCATION rather than by the sum of
			// the region sizes it declares. The regions are each validated to
			// fit, but their sum is not bounded by anything: three regions
			// overlapping at offset 0 produced a length up to three times the
			// allocation and this write ran off the end of the heap block.
			// EIDPrivateDataSpan returns header + highest region end, and 0 if
			// the blob does not validate.
			EIDFreePrivateData(pEidPrivateData, dwPrivateDataSize);
			pEidPrivateData = nullptr;
		}
		if (pCertContextVerif)
			CertFreeCertificateContext(pCertContextVerif);
		if (hHash)
			CryptDestroyHash(hHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::VerifySignatureChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	DWORD dwError = 0;
	PEID_PRIVATE_DATA pEidPrivateData = nullptr;
	DWORD dwPrivateDataSize = 0;   // allocation size, for the cleanup zeroize
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	HCRYPTKEY hKey = NULL;  // Windows handle type - keep as NULL
	HCRYPTHASH hHash = NULL;  // Windows handle type - keep as NULL
	PCCERT_CONTEXT pCertContext = nullptr;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		// read the encrypted password
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		// The challenge length MUST be checked here, not merely by the caller.
		// Below, CryptSetHashParam(HP_HASHVAL, ppChallenge, 0) copies exactly
		// the hash algorithm's digest length (20 bytes for CALG_SHA) out of
		// this buffer regardless of how large it actually is, so a short
		// challenge is a heap over-read inside LSASS. This function shipped
		// without the check - the parameter was explicitly UNREFERENCED - while
		// its two siblings GetPasswordFromSignatureChallengeResponse and
		// GetPasswordFromDPAPIChallengeResponse both enforce it.
		if (CREDENTIALKEYLENGTH != dwChallengeSize)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwChallengeSize = 0x%08x (expected %u)",dwChallengeSize,CREDENTIALKEYLENGTH);
			__leave;
		}
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData,&dwPrivateDataSize);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING,
			(PBYTE)pEidPrivateData->Data + pEidPrivateData->dwCertificatOffset, pEidPrivateData->dwCertificatSize);
		if (!pCertContext)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
			__leave;
		}
		// import the public key
		fStatus = AcquireEphemeralProvider(&hProv);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		fStatus = CryptImportPublicKeyInfo(hProv, pCertContext->dwCertEncodingType, &(pCertContext->pCertInfo->SubjectPublicKeyInfo),&hKey);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		if (!CryptCreateHash(hProv,CALG_SHA,NULL,0,&hHash))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptCreateHash", GetLastError());
			__leave;
		}
		if (!CryptSetHashParam(hHash, HP_HASHVAL, ppChallenge, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetHashParam", GetLastError());
			__leave;
		}

		if (!CryptVerifySignature(hHash, pResponse, dwResponseSize, hKey, L"", 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptVerifySignature", GetLastError());
			__leave;
		}
		fReturn = TRUE;

	}
	__finally
	{
		if (pEidPrivateData)
		{
			// This blob holds the certificate, the wrapped symmetric key and the
			// encrypted password, exactly like the paths that already scrub it.
			// It was being freed without zeroizing.
			EIDFreePrivateData(pEidPrivateData, dwPrivateDataSize);
			pEidPrivateData = nullptr;
		}
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
		if (hHash)
			CryptDestroyHash(hHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
		}
	}
	return fReturn;
}
////////////////////////////////////////////////////////////////////////////////
// LEVEL 3
////////////////////////////////////////////////////////////////////////////////

void CStoredCredentialManager::ProcessSecretBufferInternal(__in DWORD dwRid, std::span<const BYTE> secret) noexcept  // NOSONAR - API-01: signature dictated by Windows/callback API
{
    // Bounds-safe access with automatic size tracking
    if (secret.empty()) {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"ProcessSecretBufferInternal: empty buffer for RID 0x%08X", dwRid);
        return;
    }

    // Example bounds-safe iteration (replace with actual secret processing from existing StorePrivateData)
    for (const auto& byte : secret) {
        // Process each byte safely - buffer.size() automatically available
        UNREFERENCED_PARAMETER(byte);
    }

    // Access size without separate parameter: secret.size()
    DWORD dwSecretSize = static_cast<DWORD>(secret.size());  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
    EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"ProcessSecretBufferInternal: RID 0x%08X, size %u", dwRid, dwSecretSize);
}

void CStoredCredentialManager::ProcessSecretBufferDebugInternal(__in DWORD dwRid, std::span<const BYTE> secret) noexcept  // NOSONAR - API-01: signature dictated by Windows/callback API
{
    // Bounds-safe access with automatic size tracking
    if (secret.empty()) {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"ProcessSecretBufferDebugInternal: empty buffer for RID 0x%08X", dwRid);
        return;
    }

    // Example bounds-safe iteration
    for (const auto& byte : secret) {
        UNREFERENCED_PARAMETER(byte);
    }

    DWORD dwSecretSize = static_cast<DWORD>(secret.size());  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
    EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"ProcessSecretBufferDebugInternal: RID 0x%08X, size %u", dwRid, dwSecretSize);
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::StorePrivateData(__in DWORD dwRid, __in_opt PBYTE pbSecret, __in_opt USHORT usSecretSize)
{
	// Convert C-style buffer to span for internal processing
	// Validate that null buffer with non-zero size is an error
	if (pbSecret == nullptr && usSecretSize > 0) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	// Create span for bounds-safe internal processing
	std::span<const BYTE> secretSpan(pbSecret, usSecretSize);

	if (!EIDIsComponentInLSAContext())
 	{
		ProcessSecretBufferDebugInternal(dwRid, secretSpan);
		return StorePrivateDataDebug(dwRid, pbSecret, usSecretSize);
	}

	// Process buffer using span-based helper
	ProcessSecretBufferInternal(dwRid, secretSpan);

	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_HANDLE LsaPolicyHandle = nullptr;

    LSA_UNICODE_STRING lusSecretName;
    LSA_UNICODE_STRING lusSecretData;
	WCHAR szLsaKeyName[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    NTSTATUS ntsResult = STATUS_SUCCESS;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
    //  Object attributes are reserved, so initialize to zeros.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		//  Get a handle to the Policy object.
		ntsResult = LsaOpenPolicy(
			nullptr,    // local machine
			&ObjectAttributes, 
			POLICY_CREATE_SECRET | READ_CONTROL | WRITE_OWNER | WRITE_DAC,
			&LsaPolicyHandle);

		if( STATUS_SUCCESS != ntsResult )
		{
			//  An error occurred. Display it as a win32 error code.
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaOpenPolicy", ntsResult);
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		} 

		//  Initialize an LSA_UNICODE_STRING for the name of the
		if (FAILED(StringCchPrintfW(szLsaKeyName, ARRAYSIZE(szLsaKeyName), L"%s_%08X", CREDENTIAL_LSAPREFIX, dwRid)))
		{
			dwError = ERROR_BUFFER_OVERFLOW;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"StringCchPrintfW failed for LSA key name");
			__leave;
		}

		lusSecretName.Buffer = szLsaKeyName;
		lusSecretName.Length = (USHORT) wcslen(szLsaKeyName)* sizeof(WCHAR);
		lusSecretName.MaximumLength = lusSecretName.Length;
		//  If the pwszSecret parameter is NULL, then clear the secret.
		if( nullptr == pbSecret )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Clearing %x",dwRid);
			ntsResult = LsaStorePrivateData(
				LsaPolicyHandle,
				&lusSecretName,
				nullptr);

			// Log LSA secret deletion
			if (ntsResult == STATUS_SUCCESS)
			{
				WCHAR szRid[16];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
				swprintf_s(szRid, ARRAYSIZE(szRid), L"0x%08X", dwRid);
				EIDCardLibraryLogStructured(
					EID_EVENT_ID::LSA_SECRET_DELETED,
					EID_SEVERITY::INFO,
					EID_OUTCOME::SUCCESS,
					nullptr,
					L"LSA Secret Delete",
					L"LSA secret deleted successfully",
					nullptr,
					nullptr,
					0,
					0,
					0,
					szRid,
					nullptr
				);
			}
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Setting %x",dwRid);
			//  Initialize an LSA_UNICODE_STRING for the value
			//  of the private data.
			lusSecretData.Buffer = (PWSTR) pbSecret;
			lusSecretData.Length = usSecretSize;
			lusSecretData.MaximumLength = usSecretSize;
			ntsResult = LsaStorePrivateData(
				LsaPolicyHandle,
				&lusSecretName,
				&lusSecretData);

			// Log LSA secret write
			if (ntsResult == STATUS_SUCCESS)
			{
				WCHAR szRid[16];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
				swprintf_s(szRid, ARRAYSIZE(szRid), L"0x%08X", dwRid);
				EIDCardLibraryLogStructured(
					EID_EVENT_ID::LSA_SECRET_CREATED,
					EID_SEVERITY::INFO,
					EID_OUTCOME::SUCCESS,
					nullptr,
					L"LSA Secret Write",
					L"LSA secret stored successfully",
					nullptr,
					nullptr,
					0,
					0,
					0,
					szRid,
					nullptr
				);
			}
		}
		if( STATUS_SUCCESS != ntsResult )
		{
			//  An error occurred. Display it as a win32 error code.
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaStorePrivateData", ntsResult);
			dwError = LsaNtStatusToWinError(ntsResult);

			// Log LSA operation failure
			WCHAR szRid[16], szError[32];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
			swprintf_s(szRid, ARRAYSIZE(szRid), L"0x%08X", dwRid);
			swprintf_s(szError, ARRAYSIZE(szError), L"0x%08X", ntsResult);
			EIDCardLibraryLogStructured(
				EID_EVENT_ID::AUTHZ_CREDENTIAL_DENIED,
				EID_SEVERITY::ERROR,
				EID_OUTCOME::FAILURE,
				nullptr,
				L"LSA Secret Operation",
				L"LSA secret operation failed",
				nullptr,
				nullptr,
				0,
				0,
				0,
				szRid,
				szError
			);

			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (LsaPolicyHandle) LsaClose(LsaPolicyHandle);
	} 
	SetLastError(dwError);
    return fReturn;

}

BOOL CStoredCredentialManager::StorePrivateDataDebug(__in DWORD dwRid, __in_opt PBYTE pbSecret, __in_opt USHORT usSecretSize)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	// SECURITY FIX: Debug credential storage to TEMP files is disabled
	// This was a critical security vulnerability (CWE-532) that exposed credentials in plaintext
	// Credentials can only be stored securely via LSA private data storage
	UNREFERENCED_PARAMETER(dwRid);
	UNREFERENCED_PARAMETER(pbSecret);
	UNREFERENCED_PARAMETER(usSecretSize);

	EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"SECURITY: Debug credential file storage is disabled - must run in LSA context");
	SetLastError(ERROR_ACCESS_DENIED);
	return FALSE;
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
BOOL CStoredCredentialManager::RetrievePrivateData(__in DWORD dwRid, __out PEID_PRIVATE_DATA *ppPrivateData, __out_opt PDWORD pdwBlobSize)
{
	if (pdwBlobSize)
	{
		*pdwBlobSize = 0;
	}
	if (!EIDIsComponentInLSAContext())
 	{
		return RetrievePrivateDataDebug(dwRid,ppPrivateData);
	}

	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_HANDLE LsaPolicyHandle = nullptr;
 PLSA_UNICODE_STRING pData = nullptr;
    LSA_UNICODE_STRING lusSecretName;
	WCHAR szLsaKeyName[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	NTSTATUS ntsResult = STATUS_SUCCESS;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
    //  Object attributes are reserved, so initialize to zeros.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		//  Get a handle to the Policy object.
		ntsResult = LsaOpenPolicy(
			nullptr,    // local machine
			&ObjectAttributes, 
			POLICY_GET_PRIVATE_INFORMATION,
			&LsaPolicyHandle);

		if( STATUS_SUCCESS != ntsResult )
		{
			//  An error occurred. Display it as a win32 error code.
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaOpenPolicy", ntsResult);
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		} 

		//  Initialize an LSA_UNICODE_STRING for the name of the
		//  private data.
		if (FAILED(StringCchPrintfW(szLsaKeyName, ARRAYSIZE(szLsaKeyName), L"%s_%08X", CREDENTIAL_LSAPREFIX, dwRid)))
		{
			dwError = ERROR_BUFFER_OVERFLOW;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"StringCchPrintfW failed for LSA key name");
			__leave;
		}

		lusSecretName.Buffer = szLsaKeyName;
		lusSecretName.Length = (USHORT) wcslen(szLsaKeyName)* sizeof(WCHAR);
		lusSecretName.MaximumLength = lusSecretName.Length;

		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Reading dwRid = 0x%x", dwRid);
		ntsResult = LsaRetrievePrivateData(LsaPolicyHandle,&lusSecretName,&pData);
		if( STATUS_SUCCESS != ntsResult )
		{
			if (0xc0000034 == ntsResult)
			{
				// LSA secret not found is expected when scanning multiple RIDs
				// Log at VERBOSE level to avoid log noise - this is not an error condition
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"LSA secret not found for dwRid = 0x%x (expected during scan)", dwRid);

				WCHAR szRid[16];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
				swprintf_s(szRid, ARRAYSIZE(szRid), L"0x%08X", dwRid);
				EIDCardLibraryLogStructured(
					EID_EVENT_ID::AUTHZ_LSA_SECRET_SCAN_NOT_FOUND,
					EID_SEVERITY::VERBOSE,
					EID_OUTCOME::SUCCESS,  // Not a failure - this is expected during scans
					nullptr,
					L"LSA Secret Scan",
					L"Credential not found for this RID (continuing scan)",
					nullptr,
					nullptr,
					0,
					0,
					0,
					szRid,
					nullptr
				);
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaRetrievePrivateData", ntsResult);

				// Log LSA read error
				WCHAR szRid[16], szError[32];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
				swprintf_s(szRid, ARRAYSIZE(szRid), L"0x%08X", dwRid);
				swprintf_s(szError, ARRAYSIZE(szError), L"0x%08X", ntsResult);
				EIDCardLibraryLogStructured(
					EID_EVENT_ID::AUTHZ_CREDENTIAL_DENIED,
					EID_SEVERITY::ERROR,
					EID_OUTCOME::FAILURE,
					nullptr,
					L"LSA Secret Read",
					L"LSA secret read failed",
					nullptr,
					nullptr,
					0,
					0,
					0,
					szRid,
					szError
				);
			}
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		}

		// Log LSA secret read success
		WCHAR szRid[16];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		swprintf_s(szRid, ARRAYSIZE(szRid), L"0x%08X", dwRid);
		EIDCardLibraryLogStructured(
			EID_EVENT_ID::AUTHZ_LSA_SECRET_READ,
			EID_SEVERITY::INFO,
			EID_OUTCOME::SUCCESS,
			nullptr,
			L"LSA Secret Read",
			L"LSA secret retrieved successfully",
			nullptr,
			nullptr,
			0,
			0,
			0,
			szRid,
			nullptr
		); 
		*ppPrivateData = (PEID_PRIVATE_DATA) EIDAlloc(pData->Length);
		if (!*ppPrivateData)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
			__leave;
		}
		memcpy(*ppPrivateData, pData->Buffer, pData->Length);
		// Reject a truncated or self-inconsistent blob here rather than letting each
		// consumer index Data[] out of bounds inside LSASS.
		if (!EIDValidatePrivateDataLayout(*ppPrivateData, pData->Length))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EID_PRIVATE_DATA layout invalid (%d bytes) for rid 0x%08x", pData->Length, dwRid);
			EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[BOUNDS_REJECT] EID_PRIVATE_DATA layout invalid (%d bytes) for rid 0x%x", pData->Length, dwRid);
			// The full LSA secret was already memcpy'd in above, so this buffer
			// holds real key material even though its layout is malformed.
			// EIDPrivateDataSpan returns 0 for it, so the helper falls back to
			// the raw allocation size.
			EIDFreePrivateData(*ppPrivateData, pData->Length);
			*ppPrivateData = nullptr;
			dwError = ERROR_INVALID_DATA;
			__leave;
		}
		if (pdwBlobSize)
		{
			*pdwBlobSize = pData->Length;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (LsaPolicyHandle) LsaClose(LsaPolicyHandle);
		if (pData)
		{
			// The whole stored secret: certificate, wrapped key, encrypted password.
			if (pData->Buffer && pData->Length)
			{
				SecureZeroMemory(pData->Buffer, pData->Length);
			}
			LsaFreeMemory(pData);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::RetrievePrivateDataDebug(__in DWORD dwRid, __out PEID_PRIVATE_DATA *ppPrivateData)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	// SECURITY FIX: Debug credential retrieval from TEMP files is disabled
	// This was a critical security vulnerability (CWE-532) that read credentials from plaintext files
	// Credentials can only be retrieved securely via LSA private data storage
	UNREFERENCED_PARAMETER(dwRid);

	if (ppPrivateData)
	{
		*ppPrivateData = nullptr;
	}

	EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"SECURITY: Debug credential file retrieval is disabled - must run in LSA context");
	SetLastError(ERROR_ACCESS_DENIED);
	return FALSE;
}

BOOL CStoredCredentialManager::HasStoredCredential(__in DWORD dwRid)
{
	BOOL fReturn = FALSE;
	PEID_PRIVATE_DATA pSecret;
	DWORD dwSecretSize = 0;
	DWORD dwError = 0;
	if (RetrievePrivateData(dwRid, &pSecret, &dwSecretSize))
	{
		dwError = GetLastError();
		fReturn = TRUE;
		EIDFreePrivateData(pSecret, dwSecretSize);
		pSecret = nullptr;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"%s",(fReturn?L"TRUE":L"FALSE"));
	SetLastError(dwError);
	return fReturn;
}
//////////////////////////////////////////////////////////////


struct ENCRYPTED_LM_OWF_PASSWORD {
    std::array<unsigned char, 16> data;
};
using PENCRYPTED_LM_OWF_PASSWORD = ENCRYPTED_LM_OWF_PASSWORD*;
using ENCRYPTED_NT_OWF_PASSWORD = ENCRYPTED_LM_OWF_PASSWORD;
using PENCRYPTED_NT_OWF_PASSWORD = ENCRYPTED_NT_OWF_PASSWORD*;

struct SAMPR_USER_INTERNAL1_INFORMATION {
    ENCRYPTED_NT_OWF_PASSWORD  EncryptedNtOwfPassword;
    ENCRYPTED_LM_OWF_PASSWORD  EncryptedLmOwfPassword;
    unsigned char              NtPasswordPresent;
    unsigned char              LmPasswordPresent;
    unsigned char              PasswordExpired;
};
using PSAMPR_USER_INTERNAL1_INFORMATION = SAMPR_USER_INTERNAL1_INFORMATION*;

enum USER_INFORMATION_CLASS {  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
    UserInternal1Information = 18,
};
using PUSER_INFORMATION_CLASS = USER_INFORMATION_CLASS*;

using PSAMPR_USER_INFO_BUFFER = PSAMPR_USER_INTERNAL1_INFORMATION;

using PSAMPR_SERVER_NAME = WCHAR*;
using SAMPR_HANDLE = PVOID;


// opnum 0
using SamrConnect = NTSTATUS (NTAPI*)(
    __in PSAMPR_SERVER_NAME ServerName,
    __out SAMPR_HANDLE * ServerHandle,
    __in DWORD DesiredAccess,
	__in DWORD
    );

// opnum 1
using SamrCloseHandle = NTSTATUS (NTAPI*)(
    __inout SAMPR_HANDLE * SamHandle
    );

// opnum 7
using SamrOpenDomain = NTSTATUS (NTAPI*)(
    __in SAMPR_HANDLE ServerHandle,
    __in DWORD   DesiredAccess,
    __in PSID DomainId,
    __out SAMPR_HANDLE * DomainHandle
    );


		// opnum 34
using SamrOpenUser = NTSTATUS (NTAPI*)(
    __in SAMPR_HANDLE DomainHandle,
    __in DWORD   DesiredAccess,
    __in DWORD   UserId,
    __out SAMPR_HANDLE  * UserHandle
    );

// opnum 36
using SamrQueryInformationUser = NTSTATUS (NTAPI*)(
    __in SAMPR_HANDLE UserHandle,
    __in USER_INFORMATION_CLASS  UserInformationClass,
	__out PSAMPR_USER_INFO_BUFFER * Buffer
    );

using SamIFree_SAMPR_USER_INFO_BUFFER = NTSTATUS (NTAPI*)(
	__in PSAMPR_USER_INFO_BUFFER Buffer,
	__in USER_INFORMATION_CLASS UserInformationClass
	);

HMODULE samsrvDll = nullptr;  // NOSONAR - RUNTIME-01: DLL handle, loaded at runtime
SamrConnect MySamrConnect;  // NOSONAR - RUNTIME-01: Function pointer, resolved via GetProcAddress
SamrCloseHandle MySamrCloseHandle;  // NOSONAR - RUNTIME-01: Function pointer, resolved via GetProcAddress
SamrOpenDomain MySamrOpenDomain;  // NOSONAR - RUNTIME-01: Function pointer, resolved via GetProcAddress
SamrOpenUser MySamrOpenUser;  // NOSONAR - RUNTIME-01: Function pointer, resolved via GetProcAddress
SamrQueryInformationUser MySamrQueryInformationUser;  // NOSONAR - RUNTIME-01: Function pointer, resolved via GetProcAddress
SamIFree_SAMPR_USER_INFO_BUFFER MySamIFree;  // NOSONAR - RUNTIME-01: Function pointer, resolved via GetProcAddress


// samsrv.dll stays loaded in LSASS for its whole life. Resolve its exports once and never
// unload it: concurrent CheckPassword calls used to load, overwrite and free these globals
// under each other.
static INIT_ONCE s_SamSrvInitOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK LoadSamSrvOnce(PINIT_ONCE, PVOID, PVOID*)
{
	HMODULE hSamSrv = EIDLoadSystemLibrary(L"samsrv.dll");
	if (!hSamSrv)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LoadSam failed 0x%08x",GetLastError());
		return FALSE;
	}
	MySamrConnect = (SamrConnect) GetProcAddress(hSamSrv,"SamIConnect");
	MySamrCloseHandle = (SamrCloseHandle) GetProcAddress(hSamSrv,"SamrCloseHandle");
	MySamrOpenDomain = (SamrOpenDomain) GetProcAddress(hSamSrv,"SamrOpenDomain");
	MySamrOpenUser = (SamrOpenUser) GetProcAddress(hSamSrv,"SamrOpenUser");
	MySamrQueryInformationUser = (SamrQueryInformationUser) GetProcAddress(hSamSrv,"SamrQueryInformationUser");
	MySamIFree = (SamIFree_SAMPR_USER_INFO_BUFFER) GetProcAddress(hSamSrv,"SamIFree_SAMPR_USER_INFO_BUFFER");
	if (!MySamrConnect || !MySamrCloseHandle || !MySamrOpenDomain || !MySamrOpenUser
		|| !MySamrQueryInformationUser || !MySamIFree)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Null pointer function");
		FreeLibrary(hSamSrv);
		return FALSE;
	}
	samsrvDll = hSamSrv;
	return TRUE;
}

NTSTATUS LoadSamSrv()
{
	if (!InitOnceExecuteOnce(&s_SamSrvInitOnce, LoadSamSrvOnce, nullptr, nullptr))
	{
		return STATUS_FAIL_CHECK;
	}
	return STATUS_SUCCESS;
}

// CheckPassword compares the password's NT hash with SAM's directly, so a wrong guess never
// reaches SAM's bad-password count, lockout policy or logon auditing, and any user could
// guess their own password through EIDCMCreateStoredCredential at full speed. Allow
// EID_PWCHECK_MAX_FAILURES wrong passwords per RID within EID_PWCHECK_WINDOW_MS; after that
// refuse to check that RID until the window has passed. Every wrong password is audited.
constexpr DWORD EID_PWCHECK_MAX_FAILURES = 5;
constexpr ULONGLONG EID_PWCHECK_WINDOW_MS = 15ULL * 60ULL * 1000ULL;
struct EID_PWCHECK_FAILURES
{
	DWORD dwRid;
	DWORD dwCount;
	ULONGLONG ullFirstFailure;
};
static SRWLOCK s_PwCheckLock = SRWLOCK_INIT;
static std::array<EID_PWCHECK_FAILURES, 32> s_PwCheckFailures {};

// Caller holds s_PwCheckLock. Returns the slot for dwRid, or nullptr.
static EID_PWCHECK_FAILURES* FindPasswordCheckSlot(DWORD dwRid, ULONGLONG ullNow)
{
	for (auto& slot : s_PwCheckFailures)
	{
		if (slot.dwCount != 0 && slot.dwRid == dwRid)
		{
			if (ullNow - slot.ullFirstFailure >= EID_PWCHECK_WINDOW_MS)
			{
				slot = {};
				return nullptr;
			}
			return &slot;
		}
	}
	return nullptr;
}

static BOOL IsPasswordCheckThrottled(DWORD dwRid)
{
	const ULONGLONG ullNow = GetTickCount64();
	AcquireSRWLockExclusive(&s_PwCheckLock);
	const EID_PWCHECK_FAILURES* pSlot = FindPasswordCheckSlot(dwRid, ullNow);
	const BOOL fThrottled = pSlot && pSlot->dwCount >= EID_PWCHECK_MAX_FAILURES;
	ReleaseSRWLockExclusive(&s_PwCheckLock);
	return fThrottled;
}

static void RecordPasswordCheckResult(DWORD dwRid, BOOL fWrongPassword)
{
	const ULONGLONG ullNow = GetTickCount64();
	AcquireSRWLockExclusive(&s_PwCheckLock);
	EID_PWCHECK_FAILURES* pSlot = FindPasswordCheckSlot(dwRid, ullNow);
	if (!fWrongPassword)
	{
		if (pSlot)
		{
			*pSlot = {};
		}
	}
	else if (pSlot)
	{
		pSlot->dwCount++;
	}
	else
	{
		// New RID: take a free slot, else the one whose window started first.
		EID_PWCHECK_FAILURES* pVictim = &s_PwCheckFailures[0];
		for (auto& slot : s_PwCheckFailures)
		{
			if (slot.dwCount == 0)
			{
				pVictim = &slot;
				break;
			}
			if (slot.ullFirstFailure < pVictim->ullFirstFailure)
			{
				pVictim = &slot;
			}
		}
		pVictim->dwRid = dwRid;
		pVictim->dwCount = 1;
		pVictim->ullFirstFailure = ullNow;
	}
	ReleaseSRWLockExclusive(&s_PwCheckLock);
}

// SonarQube S134: Won't Fix - SEH-protected function (__try/__finally)
// Code cannot be extracted from __try blocks per LSASS safety requirements
NTSTATUS CStoredCredentialManager::CheckPassword( __in DWORD dwRid, __in PWSTR szPassword)
{
	NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	LSA_OBJECT_ATTRIBUTES connectionAttrib;
    LSA_HANDLE handlePolicy = nullptr;
    PPOLICY_ACCOUNT_DOMAIN_INFO structInfoPolicy = nullptr;// -> http://msdn2.microsoft.com/en-us/library/ms721895(VS.85).aspx.
 SAMPR_HANDLE hSam = nullptr;
 SAMPR_HANDLE hDomain = nullptr;
 SAMPR_HANDLE hUser = nullptr;
 PSAMPR_USER_INTERNAL1_INFORMATION UserInfo = nullptr;
	std::array<unsigned char, 16> bHash {};
	UNICODE_STRING EncryptedPassword;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	__try
	{
		// The byte length must fit the UNICODE_STRING's USHORT (it used to wrap at 32768 chars).
		const size_t cchPassword = szPassword ? wcsnlen(szPassword, (USHRT_MAX / sizeof(WCHAR)) + 1) : 0;
		if (!szPassword || cchPassword > USHRT_MAX / sizeof(WCHAR))
		{
			Status = STATUS_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"password absent or too long");
			__leave;
		}
		if (IsPasswordCheckThrottled(dwRid))
		{
			Status = STATUS_ACCOUNT_LOCKED_OUT;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"password checks for rid 0x%x throttled",dwRid);
			EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_PASSWORD_ERROR] Password check for rid 0x%x refused: too many wrong passwords, retry later", dwRid);
			__leave;
		}
		memset(&connectionAttrib,0,sizeof(LSA_OBJECT_ATTRIBUTES));
        connectionAttrib.Length = sizeof(LSA_OBJECT_ATTRIBUTES);
		Status = LoadSamSrv();
		if (Status!= STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LoadSamSrv failed 0x%08x",Status);
			__leave;
		}
		Status = LsaOpenPolicy(nullptr,&connectionAttrib,POLICY_VIEW_LOCAL_INFORMATION,&handlePolicy);
		if (Status!= STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaOpenPolicy failed 0x%08x",Status);
			__leave;
		}
		Status = LsaQueryInformationPolicy(handlePolicy , PolicyAccountDomainInformation , (PVOID*)&structInfoPolicy);
		if (Status!= STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaQueryInformationPolicy failed 0x%08x",Status);
			__leave;
		}
		Status = MySamrConnect(nullptr , &hSam , MAXIMUM_ALLOWED, 1);  // nullptr is already correct
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SamrConnect failed 0x%08x",Status);
			__leave;
		}
		Status = MySamrOpenDomain(hSam , 0xf07ff , structInfoPolicy->DomainSid , &hDomain);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SamrOpenDomain failed 0x%08x",Status);
			__leave;
		}
		Status = MySamrOpenUser(hDomain , MAXIMUM_ALLOWED , dwRid , &hUser);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SamrOpenUser failed 0x%08x rid = %d",Status,dwRid);
			__leave;
		}
		Status = MySamrQueryInformationUser(hUser , UserInternal1Information , &UserInfo);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SamrQueryInformationUser failed 0x%08x",Status);
			__leave;
		}
		EncryptedPassword.Length = static_cast<USHORT>(cchPassword * sizeof(WCHAR));
		EncryptedPassword.MaximumLength = EncryptedPassword.Length;
		EncryptedPassword.Buffer = szPassword;
		Status = SystemFunction007(&EncryptedPassword, bHash.data());
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SystemFunction007 failed 0x%08x",Status);
			__leave;
		}
		// Constant time: compare every byte.
		unsigned char bDiff = 0;
		for (DWORD dwI = 0 ; dwI < 16; dwI++)
		{
			bDiff |= static_cast<unsigned char>(bHash[dwI] ^ UserInfo->EncryptedNtOwfPassword.data[dwI]);
		}
		if (bDiff != 0)
		{
			Status = STATUS_WRONG_PASSWORD;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_WRONG_PASSWORD");
			EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_PASSWORD_ERROR] Password check for rid 0x%x failed: wrong password", dwRid);
		}
		RecordPasswordCheckResult(dwRid, bDiff != 0);
	}
	__finally
	{
		SecureZeroMemory(bHash.data(), bHash.size());
		if (UserInfo)
		{
			SecureZeroMemory(UserInfo, sizeof(*UserInfo));
			MySamIFree(UserInfo, UserInternal1Information);
		}
		if (hUser)
			MySamrCloseHandle(&hUser);
		if (hDomain)
			MySamrCloseHandle(&hDomain);
		if (hSam)
			MySamrCloseHandle(&hSam);
		if (structInfoPolicy)
			LsaFreeMemory(structInfoPolicy);
		if (handlePolicy)
			LsaClose(handlePolicy);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with status = 0x%08x",Status);
	return Status;
}