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

#include "EIDCardLibrary.h"
#include <utility>
#include <span>

// Forward declaration - EID_PRIVATE_DATA_TYPE is defined in EIDCardLibrary.h
// EID_PRIVATE_DATA structure definition
struct EID_PRIVATE_DATA
{
	EID_PRIVATE_DATA_TYPE dwType;
	USHORT dwCertificatOffset;
	USHORT dwCertificatSize;
	USHORT dwSymetricKeyOffset;
	USHORT dwSymetricKeySize;
	USHORT dwPasswordOffset;
	USHORT usPasswordLen;      // Renamed from dwPasswordSize to avoid shadowing global
	UCHAR Hash[CERT_HASH_LENGTH];  // NOSONAR - LSASS-01: C-style buffer for serialized private-data layout
	BYTE Data[sizeof(DWORD)];  // NOSONAR - LSASS-01: C-style buffer for serialized private-data layout
};
using PEID_PRIVATE_DATA = EID_PRIVATE_DATA*;

// Checks the enrolment proof of possession carried by EIDCMCreateStoredCredential: a signature
// with the certificate's own key over EIDBuildEnrolmentStatement, made within a few minutes.
BOOL EIDVerifyEnrolmentProof(__in DWORD dwRid, __in PCCERT_CONTEXT pCertContext, __in const FILETIME* pftTime,
	__in_bcount(cbSignature) const BYTE* pbSignature, __in DWORD cbSignature);

 class CStoredCredentialManager
 {
    // constructeurs/destructeur de OnlyOne accessibles au Singleton
public:
	// Thread-safe; returns NULL only when the instance cannot be allocated.
	static CStoredCredentialManager* Instance();

    BOOL GetUsernameFromCertContext(__in PCCERT_CONTEXT pContext, __out PWSTR *szUsername, __out PDWORD pdwRid);
	BOOL GetCertContextFromHash(__in PBYTE pbHash, __out PCCERT_CONTEXT* ppContext, __out PDWORD pdwRid);
	BOOL CreateCredential(__in DWORD dwRid, __in PCCERT_CONTEXT pContext, __in PWSTR szPassword, __in_opt USHORT usPasswordLen, __in BOOL fEncryptPassword, __in BOOL fCheckPassword);
	BOOL UpdateCredential(__in PLUID pLuid, __in PUNICODE_STRING Password);
	BOOL UpdateCredential(__in DWORD dwRid, __in PWSTR szPassword, __in_opt USHORT usPasswordLen);
	BOOL GetChallenge(__in DWORD dwRid, __out PBYTE* ppChallenge, __out PDWORD pdwChallengeSize, __out PDWORD pdwType);
	BOOL GetResponseFromChallenge(__in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in DWORD dwChallengeType, __in PCCERT_CONTEXT pContext, __in PWSTR szPin, __out PBYTE *ppResponse, __out PDWORD pdwResponseSize);
	BOOL GetPasswordFromChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize,  __in DWORD dwChallengeType, __in PBYTE pResponse, __in DWORD dwResponseSize, __out PWSTR *pszPassword);
	BOOL GetPassword(__in DWORD dwRid, __in PCCERT_CONTEXT pContext, __in PWSTR szPin, __out PWSTR *pszPassword);
	BOOL RemoveStoredCredential(__in DWORD dwRid);
	BOOL RemoveAllStoredCredential();
	BOOL HasStoredCredential(__in DWORD dwRid);
	BOOL HasStoredCredential(__in PCCERT_CONTEXT pContext);
	BOOL GetResponseFromSignatureChallenge(__in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PCCERT_CONTEXT pContext, __in PWSTR szPin, __out PBYTE *ppResponse, __out PDWORD pdwResponseSize);
	BOOL GetSignatureChallenge(__out PBYTE* ppChallenge, __out PDWORD pdwChallengeSize);
	BOOL VerifySignatureChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize);
 private:
	static CStoredCredentialManager* theSingleInstance;
	static BOOL CALLBACK CreateInstanceOnce(PINIT_ONCE, PVOID, PVOID*);
	BOOL GetResponseFromCryptedChallenge(__in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PCCERT_CONTEXT pCertContext, __in PWSTR szPin, __out PBYTE *ppResponse, __out PDWORD pdwResponseSize);
	BOOL GetPasswordFromCryptedChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize, __out PWSTR *pszPassword);
	BOOL GetPasswordFromSignatureChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize, __out PWSTR *pszPassword);
	BOOL GetPasswordFromDPAPIChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize, __out PWSTR *pszPassword);
	BOOL GetCertContextFromRid(__in DWORD dwRid, __out PCCERT_CONTEXT* ppContext, __out PBOOL fEncryptPassword);
	// TRUE when the check completed; *pfBoundElsewhere is set when another account already holds pContext.
	BOOL IsCertificateBoundToOtherRid(__in DWORD dwRid, __in PCCERT_CONTEXT pContext, __out PBOOL pfBoundElsewhere);
	// Internal buffer processing using std::span for bounds safety
	void ProcessSecretBufferInternal(__in DWORD dwRid, std::span<const BYTE> secret) noexcept;
	void ProcessSecretBufferDebugInternal(__in DWORD dwRid, std::span<const BYTE> secret) noexcept;
	// pdwBlobSize receives the allocation size of *ppPrivateData, and is
	// MANDATORY: the blob holds the certificate, the wrapped symmetric key and
	// the encrypted password, so every caller must scrub it before freeing, and
	// scrubbing needs the allocation size (the region sizes inside the struct
	// are individually bounded but their sum is not). This deliberately has no
	// default argument - four callers previously omitted it and freed the blob
	// unscrubbed, two of them on every authentication. Use EIDFreePrivateData.
	BOOL RetrievePrivateData(__in DWORD dwRid, __out PEID_PRIVATE_DATA *ppPrivateData, __out PDWORD pdwBlobSize);
	BOOL StorePrivateData(__in DWORD dwRid, __in_opt PBYTE pbSecret, __in_opt USHORT usSecretSize);
	BOOL RetrievePrivateDataDebug(__in DWORD dwRid, __out PEID_PRIVATE_DATA *ppPrivateData);
	BOOL StorePrivateDataDebug(__in DWORD dwRid, __in_opt PBYTE pbSecret, __in_opt USHORT usSecretSize);
	BOOL GenerateSymetricKeyAndEncryptIt(__in HCRYPTPROV hProv, __in HCRYPTKEY hKey, __out HCRYPTKEY *phKey, __out PBYTE* pSymetricKey, __out USHORT *usSize);
	BOOL EncryptPasswordAndSaveIt(__in HCRYPTKEY hKey, __in PWSTR szPassword, __in_opt USHORT dwPasswordLen, __out PBYTE *pEncryptedPassword, __out USHORT *usSize);
	virtual NTSTATUS CheckPassword( __in DWORD dwRid, __in PWSTR szPassword);
 };


//BOOL CanEncryptPassword(__in_opt HCRYPTPROV hProv, __in_opt DWORD dwKeySpec,  __in_opt PCCERT_CONTEXT pCertContext);

#ifdef _NTSECPKG_
NTSTATUS CompletePrimaryCredential(__in PLSA_UNICODE_STRING AuthenticatingAuthority,
						__in PLSA_UNICODE_STRING AccountName,
						__in PSID UserSid,
						__in PLUID LogonId,
						__in PWSTR szPassword,
						__out  PSECPKG_PRIMARY_CRED PrimaryCredentials);
// Wipes the password and frees every buffer CompletePrimaryCredential allocated, for a
// logon that fails after the primary credentials were built.
void FreePrimaryCredential(__inout PSECPKG_PRIMARY_CRED PrimaryCredentials);
#endif
