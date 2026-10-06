#include <ntstatus.h>
#define WIN32_NO_STATUS 1  // NOSONAR - MACRO-02: Windows SDK configuration, prevents ntstatus.h conflicts

#include <Windows.h>
#include <assert.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <wincred.h>
#include <NTSecAPI.h>
#include <NTSecPKG.h>
#include <LM.h>
#include <set>
#include <map>
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/CertificateValidation.h"
#include "../EIDCardLibrary/InputValidation.h"
#include "CredentialManagement.h"

#pragma comment(lib,"Winscard")
#pragma comment(lib,"Cryptui")

std::set<CCredential*> Credentials;  // NOSONAR - RUNTIME-01: Credential cache, modified at runtime
std::list<CSecurityContext*> Contexts;  // NOSONAR - RUNTIME-01: Context list, modified at runtime
std::map<ULONG_PTR, CUsermodeContext*> UserModeContexts;  // NOSONAR - RUNTIME-01: Context map, modified at runtime
using Credential_Pair = std::pair<LUID, CCredential*>;

// Critical section for thread-safe access to credential containers (CWE-416 fix for #24)
static CRITICAL_SECTION g_CredentialLock;  // NOSONAR - RUNTIME-01: Critical section, must be mutable

// Static initializer to ensure critical section is initialized before use
class CredentialLockInitializer {  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
public:
    CredentialLockInitializer() { InitializeCriticalSection(&g_CredentialLock); }
    ~CredentialLockInitializer() { DeleteCriticalSection(&g_CredentialLock); }
};
static CredentialLockInitializer g_CredentialLockInit;  // NOSONAR - RUNTIME-01: Initializer, runs at DLL load


CCredential* CCredential::CreateCredential(PLUID LogonIdToUse, PCERT_CREDENTIAL_INFO pCertInfo,PWSTR szPin, ULONG CredentialUseFlags)
{
	CCredential* credential = nullptr;

	if (!LogonIdToUse)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LogonIdToUse NULL");
		return nullptr;
	}

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"new Credential");
	credential = new CCredential(LogonIdToUse,pCertInfo,szPin, CredentialUseFlags);  // NOSONAR - COM-01: Credential lifecycle requires heap allocation

	EnterCriticalSection(&g_CredentialLock);
	Credentials.insert(credential);
	LeaveCriticalSection(&g_CredentialLock);

	return credential;
}

CCredential::CCredential(PLUID LogonIdToUse, PCERT_CREDENTIAL_INFO pCertInfo,PWSTR szPin, ULONG CredentialUseFlags)  // NOSONAR - API-01: signature must match class declaration
{
	if (szPin)
	{
		_dwLen = (DWORD) wcslen(szPin) + 1;
		_szPin = new WCHAR[_dwLen];  // NOSONAR - COM-01: PIN buffer requires heap allocation
		wcscpy_s(_szPin,_dwLen, szPin);
	}
	else
	{
		_dwLen = 0;
		_szPin = nullptr;
	}
	_LogonId = *LogonIdToUse;
	Use = CredentialUseFlags;
	// Zero unconditionally. SpAcquireCredentialsHandle explicitly supports
	// AuthorizationData == NULL, and this array was previously left
	// indeterminate on that path - then copied straight into the negotiate
	// token that BuildNegociateMessage hands back to the caller. That gave any
	// local process 32 fresh bytes of LSASS heap per credential handle: a
	// useful layout oracle for weaponising anything else. A zeroed hash simply
	// matches no stored credential, which is the intended outcome anyway.
	memset(_rgbHashOfCert, 0, sizeof(_rgbHashOfCert));
	// certinfo
	if (pCertInfo)
	{
		// Windows SDK defines CERT_CREDENTIAL_INFO.rgbHashOfCert with the SDK's CERT_HASH_LENGTH (20 bytes for SHA-1)
		// Our internal CERT_HASH_LENGTH is 32 (SHA-256). Only copy what the SDK structure actually contains.
		constexpr size_t SDK_CERT_HASH_LENGTH = 20;
		memset(_rgbHashOfCert, 0, sizeof(_rgbHashOfCert));
		memcpy_s(_rgbHashOfCert, sizeof(_rgbHashOfCert), pCertInfo->rgbHashOfCert, SDK_CERT_HASH_LENGTH);
		_pCertInfo = (PCERT_CREDENTIAL_INFO) EIDAlloc(pCertInfo->cbSize);
		memcpy(_pCertInfo, pCertInfo, pCertInfo->cbSize);
	}
	else
	{
		_pCertInfo = nullptr;
	}

}

CCredential::~CCredential()
{
	if (_szPin)
	{
		SecureZeroMemory(_szPin, _dwLen * sizeof(WCHAR));
		delete[] _szPin;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
	}
	if (_pCertInfo)
	{
		EIDFree(_pCertInfo);
	}
}

BOOL CCredential::Delete(ULONG_PTR phCredential)
{
	CCredential* testedCredential = (CCredential*) phCredential;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	CCredential* toDelete = nullptr;

	EnterCriticalSection(&g_CredentialLock);
	for ( auto iter = Credentials.begin( ); iter != Credentials.end( ); iter++ )
	{
		CCredential* currentCredential = *iter;  // NOSONAR - API-01: non-const pointer retained by design
		if (currentCredential == testedCredential)
		{
			toDelete = testedCredential;
			Credentials.erase(iter);  // Remove from container first
			break;
		}
	}
	LeaveCriticalSection(&g_CredentialLock);

	if (toDelete)
	{
		delete toDelete;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
		return TRUE;
	}
	return FALSE;
}

CCredential* CCredential::GetCredentialFromHandle(ULONG_PTR CredentialHandle)
{
	CCredential* pCredential = (CCredential*) CredentialHandle;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	CCredential* result = nullptr;

	EnterCriticalSection(&g_CredentialLock);
	for ( auto iter = Credentials.begin( ); iter != Credentials.end( ); iter++ )
	{
		CCredential* currentCredential = *iter;
		if (currentCredential == pCredential)
		{
			result = currentCredential;
			break;
		}
	}
	LeaveCriticalSection(&g_CredentialLock);

	if (!result)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCredential = %p not Found",pCredential);
	}
	return result;
}

PTSTR CCredential::GetName()
{
	return nullptr;
}

CSecurityContext* CSecurityContext::CreateContext(CCredential* pCredential)
{
	CSecurityContext* context = nullptr;
	if (!pCredential)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCredential NULL");
		return nullptr;
	}
	context = new CSecurityContext(pCredential);  // NOSONAR - COM-01: Security context requires heap allocation

	EnterCriticalSection(&g_CredentialLock);
	Contexts.push_back(context);
	LeaveCriticalSection(&g_CredentialLock);

	return context;
}


CSecurityContext::CSecurityContext(CCredential* pCredential)
{
	_pCredential = pCredential;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_State = EID_MESSAGE_STATE::EIDMSNone;
	pbChallenge = nullptr;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	pbResponse = nullptr;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	dwChallengeSize = 0;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	dwResponseSize = 0;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	dwRid = 0;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	pCertContext = nullptr;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	szUserName = nullptr;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_Role = EID_CONTEXT_ROLE::EIDCRUnbound;
	_fChallengeIsOurs = FALSE;
	_llExpiry = MAXLONGLONG;
	// DELIBERATELY no certificate lookup here.
	//
	// This used to call FindCertificateFromHash with
	// { _pCertInfo->rgbHashOfCert, CERT_HASH_LENGTH }: our CERT_HASH_LENGTH is
	// 32 but the SDK's CERT_CREDENTIAL_INFO hash is 20 bytes, so it read 12
	// bytes past the client-supplied structure and never matched anything.
	// Correcting the length is NOT safe: FindCertificateFromHash runs in LSASS
	// as SYSTEM, without impersonating the client, and searches the MY store
	// and every reader - a local caller could then select a certificate (and,
	// through BuildResponseMessage, a private key) that it has no access to.
	// Until the lookup and the private-key use are done under client
	// impersonation, pCertContext stays NULL on the initiating side and
	// BuildResponseMessage refuses to sign (SEC_E_UNKNOWN_CREDENTIALS).
	// The accepting side sets pCertContext in BuildChallengeMessage from the
	// stored credential.
}

BOOL CSecurityContext::Delete(ULONG_PTR phContext)
{
	CSecurityContext* testedContext = (CSecurityContext*) phContext;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	CSecurityContext* toDelete = nullptr;

	EnterCriticalSection(&g_CredentialLock);
	for ( auto iter = Contexts.begin( ); iter != Contexts.end( ); iter++ )  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
	{
		CSecurityContext* currentContext = *iter;  // NOSONAR - API-01: non-const pointer retained by design
		if (currentContext == testedContext)
		{
			toDelete = testedContext;
			Contexts.erase(iter);  // Remove from container first
			break;
		}
	}
	LeaveCriticalSection(&g_CredentialLock);

	if (toDelete)
	{
		delete toDelete;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
		return TRUE;
	}
	return FALSE;
}

CSecurityContext* CSecurityContext::GetContextFromHandle(ULONG_PTR context)
{
	CSecurityContext* testedContext = (CSecurityContext*) context;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	CSecurityContext* result = nullptr;

	EnterCriticalSection(&g_CredentialLock);
	for ( auto iter = Contexts.begin( ); iter != Contexts.end( ); iter++ )
	{
		CSecurityContext* currentContext = *iter;
		if (currentContext == testedContext)
		{
			result = currentContext;
			break;
		}
	}
	LeaveCriticalSection(&g_CredentialLock);

	return result;
}

// A context belongs to exactly one side of the handshake. The first dispatcher
// to touch it claims the role; any later attempt to drive it from the other
// side is refused.
//
// Without this, the two dispatchers share one global context list and one
// _State, so an attacker could: AcceptSecurityContext with a negotiate message
// carrying a victim's certificate hash (binding dwRid and generating a server
// challenge), then call InitializeSecurityContext on the SAME handle so
// ReceiveChallengeMessage overwrites that server-generated challenge with
// attacker-chosen bytes - and the verifier would later check a signature over a
// value the attacker picked.
BOOL CSecurityContext::ClaimRole(EID_CONTEXT_ROLE role)
{
	if (_Role == EID_CONTEXT_ROLE::EIDCRUnbound)
	{
		_Role = role;
		return TRUE;
	}
	return _Role == role;
}

NTSTATUS CSecurityContext::InitializeSecurityContextInput(PSecBufferDesc Buffer)
{
	NTSTATUS Status = STATUS_INVALID_SIGNATURE;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	if (!ClaimRole(EID_CONTEXT_ROLE::EIDCRInitiate))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Init   Input  wrong role for this context");
		return SEC_E_INVALID_HANDLE;
	}
	switch (_State)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
	{
		case EID_MESSAGE_STATE::EIDMSNegociate:
			Status = ReceiveChallengeMessage(Buffer);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Init   Input  EIDMSNegociate Status = 0x%08X", Status);
			break;
		default:
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Init   Input  default Status = 0x%08X", Status);
			break;
	}
	return Status;
}
NTSTATUS CSecurityContext::InitializeSecurityContextOutput(PSecBufferDesc Buffer)
{
	NTSTATUS Status = STATUS_INVALID_SIGNATURE;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	if (!ClaimRole(EID_CONTEXT_ROLE::EIDCRInitiate))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Init   Output wrong role for this context");
		return SEC_E_INVALID_HANDLE;
	}
	switch (_State)
	{
		case EID_MESSAGE_STATE::EIDMSNone:
			Status = BuildNegociateMessage(Buffer);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Init   Output EIDMSNone Status = 0x%08X", Status);
			break;
		case EID_MESSAGE_STATE::EIDMSChallenge:
			Status = BuildResponseMessage(Buffer);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Init   Output EIDMSChallenge Status = 0x%08X", Status);
			break;
		default:
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Init   Output default Status = 0x%08X", Status);
			break;
	}
	return Status;
}
NTSTATUS CSecurityContext::AcceptSecurityContextInput(PSecBufferDesc Buffer)
{
	NTSTATUS Status = STATUS_INVALID_SIGNATURE;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	if (!ClaimRole(EID_CONTEXT_ROLE::EIDCRAccept))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Accept Input  wrong role for this context");
		return SEC_E_INVALID_HANDLE;
	}
	switch (_State)
	{
		case EID_MESSAGE_STATE::EIDMSNone:
			Status = ReceiveNegociateMessage(Buffer);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Accept Input  EIDMSNone Status = 0x%08X", Status);
			break;
		case EID_MESSAGE_STATE::EIDMSChallenge:
			Status = ReceiveResponseMessage(Buffer);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Accept Input  EIDMSChallenge Status = 0x%08X", Status);
			break;
		default:
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Accept Input  default Status = 0x%08X", Status);
			break;
	}
	return Status;
}
NTSTATUS CSecurityContext::AcceptSecurityContextOutput(PSecBufferDesc Buffer)
{
	NTSTATUS Status = STATUS_INVALID_SIGNATURE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	if (!ClaimRole(EID_CONTEXT_ROLE::EIDCRAccept))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Accept Output wrong role for this context");
		return SEC_E_INVALID_HANDLE;
	}
	switch (_State)
	{
		case EID_MESSAGE_STATE::EIDMSNegociate:
			Status = BuildChallengeMessage(Buffer);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Accept Output EIDMSNegociate Status = 0x%08X", Status);
			break;
		case EID_MESSAGE_STATE::EIDMSComplete:
			Status = BuildCompleteMessage(Buffer);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Accept Output EIDMSComplete Status = 0x%08X", Status);
			break;
		default:
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Accept Output default Status = 0x%08X", Status);
			break;
	}
	return Status;
}

// A SecBufferDesc arrives from whatever local process called into SSPI. LSASS
// marshals it, but nothing guarantees cBuffers is non-zero or that pBuffers is
// a valid pointer - a caller can submit {cBuffers = 0, pBuffers = NULL}. Every
// entry point below indexes pBuffers[0], so each must establish the descriptor
// first or take an access violation inside LSASS. The SSP dispatch functions
// are wrapped in __finally only, with no __except, so that AV propagates into
// lsasrv and terminates the process.
//
// This helper exists because the guard was first added to only the two
// Receive* functions under review, on the mistaken belief that
// ReceiveNegociateMessage already had it - it checks cbBuffer, which requires
// dereferencing pBuffers[0] to do. That function is the only entry point
// reachable with no established context, i.e. the easiest one to reach.
static bool TokenBufferIsPresent(PSecBufferDesc Buffer)
{
	return Buffer != nullptr
		&& Buffer->pBuffers != nullptr
		&& Buffer->cBuffers != 0
		&& Buffer->pBuffers[0].pvBuffer != nullptr;
}

// SECURITY: what the SSP card actually signs.
//
// The signer (GetResponseFromSignatureChallenge) signs the first 20 bytes of
// the challenge as a raw 160-bit HP_HASHVAL, so the client used to sign whatever
// 20 bytes the peer chose: a signing oracle for the card's key (e.g. over the
// legacy 160-bit hash of a document or of another protocol's transcript). Both ends now
// sign/verify a domain-separated value instead:
//     SHA-256( L"OpenAccessEID-SSP-v1" || cbChallenge || challenge
//              || cbUserName || UserName )   truncated to 20 bytes,
// placed at the start of a zeroed buffer of the original challenge size (the
// verifier insists on CREDENTIALKEYLENGTH bytes and reads the first 20).
// SHA-256 rather than the legacy 160-bit hash: a chosen-prefix collision in that
// hash would let a peer pick a challenge that collides with a message of its choosing; a
// truncated SHA-256 output cannot be steered that way.
// Both ends are this package; a peer running an older build will fail to
// authenticate against this one (and vice versa).
static const WCHAR EID_SSP_SIGNATURE_TAG[] = L"OpenAccessEID-SSP-v1";
constexpr DWORD EID_SSP_SIGNED_DIGEST_LENGTH = 20;	// HP_HASHVAL length (160 bits) used by signer/verifier
constexpr DWORD EID_SSP_SHA256_LENGTH = 32;

static NTSTATUS DeriveSspSignedChallenge(const BYTE* pbChallenge, DWORD cbChallenge, PCWSTR szUserName,
	DWORD cbDerived, PBYTE* ppbDerived)
{
	*ppbDerived = nullptr;
	if (!pbChallenge || cbChallenge == 0 || !szUserName || cbDerived < EID_SSP_SIGNED_DIGEST_LENGTH)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: cannot derive signed challenge (cbChallenge=%u)", cbChallenge);
		return SEC_E_INVALID_TOKEN;
	}
	const size_t cchUserName = wcsnlen(szUserName, UNLEN + 1);
	if (cchUserName > UNLEN || cbChallenge > 0x10000)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: challenge or user name too long");
		return SEC_E_INVALID_TOKEN;
	}
	const DWORD cbTag = static_cast<DWORD>(sizeof(EID_SSP_SIGNATURE_TAG) - sizeof(WCHAR));	// no terminator
	const DWORD cbUserName = static_cast<DWORD>(cchUserName * sizeof(WCHAR));
	const DWORD cbInput = cbTag + sizeof(DWORD) + cbChallenge + sizeof(DWORD) + cbUserName;
	PBYTE pbInput = static_cast<PBYTE>(EIDAlloc(cbInput));
	if (!pbInput)
	{
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	PBYTE p = pbInput;
	memcpy(p, EID_SSP_SIGNATURE_TAG, cbTag);			p += cbTag;
	memcpy(p, &cbChallenge, sizeof(DWORD));			p += sizeof(DWORD);
	memcpy(p, pbChallenge, cbChallenge);				p += cbChallenge;
	memcpy(p, &cbUserName, sizeof(DWORD));				p += sizeof(DWORD);
	memcpy(p, szUserName, cbUserName);
	BYTE rgbDigest[EID_SSP_SHA256_LENGTH] = {0};		// NOSONAR - LSASS-01: fixed-size digest buffer
	DWORD cbDigest = sizeof(rgbDigest);
	const BOOL fHashed = CryptHashCertificate(NULL, CALG_SHA_256, 0, pbInput, cbInput, rgbDigest, &cbDigest);
	const DWORD dwHashError = GetLastError();
	SecureZeroMemory(pbInput, cbInput);
	EIDFree(pbInput);
	if (!fHashed || cbDigest != EID_SSP_SHA256_LENGTH)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptHashCertificate(SHA-256) 0x%08x", dwHashError);
		return SEC_E_INTERNAL_ERROR;
	}
	PBYTE pbDerived = static_cast<PBYTE>(EIDAlloc(cbDerived));
	if (!pbDerived)
	{
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	memset(pbDerived, 0, cbDerived);
	memcpy(pbDerived, rgbDigest, EID_SSP_SIGNED_DIGEST_LENGTH);
	*ppbDerived = pbDerived;
	return STATUS_SUCCESS;
}

NTSTATUS CSecurityContext::BuildNegociateMessage(PSecBufferDesc Buffer)
{
	if (!TokenBufferIsPresent(Buffer))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: empty output descriptor");
		return SEC_E_INVALID_TOKEN;
	}
	Buffer->pBuffers[0].BufferType = SECBUFFER_TOKEN;
	if (Buffer->pBuffers[0].cbBuffer < 300)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INSUFFICIENT_MEMORY");
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	PEID_NEGOCIATE_MESSAGE message = (PEID_NEGOCIATE_MESSAGE) Buffer->pBuffers[0].pvBuffer;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	memset(message, 0, sizeof(EID_NEGOCIATE_MESSAGE));
	static_assert(sizeof(message->Signature) == sizeof(EID_MESSAGE_SIGNATURE), "Signature buffer sizes must match");
	memcpy_s(message->Signature.data(), message->Signature.size(), EID_MESSAGE_SIGNATURE, sizeof(EID_MESSAGE_SIGNATURE));
	message->MessageType = static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTNegociate);  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
	message->Version = EID_MESSAGE_VERSION;
	static_assert(sizeof(Hash) == sizeof(_pCredential->_rgbHashOfCert), "Hash buffer sizes must match");
	memcpy_s(Hash, sizeof(Hash), _pCredential->_rgbHashOfCert, sizeof(Hash));
	memcpy_s(message->Hash.data(), message->Hash.size(), _pCredential->_rgbHashOfCert, message->Hash.size());
	_State = EID_MESSAGE_STATE::EIDMSNegociate;
	return SEC_I_CONTINUE_NEEDED;
}

NTSTATUS CSecurityContext::ReceiveNegociateMessage(PSecBufferDesc Buffer)
{
	if (!TokenBufferIsPresent(Buffer))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: empty buffer descriptor");
		return SEC_E_INVALID_TOKEN;
	}
	if (Buffer->pBuffers[0].cbBuffer < sizeof(EID_NEGOCIATE_MESSAGE))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INSUFFICIENT_MEMORY");
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	PEID_NEGOCIATE_MESSAGE message = (PEID_NEGOCIATE_MESSAGE) Buffer->pBuffers[0].pvBuffer;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	if (message->MessageType != static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTNegociate))  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Incorrect messageType");
		return STATUS_INVALID_SIGNATURE;
	}
	static_assert(sizeof(EID_MESSAGE_SIGNATURE) == sizeof(message->Signature), "Signature buffer sizes must match");
	if (memcmp(EID_MESSAGE_SIGNATURE, message->Signature.data(), message->Signature.size()) != 0)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_INVALID_SIGNATURE");
		return STATUS_INVALID_SIGNATURE;
	}

	static_assert(sizeof(Hash) == sizeof(message->Hash), "Hash buffer sizes must match");
	memcpy_s(Hash, sizeof(Hash), message->Hash.data(), message->Hash.size());
	_State = EID_MESSAGE_STATE::EIDMSNegociate;
	return STATUS_SUCCESS;
}

NTSTATUS CSecurityContext::BuildChallengeMessage(PSecBufferDesc Buffer)
{
	DWORD dwEntriesRead;
	DWORD dwTotalEntries;
	DWORD dwI;
	USER_INFO_3 *pInfo = nullptr;
	NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	__try
	{
		if (!TokenBufferIsPresent(Buffer))
		{
			Status = SEC_E_INVALID_TOKEN;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: empty output descriptor");
			__leave;
		}
		Buffer->pBuffers[0].BufferType = SECBUFFER_TOKEN;
		if (Buffer->pBuffers[0].cbBuffer < 300)
		{
			Status = SEC_E_INSUFFICIENT_MEMORY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INSUFFICIENT_MEMORY");
			__leave;
		}
		PEID_CHALLENGE_MESSAGE message = (PEID_CHALLENGE_MESSAGE) Buffer->pBuffers[0].pvBuffer;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		memset(message, 0, sizeof(EID_CHALLENGE_MESSAGE));
		static_assert(sizeof(message->Signature) == sizeof(EID_MESSAGE_SIGNATURE), "Signature buffer sizes must match");
		memcpy_s(message->Signature.data(), message->Signature.size(), EID_MESSAGE_SIGNATURE, sizeof(EID_MESSAGE_SIGNATURE));
		message->MessageType = static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTChallenge);  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
		message->Version = EID_MESSAGE_VERSION;
		CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
		if (pCertContext)
		{
			CertFreeCertificateContext(pCertContext);
			pCertContext = nullptr;
		}
		if (!manager->GetCertContextFromHash(Hash, &pCertContext, &dwRid))
		{
			Status = SEC_E_UNKNOWN_CREDENTIALS;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_UNKNOWN_CREDENTIALS");
			__leave;
		}
		// get username
		// NetUserEnum returns a NET_API_STATUS (NERR_* / Win32 code), not an
		// NTSTATUS: keep it out of Status and map any failure to an SSPI code.
		const NET_API_STATUS netStatus = NetUserEnum(nullptr, 3, 0, (PBYTE*)&pInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead,&dwTotalEntries, nullptr);
		if (netStatus != NERR_Success)
		{
			Status = SEC_E_INTERNAL_ERROR;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum = 0x%08X",netStatus);
			__leave;
		}
		for (dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			if ( pInfo[dwI].usri3_user_id == dwRid)
			{
				DWORD dwLen= (DWORD)(wcslen(pInfo[dwI].usri3_name)+1);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
				szUserName = (PWSTR) EIDAlloc(dwLen*sizeof(WCHAR));
				if (!szUserName)
				{
					// Must set Status: it is initialised to STATUS_SUCCESS and is
					// now the return value, so an unset failure path would report
					// success with szUserName still null.
					Status = SEC_E_INSUFFICIENT_MEMORY;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No memory");
					__leave;
				}
				wcscpy_s(szUserName, dwLen, pInfo[dwI].usri3_name);
				break;
			}
		}
		if (dwI >= dwEntriesRead)
		{
			Status = SEC_E_INTERNAL_ERROR;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Userid not found");
			__leave;
		}
		if (!manager->GetSignatureChallenge(&pbChallenge, &dwChallengeSize))
		{
			Status = SEC_E_INTERNAL_ERROR;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetSignatureChallenge 0x%08x",GetLastError());
			__leave;
		}
		// The `cbBuffer < 300` test above is a floor, not a bound: what actually
		// gets written is the header plus the challenge plus the username, and
		// nothing checked that against the caller's buffer. Compute the real
		// requirement and refuse rather than overflow the token.
		const DWORD cbChallengeNeeded = static_cast<DWORD>(sizeof(EID_CHALLENGE_MESSAGE)) + dwChallengeSize;
		const DWORD cbUserName = static_cast<DWORD>(wcslen(szUserName)) * static_cast<DWORD>(sizeof(WCHAR));
		if (dwChallengeSize > MAXDWORD - sizeof(EID_CHALLENGE_MESSAGE) ||
			cbUserName > MAXDWORD - cbChallengeNeeded ||
			cbChallengeNeeded + cbUserName > Buffer->pBuffers[0].cbBuffer)
		{
			Status = SEC_E_INSUFFICIENT_MEMORY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Challenge token needs %u bytes, buffer has %u",
				cbChallengeNeeded + cbUserName, Buffer->pBuffers[0].cbBuffer);
			__leave;
		}
		message->ChallengeLen = dwChallengeSize;
		message->ChallengeOffset = sizeof(EID_CHALLENGE_MESSAGE);
		memcpy((PBYTE)message + message->ChallengeOffset, pbChallenge, dwChallengeSize);
		message->UsernameLen = cbUserName;
		message->UsernameOffset = message->ChallengeOffset + message->ChallengeLen;
		memcpy((PBYTE)message + message->UsernameOffset,szUserName,message->UsernameLen);
		Buffer->pBuffers[0].cbBuffer = cbChallengeNeeded + cbUserName;
		_State = EID_MESSAGE_STATE::EIDMSChallenge;
		// This nonce came from GetSignatureChallenge on this context, so it is
		// safe to verify a signature against it later.
		_fChallengeIsOurs = TRUE;
		Status = SEC_I_CONTINUE_NEEDED;
	}
	__finally
	{
		// SEH cleanup - no action needed
	}
	// Return Status, not a hardcoded success. Every __leave above sets a failure
	// code and this function used to discard all of them, so an out-of-memory or
	// undersized-buffer path reported SEC_I_CONTINUE_NEEDED. That was survivable
	// only because _State is not advanced on those paths, so the next call falls
	// through to STATUS_INVALID_SIGNATURE - i.e. correctness depended on a
	// coincidence two functions away. An error path that returns success is one
	// refactor away from being an authentication bypass.
	return Status;
}

NTSTATUS CSecurityContext::ReceiveChallengeMessage(PSecBufferDesc Buffer)
{
	// The token comes from whoever called InitializeSecurityContext, i.e. any
	// local process, and is marshalled into LSASS before we see it. Nothing
	// below may be read until the descriptor and the declared offset/length
	// pairs have been checked - the sibling ReceiveNegociateMessage has always
	// done this; its absence here was an oversight, not a design choice.
	if (!TokenBufferIsPresent(Buffer))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: empty buffer descriptor");
		return SEC_E_INVALID_TOKEN;
	}
	if (!EIDValidateChallengeMessage(Buffer->pBuffers[0].pvBuffer, Buffer->pBuffers[0].cbBuffer))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: challenge layout rejected (cbBuffer=%u)",
			Buffer->pBuffers[0].cbBuffer);
		return SEC_E_INVALID_TOKEN;
	}
	PEID_CHALLENGE_MESSAGE message = (PEID_CHALLENGE_MESSAGE) Buffer->pBuffers[0].pvBuffer;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	if (message->MessageType != static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTChallenge))  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Incorrect messageType");
		return STATUS_INVALID_SIGNATURE;
	}
	static_assert(sizeof(EID_MESSAGE_SIGNATURE) == sizeof(message->Signature), "Signature buffer sizes must match");
	if (memcmp(EID_MESSAGE_SIGNATURE, message->Signature.data(), message->Signature.size()) != 0)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_INVALID_SIGNATURE");
		return STATUS_INVALID_SIGNATURE;
	}

	// EIDValidateChallengeMessage guarantees UsernameLen + sizeof(WCHAR) cannot
	// wrap and that both regions lie inside the token.
	szUserName = (PWSTR) EIDAlloc(message->UsernameLen + sizeof(WCHAR));
	if (!szUserName)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No memory for szUserName");
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	memcpy(szUserName, (PBYTE) message + message->UsernameOffset, message->UsernameLen);
	memset((PBYTE) szUserName + message->UsernameLen,0,sizeof(WCHAR));
	pbChallenge = (PBYTE) EIDAlloc(message->ChallengeLen);
	if (!pbChallenge)
	{
		EIDFree(szUserName);
		szUserName = nullptr;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No memory for pbChallenge");
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	memcpy(pbChallenge, (PBYTE)message + message->ChallengeOffset, message->ChallengeLen);
	dwChallengeSize = message->ChallengeLen;
	// This challenge arrived over the wire. We are the CLIENT here and will sign
	// it, which is fine - but it must never be handed to
	// VerifySignatureChallengeResponse, so mark it as not ours.
	_fChallengeIsOurs = FALSE;
	_State = EID_MESSAGE_STATE::EIDMSChallenge;
	return STATUS_SUCCESS;
}

NTSTATUS CSecurityContext::BuildResponseMessage(PSecBufferDesc Buffer)
{
	if (!TokenBufferIsPresent(Buffer))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: empty output descriptor");
		return SEC_E_INVALID_TOKEN;
	}
	Buffer->pBuffers[0].BufferType = SECBUFFER_TOKEN;
	if (Buffer->pBuffers[0].cbBuffer < 300)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INSUFFICIENT_MEMORY");
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	PEID_RESPONSE_MESSAGE message = (PEID_RESPONSE_MESSAGE) Buffer->pBuffers[0].pvBuffer;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	memset(message, 0, sizeof(EID_RESPONSE_MESSAGE));
	static_assert(sizeof(message->Signature) == sizeof(EID_MESSAGE_SIGNATURE), "Signature buffer sizes must match");
	memcpy_s(message->Signature.data(), message->Signature.size(), EID_MESSAGE_SIGNATURE, sizeof(EID_MESSAGE_SIGNATURE));
	message->MessageType = static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTResponse);  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
	message->Version = EID_MESSAGE_VERSION;
	// No certificate (see the constructor) or no PIN: nothing to sign with.
	// Passing a NULL context on used to fault inside LSASS.
	if (!pCertContext || !_pCredential || !_pCredential->_szPin)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_UNKNOWN_CREDENTIALS: no certificate or PIN for this context");
		return SEC_E_UNKNOWN_CREDENTIALS;
	}
	// Never sign the peer's raw challenge - sign the domain-separated digest.
	PBYTE pbToSign = nullptr;
	NTSTATUS DeriveStatus = DeriveSspSignedChallenge(pbChallenge, dwChallengeSize, szUserName, dwChallengeSize, &pbToSign);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	if (DeriveStatus != STATUS_SUCCESS)
	{
		return DeriveStatus;
	}
	CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
	const BOOL fSigned = manager->GetResponseFromSignatureChallenge(pbToSign, dwChallengeSize, pCertContext,_pCredential->_szPin, &pbResponse, &dwResponseSize);
	SecureZeroMemory(pbToSign, dwChallengeSize);
	EIDFree(pbToSign);
	if (!fSigned)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_LOGON_DENIED");
		return SEC_E_LOGON_DENIED;
	}
	// Same floor-vs-bound problem as BuildChallengeMessage: an RSA-4096 card
	// signature is 512 bytes, so header + response is 536 - well past the 300
	// this function used to treat as sufficient.
	if (dwResponseSize > MAXDWORD - sizeof(EID_RESPONSE_MESSAGE) ||
		sizeof(EID_RESPONSE_MESSAGE) + dwResponseSize > Buffer->pBuffers[0].cbBuffer)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Response token needs %u bytes, buffer has %u",
			static_cast<DWORD>(sizeof(EID_RESPONSE_MESSAGE)) + dwResponseSize, Buffer->pBuffers[0].cbBuffer);
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	message->ResponseLen = dwResponseSize;
	message->ResponseOffset = sizeof(EID_RESPONSE_MESSAGE);
	memcpy((PBYTE)message + message->ResponseOffset, pbResponse, dwResponseSize);
	Buffer->pBuffers[0].cbBuffer = static_cast<DWORD>(sizeof(EID_RESPONSE_MESSAGE)) + dwResponseSize;
	_State = EID_MESSAGE_STATE::EIDMSComplete;
	return STATUS_SUCCESS;
}

NTSTATUS CSecurityContext::ReceiveResponseMessage(PSecBufferDesc Buffer)
{
	// Server side of the same problem: this token arrives from whoever called
	// AcceptSecurityContext against the package registered under
	// HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages.
	if (!TokenBufferIsPresent(Buffer))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: empty buffer descriptor");
		return SEC_E_INVALID_TOKEN;
	}
	if (!EIDValidateResponseMessage(Buffer->pBuffers[0].pvBuffer, Buffer->pBuffers[0].cbBuffer))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: response layout rejected (cbBuffer=%u)",
			Buffer->pBuffers[0].cbBuffer);
		return SEC_E_INVALID_TOKEN;
	}
	PEID_RESPONSE_MESSAGE message = (PEID_RESPONSE_MESSAGE) Buffer->pBuffers[0].pvBuffer;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	if (message->MessageType != static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTResponse))  // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Incorrect messageType");
		return STATUS_INVALID_SIGNATURE;
	}
	static_assert(sizeof(EID_MESSAGE_SIGNATURE) == sizeof(message->Signature), "Signature buffer sizes must match");
	if (memcmp(EID_MESSAGE_SIGNATURE, message->Signature.data(), message->Signature.size()) != 0)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_INVALID_SIGNATURE");
		return STATUS_INVALID_SIGNATURE;
	}

	pbResponse = (PBYTE) EIDAlloc(message->ResponseLen);
	if (!pbResponse)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No memory for pbResponse");
		return SEC_E_INSUFFICIENT_MEMORY;
	}
	dwResponseSize = message->ResponseLen;
	memcpy(pbResponse, (PBYTE)message + message->ResponseOffset, dwResponseSize);
	_State = EID_MESSAGE_STATE::EIDMSComplete;
	return STATUS_SUCCESS;
}

NTSTATUS CSecurityContext::BuildCompleteMessage(PSecBufferDesc Buffer)  // NOSONAR - API-01: signature must match class declaration
{
	// v�rification du challenge
	UNREFERENCED_PARAMETER(Buffer);
	// Only ever verify a signature over a nonce THIS context generated. If the
	// challenge came from the peer, an attacker chose it, and verifying against
	// it turns any captured (challenge, response) pair into a permanent bearer
	// token for that RID - replayable forever, from any process, on any session.
	if (!_fChallengeIsOurs)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN: challenge was not generated by this context");
		return SEC_E_INVALID_TOKEN;
	}
	// Verify against the same domain-separated digest the client signs.
	PBYTE pbSigned = nullptr;
	NTSTATUS DeriveStatus = DeriveSspSignedChallenge(pbChallenge, dwChallengeSize, szUserName, dwChallengeSize, &pbSigned);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	if (DeriveStatus != STATUS_SUCCESS)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_LOGON_DENIED: derive 0x%08X", DeriveStatus);
		return SEC_E_LOGON_DENIED;
	}
	CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
	const BOOL fVerified = manager->VerifySignatureChallengeResponse(dwRid, pbSigned, dwChallengeSize, pbResponse, dwResponseSize);
	SecureZeroMemory(pbSigned, dwChallengeSize);
	EIDFree(pbSigned);
	if (!fVerified)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_LOGON_DENIED");
		return SEC_E_LOGON_DENIED;
	}
	// A valid signature only proves possession of the key in the STORED
	// certificate. Like the interactive logon path, also require that the
	// certificate still chains to a trusted root, carries the smart-card logon
	// EKU, is within validity and is not revoked - otherwise an expired or
	// revoked card keeps producing network logon tokens indefinitely.
	// pCertContext is the stored certificate for dwRid (GetCertContextFromHash
	// in BuildChallengeMessage returns both from the same stored record).
	if (!pCertContext)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_LOGON_DENIED: no stored certificate for rid 0x%x", dwRid);
		return SEC_E_LOGON_DENIED;
	}
	if (!IsTrustedCertificate(pCertContext))
	{
		const DWORD dwTrustError = GetLastError();
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_LOGON_DENIED: untrusted certificate for rid 0x%x (0x%08x)", dwRid, dwTrustError);
		EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_CERT_ERROR] SSP network logon refused for rid 0x%x: untrusted, expired or revoked certificate (0x%08x)", dwRid, dwTrustError);
		return SEC_E_LOGON_DENIED;
	}
	return STATUS_SUCCESS;
}

DWORD CSecurityContext::GetRid()  // NOSONAR - API-01: non-const by design (matches header declaration)
{
	return dwRid;
}

PWSTR CSecurityContext::GetUserName()
{
	if (!szUserName)
		return nullptr;
	DWORD dwLen = (DWORD) wcslen(szUserName) + 1;
	PWSTR szString = (PWSTR) EIDAlloc(dwLen * sizeof(WCHAR));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	if (!szString) return nullptr;
	wcscpy_s(szString,dwLen,szUserName);
	return szString;
}

CSecurityContext::~CSecurityContext()
{
	if (pbChallenge)
	{
		SecureZeroMemory(pbChallenge, dwChallengeSize);
		EIDFree(pbChallenge);
	}
	if (pbResponse)
	{
		SecureZeroMemory(pbResponse, dwResponseSize);
		EIDFree(pbResponse);
	}
	if (szUserName)
	{
		EIDFree(szUserName);
	}
	if (pCertContext)
	{
		CertFreeCertificateContext(pCertContext);
	}
}

CUsermodeContext::CUsermodeContext(PEID_SSP_CALLBACK_MESSAGE pMessage)
{
	Handle = pMessage->hToken;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Token = %p", Handle);
}

NTSTATUS CUsermodeContext::AddContextInfo(ULONG_PTR pHandle, PEID_SSP_CALLBACK_MESSAGE pMessage)
{
	NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	CUsermodeContext* pContext = GetContextFromHandle(pHandle);
	if (!pContext)  // NOSONAR - SCOPE-01: local scoped to block; init-statement refactor deferred
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Inserting context %p", reinterpret_cast<PVOID>(pHandle));
		pContext = new CUsermodeContext(pMessage);  // NOSONAR - COM-01: User mode context requires heap allocation
		UserModeContexts.insert(std::pair<ULONG_PTR,CUsermodeContext*> (pHandle, pContext));
	}
	return Status ;
}

NTSTATUS CUsermodeContext::DeleteContextInfo(ULONG_PTR pHandle)
{
	// C++17 init-statement: it is only used within this if/else block
	if (auto it = UserModeContexts.find(pHandle); it != UserModeContexts.end())
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Context %p deleted", reinterpret_cast<PVOID>(pHandle));
		UserModeContexts.erase(it);
		return STATUS_SUCCESS;
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_HANDLE %p", reinterpret_cast<PVOID>(pHandle));
		return SEC_E_INVALID_HANDLE;
	}
}

NTSTATUS CUsermodeContext::GetImpersonationHandle(ULONG_PTR pHandle,PHANDLE ImpersonationToken)
{
	NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	CUsermodeContext* pContext = GetContextFromHandle(pHandle);
	if (!pContext)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_HANDLE %p", reinterpret_cast<PVOID>(pHandle));
		return SEC_E_INVALID_HANDLE;
	}
	*ImpersonationToken = pContext->Handle;
	return Status ;
}

CUsermodeContext* CUsermodeContext::GetContextFromHandle(ULONG_PTR pHandle)
{
	// C++17 init-statement: it is only used within this if/else block
	if (auto it = UserModeContexts.find(pHandle); it != UserModeContexts.end())
	{
		return (*it).second;
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Context not found = %p", reinterpret_cast<PVOID>(pHandle));
		return nullptr;
	}
}