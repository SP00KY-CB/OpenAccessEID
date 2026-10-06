#ifndef __CREDENTIALMANAGEMENT_H__
#define __CREDENTIALMANAGEMENT_H__

#include <ntstatus.h>
#include <list>

#include "CertificateValidation.h"

// Forward declaration - CCredential is defined below after CSecurityContext
class CCredential;

// Which side of the handshake a context belongs to. A context is created by
// either SpInitLsaModeContext (client) or SpAcceptLsaModeContext (server) and
// must never afterwards be driven by the other side's dispatcher: the two share
// one global context list and one _State, so without this an attacker could
// create a context via AcceptSecurityContext - binding it to a victim's RID -
// and then call InitializeSecurityContext on the same handle to overwrite the
// server's freshly generated challenge with bytes of their own choosing.
enum class EID_CONTEXT_ROLE
{
	EIDCRUnbound,   // created but no message processed yet
	EIDCRInitiate,  // client side: InitializeSecurityContext
	EIDCRAccept,    // server side: AcceptSecurityContext
};

class CSecurityContext
{
public:
	static CSecurityContext* CreateContext(CCredential* pCredential);
	explicit CSecurityContext(CCredential* pCredential);
	CSecurityContext(const CSecurityContext&) = delete;
	CSecurityContext& operator=(const CSecurityContext&) = delete;
	static BOOL Delete(ULONG_PTR pHandle);
	static CSecurityContext* GetContextFromHandle(ULONG_PTR);
	NTSTATUS InitializeSecurityContextInput(PSecBufferDesc);
	NTSTATUS InitializeSecurityContextOutput(PSecBufferDesc);
	NTSTATUS AcceptSecurityContextInput(PSecBufferDesc);
	NTSTATUS AcceptSecurityContextOutput(PSecBufferDesc);
	NTSTATUS BuildNegociateMessage(PSecBufferDesc Buffer);
	NTSTATUS ReceiveNegociateMessage(PSecBufferDesc Buffer);
	NTSTATUS BuildChallengeMessage(PSecBufferDesc Buffer);
	NTSTATUS ReceiveChallengeMessage(PSecBufferDesc Buffer);
	NTSTATUS BuildResponseMessage(PSecBufferDesc Buffer);
	NTSTATUS ReceiveResponseMessage(PSecBufferDesc Buffer);
	NTSTATUS BuildCompleteMessage(PSecBufferDesc Buffer);
	DWORD GetRid();
	// Expiry (UTC FILETIME units) the accepting side clamped this context to;
	// MAXLONGLONG means no limit. Reported by SECPKG_ATTR_LIFESPAN.
	void SetExpiry(LONGLONG llExpiry) { _llExpiry = llExpiry; }
	LONGLONG GetExpiry() const { return _llExpiry; }
	~CSecurityContext();
	PWSTR GetUserName();
private:
	// Returns TRUE if this context may act in the given role, claiming the role
	// on first use. FALSE means the caller is trying to drive a context from the
	// wrong side of the handshake.
	BOOL ClaimRole(EID_CONTEXT_ROLE role);

	CCredential* _pCredential;
	EID_MESSAGE_STATE _State;
	EID_CONTEXT_ROLE _Role;
	// TRUE only when pbChallenge holds a nonce THIS context generated in
	// BuildChallengeMessage. A challenge that arrived over the wire must never
	// be fed to VerifySignatureChallengeResponse: the verifier would then be
	// checking a signature over a value the attacker picked, making any
	// captured (challenge, response) pair a permanent bearer token for that RID.
	BOOL _fChallengeIsOurs;
	UCHAR Hash[CERT_HASH_LENGTH]; // NOSONAR - LSASS-01: C-style buffer for LSASS/crypto hash safety
	PCCERT_CONTEXT pCertContext;
	DWORD dwRid;
	PBYTE pbChallenge;
	DWORD dwChallengeSize;
	PBYTE pbResponse;
	DWORD dwResponseSize;
	PWSTR szUserName;
	LONGLONG _llExpiry;
};

class CCredential  // NOSONAR - OWNERSHIP-01: manual Win32/crypto lifetime management; rule-of-five deferred
{
public:
	CCredential(PLUID LogonIdToUse, PCERT_CREDENTIAL_INFO pCertInfo,PWSTR szPin, ULONG CredentialUseFlags);
	ULONG Use;
	static BOOL Delete(ULONG_PTR pHandle);
	static CCredential* GetCredentialFromHandle(ULONG_PTR);
	std::list<CSecurityContext> _Contexts;
	PTSTR GetName();
	static CCredential* CreateCredential(PLUID LogonIdToUse, PCERT_CREDENTIAL_INFO pCertInfo,PWSTR szPin, ULONG CredentialUseFlags);
	BOOL Check(PLUID LogonId) const  // NOSONAR - API-01: PLUID parameter type dictated by LSA API
	{
		return (LogonId != nullptr) && (_LogonId.HighPart == LogonId->HighPart) && (_LogonId.LowPart == LogonId->LowPart);
	}
	~CCredential();
	LUID _LogonId;
	UCHAR _rgbHashOfCert[CERT_HASH_LENGTH]; // NOSONAR - LSASS-01: C-style buffer for LSASS/crypto hash safety
	PWSTR _szPin;
	DWORD _dwLen;
	PCERT_CREDENTIAL_INFO _pCertInfo;
};

class CUsermodeContext
{
public:
	static NTSTATUS AddContextInfo(ULONG_PTR pHandle, PEID_SSP_CALLBACK_MESSAGE pMessage);
	static NTSTATUS DeleteContextInfo(ULONG_PTR pHandle);
	static NTSTATUS GetImpersonationHandle(ULONG_PTR pHandle,PHANDLE ImpersonationToken);
private:
	static CUsermodeContext* GetContextFromHandle(ULONG_PTR Handle);
	HANDLE Handle;
	explicit CUsermodeContext(PEID_SSP_CALLBACK_MESSAGE pMessage);
};

#endif
