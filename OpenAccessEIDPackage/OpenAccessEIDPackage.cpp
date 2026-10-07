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
#define WIN32_NO_STATUS 1  // NOSONAR - MACRO-02: Windows SDK configuration, prevents ntstatus.h conflicts

#include <Windows.h>

#include <winscard.h>
#include <NTSecAPI.h>


#define SECURITY_WIN32
#include <sspi.h>

#include <NTSecPKG.h>
#include <SubAuth.h>
#include <credentialprovider.h>
#include <wincred.h>

#include <iphlpapi.h>
#include <tchar.h>
#include <LMaccess.h>
#include <lmerr.h>
#include <LM.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CompleteToken.h"
#include "../EIDCardLibrary/CompleteProfile.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/CertificateValidation.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/SmartCardModule.h"
#include "../EIDCardLibrary/CSVLogger.h"
#include "../EIDCardLibrary/CSVConfig.h"


// Package.cpp: allocator used by EIDAlloc/EIDFree for everything handed to LSA.
void SetAlloc(PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap);
void SetFree(PLSA_FREE_LSA_HEAP FreeHeap);

extern "C"
{
	// Save LsaDispatchTable
	extern PLSA_SECPKG_FUNCTION_TABLE MyLsaDispatchTable;  // NOSONAR - RUNTIME-01: LSA dispatch table, set by LSA
	// ref to function

	

	void initializeExportedFunctionsTable();

	// allocate an LSA_STRING from a char*
	PLSA_STRING LsaInitializeString(PCSTR Source)
	{
		size_t Size = strlen(Source);
		PCHAR Buffer = static_cast<PCHAR>(EIDAlloc(static_cast<DWORD>(sizeof(CHAR)*(Size+1))));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (Buffer == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Buffer");
			return NULL;
		}

		PLSA_STRING Destination = static_cast<PLSA_STRING>(EIDAlloc(sizeof(LSA_STRING)));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

		if (Destination == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Destination");
			MyLsaDispatchTable->FreeLsaHeap(Buffer);
			return NULL;
		}

		strncpy_s(Buffer,sizeof(CHAR)*(Size+1),
			Source,sizeof(CHAR)*(Size+1));
		Destination->Length = static_cast<USHORT>(sizeof(CHAR)*Size);
		Destination->MaximumLength = static_cast<USHORT>(sizeof(CHAR)*(Size+1));
		Destination->Buffer = Buffer;
		return Destination;
	}

	PLSA_UNICODE_STRING LsaInitializeUnicodeStringFromWideString(PWSTR Source)  // NOSONAR - API-01: signature dictated by Windows/callback API
	{
		if (Source == NULL)  // STRPTR-01: Validate pointer before wcslen
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Source string is NULL");
			return NULL;
		}
		DWORD Size = static_cast<DWORD>(wcslen(Source));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		// Validate string length won't overflow USHORT fields in LSA_UNICODE_STRING
		if (Size > USHRT_MAX / sizeof(WCHAR))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"String too long for UNICODE_STRING (%d chars)", Size);
			return NULL;
		}
		// BUG-002: Protect against integer overflow in buffer allocation
		if (Size > (MAXDWORD / sizeof(WCHAR)) - 1)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"String size too large for safe allocation (%d chars)", Size);
			return NULL;
		}
		PWSTR Buffer = static_cast<PWSTR>(EIDAlloc((Size + 1) * sizeof(WCHAR)));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (Buffer == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Buffer");
			return NULL;
		}

		PLSA_UNICODE_STRING Destination = static_cast<PLSA_UNICODE_STRING>(EIDAlloc(sizeof(LSA_UNICODE_STRING)));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

		if (Destination == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Destination");
			MyLsaDispatchTable->FreeLsaHeap(Buffer);
			return NULL;
		}

		wcscpy_s(Buffer,Size+1,
			Source);
		Destination->Length = static_cast<USHORT>(Size * sizeof(WCHAR));
		Destination->MaximumLength = static_cast<USHORT>((Size+1) * sizeof(WCHAR));
		Destination->Buffer = Buffer;
		return Destination;
	}

	PLSA_UNICODE_STRING LsaInitializeUnicodeStringFromUnicodeString(UNICODE_STRING Source)
	{
		PLSA_UNICODE_STRING Destination;
		Destination = static_cast<PLSA_UNICODE_STRING>(EIDAlloc(sizeof(LSA_UNICODE_STRING)));
		if (Destination == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Destination");
			return NULL;
		}
		Destination->Buffer = static_cast<WCHAR*>(EIDAlloc(Source.Length+sizeof(WCHAR)));
		if (Destination->Buffer == NULL) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory Destination->Buffer");
			MyLsaDispatchTable->FreeLsaHeap(Destination);
			return NULL;
		}
		Destination->Length = Source.Length;
		Destination->MaximumLength = Source.Length + sizeof(WCHAR);
		memcpy_s(Destination->Buffer,Destination->Length,Source.Buffer,Source.Length);
		Destination->Buffer[Destination->Length/2] = 0;
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Destination OK '%wZ'",Destination);
		return Destination;
	}

	
	// MatchUserOrIsAdmin - Check if the calling client matches the target RID or is an administrator
	// Uses impersonation to lock the client's security context during authorization check
	// This mitigates TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities
	//
	// ORDER MATTERS: the impersonation-level and restricted-token checks run
	// BEFORE the same-user match, and the same-user identity is the user SID
	// of the impersonated thread token - not the SID of the logon session
	// named by ClientInfo.LogonId. A caller impersonating an identification-
	// level token of a victim (for example an S4U token) carries the victim's
	// logon id but must not be able to act as the victim here.
	// pfIsAdmin, when given, is set TRUE only when access was granted because the caller is an
	// administrator (not because it is the account itself).
	BOOL MatchUserOrIsAdmin(__in DWORD dwRid, __out_opt PBOOL pfIsAdmin = nullptr)
	{
		if (pfIsAdmin)
		{
			*pfIsAdmin = FALSE;
		}
		BOOL fReturn = FALSE;
		SECPKG_CLIENT_INFO ClientInfo;
		NTSTATUS status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		DWORD dwError = ERROR_ACCESS_DENIED;
		PSID AdministratorsGroup = NULL;
		HANDLE hImpToken = NULL;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
		BOOL bImpersonating = FALSE;
		BOOL fIsAdmin = FALSE;
		SECURITY_IMPERSONATION_LEVEL ImpersonationLevel = SecurityAnonymous;
		DWORD dwReturnLength = 0;
		PTOKEN_USER pTokenUser = NULL;
		__try
		{
			if (STATUS_SUCCESS != MyLsaDispatchTable->GetClientInfo(&ClientInfo))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetClientInfo");
				__leave;
			}
			// A request that originates inside LSASS itself (for example Netlogon generic
			// pass-through) has no client process whose identity could be checked here.
			if (ClientInfo.ProcessID == GetCurrentProcessId())
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Client is LSASS itself - denying rid 0x%x", dwRid);
				__leave;
			}
			// Refuse restricted callers: the caller was deliberately sandboxed
			// and must not manage or query stored credentials.
			if (ClientInfo.Restricted)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Client token is restricted - denying rid 0x%x", dwRid);
				__leave;
			}
			// If the client was itself impersonating when it called us, refuse an
			// identification/anonymous-level token: a service coerced into making
			// the call on behalf of another user must not inherit that user's
			// identity or rights here.
			if (ClientInfo.Impersonating && ClientInfo.ImpersonationLevel < SecurityImpersonation)
			{
				dwError = ERROR_BAD_IMPERSONATION_LEVEL;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Client impersonation level %d too low - denying", static_cast<int>(ClientInfo.ImpersonationLevel));
				__leave;
			}

			// Impersonate the client to lock their security context
			// This prevents TOCTOU attacks where privileges change between check and use
			// FAIL CLOSED: without the client's thread token there is no
			// trustworthy identity to compare against.
			status = MyLsaDispatchTable->ImpersonateClient();
			if (status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ImpersonateClient 0x%08x - denying", status);
				__leave;
			}
			bImpersonating = TRUE;

			// OpenAsSelf = TRUE: open the token with LSASS's own rights, not the
			// (impersonated) client's, which may not be allowed to query it.
			if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hImpToken))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OpenThreadToken 0x%08x",dwError);
				__leave;
			}
			if (!GetTokenInformation(hImpToken, TokenImpersonationLevel, &ImpersonationLevel, sizeof(ImpersonationLevel), &dwReturnLength))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetTokenInformation(TokenImpersonationLevel) 0x%08x",dwError);
				__leave;
			}
			// A client that was itself impersonating must hand us a full
			// impersonation token (checked above via ClientInfo as well). A
			// direct caller's token is only read here (user SID and group
			// membership), which works at identification level, so accept that
			// rather than deny every caller should the LSA channel's QoS only
			// grant SecurityIdentification.
			if (ImpersonationLevel < (ClientInfo.Impersonating ? SecurityImpersonation : SecurityIdentification))
			{
				dwError = ERROR_BAD_IMPERSONATION_LEVEL;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Impersonation level %d too low - denying", static_cast<int>(ImpersonationLevel));
				__leave;
			}
			if (IsTokenRestricted(hImpToken))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Impersonation token is restricted - denying rid 0x%x", dwRid);
				__leave;
			}

			// User SID of the impersonated client token.
			dwReturnLength = 0;
			if (!GetTokenInformation(hImpToken, TokenUser, NULL, 0, &dwReturnLength)
				&& GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetTokenInformation(TokenUser) size 0x%08x",dwError);
				__leave;
			}
			if (dwReturnLength < sizeof(TOKEN_USER))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetTokenInformation(TokenUser) size %u too small", dwReturnLength);
				__leave;
			}
			pTokenUser = static_cast<PTOKEN_USER>(EIDAlloc(dwReturnLength));
			if (!pTokenUser)
			{
				dwError = ERROR_NOT_ENOUGH_MEMORY;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc TOKEN_USER");
				__leave;
			}
			if (!GetTokenInformation(hImpToken, TokenUser, pTokenUser, dwReturnLength, &dwReturnLength))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetTokenInformation(TokenUser) 0x%08x",dwError);
				__leave;
			}
			if (pTokenUser->User.Sid == NULL || !IsValidSid(pTokenUser->User.Sid))
			{
				dwError = ERROR_ACCESS_DENIED;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Token user SID invalid - denying");
				__leave;
			}

			// Compare the WHOLE SID, not just the trailing RID.
			//
			// The previous check was
			//     dwRid == *GetSidSubAuthority(Sid, *GetSidSubAuthorityCount(Sid) - 1)
			// which discards the issuing domain entirely. On a domain-joined
			// host CONTOSO\alice with RID 1105 therefore satisfied the check for
			// the LOCAL account with RID 1105, and this function is what
			// authorises EIDCMCreateStoredCredential /
			// EIDCMRemoveStoredCredential / EIDCMHasStoredCredential against a
			// given RID - so an unrelated principal could remove another local
			// user's stored credential and deny them logon.
			//
			// dwRid always names a LOCAL account here (the credential store is
			// keyed by local RID), so build the local account SID from this
			// machine's account-domain SID and compare exactly. LSA policy is
			// queried locally; nothing here touches the network, which matters
			// for the air-gapped deployments this product targets.
			{
				LSA_OBJECT_ATTRIBUTES ObjectAttributes;
				ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
				LSA_HANDLE hPolicy = nullptr;
				if (STATUS_SUCCESS != LsaOpenPolicy(nullptr, &ObjectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy))
				{
					dwError = ERROR_ACCESS_DENIED;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaOpenPolicy failed; denying");
					__leave;
				}
				PPOLICY_ACCOUNT_DOMAIN_INFO pDomainInfo = nullptr;
				const NTSTATUS queryStatus = LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation,
					reinterpret_cast<PVOID*>(&pDomainInfo));
				LsaClose(hPolicy);
				if (queryStatus != STATUS_SUCCESS || !pDomainInfo || !pDomainInfo->DomainSid)
				{
					if (pDomainInfo) LsaFreeMemory(pDomainInfo);
					dwError = ERROR_ACCESS_DENIED;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaQueryInformationPolicy failed; denying");
					__leave;
				}

				// Local account SID = account-domain SID with dwRid appended.
				const UCHAR ucDomainSubAuthorities = *GetSidSubAuthorityCount(pDomainInfo->DomainSid);
				BOOL fIsSameUser = FALSE;
				if (ucDomainSubAuthorities < SID_MAX_SUB_AUTHORITIES)
				{
					const DWORD cbAccountSid = GetSidLengthRequired(static_cast<UCHAR>(ucDomainSubAuthorities + 1));
					PSID pAccountSid = static_cast<PSID>(EIDAlloc(cbAccountSid));
					if (pAccountSid)
					{
						if (InitializeSid(pAccountSid, GetSidIdentifierAuthority(pDomainInfo->DomainSid),
								static_cast<BYTE>(ucDomainSubAuthorities + 1)))
						{
							for (UCHAR i = 0; i < ucDomainSubAuthorities; i++)
							{
								*GetSidSubAuthority(pAccountSid, i) = *GetSidSubAuthority(pDomainInfo->DomainSid, i);
							}
							*GetSidSubAuthority(pAccountSid, ucDomainSubAuthorities) = dwRid;
							fIsSameUser = EqualSid(pAccountSid, pTokenUser->User.Sid);
						}
						EIDFree(pAccountSid);
					}
				}
				LsaFreeMemory(pDomainInfo);

				if (fIsSameUser)
				{
					// is current user = TRUE
					dwError = 0;
					fReturn = TRUE;
					__leave;
				}
			}
			// is admin ?
			//
			// FAIL CLOSED: fReturn is still FALSE here and is set TRUE only on a
			// positive membership result below. The previous code stored the
			// AllocateAndInitializeSid result in fReturn, so any later failure
			// (OpenTokenByLogonId, CheckTokenMembership) __leave'd with TRUE and
			// granted access. It also checked membership on the logon session's
			// token from OpenTokenByLogonId, which may be a primary token -
			// CheckTokenMembership requires an impersonation token and so could
			// fail on every call, i.e. every caller was an "administrator".
			//
			// Check the CLIENT's effective identity instead: the thread
			// impersonation token obtained through ImpersonateClient above,
			// whose level was verified to be >= SecurityImpersonation. A
			// UAC-filtered administrator carries Administrators as deny-only in
			// that token, which CheckTokenMembership reports as not a member.
			dwError = ERROR_ACCESS_DENIED;
			SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
			if (!AllocateAndInitializeSid(&NtAuthority,
						2,
						SECURITY_BUILTIN_DOMAIN_RID,
						DOMAIN_ALIAS_RID_ADMINS,
						0, 0, 0, 0, 0, 0,
						&AdministratorsGroup))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AllocateAndInitializeSid 0x%08x",dwError);
				__leave;
			}
			if (!CheckTokenMembership(hImpToken, AdministratorsGroup, &fIsAdmin))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CheckTokenMembership 0x%08x",dwError);
				__leave;
			}
			if (fIsAdmin)
			{
				dwError = 0;
				fReturn = TRUE;
				if (pfIsAdmin)
				{
					*pfIsAdmin = TRUE;
				}
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Access denied for rid 0x%x", dwRid);
			}
		}
		__finally
		{
			// Revert impersonation before cleanup
			if (bImpersonating)
			{
				RevertToSelf();
			}
			if (hImpToken) CloseHandle(hImpToken);
			if (pTokenUser) EIDFree(pTokenUser);
			if (AdministratorsGroup) FreeSid(AdministratorsGroup);
		}
		SetLastError(dwError);
		return fReturn;
	}


	NTSTATUS NTAPI LsaApInitializePackage(
	  __in      ULONG AuthenticationPackageId,
	  __in      PLSA_DISPATCH_TABLE LsaDispatchTable,
	  __in_opt  PLSA_STRING Database,  // NOSONAR - API-01: signature dictated by Windows/callback API
	  __in_opt  PLSA_STRING Confidentiality,  // NOSONAR - API-01: signature dictated by Windows/callback API
	  __out     PLSA_STRING *AuthenticationPackageName
	) {
		UNREFERENCED_PARAMETER(AuthenticationPackageId);
		UNREFERENCED_PARAMETER(Database);
		UNREFERENCED_PARAMETER(Confidentiality);

		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"AuthenticationPackageName = %S",AUTHENTICATIONPACKAGENAME);
		NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit

		MyLsaDispatchTable = reinterpret_cast<PLSA_SECPKG_FUNCTION_TABLE>(LsaDispatchTable);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
		// Everything this package hands to LSA must come from the LSA heap. SpInitialize sets
		// these too when the DLL is also loaded as a security package; set them here as well so
		// the authentication package never depends on that. (LSA_DISPATCH_TABLE has the heap
		// routines; ImpersonateClient is only in the SSP function table.)
		if (LsaDispatchTable)
		{
			SetAlloc(LsaDispatchTable->AllocateLsaHeap);
			SetFree(LsaDispatchTable->FreeLsaHeap);
		}

		*AuthenticationPackageName = LsaInitializeString(AUTHENTICATIONPACKAGENAME);

		// CSV logging initializes itself on first use via the INIT_ONCE inside
		// EIDCardLibraryLogStructured; calling EID_CSV_Initialize() here as well only
		// closed and reopened the log file.
		EIDCardLibraryLogStructured(
			EID_EVENT_ID::LSA_PACKAGE_INIT,
			EID_SEVERITY::INFO,
			EID_OUTCOME::SUCCESS,
			nullptr,
			L"LSA Package",
			L"Authentication package initialized"
		);

		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		// don't fail
		Status = STATUS_SUCCESS;
		return Status;
	}



	/** Called when the authentication package's identifier has been specified in a call
	to LsaCallAuthenticationPackage by an application using an untrusted connection. 
	This function is used for communicating with processes that do not have the SeTcbPrivilege privilege.*/

	// SECURITY helper: the untrusted call-package buffer is fully attacker-controlled, including
	// the embedded pointer fields (wszPassword/pbCertificate) and the ClientBufferBase used to
	// rebase them. Validate that a rebased pointer's [offset, offset+size) range lies entirely
	// within the SubmitBufferLength-sized copy before dereferencing it. Returns the in-bounds
	// server-side pointer, or nullptr if out of bounds. Overflow-safe.
	static PBYTE RebaseAndBoundCheck(PVOID clientPtr, PVOID clientBufferBase, PVOID serverBuffer, ULONG size, ULONG submitBufferLength)  // NOSONAR - COMPLEXITY-01: bounds-check helper
	{
		ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(clientPtr) - reinterpret_cast<ULONG_PTR>(clientBufferBase);
		if (offset > submitBufferLength)			// start out of range (also catches pointer < base underflow)
			return nullptr;
		if (size > submitBufferLength - offset)		// end out of range (submitBufferLength - offset cannot underflow here)
			return nullptr;
		return reinterpret_cast<PBYTE>(serverBuffer) + offset;
	}

	// As above, for a NUL-terminated wide string: also require the terminator to be inside the buffer.
	static PWSTR RebaseWStringAndBoundCheck(PVOID clientPtr, PVOID clientBufferBase, PVOID serverBuffer, ULONG submitBufferLength)
	{
		PBYTE start = RebaseAndBoundCheck(clientPtr, clientBufferBase, serverBuffer, sizeof(WCHAR), submitBufferLength);
		if (!start)
			return nullptr;
		PBYTE bufEnd = reinterpret_cast<PBYTE>(serverBuffer) + submitBufferLength;
		for (PBYTE p = start; p + sizeof(WCHAR) <= bufEnd; p += sizeof(WCHAR))
		{
			if (*reinterpret_cast<const WCHAR*>(p) == L'\0')
				return reinterpret_cast<PWSTR>(start);
		}
		return nullptr;									// not NUL-terminated within the buffer
	}

	NTSTATUS NTAPI LsaApCallPackageUntrusted(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   PVOID ProtocolSubmitBuffer,
	  __in   PVOID ClientBufferBase,
	  __in   ULONG SubmitBufferLength,
	  __out  PVOID *ProtocolReturnBuffer,
	  __out  PULONG ReturnBufferLength,  // NOSONAR - API-01: signature dictated by Windows/callback API
	  __out  PNTSTATUS ProtocolStatus
	) 
	{
		PBYTE pPointer;
		BOOL fStatus;
		NTSTATUS status = STATUS_INVALID_MESSAGE;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		NTSTATUS statusError;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		PCCERT_CONTEXT pCertContext = NULL;
		PWSTR szUsername = NULL;
		PWSTR pwszPasswordToWipe = NULL;
		BOOL fCallerIsAdmin = FALSE;
		UNREFERENCED_PARAMETER(ClientRequest);
		__try
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
			*ProtocolStatus = STATUS_SUCCESS;
			// No message returns a buffer: results go back through CopyToClientBuffer.
			*ProtocolReturnBuffer = NULL;
			*ReturnBufferLength = 0;
			// SECURITY: an untrusted caller controls the whole submit buffer; reject any buffer
			// too small to hold the fixed message header before touching any field.
			if (SubmitBufferLength < sizeof(EID_CALLPACKAGE_BUFFER))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SubmitBufferLength 0x%x smaller than message header - rejecting",SubmitBufferLength);
				EIDSecurityAudit(SECURITY_AUDIT_WARNING, L"[IPC_REJECT] Rejected undersized untrusted call-package buffer (0x%x bytes) - possible probing of the LSA package", SubmitBufferLength);
				return STATUS_INVALID_PARAMETER;
			}
			PEID_CALLPACKAGE_BUFFER pBuffer = static_cast<PEID_CALLPACKAGE_BUFFER>(ProtocolSubmitBuffer);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
			pBuffer->dwError = 0;
			// The cases below call through the manager without checking it.
			if (!CStoredCredentialManager::Instance())
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"manager NULL");
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			
			switch (pBuffer->MessageType)
			{
			case EIDCMCreateStoredCredential:
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMCreateStoredCredential");
				if (!MatchUserOrIsAdmin(pBuffer->dwRid, &fCallerIsAdmin))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not authorized");
					break;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Has Authorization for rid = 0x%x", pBuffer->dwRid);
				// SECURITY: validate & rebase client-supplied embedded pointers against the submit
				// buffer before use, so a hostile caller cannot point them at arbitrary LSASS memory.
				pPointer = reinterpret_cast<PBYTE>(RebaseWStringAndBoundCheck(pBuffer->wszPassword, ClientBufferBase, pBuffer, SubmitBufferLength));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
				if (!pPointer)
				{
					pBuffer->dwError = ERROR_INVALID_PARAMETER;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"wszPassword offset/length out of bounds - rejecting");
					EIDSecurityAudit(SECURITY_AUDIT_WARNING, L"[IPC_REJECT] Rejected out-of-bounds wszPassword pointer in untrusted call-package (rid 0x%x)", pBuffer->dwRid);
					break;
				}
				pBuffer->wszPassword = reinterpret_cast<PWSTR>(pPointer);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
				// Wiped from this LSASS copy of the request once the message is handled.
				pwszPasswordToWipe = pBuffer->wszPassword;
				pPointer = RebaseAndBoundCheck(pBuffer->pbCertificate, ClientBufferBase, pBuffer, pBuffer->dwCertificateSize, SubmitBufferLength);
				if (!pPointer)
				{
					pBuffer->dwError = ERROR_INVALID_PARAMETER;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pbCertificate offset/size out of bounds - rejecting");
					EIDSecurityAudit(SECURITY_AUDIT_WARNING, L"[IPC_REJECT] Rejected out-of-bounds pbCertificate pointer in untrusted call-package (rid 0x%x)", pBuffer->dwRid);
					break;
				}
				pBuffer->pbCertificate = pPointer;
				// SECURITY: the stored-credential blob uses USHORT offsets/sizes; an oversized
				// certificate used to wrap the secret size and overflow the LSASS heap.
				if (static_cast<DWORD>(pBuffer->dwCertificateSize) > EID_MAX_CERTIFICATE_SIZE)
				{
					pBuffer->dwError = ERROR_INVALID_PARAMETER;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pbCertificate too large (0x%x bytes) - rejecting", pBuffer->dwCertificateSize);
					EIDSecurityAudit(SECURITY_AUDIT_WARNING, L"[IPC_REJECT] Rejected oversized certificate (0x%x bytes) in untrusted call-package (rid 0x%x)", pBuffer->dwCertificateSize, pBuffer->dwRid);
					break;
				}
				pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pBuffer->pbCertificate, pBuffer->dwCertificateSize);
				if (!pCertContext)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x", pBuffer->dwError);
					break;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Certificate created in memory");
				// SECURITY: a caller enrolling their own account must prove they hold the
				// certificate's key; certificates are public, so without this anyone could bind
				// someone else's certificate to their own account before its owner enrols it.
				if (!fCallerIsAdmin)
				{
					pPointer = (pBuffer->usEnrolmentSignatureSize != 0)
						? RebaseAndBoundCheck(pBuffer->pbEnrolmentSignature, ClientBufferBase, pBuffer, pBuffer->usEnrolmentSignatureSize, SubmitBufferLength)
						: NULL;
					if (!pPointer || !EIDVerifyEnrolmentProof(pBuffer->dwRid, pCertContext, &pBuffer->ftEnrolmentTime, pPointer, pBuffer->usEnrolmentSignatureSize))
					{
						pBuffer->dwError = NTE_BAD_SIGNATURE;
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"enrolment proof of possession missing or invalid - rejecting");
						EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[ENROL_REJECT] Refused to enrol a certificate for rid 0x%x: no valid proof that the caller holds its key", pBuffer->dwRid);
						status = STATUS_SUCCESS;
						CertFreeCertificateContext(pCertContext);
						pCertContext = NULL;
						break;
					}
				}
				fStatus = CStoredCredentialManager::Instance()->CreateCredential(pBuffer->dwRid,pCertContext,pBuffer->wszPassword, 0, pBuffer->fEncryptPassword, TRUE);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08X",pBuffer->dwError);
				}
				status = STATUS_SUCCESS;
				CertFreeCertificateContext(pCertContext);
				pCertContext = NULL;
				break;
			case EIDCMRemoveStoredCredential:
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMRemoveStoredCredential");
				if (!MatchUserOrIsAdmin(pBuffer->dwRid))
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not authorized");
					break;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Has Authorization for rid = 0x%x", pBuffer->dwRid);
				fStatus = CStoredCredentialManager::Instance()->RemoveStoredCredential(pBuffer->dwRid);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08X",pBuffer->dwError);
				}
				status = STATUS_SUCCESS;
				break;
			case EIDCMHasStoredCredential:
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMHasStoredCredential");
				if (!MatchUserOrIsAdmin(pBuffer->dwRid))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not authorized");
					break;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Has Authorization for rid = 0x%x", pBuffer->dwRid);
				fStatus = CStoredCredentialManager::Instance()->HasStoredCredential(pBuffer->dwRid);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
					if (pBuffer->dwError == 0)
					{
						pBuffer->dwError = ERROR_NOT_FOUND;
					}
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08X",pBuffer->dwError);
				}
				status = STATUS_SUCCESS;
				break;
			case EIDCMRemoveAllStoredCredential:
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMRemoveAllStoredCredential");
				if (!MatchUserOrIsAdmin(0))
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not authorized");
					break;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Has Authorization for rid = 0x%x", pBuffer->dwRid);
				fStatus = CStoredCredentialManager::Instance()->RemoveAllStoredCredential();
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08X",pBuffer->dwError);
				}
				// tried to unload the package, but according to MS source code,
				// this function can only be called when the initialisation is in progress
				// it trigger an NT exception 0x80090316 (SEC_E_BAD_PKGID)
				status = STATUS_SUCCESS;
				break;
			case EIDCMGetStoredCredentialRid:
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDCMGetStoredCredentialRid");
				if (!MatchUserOrIsAdmin(0))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not authorized");
					break;
				}
				pPointer = RebaseAndBoundCheck(pBuffer->pbCertificate, ClientBufferBase, pBuffer, pBuffer->dwCertificateSize, SubmitBufferLength);
				if (!pPointer)
				{
					pBuffer->dwError = ERROR_INVALID_PARAMETER;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pbCertificate offset/size out of bounds - rejecting");
					EIDSecurityAudit(SECURITY_AUDIT_WARNING, L"[IPC_REJECT] Rejected out-of-bounds pbCertificate pointer in untrusted call-package (rid 0x%x)", pBuffer->dwRid);
					break;
				}
				pBuffer->pbCertificate = pPointer;
				pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pBuffer->pbCertificate, pBuffer->dwCertificateSize);
				if (!pCertContext)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x", pBuffer->dwError);
					break;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Certificate created in memory");
				fStatus = CStoredCredentialManager::Instance()->GetUsernameFromCertContext(pCertContext, &szUsername, &pBuffer->dwRid);
				if (!fStatus)
				{
					pBuffer->dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08X",pBuffer->dwError);
					status = STATUS_SUCCESS;
				}
				else
				{
					EIDFree(szUsername);
					status = STATUS_SUCCESS;
				}
				CertFreeCertificateContext(pCertContext);
				pCertContext = NULL;
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"copy back");
				// copy error back to original buffer
				MyLsaDispatchTable->CopyToClientBuffer(ClientRequest, sizeof(DWORD), ((PBYTE)&(pBuffer->dwRid))  + (ULONG_PTR) ClientBufferBase - (ULONG_PTR) pBuffer, &(pBuffer->dwRid));
				break;
			
			default:
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Invalid message %d",pBuffer->MessageType);
			}
			if (pwszPasswordToWipe)
			{
				// Bounded: RebaseWStringAndBoundCheck found its terminator inside the buffer.
				SecureZeroMemory(pwszPasswordToWipe, wcslen(pwszPasswordToWipe) * sizeof(WCHAR));
				pwszPasswordToWipe = NULL;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Done in LSA memory - preparing response");
			// copy error back to original buffer
			statusError= MyLsaDispatchTable->CopyToClientBuffer(ClientRequest, sizeof(DWORD), ((PBYTE)&(pBuffer->dwError))  + (ULONG_PTR) ClientBufferBase - (ULONG_PTR) pBuffer, &(pBuffer->dwError));
			if (STATUS_SUCCESS != statusError )
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyToClientBuffer failed");
			}
			
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"return 0x%08X",status);
			return status;
		}
		__except(EIDExceptionHandler(GetExceptionInformation()))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"NT exception in LsaApCallPackageUntrusted: 0x%08x",GetExceptionCode());
			EIDLogStackTrace(GetExceptionCode());
			return STATUS_LOGON_FAILURE;
		}
	}

	// SECURITY: issued-challenge table for the GINA challenge/response pair.
	//
	// PerformGinaAuthenticationResponse used to verify the response against
	// whatever challenge the caller submitted alongside it, so a captured
	// (challenge, response) pair could be replayed indefinitely. The challenge
	// handler now records each challenge it hands out, per RID, and the response
	// handler accepts only a challenge that was issued here, at most
	// EID_GINA_CHALLENGE_LIFETIME_MS ago, and only once.
	constexpr DWORD EID_GINA_CHALLENGE_SLOTS = 16;
	constexpr DWORD EID_GINA_MAX_CHALLENGE_SIZE = 1024;	// RSA-8192 wrapped key
	constexpr ULONGLONG EID_GINA_CHALLENGE_LIFETIME_MS = 60 * 1000;

	struct EID_GINA_ISSUED_CHALLENGE
	{
		BOOL fInUse;
		DWORD dwRid;
		DWORD dwChallengeType;
		ULONGLONG ullIssuedTick;
		DWORD dwChallengeSize;
		BYTE rgbChallenge[EID_GINA_MAX_CHALLENGE_SIZE];  // NOSONAR - LSASS-01: fixed buffer, no allocation under the lock
	};

	static EID_GINA_ISSUED_CHALLENGE s_GinaChallenges[EID_GINA_CHALLENGE_SLOTS];  // NOSONAR - RUNTIME-01: guarded by s_GinaChallengeLock
	static SRWLOCK s_GinaChallengeLock = SRWLOCK_INIT;  // NOSONAR - RUNTIME-01: lock for s_GinaChallenges

	static void GinaWipeChallengeSlot(EID_GINA_ISSUED_CHALLENGE* pSlot)
	{
		SecureZeroMemory(pSlot, sizeof(EID_GINA_ISSUED_CHALLENGE));
	}

	// Record a challenge issued for dwRid, replacing any earlier one for the same
	// RID. Returns FALSE (and records nothing) if the challenge cannot be stored.
	static BOOL GinaRecordIssuedChallenge(DWORD dwRid, DWORD dwChallengeType, const BYTE* pbChallenge, DWORD dwChallengeSize)
	{
		if (!pbChallenge || dwChallengeSize == 0 || dwChallengeSize > EID_GINA_MAX_CHALLENGE_SIZE)
		{
			return FALSE;
		}
		const ULONGLONG ullNow = GetTickCount64();
		AcquireSRWLockExclusive(&s_GinaChallengeLock);
		EID_GINA_ISSUED_CHALLENGE* pTarget = nullptr;
		EID_GINA_ISSUED_CHALLENGE* pOldest = &s_GinaChallenges[0];
		for (DWORD i = 0; i < EID_GINA_CHALLENGE_SLOTS; i++)
		{
			EID_GINA_ISSUED_CHALLENGE* pSlot = &s_GinaChallenges[i];
			if (pSlot->fInUse && ullNow - pSlot->ullIssuedTick > EID_GINA_CHALLENGE_LIFETIME_MS)
			{
				GinaWipeChallengeSlot(pSlot);	// expired
			}
			if (pSlot->fInUse && pSlot->dwRid == dwRid)
			{
				pTarget = pSlot;				// one outstanding challenge per RID
				break;
			}
			if (!pSlot->fInUse && !pTarget)
			{
				pTarget = pSlot;
			}
			if (pSlot->fInUse && (!pOldest->fInUse || pSlot->ullIssuedTick < pOldest->ullIssuedTick))
			{
				pOldest = pSlot;
			}
		}
		if (!pTarget)
		{
			pTarget = pOldest;					// table full: evict the oldest
		}
		GinaWipeChallengeSlot(pTarget);
		pTarget->fInUse = TRUE;
		pTarget->dwRid = dwRid;
		pTarget->dwChallengeType = dwChallengeType;
		pTarget->ullIssuedTick = ullNow;
		pTarget->dwChallengeSize = dwChallengeSize;
		memcpy(pTarget->rgbChallenge, pbChallenge, dwChallengeSize);
		ReleaseSRWLockExclusive(&s_GinaChallengeLock);
		return TRUE;
	}

	// Consume the challenge recorded for dwRid. Returns TRUE only if one was
	// issued, has not expired, and equals the submitted type and bytes
	// (constant-time compare). The record is removed whatever the outcome:
	// single use.
	static BOOL GinaConsumeIssuedChallenge(DWORD dwRid, DWORD dwChallengeType, const BYTE* pbChallenge, DWORD dwChallengeSize)
	{
		BOOL fMatch = FALSE;
		const ULONGLONG ullNow = GetTickCount64();
		AcquireSRWLockExclusive(&s_GinaChallengeLock);
		for (DWORD i = 0; i < EID_GINA_CHALLENGE_SLOTS; i++)
		{
			EID_GINA_ISSUED_CHALLENGE* pSlot = &s_GinaChallenges[i];
			if (!pSlot->fInUse || pSlot->dwRid != dwRid)
			{
				continue;
			}
			if (pbChallenge && ullNow - pSlot->ullIssuedTick <= EID_GINA_CHALLENGE_LIFETIME_MS &&
				dwChallengeType == pSlot->dwChallengeType && dwChallengeSize == pSlot->dwChallengeSize)
			{
				BYTE bDiff = 0;
				for (DWORD j = 0; j < dwChallengeSize; j++)
				{
					bDiff |= static_cast<BYTE>(pSlot->rgbChallenge[j] ^ pbChallenge[j]);
				}
				fMatch = (bDiff == 0);
			}
			GinaWipeChallengeSlot(pSlot);
			break;
		}
		ReleaseSRWLockExclusive(&s_GinaChallengeLock);
		return fMatch;
	}

	NTSTATUS NTAPI PerformGinaAuthenticationChallenge(
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   PVOID ProtocolSubmitBuffer,
	  __in   PVOID ClientBufferBase,
	  __in   ULONG SubmitBufferLength,
	  __out  PVOID *ProtocolReturnBuffer,
	  __out  PULONG ReturnBufferLength,
	  __out  PNTSTATUS ProtocolStatus  // NOSONAR - API-01: signature dictated by Windows/callback API
	  ) 
	{
		UNREFERENCED_PARAMETER(ProtocolStatus);
		UNREFERENCED_PARAMETER(ClientBufferBase);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS StatusReturned = STATUS_SUCCESS;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		PEID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST pGina = static_cast<PEID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST>(ProtocolSubmitBuffer);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		PBYTE pbChallenge = NULL;
		DWORD dwChallengeSize = 0;
		DWORD dwType = 0;
		EID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER response = {0};
		memset(&response, 0, sizeof(EID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER));
		if (SubmitBufferLength < sizeof(EID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SubmitBufferLength");
			return STATUS_INVALID_PARAMETER;
		}
		__try
		{
			// go look for the password stored
			CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
			if (!manager)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"manager NULL");
				response.dwError = ERROR_INTERNAL_ERROR;
				__leave;
			}
			// check the PIN if using the base smart card provider to get the remaining pin attempts
			// put the result in SubStatus
						
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RID = 0x%x", pGina->dwRid);
			// the real job is done here
			if (!manager->GetChallenge(pGina->dwRid,&pbChallenge, &dwChallengeSize, &dwType))
			{
				response.dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"GetChallenge 0x%08X", response.dwError);
				__leave;
			}
			// SECURITY: GINA authentication is refused for crypted (card-bound)
			// credentials. Their "challenge" is the static wrapped symmetric key,
			// so a captured response (the unwrapped key) stays valid forever,
			// and the GINA protocol (EID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST)
			// has a single response field - no room for the proof-of-possession
			// signature over a fresh nonce that GetPassword performs for this
			// type. Without that signature a card answering the decrypt with
			// garbage or a replayed key cannot be told apart from the real one.
			// Crypted credentials must be used through the credential provider
			// path instead; clear-text and DPAPI types are unaffected (their
			// GINA challenge is already a fresh signature nonce).
			if (dwType == static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtCrypted))  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
			{
				response.dwError = ERROR_NOT_SUPPORTED;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GINA authentication not supported for crypted credential (rid 0x%x)", pGina->dwRid);
				EIDSecurityAudit(SECURITY_AUDIT_WARNING, L"[POLICY_DENY] Refused GINA challenge for crypted credential (rid 0x%x): no proof-of-possession in GINA protocol", pGina->dwRid);
				SecureZeroMemory(pbChallenge, dwChallengeSize);
				EIDFree(pbChallenge);
				pbChallenge = NULL;
				dwChallengeSize = 0;
				__leave;
			}
			// Remember what was issued so the response handler can refuse a
			// replayed or caller-invented challenge. If it cannot be recorded,
			// do not hand it out: the response would be refused anyway.
			if (!GinaRecordIssuedChallenge(pGina->dwRid, dwType, pbChallenge, dwChallengeSize))
			{
				response.dwError = ERROR_INVALID_DATA;
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Unable to record challenge (size %u)", dwChallengeSize);
				SecureZeroMemory(pbChallenge, dwChallengeSize);
				EIDFree(pbChallenge);
				pbChallenge = NULL;
				dwChallengeSize = 0;
				__leave;
			}
			// success
			response.dwChallengeSize = dwChallengeSize;
			response.dwChallengeType = dwType;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"OK");
		}
		__finally
		{
			StatusReturned = MyLsaDispatchTable->AllocateClientBuffer(ClientRequest, sizeof(EID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER) + dwChallengeSize, ProtocolReturnBuffer);
			if (StatusReturned == STATUS_SUCCESS) 
			{
				if (pbChallenge)
				{
					response.pbChallenge = static_cast<PUCHAR>(*ProtocolReturnBuffer) + sizeof(EID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER);
				}
				StatusReturned = MyLsaDispatchTable->CopyToClientBuffer(ClientRequest, sizeof(EID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER), *ProtocolReturnBuffer, &response);
				if (StatusReturned == STATUS_SUCCESS && pbChallenge) 
				{
					StatusReturned = MyLsaDispatchTable->CopyToClientBuffer(ClientRequest, dwChallengeSize,response.pbChallenge, pbChallenge);
				}
				*ReturnBufferLength = sizeof(EID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER) + dwChallengeSize;
			}
			if (pbChallenge) EIDFree(pbChallenge);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"return 0x%08X",StatusReturned);
		return StatusReturned;
	}


	NTSTATUS NTAPI PerformGinaAuthenticationResponse(
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   PVOID ProtocolSubmitBuffer,
	  __in   PVOID ClientBufferBase,
	  __in   ULONG SubmitBufferLength,
	  __out  PVOID *ProtocolReturnBuffer,
	  __out  PULONG ReturnBufferLength,
	  __out  PNTSTATUS ProtocolStatus  // NOSONAR - API-01: signature dictated by Windows/callback API
	  ) 
	{
		UNREFERENCED_PARAMETER(ProtocolStatus);
		UNREFERENCED_PARAMETER(ClientBufferBase);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS StatusReturned = STATUS_SUCCESS;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		PEID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST pGina = static_cast<PEID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST>(ProtocolSubmitBuffer);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		PWSTR szPassword = NULL;
		EID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER response = {0};
		memset(&response, 0, sizeof(EID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER));
		if (SubmitBufferLength < sizeof(EID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SubmitBufferLength");
			return STATUS_INVALID_PARAMETER;
		}
		__try
		{
			// go look for the password stored
			CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
			if (!manager)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"manager NULL");
				response.dwError = ERROR_INTERNAL_ERROR;
				__leave;
			}
			if (pGina->dwChallengeSize > SubmitBufferLength ||
				(ULONG_PTR) pGina->pbChallenge > SubmitBufferLength - pGina->dwChallengeSize)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pbChallenge overflow");
				response.dwError = ERROR_INVALID_PARAMETER;
				__leave;
			}
			if (pGina->dwResponseSize > SubmitBufferLength ||
				(ULONG_PTR) pGina->pbResponse > SubmitBufferLength - pGina->dwResponseSize)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pbResponse overflow");
				response.dwError = ERROR_INVALID_PARAMETER;
				__leave;
			}
			pGina->pbChallenge = pGina->pbChallenge + (ULONG_PTR) pGina;
			pGina->pbResponse = pGina->pbResponse + (ULONG_PTR) pGina;
			// check the PIN if using the base smart card provider to get the remaining pin attempts
			// put the result in SubStatus
						
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RID = 0x%x", pGina->dwRid);
			// Crypted credentials are never issued a GINA challenge (see
			// PerformGinaAuthenticationChallenge); refuse explicitly as well.
			if (pGina->dwChallengeType == static_cast<DWORD>(EID_PRIVATE_DATA_TYPE::eidpdtCrypted))  // NOSONAR - ENUM-01: enum-to-underlying cast for Win32/ABI compatibility
			{
				response.dwError = ERROR_NOT_SUPPORTED;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GINA authentication not supported for crypted credential (rid 0x%x)", pGina->dwRid);
				__leave;
			}
			// Only accept a challenge that PerformGinaAuthenticationChallenge
			// issued for this RID, recently, and not already used.
			if (!GinaConsumeIssuedChallenge(pGina->dwRid, pGina->dwChallengeType, pGina->pbChallenge, pGina->dwChallengeSize))
			{
				response.dwError = ERROR_ACCESS_DENIED;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Challenge not issued, expired or already used for rid 0x%x", pGina->dwRid);
				EIDSecurityAudit(SECURITY_AUDIT_WARNING, L"[AUTH_REPLAY] Rejected GINA response for rid 0x%x: challenge not issued, expired or already used", pGina->dwRid);
				__leave;
			}
			// the real job is done here
			if (!manager->GetPasswordFromChallengeResponse(pGina->dwRid,pGina->pbChallenge, pGina->dwChallengeSize, 
										pGina->dwChallengeType,pGina->pbResponse, pGina->dwResponseSize,&szPassword))
			{
				response.dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"GetChallenge 0x%08X", response.dwError);
				__leave;
			}
			// success
			// Validate password pointer and length
			if (szPassword == NULL || wcslen(szPassword) > USHRT_MAX / sizeof(WCHAR))  // STRPTR-01: Validate pointer before wcslen
			{
				if (szPassword == NULL)
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Password is NULL");
				else
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Password too long for UNICODE_STRING");
				response.dwError = ERROR_INVALID_PARAMETER;
				__leave;
			}
			// Store size to avoid calling wcslen twice
			DWORD PasswordSize = static_cast<DWORD>(wcslen(szPassword));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
			response.Password.MaximumLength = response.Password.Length = static_cast<USHORT>(sizeof(WCHAR) * PasswordSize);  // NOSONAR - IDIOM-01: chained assignment intentional
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"OK");
		}
		__finally
		{
			StatusReturned = MyLsaDispatchTable->AllocateClientBuffer(ClientRequest, sizeof(EID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER) + response.Password.Length, ProtocolReturnBuffer);
			if (StatusReturned == STATUS_SUCCESS) 
			{
				if (szPassword) 
				{
					response.Password.Buffer = reinterpret_cast<PWSTR>(static_cast<PUCHAR>(*ProtocolReturnBuffer) + sizeof(EID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER));  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
				}
				StatusReturned = MyLsaDispatchTable->CopyToClientBuffer(ClientRequest, sizeof(EID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER), *ProtocolReturnBuffer, &response);
				if (StatusReturned == STATUS_SUCCESS && szPassword) 
				{
					StatusReturned = MyLsaDispatchTable->CopyToClientBuffer(ClientRequest, response.Password.Length,response.Password.Buffer,szPassword);
				}
				*ReturnBufferLength = sizeof(EID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER) + response.Password.Length;
			}
			if (szPassword)
			{
				SecureZeroMemory(szPassword, response.Password.Length);
				EIDFree(szPassword);
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"return 0x%08X",StatusReturned);
		return StatusReturned;
	}
		/** Called when the authentication package's identifier has been specified in a call to 
	LsaCallAuthenticationPackage by an application that is using a trusted connection.

	This function provides a way for logon applications to communicate directly with authentication packages.*/

	NTSTATUS NTAPI LsaApCallPackage(
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   PVOID ProtocolSubmitBuffer,
	  __in   PVOID ClientBufferBase,
	  __in   ULONG SubmitBufferLength,
	  __out  PVOID *ProtocolReturnBuffer,
	  __out  PULONG ReturnBufferLength,
	  __out  PNTSTATUS ProtocolStatus
	) {
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS Status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		__try
		{
			*ProtocolStatus = STATUS_SUCCESS;
			// SECURITY: reject any buffer too small to hold the fixed message header before
			// dereferencing MessageType, mirroring the untrusted path's guard.
			if (SubmitBufferLength < sizeof(EID_CALLPACKAGE_BUFFER))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SubmitBufferLength 0x%x smaller than message header - rejecting",SubmitBufferLength);
				return STATUS_INVALID_PARAMETER;
			}
			// we take care here of messages requiring the TCB privilege (winlogon, msgina, ...)
			// the other message are forwarded to LsaApCallPackageUntrusted
			PEID_CALLPACKAGE_BUFFER pBuffer = static_cast<PEID_CALLPACKAGE_BUFFER>(ProtocolSubmitBuffer);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
			switch (pBuffer->MessageType)  // NOSONAR - SCOPE-01: variable reused across switch cases
			{
			case EIDCMEIDGinaAuthenticationChallenge:
				Status = PerformGinaAuthenticationChallenge(ClientRequest,ProtocolSubmitBuffer,ClientBufferBase,
					SubmitBufferLength,ProtocolReturnBuffer,ReturnBufferLength,ProtocolStatus);
				break;
			case EIDCMEIDGinaAuthenticationResponse:
				Status = PerformGinaAuthenticationResponse(ClientRequest,ProtocolSubmitBuffer,ClientBufferBase,
					SubmitBufferLength,ProtocolReturnBuffer,ReturnBufferLength,ProtocolStatus);
				break;
			default:
				Status = LsaApCallPackageUntrusted(ClientRequest,ProtocolSubmitBuffer,ClientBufferBase,
					SubmitBufferLength,ProtocolReturnBuffer,ReturnBufferLength,ProtocolStatus);
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"return 0x%08X",Status);
			return Status;
		}
		__except(EIDExceptionHandler(GetExceptionInformation()))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"NT exception in LsaApCallPackage: 0x%08x",GetExceptionCode());
			EIDLogStackTrace(GetExceptionCode());
			return STATUS_LOGON_FAILURE;
		}
	}

	/**
	Called when the authentication package's identifier has been specified in
	a call to LsaCallAuthenticationPackage for a pass-through logon request.*/

	NTSTATUS NTAPI LsaApCallPackagePassthrough(
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   PVOID ProtocolSubmitBuffer,
	  __in   PVOID ClientBufferBase,
	  __in   ULONG SubmitBufferLength,
	  __out  PVOID *ProtocolReturnBuffer,
	  __out  PULONG ReturnBufferLength,
	  __out  PNTSTATUS ProtocolStatus
	) {
		// Generic pass-through (Netlogon, on a domain controller) delivers data from the
		// network, with no local client whose identity the credential-management messages
		// could check. Nothing in this product uses it: refuse it.
		UNREFERENCED_PARAMETER(ClientRequest);
		UNREFERENCED_PARAMETER(ProtocolSubmitBuffer);
		UNREFERENCED_PARAMETER(ClientBufferBase);
		UNREFERENCED_PARAMETER(SubmitBufferLength);
		if (ProtocolReturnBuffer)
		{
			*ProtocolReturnBuffer = NULL;
		}
		if (ReturnBufferLength)
		{
			*ReturnBufferLength = 0;
		}
		if (ProtocolStatus)
		{
			*ProtocolStatus = STATUS_NOT_SUPPORTED;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pass-through call refused");
		EIDSecurityAudit(SECURITY_AUDIT_WARNING, L"[IPC_REJECT] Refused a generic pass-through call to the package");
		return STATUS_NOT_SUPPORTED;
	}

	/** Called when a logon session ends to permit the authentication package 
	to free any resources allocated for the logon session.*/

	VOID NTAPI LsaApLogonTerminated(
	  __in  PLUID LogonId  // NOSONAR - API-01: signature dictated by Windows/callback API
	) {
		UNREFERENCED_PARAMETER(LogonId);
		return;
	}

	// these API aren't available in Windows XP
	// so we have to load them manually
	using CredIsProtectedWFct = BOOL (WINAPI*)(
			__in LPWSTR                 pszProtectedCredentials,
			__out CRED_PROTECTION_TYPE* pProtectionType
			);

	using CredUnprotectWFct = BOOL (WINAPI*)(
			__in BOOL                                   fAsSelf,
			__in_ecount(cchProtectedCredentials) LPWSTR pszProtectedCredentials,
			__in DWORD                                  cchProtectedCredentials,
			__out_ecount_opt(*pcchMaxChars) LPWSTR      pszCredentials,
			__inout DWORD*                              pcchMaxChars
			);

	NTSTATUS TryToUnprotecThePin(PWSTR pwzPin, PWSTR pwzPinUncrypted, DWORD dPinUncrypted, PWSTR *pResultingPin)
	{
		CRED_PROTECTION_TYPE protectionType;
		CredIsProtectedWFct CredIsProtectedW = NULL;
		CredUnprotectWFct CredUnprotectW = NULL;
		HMODULE hModule = NULL;
		NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		__try
		{
			// default output : the PIN given to LSA (not crypted)
			*pResultingPin = pwzPin;
			// try to know if the PIN was crypted (Vista & later)
			hModule = EIDLoadSystemLibrary(TEXT("Advapi32.dll"));
			if (hModule == NULL)
			{
				__leave;
			}
			CredIsProtectedW = reinterpret_cast<CredIsProtectedWFct>(GetProcAddress(hModule,"CredIsProtectedW"));  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
			CredUnprotectW = reinterpret_cast<CredUnprotectWFct>(GetProcAddress(hModule,"CredUnprotectW"));  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
			if (CredIsProtectedW == NULL || CredUnprotectW == NULL)
			{
				// get here if on Windows XP
				__leave;
			}
			// here on Vista & later
			if(CredIsProtectedW(pwzPin, &protectionType))
			{
				if(CredUnprotected != protectionType)  // NOSONAR - COMPLEXITY-01: nested if kept separate for clarity
				{
					if (!CredUnprotectW(FALSE,pwzPin,UNLEN,pwzPinUncrypted,&dPinUncrypted))
					{
						EIDLogErrorWithContext("CredUnprotectW", HRESULT_FROM_WIN32(GetLastError()), nullptr);
						Status = STATUS_BAD_VALIDATION_CLASS;
						__leave;
					}
					// the PIN was crypted - use the uncrypted PIN
					*pResultingPin = pwzPinUncrypted;
				}
			}
		}
		__finally
		{
			if (hModule != nullptr)
				FreeLibrary(hModule);
		}
		return Status;
	}

	/** Called when the authentication package has been specified in a call to LsaLogonUser.
	This function authenticates a security principal's logon data.*/
	NTSTATUS NTAPI LsaApLogonUserEx2(  // NOSONAR - COMPLEXITY-01: LSA callback signature has fixed parameter count
	  __in   PLSA_CLIENT_REQUEST ClientRequest,
	  __in   SECURITY_LOGON_TYPE LogonType,
	  __in   PVOID AuthenticationInformation,
	  __in   PVOID ClientAuthenticationBase,
	  __in   ULONG AuthenticationInformationLength,
	  __out  PVOID *ProfileBuffer,
	  __out  PULONG ProfileBufferLength,
	  __out  PLUID LogonId,
	  __out  PNTSTATUS SubStatus,
	  __out  PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
	  __out  PVOID *TokenInformation,
	  __out  PUNICODE_STRING *AccountName,
	  __out  PUNICODE_STRING *AuthenticatingAuthority,
	  __out  PUNICODE_STRING *MachineName,
 	  __out  PSECPKG_PRIMARY_CRED PrimaryCredentials,
	  __out  PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials
	) 
	{
		UNREFERENCED_PARAMETER(AuthenticationInformationLength);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");

		// Log session logon initiation
		EIDCardLibraryLogStructured(
			EID_EVENT_ID::SESSION_LOGON_INIT,
			EID_SEVERITY::INFO,
			EID_OUTCOME::UNKNOWN,
			nullptr,
			L"Logon",
			L"Smart card logon initiated",
			nullptr,
			nullptr,
			0,
			0,
			0,
			nullptr,
			nullptr
		);

		NTSTATUS Status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		DWORD dwLen = MAX_COMPUTERNAME_LENGTH +1;
		WCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD TokenLength;
		WCHAR pwzPin[UNLEN] = L"";
		WCHAR pwzPinUncrypted[UNLEN] = L"";
		DWORD dPinUncrypted = UNLEN;
		LPWSTR pPin = pwzPin;
		PCCERT_CONTEXT pCertContext = NULL;
		LPTSTR szUserName = NULL;
		PLSA_TOKEN_INFORMATION_V2 MyTokenInformation = NULL;
		DWORD dwRid = 0;
		// Hoisted out of the body so the cleanup handler below can reach it.
		// It used to be declared at the point of use, which meant the two error
		// returns after GetPassword() succeeded left the plaintext Windows
		// password both unwiped AND unfreed on the LSASS heap.
		PWSTR szPassword = NULL;
		__try
		{
		// INNER SEH - do not remove. This function has eighteen early `return`
		// statements inside the body, and the PIN wipes used to sit only on the
		// success path at the very bottom and in the __except. Every one of the
		// other seventeen exits - including the ORDINARY WRONG-PIN PATH, which
		// an attacker can drive at will - left the plaintext PIN sitting in
		// these stack buffers. Tracing writes a MiniDumpNormal, which captures
		// thread stacks, so that residue is reachable on disk.
		//
		// A __finally runs on normal fallthrough, on `return` unwinding, and on
		// __leave, so wiring the cleanup here covers all eighteen exits without
		// touching a single one of them.
		__try
		{
			*SubStatus = STATUS_SUCCESS;

			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"LogonType = %d",LogonType);
			
			// the buffer come from another address space
			// so the pointers inside the buffer are invalid
			PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon = static_cast<PEID_INTERACTIVE_UNLOCK_LOGON>(AuthenticationInformation);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
			Status = RemapPointer(pUnlockLogon,ClientAuthenticationBase, AuthenticationInformationLength);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RemapPointer 0x%08X", Status);
				return Status;
			}
			PEID_SMARTCARD_CSP_INFO pSmartCardCspInfo = reinterpret_cast<PEID_SMARTCARD_CSP_INFO>(pUnlockLogon->Logon.CspData);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
			EIDDebugPrintEIDUnlockLogonStruct(WINEVENT_LEVEL_VERBOSE, pUnlockLogon, pUnlockLogon->Logon.CspDataLength);
			
			CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
			if (!manager)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"manager NULL");
				return STATUS_BAD_VALIDATION_CLASS;
			}

			if (GetComputerName(ComputerName, &dwLen))
			{
				*MachineName = LsaInitializeUnicodeStringFromWideString(ComputerName);
				*AuthenticatingAuthority = LsaInitializeUnicodeStringFromWideString(ComputerName);
				// Both are dereferenced later (CompletePrimaryCredential), so an
				// allocation failure here has to stop the logon, not crash LSASS.
				if (!*MachineName || !*AuthenticatingAuthority)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No memory for MachineName/AuthenticatingAuthority");
					return STATUS_INSUFFICIENT_RESOURCES;
				}
			}
			else
			{
				EIDLogErrorWithContext("GetComputerName", HRESULT_FROM_WIN32(GetLastError()), nullptr);
				return STATUS_BAD_VALIDATION_CLASS;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"MachineName OK");

			// get / decrypt PIN
			// Pin.Length is attacker-influenceable (UNICODE_STRING.Length is USHORT,
			// up to 65535). The stack buffer pwzPin is UNLEN WCHARs. Reject any
			// buffer that would overflow on the terminator write below.
			if (pUnlockLogon->Logon.Pin.Length > (UNLEN - 1) * sizeof(WCHAR))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,
					L"Pin.Length=%u exceeds UNLEN*sizeof(WCHAR); rejecting logon",
					pUnlockLogon->Logon.Pin.Length);
				return STATUS_INVALID_PARAMETER;
			}
			memcpy_s(pwzPin,UNLEN*sizeof(WCHAR),pUnlockLogon->Logon.Pin.Buffer,pUnlockLogon->Logon.Pin.Length);
			pwzPin[pUnlockLogon->Logon.Pin.Length/sizeof(WCHAR)] = 0;
			Status = TryToUnprotecThePin(pwzPin,pwzPinUncrypted, dPinUncrypted, &pPin);
			if (Status != STATUS_SUCCESS)
			{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"PIN decryption failed");
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TryToUnprotecThePin 0x%08X", Status);
				return Status;
			}
			// impersonate the client to beneficiate from the smart card redirection
			// if enabled on terminal session
			
			// check the PIN if using the base smart card provider to get the remaining pin attempts
			// put the result in SubStatus
			Status = CheckPINandGetRemainingAttemptsIfPossible(pSmartCardCspInfo, pUnlockLogon->Logon.CspDataLength, pPin, SubStatus);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"PIN verification failed");
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CheckPINandGetRemainingAttemptsIfPossible 0x%08X", Status);
				// Log PIN verification failure
				EIDCardLibraryLogStructured(
					EID_EVENT_ID::AUTH_PIN_FAILURE,
					EID_SEVERITY::WARNING,
					EID_OUTCOME::FAILURE,
					nullptr,
					L"PIN Verification",
					L"PIN verification failed",
					nullptr,
					nullptr,
					0,
					0,
					0,
					nullptr,
					L"Smart card PIN incorrect"
				);
				return Status;
			}

			// Log PIN verification success
			EIDCardLibraryLogStructured(
				EID_EVENT_ID::AUTH_PIN_SUCCESS,
				EID_SEVERITY::INFO,
				EID_OUTCOME::SUCCESS,
				nullptr,
				L"PIN Verification",
				L"PIN verified successfully",
				nullptr,
				nullptr,
				0,
				0,
				0,
				nullptr,
				nullptr
			);

			pCertContext = GetCertificateFromCspInfo(pSmartCardCspInfo, pUnlockLogon->Logon.CspDataLength);
			if (!pCertContext) {
				EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_CERT_ERROR] Smart card logon failed: Unable to get certificate from CSP info");
				// Log certificate read failure
				EIDCardLibraryLogStructured(
					EID_EVENT_ID::CERT_READ_FAILURE,
					EID_SEVERITY::ERROR,
					EID_OUTCOME::FAILURE,
					nullptr,
					L"Certificate Read",
					L"Unable to get certificate from CSP info",
					nullptr,
					nullptr,
					0,
					0,
					0,
					nullptr,
					L"CSP info invalid"
				);
				return STATUS_LOGON_FAILURE;
			}

			// Log certificate read success
			EIDCardLibraryLogStructured(
				EID_EVENT_ID::CERT_READ_SUCCESS,
				EID_SEVERITY::INFO,
				EID_OUTCOME::SUCCESS,
				nullptr,
				L"Certificate Read",
				L"Certificate retrieved from smart card",
				nullptr,
				nullptr,
				0,
				0,
				0,
				nullptr,
				nullptr
			);

			// username = username on certificate
			if (!manager->GetUsernameFromCertContext(pCertContext, &szUserName, &dwRid))
			{
				EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_CERT_ERROR] Smart card logon failed: Could not get username from certificate (0x%08x)", GetLastError());
				// Log certificate validation failure
				EIDCardLibraryLogStructured(
					EID_EVENT_ID::CERT_VALIDATE_FAILURE,
					EID_SEVERITY::ERROR,
					EID_OUTCOME::FAILURE,
					nullptr,
					L"Certificate Validation",
					L"Could not extract username from certificate",
					nullptr,
					nullptr,
					0,
					0,
					0,
					nullptr,
					L"Certificate subject invalid"
				);
				return STATUS_LOGON_FAILURE;
			}
			if (!szUserName) {
				EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_CERT_ERROR] Smart card logon failed: NULL username from certificate");
				return STATUS_LOGON_FAILURE;
			}
			*AccountName = LsaInitializeUnicodeStringFromWideString(szUserName);
			if (!*AccountName)
			{
				// Dereferenced by UserNameToToken, the audit lines and
				// CompletePrimaryCredential below.
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No memory for AccountName");
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			// trusted ?
			// check done after username to do accounting in case of failure
			// AccountName is known !
			if (!IsTrustedCertificate(pCertContext))
			{
				EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_CERT_ERROR] Smart card logon failed for user '%s': Untrusted certificate (0x%08x)", szUserName, GetLastError());
				// Log untrusted certificate
				EIDCardLibraryLogStructured(
					EID_EVENT_ID::CERT_VALIDATE_FAILURE,
					EID_SEVERITY::ERROR,
					EID_OUTCOME::FAILURE,
					szUserName,
					L"Certificate Validation",
					L"Certificate trust verification failed",
					nullptr,
					nullptr,
					0,
					0,
					0,
					nullptr,
					L"Untrusted certificate chain"
				);
				return STATUS_LOGON_FAILURE;
			}

			// Log certificate validation success
			EIDCardLibraryLogStructured(
				EID_EVENT_ID::CERT_VALIDATE_SUCCESS,
				EID_SEVERITY::INFO,
				EID_OUTCOME::SUCCESS,
				szUserName,
				L"Certificate Validation",
				L"Certificate chain validated successfully",
				nullptr,
				nullptr,
				0,
				0,
				0,
				nullptr,
				nullptr
			);
			
			EIDFree(szUserName);
			szUserName = NULL;


			// create token
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TokenInformation ?");
			Status = UserNameToToken(*AccountName,&MyTokenInformation,&TokenLength, SubStatus);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Token creation failed");
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"UserNameToToken failed %d",Status);
				return STATUS_LOGON_FAILURE;
			}
			
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TokenInformation OK substatus = 0x%08X",*SubStatus);
			*SubStatus = STATUS_SUCCESS;


			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RID = 0x%x", dwRid);
			// szPassword is declared at function scope so the cleanup handler
			// owns it - see the __finally at the bottom.
			if (!manager->GetPassword(dwRid,pCertContext, pPin, &szPassword))
			{
				DWORD dwError = GetLastError();
				EIDLogErrorWithContext("RetrieveStoredCredential", HRESULT_FROM_WIN32(dwError), nullptr);
				MyLsaDispatchTable->FreeLsaHeap(MyTokenInformation);
				switch(dwError)
				{
					case NTE_BAD_KEYSET_PARAM:
					case NTE_BAD_PUBLIC_KEY:
					case NTE_BAD_KEYSET:
						EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_CARD_ERROR] Smart card logon failed for user '%wZ': No keyset", *AccountName);
						return STATUS_SMARTCARD_NO_KEYSET;
					case SCARD_W_WRONG_CHV:
						EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_PIN_ERROR] Smart card logon failed for user '%wZ': Wrong PIN", *AccountName);
						// The tile needs the count to say how many attempts are left and to hold
						// PIN entry before the card blocks (PinAttemptsReserved). Free the certificate
						// first: it holds the Base CSP's context on the card, which may still hold a card
						// transaction (TransactionTimeoutMilliseconds) that the query would wait behind.
						CertFreeCertificateContext(pCertContext);
						pCertContext = NULL;
						*SubStatus = GetPinAttemptsAfterWrongPinIfPossible(pSmartCardCspInfo, pUnlockLogon->Logon.CspDataLength);
						return STATUS_SMARTCARD_WRONG_PIN;
					case SCARD_W_CHV_BLOCKED:
						EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_PIN_ERROR] Smart card logon failed for user '%wZ': Card blocked (too many PIN attempts)", *AccountName);
						return STATUS_SMARTCARD_CARD_BLOCKED;
					case NTE_SILENT_CONTEXT:
						EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_CARD_ERROR] Smart card logon failed for user '%wZ': Silent context error", *AccountName);
						return STATUS_SMARTCARD_SILENT_CONTEXT;
					case SCARD_W_CARD_NOT_AUTHENTICATED:
						EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_CARD_ERROR] Smart card logon failed for user '%wZ': Card not authenticated", *AccountName);
						return STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED;
					default:
						EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_CARD_ERROR] Smart card logon failed for user '%wZ': I/O error (0x%08x)", *AccountName, dwError);
						return STATUS_SMARTCARD_IO_ERROR;
				}

			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RetrieveStoredCredential OK");

			CertFreeCertificateContext(pCertContext);
			pCertContext = NULL;

			*TokenInformation = MyTokenInformation;
			*TokenInformationType = LsaTokenInformationV2;

			// create session
			if (!AllocateLocallyUniqueId (LogonId))
			{
				MyLsaDispatchTable->FreeLsaHeap (*TokenInformation);
				*TokenInformation = NULL;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No Memory logon_id");
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"AllocateLocallyUniqueId OK");
			Status = MyLsaDispatchTable->CreateLogonSession (LogonId);
			if (Status != STATUS_SUCCESS)
			{
				MyLsaDispatchTable->FreeLsaHeap (*TokenInformation);
				*TokenInformation = NULL;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateLogonSession %d",Status);
				return Status;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CreateLogonSession OK");

			// create profile

			// undocumented feature : if this buffer (which is not mandatory) is not filled
			// vista login WILL crash
			Status = UserNameToProfile(*AccountName,(PLSA_DISPATCH_TABLE)MyLsaDispatchTable,
						ClientRequest,(PEID_INTERACTIVE_PROFILE*)ProfileBuffer,ProfileBufferLength);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ProfileBuffer OK Status = %d",Status);

			// create primary credentials
			PSID pSid = MyTokenInformation->User.User.Sid;
			Status = CompletePrimaryCredential(*AuthenticatingAuthority,*AccountName,pSid,LogonId,szPassword,PrimaryCredentials);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CompletePrimaryCredential OK Status = %d",Status);
			*SupplementalCredentials = static_cast<PSECPKG_SUPPLEMENTAL_CRED_ARRAY>(EIDAlloc(sizeof(SECPKG_SUPPLEMENTAL_CRED_ARRAY)));
			if (*SupplementalCredentials)
			{
				(*SupplementalCredentials)->CredentialCount = 0;
			}
			// szPassword is wiped and freed by the __finally below, on this path
			// and on every other exit.
			Status = STATUS_SUCCESS;

			// Log successful authentication to both ETW and CSV
			EIDSecurityAudit(SECURITY_AUDIT_SUCCESS, L"[AUTH_SUCCESS] Smart card logon succeeded for user '%wZ'", *AccountName);

			// Convert AccountName to wide string for CSV logging
			WCHAR szUserNameBuffer[256] = L"";
			if (*AccountName && (*AccountName)->Buffer)
			{
				wcsncpy_s(szUserNameBuffer, (*AccountName)->Buffer,
					min((*AccountName)->Length / sizeof(WCHAR), ARRAYSIZE(szUserNameBuffer) - 1));
			}

			EIDCardLibraryLogStructured(
				EID_EVENT_ID::AUTH_SUCCESS,
				EID_SEVERITY::INFO,
				EID_OUTCOME::SUCCESS,
				szUserNameBuffer,
				L"Authentication",
				L"Smart card logon succeeded",
				nullptr,
				nullptr,
				0,
				0,
				LogonId->LowPart,
				nullptr,
				nullptr
			);

			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Success !!");
			return Status;
		}
		__finally
		{
			// Runs on all eighteen exits: normal completion, every `return`,
			// and unwinding towards the __except below.
			// The certificate context and user name used to be released only
			// on the success path, so every failed logon (wrong PIN, blocked
			// card, untrusted certificate, ...) leaked them in LSASS. The
			// success path frees them early and sets them to NULL.
			if (pCertContext)
			{
				CertFreeCertificateContext(pCertContext);
				pCertContext = NULL;
			}
			if (szUserName)
			{
				EIDFree(szUserName);
				szUserName = NULL;
			}
			SecureZeroMemory(pwzPin, sizeof(pwzPin));
			SecureZeroMemory(pwzPinUncrypted, sizeof(pwzPinUncrypted));
			if (szPassword)
			{
				// wcslen is safe here: every path that assigns szPassword gets a
				// NUL-terminated string back from GetPassword().
				SecureZeroMemory(szPassword, wcslen(szPassword) * sizeof(WCHAR));
				EIDFree(szPassword);
				szPassword = NULL;
			}
		}
		}
		__except(EIDExceptionHandler(GetExceptionInformation()))
		{
			// The inner __finally has already wiped the PIN and password by the
			// time this runs.
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"NT exception in LsaApLogonUserEx2: 0x%08x",GetExceptionCode());
			EIDLogStackTrace(GetExceptionCode());
			return STATUS_LOGON_FAILURE;
		}
	}

	void initializeLSAExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions)
	{

		exportedFunctions->InitializePackage = LsaApInitializePackage;
		// missing the word NTAPI in NTSecPkg.h
		exportedFunctions->LogonUserEx2 = reinterpret_cast<PLSA_AP_LOGON_USER_EX2>(LsaApLogonUserEx2);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
		exportedFunctions->LogonTerminated = LsaApLogonTerminated;
		exportedFunctions->CallPackage = LsaApCallPackage;
		exportedFunctions->CallPackagePassthrough = LsaApCallPackagePassthrough;
		exportedFunctions->CallPackageUntrusted = LsaApCallPackageUntrusted;
	}

	// CleanupLsaCredentials - Removes EID credential mappings from LSA Private Data
	// Called by the uninstaller ONLY when the operator ticks "Remove EID certificate mappings
	// from users". This is the sole uninstall path that deletes stored credentials:
	// DllUnRegister deliberately keeps them so uninstall/upgrade preserves enrolments.
	HRESULT WINAPI CleanupLsaCredentials()  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
	{
		HRESULT hr = S_OK;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
		LSA_OBJECT_ATTRIBUTES ObjectAttributes = {0};
		LSA_HANDLE LsaPolicyHandle = NULL;
		NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		DWORD dwUsersProcessed = 0;
		DWORD dwUsersRemoved = 0;

		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"CleanupLsaCredentials: Starting LSA credential cleanup");

		__try
		{
			// Primary removal: ask the loaded package (still resident in LSASS until reboot)
			// to delete every local user's stored credential, using the same key naming and
			// RID enumeration that created them. The direct LSA sweep below stays as a
			// fallback for when the package is not loaded.
			if (LsaEIDRemoveAllStoredCredential())
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"CleanupLsaCredentials: package removed all stored credentials");
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CleanupLsaCredentials: package removal failed (0x%08x) - using direct LSA sweep", GetLastError());
			}

			// Initialize LSA object attributes
			ObjectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

			// Open LSA policy with necessary access. POLICY_GET_PRIVATE_INFORMATION is
			// required by the LsaRetrievePrivateData existence check below; without it
			// every retrieve is denied and nothing would be removed.
			Status = LsaOpenPolicy(
				NULL,
				&ObjectAttributes,
				POLICY_CREATE_SECRET | POLICY_GET_PRIVATE_INFORMATION | READ_CONTROL | WRITE_OWNER | WRITE_DAC,
				&LsaPolicyHandle
			);

			if (Status != STATUS_SUCCESS)
			{
				DWORD dwError = LsaNtStatusToWinError(Status);
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"CleanupLsaCredentials: LsaOpenPolicy failed (0x%08x)", dwError);
				return HRESULT_FROM_WIN32(dwError);
			}

			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"CleanupLsaCredentials: LSA policy opened");

			// Enumerate local users to find their RIDs
			// We need to clean up LSA private data for each user
			LPUSER_INFO_0 pUserInfo = NULL;
			DWORD dwEntriesRead = 0;
			DWORD dwTotalEntries = 0;
			DWORD dwResumeHandle = 0;

			// NetUserEnum requires lmaccess.h and netapi32.lib
			// We'll use a simpler approach: get well-known SIDs and local accounts

			// Instead of enumerating all users, we'll look for LSA keys that match our pattern
			// LSA private data keys for EID are named: L$_EID__<RID_in_hex> (double underscore:
			// StoredCredentialManagement.cpp builds them as CREDENTIAL_LSAPREFIX "L$_EID_" + "_%08X")

			// Try to enumerate local users using NetUserEnum
			// This is more reliable than trying all possible RIDs
			Status = NetUserEnum(
				NULL,
				0,
				FILTER_NORMAL_ACCOUNT,
				(LPBYTE*)&pUserInfo,
				MAX_PREFERRED_LENGTH,
				&dwEntriesRead,
				&dwTotalEntries,
				&dwResumeHandle
			);

			if (Status == NERR_Success || Status == ERROR_MORE_DATA)
			{
				LPUSER_INFO_0 pCurrent = pUserInfo;
				for (DWORD i = 0; i < dwEntriesRead; i++)
				{
					if (pCurrent == NULL || pCurrent->usri0_name == NULL)
						break;

					// BUG FIX #16: TOCTOU race condition mitigation - use retry loop for SID allocation
					PBYTE pSidBuffer = NULL;
					DWORD dwSidSize = 0;
					PWSTR pDomain = NULL;
					DWORD dwDomainSize = 0;
					SID_NAME_USE sidUse = SidTypeUnknown;
					constexpr DWORD MAX_RETRIES = 3;
					DWORD dwRetryCount = 0;
					BOOL fSuccess = FALSE;

					// First call to get buffer sizes
					LookupAccountName(NULL, pCurrent->usri0_name, NULL, &dwSidSize, NULL, &dwDomainSize, &sidUse);
					if (dwSidSize == 0)
					{
						pCurrent++;
						continue;
					}

					// Retry loop for SID allocation (handles TOCTOU race condition)
					for (dwRetryCount = 0; dwRetryCount < MAX_RETRIES; dwRetryCount++)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
					{
						// Clean up from previous retry
						if (pSidBuffer)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
						{
							EIDFree(pSidBuffer);
							pSidBuffer = NULL;
						}
						if (pDomain)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
						{
							EIDFree(pDomain);
							pDomain = NULL;
						}

						// Allocate buffers
						pSidBuffer = (PBYTE)EIDAlloc(dwSidSize);
						pDomain = (PWSTR)EIDAlloc(dwDomainSize * sizeof(WCHAR));

						if (pSidBuffer && pDomain)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
						{
							SecureZeroMemory(pSidBuffer, dwSidSize);
							SecureZeroMemory(pDomain, dwDomainSize * sizeof(WCHAR));

							if (LookupAccountName(NULL, pCurrent->usri0_name, pSidBuffer, &dwSidSize, pDomain, &dwDomainSize, &sidUse))
							{
								fSuccess = TRUE;
								break;  // Success - exit retry loop
							}

							DWORD dwError = GetLastError();
							if (dwError == ERROR_INSUFFICIENT_BUFFER)
							{
								// Buffer size changed between check and use (TOCTOU race condition)
								EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"TOCTOU race condition on retry %u for %s: buffer size changed (retrying...)",
									dwRetryCount + 1, pCurrent->usri0_name);
								// Loop will continue with new buffer sizes
							}
							else
							{
								// Different error - not a TOCTOU issue, don't retry
								EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CleanupLsaCredentials: LookupAccountName failed for %s (0x%08x)", pCurrent->usri0_name, dwError);
								break;
							}
						}
						else
						{
							EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CleanupLsaCredentials: Failed to allocate buffers");
							break;
						}
					}

					if (fSuccess)
						{
							// Extract RID from SID
							if (IsValidSid((PSID)pSidBuffer))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
							{
								DWORD dwSubAuthorityCount = *GetSidSubAuthorityCount((PSID)pSidBuffer);
								DWORD dwRid = *GetSidSubAuthority((PSID)pSidBuffer, dwSubAuthorityCount - 1);

								// Build the LSA key name: L$_EID__<RID> (double underscore, matching
								// StoredCredentialManagement.cpp: CREDENTIAL_LSAPREFIX + "_%08X")
								WCHAR szKeyName[64];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
								swprintf_s(szKeyName, _countof(szKeyName), L"L$_EID__%08X", dwRid);

								// Create LSA_UNICODE_STRING for the key name
								LSA_UNICODE_STRING LsaKeyName;
								LsaKeyName.Length = (USHORT)(wcslen(szKeyName) * sizeof(WCHAR));  // NOSONAR - STRPTR-02: Stack buffer, null-terminated by swprintf_s
								LsaKeyName.MaximumLength = LsaKeyName.Length + sizeof(WCHAR);
								LsaKeyName.Buffer = szKeyName;

								// Check if this key exists by trying to retrieve it
								PLSA_UNICODE_STRING pPrivateData = NULL;
								NTSTATUS retrieveStatus = LsaRetrievePrivateData(
									LsaPolicyHandle,
									&LsaKeyName,
									&pPrivateData
								);

								if (retrieveStatus == STATUS_SUCCESS && pPrivateData != NULL)
								{
									// Key exists - delete it by storing NULL
									NTSTATUS deleteStatus = LsaStorePrivateData(
										LsaPolicyHandle,
										&LsaKeyName,
										NULL
									);

									if (deleteStatus == STATUS_SUCCESS)
									{
										EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"CleanupLsaCredentials: Removed credential mapping for user: %s (RID: 0x%08x)", pCurrent->usri0_name, dwRid);
										dwUsersRemoved++;
									}
									else
									{
										DWORD dwError = LsaNtStatusToWinError(deleteStatus);
										EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CleanupLsaCredentials: Failed to remove mapping for %s (0x%08x)", pCurrent->usri0_name, dwError);
									}

									// Free the retrieved data
									if (pPrivateData != NULL)
									{
										LsaFreeMemory(pPrivateData);
									}
								}

								dwUsersProcessed++;
							}
						}

						if (pDomain) EIDFree(pDomain);
						if (pSidBuffer) EIDFree(pSidBuffer);

					pCurrent++;
				}

				// Free the user enumeration buffer
				if (pUserInfo)
				{
					NetApiBufferFree(pUserInfo);
				}
			}
			else
			{
				DWORD dwError = LsaNtStatusToWinError(Status);
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CleanupLsaCredentials: NetUserEnum failed (0x%08x)", dwError);
				// Don't fail - we might still succeed partially
			}

			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"CleanupLsaCredentials: Processed %d users, removed %d credential mappings", dwUsersProcessed, dwUsersRemoved);

			// Close LSA policy handle
			if (LsaPolicyHandle != NULL)
			{
				LsaClose(LsaPolicyHandle);
			}

			hr = S_OK;
		}
		__except(EIDExceptionHandler(GetExceptionInformation()))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"CleanupLsaCredentials: Exception 0x%08x", GetExceptionCode());
			EIDLogStackTrace(GetExceptionCode());
			if (LsaPolicyHandle != NULL)
			{
				LsaClose(LsaPolicyHandle);
			}
			hr = E_FAIL;
		}

		return hr;
	}

	// EIDResealStoredCredential - re-seals an enrolled account's stored credential
	// with its new password. Exported for the password filter
	// (EIDPasswordChangeNotification.dll): it runs in the same LSASS but links its
	// own copy of EIDCardLibrary, so its own re-seal would not share the lock that
	// serialises enrolment, removal and SpAcceptCredentials in this DLL. Calling
	// through here does.
	BOOL WINAPI EIDResealStoredCredential(DWORD dwRid, PWSTR szPassword, USHORT usPasswordLen)
	{
		BOOL fReturn = FALSE;
		__try
		{
			CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
			if (manager && szPassword && usPasswordLen > 0)
			{
				fReturn = manager->UpdateCredential(dwRid, szPassword, usPasswordLen);
			}
		}
		__except(EIDExceptionHandler(GetExceptionInformation()))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"NT exception in EIDResealStoredCredential: 0x%08x",GetExceptionCode());
			fReturn = FALSE;
		}
		return fReturn;
	}

	// CleanupEIDCertificates - Removes the EID root CA (certificate + machine key
	// container) and every certificate it issued, from machine stores and all user
	// profiles. Called by the uninstaller via rundll32 before this DLL is deleted.
	HRESULT WINAPI CleanupEIDCertificates()
	{
		HRESULT hr = E_FAIL;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"CleanupEIDCertificates: starting");
		__try
		{
			hr = RemoveAllEIDCertificates();
		}
		__except(EIDExceptionHandler(GetExceptionInformation()))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"CleanupEIDCertificates: Exception 0x%08x", GetExceptionCode());
			EIDLogStackTrace(GetExceptionCode());
			hr = E_FAIL;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"CleanupEIDCertificates: finished 0x%08x", hr);
		return hr;
	}

}
