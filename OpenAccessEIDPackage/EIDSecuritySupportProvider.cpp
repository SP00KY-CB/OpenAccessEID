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
#include <tchar.h>
#include <NTSecAPI.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <sddl.h>
#include <NTSecPKG.h>
#include <wincred.h>
#include <LM.h>
#include <list>

#include <ImageHlp.h>
#pragma comment(lib,"imagehlp")

#include "../EIDCardLibrary/EIDCardLibrary.h"  // NOSONAR - INCLUDE-01: include order significant for Windows SDK
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CredentialManagement.h"
#include "../EIDCardLibrary/CompleteToken.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"

void SetAlloc(PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap);
void SetFree(PLSA_FREE_LSA_HEAP FreeHeap);
void SetImpersonate(PLSA_IMPERSONATE_CLIENT Impersonate);

extern "C"
{
	// Save LsaDispatchTable
	PLSA_SECPKG_FUNCTION_TABLE MyLsaDispatchTable;  // NOSONAR - RUNTIME-01: LSA dispatch table, set by LSA
	PSECPKG_PARAMETERS MyParameters;  // NOSONAR - RUNTIME-01: LSA parameters, set by LSA
	SECPKG_FUNCTION_TABLE MyExportedFunctions;  // NOSONAR - RUNTIME-01: Function table, initialized by LSA
	const ULONG MyExportedFunctionsCount = 1;
	const BOOL DoUnicode = TRUE;
	LUID PackageUid;  // NOSONAR - RUNTIME-01: LUID, set by LSA at initialization
	void initializeExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions);
	ULONG MutualAuthLevel=0;  // NOSONAR - RUNTIME-01: Auth level, set by LSA
	// 1.3.6.1.4.1.35000.1
	// cf http://msdn.microsoft.com/en-us/library/bb540809%28VS.85%29.aspx
	// 1.3 . 6  .  1 .  4 .1   .35000    .1
	// 0x2B,0x06,0x01,0x04,0x01,0x88,0xB8,0x01
	const UCHAR GssOid[] = {0x2B,0x06,0x01,0x04,0x01,0x88,0xB8,0x01};  // NOSONAR - OID constant
	const DWORD GssOidLen = ARRAYSIZE(GssOid);
	// The NegoEx auth scheme GUID (6550d49b-a716-484e-8955-a8e666df45d1) is no longer
	// advertised: SpGetExtendedInformation(SecpkgNego2Info) is refused.


	const TimeStamp Forever = {0x7fffffff,0xfffffff};
	const TimeStamp Never = {0,0};

	/** The SpLsaModeInitialize function is called once by the  LSA for each registered  
	security support provider/ authentication package (SSP/AP) DLL it loads. This function 
	provides the LSA with pointers to the functions implemented by each  security package 
	in the SSP/AP DLL.*/

	NTSTATUS NTAPI SpLsaModeInitialize(
	  __in   ULONG LsaVersion,
	  __out  PULONG PackageVersionOut,
	  __out  PSECPKG_FUNCTION_TABLE *ppTables,
	  __out  PULONG pcTables
	  )
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS Status = STATUS_INVALID_PARAMETER;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		__try
		{
			if (LsaVersion != SECPKG_INTERFACE_VERSION) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaVersion = %d",LsaVersion);
				__leave;
			}
			*PackageVersionOut = 1;
			memset(&MyExportedFunctions, 0, sizeof(SECPKG_FUNCTION_TABLE));
			initializeExportedFunctionsTable(&MyExportedFunctions);
			*ppTables = &MyExportedFunctions;
			*pcTables = MyExportedFunctionsCount;
			// see remark in NTSecPkg.h line 1889
			Status = SECPKG_INTERFACE_VERSION_6;
		}
		__finally
		{
			// NOSONAR - SEH-01: Empty __finally required for SEH completeness
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return Status;
	}

	/** The SpInitialize function is called once by the  LSA to provide a  security package
	with general security information and a dispatch table of support functions. The security
	package should save the information and do internal initialization processing, if any is needed.*/
	NTSTATUS NTAPI SpInitialize(
		  __in  ULONG_PTR PackageId,
		  __in  PSECPKG_PARAMETERS Parameters,
		  __in  PLSA_SECPKG_FUNCTION_TABLE FunctionTable
		)
	{
		UNREFERENCED_PARAMETER(PackageId);
		MyParameters = Parameters;
		MyLsaDispatchTable = FunctionTable;
		SetAlloc(MyLsaDispatchTable->AllocateLsaHeap);
		SetFree(MyLsaDispatchTable->FreeLsaHeap);
		SetImpersonate(MyLsaDispatchTable->ImpersonateClient);
		AllocateLocallyUniqueId(&PackageUid);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return STATUS_SUCCESS;
	}

	/** The SpShutDown function is called by the  LSA before the  security support 
	provider/ authentication package (SSP/AP) is unloaded. The implementation of 
	this function should release any allocated resources, such as  credentials.*/
	NTSTATUS NTAPI SpShutDown()
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return STATUS_SUCCESS;
	}

	/**The SpGetInfo function provides general information about the  security package, such as
		its name and capabilities.
		The SpGetInfo function is called when the client calls the QuerySecurityPackageInfo 
		function of the Security Support Provider Interface. */
	NTSTATUS NTAPI SpGetInfo(
		__out  PSecPkgInfo PackageInfo
	)
	{
		// Static buffers for SecPkgInfo Name/Comment (non-const SEC_WCHAR* required by API)
		static SEC_WCHAR s_szPackageName[] = TEXT("OpenAccessEIDPackage");
		static SEC_WCHAR s_szPackageComment[] = TEXT("OpenAccessEIDPackage");

		// Not NEGOTIABLE/NEGOTIABLE2/GSS_COMPATIBLE: network authentication is refused (see
		// SpAcquireCredentialsHandleDisabled), so Negotiate and NegoEx must not offer it.
		PackageInfo->fCapabilities = SECPKG_FLAG_LOGON |
			SECPKG_FLAG_MULTI_REQUIRED|
			SECPKG_FLAG_CLIENT_ONLY|
			SECPKG_FLAG_IMPERSONATION|
			SECPKG_FLAG_ACCEPT_WIN32_NAME;
		PackageInfo->wVersion = SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION;
		PackageInfo->wRPCID = SECPKG_ID_NONE;
		PackageInfo->cbMaxToken = 5000;
		PackageInfo->Name = s_szPackageName;
		PackageInfo->Comment = s_szPackageComment;
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return STATUS_SUCCESS;
	}

	/** The SpGetExtendedInformation function provides extended information about a  security package. */
	NTSTATUS NTAPI SpGetExtendedInformation(
		  __in   SECPKG_EXTENDED_INFORMATION_CLASS Class,
		  __out  PSECPKG_EXTENDED_INFORMATION *ppInformation
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Class = %d",Class);
		NTSTATUS Status = SEC_E_UNSUPPORTED_FUNCTION;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		switch(Class)  // NOSONAR - SWITCH-01: unhandled enum values intentionally return unsupported status
		{
			case SecpkgGssInfo:
				*ppInformation = static_cast<PSECPKG_EXTENDED_INFORMATION>(EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION)+GssOidLen));
				if (!*ppInformation) { Status = STATUS_NO_MEMORY; break; }
				(*ppInformation)->Class = SecpkgGssInfo;
				(*ppInformation)->Info.GssInfo.EncodedIdLength = GssOidLen;
				memcpy((*ppInformation)->Info.GssInfo.EncodedId, GssOid,GssOidLen);
				Status = STATUS_SUCCESS ; 
				break;
			case SecpkgContextThunks:
				*ppInformation = static_cast<PSECPKG_EXTENDED_INFORMATION>(EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION)));
				if (!*ppInformation) { Status = STATUS_NO_MEMORY; break; }
				(*ppInformation)->Class = SecpkgContextThunks;
				(*ppInformation)->Info.ContextThunks.InfoLevelCount = 0; 
				Status = STATUS_SUCCESS; 
				break;
			case SecpkgMutualAuthLevel:
				*ppInformation = static_cast<PSECPKG_EXTENDED_INFORMATION>(EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION)));
				if (!*ppInformation) { Status = STATUS_NO_MEMORY; break; }
				(*ppInformation)->Class = SecpkgMutualAuthLevel;
				(*ppInformation)->Info.MutualAuthLevel.MutualAuthLevel = MutualAuthLevel; 
				Status = STATUS_SUCCESS; 
				break;
			case SecpkgWowClientDll:
				*ppInformation = static_cast<PSECPKG_EXTENDED_INFORMATION>(EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION)));
				if (!*ppInformation) { Status = STATUS_NO_MEMORY; break; }
				(*ppInformation)->Class = SecpkgWowClientDll;
				(*ppInformation)->Info.WowClientDll.WowClientDllPath.Buffer = NULL; 
				(*ppInformation)->Info.WowClientDll.WowClientDllPath.Length = 0;
				(*ppInformation)->Info.WowClientDll.WowClientDllPath.MaximumLength = 0;
				Status = STATUS_SUCCESS; 
				break;
			case SecpkgExtraOids:
				*ppInformation = static_cast<PSECPKG_EXTENDED_INFORMATION>(EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION)));
				if (!*ppInformation) { Status = STATUS_NO_MEMORY; break; }
				(*ppInformation)->Class = SecpkgExtraOids;
				(*ppInformation)->Info.ExtraOids.OidCount = 0; 
				Status = STATUS_SUCCESS;
				break;
			case SecpkgNego2Info:
				// No NegoEx auth scheme: network authentication is refused.
				Status = SEC_E_UNSUPPORTED_FUNCTION;
				break;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with Status = 0x%08X", Status);
		return Status;
	}

	/** The SpSetExtendedInformation function is used to set extended information about the  security package.*/
	NTSTATUS NTAPI SpSetExtendedInformation(
		  __in  SECPKG_EXTENDED_INFORMATION_CLASS Class,
		  __in  PSECPKG_EXTENDED_INFORMATION Info  // NOSONAR - API-01: signature dictated by Windows/callback API
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Class = %d",Class);
		UNREFERENCED_PARAMETER(Info);
		NTSTATUS Status = SEC_E_UNSUPPORTED_FUNCTION;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		switch(Class)  // NOSONAR - SWITCH-01: unhandled enum values intentionally return unsupported status
		{
			case SecpkgGssInfo:
				Status = SEC_E_UNSUPPORTED_FUNCTION ; 
				break;
			case SecpkgContextThunks:
				Status = SEC_E_UNSUPPORTED_FUNCTION ; 
				break;
			case SecpkgMutualAuthLevel:
				MutualAuthLevel = Info->Info.MutualAuthLevel.MutualAuthLevel ; 
				Status = STATUS_SUCCESS;
				break;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return Status;
	}

	/** The SpGetUserInfo function retrieves information about a logon  session.*/
	NTSTATUS NTAPI SpGetUserInfo( 
		IN PLUID LogonId,  // NOSONAR - API-01: signature dictated by Windows/callback API 
		IN ULONG Flags, 
		OUT PSecurityUserData * UserData 
		) 
	{ 
	 
		UNREFERENCED_PARAMETER(LogonId); 
		UNREFERENCED_PARAMETER(Flags); 
		UNREFERENCED_PARAMETER(UserData); 
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		return STATUS_NOT_SUPPORTED; 
	} 

	//////////////////////////////////////////////////////////////////////////////////////
	// Credential management
	//////////////////////////////////////////////////////////////////////////////////////

	/** Applies a control token to a  security context. This function is not currently called 
	by the  Local Security Authority (LSA).*/
	NTSTATUS NTAPI SpApplyControlToken(
		LSA_SEC_HANDLE              phContext,          // Context to modify
		PSecBufferDesc              pInput              // NOSONAR - API-01: signature dictated by Windows/callback API (input token to apply)
		)
	{
		UNREFERENCED_PARAMETER(phContext);
		UNREFERENCED_PARAMETER(pInput);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		return STATUS_SUCCESS;

	}

	/** Called by the  Local Security Authority (LSA) to pass the  security package any  
	credentials stored for the authenticated  security principal. This function is called
	once for each set of credentials stored by the LSA.*/
	NTSTATUS NTAPI SpAcceptCredentials(
		  __in  SECURITY_LOGON_TYPE LogonType,
		  __in  PUNICODE_STRING AccountName,
		  __in  PSECPKG_PRIMARY_CRED PrimaryCredentials,
		  __in  PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials  // NOSONAR - API-01: signature dictated by Windows/callback API
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter for account name = %wZ type=%d",AccountName, LogonType);
		UNREFERENCED_PARAMETER(SupplementalCredentials);
		if ( PrimaryCredentials && (PrimaryCredentials->Flags & PRIMARY_CRED_UPDATE) 
								&& (PrimaryCredentials->Flags & PRIMARY_CRED_CLEAR_PASSWORD))
		{
			// is here the password update
			// note : this function is called for each session opened (even the networked one)
			// and twice is the user is an administrator (elevated token and the normal one)
			// so this function is called in average 4 times.
			// the job is also done in the notification package, if the change password is done offline
			// (for example using  net.exe)
			// this function exists because a security package can be loaded immedialty after the install
			// into LSASS.exe while a notification package requires a reboot.
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Password change with flag 0x%x", PrimaryCredentials->Flags);
			CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
			manager->UpdateCredential(&(PrimaryCredentials->LogonId), &(PrimaryCredentials->Password));
			
		}
		return STATUS_SUCCESS;
	}

	/** Called to obtain a handle to a principal's  credentials. The  security package can 
	deny access to the caller if the caller does not have permission to access the credentials.

	If the credentials handle is returned to the caller, the package should also specify an expiration time for the handle.*/
	NTSTATUS NTAPI SpAcquireCredentialsHandle(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
		  __in   PUNICODE_STRING PrincipalName,
		  __in   ULONG CredentialUseFlags,
		  __in   PLUID LogonId,
		  __in   PVOID AuthorizationData,
		  __in   PVOID GetKeyFunction,
		  __in   PVOID GetKeyArgument,
		  __out  PLSA_SEC_HANDLE pCredentialHandle,
		  __out  PTimeStamp ExpirationTime
		)
	{
		UNREFERENCED_PARAMETER(LogonId);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter PrincipalName = %wZ",PrincipalName);
		PSEC_WINNT_AUTH_IDENTITY_EXW pAuthIdentityEx = NULL;
		PSEC_WINNT_AUTH_IDENTITY pAuthIdentity = NULL; 
		CCredential* pCredential;
		ULONG CredSize = 0;
		ULONG Offset = 0;
		NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		PCERT_CREDENTIAL_INFO pCertInfo = NULL;
		CRED_MARSHAL_TYPE CredType;
		PVOID szCredential = NULL;
		PVOID szPassword = NULL;
		PWSTR szPasswordW = NULL;
		DWORD dwCharSize = 0;
		BOOL UseUnicode = TRUE;
		SECPKG_CLIENT_INFO ClientInfo; 
		PLUID LogonIdToUse; 
		// Never hand back (or trace) an uninitialised handle on a failure path.
		if (pCredentialHandle)
		{
			*pCredentialHandle = 0;
		}
		__try
		{
			if ((CredentialUseFlags & SECPKG_CRED_BOTH) == 0)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"flag not ok");
				Status = SEC_E_UNKNOWN_CREDENTIALS;
				__leave;
			}
			if (GetKeyFunction)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetKeyFunction not ok");
				Status = SEC_E_UNSUPPORTED_FUNCTION;
				__leave;
			}
			if (GetKeyArgument)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetKeyArgument not ok");
				Status = SEC_E_UNSUPPORTED_FUNCTION;
				__leave;
			}
				// 
			// First get information about the caller. 
			// 	 
			Status = MyLsaDispatchTable->GetClientInfo(&ClientInfo);
			if (Status != STATUS_SUCCESS)
			{
				EIDLogErrorWithContext("GetClientInfo", HRESULT_FROM_NT(Status), nullptr);
				__leave;
			} 
	 
			// 
			// If the caller supplied a logon ID, and it doesn't match the caller, 
			// they must have the TCB privilege 
			// 
		 
			if (LogonId && 
				((LogonId->LowPart != 0) || (LogonId->HighPart != 0)) && 
				!(( LogonId->HighPart == ClientInfo.LogonId.HighPart) && ( LogonId->LowPart == ClientInfo.LogonId.LowPart))) 
				 
			{ 
				if (!ClientInfo.HasTcbPrivilege) 
				{ 
					Status = STATUS_PRIVILEGE_NOT_HELD; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_PRIVILEGE_NOT_HELD"); 
					__leave;
				} 
				LogonIdToUse = LogonId; 
			} 
			else 
			{ 
				LogonIdToUse = &ClientInfo.LogonId; 
			}

			if (AuthorizationData != nullptr)
			{ 
				// copy the authorization data to our user space
				pAuthIdentityEx = static_cast<PSEC_WINNT_AUTH_IDENTITY_EXW>
												(EIDAlloc(sizeof(SEC_WINNT_AUTH_IDENTITY_EXW))); 
				if (!pAuthIdentityEx)
				{
					Status = STATUS_INSUFFICIENT_RESOURCES;
					EIDLogErrorWithContext("EIDAlloc", HRESULT_FROM_NT(Status), nullptr);
					__leave;
				}
				Status = MyLsaDispatchTable->CopyFromClientBuffer( 
							NULL, 
							sizeof(SEC_WINNT_AUTH_IDENTITY), 
							pAuthIdentityEx, 
							AuthorizationData);

				if (Status != STATUS_SUCCESS)
				{
					EIDLogErrorWithContext("CopyFromClientBuffer", HRESULT_FROM_NT(Status), nullptr);
					__leave;
				}
				//
				// Check for the ex version
				// 
		 
				if (pAuthIdentityEx->Version == SEC_WINNT_AUTH_IDENTITY_VERSION) 
				{ 
					Status = MyLsaDispatchTable->CopyFromClientBuffer( 
								NULL, 
								sizeof(SEC_WINNT_AUTH_IDENTITY_EXW), 
								pAuthIdentityEx, 
								AuthorizationData); 
		 
					if (Status != STATUS_SUCCESS)
					{
						EIDLogErrorWithContext("CopyFromClientBuffer", HRESULT_FROM_NT(Status), nullptr);
						__leave;
					}
					pAuthIdentity = reinterpret_cast<PSEC_WINNT_AUTH_IDENTITY>(&pAuthIdentityEx->User);  // NOSONAR - CAST-01: Win32/LSA interop cast, layout-verified 
					CredSize = pAuthIdentityEx->Length; 
					Offset = FIELD_OFFSET(SEC_WINNT_AUTH_IDENTITY_EXW, User); 
				} 
				else 
				{ 
					pAuthIdentity = reinterpret_cast<PSEC_WINNT_AUTH_IDENTITY_W>(pAuthIdentityEx);  // NOSONAR - CAST-01: Win32/LSA interop cast, layout-verified 
					CredSize = sizeof(SEC_WINNT_AUTH_IDENTITY_W); 
				} 
		 
				if (pAuthIdentity->Flags & SEC_WINNT_AUTH_IDENTITY_ANSI) 
				{ 
					dwCharSize = sizeof(CHAR);
					UseUnicode = FALSE;
				} 
				else if (pAuthIdentity->Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE)
				{
					dwCharSize = sizeof(WCHAR);
					UseUnicode = TRUE;
				}
				else
				{
					Status = SEC_E_INVALID_TOKEN; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pAuthIdentity->Flags is 0x%lx", pAuthIdentity->Flags); 
					__leave;
				}
				// Client-supplied lengths feed size arithmetic on the LSASS heap:
				// bound them before any product can wrap
				if (pAuthIdentity->UserLength > 0xFFFF || pAuthIdentity->PasswordLength > 0xFFFF)
				{
					Status = STATUS_INVALID_PARAMETER;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AuthIdentity lengths out of range (%lu/%lu)", pAuthIdentity->UserLength, pAuthIdentity->PasswordLength);
					__leave;
				}
				szCredential = EIDAlloc((pAuthIdentity->UserLength + 1) * dwCharSize);
				if (!szCredential)
				{
					Status = STATUS_INSUFFICIENT_RESOURCES; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc"); 
					__leave;
				}
				Status = MyLsaDispatchTable->CopyFromClientBuffer(NULL, 
															(pAuthIdentity->UserLength + 1) * dwCharSize, 
															szCredential,
															pAuthIdentity->User); 
				if (Status != STATUS_SUCCESS)
				{
					EIDLogErrorWithContext("CopyFromClientBuffer", HRESULT_FROM_NT(Status), nullptr);
					__leave;
				}
				// The (UserLength + 1)th character came from the client too and is
				// not guaranteed to be a terminator; CredUnmarshalCredential would
				// read past the allocation looking for one.
				if (UseUnicode)
				{
					static_cast<PWSTR>(szCredential)[pAuthIdentity->UserLength] = L'\0';
				}
				else
				{
					static_cast<PSTR>(szCredential)[pAuthIdentity->UserLength] = '\0';
				}
				BOOL fRes;
				if (UseUnicode)
				{
					fRes = CredUnmarshalCredentialW(reinterpret_cast<LPCWSTR>(szCredential),&CredType, reinterpret_cast<PVOID*>(&pCertInfo));  // NOSONAR - CAST-01: Win32/LSA interop cast, layout-verified
				}
				else
				{
					fRes = CredUnmarshalCredentialA(reinterpret_cast<LPCSTR>(szCredential),&CredType, reinterpret_cast<PVOID*>(&pCertInfo));  // NOSONAR - CAST-01: Win32/LSA interop cast, layout-verified
				}
				if (!fRes)
				{
					EIDLogErrorWithContext("CredUnmarshalCredential", HRESULT_FROM_WIN32(GetLastError()), L"UseUnicode=%d", UseUnicode);
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}				
				if (CredType != CertCredential)
				{
					Status = SEC_E_UNKNOWN_CREDENTIALS; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredType is 0x%lx", CredType); 
					__leave;
				}
				szPassword = EIDAlloc((pAuthIdentity->PasswordLength + 1) * dwCharSize);
				if (!szPassword)
				{
					Status = STATUS_INSUFFICIENT_RESOURCES; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc"); 
					__leave;
				}
				Status = MyLsaDispatchTable->CopyFromClientBuffer(NULL, 
															(pAuthIdentity->PasswordLength + 1) * dwCharSize, 
															szPassword,
															pAuthIdentity->Password); 
				if (Status != STATUS_SUCCESS)
				{
					EIDLogErrorWithContext("CopyFromClientBuffer", HRESULT_FROM_NT(Status), nullptr);
					__leave;
				}
				// Same as the user name: force the terminator at PasswordLength so
				// MultiByteToWideChar(-1) / wcslen cannot run off the buffer.
				if (UseUnicode)
				{
					static_cast<PWSTR>(szPassword)[pAuthIdentity->PasswordLength] = L'\0';
				}
				else
				{
					static_cast<PSTR>(szPassword)[pAuthIdentity->PasswordLength] = '\0';
				}
				// convert to unicode
				if (UseUnicode)
				{
					szPasswordW = static_cast<PWSTR>(szPassword);
					szPassword = NULL;
				}
				else
				{
					szPasswordW = static_cast<PWSTR>(EIDAlloc((pAuthIdentity->PasswordLength + 1) * sizeof(WCHAR)));
					if (!szPasswordW)
					{
						Status = STATUS_INSUFFICIENT_RESOURCES; 
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc"); 
						__leave;
					}
					if (!MultiByteToWideChar(CP_UTF8, 0, (PSTR) szPassword, -1, szPasswordW, pAuthIdentity->PasswordLength + 1))
					{
						Status = SEC_E_UNKNOWN_CREDENTIALS;
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"MultiByteToWideChar 0x%08x", GetLastError());
						__leave;
					}
					szPasswordW[pAuthIdentity->PasswordLength] = L'\0';
				}
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"No Authorization data"); 
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CreateCredential"); 
			pCredential = CCredential::CreateCredential(LogonIdToUse,pCertInfo, szPasswordW, CredentialUseFlags);
			if (!pCredential)
			{
				// Status is still STATUS_SUCCESS here: report the failure.
				Status = SEC_E_INSUFFICIENT_MEMORY;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateCredential failed"); 
				__leave;
			}
			*pCredentialHandle = reinterpret_cast<LSA_SEC_HANDLE>(pCredential);
			*ExpirationTime = Forever;
		}
		__finally
		{
			if (pCertInfo)
				CredFree(pCertInfo);
			if (szCredential)
				MyLsaDispatchTable->FreeLsaHeap(szCredential);
			if (szPasswordW)
			{
				SecureZeroMemory(szPasswordW,(pAuthIdentity->PasswordLength + 1) * sizeof(WCHAR));
				MyLsaDispatchTable->FreeLsaHeap(szPasswordW);
			}
			if (szPassword)
			{
				SecureZeroMemory(szPassword,((SIZE_T)pAuthIdentity->PasswordLength + 1) * dwCharSize);
				MyLsaDispatchTable->FreeLsaHeap(szPassword);
			}
			if (pAuthIdentityEx)
				MyLsaDispatchTable->FreeLsaHeap(pAuthIdentityEx);
		}
		if (Status == STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Credential %p Status = 0x%08x",reinterpret_cast<PVOID>(*pCredentialHandle), Status);
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Status = 0x%08x", Status);
		}
		return Status;
	}

	/** Frees  credentials acquired by calling the  SpAcquireCredentialsHandle function.*/
	NTSTATUS NTAPI SpFreeCredentialsHandle(
		__in LSA_SEC_HANDLE                 CredentialHandle        // Handle to free
    )
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Credential %p",reinterpret_cast<PVOID>(CredentialHandle));
		if (!CCredential::Delete(CredentialHandle))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Credential %p not found",reinterpret_cast<PVOID>(CredentialHandle));
			return STATUS_INVALID_HANDLE;
		}
		return STATUS_SUCCESS;
	}

	/** Used to add  credentials for a  security principal.*/
	NTSTATUS NTAPI SpAddCredentials(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   PUNICODE_STRING PrincipalName,
		  __in   PUNICODE_STRING Package,
		  __in   ULONG CredentialUseFlags,
		  __in   PVOID AuthorizationData,
		  __in   PVOID GetKeyFunction,
		  __in   PVOID GetKeyArgument,
		  __out  PTimeStamp ExpirationTime
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter for account name = %wZ package=%wZ",PrincipalName, Package);
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(CredentialUseFlags);
		UNREFERENCED_PARAMETER(AuthorizationData);
		UNREFERENCED_PARAMETER(GetKeyFunction);
		UNREFERENCED_PARAMETER(GetKeyArgument);
		// forever
		*ExpirationTime = Forever;
		return STATUS_SUCCESS;
	}

	/** Deletes  credentials from a  security package's list of  primary or  supplemental credentials.*/
	NTSTATUS NTAPI SpDeleteCredentials(
		  __in  LSA_SEC_HANDLE CredentialHandle,
		  __in  PSecBuffer Key  // NOSONAR - API-01: signature dictated by Windows/callback API
		)
	{
		UNREFERENCED_PARAMETER(Key);
		UNREFERENCED_PARAMETER(CredentialHandle);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		return STATUS_SUCCESS;
	}

	/** Saves a  supplemental credential to the user object.*/
	NTSTATUS NTAPI SpSaveCredentials (
		  __in  LSA_SEC_HANDLE CredentialHandle,
		  __in  PSecBuffer Key  // NOSONAR - API-01: signature dictated by Windows/callback API
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(Key);
		return STATUS_SUCCESS;
	}
	
	/** The SpGetCredentials function retrieves the  primary and  supplemental credentials from the user object.*/
	NTSTATUS NTAPI SpGetCredentials (
		  __in  LSA_SEC_HANDLE CredentialHandle,
		  __out  PSecBuffer Credentials  // NOSONAR - API-01: signature dictated by Windows/callback API
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(Credentials);
		return STATUS_NOT_IMPLEMENTED;
	}

		/** The SpQueryCredentialsAttributes function retrieves the attributes for a  credential.

	The SpQueryCredentialsAttributes function is the dispatch function for the 
	QueryCredentialsAttributes function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpQueryCredentialsAttributes(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   ULONG CredentialAttribute,
		  __out  PVOID Buffer
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter CredentialAttribute = %d",CredentialAttribute);
		// SECURITY: LSA-mode dispatch - Buffer is an address in the CLIENT
		// process. Build the structure locally and CopyToClientBuffer it, as
		// SpQueryContextAttributes does; never write through Buffer directly.
		NTSTATUS status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		PTSTR szName;
		DWORD dwSize;
		PVOID pClientName = NULL;
		SecPkgCredentials_Names CredNames;
		CCredential* pCredential = CCredential::GetCredentialFromHandle(CredentialHandle);
		if (!pCredential)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredentialHandle = %p : STATUS_INVALID_HANDLE",reinterpret_cast<PVOID>(CredentialHandle));
			return STATUS_INVALID_HANDLE;
		}
		switch(CredentialAttribute)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
		{
			case SECPKG_CRED_ATTR_NAMES:
				__try
				{
					szName = pCredential->GetName();
					if (!szName)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"szName NULL");
						status = SEC_E_INSUFFICIENT_MEMORY;
						__leave;
					}
					dwSize = static_cast<DWORD>((_tcslen(szName)+1) * sizeof(TCHAR));
					status = MyLsaDispatchTable->AllocateClientBuffer(NULL, dwSize, &pClientName);
					if (status != STATUS_SUCCESS)
					{
						pClientName = NULL;
						EIDLogErrorWithContext("AllocateClientBuffer", HRESULT_FROM_NT(status), nullptr);
						__leave;
					}
					status = MyLsaDispatchTable->CopyToClientBuffer(NULL, dwSize, pClientName, szName);
					if (status != STATUS_SUCCESS)
					{
						EIDLogErrorWithContext("CopyToClientBuffer", HRESULT_FROM_NT(status), nullptr);
						__leave;
					}
					CredNames.sUserName = static_cast<decltype(CredNames.sUserName)>(pClientName);
					status = MyLsaDispatchTable->CopyToClientBuffer(NULL, sizeof(CredNames), Buffer, &CredNames);
					if (status != STATUS_SUCCESS)
					{
						EIDLogErrorWithContext("CopyToClientBuffer", HRESULT_FROM_NT(status), nullptr);
						__leave;
					}
					status = STATUS_SUCCESS;
				}
				__finally
				{
					if (status != STATUS_SUCCESS && pClientName)
					{
						MyLsaDispatchTable->FreeClientBuffer(NULL, pClientName);
					}
				}
				EIDLogErrorWithContext("QueryContextAttributes", HRESULT_FROM_NT(status), L"attr=SECPKG_CRED_ATTR_NAMES");
				return status;
				break;
			default:
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_INVALID_PARAMETER_2");
				return STATUS_INVALID_PARAMETER_2;
		}
	}

	

	//////////////////////////////////////////////////////////////////////////////////////
	// Context management
	//////////////////////////////////////////////////////////////////////////////////////

	
	/** Deletes a  security context.*/
	NTSTATUS NTAPI SpDeleteSecurityContext(
		__in LSA_SEC_HANDLE                 phContext           // Context to delete
    )
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"delete Context %p",reinterpret_cast<PVOID>(phContext));
		if (!CSecurityContext::Delete(phContext))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Context %p not found",reinterpret_cast<PVOID>(phContext));
			return SEC_E_INVALID_HANDLE;
		}
		return SEC_E_OK;
	}

	/**  The SpQueryContextAttributes function retrieves the attributes of a  security context.

	The SpQueryContextAttributes function is the dispatch function for the 
	QueryContextAttributes (General) function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpQueryContextAttributes(
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   ULONG ContextAttribute,
		  __out  PVOID pBuffer
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter ContextAttribute = %d",ContextAttribute);
		// SECURITY: this is the LSA-mode dispatch, so pBuffer is an address in the
		// CLIENT process, not in LSASS. Never write through it directly: build each
		// structure locally and hand it over with CopyToClientBuffer, and allocate
		// any embedded data (the user name) in the client with AllocateClientBuffer.
		CSecurityContext* pContext;
		SecPkgContext_Sizes ContextSizes;
		SecPkgContext_NamesW ContextNames;
		SecPkgContext_Lifespan ContextLifespan;
		NTSTATUS Status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		switch(ContextAttribute) 
		{
			case SECPKG_ATTR_SIZES:
				ContextSizes.cbMaxSignature = 0;
				ContextSizes.cbSecurityTrailer = 0;
				ContextSizes.cbBlockSize = 0;
				// 300 was never enough and is now actively wrong. A challenge
				// token is sizeof(EID_CHALLENGE_MESSAGE) + a 256-byte challenge
				// + 2 bytes per username character, i.e. over 300 for any name
				// of five characters or more; a response carries an RSA
				// signature, 512 bytes on an RSA-4096 card. Those writes used
				// to overflow the caller's token silently and are now refused
				// outright, so a peer that sizes its buffer from this value -
				// the documented idiom - would fail every handshake. Match the
				// package's own advertised cbMaxToken instead.
				ContextSizes.cbMaxToken = 5000;
				Status = MyLsaDispatchTable->CopyToClientBuffer(NULL, sizeof(ContextSizes), pBuffer, &ContextSizes);
				if (Status != STATUS_SUCCESS)
				{
					EIDLogErrorWithContext("CopyToClientBuffer", HRESULT_FROM_NT(Status), L"attr=SECPKG_ATTR_SIZES");
					return Status;
				}
				break;
			case SECPKG_ATTR_NAMES:
			{
				if (!ContextHandle)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ContextHandle = %p",reinterpret_cast<PVOID>(ContextHandle));
					return STATUS_INVALID_HANDLE;
				}
				pContext = CSecurityContext::GetContextFromHandle(ContextHandle);
				if (!pContext)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ContextHandle = %p : SEC_E_INVALID_HANDLE",reinterpret_cast<PVOID>(ContextHandle));
					return SEC_E_INVALID_HANDLE;
				}
				PWSTR szUserName = pContext->GetUserName();  // LSA heap copy, freed below
				if (szUserName == NULL)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INSUFFICIENT_MEMORY");
					return SEC_E_INSUFFICIENT_MEMORY;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Username = %s",szUserName);
				const ULONG cbUserName = static_cast<ULONG>((wcsnlen(szUserName, UNICODE_STRING_MAX_CHARS) + 1) * sizeof(WCHAR));
				PVOID pClientUserName = NULL;
				Status = MyLsaDispatchTable->AllocateClientBuffer(NULL, cbUserName, &pClientUserName);
				if (Status != STATUS_SUCCESS)
				{
					EIDFree(szUserName);
					EIDLogErrorWithContext("AllocateClientBuffer", HRESULT_FROM_NT(Status), L"attr=SECPKG_ATTR_NAMES");
					return Status;
				}
				Status = MyLsaDispatchTable->CopyToClientBuffer(NULL, cbUserName, pClientUserName, szUserName);
				EIDFree(szUserName);
				if (Status == STATUS_SUCCESS)
				{
					ContextNames.sUserName = static_cast<SEC_WCHAR*>(pClientUserName);
					Status = MyLsaDispatchTable->CopyToClientBuffer(NULL, sizeof(ContextNames), pBuffer, &ContextNames);
				}
				if (Status != STATUS_SUCCESS)
				{
					MyLsaDispatchTable->FreeClientBuffer(NULL, pClientUserName);
					EIDLogErrorWithContext("CopyToClientBuffer", HRESULT_FROM_NT(Status), L"attr=SECPKG_ATTR_NAMES");
					return Status;
				}
				break;
			}
			case SECPKG_ATTR_LIFESPAN:
				ContextLifespan.tsStart = Never;
				ContextLifespan.tsExpiry = Forever;
				// Report the same clamp SpAcceptLsaModeContext returned, so the
				// two answers to "when does this context expire" agree.
				pContext = CSecurityContext::GetContextFromHandle(ContextHandle);
				if (!pContext)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ContextHandle = %p : SEC_E_INVALID_HANDLE",reinterpret_cast<PVOID>(ContextHandle));
					return SEC_E_INVALID_HANDLE;
				}
				if (pContext->GetExpiry() != MAXLONGLONG)
				{
					// Split explicitly rather than through LARGE_INTEGER's union.
					const ULONGLONG ullExpiry = static_cast<ULONGLONG>(pContext->GetExpiry());
					ContextLifespan.tsExpiry.LowPart = static_cast<unsigned long>(ullExpiry & 0xFFFFFFFFULL);
					ContextLifespan.tsExpiry.HighPart = static_cast<long>(ullExpiry >> 32);
				}
				Status = MyLsaDispatchTable->CopyToClientBuffer(NULL, sizeof(ContextLifespan), pBuffer, &ContextLifespan);
				if (Status != STATUS_SUCCESS)
				{
					EIDLogErrorWithContext("CopyToClientBuffer", HRESULT_FROM_NT(Status), L"attr=SECPKG_ATTR_LIFESPAN");
					return Status;
				}
				break;
			default:
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN");
				return SEC_E_INVALID_TOKEN;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"SEC_E_OK");
		return SEC_E_OK;
	}



	// First call (no ContextHandle): create a context on a credential that was
	// acquired for ulRequiredUse. Later calls: look up the existing context.
	static NTSTATUS ResolveLsaModeContext(LSA_SEC_HANDLE CredentialHandle, LSA_SEC_HANDLE ContextHandle,
		ULONG ulRequiredUse, CSecurityContext** ppContext, PLSA_SEC_HANDLE NewContextHandle)
	{
		*ppContext = nullptr;
		if (ContextHandle == NULL)
		{
			CCredential* pCredential = CCredential::GetCredentialFromHandle(CredentialHandle);
			if (pCredential == NULL)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCredential = %p",pCredential);
				return SEC_E_UNKNOWN_CREDENTIALS;
			}
			if ((pCredential->Use & ulRequiredUse) == 0)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Use = %d",pCredential->Use);
				return SEC_E_UNKNOWN_CREDENTIALS;
			}
			CSecurityContext* pNewContext = CSecurityContext::CreateContext(pCredential);
			if (pNewContext == NULL)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateContext failed");
				return SEC_E_INSUFFICIENT_MEMORY;
			}
			*NewContextHandle = reinterpret_cast<LSA_SEC_HANDLE>(pNewContext);
			*ppContext = pNewContext;
			return STATUS_SUCCESS;
		}
		CSecurityContext* pCurrentContext = CSecurityContext::GetContextFromHandle(ContextHandle);
		if (pCurrentContext == NULL)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"currentContext = %p",pCurrentContext);
			return SEC_E_INVALID_HANDLE;
		}
		*NewContextHandle = ContextHandle;
		*ppContext = pCurrentContext;
		return STATUS_SUCCESS;
	}

	/**  The SpInitLsaModeContext function is the client dispatch function used to establish a 
	security context between a server and client.

	The SpInitLsaModeContext function is called when the client calls the 
	InitializeSecurityContext (General) function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpInitLsaModeContext(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   PUNICODE_STRING TargetName,
		  __in   ULONG ContextRequirements,
		  __in   ULONG TargetDataRep,
		  __in   PSecBufferDesc InputBuffers,
		  __out  PLSA_SEC_HANDLE NewContextHandle,
		  __out  PSecBufferDesc OutputBuffers,
		  __out  PULONG ContextAttributes,
		  __out  PTimeStamp ExpirationTime,
		  __out  PBOOLEAN MappedContext,
		  __out  PSecBuffer ContextData  // NOSONAR - API-01: signature dictated by Windows/callback API
		)
	{
		UNREFERENCED_PARAMETER(ContextData);
		UNREFERENCED_PARAMETER(TargetDataRep);
		UNREFERENCED_PARAMETER(ContextRequirements);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter TargetName = %wZ",TargetName);
		NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		CSecurityContext* newContext = NULL;
		__try
		{
			*MappedContext = FALSE;
			*ContextAttributes = ASC_REQ_CONNECTION | ASC_REQ_REPLAY_DETECT;
			Status = ResolveLsaModeContext(CredentialHandle, ContextHandle, SECPKG_CRED_OUTBOUND, &newContext, NewContextHandle);
			if (Status != STATUS_SUCCESS)
			{
				__leave;
			}
			if (ContextHandle != NULL)
			{
				Status = newContext->InitializeSecurityContextInput(InputBuffers);
				if (Status != STATUS_SUCCESS)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"InitializeSecurityContextInput = 0x%08X",Status);
					__leave;
				}
			}
			// forever
			*ExpirationTime = Forever;
			Status = newContext->InitializeSecurityContextOutput(OutputBuffers);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"InitializeSecurityContextOutput = 0x%08X",Status);
				__leave;
			}

		}
		__finally
		{
			// A context created by this call is the package's to delete when the call fails:
			// the caller gets no handle back, so nothing else would ever free it.
			if (ContextHandle == NULL && newContext && static_cast<LONG>(Status) < 0)
			{
				CSecurityContext::Delete(reinterpret_cast<ULONG_PTR>(newContext));
				*NewContextHandle = 0;
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with Status = 0x%08X",Status);
		return Status;
	}

	// pAccountExpiration (optional) receives the time after which the account
	// may no longer log on (account expiry / end of permitted logon hours), as
	// computed by CheckAuthorization; MAXLONGLONG means never.
	NTSTATUS NTAPI SpCreateToken(DWORD dwRid, PHANDLE phToken, PLARGE_INTEGER pAccountExpiration)
	{
		NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		NTSTATUS SubStatus = STATUS_SUCCESS;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		LUID LogonId;
		TOKEN_SOURCE tokenSource = { "EIDAuth", PackageUid};
		UNICODE_STRING AccountName;
		UNICODE_STRING AuthorityName;
		UNICODE_STRING Workstation;
		UNICODE_STRING ProfilePath;
		UNICODE_STRING Prefix = {0,0,NULL};
		PLSA_TOKEN_INFORMATION_V2 MyTokenInformation = NULL;
		DWORD TokenLength;
		WCHAR szComputer[UNLEN+1];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		WCHAR szUserName[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		DWORD dwSize;
		USER_INFO_3 *pInfo = NULL;
		DWORD dwEntriesRead;
		DWORD dwTotalEntries;
		NET_API_STATUS NetStatus ;
		DWORD dwI;
		LARGE_INTEGER AccountExpirationTime;
		__try
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
			// create session
			if (!phToken)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"phToken null");
				Status = STATUS_INVALID_PARAMETER;
				__leave;
			}
			*phToken = INVALID_HANDLE_VALUE;
			if (pAccountExpiration)
			{
				pAccountExpiration->QuadPart = MAXLONGLONG;
			}
			// create the sid from the rid
			
			NetStatus = NetUserEnum(NULL, 3, 0, reinterpret_cast<PBYTE*>(&pInfo), MAX_PREFERRED_LENGTH, &dwEntriesRead,&dwTotalEntries, NULL);  // NOSONAR - CAST-01: Win32/LSA interop cast, layout-verified
			// Every failure below must set Status: it starts as STATUS_SUCCESS,
			// and a "successful" return with *phToken == INVALID_HANDLE_VALUE
			// would have the caller DuplicateHandle the LSASS process
			// pseudo-handle into the client.
			if (NetStatus != NERR_Success)
			{
				Status = STATUS_LOGON_FAILURE;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum = 0x%08X",NetStatus);
				__leave;
			}
			for (dwI = 0; dwI < dwEntriesRead; dwI++)
			{
				if ( pInfo[dwI].usri3_user_id == dwRid)
				{
					wcscpy_s(szUserName, ARRAYSIZE(szUserName), pInfo[dwI].usri3_name);
					break;
				}
			}
			if (dwI >= dwEntriesRead)
			{
				Status = STATUS_LOGON_FAILURE;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Userid not found");
				__leave;
			}
			// Account restrictions (disabled, locked out, expired, logon hours,
			// workstation) - the same check the interactive logon path performs
			// through UserNameToToken. A network token must not be issued for an
			// account that could not log on interactively.
			Status = CheckAuthorization(szUserName, &SubStatus, &AccountExpirationTime);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CheckAuthorization failed 0x%08X 0x%08X",Status, SubStatus);
				EIDSecurityAudit(SECURITY_AUDIT_FAILURE, L"[AUTH_RESTRICTED] SSP network logon refused for user '%s': account restriction 0x%08X/0x%08X", szUserName, Status, SubStatus);
				__leave;
			}
			if (pAccountExpiration)
			{
				*pAccountExpiration = AccountExpirationTime;
			}
			dwSize = ARRAYSIZE(szComputer);
			GetComputerNameW(szComputer, &dwSize);
			Workstation.Buffer = szComputer;
			AuthorityName.Buffer = szComputer;
			Workstation.Length = Workstation.MaximumLength = static_cast<USHORT>(wcslen(szComputer) * sizeof(WCHAR));  // NOSONAR - IDIOM-01: chained assignment sets Length and MaximumLength together
			AuthorityName.Length = AuthorityName.MaximumLength = static_cast<USHORT>(wcslen(szComputer) * sizeof(WCHAR));  // NOSONAR - IDIOM-01: chained assignment sets Length and MaximumLength together
			AccountName.Buffer = szUserName;
			AccountName.Length = AccountName.MaximumLength = static_cast<USHORT>(wcslen(szUserName) * sizeof(WCHAR));  // NOSONAR - IDIOM-01: chained assignment sets Length and MaximumLength together
			ProfilePath.Length = ProfilePath.MaximumLength = static_cast<USHORT>(wcslen(pInfo[dwI].usri3_profile) * sizeof(WCHAR));  // NOSONAR - IDIOM-01: chained assignment sets Length and MaximumLength together
			ProfilePath.Buffer = pInfo[dwI].usri3_profile;
			Status = MyLsaDispatchTable->GetAuthDataForUser(reinterpret_cast<PSECURITY_STRING>(&AccountName), SecNameSamCompatible, reinterpret_cast<PSECURITY_STRING>(&Prefix), reinterpret_cast<PUCHAR*>(&MyTokenInformation), &TokenLength, NULL);  // NOSONAR - CAST-01: Win32/LSA interop cast, layout-verified
			if (Status != STATUS_SUCCESS) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetAuthDataForUser failed 0x%08X 0x%08X",Status, SubStatus);
				__leave;
			}
			Status = MyLsaDispatchTable->ConvertAuthDataToToken(MyTokenInformation, TokenLength, SecurityImpersonation, &tokenSource,
							Network, &AuthorityName, phToken, &LogonId,&AccountName, &SubStatus);
			if (Status != STATUS_SUCCESS) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateToken failed 0x%08X 0x%08X",Status, SubStatus);
				__leave;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Token = %p",*phToken);
		}
		__finally
		{
			if (pInfo)
				NetApiBufferFree(pInfo);
			// GetAuthDataForUser allocates the auth data from the LSA heap; it
			// was never freed, leaking it on every accepted context.
			if (MyTokenInformation)
				MyLsaDispatchTable->FreeLsaHeap(MyTokenInformation);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with Status = 0x%08X",Status);
		return Status;
	}

	/** Server dispatch function used to create a  security context shared by a server and client.

	The SpAcceptLsaModeContext function is called when the server calls the 
	AcceptSecurityContext (General) function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpAcceptLsaModeContext(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   PSecBufferDesc InputBuffers,
		  __in   ULONG ContextRequirements,
		  __in   ULONG TargetDataRep,
		  __out  PLSA_SEC_HANDLE NewContextHandle,
		  __out  PSecBufferDesc OutputBuffers,
		  __out  PULONG ContextAttributes,
		  __out  PTimeStamp ExpirationTime,
		  __out  PBOOLEAN MappedContext,
		  __out  PSecBuffer ContextData
		)
	{
		UNREFERENCED_PARAMETER(ContextData);
		UNREFERENCED_PARAMETER(TargetDataRep);
		UNREFERENCED_PARAMETER(ContextRequirements);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS Status = STATUS_SUCCESS;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		PEID_SSP_CALLBACK_MESSAGE callbackMessage = NULL;
		HANDLE hToken = NULL;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
		LARGE_INTEGER AccountExpiration;
		AccountExpiration.QuadPart = MAXLONGLONG;
		CSecurityContext* newContext = NULL;
		__try
		{
			*MappedContext = FALSE;
			*ContextAttributes = ASC_REQ_CONNECTION | ASC_REQ_REPLAY_DETECT;
			Status = ResolveLsaModeContext(CredentialHandle, ContextHandle, SECPKG_CRED_INBOUND, &newContext, NewContextHandle);
			if (Status != STATUS_SUCCESS)
			{
				__leave;
			}
			Status = newContext->AcceptSecurityContextInput(InputBuffers);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AcceptSecurityContextInput = 0x%08X",Status);
				__leave;
			}
			Status = newContext->AcceptSecurityContextOutput(OutputBuffers);
			// forever
			*ExpirationTime = Forever;
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AcceptSecurityContextOutput = 0x%08X",Status);
				__leave;
			}
			// final call :
			// create a token and send it to the client

			Status = SpCreateToken(newContext->GetRid(), &hToken, &AccountExpiration);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SpCreateToken = 0x%08X",Status);
				__leave;
			}
			// The context must not outlive the account: clamp the expiration
			// reported to the caller to the account expiry / logon-hours limit
			// computed by CheckAuthorization (previously computed, then
			// discarded in favour of Forever).
			{
				LARGE_INTEGER liForever;
				liForever.LowPart = Forever.LowPart;
				liForever.HighPart = Forever.HighPart;
				if (AccountExpiration.QuadPart < liForever.QuadPart)
				{
					ExpirationTime->LowPart = AccountExpiration.LowPart;
					ExpirationTime->HighPart = AccountExpiration.HighPart;
					newContext->SetExpiry(AccountExpiration.QuadPart);
				}
			}
			callbackMessage = static_cast<PEID_SSP_CALLBACK_MESSAGE>(EIDAlloc(sizeof(EID_SSP_CALLBACK_MESSAGE)));
			if (!callbackMessage)
			{
				Status = SEC_E_INSUFFICIENT_MEMORY;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"callbackMessage no memory");
				__leave;
			}
			// duplicate the handle to the process space
			callbackMessage->Caller = EID_SSP_CALLER::EIDSSPAccept;
			Status = MyLsaDispatchTable->DuplicateHandle(hToken, &callbackMessage->hToken);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"DuplicateHandle = 0x%08X",Status);
				__leave;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"token = %p",callbackMessage->hToken);
			*MappedContext = TRUE;
			ContextData->BufferType = SECBUFFER_DATA;
			ContextData->cbBuffer = sizeof(EID_SSP_CALLBACK_MESSAGE);
			ContextData->pvBuffer = callbackMessage;
			
		}
		__finally
		{
			if (Status != STATUS_SUCCESS)
			{
				if (callbackMessage)  // NOSONAR - COMPLEXITY-01: nested guard retained for readability; logic verified
					EIDFree(callbackMessage);
			}
			// The client gets its own copy through DuplicateHandle; LSASS's
			// handle to the token was never closed, leaking one token handle
			// (and the logon session it pins) per accepted context.
			if (hToken && hToken != INVALID_HANDLE_VALUE)
				CloseHandle(hToken);
			// See SpInitLsaModeContext: a context created by a failed first call is ours to delete.
			if (ContextHandle == NULL && newContext && static_cast<LONG>(Status) < 0)
			{
				CSecurityContext::Delete(reinterpret_cast<ULONG_PTR>(newContext));
				*NewContextHandle = 0;
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpSetContextAttributes (
					__in LSA_SEC_HANDLE ContextHandle,
					__in ULONG ContextAttribute,
					__in PVOID Buffer,
					__in ULONG BufferSize )
	{
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(ContextAttribute);
		UNREFERENCED_PARAMETER(Buffer);
		UNREFERENCED_PARAMETER(BufferSize);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpSetCredentialsAttributes(
					__in LSA_SEC_HANDLE CredentialHandle,
					__in ULONG CredentialAttribute,
					__in PVOID Buffer,
					__in ULONG BufferSize )
	{
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(CredentialAttribute);
		UNREFERENCED_PARAMETER(Buffer);
		UNREFERENCED_PARAMETER(BufferSize);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpChangeAccountPassword(
					__in PUNICODE_STRING      pDomainName,  // NOSONAR - API-01: signature dictated by Windows/callback API
					__in PUNICODE_STRING      pAccountName,  // NOSONAR - API-01: signature dictated by Windows/callback API
					__in PUNICODE_STRING      pOldPassword,  // NOSONAR - API-01: signature dictated by Windows/callback API
					__in PUNICODE_STRING      pNewPassword,  // NOSONAR - API-01: signature dictated by Windows/callback API
					__in BOOLEAN              Impersonating,
					__inout PSecBufferDesc   pOutput  // NOSONAR - API-01: signature dictated by Windows/callback API
					)
	{
		UNREFERENCED_PARAMETER(pDomainName);
		UNREFERENCED_PARAMETER(pAccountName);
		UNREFERENCED_PARAMETER(pOldPassword);
		UNREFERENCED_PARAMETER(pNewPassword);
		UNREFERENCED_PARAMETER(Impersonating);
		UNREFERENCED_PARAMETER(pOutput);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpQueryMetaData(
					__in_opt LSA_SEC_HANDLE CredentialHandle,
					__in_opt PUNICODE_STRING TargetName,  // NOSONAR - API-01: signature dictated by Windows/callback API
					__in ULONG ContextRequirements,
					__out PULONG MetaDataLength,  // NOSONAR - API-01: signature dictated by Windows/callback API
					__deref_out_bcount(*MetaDataLength) PUCHAR* MetaData,
					__inout PLSA_SEC_HANDLE ContextHandle  // NOSONAR - API-01: signature dictated by Windows/callback API
					)
	{
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(TargetName);
		UNREFERENCED_PARAMETER(ContextRequirements);
		UNREFERENCED_PARAMETER(MetaDataLength);
		UNREFERENCED_PARAMETER(MetaData);
		UNREFERENCED_PARAMETER(ContextHandle);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpExchangeMetaData(
					__in_opt LSA_SEC_HANDLE CredentialHandle,
					__in_opt PUNICODE_STRING TargetName,  // NOSONAR - API-01: signature dictated by Windows/callback API
					__in ULONG ContextRequirements,
					__in ULONG MetaDataLength,
					__in_bcount(MetaDataLength) PUCHAR MetaData,  // NOSONAR - API-01: signature dictated by Windows/callback API
					__inout PLSA_SEC_HANDLE ContextHandle  // NOSONAR - API-01: signature dictated by Windows/callback API
					)
	{
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(TargetName);
		UNREFERENCED_PARAMETER(ContextRequirements);
		UNREFERENCED_PARAMETER(MetaDataLength);
		UNREFERENCED_PARAMETER(MetaData);
		UNREFERENCED_PARAMETER(ContextHandle);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpGetCredUIContext(
				   __in LSA_SEC_HANDLE ContextHandle,
				   __in GUID* CredType,  // NOSONAR - API-01: signature dictated by Windows/callback API
				   __out PULONG FlatCredUIContextLength,  // NOSONAR - API-01: signature dictated by Windows/callback API
				   __deref_out_bcount(*FlatCredUIContextLength)  PUCHAR* FlatCredUIContext
				   )
	  {
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(CredType);
		UNREFERENCED_PARAMETER(FlatCredUIContextLength);
		UNREFERENCED_PARAMETER(FlatCredUIContext);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	  }

	NTSTATUS NTAPI SpUpdateCredentials(
				  __in LSA_SEC_HANDLE ContextHandle,
				  __in GUID* CredType,  // NOSONAR - API-01: signature dictated by Windows/callback API
				  __in ULONG FlatCredUIContextLength,
				  __in_bcount(FlatCredUIContextLength) PUCHAR FlatCredUIContext  // NOSONAR - API-01: signature dictated by Windows/callback API
				  )
	{
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(CredType);
		UNREFERENCED_PARAMETER(FlatCredUIContextLength);
		UNREFERENCED_PARAMETER(FlatCredUIContext);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpValidateTargetInfo (
				__in_opt PLSA_CLIENT_REQUEST ClientRequest,
				__in_bcount(SubmitBufferLength) PVOID ProtocolSubmitBuffer,
				__in PVOID ClientBufferBase,
				__in ULONG SubmitBufferLength,
				__in PSECPKG_TARGETINFO TargetInfo  // NOSONAR - API-01: signature dictated by Windows/callback API
				)
	{
		UNREFERENCED_PARAMETER(ClientRequest);
		UNREFERENCED_PARAMETER(ProtocolSubmitBuffer);
		UNREFERENCED_PARAMETER(ClientBufferBase);
		UNREFERENCED_PARAMETER(SubmitBufferLength);
		UNREFERENCED_PARAMETER(TargetInfo);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	// Network (SSP) authentication is not supported in this build (README) and nothing in the
	// product initiates or accepts it. The handshake code (SpAcquireCredentialsHandle,
	// SpInitLsaModeContext, SpAcceptLsaModeContext and CSecurityContext) lets any local caller
	// drive LSASS state shared across concurrent calls on one handle, without a per-context
	// lock, with credentials referenced by raw pointer and with handles that are LSASS heap
	// addresses. Until that is reworked (per-context lock, reference counting, opaque handles),
	// the function table points these three entries at refusals, so no credential or context
	// is ever created; the remaining Sp* functions then only ever see handles they do not know.
	static NTSTATUS NTAPI SpAcquireCredentialsHandleDisabled(
		  __in   PUNICODE_STRING PrincipalName,
		  __in   ULONG CredentialUseFlags,
		  __in   PLUID LogonId,
		  __in   PVOID AuthorizationData,
		  __in   PVOID GetKeyFunction,
		  __in   PVOID GetKeyArgument,
		  __out  PLSA_SEC_HANDLE pCredentialHandle,
		  __out  PTimeStamp ExpirationTime
		)
	{
		UNREFERENCED_PARAMETER(PrincipalName);
		UNREFERENCED_PARAMETER(CredentialUseFlags);
		UNREFERENCED_PARAMETER(LogonId);
		UNREFERENCED_PARAMETER(AuthorizationData);
		UNREFERENCED_PARAMETER(GetKeyFunction);
		UNREFERENCED_PARAMETER(GetKeyArgument);
		UNREFERENCED_PARAMETER(ExpirationTime);
		if (pCredentialHandle)
		{
			*pCredentialHandle = 0;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Network authentication is not supported: AcquireCredentialsHandle refused");
		return SEC_E_UNSUPPORTED_FUNCTION;
	}

	static NTSTATUS NTAPI SpInitLsaModeContextDisabled(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   PUNICODE_STRING TargetName,
		  __in   ULONG ContextRequirements,
		  __in   ULONG TargetDataRep,
		  __in   PSecBufferDesc InputBuffers,
		  __out  PLSA_SEC_HANDLE NewContextHandle,
		  __out  PSecBufferDesc OutputBuffers,
		  __out  PULONG ContextAttributes,
		  __out  PTimeStamp ExpirationTime,
		  __out  PBOOLEAN MappedContext,
		  __out  PSecBuffer ContextData
		)
	{
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(TargetName);
		UNREFERENCED_PARAMETER(ContextRequirements);
		UNREFERENCED_PARAMETER(TargetDataRep);
		UNREFERENCED_PARAMETER(InputBuffers);
		UNREFERENCED_PARAMETER(OutputBuffers);
		UNREFERENCED_PARAMETER(ContextAttributes);
		UNREFERENCED_PARAMETER(ExpirationTime);
		UNREFERENCED_PARAMETER(ContextData);
		if (NewContextHandle)
		{
			*NewContextHandle = 0;
		}
		if (MappedContext)
		{
			*MappedContext = FALSE;
		}
		return SEC_E_UNSUPPORTED_FUNCTION;
	}

	static NTSTATUS NTAPI SpAcceptLsaModeContextDisabled(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   PSecBufferDesc InputBuffers,
		  __in   ULONG ContextRequirements,
		  __in   ULONG TargetDataRep,
		  __out  PLSA_SEC_HANDLE NewContextHandle,
		  __out  PSecBufferDesc OutputBuffers,
		  __out  PULONG ContextAttributes,
		  __out  PTimeStamp ExpirationTime,
		  __out  PBOOLEAN MappedContext,
		  __out  PSecBuffer ContextData
		)
	{
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(InputBuffers);
		UNREFERENCED_PARAMETER(ContextRequirements);
		UNREFERENCED_PARAMETER(TargetDataRep);
		UNREFERENCED_PARAMETER(OutputBuffers);
		UNREFERENCED_PARAMETER(ContextAttributes);
		UNREFERENCED_PARAMETER(ExpirationTime);
		UNREFERENCED_PARAMETER(ContextData);
		if (NewContextHandle)
		{
			*NewContextHandle = 0;
		}
		if (MappedContext)
		{
			*MappedContext = FALSE;
		}
		return SEC_E_UNSUPPORTED_FUNCTION;
	}

	void initializeLSAExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions);
	/** Called during system initialization to permit the authentication package to perform
	initialization tasks.*/
	// at the end to avoid double declaration of functions
	void initializeExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions)
	{
		initializeLSAExportedFunctionsTable(exportedFunctions);
		exportedFunctions->Initialize = SpInitialize;
		exportedFunctions->Shutdown = SpShutDown;
		exportedFunctions->GetInfo = SpGetInfo;
		exportedFunctions->AcceptCredentials = SpAcceptCredentials;
		exportedFunctions->AcquireCredentialsHandle = SpAcquireCredentialsHandleDisabled;
		exportedFunctions->QueryCredentialsAttributes = SpQueryCredentialsAttributes;
		exportedFunctions->FreeCredentialsHandle = SpFreeCredentialsHandle;
		exportedFunctions->SaveCredentials = SpSaveCredentials;
		exportedFunctions->GetCredentials = SpGetCredentials;
		exportedFunctions->DeleteCredentials = SpDeleteCredentials;
		exportedFunctions->InitLsaModeContext = SpInitLsaModeContextDisabled;
		exportedFunctions->AcceptLsaModeContext = SpAcceptLsaModeContextDisabled;
		exportedFunctions->DeleteContext = SpDeleteSecurityContext;
		exportedFunctions->ApplyControlToken = SpApplyControlToken;
		exportedFunctions->GetUserInfo = SpGetUserInfo;
		exportedFunctions->GetExtendedInformation = SpGetExtendedInformation;
		exportedFunctions->QueryContextAttributes = SpQueryContextAttributes;
		exportedFunctions->AddCredentials = SpAddCredentials;
		exportedFunctions->SetExtendedInformation = SpSetExtendedInformation;
		exportedFunctions->SetContextAttributes = SpSetContextAttributes; // only schanel implements this
		exportedFunctions->SetCredentialsAttributes = SpSetCredentialsAttributes; // not documented
		exportedFunctions->ChangeAccountPassword = SpChangeAccountPassword; // not documented
		exportedFunctions->QueryMetaData = SpQueryMetaData;
		exportedFunctions->ExchangeMetaData = SpExchangeMetaData;
		exportedFunctions->GetCredUIContext = SpGetCredUIContext;
		exportedFunctions->UpdateCredentials = SpUpdateCredentials;
		exportedFunctions->ValidateTargetInfo = SpValidateTargetInfo;
	}
}