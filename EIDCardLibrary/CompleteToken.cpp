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

#define SECURITY_WIN32
#include <sspi.h>

#include <NTSecAPI.h>
#include <NTSecPKG.h>
#include <SubAuth.h>
#include <LM.h>
#include <sddl.h>

#include <utility>  // for std::pair
#include <bit>      // for std::bit_cast (SonarQube cpp:S3624)

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "ErrorHandling.h"
#include "CompleteToken.h"

BOOL NameToSid(WCHAR* UserName, PSID* pUserSid);
BOOL GetGroups(WCHAR* UserName,PGROUP_USERS_INFO_1 *lpGroupInfo, LPDWORD pTotalEntries);
BOOL GetLocalGroups(WCHAR* UserName,PGROUP_USERS_INFO_0 *lpGroupInfo, LPDWORD pTotalEntries);
BOOL GetPrimaryGroupSidFromUserSid(PSID UserSID, PSID *PrimaryGroupSID);
void DebugPrintSid(const WCHAR* Name, PSID Sid);

// Internal function using Result<T> for type-safe error handling
// Marked noexcept for LSASS compatibility
// Returns token info structure with size, or HRESULT error
[[nodiscard]] EID::Result<std::pair<PLSA_TOKEN_INFORMATION_V2, DWORD>> UserNameToTokenInternal(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    __in PLSA_UNICODE_STRING AccountName,  // NOSONAR - API-01: signature dictated by Windows/callback API
    __out PNTSTATUS SubStatus) noexcept
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Enter");
	PLSA_TOKEN_INFORMATION_V2 TokenInformation = nullptr;
	PTOKEN_GROUPS pTokenGroups = nullptr;
	PGROUP_USERS_INFO_1 pGroupInfo = nullptr;
	PGROUP_USERS_INFO_0 pLocalGroupInfo = nullptr;

	DWORD NumberOfGroups = 0;
	DWORD NumberOfLocalGroups = 0;
	BOOL bResult;
	PSID UserSid = nullptr;
	PSID PrimaryGroupSid = nullptr;
	PSID* pGroupSid = nullptr;
	DWORD Size = 0;
	PBYTE Offset;
	DWORD i;
	LARGE_INTEGER ExpirationTime;
	// convert AccountName to WSTR
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Convert");
	WCHAR UserName[UNLEN+1];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety

	// Helper lambda for cleanup on error
	auto cleanup = [&]() {
		if (PrimaryGroupSid) EIDFree(PrimaryGroupSid);
		if (UserSid) EIDFree(UserSid);
		if (pGroupSid)
		{
			// The array owns the individual group SIDs too; freeing only the
			// array leaked every SID already resolved on an error path.
			for (DWORD j = 0; j < NumberOfGroups + NumberOfLocalGroups; j++)
			{
				if (pGroupSid[j]) EIDFree(pGroupSid[j]);
			}
			EIDFree(pGroupSid);
		}
		if (pGroupInfo) NetApiBufferFree(pGroupInfo);
		if (pLocalGroupInfo) NetApiBufferFree(pLocalGroupInfo);
		if (TokenInformation) EIDFree(TokenInformation);
	};

	wcsncpy_s(UserName, ARRAYSIZE(UserName), AccountName->Buffer, AccountName->Length / 2);
	UserName[AccountName->Length / 2] = 0;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"CheckAuthorization");
	// check authorization
	NTSTATUS Status = CheckAuthorization(UserName, SubStatus, &ExpirationTime);
	if (Status != STATUS_SUCCESS)  // NOSONAR - SCOPE-01: declaration kept in outer scope for clarity
	{
		cleanup();
		return EID::make_unexpected(HRESULT_FROM_NT(Status));
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"GetGroups");
	// get the number of groups
	bResult = GetGroups(UserName, &pGroupInfo, &NumberOfGroups);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GetGroups error");
		cleanup();
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"GetLocalGroups");
	bResult = GetLocalGroups(UserName, &pLocalGroupInfo, &NumberOfLocalGroups);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GetLocalGroups error");
		cleanup();
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
	}

	// get SID
	// User
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"User");
	bResult = NameToSid(UserName, &UserSid);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"NameToSid");
		cleanup();
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
	}
	// Primary Group Id
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Primary Group Id");
	bResult = GetPrimaryGroupSidFromUserSid(UserSid, &PrimaryGroupSid);
	if (!bResult)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GetPrimaryGroupSidFromUserSid");
		cleanup();
		return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
	}
	Size = 0;
	// Group
	pGroupSid = (PSID*)EIDAlloc((NumberOfGroups + NumberOfLocalGroups) * sizeof(PSID));
	if (!pGroupSid)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"pGroupSid NULL");
		cleanup();
		return EID::make_unexpected(E_OUTOFMEMORY);
	}
	// Initialize all to nullptr for safe cleanup
	for (i = 0; i < NumberOfGroups + NumberOfLocalGroups; i++)
	{
		pGroupSid[i] = nullptr;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Group");
	// NameToSid leaves the output NULL on failure, and GetLengthSid(NULL)
	// faults inside LSASS. A group whose name no longer maps to a SID
	// (orphaned or renamed: ERROR_NONE_MAPPED) is SKIPPED rather than
	// failing the whole logon, so one stale membership cannot lock the
	// account out. Any OTHER lookup failure (DC unreachable, out of memory)
	// fails the logon: leaving out a group that does exist could silently
	// lift a Deny ACE that names it. Skipped entries stay NULL in pGroupSid
	// and are compacted out when TOKEN_GROUPS is built, so the array has no
	// holes; dwResolvedGroups is its real count.
	DWORD dwResolvedGroups = 0;
	for (i = 0; i < NumberOfGroups; i++)
	{
		if (!NameToSid(pGroupInfo[i].grui1_name, &pGroupSid[i]) || !pGroupSid[i])
		{
			const DWORD dwLookupError = GetLastError();
			if (dwLookupError != ERROR_NONE_MAPPED)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"NameToSid failed for group %s (0x%08x) - failing the logon", pGroupInfo[i].grui1_name, dwLookupError);
				cleanup();
				return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"group %s no longer maps to a SID - left out of the token", pGroupInfo[i].grui1_name);
			if (pGroupSid[i])
			{
				EIDFree(pGroupSid[i]);
			}
			pGroupSid[i] = nullptr;
			continue;
		}
		Size += GetLengthSid(pGroupSid[i]);
		dwResolvedGroups++;
	}
	for (i = 0; i < NumberOfLocalGroups; i++)
	{
		if (!NameToSid(pLocalGroupInfo[i].grui0_name, &pGroupSid[NumberOfGroups + i]) || !pGroupSid[NumberOfGroups + i])
		{
			const DWORD dwLookupError = GetLastError();
			if (dwLookupError != ERROR_NONE_MAPPED)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"NameToSid failed for local group %s (0x%08x) - failing the logon", pLocalGroupInfo[i].grui0_name, dwLookupError);
				cleanup();
				return EID::make_unexpected(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"local group %s no longer maps to a SID - left out of the token", pLocalGroupInfo[i].grui0_name);
			if (pGroupSid[NumberOfGroups + i])
			{
				EIDFree(pGroupSid[NumberOfGroups + i]);
			}
			pGroupSid[NumberOfGroups + i] = nullptr;
			continue;
		}
		Size += GetLengthSid(pGroupSid[NumberOfGroups + i]);
		dwResolvedGroups++;
	}
	// compute the size
	Size += sizeof(LSA_TOKEN_INFORMATION_V2); // struct
	Size += GetLengthSid(UserSid) + GetLengthSid(PrimaryGroupSid);//sid user and primary group
	// groups: TOKEN_GROUPS header (GroupCount plus padding) and one
	// SID_AND_ATTRIBUTES per resolved group
	Size += static_cast<DWORD>(FIELD_OFFSET(TOKEN_GROUPS, Groups)) + (sizeof(SID_AND_ATTRIBUTES)) * dwResolvedGroups;

	TokenInformation = (PLSA_TOKEN_INFORMATION_V2)EIDAlloc(Size);
	if (TokenInformation == nullptr)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"TokenInformation NULL");
		cleanup();
		return EID::make_unexpected(E_OUTOFMEMORY);
	}
	// update offset and copy info
	Offset = (PBYTE)TokenInformation + sizeof(LSA_TOKEN_INFORMATION_V1);
	TokenInformation->User.User.Sid = (PSID)Offset;
	CopySid(GetLengthSid(UserSid), Offset, UserSid);
	DebugPrintSid(UserName, UserSid);
	TokenInformation->User.User.Attributes = 0; // cf msdn, no attributes defined for users sid
	Offset += GetLengthSid(UserSid);

	TokenInformation->PrimaryGroup.PrimaryGroup = (PSID)Offset;
	CopySid(GetLengthSid(PrimaryGroupSid), Offset, PrimaryGroupSid);
	DebugPrintSid(L"PrimaryGroupId", PrimaryGroupSid);
	Offset += GetLengthSid(PrimaryGroupSid);

	TokenInformation->Groups = (PTOKEN_GROUPS)Offset;
	pTokenGroups = (PTOKEN_GROUPS)Offset;
	pTokenGroups->GroupCount = dwResolvedGroups;
	// Header plus exactly dwResolvedGroups entries (FIELD_OFFSET rather than
	// sizeof(TOKEN_GROUPS) - ANYSIZE_ARRAY entries, which wraps when every
	// group was skipped)
	Offset += FIELD_OFFSET(TOKEN_GROUPS, Groups) + sizeof(SID_AND_ATTRIBUTES) * dwResolvedGroups;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Group Struct time");

	// dwOut indexes the compacted TOKEN_GROUPS array; unresolved (NULL)
	// entries of pGroupSid are skipped.
	DWORD dwOut = 0;
	for (i = 0; i < NumberOfGroups; i++)
	{
		if (!pGroupSid[i])
		{
			continue;
		}
		// attributes get directly from the struct
		pTokenGroups->Groups[dwOut].Attributes = pGroupInfo[i].grui1_attributes;
		pTokenGroups->Groups[dwOut].Sid = (PSID)Offset;
		CopySid(GetLengthSid(pGroupSid[i]), Offset, pGroupSid[i]);
		Offset += GetLengthSid(pGroupSid[i]);
		DebugPrintSid(pGroupInfo[i].grui1_name, pGroupSid[i]);
		EIDFree(pGroupSid[i]);
		pGroupSid[i] = nullptr;
		dwOut++;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Group 2");
	for (i = 0; i < NumberOfLocalGroups; i++)
	{
		if (!pGroupSid[NumberOfGroups + i])
		{
			continue;
		}
		// get the attributes of group since the struct doesn't contain attributes
		if (*GetSidSubAuthority(pGroupSid[NumberOfGroups + i], 0) != SECURITY_BUILTIN_DOMAIN_RID)
		{
			pTokenGroups->Groups[dwOut].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT;
		}
		else
		{
			pTokenGroups->Groups[dwOut].Attributes = 0;
		}
		pTokenGroups->Groups[dwOut].Sid = (PSID)Offset;
		CopySid(GetLengthSid(pGroupSid[NumberOfGroups + i]), Offset, pGroupSid[NumberOfGroups + i]);
		Offset += GetLengthSid(pGroupSid[NumberOfGroups + i]);
		DebugPrintSid(pLocalGroupInfo[i].grui0_name, pGroupSid[NumberOfGroups + i]);
		EIDFree(pGroupSid[NumberOfGroups + i]);
		pGroupSid[NumberOfGroups + i] = nullptr;
		dwOut++;
	}

	// Expiration time
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Expiration time");
	TokenInformation->ExpirationTime = ExpirationTime;

	// privileges
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"privileges");
	TokenInformation->Privileges = nullptr;

	// owner
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"owner");
	TokenInformation->Owner.Owner = nullptr;

	// dacl
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"dacl");
	TokenInformation->DefaultDacl.DefaultDacl = nullptr;

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"TokenInformation done");

	// Free intermediate buffers (but not TokenInformation - that's returned)
	if (PrimaryGroupSid) { EIDFree(PrimaryGroupSid); PrimaryGroupSid = nullptr; }
	if (UserSid) { EIDFree(UserSid); UserSid = nullptr; }
	if (pGroupSid) { EIDFree(pGroupSid); pGroupSid = nullptr; }
	if (pGroupInfo) { NetApiBufferFree(pGroupInfo); pGroupInfo = nullptr; }
	if (pLocalGroupInfo) { NetApiBufferFree(pLocalGroupInfo); pLocalGroupInfo = nullptr; }

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Leave");
	return std::make_pair(TokenInformation, Size);
}

// Map a failure HRESULT from the *Internal functions to a FAILURE NTSTATUS.
// EID::hr_to_ntstatus turns a FACILITY_WIN32 HRESULT into the bare Win32 code
// (e.g. ERROR_ACCOUNT_RESTRICTION -> 0x0000052F), which NT_SUCCESS() treats as
// success, and turns HRESULT_FROM_NT(x) into STATUS_UNSUCCESSFUL, losing x.
// Callers here compare against STATUS_SUCCESS, but anything that tests
// NT_SUCCESS() would have accepted a refused logon, so never return a
// non-error code for a failure.
static NTSTATUS EIDFailureHResultToNtStatus(HRESULT hr) noexcept
{
	if ((hr & FACILITY_NT_BIT) != 0)
	{
		const NTSTATUS ntStatus = static_cast<NTSTATUS>(hr & ~FACILITY_NT_BIT);
		return (static_cast<ULONG>(ntStatus) >= 0xC0000000UL) ? ntStatus : STATUS_LOGON_FAILURE;  // NT_ERROR severity
	}
	if (hr == HRESULT_FROM_WIN32(ERROR_NO_SUCH_USER))
	{
		return STATUS_NO_SUCH_USER;
	}
	const NTSTATUS ntStatus = EID::hr_to_ntstatus(hr);
	return (static_cast<ULONG>(ntStatus) >= 0xC0000000UL) ? ntStatus : STATUS_LOGON_FAILURE;  // NT_ERROR severity
}

// Exported wrapper maintaining NTSTATUS return for LSA compatibility
// Converts HRESULT errors to a failure NTSTATUS (see EIDFailureHResultToNtStatus)
NTSTATUS UserNameToToken(__in PLSA_UNICODE_STRING AccountName,
	__out PLSA_TOKEN_INFORMATION_V2 *Token,
	__out PDWORD TokenLength,
	__out PNTSTATUS SubStatus)
{
	auto result = UserNameToTokenInternal(AccountName, SubStatus);
	if (result)
	{
		auto [tokenInfo, size] = *result;
		*Token = tokenInfo;
		*TokenLength = size;
		return STATUS_SUCCESS;
	}
	return EIDFailureHResultToNtStatus(result.error());
}

// BUG FIX #16: TOCTOU race condition mitigation - use retry loop for SID allocation
BOOL NameToSid(WCHAR* UserName, PSID *pUserSid)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL bResult;
	SID_NAME_USE Use;
	WCHAR checkDomainName[UNCLEN+1];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD cchReferencedDomainName=0;
	constexpr DWORD MAX_RETRIES = 3;
	DWORD dwRetryCount = 0;
	PSID pTempSid = nullptr;

	DWORD dLengthSid = 0;
	bResult = LookupAccountNameW( nullptr, UserName, nullptr,&dLengthSid,nullptr, &cchReferencedDomainName, &Use);

	if (!bResult && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		// Callers decide from the last error whether a failure is fatal, so
		// keep it intact across the trace.
		const DWORD dwLookupError = GetLastError();
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to LookupAccountNameW 0x%08x",dwLookupError);
		SetLastError(dwLookupError);
		return FALSE;
	}

	// Retry loop for SID allocation (handles TOCTOU race condition)
	for (dwRetryCount = 0; dwRetryCount < MAX_RETRIES; dwRetryCount++)  // NOSONAR - PERF-01: declared once, reused across iterations
	{
		// Clean up from previous retry
		if (pTempSid)
		{
			EIDFree(pTempSid);
			pTempSid = nullptr;
		}

		// Allocate SID buffer
		pTempSid = (PSID)EIDAlloc(dLengthSid);
		if (!pTempSid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to allocate SID buffer");
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return FALSE;
		}
		SecureZeroMemory(pTempSid, dLengthSid);

		cchReferencedDomainName=UNCLEN;
		bResult = LookupAccountNameW( nullptr, UserName, pTempSid,&dLengthSid,checkDomainName, &cchReferencedDomainName, &Use);

		if (bResult)
		{
			*pUserSid = pTempSid;
			return TRUE;  // Success - exit retry loop
		}

		DWORD dwError = GetLastError();
		if (dwError == ERROR_INSUFFICIENT_BUFFER)
		{
			// Buffer size changed between check and use (TOCTOU race condition)
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"TOCTOU race condition on retry %u: buffer size changed (retrying...)",
				dwRetryCount + 1);
			// Loop will continue with new dLengthSid value
		}
		else
		{
			// Different error - not a TOCTOU issue, don't retry
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to LookupAccountNameW 0x%08x",dwError);
			EIDFree(pTempSid);
			SetLastError(dwError);
			return FALSE;
		}
	}

	// Exhausted retries
	EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Exhausted %u retries for SID lookup (possible persistent race condition)",
		MAX_RETRIES);
	if (pTempSid)
	{
		EIDFree(pTempSid);
	}
	SetLastError(ERROR_INSUFFICIENT_BUFFER);
	return FALSE;
}

BOOL GetGroups(WCHAR* UserName,PGROUP_USERS_INFO_1 *lpGroupInfo, LPDWORD pTotalEntries)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	NET_API_STATUS Status;
	DWORD NumberOfEntries;
	Status = NetUserGetGroups(nullptr,UserName,1,(LPBYTE*)lpGroupInfo,MAX_PREFERRED_LENGTH,&NumberOfEntries,pTotalEntries);
	if (Status != NERR_Success)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to NetUserGetGroups 0x%08x",Status);
		return FALSE;
	}
	return TRUE;
}

BOOL GetLocalGroups(WCHAR* UserName,PGROUP_USERS_INFO_0 *lpGroupInfo, LPDWORD pTotalEntries)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	NET_API_STATUS Status;
	DWORD NumberOfEntries;
	Status = NetUserGetLocalGroups(nullptr,UserName,0,0,(LPBYTE*)lpGroupInfo,MAX_PREFERRED_LENGTH,&NumberOfEntries,pTotalEntries);
	if (Status != NERR_Success)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to NetUserGetLocalGroups 0x%08x",Status);
		return FALSE;
	}
	return TRUE;
}

BOOL GetPrimaryGroupSidFromUserSid(PSID UserSID, PSID *PrimaryGroupSID)
{
	// duplicate the user sid and replace the last subauthority by DOMAIN_GROUP_RID_USERS
	// cf http://msdn.microsoft.com/en-us/library/aa379649.aspx
	UCHAR SubAuthorityCount;
	*PrimaryGroupSID = EIDAlloc(GetLengthSid(UserSID));
	if (!*PrimaryGroupSID)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No memory for PrimaryGroupSID");
		return FALSE;
	}
	if (!CopySid(GetLengthSid(UserSID),*PrimaryGroupSID,UserSID))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopySid 0x%08x",GetLastError());
		EIDFree(*PrimaryGroupSID);
		*PrimaryGroupSID = nullptr;
		return FALSE;
	}
	SubAuthorityCount = *GetSidSubAuthorityCount(*PrimaryGroupSID);
	*GetSidSubAuthority(*PrimaryGroupSID, SubAuthorityCount-1) = DOMAIN_GROUP_RID_USERS;
	return TRUE;
}

void DebugPrintSid(const WCHAR* Name, PSID Sid)
{
	LPTSTR chSID = nullptr;
	if (!ConvertSidToStringSid(Sid,&chSID) || !chSID)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Name %s Sid <ConvertSidToStringSid 0x%08x>",Name,GetLastError());
		return;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Name %s Sid %s",Name,chSID);
	LocalFree(chSID);
}

// Internal function using Result<T> for type-safe error handling
// Marked noexcept for LSASS compatibility
// Returns expiration time on success, HRESULT error on failure
// Sets SubStatus for account restriction details
[[nodiscard]] EID::Result<LARGE_INTEGER> CheckAuthorizationInternal(
    PWSTR UserName,
    NTSTATUS* SubStatus) noexcept
{
	PUSER_INFO_4 pUserInfo = nullptr;
	LARGE_INTEGER ExpirationTime;
	ExpirationTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
	LONGLONG llAccountExpires = 0x7FFFFFFFFFFFFFFF;  // FILETIME of account expiry; MAX = never

	NET_API_STATUS netStatus = NetUserGetInfo(nullptr, UserName, 4, (LPBYTE*)&pUserInfo);
	if (netStatus != 0)  // NOSONAR - SCOPE-01: declaration kept in outer scope for clarity
	{
		HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
		switch (netStatus)
		{
		case ERROR_ACCESS_DENIED:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"User not found (%s): ACCESS DENIED", UserName);
			hr = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
			break;
		case NERR_InvalidComputer:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"User not found (%s): Invalid computer", UserName);
			hr = HRESULT_FROM_WIN32(ERROR_BAD_NETPATH);
			break;
		case NERR_UserNotFound:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"User not found (%s): No such user", UserName);
			hr = HRESULT_FROM_WIN32(ERROR_NO_SUCH_USER);
			break;
		default:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"User not found (%s): Unknown error 0x%08x", UserName, netStatus);
			hr = HRESULT_FROM_WIN32(ERROR_NO_SUCH_USER);
			break;
		}
		return EID::make_unexpected(hr);
	}

	// Ensure cleanup on all exit paths
	struct UserInfoCleanup {
		PUSER_INFO_4* pp;
		explicit UserInfoCleanup(PUSER_INFO_4* ptr) : pp(ptr) {}
		~UserInfoCleanup() { if (pp && *pp) NetApiBufferFree(*pp); }
		// Delete copy/move - this manages a resource
		UserInfoCleanup(const UserInfoCleanup&) = delete;
		UserInfoCleanup& operator=(const UserInfoCleanup&) = delete;
	};
	UserInfoCleanup cleanup(&pUserInfo);

	if (pUserInfo->usri4_flags & UF_ACCOUNTDISABLE)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Account disabled: ACCOUNT_DISABLED");
		*SubStatus = STATUS_ACCOUNT_DISABLED;
		// Use HRESULT that maps to STATUS_ACCOUNT_RESTRICTION
		return EID::make_unexpected(HRESULT_FROM_NT(STATUS_ACCOUNT_RESTRICTION));
	}

	// A locked-out account (too many bad passwords, or an administrator lock)
	// must not be able to bypass the lockout with a card. SAM reports the
	// current lockout state in usri4_flags.
	if (pUserInfo->usri4_flags & UF_LOCKOUT)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Account locked out: STATUS_ACCOUNT_LOCKED_OUT");
		*SubStatus = STATUS_ACCOUNT_LOCKED_OUT;
		return EID::make_unexpected(HRESULT_FROM_NT(STATUS_ACCOUNT_LOCKED_OUT));
	}

	// Account expiry: usri4_acct_expires is seconds since 1970-01-01 UTC, or
	// TIMEQ_FOREVER when the account never expires.
	if (pUserInfo->usri4_acct_expires != TIMEQ_FOREVER)
	{
		FILETIME ftNow;
		GetSystemTimeAsFileTime(&ftNow);
		ULARGE_INTEGER uliNow;
		uliNow.LowPart = ftNow.dwLowDateTime;
		uliNow.HighPart = ftNow.dwHighDateTime;
		// 116444736000000000 = 1970-01-01 as a FILETIME; 64-bit arithmetic so the
		// seconds-to-100ns conversion cannot wrap.
		const ULONGLONG ullAccountExpires = 116444736000000000ULL +
			static_cast<ULONGLONG>(pUserInfo->usri4_acct_expires) * 10000000ULL;
		if (uliNow.QuadPart >= ullAccountExpires)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Account expired: STATUS_ACCOUNT_EXPIRED");
			*SubStatus = STATUS_ACCOUNT_EXPIRED;
			return EID::make_unexpected(HRESULT_FROM_NT(STATUS_ACCOUNT_EXPIRED));
		}
		llAccountExpires = static_cast<LONGLONG>(ullAccountExpires);
	}

	if (pUserInfo->usri4_logon_hours)
	{
		DWORD dwPosLogon;
		DWORD dwPosLogoff;
		DWORD dwHours;
		SYSTEMTIME SystemTime;
		FILETIME FileTime;
		GetSystemTime(&SystemTime);
		dwPosLogon = SystemTime.wDayOfWeek * 24 + SystemTime.wHour;
		if (!((pUserInfo->usri4_logon_hours[dwPosLogon / 8] >> (dwPosLogon % 8)) & 1))  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"STATUS_INVALID_LOGON_HOURS");
			*SubStatus = STATUS_INVALID_LOGON_HOURS;
			return EID::make_unexpected(HRESULT_FROM_NT(STATUS_ACCOUNT_RESTRICTION));
		}
		else
		{
			// logon authorized
			// iterates to find the first 0
			for (dwHours = 1; dwHours < 7 * 24 + 1; dwHours++)  // NOSONAR - PERF-01: declared once, reused across iterations
			{
				dwPosLogoff = (dwPosLogon + dwHours) % (7 * 24);
				if (!((pUserInfo->usri4_logon_hours[dwPosLogoff / 8] >> (dwPosLogoff % 8)) & 1))  // NOSONAR - COMPLEXITY-01: nested BYTE bit-test retained; logic verified
				{
					// Logon authorized not everytime
					EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Hour Restriction");
					LARGE_INTEGER Hour;
					Hour.LowPart = 0x61C46800;
					Hour.HighPart = 8;
					SystemTime.wMinute = 0;
					SystemTime.wSecond = 0;
					SystemTime.wMilliseconds = 0;
					SystemTimeToFileTime(&SystemTime, &FileTime);
					// Use std::bit_cast for type-safe conversion (SonarQube cpp:S3624)
					ExpirationTime.QuadPart = std::bit_cast<std::int64_t>(FileTime);
					ExpirationTime.QuadPart += Hour.QuadPart * dwHours;
					break;
				}
			}
		}
	}

	if (wcscmp(pUserInfo->usri4_logon_server, L"\\\\*") != 0)  // NOSONAR - STRING-01: escaped literal retained to preserve exact comparison
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"STATUS_INVALID_WORKSTATION");
		*SubStatus = STATUS_INVALID_WORKSTATION;
		return EID::make_unexpected(HRESULT_FROM_NT(STATUS_ACCOUNT_RESTRICTION));
	}

	// The token must not outlive the account.
	if (ExpirationTime.QuadPart > llAccountExpires)
	{
		ExpirationTime.QuadPart = llAccountExpires;
	}
	return ExpirationTime;
}

// Exported wrapper maintaining NTSTATUS return for LSA compatibility
// Converts HRESULT errors to NTSTATUS via hr_to_ntstatus()
NTSTATUS CheckAuthorization(PWSTR UserName, NTSTATUS *SubStatus, LARGE_INTEGER *ExpirationTime)
{
	auto result = CheckAuthorizationInternal(UserName, SubStatus);
	if (result)
	{
		*ExpirationTime = *result;
		return STATUS_SUCCESS;
	}
	return EIDFailureHResultToNtStatus(result.error());
}






















