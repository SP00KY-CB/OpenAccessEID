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

#include "Tracing.h"
#include "EIDCardLibrary.h"

LARGE_INTEGER SecondsSince1970ToTime( const DWORD Seconds )
{
	LARGE_INTEGER Time = {0};
    Time.QuadPart = 116444736000000000I64; // january 1st 1970
	// 64-bit multiply: Seconds * 10000000 in 32 bits wraps for any date after 1970-01-01 07:09:27
	Time.QuadPart = static_cast<LONGLONG>(Seconds) * 10000000LL + Time.QuadPart;
	return Time;
}

NTSTATUS UserNameToProfile(__in PLSA_UNICODE_STRING AccountName,  // NOSONAR - API-01: signature dictated by Windows/callback API
						__in PLSA_DISPATCH_TABLE FunctionTable,  // NOSONAR - API-01: signature dictated by Windows/callback API
						__in PLSA_CLIENT_REQUEST ClientRequest,
						__out PEID_INTERACTIVE_PROFILE *ProfileBuffer,
						__out PULONG ProfileBufferLength
						) {
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	NTSTATUS Status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	if(!ProfileBuffer)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"No ProfileBuffer");
		if (ProfileBufferLength) *ProfileBufferLength=0;
		return STATUS_SUCCESS;
	}

	// copy unicode_string into LPWSTR
	WCHAR UserName[UNLEN+1];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	WCHAR DomainName[UNLEN+1];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	ULONG Length;
	PBYTE Offset;
	DWORD dwSize;

	// UserName is UNLEN+1 WCHARs; a longer name would make wcsncpy_s abort LSASS
	// and the terminator write below land past the end of the buffer.
	if (!AccountName || !AccountName->Buffer || AccountName->Length / sizeof(WCHAR) > UNLEN)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Account name missing or longer than UNLEN");
		if (ProfileBufferLength) *ProfileBufferLength=0;
		return STATUS_INVALID_PARAMETER;
	}
	wcsncpy_s(UserName,ARRAYSIZE(UserName),AccountName->Buffer,AccountName->Length/2);
	UserName[AccountName->Length/2]=0;
	dwSize = ARRAYSIZE(DomainName);
	GetComputerNameW(DomainName, &dwSize);
	// fill info into a dummy structure
	EID_INTERACTIVE_PROFILE MyProfileBuffer;
	MyProfileBuffer.MessageType = EIDInteractiveProfile;
	PUSER_INFO_4 pUserInfo = nullptr;
	Status=NetUserGetInfo(nullptr, UserName, 4, (LPBYTE*)&pUserInfo);
	if (Status!=0)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"No NetUserGetInfo 0x%08X",Status);
		if (ProfileBufferLength) *ProfileBufferLength=0;
		return STATUS_BAD_VALIDATION_CLASS;
	}
	MyProfileBuffer.LogonCount = (USHORT)pUserInfo->usri4_num_logons;
	MyProfileBuffer.BadPasswordCount = (USHORT)pUserInfo->usri4_bad_pw_count;
	// time in s since 1970
	MyProfileBuffer.LogonTime = SecondsSince1970ToTime(pUserInfo->usri4_last_logon);
	if (TIMEQ_FOREVER == pUserInfo->usri4_acct_expires)
	{
		// infinite
		MyProfileBuffer.LogoffTime.QuadPart = 9223372036854775807;
		MyProfileBuffer.KickOffTime.QuadPart = 9223372036854775807;
	}
	else
	{
		MyProfileBuffer.LogoffTime = SecondsSince1970ToTime(pUserInfo->usri4_acct_expires);
		MyProfileBuffer.KickOffTime = SecondsSince1970ToTime(pUserInfo->usri4_acct_expires);
	}
	MyProfileBuffer.PasswordLastSet.QuadPart = static_cast<LONGLONG>(pUserInfo->usri4_password_age) * 10000000LL;
	// can change now
	MyProfileBuffer.PasswordCanChange.QuadPart = MyProfileBuffer.PasswordLastSet.QuadPart;
	// never must change
	MyProfileBuffer.PasswordMustChange.QuadPart = 9223372036854775807;
#define MYMACRO(MYSTRING1,MYSTRING2) \
	MYSTRING1.Length = (USHORT) wcslen(MYSTRING2)*sizeof(WCHAR);\
	MYSTRING1.MaximumLength = (MYSTRING1.Length?MYSTRING1.Length+2:0);

	MYMACRO(MyProfileBuffer.LogonScript,pUserInfo->usri4_script_path)
	MYMACRO(MyProfileBuffer.HomeDirectory,pUserInfo->usri4_home_dir)
	MYMACRO(MyProfileBuffer.FullName,pUserInfo->usri4_full_name)
	MYMACRO(MyProfileBuffer.ProfilePath,pUserInfo->usri4_profile)
	MYMACRO(MyProfileBuffer.HomeDirectoryDrive,pUserInfo->usri4_home_dir_drive)
	MYMACRO(MyProfileBuffer.LogonServer,DomainName)
#undef MYMACRO

	MyProfileBuffer.UserFlags = 0;
	// alocate memory
	Length = sizeof(EID_INTERACTIVE_PROFILE) +
			MyProfileBuffer.LogonScript.MaximumLength +
			MyProfileBuffer.HomeDirectory.MaximumLength +
			MyProfileBuffer.FullName.MaximumLength +
			MyProfileBuffer.ProfilePath.MaximumLength +
			MyProfileBuffer.HomeDirectoryDrive.MaximumLength +
			MyProfileBuffer.LogonServer.MaximumLength;

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Allocate ProfileBuffer size = %d",Length);
	Status = FunctionTable->AllocateClientBuffer (ClientRequest, Length, (PVOID*)ProfileBuffer);
	if (Status)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AllocateClientBuffer failed: 0x%08lx\n", Status);
		if (ProfileBufferLength) *ProfileBufferLength=0;
		return Status;
	}

	Offset = (PBYTE)*ProfileBuffer + sizeof(EID_INTERACTIVE_PROFILE);
	// copy string to client buffer
	#define MYMACRO(MYSTRING1,MYSTRING2) \
	MYSTRING1.Buffer = (MYSTRING1.MaximumLength?(PWSTR)Offset:nullptr); \
	if (MYSTRING1.MaximumLength) { \
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"%s = '%s'", TEXT(#MYSTRING1), MYSTRING2); \
		FunctionTable->CopyToClientBuffer(ClientRequest,MYSTRING1.MaximumLength,Offset,MYSTRING2); \
		Offset += MYSTRING1.MaximumLength; \
	}


	// copy data to client
	MYMACRO(MyProfileBuffer.LogonScript,pUserInfo->usri4_script_path)
	MYMACRO(MyProfileBuffer.HomeDirectory,pUserInfo->usri4_home_dir)
	MYMACRO(MyProfileBuffer.FullName,pUserInfo->usri4_full_name)
	MYMACRO(MyProfileBuffer.ProfilePath,pUserInfo->usri4_profile)
	MYMACRO(MyProfileBuffer.HomeDirectoryDrive,pUserInfo->usri4_home_dir_drive)
	MYMACRO(MyProfileBuffer.LogonServer,DomainName)
#undef MYMACRO
	
	if (ProfileBufferLength)
	{
		*ProfileBufferLength=Length;
	}
	// copy struct 
	NetApiBufferFree(pUserInfo);

	FunctionTable->CopyToClientBuffer(ClientRequest,sizeof(EID_INTERACTIVE_PROFILE),*ProfileBuffer,&MyProfileBuffer);

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return STATUS_SUCCESS;
}
