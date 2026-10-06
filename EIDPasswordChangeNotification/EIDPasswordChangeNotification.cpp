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
#include <NTSecAPI.h>


#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/Registration.h"//#include "../EIDCardLibrary/XPCompatibility.h"

using LSA_IMPERSONATE_CLIENT = NTSTATUS (NTAPI)(VOID);
using PLSA_IMPERSONATE_CLIENT = LSA_IMPERSONATE_CLIENT*;
void SetImpersonate(PLSA_IMPERSONATE_CLIENT Impersonate);

NTSTATUS NTAPI Impersonate (VOID)
{
	return STATUS_SUCCESS;
}

/*
The InitializeChangeNotify function is implemented by a password filter DLL.
This function initializes the DLL.
*/

BOOL WINAPI InitializeChangeNotify()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	// if we don't set this, the library thinks that we are in a test process
	// note : impersonation is not needed, that's why it is set to nothing
	SetImpersonate(Impersonate);
	return TRUE;
}

/*
The PasswordFilter function is implemented by a password filter DLL.
The value returned by this function determines whether the new password 
is accepted by the system. All of the password filters installed on a 
system must return TRUE for the password change to take effect.
*/

BOOL WINAPI PasswordFilter(
	PUNICODE_STRING AccountName,  // NOSONAR - API-01: signature dictated by Windows/callback API
	PUNICODE_STRING FullName,  // NOSONAR - API-01: signature dictated by Windows/callback API
	PUNICODE_STRING Password,  // NOSONAR - API-01: signature dictated by Windows/callback API
	BOOLEAN SetOperation
)
{
	UNREFERENCED_PARAMETER(AccountName);
	UNREFERENCED_PARAMETER(FullName);
	UNREFERENCED_PARAMETER(Password);
	UNREFERENCED_PARAMETER(SetOperation);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	return TRUE;
}

/*
The PasswordChangeNotify function is implemented by a password filter DLL.
It notifies the DLL that a password was changed.
*/

NTSTATUS WINAPI PasswordChangeNotify(
	PUNICODE_STRING UserName,
	ULONG RelativeId,
	PUNICODE_STRING NewPassword
)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Username %wZ RelativeId %d",UserName,RelativeId);
	CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
	// A blank password arrives as Length 0 with a possibly NULL Buffer; there is
	// nothing to re-seal (UpdateCredential refuses it) and passing it on used to
	// crash LSASS in wcslen.
	if (manager && NewPassword && NewPassword->Buffer && NewPassword->Length > 0)
	{
		manager->UpdateCredential(RelativeId, NewPassword->Buffer, NewPassword->Length);
	}
	return TRUE;
}
