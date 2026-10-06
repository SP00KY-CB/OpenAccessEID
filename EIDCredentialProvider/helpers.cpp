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

//
// Helper functions for copying parameters and packaging the buffer
// for GetSerialization.


#include "helpers.h"
#include "Dll.h"
#include "EIDCredentialProvider.h"
#include <intsafe.h>
#include <wincred.h>
#include <LM.h>
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/Package.h"

#include <CodeAnalysis/Warnings.h>

// Static buffer for empty string literal to avoid const-correctness issues
// with PWSTR (non-const wchar_t*) initialization from L""
static wchar_t s_wszEmpty[] = L"";  // NOSONAR - GLOBAL-01: Non-const for Windows API PWSTR compatibility

#pragma warning(push)
#pragma warning(disable : 4995)
#include <Shlwapi.h>
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable : 4995)
#include <strsafe.h>
#pragma warning(pop)

#pragma comment(lib,"shlwapi")
#pragma comment(lib,"comctl32")
// 
// Copies the field descriptor pointed to by rcpfd into a buffer allocated 
// using CoTaskMemAlloc. Returns that buffer in ppcpfd.
// 
HRESULT FieldDescriptorCoAllocCopy(
                                   const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
                                   CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
                                   )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    DWORD cbStruct = sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR);

    auto pcpfd = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(cbStruct));

    if (pcpfd)
    {
        hr = FieldDescriptorCopy(rcpfd, pcpfd);
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    if (SUCCEEDED(hr))
    {
        *ppcpfd = pcpfd;
    }
    else
    {
        CoTaskMemFree(pcpfd);
        *ppcpfd = nullptr;
    }

    return hr;
}

//
// Coppies rcpfd into the buffer pointed to by pcpfd. The caller is responsible for
// allocating pcpfd. This function uses CoTaskMemAlloc to allocate memory for 
// pcpfd->pszLabel.
//
HRESULT FieldDescriptorCopy(
                            const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
                            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
                            )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    // Zero-initialise so no uninitialised stack bytes reach LogonUI.
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR cpfd = {};

    cpfd.dwFieldID = rcpfd.dwFieldID;
    cpfd.cpft = rcpfd.cpft;
    cpfd.guidFieldType = rcpfd.guidFieldType;

    if (rcpfd.pszLabel)
    {
        hr = SHStrDupW(rcpfd.pszLabel, &cpfd.pszLabel);
    }
    else
    {
        cpfd.pszLabel = nullptr;
        hr = S_OK;
    }

    if (SUCCEEDED(hr))
    {
        *pcpfd = cpfd;
    }

    return hr;
}


//
// Return a copy of pwzToProtect encrypted with the CredProtect API.
//
// pwzToProtect must not be NULL or the empty string.
//
static HRESULT ProtectAndCopyString(
                                    PWSTR pwzToProtect, 
                                    PWSTR* ppwzProtected
                                    )
{
    *ppwzProtected = nullptr;

    HRESULT hr = E_FAIL;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    // The first call to CredProtect determines the length of the encrypted string.
    // Because we pass a NULL output buffer, we expect the call to fail.
    //
    // Note that the third parameter to CredProtect, the number of characters of pwzToProtect
    // to encrypt, must include the NULL terminator!
    DWORD cchProtected = 0;
	PWSTR pwzProtected = s_wszEmpty;
	   if (!CredProtectW(FALSE, pwzToProtect, (DWORD)wcslen(pwzToProtect)+1, pwzProtected, &cchProtected, nullptr))  // NOSONAR - SCOPE-01: local scoped to block; init-statement refactor deferred
    {
        DWORD dwErr = GetLastError();

        if ((ERROR_INSUFFICIENT_BUFFER == dwErr) && (0 < cchProtected))
        {
            // Allocate a buffer long enough for the encrypted string.
            pwzProtected = (PWSTR)CoTaskMemAlloc(cchProtected * sizeof(WCHAR));

            if (pwzProtected)
            {
                // The second call to CredProtect actually encrypts the string.
                if (CredProtectW(FALSE, pwzToProtect, (DWORD)wcslen(pwzToProtect)+1, pwzProtected, &cchProtected, nullptr))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    *ppwzProtected = pwzProtected;
                    hr = S_OK;
                }
                else
                {
                    CoTaskMemFree(pwzProtected);

                    dwErr = GetLastError();
                    hr = HRESULT_FROM_WIN32(dwErr);
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
        else
        {
            hr = HRESULT_FROM_WIN32(dwErr);
        }
    }

    return hr;
}

//
// If pwzPassword should be encrypted, return a copy encrypted with CredProtect.
// 
// If not, just return a copy.
//
HRESULT ProtectIfNecessaryAndCopyPassword(
                                          PWSTR pwzPassword,
                                          CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
										  DWORD dwFlags,
                                          PWSTR* ppwzProtectedPassword
                                          )
{
    *ppwzProtectedPassword = nullptr;

    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    // ProtectAndCopyString is intended for non-empty strings only.  Empty passwords
    // do not need to be encrypted.
    if (pwzPassword && *pwzPassword)
    {
        bool bCredAlreadyEncrypted = false;
        CRED_PROTECTION_TYPE protectionType;

        // If the password is already encrypted, we should not encrypt it again.
        // An encrypted password may be received through SetSerialization in the 
        // CPUS_LOGON scenario during a Terminal Services connection, for instance.
        if(CredIsProtectedW(pwzPassword, &protectionType) && CredUnprotected != protectionType)  // NOSONAR - SCOPE-01: local scoped to block; init-statement refactor deferred
        {
            bCredAlreadyEncrypted = true;
        }

        // Passwords should not be encrypted in the CPUS_CREDUI scenario.  We
        // cannot know if our caller expects or can handle an encryped password.
        if (CPUS_CREDUI == cpus || bCredAlreadyEncrypted || (dwFlags & CREDUIWIN_GENERIC))
        {
            hr = SHStrDupW(pwzPassword, ppwzProtectedPassword);
        }
        else
        {
            hr = ProtectAndCopyString(pwzPassword, ppwzProtectedPassword);
        }
    }
    else
    {
        hr = SHStrDupW(L"", ppwzProtectedPassword);
    }

    return hr;
}


void ShowCancelForcePolicyWizard(HWND hWnd)
{
	// SECURITY (M4): removed. This previously ran a dialog on the secure desktop that could launch
	// the keymgr password-reset wizard (PRShowRestoreFromMsginaW) and downgrade the smart-card-
	// required policy via an ad-hoc LogonUser prompt - a lock-screen escape / policy-downgrade
	// surface. Retained as a no-op so existing callers still link.
	UNREFERENCED_PARAMETER(hWnd);
}