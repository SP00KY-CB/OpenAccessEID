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

#define _CRTDBG_MAP_ALLOC  // NOSONAR - MACRO-02: CRT debug memory tracking macro
#include <stdlib.h>
#include <crtdbg.h>

#include <ntstatus.h>
#define WIN32_NO_STATUS  // NOSONAR - MACRO-02: Windows SDK configuration, prevents ntstatus.h conflicts
#include <Windows.h>
#include <tchar.h>
#include <intsafe.h>
#include <wincred.h>
#include <LM.h>

#include <NTSecAPI.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <NTSecPKG.h>
#include <WtsApi32.h>
#include <security.h>

#include <CodeAnalysis/Warnings.h>
#pragma warning(push)
#pragma warning(disable : 4995)
#include <Shlwapi.h>
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable : 4995)
#include <strsafe.h>
#pragma warning(pop)

#include <credentialprovider.h>

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "StoredCredentialManagement.h"
#include "InputValidation.h"

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")

constexpr char DEBUG_MARKUP[] = "MySmartLogonHeapCheck";

PLSA_ALLOCATE_LSA_HEAP MyAllocateHeap = nullptr;  // NOSONAR - RUNTIME-01: LSA heap allocator, set by LSA
PLSA_FREE_LSA_HEAP MyFreeHeap = nullptr;  // NOSONAR - RUNTIME-01: LSA heap deallocator, set by LSA
PLSA_IMPERSONATE_CLIENT MyImpersonate = nullptr;  // NOSONAR - RUNTIME-01: LSA impersonate function, set by LSA
const BOOL TraceAllocation = TRUE;

void SetAlloc(PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap)  // NOSONAR - API-01: raw function pointer required
{
	MyAllocateHeap = AllocateLsaHeap;
}

void SetFree(PLSA_FREE_LSA_HEAP FreeHeap)  // NOSONAR - API-01: raw function pointer required
{
	MyFreeHeap = FreeHeap;
}

PVOID EIDAllocEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction,DWORD dwSize)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	UNREFERENCED_PARAMETER(szFile);
	UNREFERENCED_PARAMETER(dwLine);
	UNREFERENCED_PARAMETER(szFunction);
	PVOID memory = nullptr;
	if (MyAllocateHeap)
	{
#ifdef _DEBUG	
		memory = MyAllocateHeap(dwSize + sizeof(DEBUG_MARKUP) + sizeof(PVOID));
		if (memory)
		{
			memcpy((PBYTE) memory + dwSize,DEBUG_MARKUP, sizeof(DEBUG_MARKUP));
			memcpy((PBYTE) memory + dwSize + sizeof(DEBUG_MARKUP),&memory, sizeof(PVOID));
		}
#else
		memory = MyAllocateHeap(dwSize);
#endif		
	}
	else
	{
#ifdef _DEBUG	
		memory = _malloc_dbg(dwSize,_CLIENT_BLOCK, szFile, dwLine);
#else
		memory = malloc(dwSize);
#endif		
	}
	return memory;
}
VOID EIDFreeEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction,PVOID buffer)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	UNREFERENCED_PARAMETER(szFile);
	UNREFERENCED_PARAMETER(dwLine);
	UNREFERENCED_PARAMETER(szFunction);
	if (MyFreeHeap)
	{
#ifdef _DEBUG
		// look for markup
		BOOL bFound = FALSE;
		for (int i = 0; i < 10000; i++)
		{
			if (memcmp((PBYTE)buffer + i,DEBUG_MARKUP, sizeof(DEBUG_MARKUP)) == 0)
			{
				if (memcmp((PBYTE)buffer + i + sizeof(DEBUG_MARKUP),&buffer,sizeof(PVOID)) != 0)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					EIDCardLibraryTraceEx(szFile, dwLine, szFunction, WINEVENT_LEVEL_ERROR, L"Markup not ok %p",buffer);
				}
				else
				{
					bFound = TRUE;
				}
				break;
			}
		}
		if (!bFound)
		{
			EIDCardLibraryTraceEx(szFile, dwLine, szFunction, WINEVENT_LEVEL_ERROR, L"Markup not found when freeing %p",buffer);
		}
		MyFreeHeap(buffer);
#else
		MyFreeHeap(buffer);
#endif
	}
	else
	{
#ifndef _DEBUG	
		free(buffer);
#else
		_free_dbg(buffer, _CLIENT_BLOCK);
#endif
	}
}

void SetImpersonate(PLSA_IMPERSONATE_CLIENT Impersonate)  // NOSONAR - API-01: raw function pointer required
{
	MyImpersonate = Impersonate;
}

VOID EIDImpersonate()
{
	if (MyImpersonate)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Impersonating");
		MyImpersonate();
	}
}

VOID EIDRevertToSelf()
{
	if (MyImpersonate)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RevertToSelf");
		RevertToSelf();
	}
}

BOOL EIDIsComponentInLSAContext()
{
	return MyImpersonate != nullptr;
}

// Secure DLL loading function - prevents DLL hijacking attacks
// by constructing full paths to system DLLs instead of relying on search order
HMODULE EIDLoadSystemLibrary(LPCTSTR szDllName)
{
	TCHAR szFullPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
	UINT uLen;

	// Validate input - DLL name should not contain path separators
	if (szDllName == nullptr || _tcschr(szDllName, TEXT('\\')) != nullptr || _tcschr(szDllName, TEXT('/')) != nullptr)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return nullptr;
	}

	// Get System32 directory
	uLen = GetSystemDirectory(szFullPath, ARRAYSIZE(szFullPath));
	if (uLen == 0 || uLen >= ARRAYSIZE(szFullPath))
	{
		SetLastError(ERROR_BUFFER_OVERFLOW);
		return nullptr;
	}

	// Construct full path: System32\DllName
	if (FAILED(StringCchCat(szFullPath, ARRAYSIZE(szFullPath), TEXT("\\"))) ||
		FAILED(StringCchCat(szFullPath, ARRAYSIZE(szFullPath), szDllName)))
	{
		SetLastError(ERROR_BUFFER_OVERFLOW);
		return nullptr;
	}

	// Load from the explicit full path
	return LoadLibrary(szFullPath);
}

VOID CenterWindow(HWND hWnd)
{
	RECT rc;
    if (!GetWindowRect(hWnd, &rc)) return;

    const int width  = rc.right  - rc.left;
    const int height = rc.bottom - rc.top;

    MoveWindow(hWnd,
        (GetSystemMetrics(SM_CXSCREEN) - width)  / 2,
        (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
        width, height, true);
}

VOID SetIcon(HWND hWnd)
{
	// First try to load app-specific icon (IDI_APP_ICON = 101)
	HMODULE hApp = GetModuleHandle(nullptr);
	if (hApp)
	{
		HANDLE hbicon = LoadImage(hApp, MAKEINTRESOURCE(101), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0);
		if (hbicon)
		{
			SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM) hbicon);
			hbicon = LoadImage(hApp, MAKEINTRESOURCE(101), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
			if (hbicon)
				SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM) hbicon);
			return;  // Successfully loaded app icon
		}
	}

	// Fall back to system icon (imageres.dll resource 58)
	HMODULE hDll = EIDLoadSystemLibrary(TEXT("imageres.dll"));
	if (hDll)
	{
		HANDLE hbicon = LoadImage(hDll, MAKEINTRESOURCE(58),IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0);
		if (hbicon)
			SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM) hbicon);
		hbicon = LoadImage(hDll, MAKEINTRESOURCE(58),IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
		if (hbicon)
			SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM) hbicon);
		FreeLibrary(hDll);
	}
}

//
// This function copies the length of pwz and the pointer pwz into the UNICODE_STRING structure
// This function is intended for serializing a credential in GetSerialization only.
// Note that this function just makes a copy of the string pointer. It DOES NOT ALLOCATE storage!
// Be very, very sure that this is what you want, because it probably isn't outside of the
// exact GetSerialization call where the sample uses it.
//
HRESULT UnicodeStringInitWithString(
                                       PWSTR pwz,
                                       UNICODE_STRING* pus
                                       )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    if (pwz)
    {
        size_t lenString;
        hr = StringCchLengthW(pwz, USHORT_MAX, &lenString);

        if (SUCCEEDED(hr))
        {
            USHORT usCharCount;
            hr = SizeTToUShort(lenString, &usCharCount);
            if (SUCCEEDED(hr))
            {
                USHORT usSize;
                hr = SizeTToUShort(sizeof(WCHAR), &usSize);
                if (SUCCEEDED(hr))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    hr = UShortMult(usCharCount, usSize, &(pus->Length)); // Explicitly NOT including NULL terminator
                    if (SUCCEEDED(hr))
                    {
                        pus->MaximumLength = pus->Length;
                        pus->Buffer = pwz;
                        hr = S_OK;
                    }
                    else
                    {
                        hr = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
                    }
                }
            }
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}



//
// The following function is intended to be used ONLY with the Kerb*Pack functions.  It does
// no bounds-checking because its callers have precise requirements and are written to respect
// its limitations.
//
static void _UnicodeStringPackedUnicodeStringCopy(
    const UNICODE_STRING& rus,
    PWSTR pwzBuffer,
    UNICODE_STRING* pus
    )
{
    pus->Length = rus.Length;
    pus->MaximumLength = rus.Length;
    pus->Buffer = pwzBuffer;

    CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

//
// WinLogon and LSA consume "packed" KERB_INTERACTIVE_UNLOCK_LOGONs.  In these, the PWSTR members of each
// UNICODE_STRING are not actually pointers but byte offsets into the overall buffer represented
// by the packed KERB_INTERACTIVE_UNLOCK_LOGON.  For example:
// 
// rkiulIn.Logon.LogonDomainName.Length = 14                                    -> Length is in bytes, not characters
// rkiulIn.Logon.LogonDomainName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) -> LogonDomainName begins immediately
//                                                                              after the KERB_... struct in the buffer
// rkiulIn.Logon.UserName.Length = 10
// rkiulIn.Logon.UserName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14   -> UNICODE_STRINGS are NOT null-terminated
//
// rkiulIn.Logon.Password.Length = 16
// rkiulIn.Logon.Password.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14 + 10
//

HRESULT EIDUnlockLogonPack(
									   const EID_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
									   const PEID_SMARTCARD_CSP_INFO pCspInfo,  // NOSONAR - API-01: signature dictated by Windows/callback API
                                       BYTE** prgb,
                                       DWORD* pcb
                                       )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    const EID_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

    // alloc space for struct plus extra for the three strings.
    // The string lengths are USHORTs, so only dwCspInfoLen can wrap the sum.
    const DWORD cbFixed = sizeof(rkiulIn) +
		pkilIn->LogonDomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Pin.Length;
    if (pCspInfo->dwCspInfoLen > MAXDWORD - cbFixed)
    {
        return HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
    }
    DWORD cb = cbFixed + pCspInfo->dwCspInfoLen;


    EID_INTERACTIVE_UNLOCK_LOGON* pkiulOut = (EID_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

    if (pkiulOut)  // NOSONAR - SCOPE-01: allocation reused to build output buffer
    {
        ZeroMemory(&pkiulOut->LogonId, sizeof(LUID));

        //
        // point pbBuffer at the beginning of the extra space
        //
        BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        //
        // set up the Logon structure within the EID_INTERACTIVE_UNLOCK_LOGON
        //
        EID_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;

        pkilOut->MessageType = pkilIn->MessageType;
		pkilOut->Flags = pkilIn->Flags;

        //
        // copy each string,
        // fix up appropriate buffer pointer to be offset,
        // advance buffer pointer over copied characters in extra space
        //
        _UnicodeStringPackedUnicodeStringCopy(pkilIn->LogonDomainName, (PWSTR)pbBuffer, &pkilOut->LogonDomainName);
        pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->LogonDomainName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
        pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->UserName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->Pin, (PWSTR)pbBuffer, &pkilOut->Pin);
        pkilOut->Pin.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
		pbBuffer += pkilOut->Pin.Length;

		pkilOut->CspData = (PUCHAR) (pbBuffer - (BYTE*)pkiulOut);
		pkilOut->CspDataLength = pCspInfo->dwCspInfoLen;

		memcpy(pbBuffer,pCspInfo,pCspInfo->dwCspInfoLen);

        *prgb = (BYTE*)pkiulOut;
        *pcb = cb;

        hr = S_OK;
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}


// 
// This function packs the string pszSourceString in pszDestinationString
// for use with LSA functions including LsaLookupAuthenticationPackage.
//
HRESULT LsaInitString(PSTRING pszDestinationString, PCSTR pszSourceString)
{
    size_t cchLength;
    HRESULT hr = StringCchLengthA(pszSourceString, USHORT_MAX, &cchLength);  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    if (SUCCEEDED(hr))
    {
        USHORT usLength;
        hr = SizeTToUShort(cchLength, &usLength);

        if (SUCCEEDED(hr))
        {
            pszDestinationString->Buffer = (PCHAR)pszSourceString; // NOSONAR - LSA STRING requires non-const Buffer pointer; source not modified
            pszDestinationString->Length = usLength;
            pszDestinationString->MaximumLength = pszDestinationString->Length+1;
            hr = S_OK;
        }
    }
    return hr;
}

//
// Retrieves the 'eid' AuthPackage from the LSA.
//
HRESULT RetrieveNegotiateAuthPackage(ULONG * pulAuthPackage)
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    HANDLE hLsa;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit

    NTSTATUS status = LsaConnectUntrusted(&hLsa);  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
		
		TCHAR szExeName[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		DWORD dwNumChar = GetModuleFileName(nullptr, szExeName, ARRAYSIZE(szExeName));
		// mstsc.exe
		if (dwNumChar >= 9 && _tcsicmp(szExeName + dwNumChar - 9, TEXT("mstsc.exe")) == 0)
		{
			LsaInitString(&lsaszPackageName, NEGOSSP_NAME_A);
		}
		else
		{
			LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);
		}

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            *pulAuthPackage = ulAuthPackage;
            hr = S_OK;
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr= HRESULT_FROM_NT(status);
    }

    return hr;
}

//szAuthPackageValue must be freed by  LsaFreeMemory
HRESULT CallAuthPackage(LPCWSTR username ,LPWSTR * szAuthPackageValue, PULONG szAuthPackageLen)
{
    NET_API_STATUS netStatus;
	HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    HANDLE hLsa;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	DWORD dwRid;
	DWORD dwSubAuthorityCount;
	USER_INFO_23* pUserInfo;
	PSID pSid;
	
	// transform the username to usernameinfo
	netStatus = NetUserGetInfo(nullptr,username,23,(LPBYTE*) &pUserInfo);
	if (NERR_Success != netStatus)
	{
		return MAKE_HRESULT(1,FACILITY_INTERNET,netStatus);
	}
	// get the sid
	pSid = pUserInfo->usri23_user_sid;
	// get the last identifier of the sid : it's the rid
	dwSubAuthorityCount = *GetSidSubAuthorityCount(pSid);
	dwRid = *GetSidSubAuthority(pSid, dwSubAuthorityCount-1);
	//
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
		LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, &dwRid, sizeof(DWORD),
				(PVOID *)szAuthPackageValue,szAuthPackageLen,nullptr);
			hr = HRESULT_FROM_NT(status);
            
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr= HRESULT_FROM_NT(status);
    }
	NetApiBufferFree(pUserInfo);
    return hr;
}

// change pointer according ClientAuthenticationBase : the struct is a copy
// so pointer are invalid
// Helper function to safely check buffer bounds without integer overflow
// Returns TRUE if offset + length would exceed limit or if addition overflows
static BOOL SafeCheckBufferOverflow(ULONG_PTR offset, ULONG length, ULONG limit)
{
	// Check if addition would overflow
	if (offset > MAXULONG_PTR - length)
	{
		return TRUE; // Overflow detected
	}
	// Safe to add - check bounds
	return offset + length > limit;
}

// A counted string is only well formed if Length <= MaximumLength and an absent
// (NULL) Buffer carries no length. The rebasing below skips NULL buffers, so
// without this a NULL Pin.Buffer with a non-zero Length reached
// memcpy_s(..., NULL, Length) in LsaApLogonUserEx2 and fast-failed LSASS.
static BOOL IsCountedStringHeaderValid(const UNICODE_STRING& us)
{
	if (us.Length > us.MaximumLength)
	{
		return FALSE;
	}
	if (us.Buffer == nullptr && (us.Length != 0 || us.MaximumLength != 0))
	{
		return FALSE;
	}
	return TRUE;
}

NTSTATUS RemapPointer(PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon, PVOID ClientAuthenticationBase, ULONG AuthenticationInformationLength)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Diff %p %p",(PUCHAR) pUnlockLogon, (PUCHAR) ClientAuthenticationBase);
	if (!pUnlockLogon)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pUnlockLogon NULL");
		return STATUS_INVALID_PARAMETER;
	}
	// Every check below reads Logon.UserName / Logon.CspData / CspDataLength out
	// of this buffer, so the fixed struct must be established as present FIRST.
	// A submit buffer shorter than the header was read out of bounds by the
	// very code meant to bound it.
	if (AuthenticationInformationLength < sizeof(EID_INTERACTIVE_UNLOCK_LOGON))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AuthenticationInformationLength %u < sizeof(EID_INTERACTIVE_UNLOCK_LOGON)",
			AuthenticationInformationLength);
		return STATUS_INVALID_PARAMETER_3;
	}
	if (!IsCountedStringHeaderValid(pUnlockLogon->Logon.UserName) ||
		!IsCountedStringHeaderValid(pUnlockLogon->Logon.LogonDomainName) ||
		!IsCountedStringHeaderValid(pUnlockLogon->Logon.Pin))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Malformed UNICODE_STRING (NULL Buffer with length, or Length > MaximumLength)");
		return STATUS_INVALID_PARAMETER;
	}
	if (pUnlockLogon->Logon.CspData == nullptr && pUnlockLogon->Logon.CspDataLength != 0)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CspData NULL with CspDataLength %u",pUnlockLogon->Logon.CspDataLength);
		return STATUS_INVALID_PARAMETER;
	}
	if ((pUnlockLogon->Logon.UserName.Buffer) != nullptr)
	{
		ULONG_PTR offset = (ULONG_PTR)(pUnlockLogon->Logon.UserName.Buffer);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (SafeCheckBufferOverflow(offset, pUnlockLogon->Logon.UserName.MaximumLength, AuthenticationInformationLength))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UserName Overflow1");
			return STATUS_INVALID_PARAMETER_3;
		}
		if (SafeCheckBufferOverflow(offset, pUnlockLogon->Logon.UserName.Length, AuthenticationInformationLength))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UserName Overflow2");
			return STATUS_INVALID_PARAMETER_3;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Logon from %p",pUnlockLogon->Logon.UserName.Buffer);
		pUnlockLogon->Logon.UserName.Buffer = PWSTR((ULONG_PTR)( pUnlockLogon) + (ULONG_PTR) pUnlockLogon->Logon.UserName.Buffer);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Logon to %p",pUnlockLogon->Logon.UserName.Buffer);
	}
	if ((pUnlockLogon->Logon.LogonDomainName.Buffer) != nullptr)
	{
		ULONG_PTR offset = (ULONG_PTR)(pUnlockLogon->Logon.LogonDomainName.Buffer);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (SafeCheckBufferOverflow(offset, pUnlockLogon->Logon.LogonDomainName.MaximumLength, AuthenticationInformationLength))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LogonDomainName Overflow1");
			return STATUS_INVALID_PARAMETER_3;
		}
		if (SafeCheckBufferOverflow(offset, pUnlockLogon->Logon.LogonDomainName.Length, AuthenticationInformationLength))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LogonDomainName Overflow2");
			return STATUS_INVALID_PARAMETER_3;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap LogonDomainName from %p",pUnlockLogon->Logon.LogonDomainName.Buffer);
		pUnlockLogon->Logon.LogonDomainName.Buffer = PWSTR((ULONG_PTR)( pUnlockLogon) + (ULONG_PTR) pUnlockLogon->Logon.LogonDomainName.Buffer);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap LogonDomainName to %p",pUnlockLogon->Logon.LogonDomainName.Buffer);
	}
	if ((pUnlockLogon->Logon.Pin.Buffer) != nullptr)
	{
		ULONG_PTR offset = (ULONG_PTR)(pUnlockLogon->Logon.Pin.Buffer);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (SafeCheckBufferOverflow(offset, pUnlockLogon->Logon.Pin.MaximumLength, AuthenticationInformationLength))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Pin Overflow1");
			return STATUS_INVALID_PARAMETER_3;
		}
		if (SafeCheckBufferOverflow(offset, pUnlockLogon->Logon.Pin.Length, AuthenticationInformationLength))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Pin Overflow2");
			return STATUS_INVALID_PARAMETER_3;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Pin from %p",pUnlockLogon->Logon.Pin.Buffer);
		pUnlockLogon->Logon.Pin.Buffer = PWSTR((ULONG_PTR)( pUnlockLogon) + (ULONG_PTR) pUnlockLogon->Logon.Pin.Buffer);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Pin to %p",pUnlockLogon->Logon.Pin.Buffer);
	}
	if ((pUnlockLogon->Logon.CspData) != nullptr)
	{
		ULONG_PTR offset = (ULONG_PTR)(pUnlockLogon->Logon.CspData);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (SafeCheckBufferOverflow(offset, pUnlockLogon->Logon.CspDataLength, AuthenticationInformationLength))  // NOSONAR - SCOPE-01: declaration kept separate to preserve explicit-type annotation
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CspData Overflow");
			return STATUS_INVALID_PARAMETER_3;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap CSPData from %p",pUnlockLogon->Logon.CspData);
		pUnlockLogon->Logon.CspData = PUCHAR( (PBYTE)pUnlockLogon + (ULONG_PTR) pUnlockLogon->Logon.CspData);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap CSPData to %p",pUnlockLogon->Logon.CspData);

		// The check above bounds the CspData BLOCK against the submit buffer.
		// It says nothing about the block's interior: EID_SMARTCARD_CSP_INFO
		// carries its own dwCspInfoLen plus four name offsets, and the
		// downstream consumers bound those offsets against dwCspInfoLen - a
		// field that lives inside this same attacker-supplied block. Validate
		// the interior here, at the one place every logon passes through, so
		// no consumer has to trust an attacker-supplied length again.
		if (!EIDValidateCspInfo(reinterpret_cast<PEID_SMARTCARD_CSP_INFO>(pUnlockLogon->Logon.CspData),
				pUnlockLogon->Logon.CspDataLength))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CspInfo layout rejected (CspDataLength=%u)",
				pUnlockLogon->Logon.CspDataLength);
			return STATUS_INVALID_PARAMETER_3;
		}
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return STATUS_SUCCESS;
}

// Diagnostic dump of an attacker-supplied logon buffer.
//
// This runs UNCONDITIONALLY on every logon attempt (see the call in
// OpenAccessEIDPackage.cpp), before the callers' own field validation, so
// it must be total: every length is clamped to the local buffer and every
// CspData read goes through EIDCspInfoStringAt. Two concrete defects lived
// here - `Buffer[Length/2] = 0` wrote up to index 32767 into a 1000-WCHAR
// stack array, and the four `bBuffer[nXxxNameOffset]` reads used raw 32-bit
// attacker offsets as indices and printed the result with %s.
//
// dwCspDataLength must come from the caller. Do not substitute
// pCspInfo->dwCspInfoLen: that field is exactly what cannot be trusted.
VOID EIDDebugPrintEIDUnlockLogonStruct(UCHAR dwLevel, PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon, ULONG dwCspDataLength) {
	WCHAR Buffer[1000];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
	constexpr size_t cchBuffer = ARRAYSIZE(Buffer);

	if (!pUnlockLogon)
	{
		EIDCardLibraryTrace(dwLevel,L"pUnlockLogon NULL");
		return;
	}

	// Copy at most cchBuffer-1 characters and terminate inside the array,
	// whatever Length claims. UNICODE_STRING.Length is a USHORT in bytes, so
	// Length/2 reaches 32767 - far past this buffer.
	auto TraceCountedString = [&](PCWSTR pszLabel, PCWSTR pszValue, USHORT usLengthInBytes)
	{
		if (!pszValue)
		{
			EIDCardLibraryTrace(dwLevel,L"No %s",pszLabel);
			return;
		}
		size_t cchCopy = usLengthInBytes / sizeof(WCHAR);
		if (cchCopy > cchBuffer - 1)
		{
			cchCopy = cchBuffer - 1;
		}
		wcsncpy_s(Buffer, cchBuffer, pszValue, cchCopy);
		Buffer[cchCopy] = L'\0';
		EIDCardLibraryTrace(dwLevel,L"%s '%s'",pszLabel,Buffer);
	};

	EIDCardLibraryTrace(dwLevel,L"LogonId %d %d",pUnlockLogon->LogonId.LowPart,pUnlockLogon->LogonId.HighPart);
	EIDCardLibraryTrace(dwLevel,L"Username %d",pUnlockLogon->Logon.UserName.Length);
	TraceCountedString(L"Username", pUnlockLogon->Logon.UserName.Buffer, pUnlockLogon->Logon.UserName.Length);
	EIDCardLibraryTrace(dwLevel,L"LogonDomainName %d",pUnlockLogon->Logon.LogonDomainName.Length);
	TraceCountedString(L"LogonDomainName", pUnlockLogon->Logon.LogonDomainName.Buffer, pUnlockLogon->Logon.LogonDomainName.Length);

	// The PIN is copied but deliberately never traced.
	EIDCardLibraryTrace(dwLevel,L"Pin %d",pUnlockLogon->Logon.Pin.Length);
	if (pUnlockLogon->Logon.Pin.Buffer == nullptr)
	{
		EIDCardLibraryTrace(dwLevel,L"No Pin");
	}

	EIDCardLibraryTrace(dwLevel,L"Flags %d",pUnlockLogon->Logon.Flags);
	EIDCardLibraryTrace(dwLevel,L"MessageType %d",pUnlockLogon->Logon.MessageType);
	EIDCardLibraryTrace(dwLevel,L"CspDataLength %d",pUnlockLogon->Logon.CspDataLength);
	if (pUnlockLogon->Logon.CspData)
	{
		PEID_SMARTCARD_CSP_INFO pCspInfo = (PEID_SMARTCARD_CSP_INFO) pUnlockLogon->Logon.CspData;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (!EIDValidateCspInfo(pCspInfo, dwCspDataLength))
		{
			EIDCardLibraryTrace(dwLevel,L"CspData present but layout invalid - not dumping");
			return;
		}
		EIDCardLibraryTrace(dwLevel,L"MessageType %d",pCspInfo->MessageType);
		EIDCardLibraryTrace(dwLevel,L"KeySpec %d",pCspInfo->KeySpec);

		const struct { PCWSTR pszLabel; ULONG nOffset; } rgNames[] = {
			{ L"CardName",      pCspInfo->nCardNameOffset      },
			{ L"ReaderName",    pCspInfo->nReaderNameOffset    },
			{ L"ContainerName", pCspInfo->nContainerNameOffset },
			{ L"CSPName",       pCspInfo->nCSPNameOffset       },
		};
		for (size_t i = 0; i < ARRAYSIZE(rgNames); i++)
		{
			if (rgNames[i].nOffset == 0)
			{
				continue;
			}
			PCWSTR pszName = EIDCspInfoStringAt(pCspInfo, dwCspDataLength, rgNames[i].nOffset);
			if (pszName)
			{
				EIDCardLibraryTrace(dwLevel,L"%s '%s'",rgNames[i].pszLabel,pszName);
			}
			else
			{
				EIDCardLibraryTrace(dwLevel,L"%s (invalid offset %u)",rgNames[i].pszLabel,rgNames[i].nOffset);
			}
		}
	}
}

PTSTR GetUsernameFromRid(__in DWORD dwRid)
{
	NET_API_STATUS Status;
	PUSER_INFO_3 pUserInfo = nullptr;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	BOOL fFound = FALSE;
	DWORD dwI;
	DWORD dwSize;
	PTSTR szUsername = nullptr;
	__try
	{
		Status = NetUserEnum(nullptr, 3,0, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, nullptr);
		if (Status != NERR_Success)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			dwError = Status;
			__leave;
		}
		for (dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			if (dwRid == pUserInfo[dwI].usri3_user_id)
			{
				fFound = TRUE;
				break;
			}
		}
		if (!fFound)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Rid not found %x",dwRid);
			__leave;
		}
		dwSize = (DWORD)(_tcslen(pUserInfo[dwI].usri3_name) +1);
		szUsername = (PTSTR) EIDAlloc(dwSize *sizeof(TCHAR));
		if (!szUsername)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDAlloc 0x%08x",GetLastError());
			__leave;
		}
		_tcscpy_s(szUsername, dwSize, pUserInfo[dwI].usri3_name);
		fReturn = TRUE;
	}
	__finally
	{
		if (pUserInfo)
			NetApiBufferFree(pUserInfo);
	}
	SetLastError(dwError);
	return szUsername;
}

BOOL IsCurrentUser(PTSTR szUserName)
{
	BOOL fReturn;
	PWSTR szCurrentUserName;
	DWORD dwSize;
	fReturn = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName, &szCurrentUserName, &dwSize);
	if (!fReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WTSQuerySessionInformationW 0x%08X",GetLastError());
		return FALSE;
	}

	fReturn = wcscmp(szCurrentUserName,szUserName) == 0;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CurrentUsername = '%s' match with '%s'",szCurrentUserName,szUserName);
	WTSFreeMemory(szCurrentUserName);
	return fReturn;
}

BOOL IsAdmin(PTSTR szUserName)
{
	BOOL fReturn = FALSE;
	WCHAR szAdministratorGroupName[256];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
	WCHAR szDomainName[256];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
	PLOCALGROUP_USERS_INFO_0 pGroupInfo;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	SID_NAME_USE SidType;
	PSID AdministratorsGroup;
	DWORD dwEntriesRead;
	DWORD dwTotalEntries;
	DWORD dwSize;
	if (NERR_Success != NetUserGetLocalGroups(nullptr, szUserName, 0, LG_INCLUDE_INDIRECT, (PBYTE*)&pGroupInfo,
		MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries))
		return FALSE;
	fReturn = AllocateAndInitializeSid(&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup); 
	if(!fReturn) 
	{
		NetApiBufferFree(pGroupInfo);
		return FALSE;
	}
	dwSize = ARRAYSIZE(szAdministratorGroupName);
	if( !LookupAccountSid( nullptr, AdministratorsGroup,
								  szAdministratorGroupName, &dwSize, szDomainName, 
								  &dwSize, &SidType ) ) 
	{
		FreeSid(AdministratorsGroup); 
		NetApiBufferFree(pGroupInfo);
		return FALSE;
	}

	for (DWORD dwI = 0; dwI < dwTotalEntries ; dwI++)
	{
		fReturn = wcscmp(szAdministratorGroupName, pGroupInfo[dwI].lgrui0_name) == 0;
		if (fReturn) break;
	}
	
	FreeSid(AdministratorsGroup); 
	NetApiBufferFree(pGroupInfo);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CurrentUsername = '%s'",szUserName);
	return fReturn;
}

// extract RID from current process
DWORD GetCurrentRid()
{
	DWORD dwSize = 0;
	DWORD dwRid = 0;
	PSID pSid;
	PTOKEN_USER pInfo = nullptr;
	HANDLE hToken;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))  // NOSONAR - SCOPE-01: declaration kept separate to preserve explicit-type annotation
	{
	
		GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
		pInfo = (PTOKEN_USER) EIDAlloc(dwSize);
		if (pInfo)
		{
			if (GetTokenInformation(hToken, TokenUser, pInfo, dwSize, &dwSize))
			{
				pSid = pInfo->User.Sid;
				dwRid = *GetSidSubAuthority(pSid, *GetSidSubAuthorityCount(pSid) -1);
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by GetTokenInformation", GetLastError());
			}
			EIDFree(pInfo);
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
		}
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by OpenProcessToken", GetLastError());
	}
	return dwRid;
}

	// BUG FIX #16: TOCTOU race condition mitigation - use retry loop for SID allocation
	DWORD GetRidFromUsername(LPTSTR szUsername)  // NOSONAR - API-01: signature dictated by Windows/callback API
	{
		BOOL bResult;
		SID_NAME_USE Use;
		PSID pSid = nullptr;
		TCHAR checkDomainName[UNCLEN+1];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
		DWORD cchReferencedDomainName = 0;
		DWORD dwRid = 0;
		constexpr DWORD MAX_RETRIES = 3;
		DWORD dwRetryCount = 0;

		DWORD dLengthSid = 0;
		bResult = LookupAccountName(nullptr,  szUsername, nullptr,&dLengthSid,nullptr, &cchReferencedDomainName, &Use);

		if (!bResult && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LookupAccountName", GetLastError());
			return 0;
		}

		// Retry loop for SID allocation (handles TOCTOU race condition)
		for (dwRetryCount = 0; dwRetryCount < MAX_RETRIES; dwRetryCount++)  // NOSONAR - PERF-01: declared once, reused across iterations
		{
			// Clean up from previous retry
			if (pSid)
			{
				EIDFree(pSid);
				pSid = nullptr;
			}

			// Allocate SID buffer
			pSid = (PSID)EIDAlloc(dLengthSid);
			if (!pSid)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to allocate SID buffer");
				return 0;
			}
			SecureZeroMemory(pSid, dLengthSid);

			cchReferencedDomainName=UNCLEN;
			bResult = LookupAccountName(nullptr,  szUsername, pSid,&dLengthSid,checkDomainName, &cchReferencedDomainName, &Use);

			if (bResult)
			{
				dwRid = *GetSidSubAuthority(pSid, *GetSidSubAuthorityCount(pSid) -1);
				EIDFree(pSid);
				return dwRid;  // Success - exit retry loop
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
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LookupAccountName", dwError);
				if (pSid)
				{
					EIDFree(pSid);
				}
				return 0;
			}
		}

		// Exhausted retries
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Exhausted %u retries for SID lookup (possible persistent race condition)",
			MAX_RETRIES);
		if (pSid)
		{
			EIDFree(pSid);
		}
		return 0;
	}

BOOL EIDBuildEnrolmentStatement(DWORD dwRid, const FILETIME* pftTime, PCCERT_CONTEXT pCertContext, PBYTE pbStatement, DWORD cbStatement)
{
	static const char s_szPurpose[] = "OpenAccessEID enrolment proof v1";
	static_assert(sizeof(s_szPurpose) - 1 == 32, "the purpose string is 32 bytes");
	if (!pftTime || !pCertContext || !pbStatement || cbStatement != EID_ENROLMENT_STATEMENT_SIZE)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	PBYTE p = pbStatement;
	memcpy(p, s_szPurpose, 32);
	p += 32;
	for (int i = 0; i < 4; i++)
	{
		*p++ = static_cast<BYTE>(dwRid >> (8 * i));
	}
	for (int i = 0; i < 4; i++)
	{
		*p++ = static_cast<BYTE>(pftTime->dwLowDateTime >> (8 * i));
	}
	for (int i = 0; i < 4; i++)
	{
		*p++ = static_cast<BYTE>(pftTime->dwHighDateTime >> (8 * i));
	}
	DWORD cbHash = 32;
	if (!CryptHashCertificate(NULL, CALG_SHA_256, 0, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, p, &cbHash) || cbHash != 32)
	{
		if (GetLastError() == 0)
		{
			SetLastError(ERROR_INVALID_DATA);
		}
		return FALSE;
	}
	return TRUE;
}

// Signs the enrolment statement with the certificate's key on the card, through a fresh
// non-silent context so that the card's provider asks for the PIN itself.
static BOOL SignEnrolmentStatement(PCRYPT_KEY_PROV_INFO pProvInfo, const BYTE* pbStatement, DWORD cbStatement, PBYTE* ppbSignature, DWORD* pcbSignature)
{
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	HCRYPTHASH hHash = NULL;  // Windows handle type - keep as NULL
	PBYTE pbSignature = nullptr;
	DWORD cbSignature = 0;
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	*ppbSignature = nullptr;
	*pcbSignature = 0;
	__try
	{
		if (!pProvInfo || !pProvInfo->pwszProvName)
		{
			dwError = NTE_NO_KEY;
			__leave;
		}
		if (!CryptAcquireContextW(&hProv, pProvInfo->pwszContainerName, pProvInfo->pwszProvName, pProvInfo->dwProvType,
			pProvInfo->dwFlags & CRYPT_MACHINE_KEYSET))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		if (!CryptCreateHash(hProv, CALG_SHA, NULL, 0, &hHash) || !CryptHashData(hHash, pbStatement, cbStatement, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"hash 0x%08x",dwError);
			__leave;
		}
		if (!CryptSignHashW(hHash, pProvInfo->dwKeySpec, nullptr, 0, nullptr, &cbSignature) || cbSignature == 0 || cbSignature > EID_MAX_ENROLMENT_SIGNATURE_SIZE)
		{
			dwError = GetLastError();
			if (dwError == 0)
			{
				dwError = NTE_BAD_LEN;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptSignHash 0x%08x",dwError);
			__leave;
		}
		pbSignature = static_cast<PBYTE>(EIDAlloc(cbSignature));
		if (!pbSignature)
		{
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		if (!CryptSignHashW(hHash, pProvInfo->dwKeySpec, nullptr, 0, pbSignature, &cbSignature))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptSignHash 0x%08x",dwError);
			__leave;
		}
		*ppbSignature = pbSignature;
		*pcbSignature = cbSignature;
		pbSignature = nullptr;
		fReturn = TRUE;
	}
	__finally
	{
		if (pbSignature)
		{
			EIDFree(pbSignature);
		}
		if (hHash)
		{
			CryptDestroyHash(hHash);
		}
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL LsaEIDCreateStoredCredential(__in_opt PWSTR szUsername, __in PWSTR szPassword, __in PCCERT_CONTEXT pContext, __in BOOL fEncryptPassword)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer = nullptr;
	   HANDLE hLsa = nullptr;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	DWORD dwSize;
	NTSTATUS status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	PBYTE pPointer;
	DWORD dwPasswordSize;
	DWORD dwBufferSize = 0;
	DWORD dwError = 0;
	PCRYPT_KEY_PROV_INFO pProvInfo = nullptr;
	DWORD dwRid = 0;
	FILETIME ftNow = {};
	BYTE rgbStatement[EID_ENROLMENT_STATEMENT_SIZE];  // NOSONAR - LSASS-01: C-style buffer
	PBYTE pbSignature = nullptr;
	DWORD cbSignature = 0;
	__try
	{
		if (!szPassword) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"szPassword null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		// add the CRYPT_KEY_PROV_INFO to the log if it exists
		dwSize = 0;
		if (CertGetCertificateContextProperty(pContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &dwSize))
		{
			pProvInfo = (PCRYPT_KEY_PROV_INFO) EIDAlloc(dwSize);
			if (!pProvInfo)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
				dwError = ERROR_OUTOFMEMORY;
				__leave;
			}
			if (CertGetCertificateContextProperty(pContext, CERT_KEY_PROV_INFO_PROP_ID, pProvInfo, &dwSize))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Keyspec %S container %s provider %s", (pProvInfo->dwKeySpec == AT_SIGNATURE ?"AT_SIGNATURE":"AT_KEYEXCHANGE"),
					pProvInfo->pwszContainerName, pProvInfo->pwszProvName);
			}
		}
	
		dwRid = szUsername ? GetRidFromUsername(szUsername) : GetCurrentRid();
		if (!dwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		// Prove possession of the certificate's key. The package requires this unless the
		// caller is an administrator; if signing fails the request goes without it and the
		// package decides.
		GetSystemTimeAsFileTime(&ftNow);
		if (!EIDBuildEnrolmentStatement(dwRid, &ftNow, pContext, rgbStatement, sizeof(rgbStatement))
			|| !SignEnrolmentStatement(pProvInfo, rgbStatement, sizeof(rgbStatement), &pbSignature, &cbSignature))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"no enrolment proof of possession 0x%08x", GetLastError());
			pbSignature = nullptr;
			cbSignature = 0;
		}

		dwPasswordSize = (DWORD) (wcslen(szPassword) + 1) * sizeof(WCHAR);
		dwBufferSize = (DWORD) (sizeof(EID_CALLPACKAGE_BUFFER) + dwPasswordSize + pContext->cbCertEncoded + cbSignature);

		pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwBufferSize);
		if( !pBuffer) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		memset(pBuffer, 0, sizeof(EID_CALLPACKAGE_BUFFER));
		pBuffer->dwRid = dwRid;
		pBuffer->MessageType = EIDCMCreateStoredCredential;
		pBuffer->usPasswordLen = 0;
		pPointer = (PBYTE) &(pBuffer[1]);

		pBuffer->wszPassword = (PWSTR) pPointer;
		memcpy(pPointer, szPassword, dwPasswordSize);
		pPointer += dwPasswordSize;
	
		if (pContext->cbCertEncoded > 0xFFFF)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pContext->cbCertEncoded > 0xFFFF (0x%08X)",pContext->cbCertEncoded);
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}

		pBuffer->dwCertificateSize = (USHORT) pContext->cbCertEncoded;
		pBuffer->fEncryptPassword = fEncryptPassword;

		pBuffer->pbCertificate = pPointer;
		memcpy(pPointer, pContext->pbCertEncoded, pBuffer->dwCertificateSize);
		pPointer += pBuffer->dwCertificateSize;

		pBuffer->ftEnrolmentTime = ftNow;
		pBuffer->usEnrolmentSignatureSize = static_cast<USHORT>(cbSignature);
		pBuffer->pbEnrolmentSignature = cbSignature ? pPointer : nullptr;
		if (cbSignature)
		{
			memcpy(pPointer, pbSignature, cbSignature);
			pPointer += cbSignature;
		}

		status = LsaConnectUntrusted(&hLsa);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
			__leave;
		}

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			__leave;
		}
		status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwBufferSize, nullptr, nullptr, nullptr);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			__leave;
		}
		if (pBuffer->dwError != 0)
		{
			dwError = pBuffer->dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Error = 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hLsa) LsaClose(hLsa);
		if (pBuffer) 
		{
			SecureZeroMemory(pBuffer, dwBufferSize);
			EIDFree(pBuffer);
		}
		if (pProvInfo) EIDFree(pProvInfo);
		if (pbSignature) EIDFree(pbSignature);
	}
	SetLastError(dwError);
	return fReturn;
}

/** return RID = 0 if failure */
DWORD LsaEIDGetRIDFromStoredCredential(__in PCCERT_CONTEXT pContext)
{
	PEID_CALLPACKAGE_BUFFER pBuffer = nullptr;
	   HANDLE hLsa = nullptr;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	DWORD dwSize;
	NTSTATUS status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	PBYTE pPointer;
	DWORD dwError = 0;
	DWORD dwRid = 0;
	__try
	{
		if (pContext->cbCertEncoded > 0xFFFF)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pContext->cbCertEncoded > 0xFFFF (0x%08X)",pContext->cbCertEncoded);
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}

		dwSize = (DWORD) (sizeof(EID_CALLPACKAGE_BUFFER) + pContext->cbCertEncoded); 
		pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
		if( !pBuffer) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}

		pBuffer->dwRid = 0;

		pBuffer->MessageType = EIDCMGetStoredCredentialRid;
		pBuffer->usPasswordLen = 0;
		pBuffer->wszPassword = nullptr;
		pBuffer->dwCertificateSize = (USHORT) pContext->cbCertEncoded;
		pPointer = (PBYTE) &(pBuffer[1]);
		pBuffer->pbCertificate = pPointer;
		memcpy(pPointer, pContext->pbCertEncoded, pContext->cbCertEncoded);
		pPointer += pContext->cbCertEncoded;
	
		status = LsaConnectUntrusted(&hLsa);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
			__leave;
		}

		ULONG ulAuthPackage;
		LSA_STRING lsaszPackageName;
		LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

		status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			__leave;
		}
		status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, nullptr, nullptr, nullptr);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			__leave;
		}
		if (pBuffer->dwError != 0)
		{
			// fail if the registration doesn't succeed
			dwError = pBuffer->dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Error = 0x%08x",dwError);
			__leave;
		}
		dwRid = pBuffer->dwRid;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Rid = 0x%x",dwRid);
	}
	__finally
	{
		if (hLsa) LsaClose(hLsa);
		if (pBuffer) EIDFree(pBuffer);
	}
	SetLastError(dwError);
	return dwRid;
}

BOOL IsEIDPackageAvailable()
{
    BOOL fReturn = FALSE;
	HANDLE hLsa;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	NTSTATUS status = LsaConnectUntrusted(&hLsa);  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
    if (status == STATUS_SUCCESS)  // NOSONAR - SCOPE-01: variable reused after the block
    {
        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
		if (status == STATUS_SUCCESS)
		{
			fReturn = TRUE;
		}
		LsaClose(hLsa);
	}
	return fReturn;
}

BOOL LsaEIDRemoveStoredCredential(__in_opt PWSTR szUsername)
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer = nullptr;
	   HANDLE hLsa = nullptr;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	DWORD dwSize;
	NTSTATUS status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	DWORD dwError = 0;
	__try
	{
		dwSize = sizeof(EID_CALLPACKAGE_BUFFER);
		pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
		if( !pBuffer) 
		{
			dwError = ERROR_OUTOFMEMORY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null 0x%08X",dwError);
			__leave;
		}
		if (!szUsername) 
		{
			pBuffer->dwRid = GetCurrentRid();
		}
		else
		{
			pBuffer->dwRid = GetRidFromUsername(szUsername);
		}
		pBuffer->MessageType = EIDCMRemoveStoredCredential;
		if (!pBuffer->dwRid)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
			__leave;
		}

		status = LsaConnectUntrusted(&hLsa);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
			dwError = status;
			__leave;
		}

		ULONG ulAuthPackage;
		LSA_STRING lsaszPackageName;
		LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

		status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
		status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, nullptr, nullptr, nullptr);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
		if (pBuffer->dwError != 0)
		{
			// fail if the registration doesn't succeed
			dwError = pBuffer->dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Error = 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hLsa) LsaClose(hLsa);
		if (pBuffer) EIDFree(pBuffer);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL LsaEIDRemoveAllStoredCredential()
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer = nullptr;
	   HANDLE hLsa = nullptr;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	DWORD dwSize;
	NTSTATUS status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	DWORD dwError = 0;
	__try
	{
		dwSize = sizeof(EID_CALLPACKAGE_BUFFER);
		pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
		if( !pBuffer) 
		{
			dwError = ERROR_OUTOFMEMORY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null 0x%08X",dwError);
			__leave;
		}
		pBuffer->dwRid = GetCurrentRid();
	
		pBuffer->MessageType = EIDCMRemoveAllStoredCredential;
		if (!pBuffer->dwRid)
		{
			dwError = ERROR_OUTOFMEMORY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
			__leave;
		}

		status = LsaConnectUntrusted(&hLsa);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
		}

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}

        status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, nullptr, nullptr, nullptr);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
		if (pBuffer->dwError != 0)
		{
			// fail if the registration doesn't succeed
			dwError = pBuffer->dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Error = 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
    }
	__finally
	{
		if (hLsa) LsaClose(hLsa);
		if (pBuffer) EIDFree(pBuffer);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL LsaEIDHasStoredCredential(__in_opt PWSTR szUsername)
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer = nullptr;
	   HANDLE hLsa = nullptr;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	DWORD dwSize;
	NTSTATUS status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	DWORD dwError = 0;
	__try
	{
		dwSize = sizeof(EID_CALLPACKAGE_BUFFER);
		pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
		if( !pBuffer) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		if (!szUsername) 
		{
			pBuffer->dwRid = GetCurrentRid();
		}
		else
		{
			pBuffer->dwRid = GetRidFromUsername(szUsername);
		}
		pBuffer->MessageType = EIDCMHasStoredCredential;
		if (!pBuffer->dwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}

		status = LsaConnectUntrusted(&hLsa);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
		status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, nullptr, nullptr, nullptr);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
		if( pBuffer->dwError != 0)
		{
			dwError = pBuffer->dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Error = 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hLsa) LsaClose(hLsa);
		if (pBuffer) EIDFree(pBuffer);
	}
	SetLastError(dwError);
	return fReturn;
}
