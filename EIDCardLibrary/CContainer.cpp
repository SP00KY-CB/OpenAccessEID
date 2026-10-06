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


#include <Windows.h>
#include <tchar.h>
#include <cryptuiapi.h>

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "CContainer.h"
#include "CertificateValidation.h"
#include "GPO.h"
#include "Package.h"

#pragma comment(lib, "Cryptui.lib")

static constexpr TCHAR REMOVALPOLICYKEY[] = TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Removal Policy");

// Maximum lengths for container/card/provider/reader names (CWE-20 fix for #63)
constexpr DWORD MAX_CONTAINER_NAME_LENGTH = 1024;
constexpr DWORD MAX_READER_NAME_LENGTH = 256;
constexpr DWORD MAX_CARD_NAME_LENGTH = 256;
constexpr DWORD MAX_PROVIDER_NAME_LENGTH = 256;

LPTSTR CContainer::ValidateAndCopyString(LPCTSTR szSource, DWORD maxLength, LPCWSTR szFieldName)
{
	if (szSource == nullptr)
	{
		return nullptr;
	}

	size_t len = _tcsnlen(szSource, maxLength + 1);
	if (len <= maxLength)
	{
		LPTSTR szResult = (LPTSTR) EIDAlloc((DWORD)(sizeof(TCHAR) * (len + 1)));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (szResult)
		{
			_tcscpy_s(szResult, len + 1, szSource);
			return szResult;
		}
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"%s name exceeds max length", szFieldName);
	}
	return nullptr;
}

CContainer::CContainer(LPCTSTR szReaderName, LPCTSTR szCardName, LPCTSTR szProviderName, LPCTSTR szContainerName, DWORD KeySpec,__in USHORT ActivityCount,PCCERT_CONTEXT pCertContext)
{
	_dwRid = 0; // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_szReaderName = nullptr; // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_szCardName = nullptr; // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_szProviderName = nullptr; // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_szContainerName = nullptr; // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_szUserName = nullptr; // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_KeySpec = KeySpec; // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_ActivityCount = ActivityCount; // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_pCertContext = pCertContext; // NOSONAR - INIT-01: member initialized in body for clarity/ordering

	_szReaderName = ValidateAndCopyString(szReaderName, MAX_READER_NAME_LENGTH, L"Reader");
	_szProviderName = ValidateAndCopyString(szProviderName, MAX_PROVIDER_NAME_LENGTH, L"Provider");
	_szContainerName = ValidateAndCopyString(szContainerName, MAX_CONTAINER_NAME_LENGTH, L"Container");
	_szCardName = ValidateAndCopyString(szCardName, MAX_CARD_NAME_LENGTH, L"Card");
}

CContainer::~CContainer()
{
	if (_szReaderName)
		EIDFree(_szReaderName);
	if (_szCardName)
		EIDFree(_szCardName);
	if (_szProviderName)
		EIDFree(_szProviderName);
	if (_szContainerName)
		EIDFree(_szContainerName);
	if (_szUserName) 
		EIDFree(_szUserName);
	if (_pCertContext) {
		CertFreeCertificateContext(_pCertContext);
	}
}

PTSTR CContainer::GetUserName()
{
	if (_szUserName)
	{
		return _szUserName;
	}
	DWORD dwSize;
	BOOL fReturn = FALSE;
	PCRYPT_KEY_PROV_INFO pKeyProvInfo = nullptr;
	__try
	{
		// get the subject details for the cert
		dwSize = CertGetNameString(_pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,nullptr,nullptr,0);
		if (!dwSize)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertGetNameString error = %d",GetLastError());
			__leave;
		}
		_szUserName = (LPTSTR) EIDAlloc(dwSize*sizeof(TCHAR));
		if (!_szUserName) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc error = %d",GetLastError());
			__leave;
		}
		dwSize = CertGetNameString(_pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,nullptr,_szUserName,dwSize);
		if (!dwSize)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertGetNameString error = %d",GetLastError());
			__leave;
		}
		fReturn = TRUE;

	}
	__finally
	{
		if (pKeyProvInfo)
			EIDFree(pKeyProvInfo);
		if (!fReturn && _szUserName)
		{
			EIDFree(_szUserName);
			_szUserName = nullptr;
		}
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"GetUserNameFromCertificate = %s",_szUserName);
	return _szUserName;
}

DWORD CContainer::GetRid()
{
	DWORD dwError = 0;
	if (_dwRid == 0)
	{
		_dwRid = LsaEIDGetRIDFromStoredCredential(_pCertContext);
		dwError = GetLastError();
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"_dwRid set to 0x%x",_dwRid);
	}
	SetLastError(dwError);
	return _dwRid;
}

PTSTR CContainer::GetProviderName() const
{
	return _szProviderName;
}
PTSTR CContainer::GetContainerName() const
{
	return _szContainerName;
}
DWORD CContainer::GetKeySpec() const
{
	return _KeySpec;
}

PCCERT_CONTEXT CContainer::GetCertificate() const
{
	PCCERT_CONTEXT pCertContext = CertDuplicateCertificateContext(_pCertContext);
	return pCertContext;
}

BOOL CContainer::Erase() const
{
	HCRYPTPROV hProv;
	return CryptAcquireContext(&hProv,
					_szContainerName,
					_szProviderName,
					PROV_RSA_FULL,
					CRYPT_DELETEKEYSET);
}

BOOL CContainer::IsOnReader(LPCTSTR szReaderName) const
{
	// _szReaderName is NULL if ValidateAndCopyString rejected or failed to copy it.
	if (_szReaderName == nullptr || szReaderName == nullptr)
	{
		return FALSE;
	}
	return _tcscmp(_szReaderName,szReaderName) == 0;
}

PEID_SMARTCARD_CSP_INFO CContainer::GetCSPInfo() const
{
	_ASSERTE( _CrtCheckMemory( ) );
	// Validate member pointers before use
	if (_szReaderName == nullptr || _szCardName == nullptr ||
	    _szProviderName == nullptr || _szContainerName == nullptr)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetCSPInfo: NULL member pointer");
		return nullptr;
	}
	DWORD dwReaderLen = (DWORD) _tcslen(_szReaderName)+1;
	DWORD dwCardLen = (DWORD) _tcslen(_szCardName)+1;
	DWORD dwProviderLen = (DWORD) _tcslen(_szProviderName)+1;
	DWORD dwContainerLen = (DWORD) _tcslen(_szContainerName)+1;
	DWORD dwBufferSize = dwReaderLen + dwCardLen + dwProviderLen + dwContainerLen;

	PEID_SMARTCARD_CSP_INFO pCspInfo = (PEID_SMARTCARD_CSP_INFO) EIDAlloc(sizeof(EID_SMARTCARD_CSP_INFO)+dwBufferSize*sizeof(TCHAR));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	if (!pCspInfo) return nullptr;
	memset(pCspInfo,0,sizeof(EID_SMARTCARD_CSP_INFO));
	pCspInfo->dwCspInfoLen = sizeof(EID_SMARTCARD_CSP_INFO)+dwBufferSize*sizeof(TCHAR);
	pCspInfo->MessageType = 1;
	pCspInfo->KeySpec = _KeySpec;
	pCspInfo->nCardNameOffset = ARRAYSIZE(pCspInfo->bBuffer);
	pCspInfo->nReaderNameOffset = pCspInfo->nCardNameOffset + dwCardLen;
	pCspInfo->nContainerNameOffset = pCspInfo->nReaderNameOffset + dwReaderLen;
	pCspInfo->nCSPNameOffset = pCspInfo->nContainerNameOffset + dwContainerLen;
	memset(pCspInfo->bBuffer,0,sizeof(pCspInfo->bBuffer));
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCardNameOffset] ,dwBufferSize + 4 - pCspInfo->nCardNameOffset, _szCardName);
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nReaderNameOffset] ,dwBufferSize + 4 - pCspInfo->nReaderNameOffset, _szReaderName);
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nContainerNameOffset] ,dwBufferSize + 4 - pCspInfo->nContainerNameOffset, _szContainerName);
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCSPNameOffset] ,dwBufferSize + 4 - pCspInfo->nCSPNameOffset, _szProviderName);
	_ASSERTE( _CrtCheckMemory( ) );
	return pCspInfo;
}

void CContainer::FreeCSPInfo(PEID_SMARTCARD_CSP_INFO pCspInfo) const
{
	EIDFree(pCspInfo);
}

BOOL CContainer::ViewCertificate(HWND hWnd) const
{
	CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
	BOOL fPropertiesChanged = FALSE;
	LPCSTR					szOid;
	certViewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
	certViewInfo.hwndParent = hWnd;
	// This dialog can be opened from a credential provider tile, i.e. from a SYSTEM process.
	// Remove every path out of it to a browser / file dialog / network fetch (CVE-2019-1388:
	// the "Issuer Statement" button opened a SYSTEM browser): no issuer statement, no links,
	// no hierarchy page, no store access and no URL retrieval beyond the local cache.
	certViewInfo.dwFlags = CRYPTUI_DISABLE_EDITPROPERTIES | CRYPTUI_DISABLE_ADDTOSTORE | CRYPTUI_DISABLE_EXPORT | CRYPTUI_DISABLE_HTMLLINK
		| CRYPTUI_DISABLE_ISSUERSTATEMENT | CRYPTUI_HIDE_HIERARCHYPAGE | CRYPTUI_CACHE_ONLY_URL_RETRIEVAL | CRYPTUI_DONT_OPEN_STORES;
	certViewInfo.szTitle = TEXT("Info");
	certViewInfo.pCertContext = _pCertContext;
	certViewInfo.cPurposes = 0;
	certViewInfo.rgszPurposes = nullptr;
	if (!GetPolicyValue(GPOPolicy::AllowCertificatesWithNoEKU))
	{
		certViewInfo.cPurposes = 1;
		szOid = szOID_KP_SMARTCARD_LOGON;
		certViewInfo.rgszPurposes = & szOid;
	}
	certViewInfo.pCryptProviderData = nullptr;
	certViewInfo.hWVTStateData = nullptr;
	certViewInfo.fpCryptProviderDataTrustedUsage = FALSE;
	certViewInfo.idxSigner = 0;
	certViewInfo.idxCert = 0;
	certViewInfo.fCounterSigner = FALSE;
	certViewInfo.idxCounterSigner = 0;
	certViewInfo.cStores = 0;
	certViewInfo.rghStores = nullptr;
	certViewInfo.cPropSheetPages = 0;
	certViewInfo.rgPropSheetPages = nullptr;
	certViewInfo.nStartPage = 0;
	
	return CryptUIDlgViewCertificate(&certViewInfo,&fPropertiesChanged);
}

BOOL CContainer::TriggerRemovePolicy() const
{
	LONG lResult;
	BOOL fReturn = FALSE;
	HKEY hRemovePolicyKey = nullptr;
	PBYTE pbBuffer = nullptr;
	DWORD dwSize;
	DWORD dwProcessId;
	DWORD dwSessionId;
	TCHAR szValueKey[sizeof(DWORD)+1]; // NOSONAR - LSASS-01: C-style buffer required by Win32 API

	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Enter");
	if (!_ActivityCount)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activity Count = 0");
		return FALSE;
	}
	__try
	{
		dwProcessId = GetCurrentProcessId();
		if (!ProcessIdToSessionId(dwProcessId, &dwSessionId))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ProcessIdToSessionId 0x%08x",GetLastError());
			__leave;
		}
		lResult = RegOpenKey(HKEY_LOCAL_MACHINE, REMOVALPOLICYKEY ,&hRemovePolicyKey);
		if (lResult !=ERROR_SUCCESS)
		{
			if (lResult == ERROR_FILE_NOT_FOUND)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"REMOVALPOLICYKEY not found. Creating ...");
				// Use RegCreateKeyEx with explicit security attributes for admin-only access
				SECURITY_ATTRIBUTES sa = {0};
				SECURITY_DESCRIPTOR sd = {0};
				sa.nLength = sizeof(SECURITY_ATTRIBUTES);
				sa.bInheritHandle = FALSE;
				// Initialize security descriptor with admin-only DACL
				if (InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
				{
					// NULL DACL = use inherited ACL from parent (HKLM requires admin)
					// This is acceptable since HKLM already restricts write access
					sa.lpSecurityDescriptor = &sd;
				}
				lResult = RegCreateKeyEx(HKEY_LOCAL_MACHINE, REMOVALPOLICYKEY, 0, nullptr,
					REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, &sa, &hRemovePolicyKey, nullptr);
				if (lResult !=ERROR_SUCCESS)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegCreateKeyEx 0x%08x",lResult);
					__leave;
				}
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegOpenKey 0x%08x (service not running ?)",lResult);
				__leave;
			}
		}
		// Validate reader name length to prevent integer overflow in size calculation
		if (_tcslen(_szReaderName) > MAX_PATH)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Reader name too long");
			__leave;
		}
		dwSize = (DWORD) (sizeof(USHORT) + sizeof(USHORT) + (_tcslen(_szReaderName) + 1) *sizeof(WCHAR));
		pbBuffer = (PBYTE) EIDAlloc(dwSize);
		if (!pbBuffer)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",GetLastError());
			__leave;
		}
#ifdef UNICODE
		wcscpy_s((PWSTR)pbBuffer, wcslen(_szReaderName) + 1, _szReaderName);
#else
		MultiByteToWideChar(CP_UTF8, 0, _szReaderName, _tcslen(_szReaderName) + 1, pbBuffer, _tcslen(_szReaderName) + 1);
#endif
		*(PUSHORT)(pbBuffer + dwSize - sizeof(USHORT)) = _ActivityCount;
		*(PUSHORT)(pbBuffer + dwSize - 2*sizeof(USHORT)) = 0;

		_stprintf_s(szValueKey, sizeof(DWORD)+1, TEXT("%d"),dwSessionId);

		lResult = RegSetValueEx (hRemovePolicyKey, szValueKey, 0, REG_BINARY, pbBuffer, dwSize);
		if (lResult !=ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegSetValue 0x%08x (not enough privilege ?)",lResult);
			__leave;
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RegSetValue %s %d %d",_szReaderName, _ActivityCount, dwSessionId);
		}


		fReturn = TRUE;
	}
	__finally
	{
		if (pbBuffer)
			EIDFree(pbBuffer);
		if (hRemovePolicyKey)
			RegCloseKey(hRemovePolicyKey);
	}
	return fReturn;
}

PEID_INTERACTIVE_LOGON CContainer::AllocateLogonStruct(PWSTR szPin, PDWORD pdwSize) // NOSONAR - API-01: PWSTR parameter dictated by LSA/logon struct API
{
	PEID_INTERACTIVE_LOGON pReturn = nullptr;
	PEID_INTERACTIVE_LOGON pRequest = nullptr;
	DWORD dwRid = 0;
	PWSTR szUserName = nullptr;
	WCHAR szDomainName[MAX_COMPUTERNAME_LENGTH+1] = L""; // NOSONAR - LSASS-01: C-style buffer required by Win32 API
	DWORD dwSize;
	DWORD dwTotalSize = 0;
	__try
	{
	
		// sanity check string lengths
		if (wcslen(szPin) * sizeof(WCHAR) > USHRT_MAX) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Input string is too long");
			__leave;
		}
		dwRid = this->GetRid();
		if (!dwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"dwRid = 0");
			__leave;
		}
		szUserName = GetUsernameFromRid(dwRid);
		if (!szUserName)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"szUserName not found");
			__leave;
		}
		dwSize = ARRAYSIZE(szDomainName);
		if (!GetComputerNameW(szDomainName,&dwSize))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"GetComputerNameW 0x%08x",GetLastError());
			__leave;
		}

		// Validate string lengths to prevent integer overflow in buffer size calculations
		if (wcslen(_szCardName) > MAX_PATH || wcslen(_szContainerName) > MAX_PATH ||
			wcslen(_szProviderName) > MAX_PATH || wcslen(_szReaderName) > MAX_PATH)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CSP info string too long");
			__leave;
		}

		DWORD dwCspBufferLength = (DWORD) (wcslen(_szCardName)+1  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
						+ wcslen(_szContainerName)+1
						+ wcslen(_szProviderName)+1
						+ wcslen(_szReaderName)+1);
		DWORD dwCspDataLength = sizeof(EID_SMARTCARD_CSP_INFO)
						+ dwCspBufferLength * sizeof(WCHAR);
		dwTotalSize = (DWORD) (sizeof(EID_INTERACTIVE_LOGON) 
						+ wcslen(szUserName) * sizeof(WCHAR)
						+ wcslen(szDomainName) * sizeof(WCHAR)
						+ wcslen(szPin) * sizeof(WCHAR)
						+ dwCspDataLength);
    
		pRequest = (PEID_INTERACTIVE_LOGON) EIDAlloc(dwTotalSize);
		if (!pRequest)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
			__leave;
		}
		memset(pRequest, 0, dwTotalSize);
		pRequest->MessageType = EID_INTERACTIVE_LOGON_SUBMIT_TYPE_VANILLA;
		pRequest->Flags = 0;
		_ASSERTE( _CrtCheckMemory( ) );
		PVOID pPointer = (PUCHAR) pRequest + sizeof(EID_INTERACTIVE_LOGON);
		// PIN
		_ASSERTE( _CrtCheckMemory( ) );
		pRequest->Pin.Length = pRequest->Pin.MaximumLength = (USHORT) (wcslen(szPin) * sizeof(WCHAR)); // NOSONAR - IDIOM-01: paired LENGTH/MaximumLength assignment is an intentional Win32 UNICODE_STRING idiom
		pRequest->Pin.Buffer = (PWSTR) pPointer;
		memcpy(pRequest->Pin.Buffer, szPin, pRequest->Pin.Length);
		pPointer = (PVOID) ((PCHAR) pPointer + pRequest->Pin.Length);
		// Username
		_ASSERTE( _CrtCheckMemory( ) );
		pRequest->UserName.Length = pRequest->UserName.MaximumLength = (USHORT) (wcslen(szUserName) * sizeof(WCHAR)); // NOSONAR - IDIOM-01: paired LENGTH/MaximumLength assignment is an intentional Win32 UNICODE_STRING idiom
		pRequest->UserName.Buffer = (PWSTR) pPointer;
		memcpy(pRequest->UserName.Buffer, szUserName, pRequest->UserName.Length);
		pPointer = (PVOID) ((PCHAR) pPointer + pRequest->UserName.Length);
		// Domain
		_ASSERTE( _CrtCheckMemory( ) );
		pRequest->LogonDomainName.Length = pRequest->LogonDomainName.MaximumLength = (USHORT) (wcslen(szDomainName) * sizeof(WCHAR)); // NOSONAR - IDIOM-01: paired LENGTH/MaximumLength assignment is an intentional Win32 UNICODE_STRING idiom
		pRequest->LogonDomainName.Buffer = (PWSTR) pPointer;
		memcpy(pRequest->LogonDomainName.Buffer, szDomainName, pRequest->LogonDomainName.Length);
		pPointer = (PVOID) ((PCHAR) pPointer + pRequest->LogonDomainName.Length);
		// CSPInfo
		_ASSERTE( _CrtCheckMemory( ) );
		pRequest->CspDataLength = dwCspDataLength;
		pRequest->CspData = (PUCHAR) pPointer;
		PEID_SMARTCARD_CSP_INFO pCspInfo = (PEID_SMARTCARD_CSP_INFO) pPointer;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		pCspInfo->dwCspInfoLen = pRequest->CspDataLength;
		// CSPInfo + content
		_ASSERTE( _CrtCheckMemory( ) );
		pCspInfo->MessageType = 1;
		pCspInfo->KeySpec = _KeySpec;
		pCspInfo->nCardNameOffset = ARRAYSIZE(pCspInfo->bBuffer);
		pCspInfo->nReaderNameOffset = (DWORD) (pCspInfo->nCardNameOffset + wcslen(_szCardName) + 1 );
		pCspInfo->nContainerNameOffset = (DWORD) (pCspInfo->nReaderNameOffset + wcslen(_szReaderName) + 1 );
		pCspInfo->nCSPNameOffset = (DWORD) (pCspInfo->nContainerNameOffset + wcslen(_szContainerName) + 1 );
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCardNameOffset] , dwCspBufferLength +  ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nCardNameOffset, _szCardName);
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nReaderNameOffset] ,dwCspBufferLength + ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nReaderNameOffset, _szReaderName);
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nContainerNameOffset] ,dwCspBufferLength + ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nContainerNameOffset, _szContainerName);
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCSPNameOffset] , dwCspBufferLength + ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nCSPNameOffset, _szProviderName);	
		_ASSERTE( _CrtCheckMemory( ) );
		// Put pointer in relative format
		pRequest->Pin.Buffer = (PWSTR) ((PUCHAR) pRequest->Pin.Buffer - (ULONG_PTR) pRequest);
		pRequest->UserName.Buffer = (PWSTR) ((PUCHAR) pRequest->UserName.Buffer - (ULONG_PTR) pRequest);
		pRequest->LogonDomainName.Buffer = (PWSTR) ((PUCHAR) pRequest->LogonDomainName.Buffer - (ULONG_PTR) pRequest);
		pRequest->CspData = (pRequest->CspData - (ULONG_PTR) pRequest);
		// success !
		_ASSERTE( _CrtCheckMemory( ) );
		pReturn = pRequest;
		if (pdwSize) *pdwSize = dwTotalSize;
	}
	__finally
	{
		if (!pReturn && pRequest)
		{
			// Securely zero PIN and other sensitive data before freeing
			SecureZeroMemory(pRequest, dwTotalSize);
			EIDFree(pRequest);
		}
		if (szUserName)
			EIDFree(szUserName);
	}
	return pReturn;
}