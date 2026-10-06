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
#include <AccCtrl.h>
#include <AclAPI.h>
#include "EIDCardLibrary.h"
#include "CertificateUtilities.h"
#include "Tracing.h"
#include <array>
#include <strsafe.h>

#pragma comment (lib,"Scarddlg")
#pragma comment (lib,"Rpcrt4")

// Non-const copies for Windows API compatibility (CERT_ENHKEY_USAGE.rgpszUsageIdentifier is LPSTR*)
// With /Zc:strictStrings (enabled by default in C++23), string literals are const and cannot
// be implicitly converted to non-const LPSTR. These static arrays provide writable storage.
static char s_szOidClientAuth[] = szOID_PKIX_KP_CLIENT_AUTH;          // NOSONAR - GLOBAL-01: Runtime-initialized LSA state
static char s_szOidServerAuth[] = szOID_PKIX_KP_SERVER_AUTH;          // NOSONAR - GLOBAL-01: Runtime-initialized LSA state
static char s_szOidSmartCardLogon[] = szOID_KP_SMARTCARD_LOGON;       // NOSONAR - GLOBAL-01: Runtime-initialized LSA state
static char s_szOidEfs[] = szOID_KP_EFS;                              // NOSONAR - GLOBAL-01: Runtime-initialized LSA state
static char s_szOidKeyUsage[] = szOID_KEY_USAGE;                      // NOSONAR - GLOBAL-01: Runtime-initialized LSA state
static char s_szOidBasicConstraints2[] = szOID_BASIC_CONSTRAINTS2;    // NOSONAR - GLOBAL-01: Runtime-initialized LSA state
static char s_szOidEnhancedKeyUsage[] = szOID_ENHANCED_KEY_USAGE;     // NOSONAR - GLOBAL-01: Runtime-initialized LSA state
static char s_szOidSubjectKeyId[] = szOID_SUBJECT_KEY_IDENTIFIER;     // NOSONAR - GLOBAL-01: Runtime-initialized LSA state
static char s_szOidSha1RsaSign[] = szOID_OIWSEC_sha1RSASign;          // NOSONAR - GLOBAL-01: Runtime-initialized LSA state

BOOL SetupCertificateContextWithKeyInfo(
    __in PCCERT_CONTEXT pCertContext, __in HCRYPTPROV hProv,
    __in LPCWSTR pwszProviderName, __in LPCWSTR pwszContainerName, __in DWORD dwKeySpec)
{
	CRYPT_KEY_PROV_INFO KeyProvInfo;
	memset(&KeyProvInfo, 0, sizeof(CRYPT_KEY_PROV_INFO));
	KeyProvInfo.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID;
	KeyProvInfo.pwszProvName = (LPWSTR)pwszProviderName;  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
	KeyProvInfo.pwszContainerName = (LPWSTR)pwszContainerName;  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
	KeyProvInfo.dwProvType = PROV_RSA_FULL;
	KeyProvInfo.dwKeySpec = dwKeySpec;

	if (!CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &KeyProvInfo))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CertSetCertificateContextProperty CERT_KEY_PROV_INFO_PROP_ID 0x%08x", GetLastError());
		return FALSE;
	}

	CERT_KEY_CONTEXT keyContext;
	memset(&keyContext, 0, sizeof(CERT_KEY_CONTEXT));
	keyContext.cbSize = sizeof(CERT_KEY_CONTEXT);
	keyContext.hCryptProv = hProv;
	keyContext.dwKeySpec = dwKeySpec;
	if (!CertSetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, 0, &keyContext))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CertSetCertificateContextProperty CERT_KEY_CONTEXT_PROP_ID 0x%08x", GetLastError());
		return FALSE;
	}
	return TRUE;
}

LPTSTR BuildContainerNameFromReader(LPCTSTR szReaderName)
{
	if (!szReaderName)
	{
		return nullptr;
	}

	size_t ulNameLen = _tcslen(szReaderName);
	LPTSTR szContainerName = (LPTSTR) EIDAlloc((DWORD)(sizeof(TCHAR) * (ulNameLen + 6)));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	if (!szContainerName)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"EIDAlloc failed in BuildContainerNameFromReader");
		return nullptr;
	}
	_stprintf_s(szContainerName, (ulNameLen + 6), _T("\\\\.\\%s\\"), szReaderName);
	return szContainerName;
}

BOOL SchGetProviderNameFromCardName(__in LPCTSTR szCardName, __out LPTSTR szProviderName, __out PDWORD pdwProviderNameLen)
{
	// get provider name
	SCARDCONTEXT hSCardContext;
	LONG lCardStatus;
	lCardStatus = SCardEstablishContext(SCARD_SCOPE_USER,nullptr,nullptr,&hSCardContext);
	if (SCARD_S_SUCCESS != lCardStatus)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08x",lCardStatus);
		return FALSE;
	}
	
	lCardStatus = SCardGetCardTypeProviderName(hSCardContext,
									   szCardName,
									   SCARD_PROVIDER_CSP,
									   szProviderName,
									   pdwProviderNameLen);
	if (SCARD_S_SUCCESS != lCardStatus)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardGetCardTypeProviderName 0x%08x",lCardStatus);
		SCardReleaseContext(hSCardContext);
		return FALSE;
	}
	SCardReleaseContext(hSCardContext);
	return TRUE;
}

// the string must be freed using RpcStringFree
PTSTR GetUniqueIDString()
{
	UUID pUUID;
	PTSTR sTemp = nullptr;
	RPC_STATUS hr;
	DWORD dwError = 0;
	hr = UuidCreate(&pUUID);
	if (hr == RPC_S_OK || hr == RPC_S_UUID_LOCAL_ONLY)
	{
		hr = UuidToString(&pUUID, (RPC_WSTR *)&sTemp); 
		if (hr != RPC_S_OK)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UuidToString 0x%08x",hr);
			dwError = HRESULT_CODE(hr);
		}
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UuidCreate 0x%08x",hr);
		dwError = HRESULT_CODE(hr);
	}
	SetLastError(dwError);
	return sTemp;
}

PCCERT_CONTEXT SelectCertificateWithPrivateKey(HWND hWnd)
{
	PCCERT_CONTEXT returnedContext = nullptr;

	HCERTSTORE hCertStore;
	HCERTSTORE hStore;
	BOOL bShowNoCertificate = TRUE;
	// open trusted root store
	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_CURRENT_USER,_T("Root")); // NOSONAR - Windows API requires NULL
	if (hCertStore)
	{
		PCCERT_CONTEXT pCertContext = nullptr;
		PBYTE dwKeySpec = nullptr;
		DWORD dwSize = 0;
		// open a temp store and copy context which have a private key
		hStore = CertOpenStore(CERT_STORE_PROV_MEMORY,X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,NULL,0,nullptr);

		if (hStore)
		{
			pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
			while (pCertContext)
			{
				
				if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID,dwKeySpec,&dwSize))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					//The certificate has a private key
					CertAddCertificateContextToStore(hStore,pCertContext,CERT_STORE_ADD_USE_EXISTING,nullptr);
					bShowNoCertificate = FALSE;
				}
				pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
			}
			if (bShowNoCertificate)
			{
				MessageBox(hWnd,_T("No Trusted certificate found"),_T("Warning"),0);
			}
			else
			{
				returnedContext = CryptUIDlgSelectCertificateFromStore(
					  hStore,
					  nullptr,
					  nullptr,
					  nullptr,
					  CRYPTUI_SELECT_LOCATION_COLUMN,
					  0,
					  nullptr);
			}
			CertCloseStore(hStore,0);
		}
		CertCloseStore(hCertStore,0);
	}
	return returnedContext;
}

// Helper: Check if certificate name matches computer name
static bool IsComputerNameMatch(LPCTSTR szCertName, LPCTSTR szComputerName)
{
    return szCertName && szComputerName && _tcscmp(szCertName, szComputerName) == 0;
}

// Helper: Check if certificate has an associated private key
static bool CertificateHasPrivateKey(PCCERT_CONTEXT pCertContext)
{
    if (!pCertContext) return false;
    DWORD dwSize = 0;
    return CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &dwSize) != FALSE;
}

PCCERT_CONTEXT SelectFirstCertificateWithPrivateKey()
{
	PCCERT_CONTEXT returnedContext = nullptr;
	TCHAR szCertName[1024] = TEXT("");  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	TCHAR szComputerName[257];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwSize = ARRAYSIZE(szComputerName);
	HCERTSTORE hCertStore = nullptr;
	GetComputerName(szComputerName,&dwSize);
	// open trusted root store
	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_CURRENT_USER,_T("Root")); // NOSONAR - Windows API requires NULL
	if (hCertStore)
	{
		PCCERT_CONTEXT pCertContext = nullptr;
		pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext);
		while (pCertContext)
		{
			// Skip certificates without private keys
			if (!CertificateHasPrivateKey(pCertContext))
			{
				pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext);
				continue;
			}

			// Certificate has a private key - process it
			if (returnedContext)
				CertFreeCertificateContext(returnedContext);

			// Get the subject details for the cert
			CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, szCertName, ARRAYSIZE(szCertName));

			// Check for computer name match - exact match takes priority
			if (IsComputerNameMatch(szCertName, szComputerName))
			{
				returnedContext = pCertContext;
				break;  // Found exact match, exit loop
			}

			// Keep a reference to this certificate as fallback
			returnedContext = CertDuplicateCertificateContext(pCertContext);
			pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext);
		}
		CertCloseStore(hCertStore,0);
	}
	return returnedContext;
}


LPBYTE AllocateAndEncodeObject(LPVOID pvStruct, LPCSTR lpszStructType, LPDWORD pdwSize )  // NOSONAR - API-01: signature dictated by Windows/callback API
{
   // Get Key Usage blob size   
   LPBYTE pbEncodedObject = nullptr;
   BOOL bResult = TRUE;
   DWORD dwError = 0;
	__try
   {
	   *pdwSize = 0;	
	   bResult = CryptEncodeObject(X509_ASN_ENCODING,   
								   lpszStructType,   
								   pvStruct,
								   nullptr, pdwSize);
	   if (!bResult)   
	   {   
		  dwError = GetLastError();
		  __leave;   
	   }   

	   // Allocate Memory for Key Usage Blob   
	   pbEncodedObject = (LPBYTE)EIDAlloc(*pdwSize);   
	   if (!pbEncodedObject)   
	   {   
		  bResult = FALSE;
		  dwError = GetLastError();   
		  __leave;   
	   }   

	   // Get Key Usage Extension blob   
	   bResult = CryptEncodeObject(X509_ASN_ENCODING,   
								   lpszStructType,   
								   pvStruct,   
								   pbEncodedObject, pdwSize);   
	   if (!bResult)   
	   {   
		  dwError = GetLastError();  
		  __leave;   
	   }   
   }
   __finally
   {
		if (pbEncodedObject && !bResult)
		{
			// Freed here, so it must not be returned: the callers free the
			// returned pointer again in their own cleanup (double free).
			EIDFree(pbEncodedObject);
			pbEncodedObject = nullptr;
		}
   }
   if (!pbEncodedObject)
   {
		// Callers report GetLastError() when this returns NULL.
		SetLastError(dwError);
   }
   return pbEncodedObject;
}

BOOL AskForCard(LPWSTR szReader, DWORD ReaderLength,LPWSTR szCard,DWORD CardLength)
{
	SCARDCONTEXT     hSC = NULL;  // Windows handle type - keep as NULL
	OPENCARDNAME_EX  dlgStruct;
	LONG             lReturn = 0;
	BOOL			 fReturn = FALSE;
	__try
	{
		// Establish a context.
		// It will be assigned to the structure's hSCardContext field.
		lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
										nullptr,
										nullptr,
										&hSC );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardEstablishContext 0x%08X",lReturn);

			// Provide user-friendly error message for common cases
			if (lReturn == SCARD_E_NO_SERVICE)
			{
				MessageBox(nullptr,
					L"The Smart Card service is not running.\n\n"
					L"This typically means:\n"
					L"1. No smart card reader is installed on this system\n"
					L"2. The Smart Card service is disabled\n\n"
					L"To use OpenAccess EID, you need:\n"
					L"- A physical smart card reader, OR\n"
					L"- A virtual smart card (requires TPM)\n\n"
					L"Run InstallVirtualSmartCard.ps1 (as Administrator) to create a virtual smart card if your system has TPM.",
					L"Smart Card Service Not Available",
					MB_ICONERROR | MB_OK);
			}
			__leave;
		}

		// Initialize the structure.
		memset(&dlgStruct, 0, sizeof(dlgStruct));
		dlgStruct.dwStructSize = sizeof(dlgStruct);
		dlgStruct.hSCardContext = hSC;
		dlgStruct.dwFlags = SC_DLG_MINIMAL_UI;
		dlgStruct.lpstrRdr = szReader;
		dlgStruct.nMaxRdr = ReaderLength;
		dlgStruct.lpstrCard = szCard;
		dlgStruct.nMaxCard = CardLength;
		dlgStruct.lpstrTitle = L"Select Card";
		dlgStruct.dwShareMode = 0;
		// Display the select card dialog box.
		lReturn = SCardUIDlgSelectCard(&dlgStruct);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			szReader[0]=0;
			szCard[0]=0;
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hSC)
			SCardReleaseContext(hSC);
	}
	// Free the context.
	// lReturn is of type LONG.
	// hSC was set by an earlier call to SCardEstablishContext.
	SetLastError(lReturn);
	return fReturn;
}

BOOL CreateCertificate(PUI_CERTIFICATE_INFO pCertificateInfo)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
	BOOL fReturn = FALSE;
	CERT_INFO CertInfo = {0};
	CertInfo.rgExtension = nullptr;
	CERT_NAME_BLOB SubjectIssuerBlob = {0};
	HCRYPTPROV hCryptProvNewCertificate = NULL;  // Windows handle type - keep as NULL
	HCRYPTPROV hCryptProvRootCertificate = NULL;  // Windows handle type - keep as NULL
	PCCERT_CONTEXT pNewCertificateContext = nullptr;
	PCERT_PUBLIC_KEY_INFO pbPublicKeyInfo = nullptr;
	HCERTSTORE hCertStore = nullptr;
	PBYTE  pbSignedEncodedCertReq = nullptr;
	BOOL bDestroyContainer = FALSE;
	HCRYPTKEY hKey = NULL;  // NOSONAR - HANDLE-01: HCRYPTKEY is ULONG_PTR, not pointer type
	CRYPT_KEY_PROV_INFO KeyProvInfo = {};
	LPTSTR szContainerName=nullptr;
    FILETIME ftTime;
	std::array<BYTE, 8> SerialNumber;
	DWORD dwKeyType = 0;
	DWORD cbPublicKeyInfo = 0;
	BOOL pfCallerFreeProvOrNCryptKey = FALSE;
	CRYPT_ALGORITHM_IDENTIFIER SigAlg;
	CRYPT_OBJID_BLOB  Parameters;
	CRYPTUI_WIZ_EXPORT_INFO WizInfo = {0};
	DWORD cbEncodedCertReqSize = 0;
	TCHAR szProviderName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwProviderNameLen = 1024;
	DWORD dwFlag;
	DWORD dwSize;
	HCRYPTHASH hHash = NULL;  // Windows handle type - keep as NULL
    BYTE ByteData;   
    CRYPT_BIT_BLOB KeyUsage;   
	LPBYTE pbKeyUsage = nullptr;
	LPBYTE pbBasicConstraints = nullptr;
	LPBYTE pbEnhKeyUsage = nullptr;
	LPBYTE pbKeyIdentifier = nullptr;
	LPBYTE SubjectKeyIdentifier = nullptr;
	CRYPT_DATA_BLOB CertKeyIdentifier;
	CERT_BASIC_CONSTRAINTS2_INFO BasicConstraints;
	CERT_ENHKEY_USAGE CertEnhKeyUsage = { 0, nullptr };
	CERT_EXTENSIONS CertExtensions = {0} ;
	DWORD dwError = 0;
	PSID pSidSystem = nullptr;
	PSID pSidAdmins = nullptr;
	PACL pDacl = nullptr;
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
	PSECURITY_DESCRIPTOR pSD = nullptr;
	__try   
    { 

		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Enter");
		if (pCertificateInfo == nullptr)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"pCertificateInfo NULL");
			__leave;
		}

		pCertificateInfo->pNewCertificate = nullptr;
		// prepare the container name based on the support
		if (pCertificateInfo->dwSaveon == UI_CERTIFICATE_INFO_SAVEON_SMARTCARD)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_SMARTCARD");
			// provider name
			if (!SchGetProviderNameFromCardName(pCertificateInfo->wszCardName, szProviderName, &dwProviderNameLen))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SchGetProviderNameFromCardName 0x%08X", dwError);
				__leave;
			}
			// container name from card name
			szContainerName = BuildContainerNameFromReader(pCertificateInfo->wszReaderName);
			if (!szContainerName)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"BuildContainerNameFromReader failed");
				__leave;
			}
		}
		else
		{
			// container name = GUID
			szContainerName = GetUniqueIDString();
			if (!szContainerName) 
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"GetUniqueIDString 0x%08X", dwError);
				__leave;
			}
			
			// Provider  MS_ENHANCED_PROV
			_stprintf_s(szProviderName,1024,_T("%s"),MS_ENHANCED_PROV);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"szContainerName = %s", szContainerName);

		dwFlag=CRYPT_NEWKEYSET;
		switch(pCertificateInfo->dwSaveon)
		{
			case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE: // machine
			case UI_CERTIFICATE_INFO_SAVEON_SMARTCARD: // smart card
				dwFlag |= CRYPT_MACHINE_KEYSET;
				break;
			default:
				break;
		}
		// create container
		if (!CryptAcquireContext(
			&hCryptProvNewCertificate,
			szContainerName,   
			szProviderName,
			PROV_RSA_FULL,
			dwFlag))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptAcquireContext 0x%08X", dwError);
			__leave;
		}
		else
		{
			bDestroyContainer=TRUE;
		}
		// generate key
		dwFlag=0;
		switch(pCertificateInfo->dwSaveon)
		{
			case UI_CERTIFICATE_INFO_SAVEON_USERSTORE: // user
			case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE: // machine
			case UI_CERTIFICATE_INFO_SAVEON_FILE: // file
				dwFlag |= CRYPT_EXPORTABLE;
				break;
			default:
				break;
		}
		// Key Size
		dwFlag |= pCertificateInfo->dwKeySizeInBits * 0x10000;
		if (!CryptGenKey(hCryptProvNewCertificate, pCertificateInfo->dwKeyType, dwFlag, &hKey))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptGenKey 0x%08X", dwError);
			__leave;
		}

		
		// create the cert data
		if (!CertStrToName(X509_ASN_ENCODING,pCertificateInfo->szSubject,CERT_X500_NAME_STR,nullptr,nullptr,&SubjectIssuerBlob.cbData,nullptr))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertStrToName 0x%08X", dwError);
			__leave;
		}
		SubjectIssuerBlob.pbData = (PBYTE) EIDAlloc(SubjectIssuerBlob.cbData);
		if (!SubjectIssuerBlob.pbData)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
			__leave;
		}
		if (!CertStrToName(X509_ASN_ENCODING,pCertificateInfo->szSubject,CERT_X500_NAME_STR,nullptr,(PBYTE)SubjectIssuerBlob.pbData,&SubjectIssuerBlob.cbData,nullptr))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertStrToName 0x%08X", dwError);
			__leave;
		}

		//////////////////////////////////////////////////
		// Key Usage & ...
		
		// max 10 extensions => we don't count them
		CertInfo.rgExtension = (PCERT_EXTENSION) EIDAlloc(sizeof(CERT_EXTENSION) * 10);
		CertInfo.cExtension = 0;
		if (!CertInfo.rgExtension)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
			__leave;
		}


		// Set Key Usage according to Public Key Type   
		ZeroMemory(&KeyUsage, sizeof(KeyUsage));   
		KeyUsage.cbData = 1;   
		KeyUsage.pbData = &ByteData;   
    
		if (pCertificateInfo->dwKeyType == AT_SIGNATURE)   
		{   
		   ByteData = CERT_DIGITAL_SIGNATURE_KEY_USAGE|   
						CERT_NON_REPUDIATION_KEY_USAGE|   
						CERT_KEY_CERT_SIGN_KEY_USAGE |   
						CERT_CRL_SIGN_KEY_USAGE;   
		}   
    
		if (pCertificateInfo->dwKeyType == AT_KEYEXCHANGE)   
		{   
		   ByteData = CERT_DIGITAL_SIGNATURE_KEY_USAGE |   
						CERT_DATA_ENCIPHERMENT_KEY_USAGE|   
						CERT_KEY_ENCIPHERMENT_KEY_USAGE |   
						CERT_KEY_AGREEMENT_KEY_USAGE;   
		}


		pbKeyUsage = AllocateAndEncodeObject(&KeyUsage,X509_KEY_USAGE,&dwSize);
		if (!pbKeyUsage) 
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"AllocateAndEncodeObject 0x%08X", dwError);
			__leave;
		}

		CertInfo.rgExtension[CertInfo.cExtension].pszObjId = s_szOidKeyUsage;   
		CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbKeyUsage;   
		// Increase extension count   
		CertInfo.cExtension++; 
	   //////////////////////////////////////////////////

	   // Zero Basic Constraints structure   
		ZeroMemory(&BasicConstraints, sizeof(BasicConstraints));   
    
		// Self-signed is always a CA   
		if (pCertificateInfo->bIsSelfSigned)   
		{   
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SelfSigned");
			BasicConstraints.fCA = TRUE;   
			BasicConstraints.fPathLenConstraint = TRUE;   
			BasicConstraints.dwPathLenConstraint = 1;   
		}   
		else   
		{   
			BasicConstraints.fCA = pCertificateInfo->bIsCA;   
		}   
		pbBasicConstraints = AllocateAndEncodeObject(&BasicConstraints,X509_BASIC_CONSTRAINTS2,&dwSize);
		if (!pbBasicConstraints) 
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"AllocateAndEncodeObject 0x%08X", dwError);
			__leave;
		}

		// Set Basic Constraints extension   
		CertInfo.rgExtension[CertInfo.cExtension].pszObjId = s_szOidBasicConstraints2;   
		CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbBasicConstraints;   
		// Increase extension count   
		CertInfo.cExtension++;  
		//////////////////////////////////////////////////
		if (pCertificateInfo->bHasClientAuthentication)
			CertEnhKeyUsage.cUsageIdentifier++;
		if (pCertificateInfo->bHasServerAuthentication)
			CertEnhKeyUsage.cUsageIdentifier++;
		if (pCertificateInfo->bHasSmartCardAuthentication)
			CertEnhKeyUsage.cUsageIdentifier++;
		if (pCertificateInfo->bHasEFS)
			CertEnhKeyUsage.cUsageIdentifier++;


		if (CertEnhKeyUsage.cUsageIdentifier != 0)   
		{
			CertEnhKeyUsage.rgpszUsageIdentifier = (LPSTR*) EIDAlloc(sizeof(LPSTR)*CertEnhKeyUsage.cUsageIdentifier);
			if (!CertEnhKeyUsage.rgpszUsageIdentifier)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;
			}
			CertEnhKeyUsage.cUsageIdentifier = 0;
			if (pCertificateInfo->bHasClientAuthentication)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = s_szOidClientAuth;
			if (pCertificateInfo->bHasServerAuthentication)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = s_szOidServerAuth;
			if (pCertificateInfo->bHasSmartCardAuthentication)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = s_szOidSmartCardLogon;
			if (pCertificateInfo->bHasEFS)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = s_szOidEfs;
			pbEnhKeyUsage = AllocateAndEncodeObject(&CertEnhKeyUsage,X509_ENHANCED_KEY_USAGE,&dwSize);
			if (!pbEnhKeyUsage)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"AllocateAndEncodeObject 0x%08X", dwError);
				__leave;
			}

		   // Set Basic Constraints extension   
		   CertInfo.rgExtension[CertInfo.cExtension].pszObjId = s_szOidEnhancedKeyUsage;   
		   CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		   CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		   CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbEnhKeyUsage;   
		   	// Increase extension count   
			CertInfo.cExtension++; 
		}

		//////////////////////////////////////////////////

		if (pCertificateInfo->bIsSelfSigned)
		{
			CertExtensions.cExtension = CertInfo.cExtension;
			CertExtensions.rgExtension = CertInfo.rgExtension;
			pNewCertificateContext = CertCreateSelfSignCertificate(hCryptProvNewCertificate,&SubjectIssuerBlob,
				0,nullptr,nullptr,&pCertificateInfo->StartTime,&pCertificateInfo->EndTime,&CertExtensions);
			if (!pNewCertificateContext)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertCreateSelfSignCertificate 0x%08X", dwError);
				__leave;
			}
		}
		else
		{
			CertInfo.Subject = SubjectIssuerBlob;
			CertInfo.dwVersion = CERT_V3;

			// set issuer info
			CertInfo.Issuer = pCertificateInfo->pRootCertificate->pCertInfo->Subject;
			CertInfo.IssuerUniqueId = pCertificateInfo->pRootCertificate->pCertInfo->SubjectUniqueId;

			
			SystemTimeToFileTime(&pCertificateInfo->StartTime, &ftTime);   
			CertInfo.NotBefore = ftTime;  

			SystemTimeToFileTime(&pCertificateInfo->EndTime, &ftTime);   
			CertInfo.NotAfter = ftTime;   

			// Create Random Serial Number
			if (!CryptGenRandom(hCryptProvNewCertificate, static_cast<DWORD>(SerialNumber.size()), SerialNumber.data()))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptGenRandom 0x%08X", dwError);
				__leave;
			}   

			// Set Serial Number of Certificate
			CertInfo.SerialNumber.cbData = static_cast<DWORD>(SerialNumber.size());
			CertInfo.SerialNumber.pbData = SerialNumber.data();   
			
			// public key
			//////////////
			if(!CryptExportPublicKeyInfo(
				  hCryptProvNewCertificate,
				  pCertificateInfo->dwKeyType,  
				  X509_ASN_ENCODING,      
				  pbPublicKeyInfo,		
				  &cbPublicKeyInfo))     
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptExportPublicKeyInfo 0x%08X", dwError);
				__leave;	
			}
			pbPublicKeyInfo = (PCERT_PUBLIC_KEY_INFO) EIDAlloc(cbPublicKeyInfo);
			if (!pbPublicKeyInfo) {
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;
			}
			if(!CryptExportPublicKeyInfo(
				  hCryptProvNewCertificate,
				  pCertificateInfo->dwKeyType,   
				  X509_ASN_ENCODING,      
				  pbPublicKeyInfo,		
				  &cbPublicKeyInfo))     
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptExportPublicKeyInfo 0x%08X", dwError);
				__leave;
			}
			CertInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;
			// Create Hash (using SHA-256 for security)
			if (!CryptCreateHash(hCryptProvNewCertificate, CALG_SHA_256, 0, NULL, &hHash)) // NOSONAR - Windows API requires NULL for HCRYPTPROV parameter
			{   
			  dwError = GetLastError();
			  EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptCreateHash 0x%08X", dwError);
			  __leave;   
			}   

			// Hash Public Key Info   
			if (!CryptHashData(hHash, (LPBYTE)pbPublicKeyInfo, dwSize, 0))   
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptHashData 0x%08X", dwError);
				__leave;   
			}   

			// Get Size of Hash
			if (!CryptGetHashParam(hHash, HP_HASHVAL, nullptr, &dwSize, 0))
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptGetHashParam 0x%08X", dwError);
				__leave;   
			}   

			// Allocate Memory for Key Identifier (hash of Public Key info)   
			pbKeyIdentifier = (LPBYTE)EIDAlloc(dwSize);   
			if (!pbKeyIdentifier)   
			{   
			  dwError = GetLastError();
			  EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
			  __leave;   
			}   

			// Get Hash of Public Key Info   
			if (!CryptGetHashParam(hHash, HP_HASHVAL, pbKeyIdentifier, &dwSize, 0))   
			{   
			  dwError = GetLastError();
			  EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptGetHashParam 0x%08X", dwError);
			  __leave;   
			}   

			// We will use this to set the Key Identifier extension   
			CertKeyIdentifier.cbData = dwSize;   
			CertKeyIdentifier.pbData = pbKeyIdentifier;  

			// Get Subject Key Identifier Extension size   
			if (!CryptEncodeObject(X509_ASN_ENCODING,
									   szOID_SUBJECT_KEY_IDENTIFIER,
									   (LPVOID)&CertKeyIdentifier,
									   nullptr, &dwSize))
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptEncodeObject 0x%08X", dwError);
				__leave;   
			}   

			// Allocate Memory for Subject Key Identifier Blob   
			SubjectKeyIdentifier = (LPBYTE)EIDAlloc(dwSize);   
			if (!SubjectKeyIdentifier)   
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;   
			}   

			// Get Subject Key Identifier Extension   
			if (!CryptEncodeObject(X509_ASN_ENCODING,   
									   szOID_SUBJECT_KEY_IDENTIFIER,   
									   (LPVOID)&CertKeyIdentifier,   
									   SubjectKeyIdentifier, &dwSize))
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptEncodeObject 0x%08X", dwError);
				__leave;   
			}   

			// Set Subject Key Identifier   
			CertInfo.rgExtension[CertInfo.cExtension].pszObjId = s_szOidSubjectKeyId;   
			CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
			CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
			CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = SubjectKeyIdentifier;   

			// Increase extension count   
			CertInfo.cExtension++;   
////////////////////////////////////////////////////////////////////////////////////////////////////////
			// sign certificate
			///////////////////
			memset(&Parameters, 0, sizeof(Parameters));
			SigAlg.pszObjId = s_szOidSha1RsaSign;
			SigAlg.Parameters = Parameters;

			CertInfo.SignatureAlgorithm = SigAlg;

			// retrieve crypt context from root cert
			if (!CryptAcquireCertificatePrivateKey(pCertificateInfo->pRootCertificate,0,nullptr,
					&hCryptProvRootCertificate,&dwKeyType,&pfCallerFreeProvOrNCryptKey))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptAcquireCertificatePrivateKey 0x%08X", dwError);
				//MessageBox(0,_T("need admin privilege ?"),_T("test"),0);
				__leave;
			}

			// sign certificate
			if(!CryptSignAndEncodeCertificate(
				  hCryptProvRootCertificate,    // Crypto provider
				  AT_SIGNATURE,                 // Key spec
				  X509_ASN_ENCODING,            // Encoding type
				  X509_CERT_TO_BE_SIGNED,      // Struct type
				  &CertInfo,                   // Struct info        
				  &SigAlg,                     // Signature algorithm
				  nullptr,                        // Not used
				  pbSignedEncodedCertReq,      // Pointer
				  &cbEncodedCertReqSize))  // Length of the message
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptSignAndEncodeCertificate 0x%08X", dwError);
				__leave;
			}
			pbSignedEncodedCertReq = (PBYTE) EIDAlloc(cbEncodedCertReqSize);
			if (!pbSignedEncodedCertReq) 
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;
			}
			if(!CryptSignAndEncodeCertificate(
				  hCryptProvRootCertificate,                     // Crypto provider
				  AT_SIGNATURE,                 // Key spec
				  X509_ASN_ENCODING,               // Encoding type
				  X509_CERT_TO_BE_SIGNED, // Struct type
				  &CertInfo,                   // Struct info        
				  &SigAlg,                        // Signature algorithm
				  nullptr,                           // Not used
				  pbSignedEncodedCertReq,         // Pointer
				  &cbEncodedCertReqSize))         // Length of the message
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptSignAndEncodeCertificate 0x%08X", dwError);
				__leave;
			}
			// create context
			//////////////////
			pNewCertificateContext = CertCreateCertificateContext(X509_ASN_ENCODING,pbSignedEncodedCertReq,cbEncodedCertReqSize);
			if (!pNewCertificateContext)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertCreateCertificateContext 0x%08X", dwError);
				__leave;
			}
		}

		// save context property to access the private key later
		// except for smart card (because certificate is associated to the key
		// (container name doesn't contain the real container name but \\.\ReaderName)
		//////////////////////////////////////////////////////
		if (pCertificateInfo->dwSaveon != UI_CERTIFICATE_INFO_SAVEON_SMARTCARD)
		{
			memset(&KeyProvInfo,0, sizeof(KeyProvInfo));
			KeyProvInfo.pwszProvName = szProviderName;
			KeyProvInfo.pwszContainerName = szContainerName;
			KeyProvInfo.dwProvType = PROV_RSA_FULL;
			KeyProvInfo.dwKeySpec = pCertificateInfo->dwKeyType;
			if (pCertificateInfo->dwSaveon == UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE)
			{
				KeyProvInfo.dwFlags = CRYPT_MACHINE_KEYSET;
			}

			CertSetCertificateContextProperty(pNewCertificateContext,CERT_KEY_PROV_INFO_PROP_ID,0,&KeyProvInfo);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"certificate generated");
		// save the certificate
		///////////////////////
		switch (pCertificateInfo->dwSaveon)
		{
		case UI_CERTIFICATE_INFO_SAVEON_USERSTORE: // user store
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_USERSTORE");
			hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_CURRENT_USER,_T("My"));
			if (!hCertStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertOpenStore 0x%08X", dwError);
				__leave;
			}
			if (CertAddCertificateContextToStore(hCertStore,pNewCertificateContext,CERT_STORE_ADD_ALWAYS,nullptr))
			{
				// NOSONAR - EMPTY-01: Intentionally empty - success means continue without action
			}
			else
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertAddCertificateContextToStore 0x%08X", dwError);
				__leave;
			}
			break;
		case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE: // machine store
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE");
			// set security -> admin and system
			// create SYSTEM SID

			if (!AllocateAndInitializeSid(&sia, 1, SECURITY_LOCAL_SYSTEM_RID,0, 0, 0, 0, 0, 0, 0, &pSidSystem))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"AllocateAndInitializeSid 0x%08X", dwError);
				__leave;
			}

			// create Local Administrators alias SID
			if (!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0,0, 0, &pSidAdmins))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"AllocateAndInitializeSid 0x%08X", dwError);
				__leave;
			}
			EXPLICIT_ACCESS ea[2];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
			ZeroMemory(&ea, sizeof(ea));
			// fill an entry for the SYSTEM account
			ea[0].grfAccessMode = GRANT_ACCESS;
			ea[0].grfAccessPermissions = GENERIC_ALL;
			ea[0].grfInheritance = NO_INHERITANCE;
			ea[0].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[0].Trustee.pMultipleTrustee = nullptr;
			ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
			ea[0].Trustee.ptstrName = (LPTSTR)pSidSystem;
			// fill an entry for the Administrators alias
			ea[1].grfAccessMode = GRANT_ACCESS;
			ea[1].grfAccessPermissions = GENERIC_ALL;
			ea[1].grfInheritance = NO_INHERITANCE;
			ea[1].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[1].Trustee.pMultipleTrustee = nullptr;
			ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[1].Trustee.TrusteeType = TRUSTEE_IS_ALIAS;
			ea[1].Trustee.ptstrName = (LPTSTR)pSidAdmins;
			// create a DACL
			dwError = SetEntriesInAcl(2, ea, nullptr, &pDacl);
			if (dwError != ERROR_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SetEntriesInAcl 0x%08X", dwError);
				__leave;
			}
			pSD = (PSECURITY_DESCRIPTOR) EIDAlloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
			if (!pSD)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;
			}
			if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"InitializeSecurityDescriptor 0x%08X", dwError);
				__leave;
			}
			// Add the ACL to the security descriptor.
			if (!SetSecurityDescriptorDacl(pSD,TRUE,pDacl,FALSE))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SetSecurityDescriptorDacl 0x%08X", dwError);
				__leave;
			}
			if (!SetSecurityDescriptorOwner(pSD,pSidAdmins,FALSE))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SetSecurityDescriptorOwner 0x%08X", dwError);
				__leave;
			}
			if (!SetSecurityDescriptorGroup (pSD,pSidAdmins,FALSE))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SetSecurityDescriptorGroup 0x%08X", dwError);
				__leave;
			}
			if(!CryptSetProvParam(hCryptProvNewCertificate,PP_KEYSET_SEC_DESCR,(BYTE*)pSD,DACL_SECURITY_INFORMATION))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptSetProvParam 0x%08X", dwError);
				__leave;
			}
			hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("Root"));
			if (!hCertStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertOpenStore 0x%08X", dwError);
				__leave;
			}
			if (CertAddCertificateContextToStore(hCertStore,pNewCertificateContext,CERT_STORE_ADD_ALWAYS,nullptr))
			{
				// NOSONAR - EMPTY-01: Intentionally empty - success means continue without action
			}
			else
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertAddCertificateContextToStore 0x%08X", dwError);
				__leave;
			}
			break;
		case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE_MY:
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE_MY");
			hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("My"));
			if (!hCertStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertOpenStore 0x%08X", dwError);
				__leave;
			}
			if (CertAddCertificateContextToStore(hCertStore,pNewCertificateContext,CERT_STORE_ADD_ALWAYS,nullptr))
			{
				// NOSONAR - EMPTY-01: Intentionally empty - success means continue without action
			}
			else
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertAddCertificateContextToStore 0x%08X", dwError);
				__leave;
			}
			break;
		case UI_CERTIFICATE_INFO_SAVEON_FILE: // file
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_FILE");
			WizInfo.dwSize = sizeof(CRYPTUI_WIZ_EXPORT_INFO);
			WizInfo.dwSubjectChoice=CRYPTUI_WIZ_EXPORT_CERT_CONTEXT;
			WizInfo.pCertContext=pNewCertificateContext;

			// don't care about return value
//			CryptUIWizExport(0,hMainWnd,_T("Export"),&WizInfo,NULL);
			
			break;
		case UI_CERTIFICATE_INFO_SAVEON_SMARTCARD: // smart card
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_SMARTCARD");
			if (!CryptSetKeyParam(hKey, KP_CERTIFICATE,pNewCertificateContext->pbCertEncoded, 0))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptSetKeyParam 0x%08X", dwError);
				__leave;
			}
			break;
		default:
			break;
		}
		if (pCertificateInfo->fReturnCerticateContext)
		{
			pCertificateInfo->pNewCertificate = CertDuplicateCertificateContext(pNewCertificateContext);
		}
		// don't destroy the container is creation is successful
		if (pCertificateInfo->dwSaveon != UI_CERTIFICATE_INFO_SAVEON_FILE)
			bDestroyContainer = FALSE;
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Success");
		fReturn = TRUE;
	}
	__finally
	{
		if (SubjectKeyIdentifier) EIDFree(SubjectKeyIdentifier);
		if (pbKeyIdentifier) EIDFree(pbKeyIdentifier);
		if (pNewCertificateContext) CertFreeCertificateContext(pNewCertificateContext);
		if (CertInfo.rgExtension) EIDFree(CertInfo.rgExtension);
		if (pbKeyUsage) EIDFree(pbKeyUsage);
		if (pbBasicConstraints) EIDFree(pbBasicConstraints);
		if (pbEnhKeyUsage) EIDFree(pbEnhKeyUsage);
		if (CertEnhKeyUsage.rgpszUsageIdentifier) EIDFree(CertEnhKeyUsage.rgpszUsageIdentifier);
		if (hKey) CryptDestroyKey(hKey);
		if (SubjectIssuerBlob.pbData) EIDFree(SubjectIssuerBlob.pbData);
		if (hCertStore) CertCloseStore(hCertStore,0);
		if (pbSignedEncodedCertReq) EIDFree(pbSignedEncodedCertReq);
		if (pbPublicKeyInfo) EIDFree(pbPublicKeyInfo);
		if (hCryptProvNewCertificate) CryptReleaseContext(hCryptProvNewCertificate,0);
		if (hCryptProvRootCertificate && pfCallerFreeProvOrNCryptKey) 
			CryptReleaseContext(hCryptProvRootCertificate,0);
		if (bDestroyContainer)
		{
			// if a temp container has been created, delete it
			CryptAcquireContext(
				&hCryptProvNewCertificate,
				szContainerName,
				szProviderName,
				PROV_RSA_FULL,
				CRYPT_DELETE_KEYSET);
		}
		
		if (szContainerName) 
		{
			if (pCertificateInfo->dwSaveon == UI_CERTIFICATE_INFO_SAVEON_SMARTCARD)
				EIDFree(szContainerName);
			else
				RpcStringFree((RPC_WSTR*)&szContainerName);
		}
		if (pSidSystem)
			FreeSid(pSidSystem);
		if (pSidAdmins)
			FreeSid(pSidAdmins);
		if (pDacl)
			LocalFree(pDacl);
		if (pSD)
			EIDFree(pSD);
	}
	if (!fReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Leaving with error 0x%08X", dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL ClearCard(PTSTR szReaderName, PTSTR szCardName)
{
	// Delete all key containers from the smart card
	// Note: We must collect all container names first, then delete them in a separate pass.
	// Deleting containers while enumerating corrupts the enumeration state.
	BOOL bStatus = FALSE;
	WCHAR szProviderName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwProviderNameLen = ARRAYSIZE(szProviderName);
	CHAR szContainerName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwContainerNameLen = ARRAYSIZE(szContainerName);
	DWORD dwFlags;
	HCRYPTPROV HMainCryptProv = NULL;  // Windows handle type - keep as NULL
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	LPTSTR szMainContainerName = nullptr;

	// Dynamic array to collect container names before deletion
	constexpr DWORD MAX_CONTAINERS = 100;
	LPWSTR containerNames[MAX_CONTAINERS];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwContainerCount = 0;
	DWORD i;

	// Initialize array
	for (i = 0; i < MAX_CONTAINERS; i++)
	{
		containerNames[i] = nullptr;
	}

	__try
	{
		if (!SchGetProviderNameFromCardName(szCardName, szProviderName, &dwProviderNameLen))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SchGetProviderNameFromCardName 0x%08x",dwError);
			__leave;
		}

		szMainContainerName = BuildContainerNameFromReader(szReaderName);
		if (!szMainContainerName)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"BuildContainerNameFromReader failed");
			__leave;
		}

		bStatus = CryptAcquireContext(&HMainCryptProv,
					szMainContainerName,
					szProviderName,
					PROV_RSA_FULL,
					CRYPT_VERIFYCONTEXT);
		if (!bStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}

		// Phase 1: Enumerate and collect all container names
		dwFlags = CRYPT_FIRST;
		while (CryptGetProvParam(HMainCryptProv,
					PP_ENUMCONTAINERS,
					(LPBYTE) szContainerName,
					&dwContainerNameLen,
					dwFlags)
				)
		{
			if (dwContainerCount >= MAX_CONTAINERS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Too many containers on card (max %d)", MAX_CONTAINERS);
				break;
			}

			// Convert the container name to unicode and store it
			int wLen = MultiByteToWideChar(CP_UTF8, 0, szContainerName, -1, nullptr, 0);
			containerNames[dwContainerCount] = (LPWSTR) EIDAlloc(wLen * sizeof(WCHAR));
			if (!containerNames[dwContainerCount])
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc for container name 0x%08x",dwError);
				__leave;
			}
			MultiByteToWideChar(CP_UTF8, 0, szContainerName, -1, containerNames[dwContainerCount], wLen);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Found container: %s", containerNames[dwContainerCount]);

			dwContainerCount++;
			dwFlags = CRYPT_NEXT;
			dwContainerNameLen = ARRAYSIZE(szContainerName);
		}

		// Release the enumeration context before deleting
		if (HMainCryptProv)
		{
			CryptReleaseContext(HMainCryptProv, 0);
			HMainCryptProv = NULL;
		}

		// Phase 2: Delete all collected containers
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Deleting %d containers from card", dwContainerCount);
		for (i = 0; i < dwContainerCount; i++)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Deleting container %s with provider %s", containerNames[i], szProviderName);

			if (!CryptAcquireContext(&hProv,
					containerNames[i],
					szProviderName,
					PROV_RSA_FULL,
					CRYPT_DELETEKEYSET))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CRYPT_DELETEKEYSET for %s failed: 0x%08x", containerNames[i], dwError);
				// Continue trying to delete other containers even if one fails
			}
		}

		fReturn = TRUE;
	}
	__finally
	{
		// Free all allocated container names
		for (i = 0; i < MAX_CONTAINERS; i++)
		{
			if (containerNames[i])
			{
				EIDFree(containerNames[i]);
				containerNames[i] = nullptr;
			}
		}
		if (szMainContainerName) EIDFree(szMainContainerName);
		if (HMainCryptProv) CryptReleaseContext(HMainCryptProv,0);
	}
	SetLastError(dwError);
	return fReturn;
}

struct RSAPRIVKEY {
	BLOBHEADER blobheader;
	RSAPUBKEY rsapubkey;
#ifdef _DEBUG
	static constexpr DWORD BITLEN_TO_CHECK = 2048;
	BYTE modulus[BITLEN_TO_CHECK/8];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	BYTE prime1[BITLEN_TO_CHECK/16];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	BYTE prime2[BITLEN_TO_CHECK/16];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	BYTE exponent1[BITLEN_TO_CHECK/16];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	BYTE exponent2[BITLEN_TO_CHECK/16];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	BYTE coefficient[BITLEN_TO_CHECK/16];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	BYTE privateExponent[BITLEN_TO_CHECK/8];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
#endif
};
using PRSAPRIVKEY = RSAPRIVKEY*;


BOOL CheckRSAKeyLength(PTSTR szContainerName, PTSTR szProviderName, RSAPRIVKEY* pbData)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL fReturn = FALSE;
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	DWORD dwError = 0;
	DWORD dwFlags = CRYPT_FIRST;
	PROV_ENUMALGS_EX alg;
	DWORD dwSize;
	__try
	{
		if (pbData->blobheader.bType != PRIVATEKEYBLOB)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ERROR_INVALID_PARAMETER");
			__leave;
		}
		if (! CryptAcquireContext(&hProv,szContainerName, szProviderName, PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		dwSize = sizeof(PROV_ENUMALGS_EX);
		while (CryptGetProvParam(hProv,
				PP_ENUMALGS_EX,
				(LPBYTE) &alg,
				&dwSize,
				dwFlags)
			)
		{
			if (alg.aiAlgid == pbData->blobheader.aiKeyAlg)
			{
				if (pbData->rsapubkey.bitlen >= alg.dwMinLen && pbData->rsapubkey.bitlen <= alg.dwMaxLen)
				{
					fReturn = TRUE;
				}
				else
				{
					dwError = (DWORD) NTE_BAD_LEN;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Invalid bitlen should be %d < %d < %d",alg.dwMinLen,pbData->rsapubkey.bitlen, alg.dwMaxLen);
				}
				__leave;
			}
			dwSize = sizeof(PROV_ENUMALGS_EX);
			dwFlags = 0;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"no alg data found");
		fReturn = TRUE;
	}
	__finally
	{
		if (hProv)
			CryptReleaseContext(hProv, 0);
	}
	SetLastError(dwError);
	return fReturn;
}


BOOL ImportFileToSmartCard(PTSTR szFileName, PTSTR szPassword, PTSTR szReaderName, PTSTR szCardname)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
	BOOL fReturn = FALSE;
	CRYPT_DATA_BLOB DataBlob = {0};
	HANDLE hFile = INVALID_HANDLE_VALUE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	HCERTSTORE hCS = nullptr;
	DWORD dwRead = 0;
	TCHAR szProviderName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwProviderNameLen = ARRAYSIZE(szProviderName);
	PWSTR szContainerName = nullptr;
	HCRYPTPROV hCardProv = NULL;
	HCRYPTPROV hProv = NULL;
	PCCERT_CONTEXT pCertContext = nullptr;
	BOOL fFreeProv = FALSE;
	DWORD dwKeySpec = AT_KEYEXCHANGE;
	HCRYPTKEY hKey = NULL;  // Windows handle type - keep as NULL
	HCRYPTKEY hCardKey = NULL;  // Windows handle type - keep as NULL
	PRSAPRIVKEY pbData = nullptr;
	DWORD dwSize = 0;
	DWORD dwError = 0;
	BOOL fSetBackMSBaseSCCryptoFlagImport = FALSE;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Importing %s", szFileName);
		hFile = CreateFile(szFileName,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateFile 0x%08x",dwError);
			__leave;
		}
		LARGE_INTEGER liFileSize = {0};
		if (!GetFileSizeEx(hFile, &liFileSize) || liFileSize.QuadPart == 0)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetFileSizeEx 0x%08x",dwError);
			__leave;
		}
		// A PFX holding one key and its chain is a few KB. Refuse anything
		// implausibly large rather than allocating whatever the file claims.
		if (liFileSize.QuadPart > 1024 * 1024)
		{
			dwError = ERROR_FILE_TOO_LARGE;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"PFX file too large (%lld bytes)",liFileSize.QuadPart);
			__leave;
		}
		DataBlob.cbData = static_cast<DWORD>(liFileSize.QuadPart);
		DataBlob.pbData = (PBYTE) EIDAlloc(DataBlob.cbData);
		if (!DataBlob.pbData)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
			__leave;
		}
		if (!ReadFile(hFile, DataBlob.pbData, DataBlob.cbData, &dwRead, nullptr))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ReadFile 0x%08x",dwError);
			__leave;
		}
		hCS = PFXImportCertStore(&DataBlob, szPassword, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET );
		if(!hCS)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"PFXImportCertStore 0x%08x",dwError);
			__leave;
		}
		// provider name
		if (!SchGetProviderNameFromCardName(szCardname, szProviderName, &dwProviderNameLen))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SchGetProviderNameFromCardName 0x%08x",dwError);
			__leave;
		}
		// container name from card name
		szContainerName = BuildContainerNameFromReader(szReaderName);
		if (!szContainerName)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"BuildContainerNameFromReader failed");
			__leave;
		}
		pCertContext = CertEnumCertificatesInStore(hCS, nullptr);
		while( pCertContext )
		{
			dwSize = 0;
			// this check allows to find which certificate has a private key
			if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID, nullptr, &dwSize))
			{	
				if (! CryptAcquireCertificatePrivateKey(pCertContext, 0, nullptr, &hProv, &dwKeySpec, &fFreeProv))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireCertificatePrivateKey 0x%08x",dwError);
					__leave;
				}
				if (_tcscmp(szProviderName,MS_SCARD_PROV) == 0)
				{
					// check if MS Base crypto allow the import. If not, enable it
					HKEY hRegKey;
					DWORD dwKeyData = 0;
					DWORD dwKeyDataType = 0;
					LSTATUS lQueryStatus;
					dwSize = sizeof(DWORD);
					if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Base Smart Card Crypto Provider"),NULL, KEY_READ|KEY_QUERY_VALUE|KEY_WRITE, &hRegKey))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
					{
						if (dwKeySpec == AT_SIGNATURE)
						{
							lQueryStatus = RegQueryValueEx(hRegKey,TEXT("AllowPrivateSignatureKeyImport"),nullptr, &dwKeyDataType,(PBYTE)&dwKeyData,&dwSize);
						}
						else
						{
							lQueryStatus = RegQueryValueEx(hRegKey,TEXT("AllowPrivateExchangeKeyImport"),nullptr, &dwKeyDataType,(PBYTE)&dwKeyData,&dwSize);
						}
						// A missing, unreadable or non-DWORD value means import is
						// not enabled (the provider's default).
						if (lQueryStatus != ERROR_SUCCESS || dwKeyDataType != REG_DWORD || dwSize != sizeof(DWORD))
						{
							dwKeyData = 0;
						}
						if (!dwKeyData)
						{
							fSetBackMSBaseSCCryptoFlagImport = TRUE;
							dwKeyData = 1;
							dwSize = sizeof(DWORD);
							if (dwKeySpec == AT_SIGNATURE)
							{
								RegSetValueEx(hRegKey,TEXT("AllowPrivateSignatureKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
							}
							else
							{
								RegSetValueEx(hRegKey,TEXT("AllowPrivateExchangeKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
							}
						}
						RegCloseKey(hRegKey);
					}

				}
				if (!CryptGetUserKey(hProv, dwKeySpec, &hKey))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetUserKey 0x%08x",dwError);
					__leave;
				}
				dwSize = 0;
				if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, nullptr, &dwSize))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptExportKey 0x%08x",dwError);
					__leave;
				}
				pbData = (PRSAPRIVKEY) EIDAlloc(dwSize);
				if (!pbData)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
					__leave;
				}
				memset(pbData, 0, dwSize);
				if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, (PBYTE) pbData, &dwSize))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptExportKey 0x%08x",dwError);
					__leave;
				}
				// check key length
				if (!CheckRSAKeyLength(szContainerName, szProviderName, pbData))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CheckRSAKeyLength 0x%08x",dwError);
					__leave;
				}
				if (! CryptAcquireContext(&hCardProv,szContainerName, szProviderName, PROV_RSA_FULL,CRYPT_NEWKEYSET))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
					__leave;
				}
				if (!CryptImportKey(hCardProv, (PBYTE) pbData, dwSize, NULL, 0, &hCardKey))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",dwError);
					__leave;
				}
				if (!CryptSetKeyParam(hCardKey, KP_CERTIFICATE, pCertContext->pbCertEncoded, 0))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptSetKeyParam 0x%08x",dwError);
					__leave;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OK");
				fReturn = TRUE;
				__leave;
			}
			pCertContext = CertEnumCertificatesInStore(hCS, pCertContext);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"not found");
	}
	__finally
	{
		if (hCardKey)
			CryptDestroyKey(hCardKey);
		if (pbData)
			EIDFree(pbData);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv && fFreeProv)
			CryptReleaseContext(hProv, 0);
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
		if (hCardProv)
			CryptReleaseContext(hCardProv, 0);
		if (szContainerName) 
			EIDFree(szContainerName);			
		if (hCS)
			CertCloseStore(hCS, 0);
		if (DataBlob.pbData)
			EIDFree(DataBlob.pbData);
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);
		if (fSetBackMSBaseSCCryptoFlagImport)
		{
			HKEY hRegKey;
			DWORD dwKeyData = 0;
			dwSize = sizeof(DWORD);
			if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Base Smart Card Crypto Provider"),0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE, &hRegKey))
			{
				if (dwKeySpec == AT_SIGNATURE)
				{
									RegSetValueEx(hRegKey,TEXT("AllowPrivateSignatureKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
				}
				else
				{
									RegSetValueEx(hRegKey,TEXT("AllowPrivateExchangeKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
				}
				RegCloseKey(hRegKey);
			}
		}
	}
	SetLastError(dwError);
	return fReturn;
}

// find certificate using its hash

PCCERT_CONTEXT FindCertificateFromHashOnCard(PCRYPT_DATA_BLOB pCertInfo, PTSTR szReaderName, PTSTR szProviderName)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
	PCCERT_CONTEXT pCertContext = nullptr;
	HCRYPTPROV HCryptProv = NULL;  // Windows handle type - keep as NULL
	HCRYPTPROV hProv = NULL;  // Windows handle type - keep as NULL
	TCHAR szMainContainerName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwContainerNameLen = ARRAYSIZE(szMainContainerName);
	CHAR szContainerName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwError = 0;
	DWORD pKeySpecs[2] = {AT_KEYEXCHANGE,AT_SIGNATURE};  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	HCRYPTKEY hKey = NULL;  // Windows handle type - keep as NULL
	__try
	{
		if (!pCertInfo)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCertInfo null");
			__leave;
		}
		_stprintf_s(szMainContainerName, dwContainerNameLen, TEXT("\\\\.\\%s\\"), szReaderName);
		if (!CryptAcquireContext(&HCryptProv,
					szMainContainerName,
					szProviderName,
					PROV_RSA_FULL,
					CRYPT_SILENT))
		{
			// for the spanish EID
			if (!CryptAcquireContext(&HCryptProv,  // NOSONAR - COMPLEXITY-01: crypto fallback kept as nested if
					nullptr,
					szProviderName,
					PROV_RSA_FULL,
					CRYPT_SILENT))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
				__leave;
			}
		}
		DWORD dwFlags = CRYPT_FIRST;
		/* Enumerate all the containers */
		while (CryptGetProvParam(HCryptProv,
					PP_ENUMCONTAINERS,
					(LPBYTE) szContainerName,
					&dwContainerNameLen,
					dwFlags)
				)
		{
			// convert the container name to unicode
	#ifdef UNICODE
			int wLen = MultiByteToWideChar(CP_UTF8, 0, szContainerName, -1, nullptr, 0);
			LPTSTR szWideContainerName = (LPTSTR) EIDAlloc(sizeof(TCHAR)*wLen);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
			if (szWideContainerName)
			{
				MultiByteToWideChar(CP_UTF8, 0, szContainerName, -1, szWideContainerName, wLen);
	#else
			LPTSTR szWideContainerName = (LPTSTR) EIDAlloc(sizeof(TCHAR)*(_tcslen(szContainerName)+1));
			if (szWideContainerName)
				{
				_tcscpy_s(szWideContainerName,_tcslen(szContainerName)+1,szContainerName);

	#endif
				// create a CContainer item
				if (CryptAcquireContext(&hProv,
					szWideContainerName,
					szProviderName,
					PROV_RSA_FULL,
					CRYPT_SILENT))
				{
					for (DWORD i = 0; i < ARRAYSIZE(pKeySpecs); i++)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
					{
						if (CryptGetUserKey(hProv,
								pKeySpecs[i],
								&hKey) )
						{
							BYTE Data[4096];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
							DWORD DataSize = 4096;
							if (CryptGetKeyParam(hKey,
									KP_CERTIFICATE,
									Data,
									&DataSize,
									0))
							{
								BYTE pbHash[100];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
								DWORD dwHashSize = ARRAYSIZE(pbHash);
								PCCERT_CONTEXT pTempContext = CertCreateCertificateContext(X509_ASN_ENCODING ,Data,DataSize);
								if (CryptHashCertificate(NULL, 0, 0, Data, DataSize, (PBYTE) &pbHash, &dwHashSize))
								{
									if (memcmp(pbHash, pCertInfo->pbData, pCertInfo->cbData) == 0)
									{
										// found
										pCertContext = pTempContext;
										CRYPT_KEY_PROV_INFO KeyProvInfo;
										KeyProvInfo.dwFlags = 0;
										KeyProvInfo.dwKeySpec = pKeySpecs[i];
										KeyProvInfo.dwProvType = PROV_RSA_FULL;
										KeyProvInfo.pwszContainerName = szWideContainerName;
										KeyProvInfo.pwszProvName = (LPTSTR) szProviderName;
										KeyProvInfo.rgProvParam = nullptr;
										KeyProvInfo.cProvParam = 0;
										CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &KeyProvInfo);
										__leave;
									}
								}
								else
								{
									dwError = GetLastError();
									EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptHashPublicKeyInfo 0x%08x",dwError);
								}
							}
						CryptDestroyKey(hKey);
						hKey = NULL;
						}
					}
				}
				CryptReleaseContext(hProv, 0);
				hProv = NULL;
			}
			dwFlags = CRYPT_NEXT;
			dwContainerNameLen = 1024;
			EIDFree(szWideContainerName);
		}
	
	}
	__finally
	{
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
			CryptReleaseContext(hProv,0);
		if (HCryptProv)
			CryptReleaseContext(HCryptProv,0);
	}
	SetLastError(dwError);
	return pCertContext;
}

PCCERT_CONTEXT FindCertificateFromHashInReader(PCRYPT_DATA_BLOB pCertInfo, SCARDCONTEXT hSCardContext, PTSTR szReader)
{
	PCCERT_CONTEXT pCertContext = nullptr;
	LONG Status = 0;
	SCARDHANDLE hCard = NULL;  // Windows handle type - keep as NULL
	DWORD dwProto;
	DWORD dwState;
	LPTSTR szReaders = nullptr;
	DWORD dwSize = SCARD_AUTOALLOCATE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	PBYTE pbAtr = nullptr;
	DWORD dwAtrSize = SCARD_AUTOALLOCATE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	LPTSTR szCards = nullptr;
	DWORD dwCardSize = SCARD_AUTOALLOCATE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	LPTSTR szProvider = nullptr;
	DWORD dwProviderSize = SCARD_AUTOALLOCATE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	__try
	{
		Status = SCardConnect(hSCardContext, szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &hCard, &dwProto);
		if (Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardConnect 0x%08x",Status);
			__leave;
		}
		Status = SCardStatus(hCard, (PTSTR) &szReaders, &dwSize, &dwState, &dwProto, (PBYTE)&pbAtr, &dwAtrSize);
		if (Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardStatus 0x%08x",Status);
			__leave;
		}
		Status = SCardListCards(hSCardContext, pbAtr, nullptr, 0, (PTSTR)&szCards, &dwCardSize);
		if (Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardListCards 0x%08x",Status);
			__leave;
		}
		Status = SCardGetCardTypeProviderName(hSCardContext, szCards, SCARD_PROVIDER_CSP, (PTSTR)&szProvider, &dwProviderSize);
		if (Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardListCards 0x%08x",Status);
			__leave;
		}
		SCardDisconnect(hCard, 0);
		hCard = NULL;
		pCertContext = FindCertificateFromHashOnCard(pCertInfo, szReaders, szProvider);
	}
	__finally
	{
		if (szProvider)
			SCardFreeMemory(hSCardContext, szProvider);
		if (szCards)
			SCardFreeMemory(hSCardContext, szCards);
		if (szReaders)
			SCardFreeMemory(hSCardContext, szReaders);
		if (pbAtr)
			SCardFreeMemory(hSCardContext, pbAtr);
		if (hCard)
			SCardDisconnect(hCard, 0);
	}
	SetLastError(Status);
	return pCertContext;
}

PCCERT_CONTEXT FindCertificateFromHash(PCRYPT_DATA_BLOB pCertInfo)
{
	PCCERT_CONTEXT pCertContext = nullptr;
	HCERTSTORE hCertStore = nullptr;
	DWORD dwError = 0;
	LONG Status;
	SCARDCONTEXT hSCardContext = NULL;  // Windows handle type - keep as NULL
	DWORD dwReaderCount;
	LPTSTR szReaders = nullptr;
	__try
	{
			// first, try to look into user certificate store
			hCertStore = CertOpenSystemStore(NULL, TEXT("MY"));
		if (!hCertStore)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetUserKey 0x%08x",dwError);
			__leave;
		}
		pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_HASH, (PVOID) pCertInfo, nullptr);
		if (pCertContext)
		{
			// OK, found
			__leave;
		}
		// else, look in every smart card
		Status = SCardEstablishContext(SCARD_SCOPE_USER,nullptr,nullptr,&hSCardContext);
		if (Status != SCARD_S_SUCCESS)
		{
			dwError = Status;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08x",dwError);
			__leave;
		}
		dwReaderCount = SCARD_AUTOALLOCATE;
		Status = SCardListReaders(hSCardContext, nullptr, (LPTSTR)&szReaders, &dwReaderCount);
		if (Status == SCARD_E_NO_READERS_AVAILABLE)
		{
			dwError = Status;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext SCARD_E_NO_READERS_AVAILABLE");
			__leave;
		}
		if (Status != SCARD_S_SUCCESS)
		{
			dwError = Status;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08x",dwError);
			__leave;
		}
		LPTSTR szRdr = szReaders;
		while ( 0 != *szRdr ) 
		{
			pCertContext = FindCertificateFromHashInReader(pCertInfo, hSCardContext, szRdr);
			if (pCertContext)
			{
				// OK, found
				__leave;
			}
			szRdr += lstrlen(szRdr) + 1;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not Found");
	}
	__finally
	{
		if (szReaders)
			SCardFreeMemory(hSCardContext, szReaders);
		if (hSCardContext)
			SCardReleaseContext(hSCardContext);
		if (hCertStore)
			CertCloseStore(hCertStore, 0);
	}
	SetLastError(dwError);
	return pCertContext;
}

//////////////////////////////////////////////////////////////////////////////
// Uninstall certificate cleanup
//////////////////////////////////////////////////////////////////////////////

namespace
{
	struct EID_CERT_CLEANUP_STATS
	{
		DWORD dwCertsRemoved;
		DWORD dwKeysDeleted;
		DWORD dwProfilesSwept;
		DWORD dwErrors;
	};

	constexpr std::array<LPCWSTR, 4> EID_SWEEP_STORE_NAMES = { L"Root", L"CA", L"TrustedPeople", L"My" };

	BOOL HasEIDPrefix(LPCWSTR szName)
	{
		return szName != nullptr && _wcsnicmp(szName, L"EID:", 4) == 0;
	}

	// TRUE if the certificate was created by this product. *pfSubjectMatch is set when
	// the SUBJECT carries the EID: prefix (i.e. the certificate IS the EID root CA).
	BOOL IsEIDOwnedCertificate(PCCERT_CONTEXT pCertContext, PBOOL pfSubjectMatch)
	{
		WCHAR szName[512] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		*pfSubjectMatch = FALSE;
		if (CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, szName, ARRAYSIZE(szName)) > 1
			&& HasEIDPrefix(szName))
		{
			*pfSubjectMatch = TRUE;
			return TRUE;
		}
		if (CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, szName, ARRAYSIZE(szName)) > 1
			&& HasEIDPrefix(szName))
		{
			return TRUE;
		}
		return FALSE;
	}

	// TRUE when the key container really belongs to this certificate: opens the container
	// READ-ONLY, exports its public key and compares it against the certificate's own
	// SubjectPublicKeyInfo. Without this, the container name - which is just an attribute
	// stored alongside the certificate - would be taken on trust.
	BOOL ContainerKeyMatchesCertificate(PCCERT_CONTEXT pCertContext, const CRYPT_KEY_PROV_INFO* pInfo)
	{
		HCRYPTPROV hProv = NULL;
		if (!CryptAcquireContextW(&hProv, pInfo->pwszContainerName, pInfo->pwszProvName,
			pInfo->dwProvType, CRYPT_MACHINE_KEYSET))
		{
			return FALSE; // container absent or not ours to read - never proceed to delete
		}
		BOOL fMatch = FALSE;
		if (DWORD cbPublicKey = 0; CryptExportPublicKeyInfo(hProv, pInfo->dwKeySpec, X509_ASN_ENCODING, nullptr, &cbPublicKey))
		{
			auto pPublicKey = static_cast<PCERT_PUBLIC_KEY_INFO>(EIDAlloc(cbPublicKey));
			if (pPublicKey)
			{
				if (CryptExportPublicKeyInfo(hProv, pInfo->dwKeySpec, X509_ASN_ENCODING, pPublicKey, &cbPublicKey))
				{
					fMatch = CertComparePublicKeyInfo(X509_ASN_ENCODING,
						pPublicKey, &pCertContext->pCertInfo->SubjectPublicKeyInfo);
				}
				EIDFree(pPublicKey);
			}
		}
		CryptReleaseContext(hProv, 0);
		return fMatch;
	}

	// Deletes the private key container of the EID root CA.
	//
	// SECURITY: every input here except the store location is attacker-influenced.
	// CRYPT_KEY_PROV_INFO is a persisted certificate property, so anyone who can write a
	// certificate into a swept store also chooses the container name, provider and flags -
	// including CRYPT_MACHINE_KEYSET. That flag is therefore a lure, NOT a safety rail:
	// it cannot authorise anything. Two checks that attacker-supplied data cannot forge
	// gate the deletion instead:
	//   1. the caller must have found the certificate in a LocalMachine store, which only
	//      an administrator can write to (fMachineStore, threaded down from the sweep); and
	//   2. the container's public key must match the certificate's own public key.
	// A legitimate EID CA satisfies both: MakeTrustedCertifcate only sets
	// CRYPT_MACHINE_KEYSET for UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE, which writes to
	// LocalMachine Root. Smart-card containers remain unreachable - they never carry
	// CRYPT_MACHINE_KEYSET and never live in a machine store.
	void DeleteMachineKeyContainer(PCCERT_CONTEXT pCertContext, EID_CERT_CLEANUP_STATS* pStats)
	{
		DWORD dwSize = 0;
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &dwSize))
		{
			return; // no private key recorded - nothing to delete
		}
		auto pInfo = static_cast<PCRYPT_KEY_PROV_INFO>(EIDAlloc(dwSize));
		if (!pInfo)
		{
			pStats->dwErrors++;
			return;
		}
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pInfo, &dwSize))
		{
			pStats->dwErrors++;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"RemoveAllEIDCertificates: key prov info unreadable (0x%08x)", GetLastError());
			EIDFree(pInfo);
			return;
		}
		if ((pInfo->dwFlags & CRYPT_MACHINE_KEYSET) && ContainerKeyMatchesCertificate(pCertContext, pInfo))
		{
			HCRYPTPROV hProv = NULL;
			if (CryptAcquireContextW(&hProv, pInfo->pwszContainerName, pInfo->pwszProvName,
				pInfo->dwProvType, CRYPT_DELETEKEYSET | CRYPT_MACHINE_KEYSET))
			{
				// CRYPT_DELETEKEYSET returns no handle to release
				pStats->dwKeysDeleted++;
				EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"RemoveAllEIDCertificates: deleted CA key container %s", pInfo->pwszContainerName);
			}
			else if (GetLastError() == NTE_BAD_KEYSET)
			{
				// already deleted via another copy of the same CA certificate - expected
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"RemoveAllEIDCertificates: key container %s already gone", pInfo->pwszContainerName);
			}
			else
			{
				pStats->dwErrors++;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"RemoveAllEIDCertificates: CryptAcquireContext(DELETEKEYSET) failed 0x%08x", GetLastError());
			}
		}
		EIDFree(pInfo);
	}

	// Removes every EID-owned certificate from an open store. Restarts enumeration after
	// each deletion (CertDeleteCertificateFromStore frees the context, which would
	// invalidate the enumerator). Store sizes are tiny, so O(n^2) is irrelevant.
	// fMachineStore must be TRUE only for LocalMachine stores - it authorises private key
	// destruction, so a per-user store must never set it (see DeleteMachineKeyContainer).
	void CleanOpenStore(HCERTSTORE hStore, LPCWSTR szLabel, BOOL fMachineStore, EID_CERT_CLEANUP_STATS* pStats)
	{
		BOOL fDeletedOne = TRUE;
		while (fDeletedOne)
		{
			fDeletedOne = FALSE;
			PCCERT_CONTEXT pCert = nullptr;
			while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != nullptr)
			{
				BOOL fSubjectMatch = FALSE;
				if (!IsEIDOwnedCertificate(pCert, &fSubjectMatch))
				{
					continue;
				}
				if (fSubjectMatch && fMachineStore)
				{
					DeleteMachineKeyContainer(pCert, pStats);
				}
				// CertDeleteCertificateFromStore always frees pCert (success or failure)
				if (CertDeleteCertificateFromStore(pCert))
				{
					pStats->dwCertsRemoved++;
					fDeletedOne = TRUE;
				}
				else
				{
					pStats->dwErrors++;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"RemoveAllEIDCertificates: delete failed in %s (0x%08x)", szLabel, GetLastError());
					// leave fDeletedOne FALSE: abandon this store instead of looping on a stuck certificate
				}
				break; // restart enumeration from scratch after any deletion attempt
			}
		}
	}

	// CertEnumSystemStore callback for CERT_SYSTEM_STORE_USERS: store names arrive as
	// "<SID>\<StoreName>" for every loaded profile hive.
	BOOL WINAPI CleanUserSystemStoreCallback(const void* pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void* pvReserved, void* pvArg)  // NOSONAR - API-01: signature dictated by Windows/callback API
	{
		UNREFERENCED_PARAMETER(dwFlags);
		UNREFERENCED_PARAMETER(pStoreInfo);
		UNREFERENCED_PARAMETER(pvReserved);
		auto pStats = static_cast<EID_CERT_CLEANUP_STATS*>(pvArg);
		auto szStore = static_cast<LPCWSTR>(pvSystemStore);
		LPCWSTR szBackslash = wcsrchr(szStore, L'\\');
		if (!szBackslash)
		{
			return TRUE;
		}
		LPCWSTR szName = szBackslash + 1;
		BOOL fWanted = FALSE;
		for (LPCWSTR szWanted : EID_SWEEP_STORE_NAMES)
		{
			if (_wcsicmp(szName, szWanted) == 0)
			{
				fWanted = TRUE;
				break;
			}
		}
		if (fWanted)
		{
			HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, NULL,  // NOSONAR - Windows API requires NULL
				CERT_SYSTEM_STORE_USERS | CERT_STORE_OPEN_EXISTING_FLAG, szStore);
			if (hStore)
			{
				// FALSE: a user store must never authorise private key destruction
				CleanOpenStore(hStore, szStore, FALSE, pStats);
				CertCloseStore(hStore, 0);
			}
		}
		return TRUE; // always continue enumeration
	}

	BOOL EnablePrivilege(LPCWSTR szPrivilege)
	{
		HANDLE hToken = nullptr;
		TOKEN_PRIVILEGES tp = {0};
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			return FALSE;
		}
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		BOOL fOk = LookupPrivilegeValueW(nullptr, szPrivilege, &tp.Privileges[0].Luid)
			&& AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr)
			&& GetLastError() == ERROR_SUCCESS;
		DWORD dwError = GetLastError();  // capture before CloseHandle can overwrite it
		CloseHandle(hToken);
		SetLastError(dwError);
		return fOk;
	}

	// Opens a certificate store rooted at an arbitrary registry key (used on mounted
	// NTUSER.DAT hives) and cleans it. CERT_STORE_PROV_REG persists deletions to the key.
	void CleanRegistryStore(HKEY hHiveRoot, LPCWSTR szStoreName, EID_CERT_CLEANUP_STATS* pStats)
	{
		WCHAR szSubKey[MAX_PATH] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		swprintf_s(szSubKey, ARRAYSIZE(szSubKey), L"SOFTWARE\\Microsoft\\SystemCertificates\\%s", szStoreName);
		HKEY hKey = nullptr;
		if (RegOpenKeyExW(hHiveRoot, szSubKey, 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
		{
			return; // store never created for this profile - nothing to clean
		}
		if (HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_REG, 0, NULL, 0, hKey))  // NOSONAR - Windows API requires NULL
		{
			// FALSE: a mounted user hive must never authorise private key destruction
			CleanOpenStore(hStore, szStoreName, FALSE, pStats);
			CertCloseStore(hStore, 0);
		}
		RegCloseKey(hKey);
	}

	constexpr LPCWSTR EID_CLEANUP_MOUNT_POINT = L"EID_CertCleanup_Tmp";

	// Mounts one profile's NTUSER.DAT and cleans its certificate stores. The hive is
	// always unmounted, including when it cannot be opened after a successful load.
	void SweepOneProfile(HKEY hProfileList, LPCWSTR szSid, EID_CERT_CLEANUP_STATS* pStats)
	{
		WCHAR szHivePath[MAX_PATH] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		// RRF_RT_REG_SZ alone: RegGetValue auto-expands REG_EXPAND_SZ and returns it
		// as REG_SZ (adding RRF_RT_REG_EXPAND_SZ without RRF_NOEXPAND is an error)
		if (DWORD cbPath = sizeof(szHivePath); RegGetValueW(hProfileList, szSid, L"ProfileImagePath", RRF_RT_REG_SZ,
			nullptr, szHivePath, &cbPath) != ERROR_SUCCESS)
		{
			return;
		}
		if (FAILED(StringCchCatW(szHivePath, ARRAYSIZE(szHivePath), L"\\NTUSER.DAT")))
		{
			return;
		}
		if (LSTATUS lLoad = RegLoadKeyW(HKEY_USERS, EID_CLEANUP_MOUNT_POINT, szHivePath); lLoad != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"RemoveAllEIDCertificates: RegLoadKey failed for %s (0x%08x) - profile skipped", szSid, lLoad);
			pStats->dwErrors++;
			return;
		}
		HKEY hHive = nullptr;
		if (LSTATUS lOpen = RegOpenKeyExW(HKEY_USERS, EID_CLEANUP_MOUNT_POINT, 0, KEY_READ | KEY_WRITE, &hHive); lOpen == ERROR_SUCCESS)
		{
			for (LPCWSTR szStoreName : EID_SWEEP_STORE_NAMES)
			{
				CleanRegistryStore(hHive, szStoreName, pStats);
			}
			RegCloseKey(hHive);
			pStats->dwProfilesSwept++;
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"RemoveAllEIDCertificates: mounted hive unreadable for %s (0x%08x)", szSid, lOpen);
			pStats->dwErrors++;
		}
		if (LSTATUS lUnload = RegUnLoadKeyW(HKEY_USERS, EID_CLEANUP_MOUNT_POINT); lUnload != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"RemoveAllEIDCertificates: RegUnLoadKey failed for %s (0x%08x)", szSid, lUnload);
			pStats->dwErrors++;
		}
	}

	// Mounts each not-currently-loaded user profile hive (ProfileList enumeration,
	// S-1-5-21-* accounts only) and cleans its certificate stores. Loaded hives are
	// covered separately by CertEnumSystemStore(CERT_SYSTEM_STORE_USERS).
	void SweepUnloadedProfiles(EID_CERT_CLEANUP_STATS* pStats)
	{
		if (!EnablePrivilege(SE_BACKUP_NAME) || !EnablePrivilege(SE_RESTORE_NAME))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"RemoveAllEIDCertificates: backup/restore privilege unavailable (0x%08x) - unloaded profiles skipped", GetLastError());
			pStats->dwErrors++;
			return;
		}
		HKEY hProfileList = nullptr;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
			0, KEY_READ, &hProfileList) != ERROR_SUCCESS)
		{
			pStats->dwErrors++;
			return;
		}
		for (DWORD dwIndex = 0; ; dwIndex++)
		{
			WCHAR szSid[256] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
			if (DWORD dwSidLen = ARRAYSIZE(szSid); RegEnumKeyExW(hProfileList, dwIndex, szSid, &dwSidLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
			{
				break;
			}
			if (_wcsnicmp(szSid, L"S-1-5-21-", 9) != 0)
			{
				continue; // only real local/domain accounts
			}
			if (HKEY hLoaded = nullptr; RegOpenKeyExW(HKEY_USERS, szSid, 0, KEY_READ, &hLoaded) == ERROR_SUCCESS)
			{
				RegCloseKey(hLoaded);
				continue; // hive loaded - already swept via CertEnumSystemStore
			}
			SweepOneProfile(hProfileList, szSid, pStats);
		}
		RegCloseKey(hProfileList);
	}
}

HRESULT RemoveAllEIDCertificates(VOID)
{
	EID_CERT_CLEANUP_STATS stats = {0};
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"RemoveAllEIDCertificates: starting certificate cleanup");

	// 1. LocalMachine stores - everything MakeTrustedCertifcate and the wizard write to.
	// Only these are admin-writable, so only these authorise CA key deletion (TRUE).
	for (LPCWSTR szStoreName : EID_SWEEP_STORE_NAMES)
	{
		HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, NULL,  // NOSONAR - Windows API requires NULL
			CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, szStoreName);
		if (hStore)
		{
			CleanOpenStore(hStore, szStoreName, TRUE, &stats);
			CertCloseStore(hStore, 0);
		}
	}

	// 2. Loaded user profiles (logged-on users, .DEFAULT)
	if (!CertEnumSystemStore(CERT_SYSTEM_STORE_USERS, nullptr, &stats, CleanUserSystemStoreCallback))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"RemoveAllEIDCertificates: CertEnumSystemStore failed 0x%08x", GetLastError());
		stats.dwErrors++;
	}

	// 3. Unloaded user profiles (users not logged on during uninstall - the common case)
	SweepUnloadedProfiles(&stats);

	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,
		L"RemoveAllEIDCertificates: removed %u certificates, deleted %u key containers, swept %u offline profiles, %u errors",
		stats.dwCertsRemoved, stats.dwKeysDeleted, stats.dwProfilesSwept, stats.dwErrors);
	return S_OK; // partial skips never fail the uninstall
}
