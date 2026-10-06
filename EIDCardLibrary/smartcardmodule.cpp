#include <ntstatus.h>
#define WIN32_NO_STATUS 1  // NOSONAR - MACRO-02: Windows SDK configuration, prevents ntstatus.h conflicts
#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#pragma warning(push)
#pragma warning(disable : 4201)
#include <winscard.h>
#pragma warning(pop)

// cardmod.h is available in the repository's include directory
#include "../include/cardmod.h"
#include "Tracing.h"
#include "EIDCardLibrary.h"
#include "InputValidation.h"
#include "CSVConfig.h"
#include "CSVLogger.h"

//
// Security: Safe DLL loading helper to prevent DLL hijacking attacks
// Uses LOAD_LIBRARY_SEARCH_SYSTEM32 when loading from System32,
// or validates the full path before loading
//
static HMODULE SafeLoadLibrary(__in LPCWSTR wszModulePath)
{
    if (wszModulePath == nullptr || wszModulePath[0] == L'\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }

    // SECURITY: wszModulePath is the card MODULE NAME returned by
    // SCardGetCardTypeProviderName for a card name the CLIENT supplied in its
    // logon buffer, and this function runs inside LSASS - while impersonating
    // that client, so the smart-card resource manager resolves the lookup under
    // the attacker's identity and can answer from their own HKCU Calais store.
    // Whatever comes back is about to be executed as DllMain in lsass.exe.
    //
    // The previous implementation classified anything without a drive letter or
    // leading \\ as "relative" and pasted it onto System32. "..\..\Users\Public\
    // evil.dll" therefore normalised straight back out of System32 into a
    // user-writable directory - an arbitrary DLL load into LSASS - while the
    // trace below cheerfully reported it as "from System32".
    //
    // EIDLoadSystemLibrary (Package.cpp) has always rejected separators for
    // exactly this reason. Two loaders, one hardened; this brings them into
    // line. A card module name is a bare filename - it is never a path.
    if (wcschr(wszModulePath, L'\\') != nullptr ||
        wcschr(wszModulePath, L'/')  != nullptr ||
        wcschr(wszModulePath, L':')  != nullptr)
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,
            L"SafeLoadLibrary: rejecting card module name containing a path separator: '%s'", wszModulePath);
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }

    WCHAR wszSystem32Path[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    const UINT uLen = GetSystemDirectoryW(wszSystem32Path, ARRAYSIZE(wszSystem32Path));
    if (uLen == 0 || uLen >= ARRAYSIZE(wszSystem32Path))
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return nullptr;
    }

    WCHAR wszFullPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    if (FAILED(StringCchPrintfW(wszFullPath, ARRAYSIZE(wszFullPath), L"%s\\%s", wszSystem32Path, wszModulePath)))
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return nullptr;
    }

    // LOAD_LIBRARY_SEARCH_SYSTEM32 rather than LOAD_WITH_ALTERED_SEARCH_PATH:
    // dependencies of the minidriver must resolve from System32 too, not from
    // whatever directory the module itself was found in. Also avoids mutating
    // process-global loader state (the old SetDllDirectoryW(L"") call changed
    // it for all of lsass.exe and never restored it).
    EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"SafeLoadLibrary: Loading '%s' from System32", wszModulePath);
    return LoadLibraryExW(wszFullPath, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
}

// Non-const string buffer for card module API compatibility (cardmod.h functions require LPWSTR)
static WCHAR s_wszCardUserUser[] = L"user";                           // NOSONAR - GLOBAL-01: Runtime-initialized LSA state

//
// Internal context structure for interfacing with a card module
//

struct MGSC_CONTEXT
{
    //
    // Internal context
    //

    PVOID                           pvContext;

};
using PMGSC_CONTEXT = MGSC_CONTEXT*;


struct INTERNAL_CONTEXT
{
    HMODULE hModule;
    CARD_DATA CardData;

};
using PINTERNAL_CONTEXT = INTERNAL_CONTEXT*;

//
// Macros for error checking and flow control
//

#define CHECK_DWORD(_X) {                                                   \
    if (ERROR_SUCCESS != (status = (_X))) {                                 \
        EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,TEXT("%s"), TEXT(#_X));  \
        __leave;                                                            \
    }                                                                       \
}

#define CHECK_BOOL(_X) {                                                    \
    if (FALSE == (_X)) {                                                    \
        status = GetLastError();                                            \
        EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,TEXT("%s"), TEXT(#_X));  \
        __leave;                                                            \
    }                                                                       \
}

#define CHECK_ALLOC(_X) {                                                   \
    if (nullptr == (_X)) {                                                     \
        status = ERROR_NOT_ENOUGH_MEMORY;                                   \
        __leave;                                                            \
    }                                                                       \
}

extern "C" {

//
// Heap helpers
//

LPVOID 
WINAPI
_Alloc(
    __in        SIZE_T cBytes)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cBytes);
}

LPVOID 
WINAPI 
_ReAlloc(
    __in        LPVOID pvMem,
    __in        SIZE_T cBytes)
{
    return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pvMem, cBytes);
}

void
WINAPI
_Free(
    __in        LPVOID pvMem)
{
    HeapFree(GetProcessHeap(), 0, pvMem);
}

//
// Dummy data caching stubs to satisfy the card module callback requirements
//

DWORD 
WINAPI 
_CacheAddFileStub(
    IN      PVOID       pvCacheContext,
    IN      LPWSTR      wszTag,  // NOSONAR - API-01: signature dictated by Windows/callback API
    IN      DWORD       dwFlags,
    IN      PBYTE       pbData,  // NOSONAR - API-01: signature dictated by Windows/callback API
    IN      DWORD       cbData)
{
    UNREFERENCED_PARAMETER(pvCacheContext);
    UNREFERENCED_PARAMETER(wszTag);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pbData);
    UNREFERENCED_PARAMETER(cbData);

    return ERROR_SUCCESS;
}

DWORD 
WINAPI
_CacheLookupFileStub(
    IN      PVOID       pvCacheContext,
    IN      LPWSTR      wszTag,  // NOSONAR - API-01: signature dictated by Windows/callback API
    IN      DWORD       dwFlags,
    IN      PBYTE      *ppbData,
    IN      PDWORD      pcbData)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
    UNREFERENCED_PARAMETER(pvCacheContext);
    UNREFERENCED_PARAMETER(wszTag);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(ppbData);
    UNREFERENCED_PARAMETER(pcbData);

    return ERROR_NOT_FOUND;
}

DWORD 
WINAPI 
_CacheDeleteFileStub(
    IN      PVOID       pvCacheContext,
    IN      LPWSTR      wszTag,  // NOSONAR - API-01: signature dictated by Windows/callback API
    IN      DWORD       dwFlags)
{
    UNREFERENCED_PARAMETER(pvCacheContext);
    UNREFERENCED_PARAMETER(wszTag);
    UNREFERENCED_PARAMETER(dwFlags);

    return ERROR_SUCCESS;
}

//
// Cleanup resources consumed by the INTERNAL_CONTEXT struct
//
void
WINAPI
_FreeManagedContext(
    __inout         PINTERNAL_CONTEXT pInternal)
{
    if (nullptr == pInternal)
        return;

    if (nullptr != pInternal->hModule)
        FreeLibrary(pInternal->hModule);
    if (nullptr != pInternal->CardData.pbAtr)
        _Free(pInternal->CardData.pbAtr);
    if (nullptr != pInternal->CardData.pwszCardName)
        _Free(pInternal->CardData.pwszCardName);

    _Free(pInternal);
}

}
//
// Dll export functions
//

//
// Build a card module context handle to the specified card
//

DWORD MgScCardAcquireContext(
    __inout                     PMGSC_CONTEXT pMgSc,
    __in                        SCARDCONTEXT hSCardContext,
    __in                        SCARDHANDLE hSCardHandle,
    __in                        LPCWSTR wszCardName,
    __in_bcount(cbAtr)          PBYTE pbAtr,
    __in                        DWORD cbAtr,
    __in                        DWORD dwFlags)
{
    DWORD status = ERROR_SUCCESS;
    LPWSTR wszCardModule = nullptr;
    DWORD cchCardModule = SCARD_AUTOALLOCATE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
    PINTERNAL_CONTEXT pInternal = nullptr;
    PFN_CARD_ACQUIRE_CONTEXT pfnCardAcquireContext = nullptr;
    DWORD cch = 0;

    pMgSc->pvContext = nullptr;

    __try
    {
        CHECK_ALLOC(pInternal = (PINTERNAL_CONTEXT) _Alloc(
            sizeof(INTERNAL_CONTEXT)));

        //
        // Lookup a card module for this card name
        //

        CHECK_DWORD(SCardGetCardTypeProviderName(
            hSCardContext,
            wszCardName,
            SCARD_PROVIDER_CARD_MODULE,
            (LPWSTR) &wszCardModule,
            &cchCardModule));
        if (0 == cchCardModule)
        {
            status = (DWORD) SCARD_E_UNKNOWN_CARD;
            __leave;
        }

        //
        // Load the card module dll and initial entry point
        // Security: Use SafeLoadLibrary to prevent DLL hijacking attacks
        //

        if (nullptr == (pInternal->hModule = SafeLoadLibrary(wszCardModule)))
        {
            status = GetLastError();
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"SafeLoadLibrary failed for '%s': 0x%08X", wszCardModule, status);
            __leave;
        }

        if (nullptr == (pfnCardAcquireContext =
                     (PFN_CARD_ACQUIRE_CONTEXT) GetProcAddress(
                         pInternal->hModule, "CardAcquireContext")))
        {
            status = GetLastError();
            __leave;
        }

        //
        // Setup the context structures
        //

        pInternal->CardData.dwVersion = CARD_DATA_CURRENT_VERSION;
        pInternal->CardData.pfnCspAlloc = _Alloc;
        pInternal->CardData.pfnCspFree = _Free;
        pInternal->CardData.pfnCspReAlloc = _ReAlloc;
        pInternal->CardData.pfnCspCacheAddFile = _CacheAddFileStub;
        pInternal->CardData.pfnCspCacheLookupFile = _CacheLookupFileStub;
        pInternal->CardData.pfnCspCacheDeleteFile = _CacheDeleteFileStub;
        pInternal->CardData.hScard = hSCardHandle;
        pInternal->CardData.hSCardCtx = hSCardContext;

        // Validate ATR size (ISO 7816-3 maximum is 33 bytes)
        if (cbAtr == 0 || cbAtr > 33)
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Invalid ATR size: %d", cbAtr);
            status = ERROR_INVALID_PARAMETER;
            __leave;
        }
        pInternal->CardData.cbAtr = cbAtr;
        CHECK_ALLOC(pInternal->CardData.pbAtr = (PBYTE) _Alloc(cbAtr));
        memcpy(pInternal->CardData.pbAtr, pbAtr, cbAtr);

        // Validate card name (CWE-787 fix for #27)
        if (wszCardName == nullptr)
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Card name is NULL");
            status = ERROR_INVALID_PARAMETER;
            __leave;
        }
        cch = (DWORD) wcsnlen(wszCardName, 256 + 1);
        if (cch > 256)
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Card name exceeds maximum length (256)");
            status = ERROR_INVALID_PARAMETER;
            __leave;
        }
        cch += 1;  // Add null terminator
        CHECK_ALLOC(pInternal->CardData.pwszCardName = (LPWSTR) _Alloc(
            sizeof(WCHAR) * cch));
        _tcscpy_s(
            pInternal->CardData.pwszCardName, cch, wszCardName);

        //
        // Call the card module
        //

        CHECK_DWORD(pfnCardAcquireContext(&pInternal->CardData, dwFlags));

        //
        // Output the context structure
        //

        pMgSc->pvContext = pInternal;
        pInternal = nullptr;
    }
    __finally
    {
        if (nullptr != wszCardModule)
            SCardFreeMemory(hSCardContext, wszCardModule);
        if (nullptr != pInternal)
            _FreeManagedContext(pInternal);
    }

    return status;
}

//
// Authenticate to the card as the specified user
//

DWORD 
MgScCardAuthenticatePin(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPWSTR      pwszUserId,
    //__in_bcount(cbPin)          PBYTE       pbPin,
    //__in                        DWORD       cbPin,
	__in                        LPWSTR      pwszPin,  // NOSONAR - API-01: signature dictated by Windows/callback API
    __out_opt                   PDWORD      pcAttemptsRemaining)
{
    DWORD status = ERROR_SUCCESS;
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
    
    LPSTR szPin = nullptr;
    DWORD cbPin = 0;

    __try
    {
        //
        // Convert the PIN to ANSI
        //

        if (0 == (cbPin = WideCharToMultiByte(
            CP_UTF8,
            0,
            pwszPin,
            -1,
            nullptr,
            0,
            nullptr,
            nullptr)))
        {
            status = GetLastError();
            __leave;
        }

        CHECK_ALLOC(szPin = (LPSTR) _Alloc(cbPin));

        if (0 == (cbPin = WideCharToMultiByte(
            CP_UTF8,
            0,
            pwszPin,
            -1,
            szPin,
            cbPin,
            nullptr,
            nullptr)))
        {
            status = GetLastError();
            __leave;
        }

        //
        // Call the card module
        //
		status = pInternal->CardData.pfnCardAuthenticatePin(
					&pInternal->CardData,
					pwszUserId,
					(PBYTE) szPin,
					cbPin - 1,
					pcAttemptsRemaining);

        // Log smart card PIN authentication result
        if (ERROR_SUCCESS == status)
        {
            EIDCardLibraryLogStructured(
                EID_EVENT_ID::AUTH_PIN_SUCCESS,
                EID_SEVERITY::INFO,
                EID_OUTCOME::SUCCESS,
                nullptr,
                L"SmartCard PIN",
                L"Smart card PIN authenticated successfully",
                nullptr,
                nullptr,
                0,
                0,
                0,
                pwszUserId,
                nullptr
            );
        }
        else
        {
            WCHAR szReason[64];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
            if (SCARD_W_WRONG_CHV == status)
            {
                swprintf_s(szReason, ARRAYSIZE(szReason), L"Wrong PIN (%d attempts remaining)",
                         pcAttemptsRemaining ? *pcAttemptsRemaining : 0);
            }
            else if (SCARD_W_CHV_BLOCKED == status)
            {
                swprintf_s(szReason, ARRAYSIZE(szReason), L"Card blocked - too many failed attempts");
            }
            else
            {
                swprintf_s(szReason, ARRAYSIZE(szReason), L"Error 0x%08X", status);
            }

            EIDCardLibraryLogStructured(
                EID_EVENT_ID::AUTH_PIN_FAILURE,
                EID_SEVERITY::WARNING,
                EID_OUTCOME::FAILURE,
                nullptr,
                L"SmartCard PIN",
                L"Smart card PIN authentication failed",
                nullptr,
                nullptr,
                0,
                0,
                0,
                pwszUserId,
                szReason
            );
        }

        CHECK_DWORD(status);
    }
    __finally
    {
        if (nullptr != szPin)
            _Free(szPin);
    }

    return status;
    

}

//
// Create a new file on the card
//

DWORD 
MgScCardCreateFile(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPSTR       pszDirectoryName,
    __in                        LPSTR       pszFileName,
    __in                        DWORD       cbInitialCreationSize,
    __in                        CARD_FILE_ACCESS_CONDITION AccessCondition)
{
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

    return pInternal->CardData.pfnCardCreateFile(
        &pInternal->CardData,
        pszDirectoryName,
        pszFileName,
        cbInitialCreationSize,
        AccessCondition);
}

//
// Deauthenticate the card
//

DWORD 
MgScCardDeauthenticate(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPWSTR      pwszUserId,
    __in                        DWORD       dwFlags)
{
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

    if (nullptr != pInternal->CardData.pfnCardDeauthenticate)
        return pInternal->CardData.pfnCardDeauthenticate(
            &pInternal->CardData,
            pwszUserId,
            dwFlags);
    else
        return ERROR_CALL_NOT_IMPLEMENTED;
}

//
// Free context and card module resources
//

void
MgScCardDeleteContext(
    __inout                     PMGSC_CONTEXT pMgSc)
{
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

    pInternal->CardData.pfnCardDeleteContext(&pInternal->CardData);

    _FreeManagedContext(pInternal);
}

//
// Delete a file from the card
//

DWORD 
WINAPI
MgScCardDeleteFile(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPSTR       pszDirectoryName,
    __in                        LPSTR       pszFileName,
    __in                        DWORD       dwFlags)
{
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

    return pInternal->CardData.pfnCardDeleteFile(
        &pInternal->CardData,
        pszDirectoryName,
        pszFileName,
        dwFlags);
}

//
// Read a file from the card
//

DWORD
WINAPI
MgScCardReadFile(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPSTR       pszDirectoryName,
    __in                        LPSTR       pszFileName,
    __in                        DWORD       dwFlags,
    __out_bcount_opt(*pcbData)  PBYTE       pbData,
    __inout                     PDWORD      pcbData)
{
    DWORD status = ERROR_SUCCESS;
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
    PBYTE pbLocal = nullptr;
    DWORD cbLocal = 0;

    __try
    {
        CHECK_DWORD(pInternal->CardData.pfnCardReadFile(
            &pInternal->CardData,
            pszDirectoryName,
            pszFileName,
            dwFlags,
            &pbLocal,
            &cbLocal));

        // Validate response length - max 64KB per APDU spec (CWE-131 fix for #47)
        if (cbLocal > 65535)
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Card returned invalid file size: %d", cbLocal);
            status = ERROR_INVALID_DATA;
            __leave;
        }

        if (*pcbData < cbLocal)
        {
            if (nullptr != pbData)
                status = ERROR_INSUFFICIENT_BUFFER;
        }
        else if (nullptr != pbData)
        {
            memcpy(pbData, pbLocal, cbLocal);
        }

        *pcbData = cbLocal;
    }
    __finally
    {
        if (nullptr != pbLocal)
            _Free(pbLocal);
    }
    
    return status;
}

//
// Write a file to the card
//

DWORD
WINAPI
MgScCardWriteFile(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPSTR       pszDirectoryName,
    __in                        LPSTR       pszFileName,
    __in                        DWORD       dwFlags,
    __in_bcount(cbData)         PBYTE       pbData,
    __in                        DWORD       cbData)
{
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

    return pInternal->CardData.pfnCardWriteFile(
        &pInternal->CardData,
        pszDirectoryName,
        pszFileName,
        dwFlags,
        pbData,
        cbData);
}

BOOL CheckPINandGetRemainingAttempts(LPCTSTR szReader, LPCTSTR szCard, PTSTR szPin, PDWORD pdwAttempts)
{
	MGSC_CONTEXT pContext = {};
	SCARDCONTEXT hSCardContext = NULL;
	SCARDHANDLE hSCardHandle = NULL;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	std::array<BYTE, 32> bAtr;
	DWORD cbAtr = static_cast<DWORD>(bAtr.size());  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	LONG lReturn;
	DWORD dwSize;
	DWORD dwState;
	DWORD dwProtocol;
	DWORD dwError = 0;
	TCHAR szReaderTemp[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	BOOL fReturn = FALSE;
	__try
	{
		if (pdwAttempts == nullptr)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pdwAttempts = NULL");
			__leave;
		}
		// Validate input parameters
		if (szReader == nullptr || szCard == nullptr || szPin == nullptr)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NULL parameter: reader=%p card=%p pin=%p", szReader, szCard, szPin);
			__leave;
		}
		if (_tcslen(szReader) == 0 || _tcslen(szReader) >= ARRAYSIZE(szReaderTemp))
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Reader name invalid length");
			__leave;
		}
		*pdwAttempts = 0xFFFFFFFF;
		lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
								nullptr,
								nullptr,
								&hSCardContext );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08X",lReturn);
			dwError = lReturn;
			__leave;
		}
		lReturn = SCardConnect(hSCardContext,szReader,SCARD_SHARE_SHARED,SCARD_PROTOCOL_Tx, &hSCardHandle, &dwProtocol);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardConnect 0x%08X",lReturn);
			dwError = lReturn;
			__leave;
		}
		dwSize = ARRAYSIZE(szReaderTemp);
		lReturn = SCardStatus(hSCardHandle, szReaderTemp, &dwSize, &dwState, &dwProtocol, bAtr.data(),&cbAtr);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardStatus 0x%08X",lReturn);
			dwError = lReturn;
			__leave;
		}
		lReturn = SCardBeginTransaction(hSCardHandle);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardBeginTransaction 0x%08X",lReturn);
			dwError = lReturn;
			__leave;
		}
		dwError = MgScCardAcquireContext(&pContext,hSCardContext,hSCardHandle,szCard,bAtr.data(),cbAtr,0);
		if ( dwError )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"MgScCardAcquireContext 0x%08X",dwError);
			__leave;
		}
		dwError = MgScCardAuthenticatePin(&pContext,s_wszCardUserUser,szPin,pdwAttempts);
		if ( dwError )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"MgScCardAuthenticatePin 0x%08X *pdwAttempts=%d",dwError, *pdwAttempts);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"cardmodule authentication successful");

		// Log successful smart card authentication at card level
		EIDCardLibraryLogStructured(
			EID_EVENT_ID::SC_CARD_DETECTED,
			EID_SEVERITY::VERBOSE,
			EID_OUTCOME::SUCCESS,
			nullptr,
			L"SmartCard",
			L"Smart card authenticated successfully",
			nullptr,
			nullptr,
			0,
			0,
			0,
			szCard,
			szReader
		);

		fReturn = TRUE;
	}
	__finally
	{
		BOOL fDeAuthenticated = FALSE;
		if (pContext.pvContext)
		{
			if (MgScCardDeauthenticate(&pContext, s_wszCardUserUser, 0) == ERROR_SUCCESS)
			{
				fDeAuthenticated = TRUE;
			}
			MgScCardDeleteContext(&pContext);
		}
		if (hSCardHandle)
		{
			if (!fDeAuthenticated)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Reset Card");
				SCardEndTransaction(hSCardHandle,SCARD_RESET_CARD);
			}
			else
			{
				SCardEndTransaction(hSCardHandle,SCARD_LEAVE_CARD);
			}
			SCardDisconnect(hSCardHandle,0);
		}
		if (hSCardContext)
			SCardReleaseContext(hSCardContext);
	}
	SetLastError(dwError);
	return fReturn;
}

// Card name Windows gives a PIV card that it drives with its built-in PIV minidriver.
static const TCHAR s_szInboxPivCardName[] = TEXT("Identity Device (NIST SP 800-73 [PIV])");

// Decodes the status word a PIV card answers to a VERIFY with no data: 63Cx = x PIN attempts
// left, 6983 = blocked. Anything else (9000 = already verified, or an error) leaves the count
// unknown, 0xFFFFFFFF.
static DWORD PinAttemptsFromVerifyStatus(const BYTE* pbResponse, DWORD cbResponse)
{
	if (cbResponse < 2)
	{
		return 0xFFFFFFFF;
	}
	const BYTE bSw1 = pbResponse[cbResponse - 2];
	const BYTE bSw2 = pbResponse[cbResponse - 1];
	if (bSw1 == 0x63 && (bSw2 & 0xF0) == 0xC0)
	{
		return bSw2 & 0x0F;
	}
	if (bSw1 == 0x69 && bSw2 == 0x83)
	{
		return 0;
	}
	return 0xFFFFFFFF;
}

// Reads how many attempts the PIV Card Application PIN has left without using one: per NIST
// SP 800-73-4 part 2, a VERIFY with no data field only reports the PIN's status. The PIV
// application is selected first and left selected, which is the state the PIV minidriver
// expects. Returns 0xFFFFFFFF when the count cannot be read.
static DWORD GetPivPinAttempts(LPCTSTR szReader)
{
	// SELECT the PIV application by its right-truncated AID A0 00 00 03 08 00 00 10 00.
	static const BYTE s_bSelectPiv[] = { 0x00, 0xA4, 0x04, 0x00, 0x09,
		0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00 };
	// VERIFY, key reference 80 (PIV Card Application PIN), no data.
	static const BYTE s_bVerifyStatus[] = { 0x00, 0x20, 0x00, 0x80 };
	SCARDCONTEXT hSCardContext = NULL;
	SCARDHANDLE hSCardHandle = NULL;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	BOOL fTransaction = FALSE;
	DWORD dwProtocol = 0;
	DWORD dwAttempts = 0xFFFFFFFF;
	BYTE bResponse[258];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD cbResponse;
	LONG lReturn;
	__try
	{
		lReturn = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &hSCardContext);
		if (SCARD_S_SUCCESS != lReturn)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08X",lReturn);
			__leave;
		}
		lReturn = SCardConnect(hSCardContext, szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &hSCardHandle, &dwProtocol);
		if (SCARD_S_SUCCESS != lReturn)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardConnect 0x%08X",lReturn);
			__leave;
		}
		lReturn = SCardBeginTransaction(hSCardHandle);
		if (SCARD_S_SUCCESS != lReturn)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardBeginTransaction 0x%08X",lReturn);
			__leave;
		}
		fTransaction = TRUE;
		LPCSCARD_IO_REQUEST pioSendPci = (dwProtocol == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;
		cbResponse = ARRAYSIZE(bResponse);
		lReturn = SCardTransmit(hSCardHandle, pioSendPci, s_bSelectPiv, ARRAYSIZE(s_bSelectPiv), nullptr, bResponse, &cbResponse);
		// 9000, or 61xx when T=0 holds the application template back for a GET RESPONSE.
		if (SCARD_S_SUCCESS != lReturn || cbResponse < 2
			|| !((bResponse[cbResponse - 2] == 0x90 && bResponse[cbResponse - 1] == 0x00) || bResponse[cbResponse - 2] == 0x61))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SELECT PIV 0x%08X cb=%u", lReturn, cbResponse);
			__leave;
		}
		cbResponse = ARRAYSIZE(bResponse);
		lReturn = SCardTransmit(hSCardHandle, pioSendPci, s_bVerifyStatus, ARRAYSIZE(s_bVerifyStatus), nullptr, bResponse, &cbResponse);
		if (SCARD_S_SUCCESS != lReturn)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"VERIFY (status) 0x%08X",lReturn);
			__leave;
		}
		dwAttempts = PinAttemptsFromVerifyStatus(bResponse, cbResponse);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"PIV PIN attempts left %d",dwAttempts);
	}
	__finally
	{
		if (fTransaction)
		{
			SCardEndTransaction(hSCardHandle, SCARD_LEAVE_CARD);
		}
		if (hSCardHandle)
		{
			SCardDisconnect(hSCardHandle, SCARD_LEAVE_CARD);
		}
		if (hSCardContext)
		{
			SCardReleaseContext(hSCardContext);
		}
	}
	return dwAttempts;
}

DWORD GetPinAttemptsAfterWrongPinIfPossible(PEID_SMARTCARD_CSP_INFO pCspInfo, ULONG dwCspDataLength)
{
	if (!EIDValidateCspInfo(pCspInfo, dwCspDataLength))
	{
		return 0xFFFFFFFF;
	}
	LPCTSTR szCSPName = EIDCspInfoStringAt(pCspInfo, dwCspDataLength, pCspInfo->nCSPNameOffset);
	LPCTSTR szCardName = EIDCspInfoStringAt(pCspInfo, dwCspDataLength, pCspInfo->nCardNameOffset);
	LPCTSTR szReaderName = EIDCspInfoStringAt(pCspInfo, dwCspDataLength, pCspInfo->nReaderNameOffset);
	if (!szCSPName || !szCardName || !szReaderName)
	{
		return 0xFFFFFFFF;
	}
	// Only the PIV cards CheckPINandGetRemainingAttemptsIfPossible leaves to the CSP; a card the
	// minidriver check covered already reported its count, and another card may not speak PIV.
	if (_tcscmp(MS_SCARD_PROV, szCSPName) != 0 || _tcscmp(s_szInboxPivCardName, szCardName) != 0)
	{
		return 0xFFFFFFFF;
	}
	EIDImpersonate();
	DWORD dwAttempts = GetPivPinAttempts(szReaderName);
	EIDRevertToSelf();
	return dwAttempts;
}

NTSTATUS CheckPINandGetRemainingAttemptsIfPossible(PEID_SMARTCARD_CSP_INFO pCspInfo, ULONG dwCspDataLength, PTSTR szPin, NTSTATUS *pSubStatus)
{
	DWORD dwAttempts;

	// Offset validation is centralised in EIDValidateCspInfo. The inline check
	// this replaces bounded the offsets against pCspInfo->dwCspInfoLen, which
	// is itself inside the attacker-supplied buffer, and compared byte counts
	// against offsets used to index bBuffer (TCHAR[]) - so it permitted reads
	// well past the declared bound. It also never required the strings to be
	// NUL-terminated, which matters because every use below is a _tcscmp.
	if (!EIDValidateCspInfo(pCspInfo, dwCspDataLength))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"CheckPINandGetRemainingAttemptsIfPossible: CSP info layout rejected (CspDataLength=%u)",
			dwCspDataLength);
		return STATUS_INVALID_PARAMETER;
	}

	LPCTSTR szCSPName = EIDCspInfoStringAt(pCspInfo, dwCspDataLength, pCspInfo->nCSPNameOffset);
	LPCTSTR szCardName = EIDCspInfoStringAt(pCspInfo, dwCspDataLength, pCspInfo->nCardNameOffset);
	LPCTSTR szReaderName = EIDCspInfoStringAt(pCspInfo, dwCspDataLength, pCspInfo->nReaderNameOffset);
	// All three are dereferenced below (two _tcscmp plus the reader lookup), so
	// a missing field is a rejection rather than something to work around.
	if (!szCSPName || !szCardName || !szReaderName)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"CheckPINandGetRemainingAttemptsIfPossible: CSP/card/reader name absent");
		return STATUS_INVALID_PARAMETER;
	}
	// do the test only if it is a mini driver
	if (_tcscmp(MS_SCARD_PROV, szCSPName) != 0)
	{
		return 0;
	}
	if (_tcscmp(s_szInboxPivCardName, szCardName) == 0)
	{
		return 0;
	}
	EIDImpersonate();
	BOOL fReturn = CheckPINandGetRemainingAttempts(szReaderName, szCardName, szPin, &dwAttempts);
	DWORD dwError = GetLastError();
	EIDRevertToSelf();
	if (fReturn)
	{
		return STATUS_SUCCESS;
	}
	else if (dwError == SCARD_W_WRONG_CHV)
	{
		*pSubStatus = dwAttempts;
		return STATUS_SMARTCARD_WRONG_PIN;
	}
	else if (dwError == SCARD_W_CHV_BLOCKED)
	{
		return STATUS_SMARTCARD_CARD_BLOCKED;
	}
	else
	{
		// ignore this test
		return STATUS_SUCCESS;
	}
}