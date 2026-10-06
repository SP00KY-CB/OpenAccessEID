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

#include <tchar.h>

#include "../EIDCardLibrary/CertificateValidation.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/Tracing.h"
#include <LM.h>
#include <wincred.h>

// Kept here rather than in CContainerHolderFactory.h: Cppcheck parses .h files as C and
// rejects templates there, and this is the only place the trait is used.
// Detects whether a holder type is reference counted (COM-style AddRef/Release). The credential
// provider's holder is; the configuration wizard's is not (and never takes the paths that
// hand an item out of the list lock), so the factory only pins items for the former.
template <typename U, typename = void>
struct ContainerHolderHasAddRef : std::false_type {};
template <typename U>
struct ContainerHolderHasAddRef<U, std::void_t<decltype(std::declval<U&>().AddRef())>> : std::true_type {};
// Detects a holder that implements the selected-tile "disconnected" morph (the credential
// provider's tile). The state changes are made under the list lock; the LogonUI field updates
// are made after it is dropped. Holders without it (the wizard's) never morph or revive.
template <typename U, typename = void>
struct ContainerHolderHasTileState : std::false_type {};
template <typename U>
struct ContainerHolderHasTileState<U, std::void_t<
	decltype(std::declval<U&>().MarkDisconnectedIfSelected()),
	decltype(std::declval<U&>().MarkReconnected()),
	decltype(std::declval<U&>().UpdateConnectionFields()),
	decltype(std::declval<U&>().SetProvider(nullptr))>> : std::true_type {};



template <typename T>
CContainerHolderFactory<T>::CContainerHolderFactory()
{
	_cpus = CPUS_INVALID;
	_dwFlags = 0;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_fReviveOnReconnect = FALSE;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	InitializeCriticalSection(&CriticalSection);
}

template <typename T>
void CContainerHolderFactory<T>::SetReviveOnReconnect(BOOL fRevive)
{
	_fReviveOnReconnect = fRevive;
}

template <typename T>
void CContainerHolderFactory<T>::PinItem(T* item)
{
	if constexpr (ContainerHolderHasAddRef<T>::value)
	{
		item->AddRef();
	}
	else
	{
		UNREFERENCED_PARAMETER(item);
	}
}

template <typename T>
void CContainerHolderFactory<T>::UnpinItem(T* item)
{
	if constexpr (ContainerHolderHasAddRef<T>::value)
	{
		item->Release();
	}
	else
	{
		UNREFERENCED_PARAMETER(item);
	}
}

template <typename T>
BOOL CContainerHolderFactory<T>::MarkItemDisconnectedIfSelected(T* item)
{
	if constexpr (ContainerHolderHasTileState<T>::value)
	{
		return item->MarkDisconnectedIfSelected();
	}
	else
	{
		UNREFERENCED_PARAMETER(item);
		return FALSE;
	}
}

template <typename T>
BOOL CContainerHolderFactory<T>::MarkItemReconnected(T* item)
{
	if constexpr (ContainerHolderHasTileState<T>::value)
	{
		return item->MarkReconnected();
	}
	else
	{
		UNREFERENCED_PARAMETER(item);
		return FALSE;
	}
}

template <typename T>
void CContainerHolderFactory<T>::UpdateItemConnectionFields(T* item)
{
	if constexpr (ContainerHolderHasTileState<T>::value)
	{
		item->UpdateConnectionFields();
	}
	else
	{
		UNREFERENCED_PARAMETER(item);
	}
}

template <typename T>
void CContainerHolderFactory<T>::ReleaseItem(T* item)
{
	if constexpr (ContainerHolderHasTileState<T>::value)
	{
		// The tile may outlive the list (LogonUI still holds it); it must not call back into
		// a provider that may be destroyed by then.
		item->SetProvider(nullptr);
	}
	item->Release();
}

template <typename T> 
CContainerHolderFactory<T>::~CContainerHolderFactory()
{
	CleanList();
	DeleteCriticalSection(&CriticalSection);
}

template <typename T> 
VOID CContainerHolderFactory<T>::Lock()
{
	EnterCriticalSection(&CriticalSection);
}

template <typename T> 
VOID CContainerHolderFactory<T>::Unlock()
{
	LeaveCriticalSection(&CriticalSection);
}

template <typename T> 
HRESULT CContainerHolderFactory<T>::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags
    )
{
	_cpus = cpus;
	_dwFlags = dwFlags;
	return S_OK;
}

template <typename T>
BOOL CContainerHolderFactory<T>::ConnectNotification(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount)
{
	BOOL fReturn = ConnectNotificationGeneric(szReaderName,szCardName, ActivityCount);
	// Any tile still flagged disconnected on this reader belongs to a card that is no
	// longer here (a different card was inserted); drop it so it cannot linger.
	if (_fReviveOnReconnect)
	{
		PurgeStaleDisconnected(szReaderName);
	}
	return fReturn;
}

// called to enumerate the credential built with a CContainer
template <typename T> 
BOOL CContainerHolderFactory<T>::ConnectNotificationGeneric(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
	HCRYPTPROV HCryptProv;
	HCRYPTPROV hProv = NULL;
	BOOL bStatus;
	CHAR szContainerName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwContainerNameLen = ARRAYSIZE(szContainerName);
	TCHAR szProviderName[1024] = TEXT("");  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwProviderNameLen = ARRAYSIZE(szProviderName);
	DWORD pKeySpecs[2] = {AT_KEYEXCHANGE,AT_SIGNATURE};  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwKeyNumMax = 1;
	HCRYPTKEY hKey;
	// remove existing entries
	//DisconnectNotification(szReaderName);
	EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Connect Reader %s CardName %s",szReaderName,szCardName);
	// get provider name
	if (!SchGetProviderNameFromCardName(szCardName, szProviderName, &dwProviderNameLen))
	{
		return FALSE;
	}
	// The provider comes from the card's ATR mapping. Apply the same CSP allow-list (and its
	// EnforceCSPWhitelist policy) as the LSA side before CryptAcquireContext loads the CSP
	// DLL into this process (LogonUI runs as SYSTEM).
	if (!IsAllowedCSPProvider(szProviderName))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CSP provider '%s' not allowed - card ignored",szProviderName);
		return FALSE;
	}

	LPTSTR szMainContainerName = BuildContainerNameFromReader(szReaderName);
	if (!szMainContainerName)
	{
		return FALSE;
	}
	
	// if policy 
	if (GetPolicyValue(GPOPolicy::AllowSignatureOnlyKeys) || _cpus == CPUS_INVALID)
	{
		dwKeyNumMax = 2;
	}


	bStatus = CryptAcquireContext(&HCryptProv,
				szMainContainerName,
				szProviderName,
				PROV_RSA_FULL,
				CRYPT_SILENT);
	if (!bStatus)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 1 0x%08x",GetLastError());
		// for the spanish EID
		bStatus = CryptAcquireContext(&HCryptProv,
				nullptr,
				szProviderName,
				PROV_RSA_FULL,
				CRYPT_SILENT);
		if (!bStatus)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 2 0x%08x",GetLastError());
			EIDFree(szMainContainerName);
			return FALSE;
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
		// Ensure null-termination to prevent out-of-bounds read (CWE-125 fix for #31)
		if (dwContainerNameLen >= ARRAYSIZE(szContainerName))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Container name too long: %d", dwContainerNameLen);
			dwFlags = CRYPT_NEXT;
			dwContainerNameLen = ARRAYSIZE(szContainerName);
			continue;
		}
		szContainerName[dwContainerNameLen] = '\0';

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
				for (DWORD i = 0; i < dwKeyNumMax; i++)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					if (CryptGetUserKey(hProv,
							pKeySpecs[i],
							&hKey) )
					{
						BYTE Data[4096];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
						DWORD DataSize = 4096;
						if (CryptGetKeyParam(hKey,  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
								KP_CERTIFICATE,
								Data,
								&DataSize,
								0))
						{
							CreateItemFromCertificateBlob(hProv, szReaderName,szCardName,szProviderName,
									szWideContainerName, pKeySpecs[i],ActivityCount, Data, DataSize);
							}
							CryptDestroyKey(hKey);
							hKey = NULL;
					}
				}
			}
			CryptReleaseContext(hProv, 0);
			hProv = NULL;
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Failed to allocate memory for container name");
		}
		dwFlags = CRYPT_NEXT;
		dwContainerNameLen = ARRAYSIZE(szContainerName);
		EIDFree(szWideContainerName);
	}
	if (dwFlags == CRYPT_FIRST)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetProvParam 0x%08x - creating containers manually",GetLastError());
		// the default container can be enumerated but PP_ENUMCONTAINERS doesn't work
		for (DWORD i = 0; i < dwKeyNumMax; i++)
		{
			if (CryptGetUserKey(HCryptProv,
					pKeySpecs[i],
					&hKey) )
			{
				BYTE Data[4096];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
				DWORD DataSize = 4096;
				if (CryptGetKeyParam(hKey,  // NOSONAR - COMPLEXITY-01: nesting and local declaration retained; logic verified
						KP_CERTIFICATE,
						Data,
						&DataSize,
						0))
				{
					CreateItemFromCertificateBlob(HCryptProv, szReaderName,szCardName,szProviderName,
						szMainContainerName, pKeySpecs[i],ActivityCount, Data, DataSize);
					}
				CryptDestroyKey(hKey);
				hKey = NULL;
			}
		}
	}
	CryptReleaseContext(HCryptProv,0);
	EIDFree(szMainContainerName);
	return TRUE;
}

template <typename T>
BOOL CContainerHolderFactory<T>::CreateContainer(__in LPCTSTR szReaderName,__in LPCTSTR szCardName,
															   __in LPCTSTR szProviderName, __in LPCTSTR szWideContainerName,
															   __in DWORD KeySpec, __in USHORT ActivityCount, __in PCCERT_CONTEXT pCertContext)
{
	// nothrow: this runs on the smart-card notifier thread inside LogonUI, where an escaping
	// std::bad_alloc would take the process down. On failure the caller still owns (and frees)
	// pCertContext.
	CContainer* pContainer = nullptr;
	pContainer = new (std::nothrow) CContainer(szReaderName,szCardName,szProviderName,szWideContainerName, KeySpec, ActivityCount, pCertContext);  // NOSONAR - COM-01: Container requires heap allocation
	if (!pContainer)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Out of memory (CContainer)");
		return FALSE;
	}
	this->Lock();
	T* ContainerHolder = new (std::nothrow) T(pContainer);  // NOSONAR - COM-01: Container holder requires heap allocation
	if (!ContainerHolder)
	{
		this->Unlock();
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Out of memory (container holder)");
		// ~CContainer frees the certificate context it was given, but the caller frees it too on
		// failure: hand the container its own reference so the caller's stays valid.
		CertDuplicateCertificateContext(pCertContext);
		delete pContainer;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
		return FALSE;
	}
	ContainerHolder->SetUsageScenario(_cpus, _dwFlags);
	_CredentialList.push_back(ContainerHolder);
	this->Unlock();
	return TRUE;
}

template <typename T>
BOOL CContainerHolderFactory<T>::CreateItemFromCertificateBlob(__in HCRYPTPROV hProv,  // NOSONAR - COMPLEXITY-01: parameter count and complexity retained; logic verified
																__in LPCTSTR szReaderName,__in LPCTSTR szCardName,
															   __in LPCTSTR szProviderName, __in LPCTSTR szWideContainerName,
															   __in DWORD KeySpec, __in USHORT ActivityCount,
															   __in PBYTE Data, __in DWORD DataSize)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
	BOOL fReturn = FALSE;
	PCCERT_CONTEXT pCertContext = nullptr;
	BOOL fSuccess;
	PTSTR szUsername = nullptr;
	DWORD dwError = 0;

	// Revive-in-place: if this exact container/key is already present as a tile that was
	// flagged disconnected (its card was removed while selected), just clear the flag so the
	// existing, on-screen tile comes back to life. This avoids creating a duplicate tile and
	// lets LogonUI's currently selected tile switch back from "please reconnect" to the PIN box.
	//
	// Reader, key spec and container name are chosen by whoever made the card, so they do not
	// identify it: a different card using the same container name must NOT inherit the tile
	// (and the PIN typed into it). Only revive when the certificate on the card is byte-for-byte
	// the one the tile was built from; otherwise fall through and create a new tile normally -
	// the old one stays flagged disconnected and is dropped by PurgeStaleDisconnected.
	if (_fReviveOnReconnect)
	{
		T* reviveItem = nullptr;
		this->Lock();
		for (T* item : _CredentialList)
		{
			CContainer* container = item->GetContainer();  // NOSONAR - API-01: non-const pointer retained; member access constness not guaranteed
			// The container's strings are NULL if they failed validation/allocation.
			LPCTSTR szItemContainerName = container->GetContainerName();
			if (item->IsDisconnected() &&
				szItemContainerName != nullptr &&
				container->IsOnReader(szReaderName) &&
				container->GetKeySpec() == KeySpec &&
				_tcscmp(szItemContainerName, szWideContainerName) == 0)
			{
				BOOL fSameCertificate = FALSE;
				if (PCCERT_CONTEXT pOldCert = container->GetCertificate())
				{
					fSameCertificate = (Data != nullptr &&
						pOldCert->cbCertEncoded == DataSize &&
						memcmp(pOldCert->pbCertEncoded, Data, DataSize) == 0);
					CertFreeCertificateContext(pOldCert);
				}
				if (!fSameCertificate)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not reviving tile %s: certificate on the card differs", szWideContainerName);
					continue;
				}
				// Clear the flag while still holding the list lock: a concurrent deselect re-checks
				// it under this lock before erasing the tile (RemoveIfDisconnected), so the tile is
				// either already gone from the list (and is not found here) or stays revived.
				if (MarkItemReconnected(item))
				{
					reviveItem = item;
					// Keep it alive once the lock is dropped.
					PinItem(reviveItem);
				}
				break;
			}
		}
		this->Unlock();
		if (reviveItem)
		{
			// Restore the PIN prompt outside the lock (calls into LogonUI). The flag is already
			// clear, so the post-connect PurgeStaleDisconnected will not purge the tile.
			UpdateItemConnectionFields(reviveItem);
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Revived disconnected tile %s", szWideContainerName);
			UnpinItem(reviveItem);
			return TRUE;
		}
	}

	__try
	{
		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, Data, DataSize);
		if (!pCertContext)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
			__leave;
		}
		
		// important : the hprov will be used later and free if the certificatecontext is free
		// so we have to add 1 to the reference count. Take that reference BEFORE the key context
		// is attached: were the AddRef to fail afterwards, freeing the certificate would release
		// the caller's own reference to hProv.
		fReturn = CryptContextAddRef(hProv, nullptr, 0);
		if (!fReturn)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptContextAddRef 0x%08x",dwError);
			__leave;
		}
		fReturn = SetupCertificateContextWithKeyInfo(pCertContext, hProv, szProviderName, szWideContainerName, KeySpec);
		if (!fReturn)
		{
			dwError = GetLastError();
			// The certificate does not own the key context: drop the reference taken above.
			CryptReleaseContext(hProv, 0);
			__leave;
		}
		// Only report success (and so keep pCertContext alive) once a container owns it; every
		// rejection below must let __finally free the certificate (and the hProv reference).
		fReturn = FALSE;

		if (_cpus != CPUS_CREDUI && _cpus != CPUS_INVALID)
		{
			fSuccess = IsTrustedCertificate(pCertContext);
			if (!fSuccess)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Untrusted certificate IsTrustedCertificate 0x%08x",dwError);
				__leave;
			}
		}
		else if (_cpus == CPUS_CREDUI)
		{
			fSuccess = HasCertificateRightEKU(pCertContext);
			if (!fSuccess)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Untrusted certificate HasCertificateRightEKU 0x%08x",dwError);
				__leave;
			}
		}
		// check if the Container meet the requirement
		if ((_cpus == CPUS_LOGON) || (_cpus == CPUS_UNLOCK_WORKSTATION))
		{
			// check if the user has an account to this workstation
			DWORD dwRid = LsaEIDGetRIDFromStoredCredential(pCertContext);	
			if (!dwRid)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"HasAccountOnCurrentComputer 0x%08x",dwError);
				__leave;
			}
			szUsername = GetUsernameFromRid(dwRid);
			if (!szUsername)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetUsernameFromRid 0x%08x",dwError);
				__leave;
			}
			if ((_dwFlags & CREDUIWIN_ENUMERATE_CURRENT_USER) || (_cpus == CPUS_UNLOCK_WORKSTATION))
			{
				fSuccess = IsCurrentUser(szUsername);
				if (!fSuccess)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"IsCurrentUser 0x%08x",dwError);
					__leave;
				}
			}
			if (_dwFlags & CREDUIWIN_ENUMERATE_ADMINS)
			{
				fSuccess = IsAdmin(szUsername);
				if (!fSuccess)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"IsAdmin 0x%08x",dwError);
					__leave;
				}
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Creating container szReaderName='%s'", szReaderName);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Creating container szCardName='%s'", szCardName);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Creating container szProviderName='%s'", szProviderName);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Creating container szWideContainerName='%s' KeySpec=%d ActivityCount=%d",
				szWideContainerName, KeySpec, ActivityCount);
		fSuccess = CreateContainer(szReaderName, szCardName, szProviderName, szWideContainerName, KeySpec, ActivityCount, pCertContext);
		if (!fSuccess) __leave;
		fReturn = TRUE;
	}
	__finally
	{
		if (szUsername) EIDFree(szUsername);
		if (!fReturn && pCertContext)
		{
			CertFreeCertificateContext(pCertContext);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

template <typename T>
BOOL CContainerHolderFactory<T>::DisconnectNotification(LPCTSTR szReaderName)
{
	// Tiles kept alive to be morphed to "please reconnect" after the lock is released
	// (SetDisconnected calls into LogonUI, which must not happen under our critical section).
	std::list<T*> morphItems;
	this->Lock();
	auto l_iter = _CredentialList.begin();
	while(l_iter!=_CredentialList.end())
	{
		T* item = (T *)*l_iter;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		CContainer* container = item->GetContainer();  // NOSONAR - API-01: non-const pointer retained; member access constness not guaranteed

#ifndef UNICODE
		int wLen = MultiByteToWideChar(CP_UTF8, 0, szReaderName, -1, nullptr, 0);
		LPWSTR szWideReaderName = (LPWSTR) EIDAlloc(sizeof(WCHAR)*wLen);  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (szWideReaderName)
		{
			MultiByteToWideChar(CP_UTF8, 0, szReaderName, -1, szWideReaderName, wLen);
#else
		LPWSTR szWideReaderName = (LPWSTR) EIDAlloc((DWORD)(sizeof(WCHAR)*(_tcslen(szReaderName)+1)));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		if (szWideReaderName)
			{
			_tcscpy_s(szWideReaderName,_tcslen(szReaderName)+1,szReaderName);

#endif
			if(container->IsOnReader(szWideReaderName))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Disconnect match tile=%p revive=%d selected=%d",(void*)item,_fReviveOnReconnect,item->IsSelected());
				// Keep the currently selected tile alive but flagged disconnected, so it can
				// morph to "please reconnect" in place (LogonUI will not swap a selected tile)
				// and be revived when the card returns. All other tiles are removed as before.
				// The flag is set here, under the list lock, and only if the tile is still
				// selected (tested atomically under the tile's own lock): a concurrent
				// SetDeselected either ran first - the tile is then erased below - or sees the
				// flag and asks for the tile to be purged (RemoveIfDisconnected waits for this
				// lock), so a morphed tile can never be left unselected and unpurged.
				if (_fReviveOnReconnect && MarkItemDisconnectedIfSelected(item))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Disconnect -> MORPH tile=%p",(void*)item);
					PinItem(item);  // used after the lock is dropped
					morphItems.push_back(item);
					++l_iter;
				}
				else
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Disconnect -> ERASE tile=%p",(void*)item);
					l_iter = _CredentialList.erase(l_iter);
					ReleaseItem(item);
				}
			}
			else
			{
				++l_iter;
			}
			EIDFree(szWideReaderName);
		}
	}
	this->Unlock();

	// The kept tiles were pinned under the lock, so they stay alive here even if the UI thread
	// erases them from _CredentialList concurrently. Only the LogonUI field updates remain.
	for (T* item : morphItems)
	{
		UpdateItemConnectionFields(item);
		UnpinItem(item);
	}
	return TRUE;
}

template <typename T>
void CContainerHolderFactory<T>::PurgeStaleDisconnected(LPCTSTR szReaderName)
{
	this->Lock();
	auto l_iter = _CredentialList.begin();
	while(l_iter!=_CredentialList.end())
	{
		T* item = (T *)*l_iter;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		CContainer* container = item->GetContainer();  // NOSONAR - API-01: non-const pointer retained; member access constness not guaranteed
		if (item->IsDisconnected() && container->IsOnReader(szReaderName))
		{
			l_iter = _CredentialList.erase(l_iter);
			ReleaseItem(item);
		}
		else
		{
			++l_iter;
		}
	}
	this->Unlock();
}

template <typename T>
BOOL CContainerHolderFactory<T>::RemoveIfDisconnected(T* holder)
{
	BOOL fFound = FALSE;
	this->Lock();
	auto l_iter = _CredentialList.begin();
	while(l_iter!=_CredentialList.end())
	{
		if ((T*)*l_iter == holder)  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		{
			// Re-check under the list lock: the card may have come back (revive clears the
			// flag under this same lock) since the caller saw the tile disconnected.
			if (holder->IsDisconnected())
			{
				l_iter = _CredentialList.erase(l_iter);
				ReleaseItem(holder);
				fFound = TRUE;
			}
			break;
		}
		++l_iter;
	}
	this->Unlock();
	return fFound;
}

template <typename T>
BOOL CContainerHolderFactory<T>::CleanList()
{
	this->Lock();
	auto l_iter = _CredentialList.begin();
	while(l_iter!=_CredentialList.end())
	{
		T* item = (T *)*l_iter;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
		l_iter = _CredentialList.erase(l_iter);
		ReleaseItem(item);
	}
	this->Unlock();
	return TRUE;
}

template <typename T>
BOOL CContainerHolderFactory<T>::HasContainerHolder() const
{
	const_cast<CContainerHolderFactory<T>*>(this)->Lock();  // NOSONAR - COM-01: Thread-safe locking pattern requires const_cast
	BOOL result = _CredentialList.size() > 0;
	const_cast<CContainerHolderFactory<T>*>(this)->Unlock();  // NOSONAR - COM-01: Thread-safe locking pattern requires const_cast
	return result;
}


template <typename T>
DWORD CContainerHolderFactory<T>::ContainerHolderCount() const
{
	const_cast<CContainerHolderFactory<T>*>(this)->Lock();  // NOSONAR - COM-01: Thread-safe locking pattern requires const_cast
	DWORD count = (DWORD) _CredentialList.size();  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	const_cast<CContainerHolderFactory<T>*>(this)->Unlock();  // NOSONAR - COM-01: Thread-safe locking pattern requires const_cast
	return count;
}

template <typename T>
T* CContainerHolderFactory<T>::GetContainerHolderAt(DWORD dwIndex)
{
	this->Lock();
	T* result = nullptr;
	if (dwIndex < _CredentialList.size())
	{
		auto it = _CredentialList.begin();
		std::advance(it, dwIndex);
		result = *it;
	}
	this->Unlock();
	return result;
}