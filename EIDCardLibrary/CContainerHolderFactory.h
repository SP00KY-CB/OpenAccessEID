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
#include <wincrypt.h>
#include <credentialprovider.h>
#include <list>
#include <new>
#include <type_traits>
#include <utility>

template <typename T>

class CContainerHolderFactory  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
{
public:	
	CContainerHolderFactory();
	virtual ~CContainerHolderFactory();

	HRESULT SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags);
	BOOL DisconnectNotification(__in LPCTSTR szReaderName);
	BOOL ConnectNotification(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount);
	BOOL CreateContainer(__in LPCTSTR szReaderName,__in LPCTSTR szCardName,
															   __in LPCTSTR szProviderName, __in LPCTSTR szWideContainerName,
															   __in DWORD KeySpec, __in USHORT ActivityCount, __in PCCERT_CONTEXT pCertContext);
	BOOL CreateItemFromCertificateBlob(__in HCRYPTPROV hProv, __in LPCTSTR szReaderName,__in LPCTSTR szCardName,
															   __in LPCTSTR szProviderName, __in LPCTSTR szContainerName,
															   __in DWORD KeySpec, __in USHORT ActivityCount,
															   __in PBYTE Data, __in DWORD DataSize);
	VOID Lock();
	VOID Unlock();
	BOOL HasContainerHolder() const;
	DWORD ContainerHolderCount() const;
	T* GetContainerHolderAt(DWORD dwIndex);
	// Remove a single holder by identity if it is still flagged disconnected (used when a
	// morphed tile is deselected in LogonUI so it can finally leave the tile list). The flag
	// is re-checked under the list lock, so a tile revived concurrently is kept. Returns TRUE
	// if the holder was found and erased. The caller re-enumerates afterwards.
	BOOL RemoveIfDisconnected(T* holder);
	// When enabled (used by the credential provider), a card removal that hits the
	// currently selected tile keeps that tile alive in a "disconnected" state instead
	// of erasing it, so it can be revived in place when the card is re-inserted. Callers
	// that just rebuild their view on every change (e.g. the config wizard) leave this off.
	void SetReviveOnReconnect(__in BOOL fRevive);
private:
	BOOL ConnectNotificationGeneric(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount);
	BOOL ConnectNotificationBeid(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount);
	// Remove any items on the reader that are still flagged disconnected after a connect
	// (their container was not present on the re-inserted card - i.e. a different card).
	void PurgeStaleDisconnected(__in LPCTSTR szReaderName);
	BOOL CleanList();
	// Pin / unpin an item that is used after the list lock is dropped (no-op for holders
	// without AddRef). PinItem must be called with the list lock held.
	static void PinItem(T* item);
	static void UnpinItem(T* item);
	// Disconnected-tile state changes (list lock held; no-ops for holders without that state)
	// and the matching LogonUI field updates (list lock NOT held).
	static BOOL MarkItemDisconnectedIfSelected(T* item);
	static BOOL MarkItemReconnected(T* item);
	static void UpdateItemConnectionFields(T* item);
	// Release the list's reference to an erased item (detaching it from the provider first).
	static void ReleaseItem(T* item);
	CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    DWORD _dwFlags;
	std::list<T*> _CredentialList;
	CRITICAL_SECTION CriticalSection;
	BOOL _fReviveOnReconnect;

};



#include "CContainerHolderFactory.cpp"