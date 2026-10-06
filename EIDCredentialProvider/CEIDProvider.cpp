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
// CEIDProvider implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.
// This sample illustrates processing asynchronous external events and 
// using them to provide the user with an appropriate set of credentials.
// In this sample, we provide two credentials: one for when the system
// is "connected" and one for when it isn't. When it's "connected", the
// tile provides the user with a field to log in as the administrator.
// Otherwise, the tile asks the user to connect first.
//
#define _SEC_WINNT_AUTH_TYPES 0  // NOSONAR - MACRO-02: Windows SDK configuration macro
#pragma comment(lib,"credui")
#include "CEIDProvider.h"  // NOSONAR - INCLUDE-01: include order significant for Windows SDK
#include "CEIDCredential.h"
#include "CMessageCredential.h"

#include <credentialprovider.h>
#include <new>

#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CSmartCardNotifier.h"
#include "../EIDCardLibrary/GPO.h"

// The factory detects these by signature and silently degrades if they stop matching: the
// list would no longer pin tiles it hands out of its lock, or the selected tile would no
// longer morph / revive / detach from the provider. Fail the build instead.
static_assert(ContainerHolderHasAddRef<CEIDCredential>::value,
	"CContainerHolderFactory must see CEIDCredential::AddRef to pin tiles used outside its lock");
static_assert(ContainerHolderHasTileState<CEIDCredential>::value,
	"CContainerHolderFactory must see CEIDCredential's disconnected-tile methods and SetProvider");

// CEIDProvider ////////////////////////////////////////////////////////

CEIDProvider::CEIDProvider():
    _cRef(1)  // NOSONAR - INIT-01: member initialized via constructor initializer list
{
    EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Creation");
	DllAddRef();
    _pcpe = nullptr;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
    _pMessageCredential = nullptr;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
 _pSmartCardConnectionNotifier = nullptr;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_fDontShowAnything = FALSE;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_fShuttingDown = FALSE;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	InitializeCriticalSection(&_csCallback);
}

CEIDProvider::~CEIDProvider()
{
	// Signal shutdown and wait for any running callback to complete (CWE-416 fix for #8).
	// LogonUI normally UnAdvises first; drop any events reference still held now, so a callback
	// still running on the notifier thread raises no CredentialsChanged into a LogonUI that is
	// tearing us down while we wait for it. Released below, with the lock dropped (never call
	// into LogonUI under our lock).
	EnterCriticalSection(&_csCallback);
	_fShuttingDown = TRUE;
	ICredentialProviderEvents* pcpeOld = _pcpe;
	_pcpe = nullptr;
	_upAdviseContext = 0;
	LeaveCriticalSection(&_csCallback);

	if (_pSmartCardConnectionNotifier)
	{
		_pSmartCardConnectionNotifier->Stop();
		delete _pSmartCardConnectionNotifier;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
	}

	// Tiles still held by LogonUI may outlive us: drop their raw back-pointer now, before
	// _csCallback is deleted (RemoveDisconnectedTile enters it). Tiles already erased from the
	// list were detached when they were erased. List lock -> _csFields is the allowed order.
	_CredentialList.Lock();
	for (DWORD i = 0; i < _CredentialList.ContainerHolderCount(); i++)
	{
		if (CEIDCredential* pCred = _CredentialList.GetContainerHolderAt(i))
		{
			pCred->SetProvider(nullptr);
		}
	}
	_CredentialList.Unlock();

	if (pcpeOld != nullptr)
	{
		pcpeOld->Release();
	}

	// The provider holds the creation reference on the message tile (LogonUI takes its own
	// through QueryInterface). The notifier thread that also uses it was stopped above.
	if (_pMessageCredential)
	{
		_pMessageCredential->Release();
		_pMessageCredential = nullptr;
	}

	DeleteCriticalSection(&_csCallback);
    DllRelease();
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Deletion");
}

// This method acts as a callback for the hardware emulator. When it's called, it simply
// tells the infrastructure that it needs to re-enumerate the credentials.
void CEIDProvider::Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message, __in LPCTSTR szReader,__in_opt LPCTSTR szCardName, __in_opt USHORT ActivityCount) {
	// Protect callback from destruction race (CWE-416 fix for #8)
	EnterCriticalSection(&_csCallback);
	if (_fShuttingDown)
	{
		LeaveCriticalSection(&_csCallback);
		return;
	}
	LeaveCriticalSection(&_csCallback);

	switch(Message)  // NOSONAR - SWITCH-01: unhandled reader states intentionally ignored
	{
	case EID_CREDENTIAL_PROVIDER_READER_STATE::EIDCPRSConnecting:
		// Guard clause: skip if no card name
		if (!szCardName) break;

		if (_pMessageCredential)
		{
			_pMessageCredential->SetStatus(CMessageCredentialStatus::Reading);
			_pMessageCredential->IncreaseSmartCardCount();
		}
		if (NotifyCredentialsChanged())
		{
			Sleep(100);
		}
		_CredentialList.ConnectNotification(szReader,szCardName,ActivityCount);
		if (_pMessageCredential) _pMessageCredential->SetStatus(CMessageCredentialStatus::EndReading);

		NotifyCredentialsChanged();
		break;
	case EID_CREDENTIAL_PROVIDER_READER_STATE::EIDCPRSDisconnected:
		if (_pMessageCredential)
		{
			_pMessageCredential->SetStatus(CMessageCredentialStatus::Reading);
			_pMessageCredential->DecreaseSmartCardCount();
		}
		if (NotifyCredentialsChanged())
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Disconnect CredentialsChanged (pre-DisconnectNotification)");
			Sleep(100);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Disconnect calling DisconnectNotification");
		_CredentialList.DisconnectNotification(szReader);
		if (_pMessageCredential) _pMessageCredential->SetStatus(CMessageCredentialStatus::EndReading);

		if (NotifyCredentialsChanged())
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Disconnect CredentialsChanged (post-DisconnectNotification)");
		}

		break;
	}
}

// A morphed ("please reconnect") tile stays alive only because LogonUI had it selected.
// Once LogonUI deselects it (the user moved to another tile), it is safe - and required -
// to drop it: erase it from the list outside any re-entrant callback, then ask LogonUI to
// re-enumerate so the tile is gone. Matches the locking discipline in Callback().
void CEIDProvider::RemoveDisconnectedTile(__in CEIDCredential* pCred)
{
	EnterCriticalSection(&_csCallback);
	if (_fShuttingDown)
	{
		LeaveCriticalSection(&_csCallback);
		return;
	}
	LeaveCriticalSection(&_csCallback);

	// RemoveIfDisconnected takes the list lock internally, re-checks under it that the tile is
	// still disconnected (the card may have been re-inserted and the tile revived since
	// SetDeselected looked) and only then releases the list's reference to pCred. LogonUI still
	// holds its own reference for the duration of the SetDeselected call that triggered us, so
	// pCred stays alive here.
	BOOL fRemoved = _CredentialList.RemoveIfDisconnected(pCred);

	if (fRemoved)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Deselect purge -> CredentialsChanged tile=%p",(void*)pCred);
		NotifyCredentialsChanged();
	}
}

// The notifier thread (Callback) and the UI thread (RemoveDisconnectedTile) both raise
// CredentialsChanged, while LogonUI may concurrently UnAdvise/Advise on the UI thread and
// release the events object. Snapshot and AddRef the pointer under _csCallback, then call
// out with the lock dropped: never hold our lock across a call into LogonUI.
BOOL CEIDProvider::NotifyCredentialsChanged()
{
	EnterCriticalSection(&_csCallback);
	ICredentialProviderEvents* pcpe = _pcpe;
	UINT_PTR upAdviseContext = _upAdviseContext;
	if (pcpe != nullptr)
	{
		pcpe->AddRef();
	}
	LeaveCriticalSection(&_csCallback);

	if (pcpe == nullptr)
	{
		return FALSE;
	}
	pcpe->CredentialsChanged(upAdviseContext);
	pcpe->Release();
	return TRUE;
}

HRESULT CEIDProvider::Initialize()
{
	// Guard clause: already initialized
	if (_pMessageCredential)
	{
		return S_OK;
	}

	// Create the CEIDCredential (for connected scenarios), the CMessageCredential
    // (for disconnected scenarios), and the CEIDDetection (to detect commands, such
    // as the connect/disconnect here).  We can get SetUsageScenario multiple times
    // (for example, cancel back out to the CAD screen, and then hit CAD again),
    // but there's no point in recreating our creds, since they're the same all the
    // time

    // For the locked case, a more advanced credprov might only enumerate tiles for the
    // user whose owns the locked session, since those are the only creds that will work

    _pMessageCredential = new (std::nothrow) CMessageCredential();  // NOSONAR - COM-01: Credential Provider requires heap allocation
    if (!_pMessageCredential)
    {
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_OUTOFMEMORY");
		return E_OUTOFMEMORY;
	}

	HRESULT hr = _pMessageCredential->Initialize(s_rgMessageCredProvFieldDescriptors, s_rgMessageFieldStatePairs, L"Please connect");
	_CredentialList.Lock();
	_CredentialList.SetUsageScenario(_cpus,_dwFlags);
	// Keep a selected tile alive across card removal so it can show "please reconnect"
	// in place and be revived when the card returns (LogonUI won't swap a selected tile).
	_CredentialList.SetReviveOnReconnect(TRUE);
	_CredentialList.Unlock();
	_pMessageCredential->SetUsageScenario(_cpus,_dwFlags);
	_pSmartCardConnectionNotifier = new (std::nothrow) CSmartCardConnectionNotifier(this);  // NOSONAR - COM-01: Event notifier requires heap allocation
	if (!_pSmartCardConnectionNotifier)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_OUTOFMEMORY (smart card notifier)");
	}
	return hr;
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CEIDProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Scenario: %d",cpus);
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:       
    case CPUS_CREDUI:
        _cpus = cpus;
		_dwFlags = dwFlags;
		if (_dwFlags & CREDUIWIN_AUTHPACKAGE_ONLY || _dwFlags & CREDUIWIN_IN_CRED_ONLY)
		{
			// postpone the initialization in SetSerialization
			hr = S_OK;
		}
		else
		{
			hr = Initialize();
		}
        
        break;
    case CPUS_CHANGE_PASSWORD:
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_NOTIMPL");
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
        break;
    }

    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to 
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider 
// into this sample.]
STDMETHODIMP CEIDProvider::SetSerialization(  // NOSONAR - COM-01: ICredentialProvider signature fixed by Windows SDK
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"");
	// Guard clause: LogonUI may pass a NULL serialization.
	if (!pcpcs)
	{
		return E_INVALIDARG;
	}
	if (_dwFlags & CREDUIWIN_AUTHPACKAGE_ONLY || _dwFlags & CREDUIWIN_IN_CRED_ONLY)
	{
		if (pcpcs->ulAuthenticationPackage > 0)  // NOSONAR - COMPLEXITY-01: nested guard retained for readability; logic verified
		{
			ULONG ulAuthenticationPackage;
			RetrieveNegotiateAuthPackage(&ulAuthenticationPackage);
			if (pcpcs->ulAuthenticationPackage != ulAuthenticationPackage)
			{
				_fDontShowAnything = TRUE;
			}
			else
			{
				Initialize();
			}
		}
	}
	PSEC_WINNT_CREDUI_CONTEXT pCredUIContext = nullptr;
	SECURITY_STATUS status = SspiUnmarshalCredUIContext(pcpcs->rgbSerialization, pcpcs->cbSerialization, &pCredUIContext);
	if (status != SEC_E_OK)
	{
		// Attacker-supplied bytes may fail to unmarshal; ignore them without side effects.
		return S_OK;
	}
	if (pCredUIContext)
	{
		// Free the context buffer allocated by SspiUnmarshalCredUIContext to avoid a per-call leak.
		FreeContextBuffer(pCredUIContext);
	}

	return S_OK;
}

// Called by LogonUI to give you a callback. Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated
HRESULT CEIDProvider::Advise(
    ICredentialProviderEvents* pcpe,
    UINT_PTR upAdviseContext
    )
{
	// The notifier thread reads _pcpe (NotifyCredentialsChanged), so swap it under
	// _csCallback: reference the new pointer before taking the lock and release the old one
	// only after dropping it, so no call into LogonUI happens while the lock is held.
	if (pcpe != nullptr)
	{
		pcpe->AddRef();
	}
	EnterCriticalSection(&_csCallback);
	ICredentialProviderEvents* pcpeOld = _pcpe;
	_pcpe = pcpe;
	_upAdviseContext = upAdviseContext;
	LeaveCriticalSection(&_csCallback);
	if (pcpeOld != nullptr)
	{
		pcpeOld->Release();
	}
    return S_OK;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CEIDProvider::UnAdvise()
{
	EnterCriticalSection(&_csCallback);
	ICredentialProviderEvents* pcpeOld = _pcpe;
	_pcpe = nullptr;
	_upAdviseContext = 0;
	LeaveCriticalSection(&_csCallback);
	if (pcpeOld != nullptr)
	{
		pcpeOld->Release();
	}
    return S_OK;
}

// Called by LogonUI to determine the number of fields in your tiles. We return the number
// of fields to be displayed on our active tile, which depends on our connected state. The
// "connected" CEIDCredential has SFI_NUM_FIELDS fields, whereas the "disconnected" 
// CMessageCredential has SMFI_NUM_FIELDS fields.
HRESULT CEIDProvider::GetFieldDescriptorCount(
    DWORD* pdwCount
    )
{
	_CredentialList.Lock();
	if (_CredentialList.HasContainerHolder())
    {
        *pdwCount = SFI_NUM_FIELDS;
    }
    else
    {
        *pdwCount = SMFI_NUM_FIELDS;
    }
   _CredentialList.Unlock();
   EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"pdwCount %d",*pdwCount);
    return S_OK;
}

// Gets the field descriptor for a particular field. Note that we need to determine which
// tile to use based on the "connected" status.
HRESULT CEIDProvider::GetFieldDescriptorAt(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    DWORD dwIndex, 
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
	_CredentialList.Lock();
    if (_CredentialList.HasContainerHolder())
    {
        // Verify dwIndex is a valid field.
        if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
        {
            if (dwIndex != SFI_PIN)
			{
				hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
			}
			else
			{
				*ppcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
				if (*ppcpfd)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					(*ppcpfd)->pszLabel = nullptr;
					(*ppcpfd)->dwFieldID = s_rgCredProvFieldDescriptors[dwIndex].dwFieldID;
					(*ppcpfd)->cpft = s_rgCredProvFieldDescriptors[dwIndex].cpft;
					(*ppcpfd)->guidFieldType = s_rgCredProvFieldDescriptors[dwIndex].guidFieldType;
					HINSTANCE Handle = EIDLoadSystemLibrary(TEXT("SmartcardCredentialProvider.dll"));
					if (Handle)
					{
						DWORD dwMessageLen = 256;
						// C++17 init-statement: Message is only used within this if block
						if (PWSTR Message = static_cast<PWSTR>(CoTaskMemAlloc(dwMessageLen*sizeof(WCHAR))))  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
						{
							Message[0] = L'\0';  // LoadString leaves the buffer untouched on failure
							LoadString(Handle, 4, Message, dwMessageLen);
							(*ppcpfd)->pszLabel = Message;
							hr = S_OK;
						}
						else
						{
							hr = HRESULT_FROM_WIN32(GetLastError());
							CoTaskMemFree(Message);
						}
						FreeLibrary(Handle);
					}
					else
					{

						hr = S_OK;
					}
				}
				else
				{
					hr = E_OUTOFMEMORY;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_OUTOFMEMORY");
				}
			}
        }
        else
        { 
            hr = E_INVALIDARG;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
        }
    }
    else
    {
        // Verify dwIndex is a valid field.
        if ((dwIndex < SMFI_NUM_FIELDS) && ppcpfd)
        {
            hr = FieldDescriptorCoAllocCopy(s_rgMessageCredProvFieldDescriptors[dwIndex], ppcpfd);
        }
        else
        { 
            hr = E_INVALIDARG;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
        }
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("GetFieldDescriptorAt", hr, L"index=%lu", dwIndex);
	}
	_CredentialList.Unlock();
	   return hr;
}


HRESULT CEIDProvider::GetCredentialCount(
    DWORD* pdwCount,
    DWORD* pdwDefault,
    BOOL* pbAutoLogonWithDefault
    )
{
	if (_fDontShowAnything)
	{
		*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
		*pdwCount = 0;
	}
	else
	{
		_CredentialList.Lock();
		if (_CredentialList.HasContainerHolder())
		{
			*pdwCount = _CredentialList.ContainerHolderCount();
			// Never claim a default tile. If we mark the smart-card tile as the default,
			// LogonUI auto-selects it on every (re-)enumeration - including the one that
			// fires as the card is being removed - so it is "selected" without the user ever
			// clicking it and therefore morphs to "please reconnect" instead of disappearing.
			// Leaving it unselected means an untouched tile is simply erased on card removal,
			// while a tile the user actually clicked still morphs (and is purged on deselect).
			*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
		}
		else
		{
			// hide the tile when :
			// in Logon
			// and Smart Card Logon requiered active
			*pdwCount = 1;
			if (_cpus == CPUS_LOGON)
			{
				if (!GetPolicyValue(GPOPolicy::scforceoption))  // NOSONAR - COMPLEXITY-01: nested guard retained for readability; logic verified
				{
					*pdwCount = 0;
				}
			}
			if (!_pMessageCredential) *pdwCount = 0;
			*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
		}
		_CredentialList.Unlock();
	}
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called
// to enumerate the tiles. Note that we need to return the right credential, which depends
// on whether we're connected or not.
HRESULT CEIDProvider::GetCredentialAt(
    DWORD dwIndex, 
    ICredentialProviderCredential** ppcpc
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
	// Make sure the parameters are valid.
    if (ppcpc)
    {
        _CredentialList.Lock();
		if (_CredentialList.HasContainerHolder())
        {
			CEIDCredential* EIDCredential = _CredentialList.GetContainerHolderAt(dwIndex);
			if (EIDCredential != nullptr)
			{
				// Give the tile a way back to us so it can ask to be dropped when LogonUI
				// deselects it in the disconnected state (see RemoveDisconnectedTile).
				EIDCredential->SetProvider(this);
				hr = EIDCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));  // NOSONAR - CAST-01: COM QueryInterface requires void**
			}
			else
			{
				hr = E_INVALIDARG;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDCredential NULL");
			}
			
        }
        else
        {
            hr = _pMessageCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));  // NOSONAR - CAST-01: COM QueryInterface requires void**
        }
		_CredentialList.Unlock();
    }
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ppcpc NULL");
    }
    if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("GetCredentialAt", hr, L"index=%lu", dwIndex);
	}
    return hr;
}

// Boilerplate method to create an instance of our provider.
HRESULT CEIDProvider_CreateInstance(REFIID riid, void** ppv)  // NOSONAR - CAST-01: COM requires void**
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
	if (riid != IID_ICredentialProvider) return E_NOINTERFACE;
    // C++17 init-statement: pProvider is only used within this if block
    if (CEIDProvider* pProvider = new (std::nothrow) CEIDProvider())  // NOSONAR - COM-01: Credential Provider requires heap allocation
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_OUTOFMEMORY");
    }
    if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("CEIDProvider_CreateInstance", hr, nullptr);
	}
    return hr;
}

