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

#include <credentialprovider.h>

#include "helpers.h"

#include "../EIDCardLibrary/CSmartCardNotifier.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/Tracing.h"

// Forward references for classes used here.
class CEIDCredential;
class CMessageCredential;

/**
  * Main class
  */
class CEIDProvider : public ICredentialProvider, public ISmartCardConnectionNotifierRef
{
public:
	CEIDProvider(const CEIDProvider&) = delete;
	CEIDProvider& operator=(const CEIDProvider&) = delete;
    // IUnknown
    IMPL_IUNKNOWN_ADDREF_RELEASE()

    STDMETHOD (QueryInterface)(REFIID riid, void** ppv) override  // NOSONAR - API-01: signature dictated by Windows/callback API
    {
        HRESULT hr;
        if (IID_IUnknown == riid ||
            IID_ICredentialProvider == riid)
        {
            *ppv = this;
            reinterpret_cast<IUnknown*>(*ppv)->AddRef();  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
            hr = S_OK;
        }
        else
        {
            *ppv = nullptr;
            hr = E_NOINTERFACE;
        }
        return hr;
    }

    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) override;
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;

    IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext) override;
    IFACEMETHODIMP UnAdvise() override;

    IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount) override;
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;

    IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount,
                                      __out DWORD* pdwDefault,
                                      __out BOOL* pbAutoLogonWithDefault) override;
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex,
                                   __out ICredentialProviderCredential** ppcpc) override;

    friend HRESULT CEIDProvider_CreateInstance(REFIID riid, __deref_out void** ppv);

    void Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message, __in LPCTSTR szReader, __in_opt LPCTSTR szCardName, __in_opt USHORT ActivityCount) override;

    // Called by a CEIDCredential when LogonUI deselects it while it is in the disconnected
    // ("please reconnect") state. LogonUI keeps a selected tile on screen even after its card
    // is gone, so the tile can only actually leave the list once it is no longer selected:
    // here we erase it and re-enumerate so it disappears.
    void RemoveDisconnectedTile(__in CEIDCredential* pCred);

  protected:
    CEIDProvider();
    __override ~CEIDProvider();
    HRESULT Initialize();
private:
    // Ask LogonUI to re-enumerate. Takes a referenced copy of _pcpe under _csCallback and
    // calls CredentialsChanged outside the lock (safe against a concurrent UnAdvise on the
    // UI thread). Returns TRUE if a notification was actually sent.
    BOOL NotifyCredentialsChanged();



    LONG                        _cRef;                  // Reference counter.
	CMessageCredential          *_pMessageCredential;   // Our "disconnected" credential.
    ICredentialProviderEvents   *_pcpe;                    // Used to tell our owner to re-enumerate credentials.
    UINT_PTR                    _upAdviseContext = 0;   // Used to tell our owner who we are when asking to
                                                        // re-enumerate credentials.
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus = CPUS_INVALID;
	DWORD									_dwFlags = 0;
	BOOL									_fDontShowAnything;
	CContainerHolderFactory<CEIDCredential>	_CredentialList;
	CSmartCardConnectionNotifier*			_pSmartCardConnectionNotifier;
	CRITICAL_SECTION						_csCallback;  // Protects callback from destruction race (CWE-416 fix for #8); also guards _pcpe/_upAdviseContext
	BOOL									_fShuttingDown;  // Flag to prevent callback during shutdown
};
