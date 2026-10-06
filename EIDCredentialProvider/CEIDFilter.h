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


#pragma once

#include <Windows.h>
#include <credentialprovider.h>
#include <new>
#include "helpers.h"

/**
  * Used to filter password credential when smart card logon is mandatory
  */
class CEIDFilter : public ICredentialProviderFilter
{
public:
	CEIDFilter(const CEIDFilter&) = delete;
	CEIDFilter& operator=(const CEIDFilter&) = delete;
	CEIDFilter();
	// IUnknown
    IMPL_IUNKNOWN_ADDREF_RELEASE()

    STDMETHOD (QueryInterface)(REFIID riid, void** ppv) override  // NOSONAR - CAST-01: COM QueryInterface requires void**
    {
        HRESULT hr;
        if (IID_IUnknown == riid ||
            IID_ICredentialProviderFilter == riid)
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

    IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, GUID *rgclsidProviders, BOOL *rgbAllow, DWORD cProviders) override;
	IFACEMETHODIMP UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut) override;
    
private:
	LONG                        _cRef;                  // Reference counter.
};



// Boilerplate method to create an instance of our provider.
HRESULT CEIDFilter_CreateInstance(REFIID riid, void** ppv)  // NOSONAR - CAST-01: COM requires void**
{
    HRESULT hr;
	if (riid != IID_ICredentialProviderFilter) return E_NOINTERFACE;
    // C++17 init-statement: pFilter is only used within this if block
    if (CEIDFilter* pFilter = new (std::nothrow) CEIDFilter())  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
    {
        hr = pFilter->QueryInterface(riid, ppv);
        pFilter->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

