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
// Standard dll required functions and class factory implementation.

#include <Windows.h>
#include <Unknwn.h>
#include <credentialprovider.h>
#include <new>

#include "Dll.h"
#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/Registration.h"
#include "../EIDCardLibrary/CommonManifest.h"

static LONG g_cRef = 0;   // NOSONAR - RUNTIME-01: Global DLL reference count, modified at runtime

// IClassFactory ///////////////////////////////////////////////////////////////////////

extern HRESULT CEIDProvider_CreateInstance(REFIID riid, void** ppv);  // NOSONAR - CAST-01: COM requires void**
extern HRESULT CEIDFilter_CreateInstance(REFIID riid, void** ppv);  // NOSONAR - CAST-01: COM requires void**

HINSTANCE g_hinst = nullptr;   // NOSONAR - RUNTIME-01: HINSTANCE set by Windows at DLL load

class CClassFactory : public IClassFactory
{
  public:
    // IUnknown
    STDMETHOD_(ULONG, AddRef)()
    {
        return InterlockedIncrement(&_cRef);
    }

    STDMETHOD_(ULONG, Release)()
    {
        LONG cRef = InterlockedDecrement(&_cRef);
        if (cRef == 0)
        {
            delete this;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
        }
        return cRef;
    }

    STDMETHOD (QueryInterface)(REFIID riid, void** ppv)  // NOSONAR - CAST-01: COM QueryInterface requires void**
    {
        HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
        if (ppv != nullptr)
        {
            if (IID_IClassFactory == riid || IID_IUnknown == riid)
            {
                *ppv = static_cast<IUnknown*>(this);
                reinterpret_cast<IUnknown*>(*ppv)->AddRef();  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
                hr = S_OK;
            }
            else
            {
                *ppv = nullptr;
                hr = E_NOINTERFACE;
            }
        }
        else
        {
            hr = E_INVALIDARG;
        }
        return hr;
    }

    // IClassFactory
    STDMETHOD (CreateInstance)(IUnknown* pUnkOuter, REFIID riid, void** ppv)  // NOSONAR - CAST-01: COM CreateInstance requires void**
    {
        HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
        if (!pUnkOuter)
        {
            if (IID_ICredentialProviderFilter == riid)
			{
				hr = CEIDFilter_CreateInstance(riid, ppv);
			}
			else
			{
				hr = CEIDProvider_CreateInstance(riid, ppv);
			}
        }
        else
        {
            hr = CLASS_E_NOAGGREGATION;
        }
        return hr;
    }

    STDMETHOD (LockServer)(BOOL bLock)
    {
        if (bLock)
        {
            DllAddRef();
        }
        else
        {
            DllRelease();
        }
        return S_OK;
    }

  private:
     CClassFactory() : _cRef(1) {}  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
    ~CClassFactory() = default;

  private:
    LONG _cRef;

    friend HRESULT CClassFactory_CreateInstance(REFCLSID rclsid, REFIID riid, void** ppv);  // NOSONAR - CAST-01: COM requires void**
};

HRESULT CClassFactory_CreateInstance(REFCLSID rclsid, REFIID riid, void** ppv)  // NOSONAR - CAST-01: COM requires void**
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    if (CLSID_CEIDProvider == rclsid )
    {
        auto pcf = new (std::nothrow) CClassFactory;  // NOSONAR - COM-01: COM class factory requires heap allocation
        if (pcf)
        {
            hr = pcf->QueryInterface(riid, ppv);
            pcf->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    return hr;
}

// DLL Functions ///////////////////////////////////////////////////////////////////////

BOOL WINAPI DllMain(
    HINSTANCE hinstDll,
    DWORD dwReason,
    LPVOID pReserved  // NOSONAR - API-01: signature dictated by Windows/callback API
    )
{
    UNREFERENCED_PARAMETER(pReserved);

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDll);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    default:
        break;
    }

    g_hinst = hinstDll;
    return TRUE;

}

void DllAddRef()
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease()
{
    InterlockedDecrement(&g_cRef);
}

// DLL entry point.
STDAPI DllCanUnloadNow()
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    if (g_cRef > 0)
    {
        hr = S_FALSE;   // cocreated objects still exist, don't unload
    }
    else
    {
        hr = S_OK;      // refcount is zero, ok to unload
    }

    return hr;
}

// DLL entry point.
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)  // NOSONAR - CAST-01: COM DLL entry point requires void**
{
    return CClassFactory_CreateInstance(rclsid, riid, ppv);
}

