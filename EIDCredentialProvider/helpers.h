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
// Helper functions for copying parameters and packaging the buffer
// for GetSerialization.

#pragma once
#include <Windows.h>
#include "common.h"
#include "../EIDCardLibrary/Tracing.h"

// Standard IUnknown AddRef/Release implementation for COM objects.
// Assumes the class has a LONG _cRef member. Place in the public section of the class.
#define IMPL_IUNKNOWN_ADDREF_RELEASE()                                      \
    STDMETHOD_(ULONG, AddRef)()                                             \
    {                                                                       \
        LONG cRef = InterlockedIncrement(&_cRef);                           \
        EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"AddRef %p (%ld)", this, cRef);   \
        return cRef;                                                        \
    }                                                                       \
    STDMETHOD_(ULONG, Release)()                                            \
    {                                                                       \
        LONG cRef = InterlockedDecrement(&_cRef);                           \
        EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"Release %p (%ld)", this, cRef);   \
        if (!cRef)                                                          \
        {                                                                   \
            delete this;                                                    \
        }                                                                   \
        return cRef;                                                        \
    }

// Standard ICredentialProviderCredential QueryInterface implementation.
// Both CEIDCredential and CMessageCredential implement this identically.
#define IMPL_CREDENTIAL_QUERYINTERFACE()                                    \
    STDMETHOD(QueryInterface)(REFIID riid, void** ppv) override             \
    {                                                                       \
        HRESULT hr;                                                         \
        if (ppv != nullptr)                                                 \
        {                                                                   \
            if (IID_IUnknown == riid ||                                     \
                IID_ICredentialProviderCredential == riid)                   \
            {                                                               \
                *ppv = static_cast<IUnknown*>(this);                        \
                reinterpret_cast<IUnknown*>(*ppv)->AddRef();                \
                hr = S_OK;                                                  \
            }                                                               \
            else                                                            \
            {                                                               \
                *ppv = nullptr;                                             \
                hr = E_NOINTERFACE;                                         \
            }                                                               \
        }                                                                   \
        else                                                                \
        {                                                                   \
            hr = E_INVALIDARG;                                              \
        }                                                                   \
        return hr;                                                          \
    }

//makes a copy of a field descriptor using CoTaskMemAlloc
HRESULT FieldDescriptorCoAllocCopy(
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
    );

//makes a copy of a field descriptor on the normal heap
HRESULT FieldDescriptorCopy(
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
    );

//creates a UNICODE_STRING from a NULL-terminated string
HRESULT UnicodeStringInitWithString(
    PWSTR pwz, 
    UNICODE_STRING* pus
    );


//encrypt a password (if necessary) and copy it; if not, just copy it
HRESULT ProtectIfNecessaryAndCopyPassword(
    PWSTR pwzPassword,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	DWORD dwFlags,
    PWSTR* ppwzProtectedPassword
    );

void ShowCancelForcePolicyWizard(HWND hWnd);