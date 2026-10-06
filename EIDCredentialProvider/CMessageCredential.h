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
//

#pragma once
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>

#include "helpers.h"
#include "Dll.h"
#include "EIDCredentialProvider.h"
#include <utility>

enum class CMessageCredentialStatus
{
	Idle,
	Reading,
	EndReading,
	Error,
};

/**
  * Used to display message when no credential is available
  */
class CMessageCredential : public ICredentialProviderCredential
{
public:
	CMessageCredential(const CMessageCredential&) = delete;
	CMessageCredential& operator=(const CMessageCredential&) = delete;
    // IUnknown
    IMPL_IUNKNOWN_ADDREF_RELEASE()
    IMPL_CREDENTIAL_QUERYINTERFACE()

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce) override;
    IFACEMETHODIMP UnAdvise() override;

    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon) override;
    IFACEMETHODIMP SetDeselected() override;

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                 CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz) override;
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) override;
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel) override;
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem) override;
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem) override;
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) override;

    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz) override;
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked) override;
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) override;
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID) override;

    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                    PWSTR* ppwszOptionalStatusText,
                                    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus,
                                NTSTATUS ntsSubstatus,
                                PWSTR* ppwszOptionalStatusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

    HRESULT Initialize(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                       const FIELD_STATE_PAIR* rgfsp,
                       PCWSTR szMessage);
    CMessageCredential();

    virtual ~CMessageCredential();
	void IncreaseSmartCardCount()
	{
		_dwSmartCardCount++;
	}
	void DecreaseSmartCardCount()
	{
		_dwSmartCardCount--;
	}
	void SetStatus(CMessageCredentialStatus dwStatus)
	{
		if (dwStatus == CMessageCredentialStatus::EndReading)  // NOSONAR - ENUM-01: explicit enum qualification retained for clarity
		{
			if (_dwSmartCardCount)
			{
				_dwStatus = CMessageCredentialStatus::Error;
			}
			else
			{
				_dwStatus = CMessageCredentialStatus::Idle;
			}
		}
		else
		{
			_dwStatus = dwStatus;
		}
	}
	void SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,DWORD dwFlags)
	{
		_cpus = cpus;
		_dwFlags = dwFlags;
	}

	CMessageCredentialStatus GetStatus() const
	{
		return _dwStatus;
	}

  private:
    LONG                                    _cRef;
    
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR    _rgCredProvFieldDescriptors[SMFI_NUM_FIELDS];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API   // An array holding the 
                                                                                            // type and name of each 
                                                                                            // field in the tile.
    
    FIELD_STATE_PAIR                        _rgFieldStatePairs[SMFI_NUM_FIELDS];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API            // An array holding the 
                                                                                            // state of each field in 
                                                                                            // the tile.

    PWSTR                                   _rgFieldStrings[SMFI_NUM_FIELDS];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API               // An array holding the 
                                                                                            // string value of each 
                                                                                            // field. This is different 
                                                                                            // from the name of the 
                                                                                            // field held in 
                                                                                            // _rgCredProvFieldDescriptors.
	ICredentialProviderCredentialEvents*	_pCredProvCredentialEvents;
	DWORD									_dwSmartCardCount;
	CMessageCredentialStatus				_dwStatus;
	CMessageCredentialStatus				_dwOldStatus;
	CREDENTIAL_PROVIDER_USAGE_SCENARIO    _cpus = CPUS_INVALID; // The usage scenario for which we were enumerated.
	DWORD								  _dwFlags = 0;
};

