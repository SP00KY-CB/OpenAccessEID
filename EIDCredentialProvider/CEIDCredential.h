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
// CEIDCredential is our implementation of ICredentialProviderCredential.
// ICredentialProviderCredential is what LogonUI uses to let a credential
// provider specify what a user tile looks like and then tell it what the
// user has entered into the tile.  ICredentialProviderCredential is also
// responsible for packaging up the users credentials into a buffer that
// LogonUI then sends on to LSA.

#pragma once

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>

#include "helpers.h"
#include "Dll.h"
#include "EIDCredentialProvider.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CContainer.h"

class CEIDProvider;

/**
  * Used to represent a credential
  */
class CEIDCredential : public ICredentialProviderCredential
{
public:
	CEIDCredential(const CEIDCredential&) = delete;
	CEIDCredential& operator=(const CEIDCredential&) = delete;
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

    HRESULT Initialize();
    explicit CEIDCredential(CContainer* container);
	void SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags);
    virtual ~CEIDCredential();
	CContainer* GetContainer() const;

	// Used by CContainerHolderFactory to keep the selected tile alive across a card
	// removal/re-insertion. IsSelected() reports whether LogonUI has this tile zoomed.
	// The tile morphs between the PIN prompt and a "please reconnect your smart card"
	// message in two steps:
	//  - MarkDisconnectedIfSelected() / MarkReconnected() change the state only (no call into
	//    LogonUI) and are called with the factory's list lock held. MarkDisconnectedIfSelected
	//    sets the flag only if the tile is still selected (atomically with SetDeselected) and
	//    returns FALSE when it is not (the caller then erases it); MarkReconnected returns
	//    TRUE if it cleared the flag.
	//  - UpdateConnectionFields() then pushes the current state to LogonUI (the reconnect
	//    message, the held-PIN message, or the PIN prompt); it is called with no lock held,
	//    and pushes again if the state changed while it was pushing.
	// MarkReconnected also releases a PIN hold: re-inserting the card starts over.
	BOOL IsSelected() const;
	BOOL IsDisconnected() const;
	BOOL MarkDisconnectedIfSelected();
	BOOL MarkReconnected();
	void UpdateConnectionFields();
	// Back-reference to the owning provider so the tile can ask to be removed from the tile
	// list once LogonUI deselects it in the disconnected ("please reconnect") state.
	void SetProvider(__in CEIDProvider* pProvider);
  private:
	// Caller must hold _csFields.
	void SecureClearPin();
	// Returns an AddRef'd copy of _pCredProvCredentialEvents (or nullptr), taken under
	// _csFields, so the caller can call into LogonUI with the lock dropped. Caller Releases.
	ICredentialProviderCredentialEvents* GetEventsAddRef();
	// Whether the "view certificate" command link may be shown in the current scenario.
	BOOL IsCertificateLinkAllowed() const;

	// Wrong-PIN protection (policy PinAttemptsReserved): once a wrong PIN leaves the card with
	// PinAttemptsReserved or fewer PIN attempts, PIN entry is held - the PIN box and submit
	// button hidden and the message saying why - until the card is re-inserted, so typing
	// cannot use up the card's last attempts and block it. Each re-insertion then allows one
	// attempt. Re-inserting the card (MarkReconnected; a tile created for a newly inserted card
	// starts afresh) or a successful logon releases the hold.
	void RecordWrongPin(NTSTATUS ntsSubstatus);
	// Caller must hold _csFields. TRUE while PIN entry is held; then also fills pwszMessage,
	// when given, with the text shown in place of the PIN box.
	BOOL GetPinEntryBlock(PWSTR pwszMessage, size_t cchMessage) const;
	BOOL IsPinEntryBlocked() const;

    LONG                                  _cRef;

    CREDENTIAL_PROVIDER_USAGE_SCENARIO    _cpus = CPUS_INVALID; // The usage scenario for which we were enumerated.
	DWORD								  _dwFlags = 0;

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR  _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];  // An array holding the type   // NOSONAR - LSASS-01: C-style array required by Win32/COM API
                                                                                        // and name of each field in 
                                                                                        // the tile.

    FIELD_STATE_PAIR                      _rgFieldStatePairs[SFI_NUM_FIELDS];           // An array holding the state   // NOSONAR - LSASS-01: C-style array required by Win32/COM API
                                                                                        // of each field in the tile.

    PWSTR                                 _rgFieldStrings[SFI_NUM_FIELDS];              // An array holding the string   // NOSONAR - LSASS-01: C-style array required by Win32/COM API
                                                                                        // value of each field. This is 
                                                                                        // different from the name of 
                                                                                        // the field held in 
                                                                                        // _rgCredProvFieldDescriptors.
    ICredentialProviderCredentialEvents* _pCredProvCredentialEvents;
	CContainer* _pContainer;
	BOOL        _fSelected;      // TRUE while LogonUI has this tile zoomed (between SetSelected/SetDeselected).
	BOOL        _fDisconnected;  // TRUE while the card is absent and the tile shows the reconnect prompt.
	CEIDProvider* _pProvider;   // Owning provider; used to drop this tile when deselected while disconnected.
	BOOL        _fPinHeld = FALSE;         // PIN entry held until the card is re-inserted (card nearly blocked).
	DWORD       _dwCardTriesLeft = 0;      // PIN attempts the card reported left when the hold started.
	DWORD       _dwFieldStateGen = 0;      // Bumped whenever the disconnected flag or the hold changes; see UpdateConnectionFields.
	// Guards _rgFieldStrings, _pCredProvCredentialEvents, _fSelected, _fDisconnected,
	// _pProvider and the PIN hold against the smart-card notifier thread (the disconnect morph /
	// revive) racing LogonUI's UI thread. May be taken while the factory's list lock is held
	// (that is the only nesting), never the other way round; never held across a call into
	// LogonUI or into the provider/tile list.
	mutable CRITICAL_SECTION _csFields;

};
