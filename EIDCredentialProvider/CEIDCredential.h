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
	//    message, the wrong-PIN countdown, or the PIN prompt); it is called with no lock held,
	//    and pushes again if the state changed while it was pushing.
	// MarkReconnected also resets the wrong-PIN countdown: re-inserting the card starts over.
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

	// Wrong-PIN countdown. After EID_PIN_FREE_ATTEMPTS wrong PINs, each further wrong PIN
	// hides the PIN box and submit button for EID_PIN_THROTTLE_SECONDS while the message
	// counts down; a thread-pool timer ticks it every second (one-shot, re-armed by each tick
	// so ticks never overlap) and holds a reference to the tile until its last tick.
	// Re-inserting the card resets it (MarkReconnected; a tile created for a newly inserted
	// card starts at zero), and so does a successful logon.
	void RecordWrongPin();
	// Caller must hold _csFields. 0 when no countdown is running.
	DWORD PinThrottleSecondsLeft() const;
	BOOL IsPinThrottled() const;
	static VOID CALLBACK PinThrottleTimerCallback(PTP_CALLBACK_INSTANCE pInstance, PVOID pvContext, PTP_TIMER pTimer);
	void OnPinThrottleTick(PTP_TIMER pTimer);

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
	DWORD       _dwWrongPinCount = 0;      // Wrong PINs since the card was inserted (or the last success).
	ULONGLONG   _ullPinThrottleEnd = 0;    // GetTickCount64() at which the countdown ends; 0 = none.
	PTP_TIMER   _pPinThrottleTimer = nullptr;  // Ticks the countdown; non-null while it holds a reference.
	DWORD       _dwFieldStateGen = 0;      // Bumped whenever the disconnected flag or the countdown starts/stops; see UpdateConnectionFields.
	// Guards _rgFieldStrings, _pCredProvCredentialEvents, _fSelected, _fDisconnected,
	// _pProvider and the wrong-PIN countdown state against the smart-card notifier thread (the
	// disconnect morph / revive) and the countdown timer racing LogonUI's UI thread. May be
	// taken while the factory's list lock is held (that is the only nesting), never the other
	// way round; never held across a call into LogonUI or into the provider/tile list.
	mutable CRITICAL_SECTION _csFields;

};
