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


#include "CEIDCredential.h"
#include "CEIDProvider.h"
#include "EIDCredentialProvider.h"


#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/GPO.h"

#include <wincred.h>
#include <CodeAnalysis/Warnings.h>
// C4995 (deprecated function names) fires inside both SDK headers.
#pragma warning(push)
#pragma warning(disable : 4995)
#include <Shlwapi.h>
#include <strsafe.h>
#pragma warning(pop)
// Static buffer for PWSTR* assignment (C++23 /Zc:strictStrings compatibility)
static wchar_t s_wszUnknownError[] = L"Unknow Error";  // NOSONAR - GLOBAL-01: Non-const for Windows API PWSTR compatibility

// Message shown in place of the PIN box once the card is removed while this tile is selected.
static const wchar_t s_szReconnectCard[] = L"Please reconnect your smart card";

// Wrong-PIN protection policies (values under the SmartCardCredentialProvider policy key):
// defaults when not configured, and the largest value honoured.
constexpr DWORD EID_PIN_DELAY_THRESHOLD_DEFAULT = 5;    // wrong PINs before the countdown
constexpr DWORD EID_PIN_DELAY_THRESHOLD_MAX = 100;
constexpr DWORD EID_PIN_DELAY_SECONDS_DEFAULT = 10;     // countdown length; 0 = no countdown
constexpr DWORD EID_PIN_DELAY_SECONDS_MAX = 300;
constexpr DWORD EID_PIN_ATTEMPTS_RESERVED_DEFAULT = 1;  // card attempts held back; 0 = no hold
constexpr DWORD EID_PIN_ATTEMPTS_RESERVED_MAX = 10;
constexpr DWORD EID_PIN_THROTTLE_TICK_MS = 1000;
constexpr size_t EID_PIN_MESSAGE_CCH = 192;  // room for the longest PIN-entry message

struct PIN_ENTRY_POLICY
{
	DWORD dwDelayThreshold;
	DWORD dwDelaySeconds;
	DWORD dwAttemptsReserved;
};

// Read on every wrong PIN, so a policy change applies from the next one.
static PIN_ENTRY_POLICY ReadPinEntryPolicy()
{
	PIN_ENTRY_POLICY policy;
	policy.dwDelayThreshold = GetPolicyValueOrDefault(GPOPolicy::PinDelayThreshold, EID_PIN_DELAY_THRESHOLD_DEFAULT);
	if (policy.dwDelayThreshold == 0)
	{
		policy.dwDelayThreshold = 1;
	}
	else if (policy.dwDelayThreshold > EID_PIN_DELAY_THRESHOLD_MAX)
	{
		policy.dwDelayThreshold = EID_PIN_DELAY_THRESHOLD_MAX;
	}
	policy.dwDelaySeconds = GetPolicyValueOrDefault(GPOPolicy::PinDelaySeconds, EID_PIN_DELAY_SECONDS_DEFAULT);
	if (policy.dwDelaySeconds > EID_PIN_DELAY_SECONDS_MAX)
	{
		policy.dwDelaySeconds = EID_PIN_DELAY_SECONDS_MAX;
	}
	policy.dwAttemptsReserved = GetPolicyValueOrDefault(GPOPolicy::PinAttemptsReserved, EID_PIN_ATTEMPTS_RESERVED_DEFAULT);
	if (policy.dwAttemptsReserved > EID_PIN_ATTEMPTS_RESERVED_MAX)
	{
		policy.dwAttemptsReserved = EID_PIN_ATTEMPTS_RESERVED_MAX;
	}
	return policy;
}

// Message shown in place of the PIN box while the countdown runs.
static void FormatPinThrottleMessage(DWORD dwSecondsLeft, PWSTR pwszBuffer, size_t cchBuffer)
{
	StringCchPrintfW(pwszBuffer, cchBuffer, L"Too many incorrect PINs. Try again in %lu second%ls.",
		dwSecondsLeft, dwSecondsLeft == 1 ? L"" : L"s");
}

// Message shown in place of the PIN box while PIN entry is held until the card is re-inserted.
static void FormatPinHeldMessage(DWORD dwTriesLeft, PWSTR pwszBuffer, size_t cchBuffer)
{
	StringCchPrintfW(pwszBuffer, cchBuffer,
		L"This card has only %lu PIN attempt%ls left before it is blocked. Remove the card and insert it again to try again.",
		dwTriesLeft, dwTriesLeft == 1 ? L"" : L"s");
}

// Arms the countdown timer for one tick from now. One-shot: each tick re-arms it, so a slow
// tick can never overlap the next one.
static void ArmPinThrottleTimer(PTP_TIMER pTimer)
{
	// Negative = relative, in 100 ns units.
	const ULONGLONG ullDue = static_cast<ULONGLONG>(-static_cast<LONGLONG>(EID_PIN_THROTTLE_TICK_MS) * 10000);
	FILETIME ftDue;
	ftDue.dwLowDateTime = static_cast<DWORD>(ullDue & 0xFFFFFFFF);
	ftDue.dwHighDateTime = static_cast<DWORD>(ullDue >> 32);
	SetThreadpoolTimer(pTimer, &ftDue, 0, 0);
}

// CEIDCredential ////////////////////////////////////////////////////////

CEIDCredential::CEIDCredential(CContainer* container):
    _cRef(1),  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
    _pCredProvCredentialEvents(nullptr)  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Creation");
	DllAddRef();
    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
	_pContainer = container;  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
	_fSelected = FALSE;  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
	_fDisconnected = FALSE;  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
	_pProvider = nullptr;  // NOSONAR - INIT-01: member initialized in constructor for clarity/ordering
	InitializeCriticalSection(&_csFields);
	Initialize();
}

CEIDCredential::~CEIDCredential()
{
	if (_pContainer)
	{
		delete _pContainer;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
	}
	if (_rgFieldStrings[SFI_PIN])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPin;
        HRESULT hr = StringCchLengthW(_rgFieldStrings[SFI_PIN], 128, &lenPin);  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
        if (SUCCEEDED(hr))
        {
            SecureZeroMemory(_rgFieldStrings[SFI_PIN], lenPin * sizeof(*_rgFieldStrings[SFI_PIN]));
        }
        else
        {
            // If length calculation fails, use maximum length to ensure memory is cleared
            SecureZeroMemory(_rgFieldStrings[SFI_PIN], 128 * sizeof(*_rgFieldStrings[SFI_PIN]));
        }
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
	if (_pCredProvCredentialEvents != nullptr)
	{
		// LogonUI normally UnAdvises first; drop any reference still held.
		_pCredProvCredentialEvents->Release();
		_pCredProvCredentialEvents = nullptr;
	}
	DeleteCriticalSection(&_csFields);

    DllRelease();
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Deletion");
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
HRESULT CEIDCredential::Initialize()
{
    HRESULT hr = S_OK;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(s_rgCredProvFieldDescriptors); i++)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairs[i];
		hr = FieldDescriptorCopy(s_rgCredProvFieldDescriptors[i], &_rgCredProvFieldDescriptors[i]);
    }

	// Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
	{
		SHStrDupW(_pContainer->GetUserNameW(), &_rgFieldStrings[SFI_USERNAME]);
	}
	if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
    }
	if (SUCCEEDED(hr))
    {
        HINSTANCE Handle = EIDLoadSystemLibrary(TEXT("SmartcardCredentialProvider.dll"));
		WCHAR Message[256] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		if (Handle)
		{
			LoadStringW(Handle, 34, Message, ARRAYSIZE(Message));
			FreeLibrary(Handle);
		}
		hr = SHStrDupW(Message, &_rgFieldStrings[SFI_MESSAGE]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        WCHAR szCertificateDetail[256] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		LoadStringW(g_hinst,IDS_CERTIFICATEDETAIL,szCertificateDetail,ARRAYSIZE(szCertificateDetail));
		hr = SHStrDupW(szCertificateDetail, &_rgFieldStrings[SFI_CERTIFICATE]);
    }
	else
	{
		EIDLogErrorWithContext("Initialize::SHStrDupW", hr, L"field=certificate");
	}
    return hr;
}

CContainer* CEIDCredential::GetContainer() const
{
	return _pContainer;
}

BOOL CEIDCredential::IsSelected() const
{
	EnterCriticalSection(&_csFields);
	BOOL fSelected = _fSelected;
	LeaveCriticalSection(&_csFields);
	return fSelected;
}

BOOL CEIDCredential::IsDisconnected() const
{
	EnterCriticalSection(&_csFields);
	BOOL fDisconnected = _fDisconnected;
	LeaveCriticalSection(&_csFields);
	return fDisconnected;
}

void CEIDCredential::SetProvider(CEIDProvider* pProvider)
{
	EnterCriticalSection(&_csFields);
	_pProvider = pProvider;
	LeaveCriticalSection(&_csFields);
}

ICredentialProviderCredentialEvents* CEIDCredential::GetEventsAddRef()
{
	EnterCriticalSection(&_csFields);
	ICredentialProviderCredentialEvents* pEvents = _pCredProvCredentialEvents;
	if (pEvents != nullptr)
	{
		pEvents->AddRef();
	}
	LeaveCriticalSection(&_csFields);
	return pEvents;
}

// TRUE if this process runs as LocalSystem (or if that cannot be determined: fail closed).
static BOOL IsProcessLocalSystem()
{
	BOOL fLocalSystem = TRUE;
	HANDLE hToken = nullptr;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		alignas(TOKEN_USER) BYTE TokenUserBuffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		DWORD dwSize = 0;
		if (GetTokenInformation(hToken, TokenUser, TokenUserBuffer, sizeof(TokenUserBuffer), &dwSize))
		{
			const TOKEN_USER* pTokenUser = reinterpret_cast<const TOKEN_USER*>(TokenUserBuffer);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
			fLocalSystem = IsWellKnownSid(pTokenUser->User.Sid, WinLocalSystemSid);
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetTokenInformation 0x%08x",GetLastError());
		}
		CloseHandle(hToken);
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OpenProcessToken 0x%08x",GetLastError());
	}
	return fLocalSystem;
}

// The certificate viewer is a full CryptUI dialog, from which a browser or file dialog can be
// opened. It must never be reachable from a process running as SYSTEM on the secure desktop:
// LogonUI on the logon / unlock screens, and also the UAC credential prompt, which is the
// CredUI scenario hosted by consent.exe as SYSTEM (CVE-2019-1388). The link is therefore only
// offered in CredUI, outside a secure prompt, and in a process that is not LocalSystem.
BOOL CEIDCredential::IsCertificateLinkAllowed() const
{
	if (_cpus != CPUS_CREDUI || (_dwFlags & CREDUIWIN_SECURE_PROMPT))
	{
		return FALSE;
	}
	// The process identity never changes: query the token once.
	static const BOOL s_fLocalSystem = IsProcessLocalSystem();
	return !s_fLocalSystem;
}

// Securely wipe and reset the PIN edit buffer (mirrors SetDeselected's handling).
// Caller must hold _csFields.
void CEIDCredential::SecureClearPin()
{
	if (_rgFieldStrings[SFI_PIN])
	{
		size_t lenPin;
		if (SUCCEEDED(StringCchLengthW(_rgFieldStrings[SFI_PIN], 128, &lenPin)))
		{
			SecureZeroMemory(_rgFieldStrings[SFI_PIN], lenPin * sizeof(*_rgFieldStrings[SFI_PIN]));
		}
		else
		{
			SecureZeroMemory(_rgFieldStrings[SFI_PIN], 128 * sizeof(*_rgFieldStrings[SFI_PIN]));
		}
		CoTaskMemFree(_rgFieldStrings[SFI_PIN]);
		_rgFieldStrings[SFI_PIN] = nullptr;
		SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
	}
}

// Morph the tile between the PIN prompt and a "please reconnect your smart card" message.
// LogonUI will not swap a tile that the user has selected, so when the card is pulled we
// update this tile's own fields in place (fDisconnected==TRUE); when the card returns we
// restore the PIN prompt (fDisconnected==FALSE). GetFieldState/GetStringValue mirror this
// state so LogonUI stays consistent even if it re-queries the tile.
//
// Runs on the smart-card notifier thread, in two steps. The state change (flag + PIN wipe) is
// made by MarkDisconnectedIfSelected / MarkReconnected under _csFields, with the factory's
// list lock held by the caller, so it is atomic with respect to SetDeselected (which reads the
// flag under _csFields) and to the tile's removal (re-checked under the list lock).
// UpdateConnectionFields then makes the LogonUI callbacks on an AddRef'd copy of the events
// pointer with no lock held, so the UI thread waiting on _csFields can never deadlock with
// LogonUI marshalling one of these calls back to it.
BOOL CEIDCredential::MarkDisconnectedIfSelected()
{
	EnterCriticalSection(&_csFields);
	const BOOL fSelected = _fSelected;
	if (fSelected && !_fDisconnected)
	{
		_fDisconnected = TRUE;
		_dwFieldStateGen++;
		// Never keep a typed PIN across a card removal.
		SecureClearPin();
	}
	LeaveCriticalSection(&_csFields);
	return fSelected;
}

BOOL CEIDCredential::MarkReconnected()
{
	EnterCriticalSection(&_csFields);
	const BOOL fWasDisconnected = _fDisconnected;
	if (fWasDisconnected)
	{
		_fDisconnected = FALSE;
		_dwFieldStateGen++;
		SecureClearPin();
		// The card has been re-inserted: release a hold and start the wrong-PIN count afresh.
		// A countdown still running ends at its next tick (it sees no time left).
		_dwWrongPinCount = 0;
		_ullPinThrottleEnd = 0;
		_fPinHeld = FALSE;
	}
	LeaveCriticalSection(&_csFields);
	return fWasDisconnected;
}

void CEIDCredential::UpdateConnectionFields()
{
	// Several threads push - the notifier thread on a card removal or re-insertion, LogonUI's
	// thread when PIN entry is blocked after a wrong PIN, the countdown timer when it ends - each with no
	// lock held, so two pushes can interleave and leave LogonUI showing a mix of both states.
	// So each push checks afterwards whether the state changed while it was pushing, and if it
	// did pushes again: whichever push finishes last leaves the current state on screen.
	for (int iPass = 0; iPass < 3; iPass++)
	{
		WCHAR szBlocked[EID_PIN_MESSAGE_CCH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		EnterCriticalSection(&_csFields);
		const DWORD dwGen = _dwFieldStateGen;
		const BOOL fDisconnected = _fDisconnected;
		const BOOL fBlocked = GetPinEntryBlock(szBlocked, ARRAYSIZE(szBlocked));
		ICredentialProviderCredentialEvents* pEvents = _pCredProvCredentialEvents;
		PWSTR pwszMessage = nullptr;
		if (pEvents != nullptr)
		{
			pEvents->AddRef();
			if (!fDisconnected && !fBlocked && _rgFieldStrings[SFI_MESSAGE])
			{
				// Private copy so the string can be handed to LogonUI outside the lock.
				SHStrDupW(_rgFieldStrings[SFI_MESSAGE], &pwszMessage);
			}
		}
		LeaveCriticalSection(&_csFields);
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: UpdateConnectionFields tile=%p fDisconnected=%d pinBlocked=%d advised=%d",(void*)this,fDisconnected,fBlocked,pEvents!=nullptr);

		if (!pEvents)
		{
			// Not currently advised by LogonUI; the state is enough for the next query.
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: UpdateConnectionFields tile=%p SKIPPED field updates (not advised)",(void*)this);
			return;
		}

		if (fDisconnected)
		{
			pEvents->SetFieldState(this, SFI_PIN, CPFS_HIDDEN);
			pEvents->SetFieldState(this, SFI_SUBMIT_BUTTON, CPFS_HIDDEN);
			pEvents->SetFieldState(this, SFI_CERTIFICATE, CPFS_HIDDEN);
			pEvents->SetFieldString(this, SFI_PIN, L"");
			pEvents->SetFieldString(this, SFI_MESSAGE, s_szReconnectCard);
		}
		else if (fBlocked)
		{
			pEvents->SetFieldState(this, SFI_PIN, CPFS_HIDDEN);
			pEvents->SetFieldState(this, SFI_SUBMIT_BUTTON, CPFS_HIDDEN);
			pEvents->SetFieldString(this, SFI_PIN, L"");
			pEvents->SetFieldString(this, SFI_MESSAGE, szBlocked);
		}
		else
		{
			pEvents->SetFieldState(this, SFI_PIN, _rgFieldStatePairs[SFI_PIN].cpfs);
			pEvents->SetFieldState(this, SFI_SUBMIT_BUTTON, _rgFieldStatePairs[SFI_SUBMIT_BUTTON].cpfs);
			pEvents->SetFieldState(this, SFI_CERTIFICATE,
				IsCertificateLinkAllowed() ? _rgFieldStatePairs[SFI_CERTIFICATE].cpfs : CPFS_HIDDEN);
			pEvents->SetFieldString(this, SFI_PIN, L"");
			pEvents->SetFieldString(this, SFI_MESSAGE, pwszMessage ? pwszMessage : L"");
			pEvents->SetFieldInteractiveState(this, SFI_PIN, CPFIS_FOCUSED);
		}
		CoTaskMemFree(pwszMessage);
		pEvents->Release();

		EnterCriticalSection(&_csFields);
		const BOOL fChanged = (_dwFieldStateGen != dwGen);
		LeaveCriticalSection(&_csFields);
		if (!fChanged)
		{
			return;
		}
	}
}

DWORD CEIDCredential::PinThrottleSecondsLeft() const
{
	const ULONGLONG ullNow = GetTickCount64();
	if (_ullPinThrottleEnd <= ullNow)
	{
		return 0;
	}
	return static_cast<DWORD>((_ullPinThrottleEnd - ullNow + 999) / 1000);
}

BOOL CEIDCredential::GetPinEntryBlock(PWSTR pwszMessage, size_t cchMessage) const
{
	// A hold outranks a countdown: either way no attempt is allowed, but only re-inserting
	// the card ends a hold.
	if (_fPinHeld)
	{
		if (pwszMessage)
		{
			FormatPinHeldMessage(_dwCardTriesLeft, pwszMessage, cchMessage);
		}
		return TRUE;
	}
	const DWORD dwSecondsLeft = PinThrottleSecondsLeft();
	if (dwSecondsLeft != 0)
	{
		if (pwszMessage)
		{
			FormatPinThrottleMessage(dwSecondsLeft, pwszMessage, cchMessage);
		}
		return TRUE;
	}
	return FALSE;
}

BOOL CEIDCredential::IsPinEntryBlocked() const
{
	EnterCriticalSection(&_csFields);
	const BOOL fBlocked = GetPinEntryBlock(nullptr, 0);
	LeaveCriticalSection(&_csFields);
	return fBlocked;
}

// Counts a wrong PIN. When the card is down to its reserved PIN attempts, holds PIN entry until
// the card is re-inserted; otherwise, from the PinDelayThreshold-th wrong PIN on, starts the
// countdown that has to run out before the next attempt. Called on LogonUI's thread
// (ReportResult). ntsSubstatus is the number of PIN attempts the card has left, or 0xFFFFFFFF
// when the card did not say (the hold then cannot apply).
void CEIDCredential::RecordWrongPin(NTSTATUS ntsSubstatus)
{
	const PIN_ENTRY_POLICY policy = ReadPinEntryPolicy();
	const DWORD dwTriesLeft = static_cast<DWORD>(ntsSubstatus);
	// None left means the card is blocked already: there is nothing left to hold back.
	const BOOL fHold = (dwTriesLeft != 0xFFFFFFFF && dwTriesLeft != 0 && dwTriesLeft <= policy.dwAttemptsReserved);
	BOOL fStarted = FALSE;
	EnterCriticalSection(&_csFields);
	if (_dwWrongPinCount < MAXDWORD)
	{
		_dwWrongPinCount++;
	}
	if (fHold)
	{
		// No countdown on top: nothing is allowed until the card is re-inserted anyway.
		_fPinHeld = TRUE;
		_dwCardTriesLeft = dwTriesLeft;
		_dwFieldStateGen++;
		fStarted = TRUE;
	}
	else if (policy.dwDelaySeconds != 0 && _dwWrongPinCount >= policy.dwDelayThreshold)
	{
		if (_pPinThrottleTimer == nullptr)
		{
			TP_CALLBACK_ENVIRON env;
			InitializeThreadpoolEnvironment(&env);
			// The last tick releases the timer's reference to the tile, which may be the last
			// one and with it this DLL's last reference: keep the DLL loaded until it returns.
			SetThreadpoolCallbackLibrary(&env, HINST_THISDLL);
			_pPinThrottleTimer = CreateThreadpoolTimer(PinThrottleTimerCallback, this, &env);
			DestroyThreadpoolEnvironment(&env);
			if (_pPinThrottleTimer != nullptr)
			{
				AddRef();  // held by the timer; released by its last tick
				ArmPinThrottleTimer(_pPinThrottleTimer);
			}
			else
			{
				// No countdown without a timer to end it (the PIN box would stay hidden); the
				// card's own retry counter still applies.
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateThreadpoolTimer 0x%08x - wrong-PIN countdown not started",GetLastError());
			}
		}
		// A timer that is still running (a countdown reset by a re-insertion, not yet past
		// its next tick) carries on with the new deadline.
		if (_pPinThrottleTimer != nullptr)
		{
			_ullPinThrottleEnd = GetTickCount64() + policy.dwDelaySeconds * 1000ULL;
			_dwFieldStateGen++;
			fStarted = TRUE;
		}
	}
	const DWORD dwCount = _dwWrongPinCount;
	LeaveCriticalSection(&_csFields);
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: wrong PIN tile=%p count=%lu triesLeft=%lu hold=%d blocked=%d",(void*)this,dwCount,dwTriesLeft,fHold,fStarted);

	if (fStarted)
	{
		// Hide the PIN box and submit button and say why.
		UpdateConnectionFields();
	}
}

VOID CALLBACK CEIDCredential::PinThrottleTimerCallback(PTP_CALLBACK_INSTANCE pInstance, PVOID pvContext, PTP_TIMER pTimer)
{
	UNREFERENCED_PARAMETER(pInstance);
	static_cast<CEIDCredential*>(pvContext)->OnPinThrottleTick(pTimer);
}

// Runs on a thread-pool thread, once a second while the countdown runs; the timer's reference
// keeps the tile alive. Calls into LogonUI with no lock held, like the notifier thread does.
void CEIDCredential::OnPinThrottleTick(PTP_TIMER pTimer)
{
	WCHAR szMessage[EID_PIN_MESSAGE_CCH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	EnterCriticalSection(&_csFields);
	const DWORD dwSecondsLeft = PinThrottleSecondsLeft();
	const BOOL fDisconnected = _fDisconnected;
	if (dwSecondsLeft == 0)
	{
		// Over, or reset by a card re-insertion. From here on this tick owns the timer: a
		// wrong PIN from now on starts a new one.
		_ullPinThrottleEnd = 0;
		_pPinThrottleTimer = nullptr;
		_dwFieldStateGen++;
	}
	// While the countdown runs this is its message (or a hold's, which outranks it).
	GetPinEntryBlock(szMessage, ARRAYSIZE(szMessage));
	const DWORD dwGen = _dwFieldStateGen;
	LeaveCriticalSection(&_csFields);

	if (dwSecondsLeft != 0)
	{
		if (ICredentialProviderCredentialEvents* pEvents = GetEventsAddRef())
		{
			pEvents->SetFieldString(this, SFI_MESSAGE, fDisconnected ? s_szReconnectCard : szMessage);
			pEvents->Release();
		}
		// A card removal or re-insertion pushed its own state meanwhile: this message may
		// have overwritten it, so push the whole current state again.
		EnterCriticalSection(&_csFields);
		const BOOL fChanged = (_dwFieldStateGen != dwGen);
		LeaveCriticalSection(&_csFields);
		if (fChanged)
		{
			UpdateConnectionFields();
		}
		ArmPinThrottleTimer(pTimer);
		return;
	}

	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: wrong-PIN countdown over tile=%p",(void*)this);
	// Bring back the PIN prompt (or the reconnect message, if the card is out).
	UpdateConnectionFields();
	// Allowed from the timer's own callback: it is freed once this callback returns.
	CloseThreadpoolTimer(pTimer);
	// The timer's reference. May delete this tile: nothing may touch a member after it.
	Release();
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CEIDCredential::Advise(
    ICredentialProviderCredentialEvents* pcpce
    )
{
	// Swap under _csFields (the notifier thread reads it); release the old one outside the lock.
	if (pcpce != nullptr)
	{
		pcpce->AddRef();
	}
	EnterCriticalSection(&_csFields);
	ICredentialProviderCredentialEvents* pOld = _pCredProvCredentialEvents;
	_pCredProvCredentialEvents = pcpce;
	LeaveCriticalSection(&_csFields);
	if (pOld != nullptr)
	{
		pOld->Release();
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: Advise tile=%p",(void*)this);

    return S_OK;
}

void CEIDCredential::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
{
	_cpus = cpus;
	_dwFlags = dwFlags;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CEIDCredential::UnAdvise()
{
	EnterCriticalSection(&_csFields);
	ICredentialProviderCredentialEvents* pOld = _pCredProvCredentialEvents;
	_pCredProvCredentialEvents = nullptr;
	LeaveCriticalSection(&_csFields);
	if (pOld != nullptr)
	{
		pOld->Release();
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: UnAdvise tile=%p",(void*)this);
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CEIDCredential::SetSelected(BOOL* pbAutoLogon)
{
	*pbAutoLogon = FALSE;
	EnterCriticalSection(&_csFields);
	_fSelected = TRUE;
	LeaveCriticalSection(&_csFields);
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: SetSelected tile=%p",(void*)this);
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is.  The most common thing to do here (which we do below)
// is to clear out the Pin field.
HRESULT CEIDCredential::SetDeselected()
{
    HRESULT hr = S_OK;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
	BOOL fClearedPin = FALSE;
	EnterCriticalSection(&_csFields);
	_fSelected = FALSE;
	if (_rgFieldStrings[SFI_PIN])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPin;
        hr = StringCchLengthW(_rgFieldStrings[SFI_PIN], 128, &lenPin);
        if (SUCCEEDED(hr))
        {
            SecureZeroMemory(_rgFieldStrings[SFI_PIN], lenPin * sizeof(*_rgFieldStrings[SFI_PIN]));

            CoTaskMemFree(_rgFieldStrings[SFI_PIN]);
            _rgFieldStrings[SFI_PIN] = nullptr;
            hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
        }
        fClearedPin = SUCCEEDED(hr);
    }
	const BOOL fDisconnected = _fDisconnected;
	CEIDProvider* pProvider = _pProvider;
	LeaveCriticalSection(&_csFields);
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: SetDeselected tile=%p",(void*)this);

	if (fClearedPin)
	{
		// Call into LogonUI with _csFields dropped.
		if (ICredentialProviderCredentialEvents* pEvents = GetEventsAddRef())
		{
			pEvents->SetFieldString(this, SFI_PIN, L"");
			pEvents->Release();
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"");
		}
	}
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("SetDeselected", hr, L"field=SFI_PIN");
	}

	// If the card is gone and this tile was only being kept alive because LogonUI had it
	// selected (the "please reconnect" morph), deselection is our cue to finally drop it:
	// LogonUI will not remove a selected tile, but now that it is deselected the provider can
	// erase it and re-enumerate so it disappears. The provider re-checks the flag under the
	// list lock, so a tile revived since the snapshot above is kept. This runs LAST - RemoveDisconnectedTile
	// re-enters LogonUI via CredentialsChanged and releases the list's reference to us, so we
	// must not touch any member after it (LogonUI's own reference keeps `this` alive until the
	// call returns).
	if (fDisconnected && pProvider)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"EVID: SetDeselected while disconnected -> request purge tile=%p",(void*)this);
		pProvider->RemoveDisconnectedTile(this);
	}

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information to
// display the tile.
HRESULT CEIDCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    if (dwFieldID < ARRAYSIZE(_rgFieldStatePairs) && pcpfs && pcpfis)
    {
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        // While the card is absent, hide the PIN entry, submit button and certificate link so
        // only the "please reconnect" message remains. Keeps LogonUI consistent if it re-queries.
        if (IsDisconnected() &&
            (dwFieldID == SFI_PIN || dwFieldID == SFI_SUBMIT_BUTTON || dwFieldID == SFI_CERTIFICATE))
        {
            *pcpfs = CPFS_HIDDEN;
        }
        // Likewise the PIN entry and submit button while PIN entry is blocked (wrong-PIN
        // countdown, or the card's last attempts held back until it is re-inserted).
        if ((dwFieldID == SFI_PIN || dwFieldID == SFI_SUBMIT_BUTTON) && IsPinEntryBlocked())
        {
            *pcpfs = CPFS_HIDDEN;
        }
        // The certificate viewer must not be reachable as SYSTEM on the secure desktop (logon /
        // unlock screens, UAC prompt in consent.exe); see IsCertificateLinkAllowed.
        if (dwFieldID == SFI_CERTIFICATE && !IsCertificateLinkAllowed())
        {
            *pcpfs = CPFS_HIDDEN;
        }
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("GetFieldState", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CEIDCredential::GetStringValue(
    DWORD dwFieldID, 
    PWSTR* ppwsz
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    // Check to make sure dwFieldID is a legitimate index.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz)
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        WCHAR szBlocked[EID_PIN_MESSAGE_CCH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
        EnterCriticalSection(&_csFields);
        if (_fDisconnected && dwFieldID == SFI_MESSAGE)
        {
            hr = SHStrDupW(s_szReconnectCard, ppwsz);
        }
        else if (dwFieldID == SFI_MESSAGE && GetPinEntryBlock(szBlocked, ARRAYSIZE(szBlocked)))
        {
            hr = SHStrDupW(szBlocked, ppwsz);
        }
        else
        {
            hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
        }
        LeaveCriticalSection(&_csFields);
    }
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("GetStringValue", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}

// Get the image to show in the user tile.
HRESULT CEIDCredential::GetBitmapValue(
    DWORD dwFieldID,
    HBITMAP* phbmp
    )
{
    HRESULT hr = E_INVALIDARG;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
	if ((SFI_TILEIMAGE == dwFieldID) && phbmp)
    {
        *phbmp = nullptr;

		// Use LoadImage instead of deprecated LoadBitmap
		// LoadImage with LR_CREATEDIBSECTION creates a DIB section bitmap
		// which is more reliable for credential providers
		HBITMAP hbmp = static_cast<HBITMAP>(LoadImageW(  // NOSONAR (EXPLICIT-TYPE-02) - HBITMAP handle type retained for clarity
			HINST_THISDLL,
			MAKEINTRESOURCEW(IDB_TILE_IMAGE),
			IMAGE_BITMAP,
			0,  // Use actual width from resource
			0,  // Use actual height from resource
			LR_CREATEDIBSECTION | LR_DEFAULTSIZE
		));

		if (hbmp != nullptr)
		{
			hr = S_OK;
			*phbmp = hbmp;
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"GetBitmapValue: Bitmap loaded successfully");
		}
		else
		{
			DWORD dwErr = GetLastError();
			hr = HRESULT_FROM_WIN32(dwErr);
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"GetBitmapValue: LoadImageW failed with error 0x%08x", dwErr);
			EIDLogErrorWithContext("GetBitmapValue", hr, L"LoadImageW failed; g_hinst=0x%p, ID=%d", HINST_THISDLL, IDB_TILE_IMAGE);

			// Fallback: Try LoadBitmap as backup for older systems
			hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
			if (hbmp != nullptr)
			{
				hr = S_OK;
				*phbmp = hbmp;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GetBitmapValue: Fallback to LoadBitmap succeeded");
			}
			else
			{
				dwErr = GetLastError();
				hr = HRESULT_FROM_WIN32(dwErr);
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"GetBitmapValue: LoadBitmap fallback also failed with error 0x%08x", dwErr);
			}
		}
    }
    else
    {
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"GetBitmapValue: Invalid field ID or null phbmp (fieldId=%lu)", dwFieldID);
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("GetBitmapValue", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CEIDCredential::GetSubmitButtonValue(
    DWORD dwFieldID,
    DWORD* pdwAdjacentTo
    )
{
    HRESULT hr = E_INVALIDARG;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
    if (SFI_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to 
        // appear next to.
        *pdwAdjacentTo = SFI_PIN;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("GetSubmitButtonValue", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CEIDCredential::SetStringValue(
    DWORD dwFieldID, 
    PCWSTR pwz
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
       (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft || 
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
    {
        EnterCriticalSection(&_csFields);
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
        // Wipe before releasing. LogonUI calls this on EVERY KEYSTROKE, and it
        // frees the previous value - so without this, typing an N-character PIN
        // released N-1 progressively longer prefixes of it, in clear, to the COM
        // heap. Every other PIN path in this class already scrubs; this one, the
        // hottest, did not, which undid the care taken everywhere else.
        //
        // Scrub any password-type field, not just SFI_PIN, so a future field
        // gets the same treatment by default.
        if (*ppwszStored != nullptr &&
            CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft)
        {
            size_t cchStored = 0;
            if (SUCCEEDED(StringCchLengthW(*ppwszStored, STRSAFE_MAX_CCH, &cchStored)))
            {
                SecureZeroMemory(*ppwszStored, cchStored * sizeof(**ppwszStored));
            }
        }
        CoTaskMemFree(*ppwszStored);
        *ppwszStored = nullptr;

        hr = SHStrDupW(pwz, ppwszStored);
        LeaveCriticalSection(&_csFields);
    }
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("SetStringValue", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}

//-------------
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT CEIDCredential::GetCheckboxValue(
    DWORD dwFieldID, 
    BOOL* pbChecked,
    PWSTR* ppwszLabel
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);

    return E_NOTIMPL;
}

HRESULT CEIDCredential::GetComboBoxValueCount(
    DWORD dwFieldID, 
    DWORD* pcItems, 
    DWORD* pdwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
	return E_NOTIMPL;
}

HRESULT CEIDCredential::GetComboBoxValueAt(
    DWORD dwFieldID, 
    DWORD dwItem,
    PWSTR* ppwszItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
	return E_NOTIMPL;
}

HRESULT CEIDCredential::SetCheckboxValue(
    DWORD dwFieldID, 
    BOOL bChecked
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);

    return E_NOTIMPL;
}

HRESULT CEIDCredential::SetComboBoxSelectedValue(
    DWORD dwFieldID,
    DWORD dwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwSelectedItem);
	return E_NOTIMPL;
}

HRESULT CEIDCredential::CommandLinkClicked(DWORD dwFieldID)
{
	HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit
	if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
       (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
    {
		if (!IsCertificateLinkAllowed())
		{
			// The link is hidden in that case; refuse it even if LogonUI invokes it anyway.
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Certificate viewer refused in scenario %d flags 0x%08x",_cpus,_dwFlags);
		}
		else if (ICredentialProviderCredentialEvents* pEvents = GetEventsAddRef())
		{
			// The viewer is modal: run it with _csFields dropped.
			HWND hWnd = nullptr;
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"");
			if (SUCCEEDED(pEvents->OnCreatingWindow(&hWnd)))
			{
				_pContainer->ViewCertificate(hWnd);
			}
			pEvents->Release();
		}
		hr = S_OK;
	}
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
    }
	if (!SUCCEEDED(hr))
	{
		EIDLogErrorWithContext("CommandLinkClicked", hr, L"fieldId=%lu", dwFieldID);
	}
    return hr;
}
//------ end of methods for controls we don't have in our tile ----//


//
// Initialize the members of a EID_INTERACTIVE_UNLOCK_LOGON with weak references to the
// passed-in strings.  This is useful if you will later use KerbInteractiveUnlockLogonPack
// to serialize the structure.  
//
// The password is stored in encrypted form for CPUS_LOGON and CPUS_UNLOCK_WORKSTATION
// because the system can accept encrypted credentials.  It is not encrypted in CPUS_CREDUI
// because we cannot know whether our caller can accept encrypted credentials.
//
HRESULT EIDUnlockLogonInit(
                                       PWSTR pwzDomain,
                                       PWSTR pwzUsername,
                                       PWSTR pwzPin,
                                       CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                       EID_INTERACTIVE_UNLOCK_LOGON* pkiul
                                       )
{
    UNREFERENCED_PARAMETER(cpus);
	EID_INTERACTIVE_UNLOCK_LOGON kiul;
    ZeroMemory(&kiul, sizeof(kiul));

    EID_INTERACTIVE_LOGON* pkil = &kiul.Logon;

    // Note: this method uses custom logic to pack a EID_INTERACTIVE_UNLOCK_LOGON with a
    // serialized credential.  We could replace the calls to UnicodeStringInitWithString
    // and KerbInteractiveUnlockLogonPack with a single cal to CredPackAuthenticationBuffer,
    // but that API has a drawback: it returns a EID_INTERACTIVE_UNLOCK_LOGON whose
    // MessageType is always KerbInteractiveLogon.  
    //
    // If we only handled CPUS_LOGON, this drawback would not be a problem.  For 
    // CPUS_UNLOCK_WORKSTATION, we could cast the output buffer of CredPackAuthenticationBuffer
    // to EID_INTERACTIVE_UNLOCK_LOGON and modify the MessageType to KerbWorkstationUnlockLogon,
    // but such a cast would be unsupported -- the output format of CredPackAuthenticationBuffer
    // is not officially documented.

    // Initialize the UNICODE_STRINGS to share our username and password strings.
    HRESULT hr = UnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    if (SUCCEEDED(hr))
    {
        hr = UnicodeStringInitWithString(pwzUsername, &pkil->UserName);

        if (SUCCEEDED(hr))
        {
            hr = UnicodeStringInitWithString(pwzPin, &pkil->Pin);
            
            if (SUCCEEDED(hr))
            {
                // Set a MessageType based on the usage scenario.
                pkil->MessageType = EID_INTERACTIVE_LOGON_SUBMIT_TYPE_VANILLA;
                pkil->CspDataLength = 0;
                pkil->CspData = nullptr;
                pkil->Flags = 0;

                // EID_INTERACTIVE_UNLOCK_LOGON is just a series of structures.  A
                // flat copy will properly initialize the output parameter.
                CopyMemory(pkiul, &kiul, sizeof(*pkiul));
            }
        }
    }

    return hr;
}


// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
// http://msdn.microsoft.com/en-us/library/bb776026(VS.85).aspx
HRESULT CEIDCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    HRESULT hr;  // NOSONAR - EXPLICIT-TYPE-03: HRESULT visible for security audit

    // The PIN box is hidden while PIN entry is blocked; refuse a submission that gets here
    // anyway rather than send the PIN to the card.
    WCHAR szBlocked[EID_PIN_MESSAGE_CCH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    EnterCriticalSection(&_csFields);
    const BOOL fBlocked = GetPinEntryBlock(szBlocked, ARRAYSIZE(szBlocked));
    LeaveCriticalSection(&_csFields);
    if (fBlocked)
    {
        if (ppwszOptionalStatusText)
        {
            SHStrDupW(szBlocked, ppwszOptionalStatusText);
        }
        if (pcpsiOptionalStatusIcon)
        {
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
        }
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Submission refused: PIN entry blocked");
        return S_OK;
    }

    WCHAR wsz[MAX_COMPUTERNAME_LENGTH+1];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    DWORD cch = ARRAYSIZE(wsz);

    // Guard clause: GetComputerNameW failed
    if (!GetComputerNameW(wsz, &cch))  // NOSONAR - SCOPE-01: variable declared before the block by design
    {
        DWORD dwErr = GetLastError();
        hr = HRESULT_FROM_WIN32(dwErr);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetComputerNameW failed 0x%08x",dwErr);
		EIDLogErrorWithContext("GetSerialization", hr, nullptr);
        return hr;
    }

    PWSTR pwzProtectedPin = nullptr;
    // Copy the PIN under _csFields: a card removal on the notifier thread may wipe and
    // reallocate it concurrently.
    EnterCriticalSection(&_csFields);
    hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PIN], _cpus, _dwFlags, &pwzProtectedPin);
    LeaveCriticalSection(&_csFields);

    // Guard clause: password protection failed
    if (FAILED(hr))
    {
        EIDLogErrorWithContext("GetSerialization::ProtectIfNecessaryAndCopyPassword", hr, nullptr);
        EIDLogErrorWithContext("GetSerialization", hr, nullptr);
        return hr;
    }

    EID_INTERACTIVE_UNLOCK_LOGON kiul;

    // Initialize kiul with weak references to our credential.
    // EIDUnlockLogonInit stores only a WEAK pointer to pwzProtectedPin inside kiul, and
    // EIDUnlockLogonPack (below) copies the PIN bytes FROM that buffer.  The CredProtect-wrapped
    // PIN copy must therefore stay alive until AFTER EIDUnlockLogonPack has consumed it; only then
    // is it zeroized and freed.  Every early-exit path between here and that point frees it too, so
    // it is neither leaked nor freed while kiul still references it.
    hr = EIDUnlockLogonInit(wsz, _rgFieldStrings[SFI_USERNAME], pwzProtectedPin, _cpus, &kiul);

    // Guard clause: logon init failed
    if (FAILED(hr))
    {
        // Zeroize the CredProtect-wrapped PIN copy before releasing it so it does not linger.
        if (pwzProtectedPin)
        {
            SecureZeroMemory(pwzProtectedPin, (wcslen(pwzProtectedPin) + 1) * sizeof(WCHAR));
        }
        CoTaskMemFree(pwzProtectedPin);
        EIDLogErrorWithContext("GetSerialization::EIDUnlockLogonInit", hr, nullptr);
        EIDLogErrorWithContext("GetSerialization", hr, nullptr);
        return hr;
    }

    // We use EID_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
    // EID_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
    // as necessary.
    PEID_SMARTCARD_CSP_INFO pCspInfo = _pContainer->GetCSPInfo();

    // Guard clause: no CSP info
    if (!pCspInfo)
    {
        // Zeroize the CredProtect-wrapped PIN copy before releasing it so it does not linger.
        if (pwzProtectedPin)
        {
            SecureZeroMemory(pwzProtectedPin, (wcslen(pwzProtectedPin) + 1) * sizeof(WCHAR));
        }
        CoTaskMemFree(pwzProtectedPin);
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCspInfo NULL");
        EIDLogErrorWithContext("GetSerialization", E_FAIL, nullptr);
        return E_FAIL;
    }

    hr = EIDUnlockLogonPack(kiul, pCspInfo, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
    _pContainer->FreeCSPInfo(pCspInfo);

    // EIDUnlockLogonPack has now consumed the weakly-referenced PIN.  Zeroize the CredProtect-wrapped
    // PIN copy before releasing it so it does not linger; this covers the pack-failed guard below and
    // every path to the end of the function.
    if (pwzProtectedPin)
    {
        SecureZeroMemory(pwzProtectedPin, (wcslen(pwzProtectedPin) + 1) * sizeof(WCHAR));
    }
    CoTaskMemFree(pwzProtectedPin);
    pwzProtectedPin = nullptr;

    // Guard clause: logon pack failed
    if (FAILED(hr))
    {
        EIDLogErrorWithContext("GetSerialization::EIDUnlockLogonPack", hr, nullptr);
        EIDLogErrorWithContext("GetSerialization", hr, nullptr);
        return hr;
    }

    ULONG ulAuthPackage;
    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

    // Guard clause: auth package retrieval failed
    if (FAILED(hr))
    {
        EIDLogErrorWithContext("GetSerialization::RetrieveNegotiateAuthPackage", hr, nullptr);
        EIDLogErrorWithContext("GetSerialization", hr, nullptr);
        return hr;
    }

    pcpcs->ulAuthenticationPackage = ulAuthPackage;
    pcpcs->clsidCredentialProvider = CLSID_CEIDProvider;

    // At this point the credential has created the serialized credential used for logon
    // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
    // that we have all the information we need and it should attempt to submit the
    // serialized credential.
    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

    EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OK");
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
    NTSTATUS ntsSubstatus;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =  // NOSONAR - LSASS-01: C-style lookup table retained for Win32 status mapping
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/Pin and in the case of the account
// being disabled.

HRESULT CEIDCredential::ReportResult(
    NTSTATUS ntsStatus, 
    NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText, 
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    // NULL is a valid "no text" value. LogonUI CoTaskMemFree()s any other value, so it must
    // never be pointed at static storage.
    if (ppwszOptionalStatusText) *ppwszOptionalStatusText = nullptr;
    if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_NONE;
	
	if (ntsStatus == STATUS_SUCCESS)
	{
		_pContainer->TriggerRemovePolicy();
	}

    DWORD dwStatusInfo = (DWORD)-1;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
			if (pcpsiOptionalStatusIcon)  // NOSONAR - CONTROL-01: nested if kept for cleanup clarity
				*pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
    }

	if (ppwszOptionalStatusText)
	{
	    // get message from system table
		PWSTR Error = nullptr;
		if (ntsStatus == STATUS_SMARTCARD_WRONG_PIN && ntsSubstatus != 0xFFFFFFFF)
		{
			HINSTANCE Handle = EIDLoadSystemLibrary(TEXT("SmartcardCredentialProvider.dll"));
			WCHAR Message[256] = L"%d retries";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
			WCHAR MessageFormatted[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
			if (Handle)
			{
				LoadStringW(Handle, 4001, Message, ARRAYSIZE(Message));
				FreeLibrary(Handle);
			}
			// Message is a localized resource string from a system DLL used as a format; truncate rather than fast-fail.
			_snwprintf_s(MessageFormatted,ARRAYSIZE(MessageFormatted),_TRUNCATE, Message, ntsSubstatus);
			SHStrDupW(MessageFormatted, ppwszOptionalStatusText);
		}
		else
		{
			// FormatMessage's nSize is a WCHAR count, not a byte count, so the allocation
			// must be dwLen * sizeof(WCHAR) or a long system message overflows it by 2x.
			DWORD dwLen = 2048;
			Error = (PWSTR) CoTaskMemAlloc(dwLen * sizeof(WCHAR));
			if (Error)
			{
				Error[0] = L'\0';
				if (!FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,nullptr,LsaNtStatusToWinError(ntsStatus),0,Error,dwLen,nullptr))
				{
					// No system text for this status: never show the unwritten buffer, fall
					// back to a generic message (or NULL, which is also valid, if that fails).
					CoTaskMemFree(Error);
					Error = nullptr;
					SHStrDupW(s_wszUnknownError, &Error);
				}
			}
			*ppwszOptionalStatusText = Error;
		}
	}
    // If we failed the logon, try to erase the Pin field.
    if (!SUCCEEDED(HRESULT_FROM_NT(ntsStatus)))
    {
        // Zeroize the internal PIN buffer, not just the visible UI field, so the typed
        // PIN does not linger in memory after a failed logon.
        EnterCriticalSection(&_csFields);
        SecureClearPin();
        LeaveCriticalSection(&_csFields);
        if (ICredentialProviderCredentialEvents* pEvents = GetEventsAddRef())  // NOSONAR - CONTROL-01: nested if kept for cleanup clarity
        {
            pEvents->SetFieldString(this, SFI_PIN, L"");
            pEvents->Release();
        }
    }

    // Wrong-PIN protection: count wrong PINs (ntsSubstatus is the card's attempts left), which
    // may block PIN entry; a successful logon starts the count afresh.
    if (ntsStatus == STATUS_SMARTCARD_WRONG_PIN)
    {
        RecordWrongPin(ntsSubstatus);
    }
    else if (ntsStatus == STATUS_SUCCESS)
    {
        EnterCriticalSection(&_csFields);
        _dwWrongPinCount = 0;
        _fPinHeld = FALSE;
        LeaveCriticalSection(&_csFields);
    }

    // Since NULL is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    
	return S_OK;
}

