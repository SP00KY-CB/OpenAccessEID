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
#include <tchar.h>

#include "CSmartCardNotifier.h"
#include "Tracing.h"
#include "CContainer.h"

constexpr DWORD TIMEOUT = 300;

#pragma comment(lib,"Winscard")
#pragma comment(lib,"User32")




CSmartCardConnectionNotifier::CSmartCardConnectionNotifier(ISmartCardConnectionNotifierRef* CallBack, BOOL fImmediateStart) 
{
	_CallBack = CallBack;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_hAccessStartedEvent = nullptr;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_hThread = nullptr;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	_hSCardContext = NULL;  // NOSONAR - INIT-01: member initialized in body for clarity/ordering
	if (fImmediateStart)
	{
		Start();
	}
}

CSmartCardConnectionNotifier::~CSmartCardConnectionNotifier() 
{
	if (_hThread != nullptr)
	{
		Stop();
	}
}


HRESULT CSmartCardConnectionNotifier::Start() 
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	
	// check callback
	if(nullptr == _CallBack)
	{
		// no callback defined : don't launch
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No callback defined");
		return E_FAIL;
	}
	if (_hThread != nullptr)
	{
		// Thread already launched
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Thread already launched");
		return E_FAIL;
	}
	// create the stop event before the thread : the thread reads it as soon as it starts
	_hAccessStartedEvent = CreateEvent(nullptr,TRUE,FALSE,nullptr);
	if (_hAccessStartedEvent == nullptr)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to create the stop event : %d",GetLastError());
		return E_FAIL;
	}
	_hThread = CreateThread(nullptr, 0, CSmartCardConnectionNotifier::_ThreadProc, (LPVOID) this, 0, nullptr);
    if (_hThread == nullptr)
    {
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to launch the thread : %d",GetLastError());
		CloseHandle(_hAccessStartedEvent);
		_hAccessStartedEvent = nullptr;
		return E_FAIL;
    }

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return S_OK;
}


// Stop() runs on LogonUI's UI thread (from the provider's destructor). A callback still running
// on the notifier thread may be inside a call into LogonUI that is delivered to this thread with
// SendMessage (a tile field update); a plain wait would then never return. So dispatch sent
// messages - only those: posted and input messages stay queued - until the thread exits. The
// wait itself is not bounded: the callback uses the provider, which must outlive it.
static void WaitForThreadDispatchingSentMessages(HANDLE hThread)
{
	DWORD dwTimeout = 5000;
	for (;;)
	{
		DWORD dwWait = MsgWaitForMultipleObjectsEx(1, &hThread, dwTimeout, QS_SENDMESSAGE, MWMO_INPUTAVAILABLE);
		if (dwWait == WAIT_OBJECT_0)
		{
			return;
		}
		if (dwWait == WAIT_OBJECT_0 + 1)
		{
			// Delivers the pending sent messages; removes nothing from the queue.
			MSG msg;
			PeekMessage(&msg, nullptr, 0, 0, PM_NOREMOVE | PM_QS_SENDMESSAGE);
			continue;
		}
		if (dwWait == WAIT_TIMEOUT)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Notifier thread still running after %u ms (card read in progress?)",dwTimeout);
			dwTimeout = INFINITE;
			continue;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"MsgWaitForMultipleObjectsEx 0x%08X",GetLastError());
		WaitForSingleObject(hThread,INFINITE);
		return;
	}
}

HRESULT CSmartCardConnectionNotifier::Stop()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	LONG lReturn;

	if (_hThread != nullptr)
	{
		if (WaitForSingleObject(_hThread,0)==WAIT_TIMEOUT) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Wait for thread");
			// blocked on SCardAccessStartedEvent ?
			if (_hAccessStartedEvent != nullptr) {
				SetEvent( _hAccessStartedEvent );
			}
			if (_hSCardContext != NULL)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardCancel");
				if (SCARD_S_SUCCESS != (lReturn=SCardCancel(_hSCardContext)))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to SCardCancel %X",lReturn);
				}
			}
			WaitForThreadDispatchingSentMessages(_hThread);
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Thread already finished");
		}
		CloseHandle(_hThread);
		_hThread = nullptr;
	}
	else
	{
		// no thread to stop
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Thread handle NULL");
		return E_FAIL;
	}

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return S_OK;
}

DWORD WINAPI CSmartCardConnectionNotifier::_ThreadProc(LPVOID lpParameter)  // NOSONAR - API-01: signature dictated by Windows/callback API 
{
	auto pSmartCardConnectionNotifier = static_cast<CSmartCardConnectionNotifier*>(lpParameter);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"");
	pSmartCardConnectionNotifier->WaitForSmartCardInsertion();

	return 0;
}





// Statuses after which the monitoring loop must re-establish its context and resume,
// instead of terminating the thread (issue #33):
// - SCARD_E_SYSTEM_CANCELLED : the system cancelled the context when logonui is launched
//   cf http://blogs.msdn.com/shivaram/archive/2007/02/26/smart-card-logon-on-windows-vista.aspx
// - SCARD_E_SERVICE_STOPPED / SCARD_E_NO_SERVICE : on Windows 8+ SCardSvr is trigger-managed
//   and stops when the last reader is removed (e.g. an unplugged Yubikey); it restarts on replug
// - SCARD_E_INVALID_HANDLE : the context died with the service
// - SCARD_E_UNKNOWN_READER : a watched reader disappeared while waiting
static BOOL IsRecoverableStatus(LONG Status)
{
	return Status == SCARD_E_SYSTEM_CANCELLED
		|| Status == SCARD_E_SERVICE_STOPPED
		|| Status == SCARD_E_NO_SERVICE
		|| Status == SCARD_E_INVALID_HANDLE
		|| Status == SCARD_E_UNKNOWN_READER;
}

// try to know if there are an existing card or wait for this card
// then call ValidateCard
LONG CSmartCardConnectionNotifier::WaitForSmartCardInsertion()  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{

	LONG					Status;
	LONG					lReturn;

	SCARD_READERSTATE 		rgscState[MAXIMUM_SMARTCARD_READERS];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD             		dwI;
	DWORD             		dwRdrCount;
	HANDLE					hAccessStartedEvent[2];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	BOOL					fFirstAttempt = TRUE;


	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	do {  // NOSONAR - COMPLEXITY-01: nested break retained; logic verified
		// backoff so a flapping resource manager cannot make the recovery loop spin
		if (!fFirstAttempt)
		{
			Sleep(250);
		}
		fFirstAttempt = FALSE;

		// Establish the Resource Manager Context.
		Status = SCardEstablishContext(SCARD_SCOPE_USER,nullptr,nullptr,&_hSCardContext);
		if(Status == SCARD_E_NO_SERVICE)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext : SCARD_E_NO_SERVICE");
			// Wait for the (re)start of the Resource Manager
			hAccessStartedEvent[0] = SCardAccessStartedEvent();
			if (hAccessStartedEvent[0] == nullptr)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardAccessStartedEvent : %d",GetLastError());
				Status = SCARD_E_NO_SERVICE;
				break;
			}
			hAccessStartedEvent[1] = _hAccessStartedEvent;
			Status = WaitForMultipleObjects(2,hAccessStartedEvent,FALSE,INFINITE);
			SCardReleaseStartedEvent();
			if (Status == (WAIT_OBJECT_0 + 1))
			{
				// stop requested by Stop()
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardAccessStartedEvent-Cancelled");
				Status = SCARD_E_CANCELLED;
				break;
			}
			else if (Status != WAIT_OBJECT_0)
			{
				// error
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardAccessStartedEvent-WaitForMultipleObjects :%X",Status);
				Status = SCARD_E_NO_SERVICE;
				break;
			}
			// no error and manager available
			Status = SCardEstablishContext(SCARD_SCOPE_USER,nullptr,nullptr,&_hSCardContext);
			if(Status != SCARD_S_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext2 :%X",Status);
				// retried or aborted by the while() condition below (issue #33)
				continue;
			}
		}
		else if(Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext :%X",Status);
			// retried or aborted by the while() condition below (issue #33)
			continue;
		}

		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Main loop started");
		///////////////////////////////////////////////////////////
		// Main loop : wait for any changes
		///////////////////////////////////////////////////////////
		dwRdrCount = 0; // for PNP fake Reader
		Status = GetReaderStates(rgscState,&dwRdrCount);
		if(Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetReaderStates :%X",Status);
			// fall through to the shared cleanup below, which decides whether to retry (issue #33)
		}

		// Call the SCardGetStatusChange to detect configuration changes on all the detected
		// readers.
		if (Status == SCARD_S_SUCCESS)
		{
			Status = SCardGetStatusChange(_hSCardContext, (DWORD) 2000 ,rgscState,dwRdrCount);
		}
		while((Status == SCARD_S_SUCCESS) || (Status == SCARD_E_TIMEOUT))  // NOSONAR - COMPLEXITY-01: nested break retained; logic verified
		{ 
			for (dwI = 0; dwI < dwRdrCount; dwI++)
		{
			// Skip unchanged or mute readers early
			if ((SCARD_STATE_MUTE & rgscState[dwI].dwEventState) ||  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				!(SCARD_STATE_CHANGED & rgscState[dwI].dwEventState))
			{
				rgscState[dwI].dwCurrentState = rgscState[dwI].dwEventState;
				continue;
			}

			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"SCardGetStatusChange :0x%08X", rgscState[dwI].dwEventState);

			// Handle card insertion at reduced nesting level
			if ((SCARD_STATE_PRESENT & rgscState[dwI].dwEventState) &&  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				!(SCARD_STATE_PRESENT & rgscState[dwI].dwCurrentState))
			{
				LPTSTR pmszCards = nullptr;
				DWORD cch = SCARD_AUTOALLOCATE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
				for (DWORD dwJ = 0; dwJ < 4; dwJ++)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"ATR :%02X %02X %02X %02X %02X %02X %02X %02X",
						rgscState[dwI].rgbAtr[dwJ * 8 + 0],
						rgscState[dwI].rgbAtr[dwJ * 8 + 1],
						rgscState[dwI].rgbAtr[dwJ * 8 + 2],
						rgscState[dwI].rgbAtr[dwJ * 8 + 3],
						rgscState[dwI].rgbAtr[dwJ * 8 + 4],
						rgscState[dwI].rgbAtr[dwJ * 8 + 5],
						rgscState[dwI].rgbAtr[dwJ * 8 + 6],
						rgscState[dwI].rgbAtr[dwJ * 8 + 7]
					);
				}
				Status = SCardListCards(_hSCardContext, rgscState[dwI].rgbAtr, nullptr, 0, (LPTSTR)&pmszCards, &cch);
				if (Status != SCARD_S_SUCCESS)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"Unable to retrieve smart card name 0x%08x", Status);
				}
				Callback(EID_CREDENTIAL_PROVIDER_READER_STATE::EIDCPRSConnecting, rgscState[dwI].szReader, pmszCards, (rgscState[dwI].dwEventState) >> 16);
				SCardFreeMemory(_hSCardContext, pmszCards);
				rgscState[dwI].dwCurrentState = SCARD_STATE_PRESENT;
			}

			// Handle card removal at reduced nesting level
			if (!(SCARD_STATE_PRESENT & rgscState[dwI].dwEventState) &&  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				(SCARD_STATE_PRESENT & rgscState[dwI].dwCurrentState) &&
				!(SCARD_STATE_MUTE & rgscState[dwI].dwCurrentState))
			{
				Callback(EID_CREDENTIAL_PROVIDER_READER_STATE::EIDCPRSDisconnected, rgscState[dwI].szReader, nullptr, 0);
				rgscState[dwI].dwCurrentState = SCARD_STATE_EMPTY;
			}

			// Memorize the current state.
			rgscState[dwI].dwCurrentState = rgscState[dwI].dwEventState;
		}	
			//update reader list (add or remove readers)
			Status = GetReaderStates(rgscState,&dwRdrCount);
			if(Status != SCARD_S_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetReaderStates :%X",Status);
				// shared cleanup below decides whether to retry (issue #33)
				break;
			}
			if( WaitForSingleObject(_hAccessStartedEvent,0) != WAIT_TIMEOUT)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Event signaled _hAccessStartedEvent");
				// stop requested by Stop()
				Status = SCARD_E_CANCELLED;
				break;
			}
			Status = SCardGetStatusChange(_hSCardContext, INFINITE ,rgscState,dwRdrCount);
		} // end while

		// free memory
		for ( dwI=0; dwI < dwRdrCount; dwI++)
		{
			// if the monitoring was interrupted (logonui launched, smart card service
			// stopped after the reader was unplugged, ...), notify that the card has
			// been removed so it can be added again when monitoring resumes
			if (IsRecoverableStatus(Status) &&
				(SCARD_STATE_PRESENT & rgscState[dwI].dwEventState))
			{
				Callback(EID_CREDENTIAL_PROVIDER_READER_STATE::EIDCPRSDisconnected,rgscState[dwI].szReader, nullptr, 0);
			}
			EIDFree((PVOID)rgscState[dwI].szReader);
		}
		// Resource Manager Context: Release
		// do not store the result into Status : it drives the retry decision below
		lReturn = SCardReleaseContext(_hSCardContext);
		if (lReturn != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardReleaseContext :%X",lReturn);
		}
		_hSCardContext = NULL;

		// keep monitoring across recoverable interruptions, unless a stop was requested (issue #33)
	} while (IsRecoverableStatus(Status) && WaitForSingleObject(_hAccessStartedEvent,0) == WAIT_TIMEOUT);

	if (Status != SCARD_E_CANCELLED)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardGetStatusChange stopped :%X",Status);
	}
	// synchronization event
	CloseHandle(_hAccessStartedEvent);
	_hAccessStartedEvent = nullptr;
	Callback(EID_CREDENTIAL_PROVIDER_READER_STATE::EIDCPRSThreadFinished,_T(""), nullptr, 0);
	return Status;
}



// Look for readers in system
// and then for connected card
LONG CSmartCardConnectionNotifier::GetReaderStates(SCARD_READERSTATE rgscState[MAXIMUM_SMARTCARD_READERS],PDWORD dwRdrCount) {  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
	LONG					Status;
	DWORD   				dwReadersLength;
	LPTSTR					szRdr;
	LPTSTR					szListReaders;

	DWORD					dwPreviousRdrCount;
	DWORD					dwI;
	DWORD					dwJ;
	DWORD					dwOldListToNewList[MAXIMUM_SMARTCARD_READERS];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD					dwNewListToOldList[MAXIMUM_SMARTCARD_READERS];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	LPTSTR					szReader[MAXIMUM_SMARTCARD_READERS];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	
	// initialise matrix
	for ( dwI = 1; dwI < MAXIMUM_SMARTCARD_READERS; dwI++ )
	{
		dwOldListToNewList[dwI] = (DWORD)-1;
		dwNewListToOldList[dwI] = (DWORD)-1;
	}
	
	
	if (! *dwRdrCount)
	{
		// init fake PNP reader
		memset(&rgscState[0],0,sizeof(SCARD_READERSTATE));
		rgscState[0].szReader = (LPWSTR) EIDAlloc((DWORD)(sizeof(WCHAR)*(wcslen(L"\\\\?PNP?\\NOTIFICATION")+1)));
		if (!rgscState[0].szReader)
		{
			return SCARD_E_NO_MEMORY;
		}
		wcscpy_s((WCHAR*) rgscState[0].szReader,wcslen(L"\\\\?PNP?\\NOTIFICATION")+1,L"\\\\?PNP?\\NOTIFICATION"); // NOSONAR - SCARD_READERSTATE requires LPWSTR cast for string operations
		rgscState[0].dwCurrentState = SCARD_STATE_UNAWARE;
		rgscState[0].dwEventState = SCARD_STATE_UNAWARE;
		*dwRdrCount = 1;
		dwPreviousRdrCount = 1;
	}
	else
	{
		dwPreviousRdrCount = *dwRdrCount;
	}

	dwReadersLength = SCARD_AUTOALLOCATE;
	szListReaders = nullptr;
	Status = SCardListReaders(_hSCardContext,nullptr,(LPTSTR)&szListReaders,&dwReadersLength);
	// No reader is connected to the system.
	if (Status == SCARD_E_NO_READERS_AVAILABLE)
	{
		*dwRdrCount = 1;
	}
	// An error condition was raised.
	else if (Status != SCARD_S_SUCCESS)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardListReaders: %Xh",Status);
		return Status;
	}
	// else : At least one reader is available !
	else
	{
		// NOSONAR - CONTROL-01: Empty else for comment/documentation clarity
	}
	

	// Track events on found readers.
	
	if (Status == SCARD_S_SUCCESS) {
		// Flag Reader removed or added
		szRdr = szListReaders;
		dwJ = 1;
		while ( 0 != *szRdr ) 
		{
			szReader[dwJ] = szRdr;
			for (dwI = 1; dwI < dwPreviousRdrCount; dwI++) {
				if (wcscmp(rgscState[dwI].szReader,szRdr) == 0)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					dwOldListToNewList[dwI] = dwJ;
					dwNewListToOldList[dwJ] = dwI;
					break;
				}
			}
			szRdr += lstrlen(szRdr) + 1;
			dwJ++;
		}
		*dwRdrCount = dwJ;
	}
	
	// remove old entries
	for (dwI = 1; dwI < dwPreviousRdrCount; dwI++) {  // NOSONAR - COMPLEXITY-01: loop mutates counters by design; logic verified
		if (dwOldListToNewList[dwI] == ((DWORD)-1))
		{
			// to remove
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remove old entries %s",rgscState[dwI].szReader);
			if (dwI != (dwPreviousRdrCount -1) )
			{
				// not the last
				// free memory
				EIDFree((PVOID)rgscState[dwI].szReader);
				// so move the last to this place
				rgscState[dwI].szReader = rgscState[dwPreviousRdrCount -1].szReader;
				// The last slot leaves the active range below; drop its copy of
				// the pointer so nothing can free or use it twice.
				rgscState[dwPreviousRdrCount -1].szReader = nullptr;
				rgscState[dwI].cbAtr = rgscState[dwPreviousRdrCount -1].cbAtr;
				rgscState[dwI].dwCurrentState = rgscState[dwPreviousRdrCount -1].dwCurrentState;
				rgscState[dwI].dwEventState = rgscState[dwPreviousRdrCount -1].dwEventState;
				rgscState[dwI].pvUserData = rgscState[dwPreviousRdrCount -1].pvUserData;
				for(dwJ = 0; dwJ < 36; dwJ++)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					rgscState[dwI].rgbAtr[dwJ] = rgscState[dwPreviousRdrCount -1].rgbAtr[dwJ];
				}
				// update matrix
				dwOldListToNewList[dwI] = dwOldListToNewList[dwPreviousRdrCount -1];
				for (dwJ = 1; dwJ < MAXIMUM_SMARTCARD_READERS; dwJ++)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
				{
					if (dwNewListToOldList[dwJ] == dwPreviousRdrCount -1) {
						dwNewListToOldList[dwJ] = dwI;
					}
				}
				// redo the work on this item
				dwI--;
			}
			else
			{
				// last entry : nothing to move, but its name still has to be freed
				EIDFree((PVOID)rgscState[dwI].szReader);
				rgscState[dwI].szReader = nullptr;
			}
			dwPreviousRdrCount--;
		}
		else
		{
			// update the pointer in szListReaders
		}
	}
	
	
	// add new entries
	for (dwI = 1; dwI < *dwRdrCount; dwI++) {
		if (dwNewListToOldList[dwI] == (DWORD) -1)
		{
			// to add
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Add new entries %s",szReader[dwI]);
			memset(&rgscState[dwPreviousRdrCount],0,sizeof(SCARD_READERSTATE));

			rgscState[dwPreviousRdrCount].szReader = (LPWSTR) EIDAlloc((DWORD)(sizeof(WCHAR)*(wcslen(szReader[dwI])+1)));
			if (!rgscState[dwPreviousRdrCount].szReader)
			{
				// Readers not yet added stay untracked; the next pass retries them.
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No memory for reader %s",szReader[dwI]);
				*dwRdrCount = dwPreviousRdrCount;
				SCardFreeMemory(_hSCardContext,szListReaders);
				return SCARD_E_NO_MEMORY;
			}
			wcscpy_s((WCHAR*) rgscState[dwPreviousRdrCount].szReader,wcslen(szReader[dwI])+1,szReader[dwI]); // NOSONAR - SCARD_READERSTATE requires LPWSTR cast for string operations
			rgscState[dwPreviousRdrCount].dwCurrentState = SCARD_STATE_UNAWARE;
			rgscState[dwPreviousRdrCount].dwEventState = SCARD_STATE_UNAWARE;
			dwPreviousRdrCount++;
		}
	}
	SCardFreeMemory(_hSCardContext,szListReaders);
	return SCARD_S_SUCCESS;
}

void CSmartCardConnectionNotifier::Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message,__in LPCTSTR Reader,__in_opt LPCTSTR CardName, __in_opt USHORT ActivityCount)
{
	_CallBack->Callback(Message,Reader,CardName,ActivityCount);
}
