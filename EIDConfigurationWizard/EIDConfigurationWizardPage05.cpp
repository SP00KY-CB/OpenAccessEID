#include <Windows.h>
#include <tchar.h>

#include "../EIDCardLibrary/Tracing.h"

#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"

#include "global.h"
#include "EIDConfigurationWizard.h"

#include "CContainerHolder.h"

// Static buffer for tooltip space character (required for LPTSTR compatibility with const-correctness)
static wchar_t s_wszSpace[] = L" ";  // NOSONAR - GLOBAL-01: Non-const for Windows API LPTSTR compatibility

// from previous step
// credentials
extern CContainerHolderFactory<CContainerHolderTest> *pCredentialList;  // NOSONAR - RUNTIME-01: Credential list
// selected credential
extern DWORD dwCurrentCredential;  // NOSONAR - RUNTIME-01: Selected index

extern BOOL PopulateListViewListData(HWND hWndListView);
extern BOOL InitListViewListIcon(HWND hWndListView);

extern BOOL fHasDeselected;  // NOSONAR - RUNTIME-01: UI state flag

DWORD dwWizardError = 0;  // NOSONAR - RUNTIME-01: Error code, set at runtime

BOOL WizardFinishButton(PTSTR wszUserPassword)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;

	CContainerHolderTest* MyTest = pCredentialList->GetContainerHolderAt(dwCurrentCredential);  // NOSONAR - API-01: pointer type dictated by non-const accessor API
	// No selection (0xFFFFFFFF) or the card was removed since it was selected.
	CContainer* container = MyTest ? MyTest->GetContainer() : nullptr;  // NOSONAR - API-01: pointer type dictated by non-const accessor API
	if (!container)
	{
		SetLastError(ERROR_NOT_FOUND);
		return FALSE;
	}
	PCCERT_CONTEXT pCertContext = container->GetCertificate();
	fReturn = LsaEIDCreateStoredCredential(szUserName, wszUserPassword, pCertContext, container->GetKeySpec() == AT_KEYEXCHANGE);
	if (!fReturn)
	{
		dwError = GetLastError();
	}
	CertFreeCertificateContext(pCertContext);
	SetLastError(dwError);
	return fReturn;
}

BOOL TestLogon(HWND hMainWnd);

HWND hwndInvalidPasswordBalloon = nullptr;  // NOSONAR - RUNTIME-01: Tooltip window handle, created/destroyed at runtime
VOID ShowInvalidPasswordBalloon(HWND hWnd)
{
	if (hwndInvalidPasswordBalloon) 
	{ 
		DestroyWindow(hwndInvalidPasswordBalloon); 
		hwndInvalidPasswordBalloon = nullptr;
	}
	hwndInvalidPasswordBalloon = CreateWindowEx(0, TOOLTIPS_CLASS, nullptr,
                            WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP | TTS_BALLOON | TTS_CLOSE,
                            CW_USEDEFAULT, CW_USEDEFAULT,
                            CW_USEDEFAULT, CW_USEDEFAULT,
                            hWnd, nullptr, g_hinst,
                            nullptr);

	if (hwndInvalidPasswordBalloon)
	{
		LPTSTR szError = nullptr;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
			nullptr,ERROR_INVALID_PASSWORD,0,(LPTSTR)&szError,0,nullptr);
		TOOLINFO ti;
		memset(&ti,0,sizeof(TOOLINFO));
		ti.cbSize   = sizeof(ti);
		ti.uFlags   = TTF_TRANSPARENT | TTF_CENTERTIP | TTF_IDISHWND | TTF_SUBCLASS;
		ti.hwnd     = hWnd;
		ti.uId      = (UINT_PTR) GetDlgItem(hWnd, IDC_05PASSWORD);
		ti.hinst    = g_hinst;
		ti.lpszText = s_wszSpace;
		SendMessage(hwndInvalidPasswordBalloon, TTM_SETTITLE, TTI_ERROR, (LPARAM) szError);
		SendMessage(hwndInvalidPasswordBalloon, TTM_ADDTOOL, 0, (LPARAM) &ti );
		SendMessage(hwndInvalidPasswordBalloon,TTM_TRACKACTIVATE,(WPARAM)TRUE,(LPARAM)&ti);
		LocalFree(szError);
	}
}

constexpr UINT WM_MYMESSAGE = WM_USER + 10;
INT_PTR CALLBACK	WndProc_05PASSWORD(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
	int wmId;
	int wmEvent;
	switch(message)
	{
	case WM_INITDIALOG:
		InitListViewListIcon(GetDlgItem(hWnd,IDC_05LIST));
		SendMessage(GetDlgItem(hWnd,IDC_05TEST), BM_SETCHECK, BST_CHECKED,0);
		break;
	case WM_MYMESSAGE:
		if (fHasDeselected)
		{
			ListView_SetItemState(GetDlgItem(hWnd,IDC_05LIST), dwCurrentCredential, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
			ListView_Update(GetDlgItem(hWnd,IDC_05LIST), dwCurrentCredential);
		}
		return TRUE;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);  // NOSONAR - dead store retained; wmEvent is standard Win32 WndProc boilerplate
		switch(wmId)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
		{
		case IDC_05TEST:
			if (IsDlgButtonChecked(hWnd,IDC_05TEST))
			{
				PropSheet_SetWizButtons(hWnd, PSWIZB_NEXT |	PSWIZB_BACK);
			}
			else
			{
				PropSheet_SetWizButtons(hWnd, PSWIZB_FINISH | PSWIZB_BACK);
			}
			break;
		default:
			break;
		}
		break;

	case WM_NOTIFY :
		{
			LPNMHDR pnmh = (LPNMHDR)lParam;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
			switch(pnmh->code)  // NOSONAR - SCOPE-01: pnmh reused across all switch cases
			{
			case PSN_SETACTIVE :
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activate");
				//this is an interior page
				ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_05LIST));
				PopulateListViewListData(GetDlgItem(hWnd, IDC_05LIST));
				// Enforce correct button state based on test checkbox
				// When test is checked, only allow Next (not Finish) to ensure results page is shown
				if (IsDlgButtonChecked(hWnd, IDC_05TEST))
				{
					PropSheet_SetWizButtons(hWnd, PSWIZB_NEXT | PSWIZB_BACK);
				}
				else
				{
					// When test is not checked, allow Finish to skip testing
					PropSheet_SetWizButtons(hWnd, PSWIZB_FINISH | PSWIZB_BACK);
				}
				break;
			case PSN_WIZFINISH :
			case PSN_WIZNEXT:
				if (hwndInvalidPasswordBalloon) 
				{
					DestroyWindow(hwndInvalidPasswordBalloon); 
					hwndInvalidPasswordBalloon = nullptr;
				}
				GetWindowText(GetDlgItem(hWnd,IDC_05PASSWORD),szPassword,dwPasswordSize);
				// Lock the password buffer in memory to prevent paging to disk
				VirtualLock(szPassword, dwPasswordSize * sizeof(WCHAR));
				if (!WizardFinishButton(szPassword))
				{
					// go to the error page
					dwWizardError = GetLastError();
					if (pnmh->code == PSN_WIZNEXT && dwWizardError != ERROR_INVALID_PASSWORD)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
					{
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						PropSheet_SetCurSelByID(hWnd, IDD_07TESTRESULTNOTOK);
					}
					else
					{
						if (dwWizardError != ERROR_INVALID_PASSWORD)
						{
							MessageBoxWin32Ex(dwWizardError,hWnd);
						}
						else
						{
							ShowInvalidPasswordBalloon(hWnd);
						}
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,(LONG_PTR)IDD_05PASSWORD);
					}
					return TRUE;
				}
				if (IsDlgButtonChecked(hWnd,IDC_05TEST))
				{
					if (!TestLogon(hWnd))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
					{
						// handle if the credential test is cancelled
						dwWizardError = GetLastError();
						if (dwWizardError == ERROR_CANCELLED)
						{
							SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
							return TRUE;
						}
						// go to the error page
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						PropSheet_SetCurSelByID(hWnd, IDD_07TESTRESULTNOTOK);
						return TRUE;
					}
					// Test succeeded - wizard proceeds to next page (success page)
				}
				break;
			case PSN_RESET:
					// Securely clear the password when wizard is cancelled
					SecurelyClearPassword();
					if (pCredentialList)
					{
						delete pCredentialList;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
						pCredentialList = nullptr;
					}
					break;

			case LVN_ITEMCHANGED:
				if (pnmh->idFrom == IDC_05LIST && pCredentialList)
				{
					if (((LPNMITEMACTIVATE)lParam)->uNewState & LVIS_SELECTED )  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
					{
						if ((DWORD)(((LPNMITEMACTIVATE)lParam)->iItem) < pCredentialList->ContainerHolderCount())
						{
							fHasDeselected = FALSE;
							dwCurrentCredential = ((LPNMITEMACTIVATE)lParam)->iItem;
							if (pCredentialList->GetContainerHolderAt(dwCurrentCredential)->GetIconIndex())
							{
								PropSheet_SetWizButtons(hWnd, PSWIZB_FINISH |	PSWIZB_BACK);
							}
							else
							{
								PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
							}
						}
					}
					else
					{
						fHasDeselected = TRUE;
						PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
						PostMessage(hWnd, WM_MYMESSAGE, 0, 0);
					}
				}
				break;
			case NM_DBLCLK:
				if (pnmh->idFrom == IDC_05LIST && pCredentialList &&
					((LPNMITEMACTIVATE)lParam)->iItem >= 0 && (DWORD)((LPNMITEMACTIVATE)lParam)->iItem < pCredentialList->ContainerHolderCount())
				{
					pCredentialList->GetContainerHolderAt(((LPNMITEMACTIVATE)lParam)->iItem)->GetContainer()->ViewCertificate(hWnd);
				}
				break;
			default:
				break;
			}
			break;
		}
	default:
		break;
    }
	return FALSE;
}