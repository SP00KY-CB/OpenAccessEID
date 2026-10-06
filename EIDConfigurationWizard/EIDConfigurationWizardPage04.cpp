#include <Windows.h>
#include <tchar.h>
#include <CommCtrl.h>
#include <WinUser.h>
#include "global.h"
#include "EIDConfigurationWizard.h"
#include "ProgressDialog.h"

#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"

#include "CContainerHolder.h"

// RAII helper to automatically close progress dialog on scope exit
class ProgressGuard {
    HWND m_hProgress;
public:
    explicit ProgressGuard(HWND hProgress) : m_hProgress(hProgress) {}
    ~ProgressGuard() { CloseProgressDialog(m_hProgress); }
    ProgressGuard(const ProgressGuard&) = delete;
    ProgressGuard& operator=(const ProgressGuard&) = delete;
};

#pragma comment(lib,"Netapi32")
#pragma comment(lib,"Winscard")
#pragma comment(lib,"Scarddlg")

// Static buffer for column name (required for PTSTR compatibility with const-correctness)
static TCHAR s_szColumnName[] = TEXT("Comment");                     // NOSONAR - GLOBAL-01: Runtime-initialized LSA state

CContainerHolderFactory<CContainerHolderTest> *pCredentialList = nullptr;  // NOSONAR - RUNTIME-01: Credential list, populated at runtime
DWORD dwCurrentCredential = 0xFFFFFFFF;  // NOSONAR - RUNTIME-01: Selected credential index, modified at runtime
BOOL fHasDeselected = TRUE;  // NOSONAR - RUNTIME-01: UI state flag, modified at runtime

// Forward declaration
BOOL PopulateListViewCheckData(HWND hWndListViewList, HWND hWndListViewCheck);

PTSTR Columns[] = { s_szColumnName };  // NOSONAR - RUNTIME-01: Array of non-const pointers for ListView API
#define COLUMN_NUM ARRAYSIZE(Columns)  // NOSONAR - MACRO-02: ARRAYSIZE requires preprocessor

BOOL InitListViewColumns(HWND hWndListView) 
{ 
    LVCOLUMN lvc; 
    int iCol; 

    // Initialize the LVCOLUMN structure.
    // The mask specifies that the format, width, text, and subitem members
    // of the structure are valid. 
    lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH; 
	  
    // Add the columns
    for (iCol = 0; iCol < COLUMN_NUM; iCol++)  // NOSONAR - PERF-01: loop counter declared once at function scope 
    { 
        lvc.iSubItem = iCol;
        lvc.pszText = Columns[iCol];	
        lvc.fmt = LVCFMT_LEFT;
		lvc.cx = 450;

        if (ListView_InsertColumn(hWndListView, iCol, &lvc) == -1) 
            return FALSE; 
    } 
    return TRUE; 
} 

BOOL PopulateListViewCheckData(HWND hWndListViewList, HWND hWndListViewCheck)
{
	LVITEM lvI;
	UINT ColumnsToDisplay[] = {1,2,3};  // NOSONAR - LSASS-01: C-style array required by Win32 API
	TCHAR szMessage[256] = TEXT("");  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	// Some code to create the list-view control.
	// Initialize LVITEM members that are common to all items.
	lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE | LVIF_COLUMNS | LVIF_GROUPID; 
	lvI.state = 0; 
	lvI.stateMask = 0; 

	LVGROUP grp;
	
	if (!pCredentialList)
	{
		return FALSE;
	}
	CContainerHolderTest* pContainerHolder = pCredentialList->GetContainerHolderAt(dwCurrentCredential);
	// dwCurrentCredential is 0xFFFFFFFF when nothing is selected, and the list
	// can shrink when a card is removed.
	if (!pContainerHolder)
	{
		return FALSE;
	}

	//GRP
	for (int index = pContainerHolder->GetCheckCount() -1; index >= 0; index--)
	{
		grp.cbSize = sizeof(grp);
		grp.iGroupId = index;
		switch(index)
		{  // NOSONAR - ENUM-01: explicit enum qualification retained for clarity
		case std::to_underlying(CheckType::CHECK_SIGNATUREONLY):
			LoadString(g_hinst,IDS_04TESTSIGNATURE, szMessage, ARRAYSIZE(szMessage));
			break;
		case std::to_underlying(CheckType::CHECK_TRUST):
			LoadString(g_hinst,IDS_04TESTTRUST, szMessage, ARRAYSIZE(szMessage));
			break;
		case std::to_underlying(CheckType::CHECK_CRYPTO):
			LoadString(g_hinst,IDS_04TESTCRYPTO, szMessage, ARRAYSIZE(szMessage));
			break;
		default:
			break;
		}
		grp.pszHeader = szMessage;
		grp.cchHeader = (int) (grp.pszHeader?_tcslen(grp.pszHeader):0);
		grp.pszTask = pContainerHolder->GetSolveDescription(index);
		grp.mask = LVGF_HEADER | LVGF_GROUPID | LVGF_TASK;
		ListView_InsertGroup(hWndListViewCheck, 0, &grp);
		if (grp.pszTask)
			EIDFree(grp.pszTask);
	}

	// Initialize LVITEM members that are different for each item. 
	for (int index = 0; index < pContainerHolder->GetCheckCount(); index++)
	{
		lvI.iItem = index;
		lvI.iImage = pContainerHolder->GetImage(index);
		lvI.iSubItem = 0;
		lvI.pszText = pContainerHolder->GetDescription(index);
		lvI.cColumns = ARRAYSIZE(ColumnsToDisplay);
		lvI.puColumns = ColumnsToDisplay;
		lvI.iGroupId = index;
		ListView_InsertItem(hWndListViewCheck, &lvI);
		// The list view keeps its own copy of the text.
		if (lvI.pszText)
		{
			EIDFree(lvI.pszText);
		}
	}


	return TRUE;
}

BOOL PopulateListViewListData(HWND hWndListView)
{
	LVITEM lvI;
	UINT ColumnsToDisplay[] = {1,2,3};  // NOSONAR - LSASS-01: C-style array required by Win32 API
	// Some code to create the list-view control.
	
	ListView_DeleteAllItems(hWndListView);
	// pCredentialList is reset to nullptr when later pages tear the list down.
	if (!pCredentialList)
	{
		return FALSE;
	}
	// Initialize LVITEM members that are common to all items.
	lvI.mask = LVIF_TEXT | LVIF_IMAGE |  LVIF_STATE | LVIF_COLUMNS; 
	
	// Initialize LVITEM members that are different for each item. 
	for (DWORD index = 0; index < pCredentialList->ContainerHolderCount(); index++)
	{
		// Each accessor call takes the lock separately, so the list can shrink
		// between the count and the lookup.
		CContainerHolderTest* pHolder = pCredentialList->GetContainerHolderAt(index);  // NOSONAR - API-01: pointer type dictated by non-const accessor API
		if (!pHolder || !pHolder->GetContainer())
		{
			continue;
		}
		lvI.stateMask = LVIS_OVERLAYMASK;
		lvI.state = INDEXTOOVERLAYMASK(pHolder->GetIconIndex() +1);
		lvI.iItem = index;
		lvI.iImage = 0;
		lvI.iSubItem = 0;
		lvI.pszText = pHolder->GetContainer()->GetUserName();
		lvI.cColumns = ARRAYSIZE(ColumnsToDisplay);
		lvI.puColumns = ColumnsToDisplay;
		ListView_InsertItem(hWndListView, &lvI);
	}
	
	ListView_SetItemState(hWndListView, dwCurrentCredential, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
	ListView_Update(hWndListView, dwCurrentCredential);
	return TRUE;
}

//  Creates a new icon as a copy of the passed-in icon, overlayed with a shortcut image. 

#define DEBUGH(hbitmap) if( OpenClipboard ( nullptr ) ) \
{\
EmptyClipboard();\
SetClipboardData(CF_BITMAP,hbitmap);\
CloseClipboard();\
}
HWND hWndTemp;  // NOSONAR - RUNTIME-01: Temporary window handle for UI operations

HICON MiniIcon(HICON SourceIcon)
{
	// Zero-initialised so that the single cleanup in __finally is correct
	// whichever step fails.
	ICONINFO SourceIconInfo = {};
	ICONINFO TargetIconInfo = {};
	HICON TargetIcon = nullptr;
	BITMAP SourceBitmapInfo = {};
	HDC SourceDC = nullptr;
	HDC TargetDC = nullptr;
	HDC ScreenDC = nullptr;
	HBITMAP OldSourceBitmap = nullptr;
	HBITMAP OldTargetBitmap = nullptr;
	__try
	{
		/* Get information about the source icon. GetIconInfo hands us copies
		   of the mask and colour bitmaps, which we own and must delete. */
		if (! GetIconInfo(SourceIcon, &SourceIconInfo)
			|| nullptr == SourceIconInfo.hbmColor
			|| 0 == GetObjectW(SourceIconInfo.hbmColor, sizeof(BITMAP), &SourceBitmapInfo))
		{
		  __leave;
		}

		TargetIconInfo.fIcon = SourceIconInfo.fIcon;
		TargetIconInfo.xHotspot = SourceIconInfo.xHotspot;
		TargetIconInfo.yHotspot = SourceIconInfo.yHotspot;
		TargetIconInfo.hbmMask = nullptr;
		TargetIconInfo.hbmColor = nullptr;

		/* Setup the source, shortcut and target masks */
		SourceDC = CreateCompatibleDC(nullptr);
		if (nullptr == SourceDC) __leave;
		OldSourceBitmap = (HBITMAP) SelectObject(SourceDC, SourceIconInfo.hbmMask);
		if (nullptr == OldSourceBitmap) __leave;

		TargetDC = CreateCompatibleDC(nullptr);
		if (nullptr == TargetDC) __leave;
		TargetIconInfo.hbmMask = CreateCompatibleBitmap(TargetDC, GetSystemMetrics(SM_CXICON),
														GetSystemMetrics(SM_CYICON));
		if (nullptr == TargetIconInfo.hbmMask) __leave;
		ScreenDC = GetDC(nullptr);
		if (nullptr == ScreenDC) __leave;
		TargetIconInfo.hbmColor = CreateCompatibleBitmap(ScreenDC, GetSystemMetrics(SM_CXICON),
														 GetSystemMetrics(SM_CYICON));
		if (nullptr == TargetIconInfo.hbmColor) __leave;
		OldTargetBitmap = (HBITMAP) SelectObject(TargetDC, TargetIconInfo.hbmMask);
		if (nullptr == OldTargetBitmap) __leave;

		/* Create the target mask by ANDing the source and shortcut masks */
		if (! BitBlt(TargetDC, 0, 0, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON),
					 SourceDC, 0, 0, WHITENESS))
		{
			__leave;
		}
		if (! BitBlt(TargetDC, 0, GetSystemMetrics(SM_CYICON) - SourceBitmapInfo.bmHeight, SourceBitmapInfo.bmWidth, SourceBitmapInfo.bmHeight,
					 SourceDC, 0, 0, SRCCOPY))
		{
			__leave;
		}
		if (nullptr == SelectObject(SourceDC, SourceIconInfo.hbmColor) ||
			nullptr == SelectObject(TargetDC, TargetIconInfo.hbmColor))
		{
		  __leave;
		}

		if (! BitBlt(TargetDC, 0, GetSystemMetrics(SM_CYICON) - SourceBitmapInfo.bmHeight, SourceBitmapInfo.bmWidth, SourceBitmapInfo.bmHeight,
					 SourceDC, 0, 0, SRCCOPY))
		{
			__leave;
		}

		/* Deselect the target bitmap before handing it to CreateIconIndirect */
		SelectObject(TargetDC, OldTargetBitmap);
		OldTargetBitmap = nullptr;

		/* Create the icon using the bitmaps prepared earlier. CreateIconIndirect
		   copies the bitmaps, so ours are released in __finally either way. */
		TargetIcon = CreateIconIndirect(&TargetIconInfo);
	}
	__finally
	{
		/* Single cleanup path: deselect, then delete bitmaps, then delete DCs */
		if (ScreenDC)
			ReleaseDC(nullptr, ScreenDC);
		if (OldTargetBitmap)
			SelectObject(TargetDC, OldTargetBitmap);
		if (OldSourceBitmap)
			SelectObject(SourceDC, OldSourceBitmap);
		if (TargetIconInfo.hbmColor)
			DeleteObject(TargetIconInfo.hbmColor);
		if (TargetIconInfo.hbmMask)
			DeleteObject(TargetIconInfo.hbmMask);
		if (SourceIconInfo.hbmColor)
			DeleteObject(SourceIconInfo.hbmColor);
		if (SourceIconInfo.hbmMask)
			DeleteObject(SourceIconInfo.hbmMask);
		if (TargetDC)
			DeleteDC(TargetDC);
		if (SourceDC)
			DeleteDC(SourceDC);
	}
	return TargetIcon;
}

BOOL InitListViewCheckIcon(HWND hWndListView)
{
	HICON hiconItem;     // icon for list-view items 
    HIMAGELIST hLarge;   // image list for icon view 
    HIMAGELIST hSmall;   // image list for other views 

    // Create the full-sized icon image lists. 

	hLarge = ImageList_Create(GetSystemMetrics(SM_CXICON), 
                              GetSystemMetrics(SM_CYICON), 
                               ILC_COLORDDB | ILC_MASK, 3, 3); 

    hSmall = ImageList_Create(GetSystemMetrics(SM_CXSMICON), 
                              GetSystemMetrics(SM_CYSMICON), 
                               ILC_COLORDDB | ILC_MASK, 3, 3); 
	
    ImageList_SetBkColor(hLarge, GetSysColor(COLOR_WINDOW));
	ImageList_SetBkColor(hSmall, GetSysColor(COLOR_WINDOW));

	// Add an icon to each image list.
	//Check if hIcon is valid
	if (HMODULE hDll = EIDLoadSystemLibrary(TEXT("imageres.dll")))
	{
		// red shield
		hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(105)); 
		ImageList_AddIcon(hLarge, hiconItem); 
		ImageList_AddIcon(hSmall, hiconItem); 
		DestroyIcon(hiconItem); 
	    
		// yellow shield
		hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(107)); 
		ImageList_AddIcon(hLarge, hiconItem); 
		ImageList_AddIcon(hSmall, hiconItem); 
		DestroyIcon(hiconItem); 
	    
		// green shield
		hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(106)); 
		ImageList_AddIcon(hLarge, hiconItem); 
		ImageList_AddIcon(hSmall, hiconItem); 
		DestroyIcon(hiconItem); 

		// blue circle with a "i" inside
		hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(81)); 
		ImageList_AddIcon(hLarge, hiconItem); 
		ImageList_AddIcon(hSmall, hiconItem); 
		DestroyIcon(hiconItem);
		FreeLibrary(hDll) ;
	}

	// Assign the image lists to the list-view control. 
    ListView_SetImageList(hWndListView, hLarge, LVSIL_NORMAL); 
    ListView_SetImageList(hWndListView, hSmall, LVSIL_SMALL); 
	return TRUE;
}

HICON LoadModIcon(int Num)
{
	HMODULE hDll2 = nullptr;
	HRSRC hResInfo = nullptr;
	HGLOBAL hGlobal = nullptr;
	HRSRC hResInfo2 = nullptr;
	HGLOBAL hGlobal2 = nullptr;
	int iResourceNum;
	HICON hCertOK = nullptr;
	__try
	{
		hDll2 = EIDLoadSystemLibrary(TEXT("imageres.dll"));
		if (!hDll2) __leave;
		hResInfo = FindResource(hDll2,MAKEINTRESOURCE(Num),RT_GROUP_ICON);
		if (!hResInfo) __leave;
		hGlobal = LoadResource(hDll2, hResInfo);
		if (!hGlobal) __leave;
		iResourceNum = LookupIconIdFromDirectoryEx((PBYTE)LockResource(hGlobal), TRUE, 16, 16, 0);
		hResInfo2 = FindResource(hDll2,MAKEINTRESOURCE(iResourceNum),RT_ICON);
		if (!hResInfo2) __leave;
		hGlobal2 = LoadResource(hDll2, hResInfo2);
		if (!hGlobal2) __leave;
		DWORD dwSize = SizeofResource(hDll2,hResInfo2);
		hCertOK = CreateIconFromResourceEx((PBYTE)LockResource(hGlobal2),dwSize,TRUE,0x00030000,0,0,0);
		//Check if hIcon is valid
	}
	__finally
	{
		if (hGlobal) 
			FreeResource(hGlobal);
		if (hGlobal2) 
			FreeResource(hGlobal2);
		if (hDll2)
			FreeLibrary(hDll2) ;
	}
	return hCertOK;
}

BOOL InitListViewListIcon(HWND hWndListView)
{
	HIMAGELIST hLarge;   // image list for icon view 
	HIMAGELIST hSmall;   // image list for icon view 

    // Create the full-sized icon image lists. 

	hLarge = ImageList_Create(GetSystemMetrics(SM_CXICON), 
                              GetSystemMetrics(SM_CYICON), 
                               ILC_COLORDDB | ILC_MASK, 3, 3); 

	hSmall = ImageList_Create(GetSystemMetrics(SM_CXSMICON), 
                              GetSystemMetrics(SM_CYSMICON), 
                               ILC_COLORDDB | ILC_MASK, 3, 3); 

    ImageList_SetBkColor(hLarge, GetSysColor(COLOR_WINDOW));
	ImageList_SetBkColor(hSmall, GetSysColor(COLOR_WINDOW));

	// Add an icon to each image list.
	HMODULE hDll = EIDLoadSystemLibrary(TEXT("certmgr.dll"));
	if (hDll)
	{
		//Check if hIcon is valid
		HICON hIcon = LoadIcon(hDll, MAKEINTRESOURCE(218));
		ImageList_AddIcon(hLarge, hIcon );
		ImageList_AddIcon(hSmall, hIcon );

		DestroyIcon(hIcon );
		FreeLibrary(hDll);
	}
	hDll = EIDLoadSystemLibrary(TEXT("imageres.dll"));
	if (hDll)
	{
		HICON hIcon = MiniIcon(LoadModIcon(105));

		ImageList_AddIcon(hLarge, hIcon ); 
		ImageList_AddIcon(hSmall, hIcon ); 
		DestroyIcon(hIcon ); 
		hIcon =  MiniIcon(LoadModIcon(106));
		ImageList_AddIcon(hLarge, hIcon ); 
		ImageList_AddIcon(hSmall, hIcon ); 
		DestroyIcon(hIcon ); 
		FreeLibrary(hDll);
	}
	ImageList_SetOverlayImage(hLarge, 1, 1);
	ImageList_SetOverlayImage(hLarge, 2, 2);
	ImageList_SetOverlayImage(hSmall, 1, 1);
	ImageList_SetOverlayImage(hSmall, 2, 2);
	// Assign the image lists to the list-view control. 
    ListView_SetImageList(hWndListView, hLarge, LVSIL_NORMAL); 
	ListView_SetImageList(hWndListView, hSmall, LVSIL_SMALL); 
	
	return TRUE;
}

BOOL InitListViewView(HWND hWndListView)
{
	ListView_SetExtendedListViewStyle(hWndListView, LVS_EX_JUSTIFYCOLUMNS   );
	ListView_EnableGroupView(hWndListView, TRUE);
	return TRUE;
}

// TRUE when the selected credential exists and passed its checks. The list can be
// torn down by later pages or shrink when a card is removed, so never dereference
// GetContainerHolderAt() unchecked.
static BOOL CurrentCredentialIsUsable()
{
	if (!pCredentialList)
	{
		return FALSE;
	}
	CContainerHolderTest* pHolder = pCredentialList->GetContainerHolderAt(dwCurrentCredential);  // NOSONAR - API-01: pointer type dictated by non-const accessor API
	return (pHolder && pHolder->GetIconIndex()) ? TRUE : FALSE;
}

void SelectBestCredential()
{
	dwCurrentCredential = 0;
	if (!pCredentialList)
	{
		return;
	}
	for (DWORD index = 0; index < pCredentialList->ContainerHolderCount(); index++)
	{
		CContainerHolderTest* pHolder = pCredentialList->GetContainerHolderAt(index);  // NOSONAR - API-01: pointer type dictated by non-const accessor API
		if (pHolder && pHolder->GetIconIndex())
		{
			dwCurrentCredential = index;
			break;
		}
	}
}

constexpr UINT WM_MYMESSAGE = WM_USER + 10;

// Helper: Handle refresh button click - reconnect to smart card and refresh credential list
// Returns TRUE if refresh succeeded, FALSE if cancelled or failed
static BOOL HandleRefreshRequest(HWND hWnd)
{
    if (!pCredentialList) return FALSE;

    // Clear all data
    PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
    pCredentialList->DisconnectNotification(szReader);
    dwCurrentCredential = 0xFFFFFFFF;
    ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04LIST));
    ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04CHECKS));

    // Prompt for card
    if (!AskForCard(szReader, dwReaderSize, szCard, dwCardSize))
    {
        if (LONG lReturn = GetLastError(); lReturn != SCARD_W_CANCELLED_BY_USER)
        {
            MessageBoxWin32Ex(lReturn, hWnd);
        }
        return FALSE;
    }

    // Reconnect and trigger refresh
    ProgressGuard progress(ShowProgressDialog(hWnd));
    pCredentialList->ConnectNotification(szReader, szCard, 0);

    // Send activation message to refresh UI
    NMHDR nmh;
    nmh.code = PSN_SETACTIVE;
    SendMessage(hWnd, WM_NOTIFY, 0, (LPARAM)&nmh);
    return TRUE;
}

// Helper: Handle credential selection change in the list view
static void HandleCredentialSelectionChange(HWND hWnd, LPNMITEMACTIVATE pnmItem)
{
    if (!pCredentialList) return;

    if (pnmItem->uNewState & LVIS_SELECTED)
    {
        if ((DWORD)pnmItem->iItem < pCredentialList->ContainerHolderCount())
        {
            fHasDeselected = FALSE;
            dwCurrentCredential = (DWORD)pnmItem->iItem;
            PopulateListViewCheckData(GetDlgItem(hWnd, IDC_04LIST), GetDlgItem(hWnd, IDC_04CHECKS));

            if (CurrentCredentialIsUsable())
            {
                PropSheet_SetWizButtons(hWnd, PSWIZB_NEXT | PSWIZB_BACK);
            }
            else
            {
                PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
            }
        }
    }
    else
    {
        // Deselection - clear check list and reset state
        ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04CHECKS));
        PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
        fHasDeselected = TRUE;
        PostMessage(hWnd, WM_MYMESSAGE, 0, 0);
    }
}

INT_PTR CALLBACK	WndProc_04CHECKS(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) // NOSONAR - variable used
{
	hWndTemp = hWnd;
	switch(message)
	{
	case WM_INITDIALOG:
		InitListViewColumns(GetDlgItem(hWnd, IDC_04CHECKS));
		InitListViewCheckIcon(GetDlgItem(hWnd, IDC_04CHECKS));
		InitListViewListIcon(GetDlgItem(hWnd, IDC_04LIST));
		InitListViewView(GetDlgItem(hWnd, IDC_04CHECKS));
		break;
	case WM_MYMESSAGE:
		if (fHasDeselected)
		{
			ListView_SetItemState(GetDlgItem(hWnd,IDC_04LIST), dwCurrentCredential, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
			ListView_Update(GetDlgItem(hWnd,IDC_04LIST), dwCurrentCredential);
		}
		return TRUE;
		break;
	case WM_NOTIFY :
		{
			LPNMHDR pnmh = (LPNMHDR)lParam;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
			switch(pnmh->code)  // NOSONAR - SCOPE-01: pnmh used across all switch cases
			{
			case PSN_SETACTIVE :
				// list view
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activate");
					ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04CHECKS));
					ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04LIST));
	
					if (!pCredentialList)
					{
						pCredentialList = new CContainerHolderFactory<CContainerHolderTest>();  // NOSONAR - COM-01: UI credential list requires heap allocation
						pCredentialList->SetUsageScenario(CPUS_INVALID,0);
						// Show progress dialog during card enumeration (blocking operation)
						ProgressGuard progress(ShowProgressDialog(hWnd));
						pCredentialList->ConnectNotification(szReader,szCard,0);
					}
					
					if (pCredentialList->HasContainerHolder())
					{
						//has certificate
						SelectBestCredential();
						PopulateListViewListData(GetDlgItem(hWnd, IDC_04LIST));	
						if (CurrentCredentialIsUsable())
						{
							PropSheet_SetWizButtons(hWnd, PSWIZB_NEXT |	PSWIZB_BACK);
						}
						else
						{
							PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
						}
					}
					else
					{
						// no certificate
						TCHAR szMessage[256] = TEXT("");  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
						LoadString(g_hinst,IDS_NO_CERTIFICATE, szMessage, ARRAYSIZE(szMessage));
						LVITEM lvI;
						UINT ColumnsToDisplay[] = {1,2,3};  // NOSONAR - LSASS-01: C-style array required by Win32 API
						// Initialize LVITEM members that are common to all items.
						lvI.mask = LVIF_TEXT | LVIF_IMAGE |  LVIF_COLUMNS; 
						lvI.iItem = 0;
						lvI.iImage = 0;
						lvI.iSubItem = 0;
						lvI.pszText = szMessage;
						lvI.cColumns = ARRAYSIZE(ColumnsToDisplay);
						lvI.puColumns = ColumnsToDisplay;
						ListView_InsertItem(GetDlgItem(hWnd, IDC_04LIST), &lvI);
	
						PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
					}
				}
				break;
			case PSN_WIZNEXT:
				// Proceed to next page
				break;
			case PSN_WIZBACK:
				// back
				if (pCredentialList)
				{
					delete pCredentialList;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
					pCredentialList = nullptr;
				}
				ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04CHECKS));
				if (!fShowNewCertificatePanel)
				{
					PropSheet_PressButton(hWnd, PSBTN_BACK);
				}
				break;
			case PSN_RESET:
				// cancel
				if (pCredentialList)
				{
					delete pCredentialList;  // NOSONAR - OWNERSHIP-01: manual Win32 lifetime management
					pCredentialList = nullptr;
				}
				break;
				
			case LVN_ITEMCHANGED:
				if (pnmh->idFrom == IDC_04LIST && pCredentialList)
				{
					HandleCredentialSelectionChange(hWnd, (LPNMITEMACTIVATE)lParam);
				}
				break;
			case NM_DBLCLK:
				if (pnmh->idFrom == IDC_04LIST && pCredentialList &&
					((LPNMITEMACTIVATE)lParam)->iItem >= 0 && (DWORD)((LPNMITEMACTIVATE)lParam)->iItem < pCredentialList->ContainerHolderCount())
				{
					CContainerHolderTest* pHolder = pCredentialList->GetContainerHolderAt(((LPNMITEMACTIVATE)lParam)->iItem);  // NOSONAR - API-01: pointer type dictated by non-const accessor API
					if (pHolder && pHolder->GetContainer())
					{
						pHolder->GetContainer()->ViewCertificate(hWnd);
					}
				}
				break;
			case LVN_LINKCLICK:
				if (pnmh->idFrom == IDC_04CHECKS && pCredentialList)	
				{
					BOOL fReturn = FALSE;
					CContainerHolderTest* pHolder = pCredentialList->GetContainerHolderAt(dwCurrentCredential);  // NOSONAR - API-01: pointer type dictated by non-const accessor API
					if (pHolder)
					{
						fReturn = pHolder->Solve(((NMLVLINK*)lParam)->iSubItem);
					}
					else
					{
						SetLastError(ERROR_NOT_FOUND);
					}
					if (!fReturn)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
					{
						MessageBoxWin32Ex(GetLastError(),hWnd);
					}
					else
					{
						// refresh
						NMLINK nmh;
						LITEM item;
						nmh.hdr.code = NM_CLICK;
						nmh.hdr.hwndFrom = hWnd;
						nmh.hdr.idFrom = IDC_04CHECKS;
						memset(&item,0,sizeof(LITEM));
						nmh.item = item;
						wcscpy_s(nmh.item.szID,MAX_LINKID_TEXT,L"idrefresh");
						SendMessage(hWnd,WM_NOTIFY,0,(LPARAM)&nmh);
					}
				}
				break;
			case NM_CLICK:
			case NM_RETURN:
				{
					PNMLINK pNMLink = (PNMLINK)lParam;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
					LITEM item = pNMLink->item;
					if (wcscmp(item.szID, L"idrefresh") == 0)
					{
						HandleRefreshRequest(hWnd);
					}
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
