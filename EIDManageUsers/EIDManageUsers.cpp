// EIDManageUsers.cpp - Main entry point for EID User Management Tool
// Copyright (c) 2026

#include "EIDManageUsers.h"
#include "MainPage.h"
#include "SettingsDialog.h"
#include "ManageDialog.h"
#include "DetailsDialog.h"
#include "RegistryConfig.h"
#include "EIDUserManagement.h"
#include <shellapi.h>
#include <comdef.h>
#include <lm.h>  // NOSONAR - INCLUDE-01: include order/casing significant for Windows SDK
#include <sddl.h>
#include <exception>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// Global application state
USER_MANAGE_APP_STATE g_appState;  // NOSONAR - GLOBAL-01: mutable global state modified at runtime
HINSTANCE g_hinst = nullptr;  // NOSONAR - GLOBAL-01: pointer assigned at runtime

// Utility: Check if running as administrator
BOOL IsUserAdmin()
{
    BOOL fIsAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY authNT = SECURITY_NT_AUTHORITY;
    PSID pAdminSID = nullptr;

    if (AllocateAndInitializeSid(&authNT, 2,  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdminSID))
    {
        if (!CheckTokenMembership(nullptr, pAdminSID, &fIsAdmin))
        {
            fIsAdmin = FALSE;
        }
        FreeSid(pAdminSID);
    }

    return fIsAdmin;
}

// Utility: Load string resource
std::wstring LoadStringResource(UINT uID)
{
    WCHAR szBuffer[512];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    if (LoadStringW(g_hinst, uID, szBuffer, ARRAYSIZE(szBuffer)))  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
    {
        return std::wstring(szBuffer);
    }
    return std::wstring();
}

// Utility: Set window icon
void SetWindowIcon(HWND hwnd, int iconId)
{
    if (iconId == 0)
        iconId = IDI_APP_ICON;

    HICON hIcon = (HICON)LoadImageW(g_hinst,  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
        MAKEINTRESOURCE(iconId),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXICON),
        GetSystemMetrics(SM_CYICON),
        LR_DEFAULTCOLOR);

    if (hIcon)
    {
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
    }

    HICON hIconSmall = (HICON)LoadImageW(g_hinst,  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
        MAKEINTRESOURCE(iconId),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON),
        LR_DEFAULTCOLOR);

    if (hIconSmall)
    {
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIconSmall);
    }
}

// Utility: Ensure running with administrator privileges
HRESULT EnsureElevated()
{
    if (!IsUserAdmin())
    {
        // Get current executable path
        WCHAR szPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        if (!GetModuleFileNameW(nullptr, szPath, ARRAYSIZE(szPath)))
        {
            return HRESULT_FROM_WIN32(GetLastError());
        }

        // Launch new instance with elevation
        SHELLEXECUTEINFOW sei = {0};
        sei.cbSize = sizeof(SHELLEXECUTEINFOW);
        sei.hwnd = nullptr;
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hInstApp = nullptr;

        if (!ShellExecuteExW(&sei))
        {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED)
            {
                // User declined elevation
                return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
            }
            return HRESULT_FROM_WIN32(dwError);
        }

        // This instance will exit, elevated instance continues
        return S_FALSE;
    }

    return S_OK;
}

// Utility: Format FILETIME to readable string
std::wstring FormatFileTime(const FILETIME& ft)
{
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0)
    {
        return L"Never";
    }

    FILETIME ftLocal;
    if (!FileTimeToLocalFileTime(&ft, &ftLocal))
    {
        return L"Unknown";
    }

    SYSTEMTIME st = {0};
    if (!FileTimeToSystemTime(&ftLocal, &st))
    {
        return L"Unknown";
    }

    WCHAR szBuffer[64];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    swprintf_s(szBuffer, ARRAYSIZE(szBuffer),
        L"%04u-%02u-%02u %02u:%02u",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute);

    return std::wstring(szBuffer);
}

// Utility: Get current user SID
std::wstring GetCurrentUserSid()
{
    WCHAR szUsername[UNLEN + 1];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    DWORD dwSize = ARRAYSIZE(szUsername);

    if (!GetUserNameW(szUsername, &dwSize))  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
    {
        return L"";
    }

    // Get SID size
    DWORD dwSidSize = 0;
    DWORD dwDomainSize = 0;
    SID_NAME_USE use;

    LookupAccountNameW(nullptr, szUsername, nullptr, &dwSidSize,
        nullptr, &dwDomainSize, &use);

    if (dwSidSize == 0)
    {
        return L"";
    }

    // Allocate and get SID
    std::vector<BYTE> sidBuffer(dwSidSize);
    std::vector<WCHAR> domainBuffer(dwDomainSize);

    if (!LookupAccountNameW(nullptr, szUsername,  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
        reinterpret_cast<PSID>(sidBuffer.data()), &dwSidSize,  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
        domainBuffer.data(), &dwDomainSize, &use))
    {
        return L"";
    }

    LPWSTR pwszSid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sidBuffer.data()), &pwszSid))  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
    {
        return L"";
    }

    std::wstring wsResult(pwszSid);
    LocalFree(pwszSid);

    return wsResult;
}

// Main dialog procedure body. Called only through WndProc_Main, which keeps
// C++ exceptions (std::bad_alloc, std::length_error, ...) from unwinding
// through user32's dispatch frames.
static INT_PTR WndProc_Main_Impl(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        g_appState.hwndMain = hwndDlg;
        SetWindowIcon(hwndDlg);

        // Set window title
        SetWindowTextW(hwndDlg, EIDMANAGE_APP_NAME);

        // Load settings from registry
        LoadSettings();

        // Initialize the main page
        InitializeMainPage(hwndDlg);

        return TRUE;
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_MAIN_FILTER_EID:
            if (HIWORD(wParam) == BN_CLICKED)
            {
                UpdateFilterControls(hwndDlg, FILTER_EID_ONLY);
                RefreshUserList(hwndDlg);
            }
            return TRUE;

        case IDC_MAIN_FILTER_ALL:
            if (HIWORD(wParam) == BN_CLICKED)
            {
                UpdateFilterControls(hwndDlg, FILTER_ALL_USERS);
                RefreshUserList(hwndDlg);
            }
            return TRUE;

        case IDC_MAIN_REFRESH:
            RefreshUserList(hwndDlg);
            return TRUE;

        case IDC_MAIN_DETAILS:
            ShowDetailsDialog(hwndDlg);
            return TRUE;

        case IDC_MAIN_MANAGE:
            ShowManageDialog(hwndDlg);
            return TRUE;

        case IDC_MAIN_SETTINGS:
            DialogBoxParamW(g_hinst, MAKEINTRESOURCE(IDD_SETTINGS),
                hwndDlg, WndProc_Settings, 0);
            return TRUE;

        case IDCANCEL:
        case IDOK:
            EndDialog(hwndDlg, IDOK);
            return TRUE;
        }
        break;
    }

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = (LPNMHDR)lParam;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity

        if (pnmh->idFrom == IDC_MAIN_LIST && pnmh->code == NM_DBLCLK)
        {
            // Double-click to show details
            ShowDetailsDialog(hwndDlg);
            return TRUE;
        }
        break;
    }

    case WM_DESTROY:
        SaveSettings();
        break;

    default:
        break;
    }

    return FALSE;
}

// Main dialog procedure
INT_PTR CALLBACK WndProc_Main(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    try
    {
        return WndProc_Main_Impl(hwndDlg, uMsg, wParam, lParam);
    }
    catch (const std::exception&)  // also covers std::bad_alloc
    {
        // Report "not handled" rather than letting a C++ exception cross user32.
        // Deliberately NOT catch (...): this project builds with /EHa, where
        // catch (...) would also swallow SEH exceptions such as access
        // violations and leave the process running in a corrupted state.
        return FALSE;
    }
}

// Main entry point
int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine, _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    g_hinst = hInstance;

    // Initialize common controls
    INITCOMMONCONTROLSEX icex = {0};
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS;

    if (!InitCommonControlsEx(&icex))
    {
        MessageBoxW(nullptr, L"Failed to initialize common controls.",
            EIDMANAGE_APP_NAME, MB_ICONERROR);
        return 1;
    }

    // Ensure running with administrator privileges
    HRESULT hr = EnsureElevated();
    if (hr == S_FALSE)
    {
        // Elevated instance launched, this one exits
        return 0;
    }
    else if (FAILED(hr))
    {
        MessageBoxW(nullptr,
            L"This application requires administrator privileges.\n\nPlease run as administrator.",
            EIDMANAGE_APP_NAME, MB_ICONERROR);
        return 1;
    }

    // Show main dialog
    INT_PTR nResult = DialogBoxParamW(hInstance,
        MAKEINTRESOURCE(IDD_MAIN),
        nullptr,
        WndProc_Main,
        0);

    return (nResult == IDOK) ? 0 : 1;
}
