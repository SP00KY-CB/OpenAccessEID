// Page13_PasswordPrompt.cpp - Password Prompt Dialog Implementation
// This modal dialog allows setting a password for a user account when a certificate is found

#include "Page13_PasswordPrompt.h"
#include "EIDMigrateUI.h"
#include "../EIDMigrate/Tracing.h"
#include <lm.h>  // NOSONAR - INCLUDE-01: include casing significant for Windows SDK

#pragma comment(lib, "netapi32.lib")

// Set password for a local user account
HRESULT SetUserPassword(
    _In_ const std::wstring& wsUsername,
    _In_ const std::wstring& wsPassword)
{
    USER_INFO_1003 ui;
    ui.usri1003_password = const_cast<LPWSTR>(wsPassword.c_str());  // NOSONAR - CAST-01: const_cast required for Win32 NetUserSetInfo buffer

    DWORD dwStatus = NetUserSetInfo(
        nullptr,
        const_cast<LPWSTR>(wsUsername.c_str()),  // NOSONAR - CAST-01: const_cast required for Win32 NetUserSetInfo buffer
        1003,  // Password level
        reinterpret_cast<LPBYTE>(&ui),  // NOSONAR - BYTE-01: BYTE buffer required by Win32 NetUserSetInfo
        nullptr);

    if (dwStatus == NERR_Success)
    {
        EIDM_TRACE_INFO(L"Password set successfully for user: %ls", wsUsername.c_str());
        return S_OK;
    }
    else
    {
        EIDM_TRACE_ERROR(L"Failed to set password for %ls: %u", wsUsername.c_str(), dwStatus);
        return HRESULT_FROM_WIN32(dwStatus);
    }
}

// Structure to pass data to/from the dialog
struct PASSWORD_PROMPT_DATA {
    std::wstring wsUsername;
    std::wstring wsPassword;
    BOOL fSkip;
    BOOL fPasswordSet;

    PASSWORD_PROMPT_DATA() : fSkip(FALSE), fPasswordSet(FALSE) {}  // NOSONAR - INIT-01: members initialized in constructor init list
};

// Dialog procedure
INT_PTR CALLBACK PasswordPromptDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    static PASSWORD_PROMPT_DATA* pData = nullptr;

    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        pData = reinterpret_cast<PASSWORD_PROMPT_DATA*>(lParam);  // NOSONAR - CAST-01: reinterpret_cast of LPARAM dialog context
        if (!pData)
            EndDialog(hwndDlg, IDCANCEL);

        // Set username
        SetDlgItemText(hwndDlg, IDC_13_USERNAME, pData->wsUsername.c_str());

        // Focus on password field
        SetFocus(GetDlgItem(hwndDlg, IDC_13_PASSWORD));
        return FALSE;  // We set the focus manually
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_13_SHOW_PASSWORD:
        {
            HWND hPassword = GetDlgItem(hwndDlg, IDC_13_PASSWORD);
            HWND hConfirm = GetDlgItem(hwndDlg, IDC_13_CONFIRM_PASSWORD);
            HWND hShow = GetDlgItem(hwndDlg, IDC_13_SHOW_PASSWORD);

            BOOL fShow = (Button_GetCheck(hShow) == BST_CHECKED);
            SendMessage(hPassword, EM_SETPASSWORDCHAR, fShow ? 0 : '*', 0);
            SendMessage(hConfirm, EM_SETPASSWORDCHAR, fShow ? 0 : '*', 0);
            InvalidateRect(hPassword, nullptr, TRUE);
            InvalidateRect(hConfirm, nullptr, TRUE);
            return TRUE;
        }

        case IDOK:
        {
            WCHAR szPassword[256];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
            WCHAR szConfirm[256];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API

            GetDlgItemText(hwndDlg, IDC_13_PASSWORD, szPassword, ARRAYSIZE(szPassword));
            GetDlgItemText(hwndDlg, IDC_13_CONFIRM_PASSWORD, szConfirm, ARRAYSIZE(szConfirm));

            // Check if password is empty - allow empty (skip)
            if (szPassword[0] == L'\0')
            {
                pData->fSkip = TRUE;
                SecureZeroMemory(szPassword, sizeof(szPassword));
                SecureZeroMemory(szConfirm, sizeof(szConfirm));
                EndDialog(hwndDlg, IDCANCEL);
                return TRUE;
            }

            // Check passwords match
            if (wcscmp(szPassword, szConfirm) != 0)
            {
                MessageBoxW(hwndDlg, L"The passwords do not match.", L"Password Mismatch",
                    MB_ICONERROR | MB_OK);
                SecureZeroMemory(szPassword, sizeof(szPassword));
                SecureZeroMemory(szConfirm, sizeof(szConfirm));
                return TRUE;
            }

            // Password length validation (optional - Windows allows empty)
            if (wcsnlen(szPassword, ARRAYSIZE(szPassword)) < 1) // NOSONAR - szPassword is stack-allocated buffer, never NULL
            {
                MessageBoxW(hwndDlg, L"Password cannot be empty. Click Skip to continue without setting a password.",
                    L"Invalid Password", MB_ICONERROR | MB_OK);
                SecureZeroMemory(szPassword, sizeof(szPassword));
                SecureZeroMemory(szConfirm, sizeof(szConfirm));
                return TRUE;
            }

            pData->wsPassword = szPassword;
            pData->fPasswordSet = TRUE;
            SecureZeroMemory(szPassword, sizeof(szPassword));
            SecureZeroMemory(szConfirm, sizeof(szConfirm));
            EndDialog(hwndDlg, IDOK);
            return TRUE;
        }

        case IDC_13_SKIP:
        {
            pData->fSkip = TRUE;
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;
        }

        case IDCANCEL:
        {
            pData->fSkip = TRUE;  // NOSONAR - SWITCH-01: cases kept distinct for readability
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;
        }
        }
        break;
    }

    case WM_DESTROY:
        pData = nullptr;
        break;

    default:
        break;
    }

    return FALSE;
}

// Public function to show the password prompt dialog
BOOL ShowPasswordPromptDialog(
    _In_ HWND hwndParent,
    _In_ const std::wstring& wsUsername,
    _Out_ std::wstring& wsPassword,
    _Out_ BOOL& pfSkipped)
{
    PASSWORD_PROMPT_DATA data;
    data.wsUsername = wsUsername;

    INT_PTR nResult = DialogBoxParam(
        g_hinst,
        MAKEINTRESOURCE(IDD_13_PASSWORD_PROMPT),
        hwndParent,
        PasswordPromptDlgProc,
        reinterpret_cast<LPARAM>(&data));

    if (nResult == IDOK && data.fPasswordSet)
    {
        wsPassword = data.wsPassword;
        pfSkipped = FALSE;
        return TRUE;
    }
    else
    {
        pfSkipped = TRUE;
        wsPassword.clear();
        return FALSE;
    }
}
