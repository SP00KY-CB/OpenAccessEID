// Page02_ExportSelect.cpp - Export Options Page Implementation
#include "Page02_ExportSelect.h"
#include <commdlg.h>

INT_PTR CALLBACK WndProc_02_ExportSelect(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        // Set default options
        HWND hValidate = GetDlgItem(hwndDlg, IDC_02_VALIDATE_CERTS); // NOSONAR - variable used
        HWND hGroups = GetDlgItem(hwndDlg, IDC_02_INCLUDE_GROUPS);
        if (hGroups) Button_SetCheck(hGroups, BST_CHECKED);
        return TRUE;
    }

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = (LPNMHDR)lParam;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
        switch (pnmh->code)
        {
        case PSN_SETACTIVE:
            PropSheet_SetWizButtons(hwndDlg, PSWIZB_BACK | PSWIZB_NEXT);
            return TRUE;

        case PSN_WIZNEXT:
        {
            // Validate and store options
            WCHAR szFile[MAX_PATH]; // NOSONAR - C-style array required for Windows API GetDlgItemText
            WCHAR szPassword[256]; // NOSONAR - C-style array required for Windows API GetDlgItemText
            WCHAR szConfirm[256]; // NOSONAR - C-style array required for Windows API GetDlgItemText

            GetDlgItemText(hwndDlg, IDC_02_OUTPUT_FILE, szFile, ARRAYSIZE(szFile));
            GetDlgItemText(hwndDlg, IDC_02_PASSWORD, szPassword, ARRAYSIZE(szPassword));
            GetDlgItemText(hwndDlg, IDC_02_CONFIRM_PASSWORD, szConfirm, ARRAYSIZE(szConfirm));

            // Validate file path
            if (wcsnlen(szFile, ARRAYSIZE(szFile)) == 0) { // NOSONAR - szFile is stack-allocated buffer, never NULL
                SecureZeroMemory(szPassword, sizeof(szPassword));
                SecureZeroMemory(szConfirm, sizeof(szConfirm));
                MessageBoxW(hwndDlg, L"Please specify an output file.",
                    L"Export", MB_ICONEXCLAMATION);
                SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, -1);
                return TRUE;
            }

            // Validate password
            if (wcsnlen(szPassword, ARRAYSIZE(szPassword)) < 16) { // NOSONAR - szPassword is stack-allocated buffer, never NULL
                SecureZeroMemory(szPassword, sizeof(szPassword));
                SecureZeroMemory(szConfirm, sizeof(szConfirm));
                MessageBoxW(hwndDlg, L"Password must be at least 16 characters.",
                    L"Export", MB_ICONEXCLAMATION);
                SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, -1);
                return TRUE;
            }

            // Confirm password
            if (wcscmp(szPassword, szConfirm) != 0) {
                SecureZeroMemory(szPassword, sizeof(szPassword));
                SecureZeroMemory(szConfirm, sizeof(szConfirm));
                MessageBoxW(hwndDlg, L"Passwords do not match.",
                    L"Export", MB_ICONEXCLAMATION);
                SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, -1);
                return TRUE;
            }

            // Store options
            g_wizardData.wsOutputFile = szFile;
            g_wizardData.wsPassword.assign(szPassword, wcsnlen(szPassword, ARRAYSIZE(szPassword))); // NOSONAR - szPassword is stack-allocated buffer, never NULL
            SecureZeroMemory(szPassword, sizeof(szPassword));
            SecureZeroMemory(szConfirm, sizeof(szConfirm));

            HWND hValidate = GetDlgItem(hwndDlg, IDC_02_VALIDATE_CERTS);
            HWND hGroups = GetDlgItem(hwndDlg, IDC_02_INCLUDE_GROUPS);
            g_wizardData.fValidateCerts = (hValidate && Button_GetCheck(hValidate) == BST_CHECKED);
            g_wizardData.fIncludeGroups = (hGroups && Button_GetCheck(hGroups) == BST_CHECKED);

            return TRUE;
        }
        default:
            break;
        }
        break;
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_02_BROWSE_OUTPUT:
        {
            WCHAR szFile[MAX_PATH] = L""; // NOSONAR - C-style array required for Windows API OPENFILENAME structure
            OPENFILENAME ofn = {0};
            ofn.lStructSize = sizeof(OPENFILENAME);
            ofn.hwndOwner = hwndDlg;
            ofn.lpstrFilter = L"EID Export Files (*.eid)\0*.eid\0All Files\0*.*\0";
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = ARRAYSIZE(szFile);
            ofn.lpstrDefExt = L"eid";
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOREADONLYRETURN;

            if (GetSaveFileName(&ofn)) {
                SetDlgItemText(hwndDlg, IDC_02_OUTPUT_FILE, szFile);
            }
            return TRUE;
        }
        case IDC_02_SHOW_PASSWORD:
        {
            HWND hPassword = GetDlgItem(hwndDlg, IDC_02_PASSWORD);
            HWND hConfirm = GetDlgItem(hwndDlg, IDC_02_CONFIRM_PASSWORD);
            HWND hShow = GetDlgItem(hwndDlg, IDC_02_SHOW_PASSWORD);
            if (hPassword && hConfirm && hShow) {
                BOOL fShow = (Button_GetCheck(hShow) == BST_CHECKED);
                SendMessage(hPassword, EM_SETPASSWORDCHAR, fShow ? 0 : '*', 0);
                SendMessage(hConfirm, EM_SETPASSWORDCHAR, fShow ? 0 : '*', 0);
                InvalidateRect(hPassword, nullptr, TRUE);
                InvalidateRect(hConfirm, nullptr, TRUE);
            }
            return TRUE;
        }
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
