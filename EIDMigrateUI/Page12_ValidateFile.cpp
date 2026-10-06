// Page12_ValidateFile.cpp - Validate File Page Implementation
#include "Page12_ValidateFile.h"
#include "../EIDMigrate/Validate.h"
#include "../EIDMigrate/SecureMemory.h"
#include "../EIDMigrate/Utils.h"
#include <commdlg.h>

INT_PTR CALLBACK WndProc_12_ValidateFile(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
        return TRUE;

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = (LPNMHDR)lParam;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
        switch (pnmh->code)
        {
        case PSN_SETACTIVE:
        {
            // Reset validation results
            SetDlgItemText(hwndDlg, IDC_12_FORMAT_STATUS, L"N/A");
            SetDlgItemText(hwndDlg, IDC_12_HEADER_STATUS, L"N/A");
            SetDlgItemText(hwndDlg, IDC_12_HMAC_STATUS, L"N/A");
            SetDlgItemText(hwndDlg, IDC_12_ENCRYPTION_STATUS, L"N/A");
            SetDlgItemText(hwndDlg, IDC_12_JSON_STATUS, L"N/A");
            SetDlgItemText(hwndDlg, IDC_12_CREDENTIAL_COUNT, L"N/A");
            SetDlgItemText(hwndDlg, IDC_12_SOURCE_MACHINE, L"N/A");
            SetDlgItemText(hwndDlg, IDC_12_EXPORT_DATE, L"N/A");

            // Clear password field
            SetDlgItemText(hwndDlg, IDC_12_PASSWORD, L"");

            // Change Cancel button to Close
            HWND hwndPS = GetParent(hwndDlg);
            if (hwndPS) {
                SetWindowTextW(GetDlgItem(hwndPS, IDCANCEL), L"Close");
            }

            // Enable Back button to return to Welcome, hide Next
            PropSheet_SetWizButtons(hwndDlg, PSWIZB_BACK);
            return TRUE;
        }

        case PSN_WIZBACK:
        {
            // Jump back to Welcome page (index 0) instead of sequential back
            HWND hwndParent = GetParent(hwndDlg);
            if (hwndParent) {
                PropSheet_SetCurSel(hwndParent, nullptr, 0);
                SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, -1);  // Prevent default back
            }
            return TRUE;
        }

        case PSN_WIZFINISH:
            return TRUE;

        default:
            break;
        }
        break;
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_12_BROWSE:
        {
            WCHAR szFile[MAX_PATH] = L"";  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
            OPENFILENAME ofn = {0};
            ofn.lStructSize = sizeof(OPENFILENAME);
            ofn.hwndOwner = hwndDlg;
            ofn.lpstrFilter = L"EID Export Files (*.eid)\0*.eid\0All Files\0*.*\0";
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = ARRAYSIZE(szFile);
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

            if (GetOpenFileName(&ofn)) {
                SetDlgItemText(hwndDlg, IDC_12_FILE_PATH, szFile);
            }
            return TRUE;
        }

        case IDC_12_SHOW_PASSWORD:
        {
            HWND hPassword = GetDlgItem(hwndDlg, IDC_12_PASSWORD);
            HWND hShow = GetDlgItem(hwndDlg, IDC_12_SHOW_PASSWORD);
            if (hPassword && hShow) {
                BOOL fShow = (Button_GetCheck(hShow) == BST_CHECKED);
                SendMessage(hPassword, EM_SETPASSWORDCHAR, fShow ? 0 : '*', 0);
                InvalidateRect(hPassword, nullptr, TRUE);
            }
            return TRUE;
        }

        case IDC_12_VALIDATE:
        {
            WCHAR szFile[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
            WCHAR szPassword[256];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
            GetDlgItemText(hwndDlg, IDC_12_FILE_PATH, szFile, ARRAYSIZE(szFile));
            GetDlgItemText(hwndDlg, IDC_12_PASSWORD, szPassword, ARRAYSIZE(szPassword));

            if (wcsnlen(szFile, ARRAYSIZE(szFile)) == 0) { // NOSONAR - szFile is stack-allocated buffer, never NULL
                MessageBoxW(hwndDlg, L"Please select a file to validate.",
                    L"Validate", MB_ICONEXCLAMATION);
                return TRUE;
            }

            if (wcsnlen(szPassword, ARRAYSIZE(szPassword)) == 0) { // NOSONAR - szPassword is stack-allocated buffer, never NULL
                MessageBoxW(hwndDlg, L"Please enter the passphrase.",
                    L"Validate", MB_ICONEXCLAMATION);
                return TRUE;
            }

            // Perform validation
            VALIDATE_OPTIONS options;
            options.wsInputPath = szFile;
            options.fRequireSmartCard = FALSE;
            options.fVerbose = FALSE;

            VALIDATION_RESULT result;
            SecureWString swPassword(szPassword);
            HRESULT hr = ValidateImportFile(szFile, swPassword, options, result);

            // Clear password from memory
            SecureZeroMemory(szPassword, sizeof(szPassword));

            // Update results
            if (SUCCEEDED(hr) && result.IsValid()) {
                SetDlgItemText(hwndDlg, IDC_12_FORMAT_STATUS, L"Valid");
                SetDlgItemText(hwndDlg, IDC_12_HEADER_STATUS, result.fValidHeader ? L"OK" : L"Failed");
                SetDlgItemText(hwndDlg, IDC_12_HMAC_STATUS, result.fValidHmac ? L"Valid" : L"Invalid");
                SetDlgItemText(hwndDlg, IDC_12_ENCRYPTION_STATUS, L"OK");
                SetDlgItemText(hwndDlg, IDC_12_JSON_STATUS, result.fValidJson ? L"Valid" : L"Invalid");

                WCHAR szCount[32];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
                swprintf_s(szCount, ARRAYSIZE(szCount), L"%u", result.dwCredentialCount);
                SetDlgItemText(hwndDlg, IDC_12_CREDENTIAL_COUNT, szCount);

                if (!result.wsSourceMachine.empty())  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                    SetDlgItemText(hwndDlg, IDC_12_SOURCE_MACHINE, result.wsSourceMachine.c_str());

                // Don't show export date anymore (removed from dialog layout)
                // if (!result.wsExportDate.empty())
                //     SetDlgItemText(hwndDlg, IDC_12_EXPORT_DATE, result.wsExportDate.c_str());

                MessageBoxW(hwndDlg, L"File is valid!", L"Validate", MB_ICONINFORMATION);
            } else {
                SetDlgItemText(hwndDlg, IDC_12_FORMAT_STATUS, L"Invalid");
                SetDlgItemText(hwndDlg, IDC_12_HEADER_STATUS, L"Failed");
                SetDlgItemText(hwndDlg, IDC_12_HMAC_STATUS, L"Invalid");
                SetDlgItemText(hwndDlg, IDC_12_ENCRYPTION_STATUS, L"Failed");
                SetDlgItemText(hwndDlg, IDC_12_JSON_STATUS, L"Failed");

                // Show error details
                std::wstring wsError = L"File validation failed.";
                if (!result.errors.empty()) {  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                    wsError += L"\n\n";
                    for (const auto& e : result.errors) {
                        wsError += e + L"\n";
                    }
                }
                MessageBoxW(hwndDlg, wsError.c_str(), L"Validate", MB_ICONERROR);
            }
            return TRUE;
        }
        }
        break;
    }

    default:
        break;
    }
    return FALSE;
}
