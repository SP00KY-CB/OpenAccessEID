// Page06_ImportSelect.cpp - Import File Selection Page Implementation
#include "Page06_ImportSelect.h"
#include "../EIDMigrate/Import.h"
#include "../EIDMigrate/SecureMemory.h"
#include <commdlg.h>

INT_PTR CALLBACK WndProc_06_ImportSelect(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        // Clear file state
        g_wizardData.fFileDecrypted = FALSE;
        g_wizardData.wsInputFile.clear();
        SecureClear(g_wizardData.wsPassword);
        return TRUE;
    }

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = (LPNMHDR)lParam;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
        switch (pnmh->code)
        {
        case PSN_SETACTIVE:
            PropSheet_SetWizButtons(hwndDlg, PSWIZB_BACK | PSWIZB_NEXT);
            return TRUE;

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

        case PSN_WIZNEXT:
        {
            // Validate file is selected and decrypted
            if (!g_wizardData.fFileDecrypted) {
                MessageBoxW(hwndDlg, L"Please select and decrypt a file first.",
                    L"Import", MB_ICONEXCLAMATION);
                SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, -1);
                return TRUE;
            }
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
        case IDC_06_BROWSE_INPUT:
        {
            WCHAR szFile[MAX_PATH] = L""; // NOSONAR - C-style array required for Windows API OPENFILENAME
            OPENFILENAME ofn = {0};
            ofn.lStructSize = sizeof(OPENFILENAME);
            ofn.hwndOwner = hwndDlg;
            ofn.lpstrFilter = L"EID Export Files (*.eid)\0*.eid\0All Files\0*.*\0";
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = ARRAYSIZE(szFile);
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

            if (GetOpenFileName(&ofn)) {
                SetDlgItemText(hwndDlg, IDC_06_INPUT_FILE, szFile);
                g_wizardData.wsInputFile = szFile;
            }
            return TRUE;
        }
        case IDC_06_SHOW_PASSWORD:
        {
            HWND hPassword = GetDlgItem(hwndDlg, IDC_06_PASSWORD);
            HWND hShow = GetDlgItem(hwndDlg, IDC_06_SHOW_PASSWORD);
            if (hPassword && hShow) {
                BOOL fShow = (Button_GetCheck(hShow) == BST_CHECKED);
                SendMessage(hPassword, EM_SETPASSWORDCHAR, fShow ? 0 : '*', 0);
                InvalidateRect(hPassword, nullptr, TRUE);
            }
            return TRUE;
        }
        case IDC_06_DECRYPT_BUTTON:
        {
            // Get file and password
            WCHAR szFile[MAX_PATH]; // NOSONAR - C-style array required for Windows API GetDlgItemText
            WCHAR szPassword[256]; // NOSONAR - C-style array required for Windows API GetDlgItemText
            GetDlgItemText(hwndDlg, IDC_06_INPUT_FILE, szFile, ARRAYSIZE(szFile));
            GetDlgItemText(hwndDlg, IDC_06_PASSWORD, szPassword, ARRAYSIZE(szPassword));

            if (wcsnlen(szFile, ARRAYSIZE(szFile)) == 0 || wcsnlen(szPassword, ARRAYSIZE(szPassword)) == 0) { // NOSONAR - both are stack-allocated buffers, never NULL
                SecureZeroMemory(szPassword, sizeof(szPassword));
                MessageBoxW(hwndDlg, L"Please select a file and enter a password.",
                    L"Import", MB_ICONEXCLAMATION);
                return TRUE;
            }

            // Validate password length
            if (wcsnlen(szPassword, ARRAYSIZE(szPassword)) < 16) { // NOSONAR - szPassword is stack-allocated buffer, never NULL
                SecureZeroMemory(szPassword, sizeof(szPassword));
                MessageBoxW(hwndDlg, L"Password must be at least 16 characters.",
                    L"Import", MB_ICONEXCLAMATION);
                return TRUE;
            }

            // Store password (SecureWString: zeroed when released)
            g_wizardData.wsInputFile = szFile;
            g_wizardData.wsPassword.assign(szPassword, wcsnlen(szPassword, ARRAYSIZE(szPassword))); // NOSONAR - szPassword is stack-allocated buffer, never NULL
            SecureZeroMemory(szPassword, sizeof(szPassword));

            // Try to read and parse the file
            std::vector<CredentialInfo> credentials;
            std::vector<GroupInfo> groups;
            std::wstring wsSourceMachine;
            std::wstring wsExportDate;

            HRESULT hr = ReadImportFileWithMetadata(szFile, g_wizardData.wsPassword, credentials, groups,
                &wsSourceMachine, &wsExportDate, nullptr);
            if (SUCCEEDED(hr)) {
                g_wizardData.fFileDecrypted = TRUE;
                const DWORD dwCredentialCount = static_cast<DWORD>(credentials.size());
                g_wizardData.credentials = std::move(credentials);
                g_wizardData.groups = std::move(groups);
                g_wizardData.dwFileCredentialCount = dwCredentialCount;
                g_wizardData.wsSourceMachine = wsSourceMachine;
                g_wizardData.wsExportDate = wsExportDate;

                // Update UI with file info
                SetDlgItemText(hwndDlg, IDC_06_SOURCE_MACHINE,
                    wsSourceMachine.empty() ? L"Unknown" : wsSourceMachine.c_str());
                SetDlgItemText(hwndDlg, IDC_06_EXPORT_DATE,
                    wsExportDate.empty() ? L"Unknown" : wsExportDate.c_str());
                WCHAR szCount[32]; // NOSONAR - C-style array required for Windows API swprintf_s/SetDlgItemText
                swprintf_s(szCount, ARRAYSIZE(szCount), L"%u", dwCredentialCount);
                SetDlgItemText(hwndDlg, IDC_06_CREDENTIAL_COUNT, szCount);
                SetDlgItemText(hwndDlg, IDC_06_VERSION, L"1.0");

                MessageBoxW(hwndDlg, L"File decrypted successfully!", L"Import", MB_ICONINFORMATION);
            } else {
                SecureClear(g_wizardData.wsPassword);
                MessageBoxW(hwndDlg, L"Failed to decrypt file. Check the password.",
                    L"Import", MB_ICONERROR);
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
