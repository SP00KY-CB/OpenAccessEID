// Page11_ListCredentials.cpp - List Credentials Page Implementation
#include "Page11_ListCredentials.h"
#include "../EIDMigrate/FileCrypto.h"
#include "../EIDMigrate/Utils.h"
#include "../EIDMigrate/SecureMemory.h"
#include "../EIDMigrate/CryptoHelpers.h"
#include <commdlg.h>
#include <windowsx.h>
#include <commctrl.h>  // NOSONAR - INCLUDE-01: include order/casing significant for Windows SDK

// Store the current file path for this page
static std::wstring g_wsCurrentFile;  // NOSONAR - GLOBAL-01: global state written at runtime

// Store the currently displayed credentials (for both local and file modes)
static std::vector<CredentialInfo> g_CurrentCredentials;  // NOSONAR - GLOBAL-01: global state written at runtime

// Forward declaration of file password dialog
INT_PTR CALLBACK FilePasswordDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

// Structure for file password dialog data
struct FILE_PASSWORD_DATA {
    SecureWString wsPassword;  // zeroed when released
    BOOL fConfirmed;
    FILE_PASSWORD_DATA() : fConfirmed(FALSE) {}  // NOSONAR - INIT-01: constructor initializer list retained for clarity
};

// Simple file password dialog
INT_PTR CALLBACK FilePasswordDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    static FILE_PASSWORD_DATA* pData = nullptr;

    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        pData = reinterpret_cast<FILE_PASSWORD_DATA*>(lParam);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
        if (!pData)
            EndDialog(hwndDlg, IDCANCEL);

        // Set caption and instruction text
        SetWindowTextW(hwndDlg, L"Enter Export File Password");

        // Update the info text
        SetDlgItemTextW(hwndDlg, IDC_13_INFO_TEXT,
            L"Enter a password to encrypt the export file. The password must be at least 16 characters.");

        // Hide the username label and value (not needed for file password)
        ShowWindow(GetDlgItem(hwndDlg, IDC_13_USERNAME), SW_HIDE);
        HWND hUsernameLabel = GetDlgItem(hwndDlg, IDC_STATIC);
        if (hUsernameLabel)
        {
            // Find the "User:" label by enumerating or checking text
            // For simplicity, we'll just rely on the password fields
        }

        // Change Skip button to Cancel
        SetWindowTextW(GetDlgItem(hwndDlg, IDC_13_SKIP), L"Cancel");

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
            WCHAR szPassword[256]; // NOSONAR - C-style array required for Windows API GetDlgItemText
            WCHAR szConfirm[256]; // NOSONAR - C-style array required for Windows API GetDlgItemText

            GetDlgItemText(hwndDlg, IDC_13_PASSWORD, szPassword, ARRAYSIZE(szPassword));
            GetDlgItemText(hwndDlg, IDC_13_CONFIRM_PASSWORD, szConfirm, ARRAYSIZE(szConfirm));

            // Check if password is empty
            if (szPassword[0] == L'\0')
            {
                MessageBoxW(hwndDlg, L"Please enter a password.", L"Export File",
                    MB_ICONERROR | MB_OK);
                SecureZeroMemory(szPassword, sizeof(szPassword));
                SecureZeroMemory(szConfirm, sizeof(szConfirm));
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

            // Password length validation
            if (wcsnlen(szPassword, ARRAYSIZE(szPassword)) < 16) // NOSONAR - szPassword is stack-allocated buffer, never NULL
            {
                int nResult = MessageBoxW(hwndDlg,
                    L"The password is less than 16 characters. A strong password is recommended.\n\nDo you want to continue?",
                    L"Short Password",
                    MB_YESNO | MB_ICONWARNING);
                if (nResult == IDNO)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    SecureZeroMemory(szPassword, sizeof(szPassword));
                    SecureZeroMemory(szConfirm, sizeof(szConfirm));
                    return TRUE;
                }
            }

            pData->wsPassword.assign(szPassword, wcsnlen(szPassword, ARRAYSIZE(szPassword))); // NOSONAR - szPassword is stack-allocated buffer, never NULL
            pData->fConfirmed = TRUE;
            SecureZeroMemory(szPassword, sizeof(szPassword));
            SecureZeroMemory(szConfirm, sizeof(szConfirm));
            EndDialog(hwndDlg, IDOK);
            return TRUE;
        }

        case IDC_13_SKIP:
        case IDCANCEL:
        {
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

// Helper function to get password from user for file encryption/decryption
static SecureWString PromptForFilePassword(HWND hwndParent, BOOL bForEncryption = FALSE)
{
    FILE_PASSWORD_DATA data;

    INT_PTR nResult = DialogBoxParam(
        GetModuleHandleW(L"EIDMigrateUI.exe"),
        MAKEINTRESOURCE(IDD_13_PASSWORD_PROMPT),
        hwndParent,
        FilePasswordDlgProc,
        reinterpret_cast<LPARAM>(&data));

    if (nResult == IDOK && data.fConfirmed)
    {
        return data.wsPassword;
    }

    return SecureWString();
}

// Helper function to populate listview with credentials
static void PopulateCredentialList(HWND hList, _In_ const std::vector<CredentialInfo>& credentials)
{
    ListView_DeleteAllItems(hList);

    // Store credentials globally for export access
    g_CurrentCredentials = credentials;

    for (size_t i = 0; i < credentials.size(); i++)
    {
        const auto& cred = credentials[i];

        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.pszText = const_cast<LPWSTR>(cred.wsUsername.c_str()); // Safe: ListView won't modify the string // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
        lvi.iItem = (int)i;
        lvi.lParam = (LPARAM)i;  // Store index in lParam
        int iItem = ListView_InsertItem(hList, &lvi);  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity

        // Column 1: Username (already set in insert)
        // Column 2: RID
        WCHAR szRID[32]; // NOSONAR - C-style array required for Windows API swprintf_s/ListView_SetItemText
        swprintf_s(szRID, ARRAYSIZE(szRID), L"%u", cred.dwRid);
        ListView_SetItemText(hList, iItem, 2, szRID);

        // Column 3: Encryption
        PCWSTR pwszEncFallback = (cred.EncryptionType == EID_PRIVATE_DATA_TYPE::eidpdtDPAPI) ? L"DPAPI" : L"None";
        PCWSTR pwszEnc = (cred.EncryptionType == EID_PRIVATE_DATA_TYPE::eidpdtCrypted) ? L"Certificate" : pwszEncFallback;
        ListView_SetItemText(hList, iItem, 3, const_cast<LPWSTR>(pwszEnc)); // Safe: ListView won't modify the string

        // Column 4: Certificate Hash (preview)
        WCHAR szHash[64]; // NOSONAR - C-style array required for Windows API swprintf_s/ListView_SetItemText
        DWORD dwHashLen = 0;
        for (DWORD j = 0; j < 16 && j < CERT_HASH_LENGTH; j++)
        {
            swprintf_s(szHash + dwHashLen * 2, 3, L"%02X", cred.CertificateHash[j]);
            dwHashLen++;
        }
        ListView_SetItemText(hList, iItem, 4, szHash);

        // Auto-check the item by default
        ListView_SetCheckState(hList, iItem, TRUE);
    }
}

// Helper function to enumerate local credentials
static HRESULT EnumerateLocalCredentialsHelper(HWND hList, HWND hwndDlg)
{
    std::vector<CredentialInfo> credentials;
    HRESULT hr = EnumerateLsaCredentials(credentials);

    if (hList)
    {
        PopulateCredentialList(hList, credentials);
    }

    if (SUCCEEDED(hr))
    {
        SetWindowTextW(hwndDlg,
            (std::wstring(L"Local Machine (") +  // NOSONAR - STRING-01: manual concatenation retained
            std::to_wstring(credentials.size()) + L" credentials)").c_str());
    }
    else
    {
        MessageBoxW(hwndDlg,
            L"Failed to enumerate local credentials.",
            L"List Credentials",
            MB_ICONERROR);
    }

    return hr;
}

// Helper function to enumerate file credentials
static HRESULT EnumerateFileCredentialsHelper(HWND hList, HWND hwndDlg)
{
    if (g_wsCurrentFile.empty())
    {
        // No file selected, prompt to browse
        MessageBoxW(hwndDlg,
            L"Please browse for an export file first.",
            L"List Credentials",
            MB_ICONINFORMATION);
        return E_FAIL;
    }

    // Get password
    SecureWString wsPassword = PromptForFilePassword(hwndDlg, FALSE);
    if (wsPassword.empty())
    {
        MessageBoxW(hwndDlg,
            L"Password is required to decrypt the export file.",
            L"List Credentials",
            MB_ICONWARNING);
        return E_FAIL;
    }

    // Read the export file
    ExportFileData data;
    HRESULT hr = ReadEncryptedFile(g_wsCurrentFile, wsPassword, data);

    if (SUCCEEDED(hr))
    {
        // Store credentials in wizard data for export feature
        WIZARD_DATA* pWIZARD_DATA = (WIZARD_DATA*)GetWindowLongPtrW(GetParent(hwndDlg), DWLP_USER);  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
        if (pWIZARD_DATA)
        {
            pWIZARD_DATA->credentials = data.credentials;
            pWIZARD_DATA->groups = data.groups;
            pWIZARD_DATA->wsInputFile = g_wsCurrentFile;
            pWIZARD_DATA->wsPassword = wsPassword;
        }

        if (hList)
        {
            PopulateCredentialList(hList, data.credentials);

            // Show file info in window title
            SetWindowTextW(hwndDlg,
                (std::wstring(L"Viewing: ") +  // NOSONAR - STRING-01: manual concatenation retained
                g_wsCurrentFile.substr(g_wsCurrentFile.find_last_of(L"\\/") + 1) +
                L" (" + std::to_wstring(data.credentials.size()) + L" credentials)").c_str());
        }

        MessageBoxW(hwndDlg,
            (std::wstring(L"Successfully loaded ") +  // NOSONAR - STRING-01: manual concatenation retained
            std::to_wstring(data.credentials.size()) + L" credential(s) from file.").c_str(),
            L"List Credentials",
            MB_ICONINFORMATION);
    }
    else
    {
        MessageBoxW(hwndDlg,
            (std::wstring(L"Failed to read export file.\n\nError code: 0x") +  // NOSONAR - STRING-01: manual concatenation retained
            std::to_wstring(hr)).c_str(),
            L"List Credentials",
            MB_ICONERROR);
    }

    return hr;
}

// Helper function to show credential details
// Built with std::wstring: subject/issuer come from an imported (untrusted)
// file and can be arbitrarily long, so a fixed buffer filled by a chain of
// swprintf_s calls could hit the CRT invalid-parameter handler (fast-fail).
static void ShowCredentialDetails(HWND hwndParent, _In_ const CredentialInfo& cred)
{
    std::wstring wsDetails;

    wsDetails += L"Credential Details for: " + cred.wsUsername + L"\r\n\r\n";  // NOSONAR - FORMAT-01: plain appends keep untrusted lengths allocation-safe
    wsDetails += L"RID: " + std::to_wstring(cred.dwRid) + L"\r\n";

    PCWSTR pwszEncFallback = (cred.EncryptionType == EID_PRIVATE_DATA_TYPE::eidpdtDPAPI) ? L"DPAPI" : L"None";
    PCWSTR pwszEnc = (cred.EncryptionType == EID_PRIVATE_DATA_TYPE::eidpdtCrypted) ? L"Certificate-based" : pwszEncFallback;
    wsDetails += L"Encryption Type: ";
    wsDetails += pwszEnc;
    wsDetails += L"\r\n";

    if (!cred.wsSid.empty())
    {
        wsDetails += L"SID: " + cred.wsSid + L"\r\n";
    }

    wsDetails += L"\r\n--- Certificate Information ---\r\n";

    if (!cred.Certificate.empty())
    {
        wsDetails += L"Certificate Size: " + std::to_wstring(cred.Certificate.size()) + L" bytes\r\n";
        wsDetails += L"Certificate Present: Yes\r\n";
    }
    else
    {
        wsDetails += L"Certificate Present: No\r\n";
    }

    // Certificate hash. The hex digits are ASCII, so widening each char is exact.
    std::string sHash = BytesToHex(cred.CertificateHash, CERT_HASH_LENGTH);
    wsDetails += L"Certificate Hash: ";
    for (char ch : sHash)
    {
        wsDetails += static_cast<wchar_t>(ch);
    }
    wsDetails += L"\r\n";

    if (!cred.wsCertSubject.empty())
    {
        wsDetails += L"Subject: " + cred.wsCertSubject + L"\r\n";
    }

    if (!cred.wsCertIssuer.empty())
    {
        wsDetails += L"Issuer: " + cred.wsCertIssuer + L"\r\n";
    }

    // Convert FILETIME to readable expiry date
    if (cred.ftCertValidTo.dwLowDateTime != 0 || cred.ftCertValidTo.dwHighDateTime != 0)
    {
        SYSTEMTIME st = {0};
        if (FileTimeToSystemTime(&cred.ftCertValidTo, &st))
        {
            WCHAR szDate[64]; // NOSONAR - C-style array; fixed-width numeric fields always fit
            swprintf_s(szDate, ARRAYSIZE(szDate), L"%04u-%02u-%02u %02u:%02u:%02u",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            wsDetails += L"Expires: ";
            wsDetails += szDate;
            wsDetails += L"\r\n";
        }
    }

    wsDetails += L"\r\n--- Encryption Data ---\r\n";

    if (!cred.SymmetricKey.empty())
    {
        wsDetails += L"Symmetric Key: " + std::to_wstring(cred.SymmetricKey.size()) + L" bytes\r\n";
    }

    if (!cred.EncryptedPassword.empty())
    {
        wsDetails += L"Encrypted Password: " + std::to_wstring(cred.EncryptedPassword.size()) + L" bytes\r\n";
    }

    MessageBoxW(hwndParent, wsDetails.c_str(), L"Credential Details", MB_OK | MB_ICONINFORMATION);
}

INT_PTR CALLBACK WndProc_11_ListCredentials(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        // Setup listview columns
        HWND hList = GetDlgItem(hwndDlg, IDC_11_LIST);
        if (hList)
        {
            // Enable checkboxes
            ListView_SetExtendedListViewStyle(hList,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_CHECKBOXES);

            LVCOLUMN lvc = {0};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;

            // Column 0: Checkbox (automatic with LVS_EX_CHECKBOXES)
            // Column 1: Username
            lvc.pszText = const_cast<LPWSTR>(L"Username"); // Safe: ListView won't modify the string // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
            lvc.cx = 120;
            ListView_InsertColumn(hList, 1, &lvc);

            // Column 2: RID
            lvc.pszText = const_cast<LPWSTR>(L"RID"); // Safe: ListView won't modify the string // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
            lvc.cx = 60;
            ListView_InsertColumn(hList, 2, &lvc);

            // Column 3: Encryption
            lvc.pszText = const_cast<LPWSTR>(L"Encryption"); // Safe: ListView won't modify the string // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
            lvc.cx = 90;
            ListView_InsertColumn(hList, 3, &lvc);

            // Column 4: Certificate Hash (preview)
            lvc.pszText = const_cast<LPWSTR>(L"Certificate Hash (preview)"); // Safe: ListView won't modify the string // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
            lvc.cx = 180;
            ListView_InsertColumn(hList, 4, &lvc);
        }

        // Set default radio
        HWND hLocal = GetDlgItem(hwndDlg, IDC_11_LOCAL);
        if (hLocal) Button_SetCheck(hLocal, BST_CHECKED);

        return TRUE;
    }

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = (LPNMHDR)lParam;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
        switch (pnmh->code)
        {
        case PSN_SETACTIVE:
        {
            HWND hList = GetDlgItem(hwndDlg, IDC_11_LIST);
            HWND hLocal = GetDlgItem(hwndDlg, IDC_11_LOCAL);
            HWND hFromFile = GetDlgItem(hwndDlg, IDC_11_FROM_FILE);

            if (hFromFile && Button_GetCheck(hFromFile) == BST_CHECKED)
            {
                // List from file - use helper function
                EnumerateFileCredentialsHelper(hList, hwndDlg);
            }
            else if (hLocal && Button_GetCheck(hLocal) == BST_CHECKED)
            {
                // List local credentials - use helper function
                EnumerateLocalCredentialsHelper(hList, hwndDlg);
            }

            // Change Cancel button to Close
            HWND hwndPS = GetParent(hwndDlg);
            if (hwndPS)
            {
                SetWindowTextW(GetDlgItem(hwndPS, IDCANCEL), L"Close");
            }

            // Enable Back button to return to Welcome, hide Next
            PropSheet_SetWizButtons(hwndDlg, PSWIZB_BACK);
            return TRUE;
        }

        case PSN_WIZBACK:
        {
            // Clear the current file when going back
            g_wsCurrentFile.clear();

            // Jump back to Welcome page (index 0) instead of sequential back
            HWND hwndParent = GetParent(hwndDlg);
            if (hwndParent)
            {
                PropSheet_SetCurSel(hwndParent, nullptr, 0);
                SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, -1);  // Prevent default back
            }
            return TRUE;
        }

        case PSN_WIZFINISH:
            // Allow wizard to close
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
        case IDC_11_REFRESH:
        {
            // Refresh enumeration - call the appropriate helper directly
            HWND hList = GetDlgItem(hwndDlg, IDC_11_LIST);
            HWND hLocal = GetDlgItem(hwndDlg, IDC_11_LOCAL);
            HWND hFromFile = GetDlgItem(hwndDlg, IDC_11_FROM_FILE);

            if (hLocal && Button_GetCheck(hLocal) == BST_CHECKED)
            {
                EnumerateLocalCredentialsHelper(hList, hwndDlg);
            }
            else if (hFromFile && Button_GetCheck(hFromFile) == BST_CHECKED)
            {
                EnumerateFileCredentialsHelper(hList, hwndDlg);
            }
            return TRUE;
        }

        case IDC_11_FILE_BROWSE:
        {
            // Browse for file to list
            WCHAR szFile[MAX_PATH] = L""; // NOSONAR - C-style array required for Windows API GetOpenFileName
            if (!g_wsCurrentFile.empty())
            {
                wcscpy_s(szFile, ARRAYSIZE(szFile), g_wsCurrentFile.c_str());
            }

            OPENFILENAMEW ofn = {0};
            ofn.lStructSize = sizeof(OPENFILENAMEW);
            ofn.hwndOwner = hwndDlg;
            ofn.lpstrFilter = L"EID Export Files (*.eid)\0*.eid\0All Files\0*.*\0";
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = ARRAYSIZE(szFile);
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
            ofn.lpstrTitle = L"Select EID Export File to View";

            if (GetOpenFileNameW(&ofn))
            {
                g_wsCurrentFile = szFile;
                HWND hFromFile = GetDlgItem(hwndDlg, IDC_11_FROM_FILE);
                HWND hList = GetDlgItem(hwndDlg, IDC_11_LIST);
                Button_SetCheck(hFromFile, BST_CHECKED);

                // Trigger the file listing directly
                EnumerateFileCredentialsHelper(hList, hwndDlg);
            }
            return TRUE;
        }

        case IDC_11_LOCAL:
        {
            // Switch mode and enumerate
            g_wsCurrentFile.clear();
            HWND hList = GetDlgItem(hwndDlg, IDC_11_LIST);
            EnumerateLocalCredentialsHelper(hList, hwndDlg);
            return TRUE;
        }

        case IDC_11_FROM_FILE:
        {
            // Switch to file mode - user will need to browse
            g_wsCurrentFile.clear();
            HWND hList = GetDlgItem(hwndDlg, IDC_11_LIST);
            ListView_DeleteAllItems(hList);  // Clear the list
            SetWindowTextW(hwndDlg, L"View Credentials - No file selected");
            return TRUE;
        }

        case IDC_11_EXPORT_SELECTED:
        {
            // Export checked credentials
            HWND hList = GetDlgItem(hwndDlg, IDC_11_LIST);
            if (!hList) return TRUE;

            // Count checked items
            int nChecked = 0;
            int nItemCount = ListView_GetItemCount(hList);  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
            for (int i = 0; i < nItemCount; i++)
            {
                if (ListView_GetCheckState(hList, i))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                    nChecked++;
            }

            if (nChecked == 0)
            {
                MessageBoxW(hwndDlg,
                    L"Please select at least one credential to export.",
                    L"Export Selected",
                    MB_ICONINFORMATION);
                return TRUE;
            }

            // Prompt for output file
            WCHAR szFile[MAX_PATH] = L"export_selected.eid";  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
            OPENFILENAMEW ofn = {0};
            ofn.lStructSize = sizeof(OPENFILENAMEW);
            ofn.hwndOwner = hwndDlg;
            ofn.lpstrFilter = L"EID Export Files (*.eid)\0*.eid\0All Files\0*.*\0";
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = ARRAYSIZE(szFile);
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY;
            ofn.lpstrDefExt = L"eid";
            ofn.lpstrTitle = L"Export Selected Credentials";

            if (!GetSaveFileNameW(&ofn))
            {
                return TRUE;
            }

            // Prompt for password
            SecureWString wsPassword = PromptForFilePassword(hwndDlg, TRUE);
            if (wsPassword.empty())
            {
                MessageBoxW(hwndDlg,
                    L"Password is required to encrypt the export file.",
                    L"Export Selected",
                    MB_ICONWARNING);
                return TRUE;
            }

            // Collect checked credentials from g_CurrentCredentials
            std::vector<CredentialInfo> selectedCredentials;
            for (int i = 0; i < nItemCount; i++)
            {
                if (ListView_GetCheckState(hList, i))  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    // Get the item data (index into g_CurrentCredentials)
                    LVITEM lviGetData = {0};
                    lviGetData.mask = LVIF_PARAM;
                    lviGetData.iItem = i;
                    ListView_GetItem(hList, &lviGetData);
                    size_t dwIndex = (size_t)lviGetData.lParam;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity

                    if (dwIndex < g_CurrentCredentials.size())
                    {
                        selectedCredentials.push_back(g_CurrentCredentials[dwIndex]);
                    }
                }
            }

            if (selectedCredentials.empty())
            {
                MessageBoxW(hwndDlg,
                    L"No credentials to export.",
                    L"Export Selected",
                    MB_ICONWARNING);
                return TRUE;
            }

            // Create export file data
            ExportFileData data;
            data.credentials = selectedCredentials;
            data.formatVersion = "EIDMigrate-v1.0";
            data.dwVersion = EIDMIGRATE_VERSION;  // match the binary header (FileFormat.h), as Export.cpp does

            // Get current UTC time for export date (ISO 8601 format)
            data.exportDate = WideToUtf8(FormatCurrentTimestamp());

            // Get computer name
            WCHAR szComputer[MAX_COMPUTERNAME_LENGTH + 1]; // NOSONAR - C-style array required for Windows API GetComputerNameW
            DWORD dwSize = ARRAYSIZE(szComputer);
            if (GetComputerNameW(szComputer, &dwSize))
            {
                data.wsSourceMachine = szComputer;
            }

            // Get username
            WCHAR szUsername[UNLEN + 1]; // NOSONAR - C-style array required for Windows API GetUserNameW
            dwSize = ARRAYSIZE(szUsername);
            if (GetUserNameW(szUsername, &dwSize))
            {
                data.wsExportedBy = szUsername;
            }

            // Write the export file
            HRESULT hr = WriteEncryptedFile(szFile, wsPassword, data);

            if (SUCCEEDED(hr))
            {
                MessageBoxW(hwndDlg,
                    (std::wstring(L"Successfully exported ") +  // NOSONAR - STRING-01: manual concatenation retained
                    std::to_wstring(selectedCredentials.size()) +
                    L" credential(s) to:\n" + szFile).c_str(),
                    L"Export Selected",
                    MB_ICONINFORMATION);
            }
            else
            {
                MessageBoxW(hwndDlg,
                    (std::wstring(L"Failed to export credentials.\n\nError code: 0x") +  // NOSONAR - STRING-01: manual concatenation retained
                    std::to_wstring(hr)).c_str(),
                    L"Export Selected",
                    MB_ICONERROR);
            }
            return TRUE;
        }

        case IDC_11_DETAILS:
        {
            // Show details for selected credential
            HWND hList = GetDlgItem(hwndDlg, IDC_11_LIST);
            if (!hList) return TRUE;

            int nSelected = ListView_GetSelectedCount(hList);
            if (nSelected == 0)
            {
                MessageBoxW(hwndDlg,
                    L"Please select a credential to view details.",
                    L"View Details",
                    MB_ICONINFORMATION);
                return TRUE;
            }

            if (nSelected > 1)
            {
                MessageBoxW(hwndDlg,
                    L"Please select only one credential to view details.",
                    L"View Details",
                    MB_ICONINFORMATION);
                return TRUE;
            }

            // Get the selected item
            int iItem = ListView_GetNextItem(hList, -1, LVNI_SELECTED);  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
            if (iItem != -1)
            {
                // Get the credential data from g_CurrentCredentials
                LVITEM lviGetData = {0};
                lviGetData.mask = LVIF_PARAM;
                lviGetData.iItem = iItem;
                ListView_GetItem(hList, &lviGetData);
                size_t dwIndex = (size_t)lviGetData.lParam;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity

                if (dwIndex < g_CurrentCredentials.size())  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    ShowCredentialDetails(hwndDlg, g_CurrentCredentials[dwIndex]);
                }
                else
                {
                    MessageBoxW(hwndDlg,
                        L"Unable to retrieve credential details.",
                        L"View Details",
                        MB_ICONWARNING);
                }
            }
            return TRUE;
        }

        case IDOK:
            // Handle Enter key
            return TRUE;
        }
        break;
    }

    default:
        break;
    }
    return FALSE;
}
