// Page15_Revocation.cpp - Certificate Revocation Management Page Implementation
//
// Lets the operator control certificate revocation entirely from the GUI (no command line):
//   1. Install / update a signature-verified CRL for OFFLINE revocation checking
//      (delegates to InstallCrlFromFile, shared with EIDMigrate's import-crl command).
//   2. Toggle the "Require revocation checking" policy (RequireRevocationCheck) which makes
//      the auth stack fail-closed when a card's revocation status cannot be confirmed offline.
#include "Page15_Revocation.h"
#include "../EIDMigrate/CertificateInstall.h"
#include <commdlg.h>

// Same policy key/value the auth stack reads (EIDCardLibrary\GPO.cpp: szMainGPOKey).
static const wchar_t* const SC_POLICY_KEY =
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider";
static const wchar_t* const REQUIRE_REVOCATION_VALUE = L"RequireRevocationCheck";

static void LoadRequireRevocation(HWND hwndDlg)
{
    DWORD dwVal = 0;
    DWORD cb = sizeof(dwVal);
    LSTATUS s = RegGetValueW(HKEY_LOCAL_MACHINE, SC_POLICY_KEY, REQUIRE_REVOCATION_VALUE,
        RRF_RT_REG_DWORD, nullptr, &dwVal, &cb);
    BOOL fChecked = (s == ERROR_SUCCESS && dwVal != 0);
    CheckDlgButton(hwndDlg, IDC_15_REQUIRE_REVOCATION, fChecked ? BST_CHECKED : BST_UNCHECKED);
}

// Revocation checking here is deliberately offline-only, so a machine with no CRL in its
// CA store can never confirm revocation status. Turning the policy on in that state makes
// the auth stack fail closed for every card - a machine-wide logon outage.
static BOOL MachineHasInstalledCrl()
{
    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG, L"CA");
    if (!hStore)
    {
        return FALSE;
    }
    PCCRL_CONTEXT pCrl = CertEnumCRLsInStore(hStore, nullptr);
    const BOOL fHasCrl = (pCrl != nullptr);
    if (pCrl)
    {
        CertFreeCRLContext(pCrl);
    }
    CertCloseStore(hStore, 0);
    return fHasCrl;
}

static void SaveRequireRevocation(HWND hwndDlg)
{
    DWORD dwVal = (IsDlgButtonChecked(hwndDlg, IDC_15_REQUIRE_REVOCATION) == BST_CHECKED) ? 1u : 0u;

    if (dwVal != 0 && !MachineHasInstalledCrl())
    {
        const int nAnswer = MessageBoxW(hwndDlg,
            L"No CRL is installed on this machine.\n\n"
            L"Revocation checking is offline-only, so with no CRL present every card's "
            L"revocation status is unknown and EVERY logon on this machine will be refused "
            L"while this policy is enabled.\n\n"
            L"Install a CRL first (the button above), then enable this policy.\n\n"
            L"Enable it anyway?",
            L"Revocation", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
        if (nAnswer != IDYES)
        {
            LoadRequireRevocation(hwndDlg);
            return;
        }
    }

    LSTATUS s = RegSetKeyValueW(HKEY_LOCAL_MACHINE, SC_POLICY_KEY, REQUIRE_REVOCATION_VALUE,
        REG_DWORD, &dwVal, sizeof(dwVal));
    if (s != ERROR_SUCCESS)
    {
        MessageBoxW(hwndDlg,
            L"Could not update the revocation policy. Administrator rights are required to change machine policy.",
            L"Revocation", MB_ICONWARNING);
        // Restore the checkbox to the on-disk value so the UI reflects reality.
        LoadRequireRevocation(hwndDlg);
    }
    else if (dwVal != 0)
    {
        SetDlgItemText(hwndDlg, IDC_15_RESULTS,
            L"Revocation checking is now REQUIRED. A card will be refused if its revocation "
            L"status cannot be confirmed from a locally installed CRL.");
    }
    else
    {
        SetDlgItemText(hwndDlg, IDC_15_RESULTS,
            L"Revocation checking is now optional. Logon is allowed when revocation status is unknown.");
    }
}

INT_PTR CALLBACK WndProc_15_Revocation(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
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
            LoadRequireRevocation(hwndDlg);
            SetDlgItemText(hwndDlg, IDC_15_RESULTS, L"");

            // Change Cancel button to Close (this is a terminal branch off Welcome)
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
        case IDC_15_BROWSE:
        {
            WCHAR szFile[MAX_PATH] = L"";  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
            OPENFILENAME ofn = {0};
            ofn.lStructSize = sizeof(OPENFILENAME);
            ofn.hwndOwner = hwndDlg;
            ofn.lpstrFilter = L"CRL Files (*.crl)\0*.crl\0All Files\0*.*\0";
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = ARRAYSIZE(szFile);
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

            if (GetOpenFileName(&ofn)) {
                SetDlgItemText(hwndDlg, IDC_15_CRL_PATH, szFile);
            }
            return TRUE;
        }

        case IDC_15_INSTALL:
        {
            WCHAR szFile[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
            GetDlgItemText(hwndDlg, IDC_15_CRL_PATH, szFile, ARRAYSIZE(szFile));

            if (wcsnlen(szFile, ARRAYSIZE(szFile)) == 0) { // NOSONAR - szFile is stack-allocated buffer, never NULL
                MessageBoxW(hwndDlg, L"Please select a CRL file (.crl) to install.",
                    L"Revocation", MB_ICONEXCLAMATION);
                return TRUE;
            }

            HRESULT hr = InstallCrlFromFile(szFile);
            if (SUCCEEDED(hr)) {
                SetDlgItemText(hwndDlg, IDC_15_RESULTS,
                    L"CRL installed successfully into the machine CA store. Offline revocation "
                    L"checking will use it immediately.");
                MessageBoxW(hwndDlg, L"CRL installed successfully.",
                    L"Revocation", MB_ICONINFORMATION);
            } else {
                WCHAR szMsg[320];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
                swprintf_s(szMsg, ARRAYSIZE(szMsg),
                    L"Failed to install the CRL (0x%08X).\n\nThe file must be a valid CRL signed "
                    L"by a certification authority already trusted on this machine, and "
                    L"administrator rights are required.", (unsigned)hr);
                SetDlgItemText(hwndDlg, IDC_15_RESULTS, szMsg);
                MessageBoxW(hwndDlg, szMsg, L"Revocation", MB_ICONERROR);
            }
            return TRUE;
        }

        case IDC_15_REQUIRE_REVOCATION:
            // Only act on a real click. Without the notification-code test a future
            // BS_NOTIFY focus change would silently rewrite the policy.
            if (HIWORD(wParam) == BN_CLICKED)
            {
                SaveRequireRevocation(hwndDlg);
            }
            return TRUE;

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
