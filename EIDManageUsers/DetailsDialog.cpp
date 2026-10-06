// DetailsDialog.cpp - User details dialog implementation
#include "DetailsDialog.h"
#include "../EIDMigrate/LsaClient.h"
#include <windowsx.h>

// Helper: Convert bytes to hex string (local implementation to avoid include issues)
static std::string BytesToHex(_In_reads_bytes_(cbBytes) const BYTE* pbBytes, _In_ DWORD cbBytes)  // NOSONAR - API-01: pointer+length signature dictated by Win32 buffer convention
{
    std::string result;
    result.reserve(cbBytes * 2);
    for (DWORD i = 0; i < cbBytes; i++)
    {
        char szHex[3];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        sprintf_s(szHex, sizeof(szHex), "%02X", pbBytes[i]);
        result += szHex;
    }
    return result;
}

// Store user pointer for dialog
static const UserInfo* g_pUser = nullptr;  // NOSONAR - GLOBAL-01: pointer assigned at runtime

// Format user details
//
// Built as a std::wstring rather than swprintf_s into a fixed buffer: the group
// list is unbounded, and once a 4096-character buffer filled, swprintf_s's
// invalid-parameter handler terminated the tool.
std::wstring FormatUserDetails(_In_ const UserInfo& user)
{
    std::wstring wsDetails;

    wsDetails += L"User Details for: " + user.wsUsername + L"\r\n\r\n";  // NOSONAR - FORMAT-01: plain appends keep the unbounded group list allocation-safe
    wsDetails += L"RID: " + std::to_wstring(user.dwRid) + L"\r\n";
    wsDetails += L"SID: " + user.wsSid + L"\r\n";
    wsDetails += L"Has EID Credential: ";
    wsDetails += user.fHasEIDCredential ? L"Yes" : L"No";
    wsDetails += L"\r\n";

    PCWSTR pwszEncFallback = (user.EncryptionType == EID_PRIVATE_DATA_TYPE::eidpdtDPAPI) ? L"DPAPI" : L"None";
    PCWSTR pwszEnc = (user.EncryptionType == EID_PRIVATE_DATA_TYPE::eidpdtCrypted) ? L"Certificate-based" : pwszEncFallback;
    wsDetails += L"Encryption Type: ";
    wsDetails += pwszEnc;
    wsDetails += L"\r\n";

    wsDetails += L"Last Login: " + user.wsLastLogin + L"\r\n\r\n";

    // Certificate hash
    if (user.fHasEIDCredential)
    {
        wsDetails += L"--- Certificate Information ---\r\n";

        // The hex digits are ASCII, so widening each char is exact.
        std::string sHash = BytesToHex(user.CertificateHash, CERT_HASH_LENGTH);
        wsDetails += L"Certificate Hash: ";
        for (char ch : sHash)
        {
            wsDetails += static_cast<wchar_t>(ch);
        }
        wsDetails += L"\r\n\r\n";
    }

    // Groups
    wsDetails += L"--- Group Membership ---\r\n";
    if (user.wsGroups.empty())
    {
        wsDetails += L"No group memberships found.\r\n";
    }
    else
    {
        for (const auto& group : user.wsGroups)
        {
            wsDetails += L"\u2022 " + group + L"\r\n";  // NOSONAR - ESCAPE-01: C++23 delimited escapes not used in this codebase
        }
    }

    return wsDetails;
}

// Initialize details dialog
void InitializeDetailsDialog(HWND hwndDlg, _In_ const UserInfo* pUser)
{
    g_pUser = pUser;

    // Set window title
    WCHAR szTitle[256];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    swprintf_s(szTitle, ARRAYSIZE(szTitle),
        L"User Details - %s", pUser->wsUsername.c_str());
    SetWindowTextW(hwndDlg, szTitle);

    // Get details text control
    HWND hDetails = GetDlgItem(hwndDlg, IDC_DETAILS_TEXT);
    if (hDetails)
    {
        std::wstring wsDetails = FormatUserDetails(*pUser);
        SetWindowTextW(hDetails, wsDetails.c_str());
    }
}

// Details dialog procedure
INT_PTR CALLBACK WndProc_Details(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
        SetWindowIcon(hwndDlg);
        InitializeDetailsDialog(hwndDlg,
            reinterpret_cast<const UserInfo*>(lParam));  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDCLOSE:
        case IDOK:
        case IDCANCEL:
            EndDialog(hwndDlg, IDOK);
            return TRUE;
        default:
            break;
        }
        break;

    default:
        break;
    }

    return FALSE;
}
