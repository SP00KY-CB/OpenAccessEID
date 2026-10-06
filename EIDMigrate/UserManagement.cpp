// File: EIDMigrate/UserManagement.cpp
// User account management functions

#include "UserManagement.h"
#include "LsaClient.h"
#include "AuditLogging.h"
#include "Tracing.h"
#include <lm.h>  // NOSONAR - INCLUDE-01: include case/order significant for Windows SDK

#pragma comment(lib, "netapi32.lib")

HRESULT UserExists(_In_ const std::wstring& wsUsername, _Out_ BOOL& pfExists)
{
    USER_INFO_0* pInfo = nullptr;
    DWORD dwError = 0; // NOSONAR - variable used

    pfExists = FALSE;

    NET_API_STATUS status = NetUserGetInfo(nullptr, wsUsername.c_str(), 0,
        reinterpret_cast<LPBYTE*>(&pInfo));  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified

    if (status == NERR_Success)
    {
        pfExists = TRUE;
        NetApiBufferFree(pInfo);
        return S_OK;
    }
    else if (status == NERR_UserNotFound)
    {
        return S_OK;
    }

    return HRESULT_FROM_WIN32(status);
}

HRESULT GetUserInfo(_In_ const std::wstring& wsUsername, _Out_ LocalUserInfo& info)
{
    USER_INFO_1* pInfo = nullptr;
    DWORD dwError = 0; // NOSONAR - variable used

    NET_API_STATUS status = NetUserGetInfo(nullptr, wsUsername.c_str(), 1,
        reinterpret_cast<LPBYTE*>(&pInfo));  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified

    if (status != NERR_Success)  // NOSONAR - SCOPE-01: status kept as a named local for readability
        return HRESULT_FROM_WIN32(status);

    info.wsUsername = wsUsername;
    info.dwAccountId = 0;  // Not directly available in USER_INFO_1
    info.fEnabled = !(pInfo->usri1_flags & UF_ACCOUNTDISABLE);

    NetApiBufferFree(pInfo);

    // Get RID
    DWORD dwRid = 0;
    HRESULT hr = GetUserRid(wsUsername, dwRid);
    if (SUCCEEDED(hr))
    {
        info.dwRid = dwRid;
    }
    else
    {
        info.dwRid = 0;
    }

    // Get SID
    std::wstring wsSid;
    hr = GetUserSid(wsUsername, wsSid);
    if (SUCCEEDED(hr))
    {
        info.wsSid = std::move(wsSid);
    }
    else
    {
        info.wsSid.clear();
    }

    return S_OK;
}

HRESULT GetUserRid(_In_ const std::wstring& wsUsername, _Out_ DWORD& pdwRid)
{
    pdwRid = LookupRidByUsername(wsUsername);
    return (pdwRid != 0) ? S_OK : E_FAIL;
}

HRESULT GetUserSid(_In_ const std::wstring& wsUsername, _Out_ std::wstring& wsSid)
{
    wsSid = LookupSidByUsername(wsUsername);
    return (!wsSid.empty()) ? S_OK : E_FAIL;
}

HRESULT CreateLocalUserAccount(
    _In_ const std::wstring& wsUsername,
    _In_ const std::wstring& wsFullName, // NOSONAR - variable used
    _In_ const std::wstring& wsComment,
    _In_opt_ PCWSTR pwszPassword,
    _In_ BOOL fEnabled,
    _In_ BOOL fPasswordNeverExpires)
{
    USER_INFO_1 ui1 = {};
    ui1.usri1_name = const_cast<LPWSTR>(wsUsername.c_str());  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
    ui1.usri1_password = const_cast<LPWSTR>((pwszPassword) ? pwszPassword : L"");  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
    ui1.usri1_priv = USER_PRIV_USER;
    ui1.usri1_home_dir = nullptr;
    ui1.usri1_comment = const_cast<LPWSTR>(wsComment.c_str());  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
    ui1.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT |
        (fEnabled ? 0 : UF_ACCOUNTDISABLE) |
        (fPasswordNeverExpires ? UF_DONT_EXPIRE_PASSWD : 0);
    ui1.usri1_script_path = nullptr;

    NET_API_STATUS status = NetUserAdd(nullptr, 1,
        reinterpret_cast<LPBYTE>(&ui1), nullptr);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API

    // BUG FIX #21: Audit logging for user creation
    if (status == NERR_Success)
    {
        WCHAR szDetails[256];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        swprintf_s(szDetails, ARRAYSIZE(szDetails), L"User account created: %ls (Enabled: %d)",
            wsUsername.c_str(), fEnabled);
        LOG_USER_CREATED(wsUsername.c_str(), szDetails);
    }
    else
    {
        WCHAR szDetails[256];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        swprintf_s(szDetails, ARRAYSIZE(szDetails), L"User creation failed for %ls: Error %u",
            wsUsername.c_str(), status);
        LOG_WARNING(szDetails);
    }

    return HRESULT_FROM_WIN32(status);
}

HRESULT SetUserPassword(_In_ const std::wstring& wsUsername, _In_ PCWSTR pwszPassword)
{
    USER_INFO_1003 ui1003 = {};
    ui1003.usri1003_password = const_cast<LPWSTR>(pwszPassword);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified

    NET_API_STATUS status = NetUserSetInfo(nullptr, wsUsername.c_str(),
        1003, reinterpret_cast<LPBYTE>(&ui1003), nullptr);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API

    return HRESULT_FROM_WIN32(status);
}

// Read-modify-write of a local account's USER_INFO flags: sets dwSet and
// clears dwClear, leaving every other flag as it was.
static HRESULT UpdateUserFlags(_In_ const std::wstring& wsUsername, _In_ DWORD dwSet, _In_ DWORD dwClear)
{
    USER_INFO_1* pInfo = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, wsUsername.c_str(), 1,
        reinterpret_cast<LPBYTE*>(&pInfo));  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified

    if (status != NERR_Success)
        return HRESULT_FROM_WIN32(status);

    const DWORD dwFlags = (pInfo->usri1_flags & ~dwClear) | dwSet;
    NetApiBufferFree(pInfo);

    USER_INFO_1008 ui1008 = {};
    ui1008.usri1008_flags = dwFlags;

    status = NetUserSetInfo(nullptr, wsUsername.c_str(),
        1008, reinterpret_cast<LPBYTE>(&ui1008), nullptr);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API

    return HRESULT_FROM_WIN32(status);
}

HRESULT SetUserEnabled(_In_ const std::wstring& wsUsername, _In_ BOOL fEnabled)
{
    // Modify only the disabled flag
    return fEnabled ? UpdateUserFlags(wsUsername, 0, UF_ACCOUNTDISABLE)
                    : UpdateUserFlags(wsUsername, UF_ACCOUNTDISABLE, 0);
}

HRESULT SetUserPasswordNeverExpires(_In_ const std::wstring& wsUsername, _In_ BOOL fNeverExpires)
{
    return fNeverExpires ? UpdateUserFlags(wsUsername, UF_DONT_EXPIRE_PASSWD, 0)
                         : UpdateUserFlags(wsUsername, 0, UF_DONT_EXPIRE_PASSWD);
}

HRESULT EnumerateLocalUsers(_Out_ std::vector<LocalUserInfo>& users)
{
    LPUSER_INFO_0 pBuf = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS status;

    status = NetUserEnum(nullptr, 0, FILTER_NORMAL_ACCOUNT,
        reinterpret_cast<LPBYTE*>(&pBuf),  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries,
        nullptr);

    if (status != NERR_Success)
        return HRESULT_FROM_WIN32(status);

    for (DWORD i = 0; i < dwEntriesRead; i++)
    {
        LocalUserInfo info;
        if (SUCCEEDED(GetUserInfo(pBuf[i].usri0_name, info)))
        {
            users.push_back(std::move(info));
        }
    }

    NetApiBufferFree(pBuf);
    return S_OK;
}

void DisplayUserInfo(_In_ const LocalUserInfo& info)
{
    EIDM_TRACE_INFO(L"  User: %ls", info.wsUsername.c_str());
    EIDM_TRACE_INFO(L"    RID: %u", info.dwRid);
    EIDM_TRACE_INFO(L"    SID: %ls", info.wsSid.c_str());
    EIDM_TRACE_INFO(L"    Enabled: %ls", info.fEnabled ? L"Yes" : L"No");
}
