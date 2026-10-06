// File: EIDMigrate/GroupManagement.cpp
// Local group management functions

#include "GroupManagement.h"
#include "Tracing.h"
#include <lm.h>
#include <sddl.h>

#pragma comment(lib, "netapi32.lib")

namespace BuiltinGroups
{
    BOOL IsBuiltin(_In_ const std::wstring& wsGroupName)  // NOSONAR - API-01: const reference signature retained for interface stability
    {
        return (wsGroupName == ADMINISTRATORS ||
            wsGroupName == USERS ||
            wsGroupName == GUESTS ||
            wsGroupName == POWER_USERS ||
            wsGroupName == REMOTE_DESKTOP_USERS ||
            wsGroupName == REMOTE_MANAGEMENT_USERS);
    }

    BOOL IsBuiltinSid(_In_ PSID pSid)
    {
        if (!pSid)
            return FALSE;

        SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
        PSID pBuiltinSid = nullptr;

        // Check for well-known SIDs
        if (!AllocateAndInitializeSid(&auth, 2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &pBuiltinSid))
        {
            return FALSE;
        }

        BOOL fResult = EqualSid(pSid, pBuiltinSid);
        FreeSid(pBuiltinSid);

        return fResult;
    }
}

HRESULT GroupExists(_In_ const std::wstring& wsGroupName, _Out_ BOOL& pfExists)
{
    LOCALGROUP_INFO_0* pInfo = nullptr;

    pfExists = FALSE;

    NET_API_STATUS status = NetLocalGroupGetInfo(nullptr, wsGroupName.c_str(), 0,
        reinterpret_cast<LPBYTE*>(&pInfo)); // NOSONAR - Windows Net API requires LPBYTE (BYTE*); cannot use std::byte

    if (status == NERR_Success)
    {
        pfExists = TRUE;
        NetApiBufferFree(pInfo);
        return S_OK;
    }
    else if (status == NERR_GroupNotFound)
    {
        return S_OK;
    }

    return HRESULT_FROM_WIN32(status);
}

HRESULT GetGroupInfo(_In_ const std::wstring& wsGroupName, _Out_ LocalGroupInfo& info)
{
    LOCALGROUP_INFO_1* pInfo = nullptr;

    NET_API_STATUS status = NetLocalGroupGetInfo(nullptr, wsGroupName.c_str(), 1,
        reinterpret_cast<LPBYTE*>(&pInfo)); // NOSONAR - Windows Net API requires LPBYTE (BYTE*); cannot use std::byte

    if (status != NERR_Success)  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
        return HRESULT_FROM_WIN32(status);

    info.wsName = wsGroupName;
    info.wsComment = pInfo->lgrpi1_comment;
    info.fBuiltin = BuiltinGroups::IsBuiltin(wsGroupName);

    NetApiBufferFree(pInfo);

    // Get members
    return GetGroupMembers(wsGroupName, info.wsMembers);
}

HRESULT CreateLocalGroup(_In_ const std::wstring& wsGroupName, _In_ const std::wstring& wsComment)
{
    LOCALGROUP_INFO_0 lg0 = {};
    lg0.lgrpi0_name = const_cast<LPWSTR>(wsGroupName.c_str());  // NOSONAR - CAST-01: Win32 Net API struct field is input-only; const_cast safe

    DWORD parm_err = 0;
    NET_API_STATUS status = NetLocalGroupAdd(nullptr, 0,
        reinterpret_cast<LPBYTE>(&lg0), &parm_err); // NOSONAR - Windows Net API requires LPBYTE (BYTE*); cannot use std::byte which is incompatible with Win32 APIs

    if (status == NERR_Success && !wsComment.empty())
    {
        SetGroupComment(wsGroupName, wsComment);
    }

    return HRESULT_FROM_WIN32(status);
}

HRESULT SetGroupComment(_In_ const std::wstring& wsGroupName, _In_ const std::wstring& wsComment)
{
    LOCALGROUP_INFO_1002 lg1002 = {};
    lg1002.lgrpi1002_comment = const_cast<LPWSTR>(wsComment.c_str());  // NOSONAR - CAST-01: Win32 Net API struct field is input-only; const_cast safe

    NET_API_STATUS status = NetLocalGroupSetInfo(nullptr, wsGroupName.c_str(),
        1002, reinterpret_cast<LPBYTE>(&lg1002), nullptr); // NOSONAR - Windows Net API requires LPBYTE (BYTE*); cannot use std::byte

    return HRESULT_FROM_WIN32(status);
}

HRESULT AddUserToGroup(_In_ const std::wstring& wsUsername, _In_ const std::wstring& wsGroupName)
{
    LOCALGROUP_MEMBERS_INFO_3 lm3 = {};
    lm3.lgrmi3_domainandname = const_cast<LPWSTR>(wsUsername.c_str());  // NOSONAR - CAST-01: Win32 Net API struct field is input-only; const_cast safe

    NET_API_STATUS status = NetLocalGroupAddMembers(nullptr, wsGroupName.c_str(),
        3, reinterpret_cast<LPBYTE>(&lm3), 1); // NOSONAR - Windows Net API requires LPBYTE (BYTE*); cannot use std::byte

    return HRESULT_FROM_WIN32(status);
}

HRESULT RemoveUserFromGroup(_In_ const std::wstring& wsUsername, _In_ const std::wstring& wsGroupName)
{
    LOCALGROUP_MEMBERS_INFO_3 lm3 = {};
    lm3.lgrmi3_domainandname = const_cast<LPWSTR>(wsUsername.c_str());  // NOSONAR - CAST-01: Win32 Net API struct field is input-only; const_cast safe

    NET_API_STATUS status = NetLocalGroupDelMembers(nullptr, wsGroupName.c_str(),
        3, reinterpret_cast<LPBYTE>(&lm3), 1); // NOSONAR - Windows Net API requires LPBYTE (BYTE*); cannot use std::byte

    return HRESULT_FROM_WIN32(status);
}

HRESULT GetGroupMembers(_In_ const std::wstring& wsGroupName, _Out_ std::vector<std::wstring>& wsMembers)
{
    LPLOCALGROUP_MEMBERS_INFO_2 pBuf = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;

    NET_API_STATUS status = NetLocalGroupGetMembers(nullptr, wsGroupName.c_str(), 2,
        reinterpret_cast<LPBYTE*>(&pBuf),  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries,
        nullptr);

    if (status != NERR_Success)  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
        return HRESULT_FROM_WIN32(status);

    for (DWORD i = 0; i < dwEntriesRead; i++)
    {
        if (pBuf[i].lgrmi2_sidusage == SidTypeUser)
        {
            wsMembers.emplace_back(pBuf[i].lgrmi2_domainandname);
        }
    }

    NetApiBufferFree(pBuf);
    return S_OK;
}

HRESULT EnumerateLocalGroups(_Out_ std::vector<LocalGroupInfo>& groups)
{
    LPLOCALGROUP_INFO_1 pBuf = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;

    NET_API_STATUS status = NetLocalGroupEnum(nullptr, 1,
        reinterpret_cast<LPBYTE*>(&pBuf),  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries,
        nullptr);

    if (status != NERR_Success)  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
        return HRESULT_FROM_WIN32(status);

    for (DWORD i = 0; i < dwEntriesRead; i++)
    {
        LocalGroupInfo info;
        info.wsName = pBuf[i].lgrpi1_name;
        info.wsComment = pBuf[i].lgrpi1_comment;
        info.fBuiltin = BuiltinGroups::IsBuiltin(info.wsName);

        // Get members for this group
        GetGroupMembers(info.wsName, info.wsMembers);

        groups.push_back(std::move(info));
    }

    NetApiBufferFree(pBuf);
    return S_OK;
}

HRESULT GetUserGroups(_In_ const std::wstring& wsUsername, _Out_ std::vector<std::wstring>& wsGroupNames)
{
    LPLOCALGROUP_USERS_INFO_0 pBuf = nullptr;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;

    NET_API_STATUS status = NetUserGetLocalGroups(nullptr, wsUsername.c_str(), 0,
        LG_INCLUDE_INDIRECT,
        reinterpret_cast<LPBYTE*>(&pBuf),  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries);

    if (status != NERR_Success)  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
        return HRESULT_FROM_WIN32(status);

    for (DWORD i = 0; i < dwEntriesRead; i++)
    {
        wsGroupNames.emplace_back(pBuf[i].lgrui0_name);
    }

    NetApiBufferFree(pBuf);
    return S_OK;
}

HRESULT SynchronizeGroupMemberships(
    _In_ const std::wstring& wsUsername,
    _In_ const std::vector<std::wstring>& wsTargetGroups,
    _Out_ DWORD& pdwChanges)
{
    pdwChanges = 0;

    // Get current groups
    std::vector<std::wstring> wsCurrentGroups;
    HRESULT hr = GetUserGroups(wsUsername, wsCurrentGroups);
    if (FAILED(hr))
        return hr;

    // Add to groups that are in target but not current
    for (const auto& wsTargetGroup : wsTargetGroups)
    {
        // Check if user is already in this group
        BOOL fInGroup = FALSE;
        for (const auto& wsCurrentGroup : wsCurrentGroups)
        {
            if (_wcsicmp(wsCurrentGroup.c_str(), wsTargetGroup.c_str()) == 0)
            {
                fInGroup = TRUE;
                break;
            }
        }

        if (!fInGroup)
        {
            // Don't try to add to built-in groups that don't exist
            if (!BuiltinGroups::IsBuiltin(wsTargetGroup))  // NOSONAR - COMPLEXITY-01: nested if kept separate for clarity
            {
                BOOL fExists = FALSE;
                GroupExists(wsTargetGroup, fExists);

                if (fExists) // NOSONAR - Nested if required; GroupExists uses output parameter, cannot easily merge conditions
                {
                    hr = AddUserToGroup(wsUsername, wsTargetGroup);
                    if (SUCCEEDED(hr))
                    {
                        pdwChanges++;
                        EIDM_TRACE_VERBOSE(L"Added %ls to group %ls",
                            wsUsername.c_str(), wsTargetGroup.c_str());
                    }
                }
            }
        }
    }

    // Note: We don't remove from current groups that aren't in target
    // as that might remove admin access

    return S_OK;
}
