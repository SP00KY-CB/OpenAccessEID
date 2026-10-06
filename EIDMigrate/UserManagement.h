#pragma once

// File: EIDMigrate/UserManagement.h
// User account management functions

#include "EIDMigrate.h"
#include <LM.h>
#include <vector>

// User information structure.
// Not named UserInfo: EIDManageUsers links this file and has its own, different
// UserInfo, and two definitions under one name break the one-definition rule.
struct LocalUserInfo
{
    std::wstring wsUsername;
    std::wstring wsFullName;
    std::wstring wsComment;
    DWORD dwRid;
    std::wstring wsSid;
    DWORD dwAccountId;  // USER_ACCOUNT_ID from NetUserGetInfo
    BOOL fEnabled;
    BOOL fPasswordExpired;

    LocalUserInfo() :
        dwRid(0),  // NOSONAR - INIT-01: member initialized via constructor initializer list
        dwAccountId(0),  // NOSONAR - INIT-01: member initialized via constructor initializer list
        fEnabled(TRUE),  // NOSONAR - INIT-01: member initialized via constructor initializer list
        fPasswordExpired(FALSE)  // NOSONAR - INIT-01: member initialized via constructor initializer list
    {}
};

// Check if user account exists
HRESULT UserExists(
    _In_ const std::wstring& wsUsername,
    _Out_ BOOL& pfExists);

// Get user information
HRESULT GetUserInfo(
    _In_ const std::wstring& wsUsername,
    _Out_ LocalUserInfo& info);

// Get user RID
HRESULT GetUserRid(
    _In_ const std::wstring& wsUsername,
    _Out_ DWORD& pdwRid);

// Get user SID
HRESULT GetUserSid(
    _In_ const std::wstring& wsUsername,
    _Out_ std::wstring& wsSid);

// Create local user account
HRESULT CreateLocalUserAccount(
    _In_ const std::wstring& wsUsername,
    _In_ const std::wstring& wsFullName,
    _In_ const std::wstring& wsComment,
    _In_opt_ PCWSTR pwszPassword,
    _In_ BOOL fEnabled,
    _In_ BOOL fPasswordNeverExpires);

// Set user password
HRESULT SetUserPassword(
    _In_ const std::wstring& wsUsername,
    _In_ PCWSTR pwszPassword);

// Enable/disable user account
HRESULT SetUserEnabled(
    _In_ const std::wstring& wsUsername,
    _In_ BOOL fEnabled);

// Set "password never expires" flag
HRESULT SetUserPasswordNeverExpires(
    _In_ const std::wstring& wsUsername,
    _In_ BOOL fNeverExpires);

// Enumerate local users
HRESULT EnumerateLocalUsers(
    _Out_ std::vector<LocalUserInfo>& users);

// Display user information
void DisplayUserInfo(_In_ const LocalUserInfo& info);
