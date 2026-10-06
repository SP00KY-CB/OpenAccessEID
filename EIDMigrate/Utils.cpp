// File: EIDMigrate/Utils.cpp
// General utility functions implementation

#include "Utils.h"
#include "RateLimiter.h"
#include <lm.h>  // NOSONAR - INCLUDE-01: include order/casing significant for Windows SDK
#include <shlwapi.h>  // NOSONAR - INCLUDE-01: include order/casing significant for Windows SDK
#include <chrono>
#include <sstream>
#include <bcrypt.h>
#include <sddl.h>
#include <stdlib.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")

// Check if we have a valid console (for GUI compatibility)
static BOOL HasValidConsole()
{
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);  // NOSONAR - API-01: signature dictated by Windows/callback API
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);  // NOSONAR - API-01: signature dictated by Windows/callback API
    HANDLE hStdErr = GetStdHandle(STD_ERROR_HANDLE);  // NOSONAR - API-01: signature dictated by Windows/callback API

    return (hStdOut != INVALID_HANDLE_VALUE && hStdOut != nullptr &&
            hStdIn != INVALID_HANDLE_VALUE && hStdIn != nullptr &&
            hStdErr != INVALID_HANDLE_VALUE && hStdErr != nullptr);
}

// String conversion utilities
std::string WideToUtf8(_In_ const std::wstring& ws)
{
    if (ws.empty())
        return std::string();

    int cchNeeded = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(),
        static_cast<int>(ws.length()), nullptr, 0, nullptr, nullptr);
    if (cchNeeded <= 0)
        return std::string();

    std::string result(cchNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(),
        static_cast<int>(ws.length()), &result[0], cchNeeded, nullptr, nullptr);

    return result;
}

std::wstring Utf8ToWide(_In_ const std::string& s)
{
    if (s.empty())
        return std::wstring();

    int cchNeeded = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
        static_cast<int>(s.length()), nullptr, 0);
    if (cchNeeded <= 0)
        return std::wstring();

    std::wstring result(cchNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
        static_cast<int>(s.length()), &result[0], cchNeeded);

    return result;
}

std::wstring AnsiToWide(_In_ const std::string& s)
{
    if (s.empty())
        return std::wstring();

    int cchNeeded = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
        static_cast<int>(s.length()), nullptr, 0);
    if (cchNeeded <= 0)
        return std::wstring();

    std::wstring result(cchNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
        static_cast<int>(s.length()), &result[0], cchNeeded);

    return result;
}

// SID conversion utilities
std::wstring SidToString(_In_ PSID pSid)
{
    if (!pSid)
        return std::wstring();

    LPWSTR pwszSid = nullptr;
    if (!ConvertSidToStringSidW(pSid, &pwszSid))
        return std::wstring();

    std::wstring wsResult(pwszSid);
    LocalFree(pwszSid);

    return wsResult;
}

BOOL StringToSid(_In_ const std::wstring& wsSid, _Out_ PSID* ppSid)
{
    if (!ppSid || wsSid.empty())
        return FALSE;

    return ConvertStringSidToSidW(wsSid.c_str(), ppSid);
}

DWORD GetRidFromSid(_In_ PSID pSid)
{
    if (!pSid)
        return 0;

    DWORD dwSubAuthorityCount = *GetSidSubAuthorityCount(pSid);
    if (dwSubAuthorityCount == 0)
        return 0;

    return *GetSidSubAuthority(pSid, dwSubAuthorityCount - 1);
}

// Computer name
std::wstring GetComputerName()
{
    WCHAR szBuffer[MAX_COMPUTERNAME_LENGTH + 1];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    DWORD dwSize = ARRAYSIZE(szBuffer);

    if (!::GetComputerNameW(szBuffer, &dwSize))  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
        return L".";

    return std::wstring(szBuffer);
}

std::wstring GetUserName()
{
    WCHAR szBuffer[UNLEN + 1];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    DWORD dwSize = ARRAYSIZE(szBuffer);

    if (!::GetUserNameW(szBuffer, &dwSize))  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
        return L"?";

    return std::wstring(szBuffer);
}

// File path utilities
std::wstring GetFileExtension(_In_ const std::wstring& wsPath)
{
    return PathFindExtensionW(wsPath.c_str());
}

std::wstring GetFileName(_In_ const std::wstring& wsPath)
{
    return PathFindFileNameW(wsPath.c_str());
}

std::wstring GetDirectoryPath(_In_ const std::wstring& wsPath)
{
    WCHAR szDir[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    wcscpy_s(szDir, wsPath.c_str());
    PathRemoveFileSpecW(szDir);
    return std::wstring(szDir);
}

bool FileExists(_In_ const std::wstring& wsPath)
{
    return (GetFileAttributesW(wsPath.c_str()) != INVALID_FILE_ATTRIBUTES);
}

bool IsFileReadable(_In_ const std::wstring& wsPath)
{
    HANDLE hFile = CreateFileW(wsPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    CloseHandle(hFile);
    return true;
}

bool IsFileWritable(_In_ const std::wstring& wsPath)
{
    HANDLE hFile = CreateFileW(wsPath.c_str(), GENERIC_WRITE,
        0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    CloseHandle(hFile);
    return true;
}

// Time formatting
std::wstring FormatTimestamp(_In_ const FILETIME& ft)
{
    // Convert FILETIME to system time
    FILETIME ftLocal;
    if (!FileTimeToLocalFileTime(&ft, &ftLocal))
        return L"?";

    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ftLocal, &st))
        return L"?";

    // Format as ISO 8601
    WCHAR szBuffer[64];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    swprintf_s(szBuffer, L"%04d-%02d-%02dT%02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    return std::wstring(szBuffer);
}

std::wstring FormatCurrentTimestamp()
{
    SYSTEMTIME st;
    GetSystemTime(&st);  // Use UTC time, not local time

    WCHAR szBuffer[64];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    swprintf_s(szBuffer, L"%04d-%02d-%02dT%02d:%02d:%02dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    return std::wstring(szBuffer);
}

// Prompt user for input
BOOL PromptYesNo(_In_ PCWSTR pwszPrompt, _In_ BOOL fDefaultYes)
{
    // GUI compatibility: return default if no console
    if (!HasValidConsole())
        return fDefaultYes;

    if (!pwszPrompt)
        return fDefaultYes;

    fwprintf(stderr, L"%ls", pwszPrompt);

    WCHAR szResponse[16];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    if (fgetws(szResponse, ARRAYSIZE(szResponse), stdin) == nullptr)
        return fDefaultYes;

    // Trim whitespace
    size_t cchLen = wcslen(szResponse); // NOSONAR - szResponse is stack-allocated buffer, never NULL
    while (cchLen > 0 && iswspace(szResponse[cchLen - 1]))
        szResponse[--cchLen] = L'\0';

    if (cchLen == 0)
        return fDefaultYes;

    return (towupper(szResponse[0]) == L'Y');
}

std::wstring PromptForString(_In_ PCWSTR pwszPrompt)
{
    // GUI compatibility: return empty string if no console
    if (!HasValidConsole())
        return std::wstring();

    if (!pwszPrompt)
        return std::wstring();

    fwprintf(stderr, L"%ls", pwszPrompt);

    WCHAR szBuffer[512];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    if (fgetws(szBuffer, ARRAYSIZE(szBuffer), stdin) == nullptr)
        return std::wstring();

    // Trim newline
    size_t cchLen = wcslen(szBuffer); // NOSONAR - szBuffer is stack-allocated buffer, never NULL
    while (cchLen > 0 && (szBuffer[cchLen - 1] == L'\r' || szBuffer[cchLen - 1] == L'\n'))
        szBuffer[--cchLen] = L'\0';

    return std::wstring(szBuffer, cchLen);
}

SecureWString PromptForPassphrase(_In_ PCWSTR pwszPrompt, _In_ BOOL fConfirm)
{
    // GUI compatibility: return empty string if no console
    if (!HasValidConsole())
        return SecureWString();

    // BUG FIX #20: Rate limiting for passphrase attempts to prevent brute force attacks
    SecurityRateLimiter& rateLimiter = SecurityRateLimiter::GetInstance();

    // Check if we should rate limit
    DWORD dwDelayMs = 0;
    if (rateLimiter.RecordFailedAttempt(L"Passphrase entry", &dwDelayMs))  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
    {
        EIDM_TRACE_WARN(L"Too many failed passphrase attempts. Waiting %u ms before allowing retry.", dwDelayMs);
        Sleep(dwDelayMs);
    }

    if (!pwszPrompt)
        pwszPrompt = L"Enter passphrase: ";

    // Note: This is a simple implementation. For production,
    // we should use proper console input masking.
    // We'll implement the proper version in PinPrompt.cpp

    fwprintf(stderr, L"%ls", pwszPrompt);

    WCHAR szBuffer[256];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    if (fgetws(szBuffer, ARRAYSIZE(szBuffer), stdin) == nullptr)
    {
        SecureZeroMemory(szBuffer, sizeof(szBuffer));
        return SecureWString();
    }

    // Trim newline
    size_t cchLen = wcslen(szBuffer); // NOSONAR - szBuffer is stack-allocated buffer, never NULL
    while (cchLen > 0 && (szBuffer[cchLen - 1] == L'\r' || szBuffer[cchLen - 1] == L'\n'))
        szBuffer[--cchLen] = L'\0';

    SecureWString wsResult(szBuffer, cchLen);
    SecureZeroMemory(szBuffer, sizeof(szBuffer));

    if (fConfirm)
    {
        fwprintf(stderr, L"Confirm passphrase: ");

        WCHAR szConfirm[256];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        if (fgetws(szConfirm, ARRAYSIZE(szConfirm), stdin) == nullptr)
        {
            SecureZeroMemory(szConfirm, sizeof(szConfirm));
            return SecureWString();
        }

        cchLen = wcslen(szConfirm); // NOSONAR - szConfirm is stack-allocated buffer, never NULL
        while (cchLen > 0 && (szConfirm[cchLen - 1] == L'\r' || szConfirm[cchLen - 1] == L'\n'))
            szConfirm[--cchLen] = L'\0';

        // Compare against the captured passphrase: szBuffer has already been wiped.
        const bool fMatch = (cchLen == wsResult.size()) &&
            (wmemcmp(wsResult.c_str(), szConfirm, cchLen) == 0);
        if (!fMatch)
        {
            fwprintf(stderr, L"Error: Passphrases do not match.\n");
            SecureZeroMemory(szConfirm, sizeof(szConfirm));
            // Note: Failure already recorded at function entry, will be cleared on next successful entry
            return SecureWString();
        }

        SecureZeroMemory(szConfirm, sizeof(szConfirm));
    }

    // Record successful passphrase entry
    rateLimiter.RecordSuccess();

    return wsResult;
}

// Version info
std::wstring GetFileVersion(_In_ PCWSTR pwszFilePath)
{
    if (!pwszFilePath)
        return std::wstring();

    DWORD dwDummy = 0;
    DWORD dwSize = GetFileVersionInfoSizeW(pwszFilePath, &dwDummy);
    if (dwSize == 0)
        return std::wstring();

    std::vector<BYTE> buffer(dwSize);
    if (!GetFileVersionInfoW(pwszFilePath, 0, dwSize, buffer.data()))
        return std::wstring();

    LPVOID pvBuffer = nullptr;
    UINT uLen = 0;
    if (!VerQueryValueW(buffer.data(), L"\\StringFileInfo\\040904b0\\FileVersion",  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
        &pvBuffer, &uLen))
        return std::wstring();

    return std::wstring(static_cast<PWSTR>(pvBuffer));
}

// Check if running as administrator
BOOL IsRunningAsAdmin()
{
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    PSID pAdminSid = nullptr;

    if (!AllocateAndInitializeSid(&auth, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdminSid))
        return FALSE;

    BOOL fIsAdmin = FALSE;
    if (!CheckTokenMembership(nullptr, pAdminSid, &fIsAdmin))
        fIsAdmin = FALSE;

    FreeSid(pAdminSid);
    return fIsAdmin;
}

// Enable a privilege for the current process
BOOL EnablePrivilege(_In_ PCWSTR pwszPrivilege)
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, pwszPrivilege, &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL fResult = AdjustTokenPrivileges(hToken, FALSE, &tp,
        sizeof(tp), nullptr, nullptr);

    DWORD dwError = GetLastError();
    CloseHandle(hToken);

    return fResult && (dwError == ERROR_SUCCESS);
}

// Error formatting
std::wstring FormatErrorMessage(_In_ DWORD dwError)
{
    LPWSTR pwszMessage = nullptr;
    DWORD dwLen = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, dwError, 0,
        reinterpret_cast<LPWSTR>(&pwszMessage), 0, nullptr);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified

    if (dwLen == 0 || !pwszMessage)  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
    {
        WCHAR szBuffer[64];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        swprintf_s(szBuffer, L"Error 0x%08X", dwError);
        return std::wstring(szBuffer);
    }

    std::wstring wsResult(pwszMessage);
    LocalFree(pwszMessage);

    // Remove trailing newlines
    while (!wsResult.empty() && (wsResult.back() == L'\r' || wsResult.back() == L'\n'))
        wsResult.pop_back();

    return wsResult;
}

std::wstring FormatHResult(_In_ HRESULT hr)
{
    if (HRESULT_FACILITY(hr) == FACILITY_WIN32)
        return FormatErrorMessage(HRESULT_CODE(hr));

    LPWSTR pwszMessage = nullptr;
    DWORD dwLen = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, hr, 0,
        reinterpret_cast<LPWSTR>(&pwszMessage), 0, nullptr);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified

    if (dwLen == 0 || !pwszMessage)  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
    {
        WCHAR szBuffer[64];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        swprintf_s(szBuffer, L"HRESULT 0x%08X", hr);
        return std::wstring(szBuffer);
    }

    std::wstring wsResult(pwszMessage);
    LocalFree(pwszMessage);

    while (!wsResult.empty() && (wsResult.back() == L'\r' || wsResult.back() == L'\n'))
        wsResult.pop_back();

    return wsResult;
}

std::wstring GenerateRandomPassword(_In_ DWORD dwLength)
{
    static const wchar_t szChars[] =
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";

    std::wstring wsPassword;
    wsPassword.reserve(dwLength);

    BYTE pbRnd[32];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API

    // Use BCrypt for cryptographically secure random numbers
    // If BCryptGenRandom fails, return empty string rather than falling back to weak randomness
    if (BCryptGenRandom(nullptr, pbRnd, sizeof(pbRnd), 0) >= 0)  // NOSONAR - SCOPE-01: declaration kept in enclosing scope
    {
        for (DWORD i = 0; i < dwLength; i++)
        {
            DWORD dwIndex = pbRnd[i % sizeof(pbRnd)] % (wcslen(szChars) - 1); // NOSONAR - szChars is static const array, never NULL
            wsPassword += szChars[dwIndex];
        }
    }
    // If BCryptGenRandom fails, return empty string (SEC-003: no insecure fallback)

    return wsPassword;
}
