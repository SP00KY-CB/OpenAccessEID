/*
    OpenAccess EID - Smart card authentication for Windows
    Copyright (C) 2009 Vincent Le Toux
    Copyright (C) 2026 Contributors

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, see <https://www.gnu.org/licenses/>.
*/

/**
 *  CSV Configuration Implementation
 *
 *  JSON and Registry persistence for CSV logging configuration.
 */

#include "CSVConfig.h"
#include "Tracing.h"
#include "../EIDMigrate/JsonHelper.h"
#include "../EIDMigrate/Utils.h"

// DO NOT call EIDSecurityAudit (or anything else that reaches
// EIDCardLibraryLogStructured) from this file's config-loading path.
//
// EIDSecurityAuditEx -> EIDCardLibraryLogStructured -> InitOnceExecuteOnce on
// g_CSVInitOnce. That is the SAME one-time-init this code is running inside:
// EIDCardLibraryLogStructured -> InitOnce -> EIDCSVInitOnceCallback ->
// EID_CSV_Initialize -> EID_CSV_LoadConfig -> EID_CSV_LoadConfigFromFile.
// Re-entering InitOnceExecuteOnce from its own callback on the same thread
// deadlocks - inside LSASS, on the logon path.
//
// EIDCardLibraryTrace writes straight to ETW and is a leaf, so it is safe here
// and is what the rejection paths below use.
#include <fstream>
#include <filesystem>

namespace fs = std::experimental::filesystem;

// ================================================================
// Helper: Convert EID_CSV_CONFIG to JSON string
// ================================================================
std::string EID_CSV_ConfigToJson(const EID_CSV_CONFIG& config)
{
    JsonBuilder builder;

    builder.add("enabled", config.fEnabled != FALSE);

    // Convert wide strings to UTF-8
    std::string logPath = WideToUtf8(config.szLogPath);
    builder.add("logPath", logPath);

    builder.add("maxFileSizeMB", static_cast<int>(config.dwMaxFileSizeMB));
    builder.add("fileCount", static_cast<int>(config.dwFileCount));

    // Store column bitmask as integer
    builder.add("columns", static_cast<int>(config.dwColumns));  // NOSONAR - ENUM-01: explicit integral cast retained for serialization

    // Store category filter as integer
    builder.add("categoryFilter", static_cast<int>(config.dwCategoryFilter));

    builder.add("verboseEvents", config.fVerboseEvents != FALSE);

    builder.add("diagnosticsEnabled", config.fDiagnosticsEnabled != FALSE);
    builder.add("diagnosticsLevel", static_cast<int>(config.dwDiagnosticsLevel));

    return builder.build();
}

// ================================================================
// Helper: is a configured log path acceptable?
// ================================================================
// The log path drives an elevated operation: CSVLogger passes its directory to
// EnsureLogDirSecured, which rewrites that directory's DACL as SYSTEM with
// PROTECTED_DACL_SECURITY_INFORMATION - stripping inherited and TrustedInstaller
// ACEs - and SetNamedSecurityInfoW follows junctions. So an arbitrary path here
// is an arbitrary-directory ACL rewrite, not just an odd place to write a log.
//
// Constrain it to the product's own directory. Anything else - UNC, device
// namespace, drive-relative, or traversal - is refused and the default kept.
// The rules live in LogDirSecurity.h (EID_IsAcceptableLogPath), shared with the
// EIDTraceConsumer service, which reads the same registry and policy values.
static bool EID_CSV_IsAcceptableLogPath(const std::wstring& wsPath)
{
    return wsPath.length() < MAX_PATH && EID_IsAcceptableLogPath(wsPath.c_str());
}

// ================================================================
// Helper: Convert JSON string to EID_CSV_CONFIG
// ================================================================
HRESULT EID_CSV_JsonToConfig(const std::string& json, EID_CSV_CONFIG& config)
{
    JsonParser parser(json);
    auto pRoot = parser.parse();

    if (!pRoot || !pRoot->isObject())
        return E_INVALIDARG;

    const JsonObject& root = pRoot->asObject();

    // Initialize with defaults
    config = EID_CSV_CONFIG();

    // Typed member lookup: logging.json is untrusted input, and asBool() /
    // asNumber() / asString() on a value of another JSON type read a member
    // that type never set. A member of the wrong type is ignored (the default
    // is kept), exactly as if it were absent.
    auto member = [&root](const char* key, JsonType expected) -> const JsonValue*
    {
        if (!root.has(key))
            return nullptr;
        const std::shared_ptr<JsonValue>& pValue = root[key];
        if (!pValue || pValue->type() != expected)
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,
                L"[CONFIG_REJECT] logging.json member '%S' has the wrong type; ignored", key);
            return nullptr;
        }
        return pValue.get();
    };
    const JsonValue* pMember = nullptr;

    // Read enabled flag
    if ((pMember = member("enabled", JsonType::Boolean)) != nullptr)
        config.fEnabled = pMember->asBool() ? TRUE : FALSE;

    // Read log path.
    //
    // This is the least trusted of the four config sources - it is a file, and
    // on a machine where the config directory has not yet been secured a
    // standard user can create it. The path is not merely stored: CSVLogger
    // hands its directory to EnsureLogDirSecured, which calls
    // SetNamedSecurityInfoW with a PROTECTED DACL **as SYSTEM**, follows
    // junctions, and severs inheritance. A length check is not enough.
    if ((pMember = member("logPath", JsonType::String)) != nullptr)
    {
        std::string utf8Path = pMember->asString();
        std::wstring wpath = Utf8ToWide(utf8Path);
        if (!EID_CSV_IsAcceptableLogPath(wpath))
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,
                L"[CONFIG_REJECT] logging.json specified an unacceptable logPath; default retained");
        }
        else
        {
            wcscpy_s(config.szLogPath, wpath.c_str());
        }
    }

    // Read max file size.
    // asNumber() returns long long and is truncated to DWORD with no sign
    // check, so a negative value becomes an enormous positive one. The
    // registry, GPO and trace-consumer loaders all clamp these; this loader -
    // the only one parsing untrusted bytes - did not, which let
    // {"fileCount": -1} drive ~4.29 billion GetFileAttributesW calls inside
    // CSVLogger::RotateLogFile while holding s_csLogger, in LSASS, on the logon
    // path. Same bounds as the other three loaders.
    if ((pMember = member("maxFileSizeMB", JsonType::Number)) != nullptr)
    {
        const long long llValue = pMember->asNumber();
        config.dwMaxFileSizeMB = (llValue < 1) ? 1 : (llValue > 100 ? 100 : static_cast<DWORD>(llValue));
    }

    // Read file count
    if ((pMember = member("fileCount", JsonType::Number)) != nullptr)
    {
        const long long llValue = pMember->asNumber();
        config.dwFileCount = (llValue < 1) ? 1 : (llValue > 100 ? 100 : static_cast<DWORD>(llValue));
    }

    // Read columns bitmask
    if ((pMember = member("columns", JsonType::Number)) != nullptr)
        config.dwColumns = static_cast<EID_CSV_COLUMN>(static_cast<DWORD>(pMember->asNumber()));

    // Read category filter bitmask
    if ((pMember = member("categoryFilter", JsonType::Number)) != nullptr)
        config.dwCategoryFilter = static_cast<DWORD>(pMember->asNumber());

    // Read verbose events flag
    if ((pMember = member("verboseEvents", JsonType::Boolean)) != nullptr)
        config.fVerboseEvents = pMember->asBool() ? TRUE : FALSE;

    // Read diagnostics flags
    if ((pMember = member("diagnosticsEnabled", JsonType::Boolean)) != nullptr)
        config.fDiagnosticsEnabled = pMember->asBool() ? TRUE : FALSE;
    if ((pMember = member("diagnosticsLevel", JsonType::Number)) != nullptr)
        config.dwDiagnosticsLevel = static_cast<DWORD>(pMember->asNumber());

    return S_OK;
}

// ================================================================
// Load configuration from file
// ================================================================
// TRUE when no one but SYSTEM and Administrators may change the file: no allow ACE
// for any other SID carries a write, append, delete or permission-change right.
static bool EID_CSV_OnlyAdminsCanWrite(HANDLE hFile)
{
    PACL pDacl = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (GetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pDacl, nullptr, &pSD) != ERROR_SUCCESS)
    {
        return false;
    }
    // A NULL DACL grants everyone everything.
    bool fOnlyAdmins = (pDacl != nullptr);
    const ACCESS_MASK maskWrite = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
        DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    for (DWORD i = 0; fOnlyAdmins && i < pDacl->AceCount; i++)
    {
        PACE_HEADER pHeader = nullptr;
        if (!GetAce(pDacl, i, reinterpret_cast<LPVOID*>(&pHeader)) || !pHeader)
        {
            fOnlyAdmins = false;
            break;
        }
        if (pHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
        {
            continue;
        }
        const ACCESS_ALLOWED_ACE* pAce = reinterpret_cast<const ACCESS_ALLOWED_ACE*>(pHeader);
        PSID pSid = const_cast<PSID>(static_cast<const void*>(&pAce->SidStart));
        if ((pAce->Mask & maskWrite) != 0 &&
            !(IsValidSid(pSid) && (IsWellKnownSid(pSid, WinLocalSystemSid) || IsWellKnownSid(pSid, WinBuiltinAdministratorsSid))))
        {
            fOnlyAdmins = false;
        }
    }
    LocalFree(pSD);
    return fOnlyAdmins;
}

HRESULT EID_CSV_LoadConfigFromFile(PCWSTR pwszPath, EID_CSV_CONFIG& config)
{
    // Open once, without following links, and check and read through that one
    // handle: it is not a reparse point, it is owned by SYSTEM/Administrators, it
    // has a single link (a hard link to some user-writable file would pass the
    // owner check) and only SYSTEM/Administrators may write it. The file used to
    // be checked by path and then read by path.
    HANDLE hFile = CreateFileW(pwszPath, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        const DWORD dwError = GetLastError();
        return HRESULT_FROM_WIN32(dwError == ERROR_PATH_NOT_FOUND ? ERROR_FILE_NOT_FOUND : dwError);
    }

    std::string content;
    HRESULT hrRead = S_OK;
    BY_HANDLE_FILE_INFORMATION info = {};
    LARGE_INTEGER liSize = {};
    // logging.json is a few hundred bytes; refuse anything absurd.
    constexpr LONGLONG cbMaxConfig = 64 * 1024;
    if (!GetFileInformationByHandle(hFile, &info) || info.nNumberOfLinks != 1 ||
        !EID_IsAdminOwnedNonReparseHandle(hFile) || !EID_CSV_OnlyAdminsCanWrite(hFile))
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,
            L"[CONFIG_REJECT] logging.json is linked elsewhere, not owned by SYSTEM/Administrators, or writable by other users; ignored");
        hrRead = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }
    else if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart < 0 || liSize.QuadPart > cbMaxConfig)
    {
        hrRead = HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);
    }
    else
    {
        try
        {
            content.resize(static_cast<size_t>(liSize.QuadPart));
        }
        catch (...)  // NOSONAR - EXCEPTION-01: catch-all is intentional guard
        {
            hrRead = E_OUTOFMEMORY;
        }
        DWORD cbRead = 0;
        if (SUCCEEDED(hrRead) && !content.empty() &&
            (!ReadFile(hFile, content.data(), static_cast<DWORD>(content.size()), &cbRead, nullptr) || cbRead != content.size()))
        {
            hrRead = E_FAIL;
        }
    }
    CloseHandle(hFile);
    if (FAILED(hrRead))
        return hrRead;

    // Parse JSON.
    //
    // This MUST NOT be allowed to throw. JsonParser reports malformed input by
    // throwing std::runtime_error, and this function is reached inside the LSA
    // package: EIDCardLibraryLogStructured -> InitOnceExecuteOnce ->
    // EIDCSVInitOnceCallback -> EID_CSV_Initialize -> EID_CSV_LoadConfig ->
    // here. An exception escaping an InitOnce callback in LSASS is a process
    // crash, and the read above was already guarded while the parse - the part
    // that actually parses untrusted bytes - was not.
    //
    // Falling back to the default configuration is the right failure mode:
    // logging configuration is not security policy, and refusing to start the
    // logger is strictly worse than starting it with defaults.
    try
    {
        return EID_CSV_JsonToConfig(content, config);
    }
    catch (const std::exception&)  // NOSONAR - EXCEPTION-01: must not escape into LSASS
    {
        // Leave a breadcrumb. Swapping a throw for a quiet fallback is right -
        // an exception escaping an InitOnce callback in LSASS is a crash - but
        // silently degrading the logging configuration on malformed input, with
        // no record of it, makes a corrupt file indistinguishable from a tampered
        // one. ETW only: see the re-entrancy note at the top of this file.
        EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,
            L"[CONFIG_REJECT] logging.json failed to parse; falling back to registry/default configuration");
        return E_FAIL;
    }
    catch (...)  // NOSONAR - EXCEPTION-01: must not escape into LSASS
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,
            L"[CONFIG_REJECT] logging.json raised a non-standard exception; falling back to registry/default configuration");
        return E_FAIL;
    }
}

// ================================================================
// Save configuration to file
// ================================================================
HRESULT EID_CSV_SaveConfigToFile(PCWSTR pwszPath, const EID_CSV_CONFIG& config)
{
    // Ensure directory exists
    std::wstring wpath(pwszPath);
    size_t lastSlash = wpath.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos)  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
    {
        std::wstring dir = wpath.substr(0, lastSlash);
        // M5: create the config directory with a restrictive DACL (Full to SYSTEM/Admins,
        // Read&Execute to Users), re-applying it if the directory already exists. Refuse
        // to write into a directory that is a reparse point or not admin/SYSTEM-owned.
        if (!EnsureLogDirSecured(dir.c_str()))
            return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }

    // Convert to JSON
    std::string json = EID_CSV_ConfigToJson(config);

    // Write to file
    std::string utf8Path = WideToUtf8(wpath);
    std::ofstream file(utf8Path, std::ios::binary | std::ios::trunc);
    if (!file.is_open())
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

    try
    {
        file.write(json.c_str(), json.size());
    }
    catch (...)  // NOSONAR - EXCEPTION-01: catch-all is intentional guard
    {
        file.close();
        return E_FAIL;
    }
    file.close();

    // The loader only honours a logging.json owned by SYSTEM or Administrators. An
    // elevated writer's default owner may be its own user SID, so hand the file to
    // Administrators explicitly (best effort; the loader rejects it otherwise).
    BYTE adminSid[SECURITY_MAX_SID_SIZE];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    DWORD cbAdminSid = sizeof(adminSid);
    if (CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid, &cbAdminSid))
    {
        SetNamedSecurityInfoW(const_cast<PWSTR>(pwszPath), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION, adminSid, nullptr, nullptr, nullptr);
    }

    return S_OK;
}

// ================================================================
// Load configuration from registry
// ================================================================
HRESULT EID_CSV_LoadConfigFromRegistry(EID_CSV_CONFIG& config)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    HKEY hKey = nullptr;
    LONG err = 0;
    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - Explicit type preferred for clarity
    DWORD dwType = 0;
    DWORD dwSize = 0;

    // Initialize with defaults
    config = EID_CSV_CONFIG();

    __try
    {
        err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, EID_CSV_CONFIG_KEY, 0, KEY_READ, &hKey);
        if (err != ERROR_SUCCESS)
        {
            // Key doesn't exist, use defaults
            // Set default log path
            wcscpy_s(config.szLogPath, EID_CSV_DEFAULT_LOG_PATH);
            __leave;
        }

        // Read CSVEnabled
        dwSize = sizeof(DWORD);
        DWORD dwValue = 0;
        err = RegQueryValueExW(hKey, L"CSVEnabled", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&dwValue), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err == ERROR_SUCCESS && dwType == REG_DWORD)
            config.fEnabled = dwValue ? TRUE : FALSE;

        // Read CSVLogPath
        dwSize = MAX_PATH * sizeof(WCHAR);
        err = RegQueryValueExW(hKey, L"CSVLogPath", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(config.szLogPath), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_SZ)
        {
            wcscpy_s(config.szLogPath, EID_CSV_DEFAULT_LOG_PATH);
        }
        else
        {
            // REG_SZ is not guaranteed null-terminated; terminate within the buffer.
            DWORD cchPath = dwSize / sizeof(WCHAR);
            if (cchPath >= MAX_PATH) cchPath = MAX_PATH - 1;
            config.szLogPath[cchPath] = L'\0';
        }

        // Read CSVMaxFileSize
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"CSVMaxFileSize", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&config.dwMaxFileSizeMB), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_DWORD)
            config.dwMaxFileSizeMB = 64;
        // BUG 10: clamp to [1, 1024] MB - an unbounded value here is only a sizing knob, but
        // keep it in the same sane range as the override path / ETL trace config for consistency.
        if (config.dwMaxFileSizeMB < 1) config.dwMaxFileSizeMB = 1;
        if (config.dwMaxFileSizeMB > 1024) config.dwMaxFileSizeMB = 1024;

        // Read CSVFileCount
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"CSVFileCount", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&config.dwFileCount), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_DWORD)
            config.dwFileCount = 5;
        // BUG 10: clamp to [1, 100] - prevents a huge/zero value from driving a runaway
        // rotation loop in CSVLogger::RotateLogFile (DoS via misconfiguration).
        if (config.dwFileCount < 1) config.dwFileCount = 1;
        if (config.dwFileCount > 100) config.dwFileCount = 100;

        // Read CSVColumns
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"CSVColumns", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&config.dwColumns), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_DWORD)
            config.dwColumns = EID_CSV_PRESETS::STANDARD;

        // Read CSVCategoryFilter
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"CSVCategoryFilter", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&config.dwCategoryFilter), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_DWORD)
            config.dwCategoryFilter = 0x0000FFFF;

        // Read CSVVerbose
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"CSVVerbose", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&dwValue), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err == ERROR_SUCCESS && dwType == REG_DWORD)
            config.fVerboseEvents = dwValue ? TRUE : FALSE;

        // Read DiagnosticsEnabled
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"DiagnosticsEnabled", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&dwValue), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err == ERROR_SUCCESS && dwType == REG_DWORD)
            config.fDiagnosticsEnabled = dwValue ? TRUE : FALSE;

        // Read DiagnosticsLevel
        dwSize = sizeof(DWORD);
        err = RegQueryValueExW(hKey, L"DiagnosticsLevel", nullptr, &dwType,
            reinterpret_cast<LPBYTE>(&config.dwDiagnosticsLevel), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS || dwType != REG_DWORD)
            config.dwDiagnosticsLevel = 4; // WINEVENT_LEVEL_INFO
    }
    __finally
    {
        if (hKey != nullptr)
            RegCloseKey(hKey);
    }

    return hr;
}

// ================================================================
// Save configuration to registry
// ================================================================
HRESULT EID_CSV_SaveConfigToRegistry(const EID_CSV_CONFIG& config)
{
    HKEY hKey = nullptr;
    LONG err = 0;
    HRESULT hr = S_OK;  // NOSONAR (EXPLICIT-TYPE-03) - Explicit type preferred for clarity

    __try
    {
        err = RegCreateKeyExW(HKEY_LOCAL_MACHINE, EID_CSV_CONFIG_KEY, 0, nullptr,
            0, KEY_READ | KEY_WRITE, nullptr, &hKey, nullptr);
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        DWORD dwValue = config.fEnabled ? 1 : 0;
        err = RegSetValueExW(hKey, L"CSVEnabled", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&dwValue), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        err = RegSetValueExW(hKey, L"CSVLogPath", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(config.szLogPath),  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
            static_cast<DWORD>((wcslen(config.szLogPath) + 1) * sizeof(WCHAR)));
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        err = RegSetValueExW(hKey, L"CSVMaxFileSize", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&config.dwMaxFileSizeMB), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        err = RegSetValueExW(hKey, L"CSVFileCount", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&config.dwFileCount), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        err = RegSetValueExW(hKey, L"CSVColumns", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&config.dwColumns), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        err = RegSetValueExW(hKey, L"CSVCategoryFilter", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&config.dwCategoryFilter), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        dwValue = config.fVerboseEvents ? 1 : 0;
        err = RegSetValueExW(hKey, L"CSVVerbose", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&dwValue), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(err);
            __leave;
        }

        dwValue = config.fDiagnosticsEnabled ? 1 : 0;
        err = RegSetValueExW(hKey, L"DiagnosticsEnabled", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&dwValue), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS) { hr = HRESULT_FROM_WIN32(err); __leave; }

        err = RegSetValueExW(hKey, L"DiagnosticsLevel", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&config.dwDiagnosticsLevel), sizeof(DWORD));  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        if (err != ERROR_SUCCESS) { hr = HRESULT_FROM_WIN32(err); __leave; }
    }
    __finally
    {
        if (hKey != nullptr)
            RegCloseKey(hKey);
    }

    return hr;
}

// ================================================================
// Apply Group Policy overrides (HKLM\SOFTWARE\Policies\OpenAccessEID\LogManager)
// Any value present under the policy key wins over local file/registry config.
// ================================================================
void EID_CSV_ApplyPolicyOverrides(EID_CSV_CONFIG& config)  // NOSONAR - COMPLEXITY-01: sequential per-value overrides, logic verified
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, EID_CSV_POLICY_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    DWORD dwType = 0;
    DWORD dwValue = 0;
    DWORD dwSize = 0;

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVEnabled", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.fEnabled = (dwValue != 0);

    WCHAR szPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    dwSize = sizeof(szPath);
    if (RegQueryValueExW(hKey, L"CSVLogPath", nullptr, &dwType, reinterpret_cast<LPBYTE>(szPath), &dwSize) == ERROR_SUCCESS && dwType == REG_SZ && szPath[0] != L'\0')
    {
        szPath[MAX_PATH - 1] = L'\0';
        wcscpy_s(config.szLogPath, szPath);
    }

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVMaxFileSize", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
    {
        // BUG 10: clamp policy-supplied value to [1, 1024] MB instead of taking it verbatim -
        // matches the bounds used by the ETL trace path (Registration.cpp SetTraceConfig).
        if (dwValue < 1) dwValue = 1;
        if (dwValue > 1024) dwValue = 1024;
        config.dwMaxFileSizeMB = dwValue;
    }

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVFileCount", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
    {
        // BUG 10: clamp policy-supplied value to [1, 100] - an unclamped admin-set
        // CSVFileCount (e.g. 0xFFFFFFFF) would drive a ~4-billion-iteration rotation loop
        // in CSVLogger::RotateLogFile (DoS via misconfiguration).
        if (dwValue < 1) dwValue = 1;
        if (dwValue > 100) dwValue = 100;
        config.dwFileCount = dwValue;
    }

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVColumns", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.dwColumns = static_cast<EID_CSV_COLUMN>(dwValue);  // NOSONAR - ENUM-01: enum cast retained for Win32/ABI compatibility

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVCategoryFilter", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.dwCategoryFilter = dwValue;

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"CSVVerbose", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.fVerboseEvents = (dwValue != 0);

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"DiagnosticsEnabled", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.fDiagnosticsEnabled = (dwValue != 0);

    dwSize = sizeof(dwValue);
    if (RegQueryValueExW(hKey, L"DiagnosticsLevel", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwValue), &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        config.dwDiagnosticsLevel = dwValue;

    RegCloseKey(hKey);
}

// ================================================================
// Load configuration (tries JSON, then registry, then defaults; GPO overrides win)
// ================================================================
HRESULT EID_CSV_LoadConfig(EID_CSV_CONFIG& config)
{
    // Try JSON file first, then registry, then defaults.
    //
    // logging.json is only honoured when both the file and its directory are owned by
    // SYSTEM or Administrators and neither is a reparse point. C:\ProgramData lets any
    // user create C:\ProgramData\OpenAccessEID before the installer does; trusting a
    // file there would let them steer this SYSTEM logger. ETW-only rejection: see the
    // re-entrancy note at the top of this file.
    HRESULT hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    if (GetFileAttributesW(EID_CSV_CONFIG_PATH) != INVALID_FILE_ATTRIBUTES)
    {
        if (EID_IsAdminOwnedNonReparse(EID_CSV_CONFIG_DIR) &&
            EID_IsAdminOwnedNonReparse(EID_CSV_CONFIG_PATH))
        {
            hr = EID_CSV_LoadConfigFromFile(EID_CSV_CONFIG_PATH, config);
        }
        else
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,
                L"[CONFIG_REJECT] logging.json or its directory is a reparse point or not owned by SYSTEM/Administrators; ignored, falling back to registry/default configuration");
            hr = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        }
    }
    if (FAILED(hr))
        hr = EID_CSV_LoadConfigFromRegistry(config);
    if (FAILED(hr))
    {
        config = EID_CSV_CONFIG();
        wcscpy_s(config.szLogPath, EID_CSV_DEFAULT_LOG_PATH);
        hr = S_FALSE;  // Indicate defaults were used
    }

    // Group Policy overrides win over local file/registry config.
    EID_CSV_ApplyPolicyOverrides(config);

    // The log path decides which directory a SYSTEM writer re-secures, renames in
    // and deletes from. Only logging.json used to be held to the product directory;
    // a CSVLogPath from the registry or from policy is held to it too.
    if (config.szLogPath[0] != L'\0' && !EID_CSV_IsAcceptableLogPath(std::wstring(config.szLogPath)))
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,
            L"[CONFIG_REJECT] CSVLogPath is not inside %s; using the default log path", EID_CSV_CONFIG_DIR);
        wcscpy_s(config.szLogPath, EID_CSV_DEFAULT_LOG_PATH);
    }
    return hr;
}

// ================================================================
// Save configuration (saves to both JSON and registry)
// ================================================================
HRESULT EID_CSV_SaveConfig(const EID_CSV_CONFIG& config)
{
    HRESULT hrJson = EID_CSV_SaveConfigToFile(EID_CSV_CONFIG_PATH, config);
    HRESULT hrReg = EID_CSV_SaveConfigToRegistry(config);

    // Both stores must succeed: the JSON file feeds EID_CSV_LoadConfig (the in-process
    // logger and the log manager UI), while the registry feeds the EIDTraceConsumer
    // service. If either write fails the config is only partly applied, so report the
    // first failure instead of a false success.
    if (FAILED(hrJson)) return hrJson;
    if (FAILED(hrReg)) return hrReg;
    return S_OK;
}
