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
 *  CSV Logger Implementation
 *
 *  Thread-safe CSV logger with LSASS-safe design.
 */

#include "CSVLogger.h"
#include "Tracing.h"
#include "../EIDMigrate/Utils.h"
#include <string>
#include <cmath>

// ================================================================
// Static Member Initialization
// ================================================================
CRITICAL_SECTION EIDCSVLogger::s_csLogger;
BOOL EIDCSVLogger::s_csInitialized = FALSE;
HANDLE EIDCSVLogger::s_hLogFile = INVALID_HANDLE_VALUE;
EID_CSV_CONFIG EIDCSVLogger::s_config;
DWORD EIDCSVLogger::s_dwCurrentFileSize = 0;
WCHAR EIDCSVLogger::s_szCurrentLogPath[MAX_PATH] = {0};  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
BOOL EIDCSVLogger::s_fHeaderWritten = FALSE;

// ================================================================
// BUG 7: Thread-safe one-time creation of the logger critical section.
// Two concurrent first-logons (e.g. console + RDP) could both observe
// s_csInitialized == FALSE and call InitializeCriticalSection twice on the same
// object, corrupting the lock. INIT_ONCE serialises the creation exactly once.
// The critical section is passed via the callback Parameter so the free callback
// needs no access to the private class members; s_csInitialized is then set by
// Initialize() itself (which has member access) purely for state consistency.
// ================================================================
static INIT_ONCE s_csLoggerInitOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK EIDCSVLoggerInitCriticalSection(PINIT_ONCE, PVOID Parameter, PVOID*)
{
    InitializeCriticalSection(static_cast<LPCRITICAL_SECTION>(Parameter));
    return TRUE;
}

// ================================================================
// Helper: Format Timestamp as ISO 8601
// ================================================================
void EIDCSVLogger::FormatTimestamp(WCHAR* pszBuffer, size_t cchBuffer)
{
    SYSTEMTIME st;
    GetSystemTime(&st);  // UTC time

    swprintf_s(pszBuffer, cchBuffer,
        L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

// ================================================================
// Helper: Check if event should be logged
// ================================================================
BOOL EIDCSVLogger::IsEventEnabled(EID_EVENT_ID eventId, EID_SEVERITY severity)
{
    // Check if logger is enabled
    if (!s_config.fEnabled)
        return FALSE;

    // Check verbose filter
    if (severity == EID_SEVERITY::VERBOSE && !s_config.fVerboseEvents)
        return FALSE;

    // Check category filter
    EID_EVENT_CATEGORY category = GetEventCategory(eventId);
    if (!IsCategoryEnabled(s_config.dwCategoryFilter, category))  // NOSONAR - SCOPE-01: declaration kept separate from if for readability
        return FALSE;

    return TRUE;
}

// ================================================================
// Helper: Write CSV Header
// ================================================================
void EIDCSVLogger::WriteCSVHeader()
{
    if (s_fHeaderWritten)
        return;

    WCHAR szHeader[2048];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    size_t offset = 0;
    EID_CSV_COLUMN cols = s_config.dwColumns;

    // Helper lambda to append field name
    auto appendField = [&szHeader, &offset](PCWSTR pwszName)  // NOSONAR - LSASS-01: C-style WCHAR buffer captured for LSASS safety
    {
        if (offset > 0)
            szHeader[offset++] = L',';
        size_t len = wcslen(pwszName);
        wcsncpy_s(szHeader + offset, _countof(szHeader) - offset, pwszName, _TRUNCATE);
        offset += len;
    };

    if (cols & EID_CSV_COLUMN::TIMESTAMP)    appendField(L"Timestamp");
    if (cols & EID_CSV_COLUMN::EVENT_ID)     appendField(L"EventID");
    if (cols & EID_CSV_COLUMN::CATEGORY)     appendField(L"Category");
    if (cols & EID_CSV_COLUMN::SEVERITY)     appendField(L"Severity");
    if (cols & EID_CSV_COLUMN::OUTCOME)      appendField(L"Outcome");
    if (cols & EID_CSV_COLUMN::USERNAME)     appendField(L"Username");
    if (cols & EID_CSV_COLUMN::DOMAIN)       appendField(L"Domain");
    if (cols & EID_CSV_COLUMN::CLIENT_IP)    appendField(L"SourceIP");
    if (cols & EID_CSV_COLUMN::ACTION)       appendField(L"Action");
    if (cols & EID_CSV_COLUMN::TARGET)     appendField(L"Resource");
    if (cols & EID_CSV_COLUMN::REASON)       appendField(L"Reason");
    if (cols & EID_CSV_COLUMN::LOGIN_SESSION)   appendField(L"SessionID");
    if (cols & EID_CSV_COLUMN::PROCESS_ID)   appendField(L"ProcessID");
    if (cols & EID_CSV_COLUMN::MESSAGE)      appendField(L"Message");

    szHeader[offset++] = L'\r';
    szHeader[offset++] = L'\n';
    szHeader[offset] = L'\0';

    // Write header
    DWORD dwWritten = 0;
    WriteFile(s_hLogFile, szHeader, static_cast<DWORD>(offset * sizeof(WCHAR)), &dwWritten, nullptr);
    s_dwCurrentFileSize += dwWritten;
    s_fHeaderWritten = TRUE;
}

// ================================================================
// Helper: Rotate Log File
// ================================================================
void EIDCSVLogger::RotateLogFile()
{
    // Close current file
    if (s_hLogFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(s_hLogFile);
        s_hLogFile = INVALID_HANDLE_VALUE;
    }

    // Rotation renames and deletes files as SYSTEM. Re-verify, right before doing so, that
    // the log directory (and the product directory above it) is a real directory owned by
    // SYSTEM/Administrators - not a junction a user planted or swapped in - otherwise the
    // MoveFileExW/DeleteFileW below would act on whatever the junction points at.
    if (!EID_IsLogDirSafeForRotation(s_szCurrentLogPath))
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,
            L"[CONFIG_REJECT] log directory is a reparse point or not owned by SYSTEM/Administrators; CSV file logging disabled");
        s_config.fEnabled = FALSE;
        return;
    }

    // Shift the generations, newest first: drop .NNN (N = file count), move
    // .(i-1) -> .i, then the live file -> .001 - the same scheme EIDTraceConsumer
    // uses. (The previous "first free slot" search never detected a full set,
    // because dwRotation started at 1, so once every slot existed each rotation
    // overwrote .001.) Every step is checked: if one fails, rotation stops there
    // and the live file is kept, rather than letting the next rename overwrite a
    // generation that could not be moved and lose audit history. Nothing below
    // replaces an existing file except the explicit delete of the oldest one.
    // Paths are built with _snwprintf_s/_TRUNCATE: swprintf_s fast-fails the
    // process (LSASS) when a path near MAX_PATH does not fit; on truncation the
    // rotation is skipped instead.
    WCHAR szRotatedPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    WCHAR szOldPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    const DWORD dwCount = s_config.dwFileCount ? s_config.dwFileCount : 1;
    BOOL fShifted = TRUE;
    BOOL fNeedShift = TRUE;

    // When .001 is free (a previous rotation shifted but could not rename the
    // live file) there is nothing to shift: do not drop another generation.
    if (_snwprintf_s(szRotatedPath, ARRAYSIZE(szRotatedPath), _TRUNCATE, L"%s.%03u", s_szCurrentLogPath, 1u) >= 0 &&
        GetFileAttributesW(szRotatedPath) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND)
    {
        fNeedShift = FALSE;
    }

    if (fNeedShift && _snwprintf_s(szRotatedPath, ARRAYSIZE(szRotatedPath), _TRUNCATE, L"%s.%03u", s_szCurrentLogPath, dwCount) < 0)
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"log path too long to rotate - rotation skipped");
        fShifted = FALSE;
    }
    else if (fNeedShift && !DeleteFileW(szRotatedPath) && GetLastError() != ERROR_FILE_NOT_FOUND)
    {
        EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"cannot delete oldest log generation (0x%08x) - rotation stopped", GetLastError());
        fShifted = FALSE;
    }

    // Count down from dwCount so a count of 1 runs no iteration and the loop
    // counter can never underflow. Shifts .00(i-1) -> .00i.
    for (DWORD i = dwCount; fNeedShift && fShifted && i > 1; i--)
    {
        if (_snwprintf_s(szOldPath, ARRAYSIZE(szOldPath), _TRUNCATE, L"%s.%03u", s_szCurrentLogPath, i - 1) < 0 ||
            _snwprintf_s(szRotatedPath, ARRAYSIZE(szRotatedPath), _TRUNCATE, L"%s.%03u", s_szCurrentLogPath, i) < 0)
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"log path too long to rotate - rotation skipped");
            fShifted = FALSE;
        }
        else if (!MoveFileExW(szOldPath, szRotatedPath, 0) && GetLastError() != ERROR_FILE_NOT_FOUND)
        {
            // A missing generation (gap) is fine; any other failure stops rotation.
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"cannot shift log generation %u (0x%08x) - rotation stopped", i - 1, GetLastError());
            fShifted = FALSE;
        }
    }

    // Rename the live file to .001. Only reset the state if the rename actually
    // happened. On failure the oversized file is still in place, so clearing
    // s_fHeaderWritten would append a second header row to it; EnsureLogFileOpen
    // re-reads the true size and rotation is retried on the next event.
    if (fShifted)
    {
        if (_snwprintf_s(szRotatedPath, ARRAYSIZE(szRotatedPath), _TRUNCATE, L"%s.%03u", s_szCurrentLogPath, 1u) < 0)
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"log path too long to rotate - rotation skipped");
        }
        else if (MoveFileExW(s_szCurrentLogPath, szRotatedPath, 0))
        {
            s_dwCurrentFileSize = 0;
            s_fHeaderWritten = FALSE;
        }
        else
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"cannot rename the live log (0x%08x) - rotation stopped", GetLastError());
        }
    }

    // Open new file
    EnsureLogFileOpen();
}

// ================================================================
// Helper: Ensure Log File is Open
// ================================================================
BOOL EIDCSVLogger::EnsureLogFileOpen()
{
    if (s_hLogFile != INVALID_HANDLE_VALUE)
        return TRUE;

    // Create directory if needed
    WCHAR szDir[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    wcscpy_s(szDir, s_szCurrentLogPath);
    WCHAR* pLastSlash = wcsrchr(szDir, L'\\');
    if (pLastSlash)  // NOSONAR - SCOPE-01: declaration kept separate from if for readability
    {
        *pLastSlash = L'\0';
        // M5: create the log directory with a restrictive DACL (Full to SYSTEM/Admins,
        // Read&Execute to Users), re-applying it if the directory already exists.
        // A directory that is a reparse point or not owned by SYSTEM/Administrators (e.g.
        // pre-created by an unprivileged user) is refused, not adopted: disable file
        // logging rather than write or rotate there.
        if (!EnsureLogDirSecured(szDir))
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,
                L"[CONFIG_REJECT] log directory is a reparse point or not owned by SYSTEM/Administrators; CSV file logging disabled");
            s_config.fEnabled = FALSE;
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }

    // Open file for append (UTF-16 LE encoding)
    // M5: FILE_FLAG_OPEN_REPARSE_POINT so a pre-planted symlink/junction at the
    // log path is opened as the reparse point (and fails) rather than followed.
    // BUG 4: LSASS and the LogonUI credential provider are SEPARATE processes both
    // emitting audit rows on the logon path. Open with FILE_APPEND_DATA (not
    // GENERIC_WRITE/FILE_WRITE_DATA) so every write atomically targets end-of-file,
    // and share FILE_SHARE_READ | FILE_SHARE_WRITE so the second process no longer
    // fails CreateFileW with ERROR_SHARING_VIOLATION and silently drops its audits.
    // FILE_READ_ATTRIBUTES is added so GetFileSizeEx (used for rotation) still works
    // on the append-only handle without granting FILE_WRITE_DATA (which would defeat
    // the kernel's atomic-append guarantee).
    // FILE_SHARE_DELETE is required for rotation: renaming the active log opens it for
    // DELETE access, which fails with ERROR_SHARING_VIOLATION while the other process
    // still holds a handle without this flag - leaving events.csv to grow unbounded.
    s_hLogFile = CreateFileW(
        s_szCurrentLogPath,
        FILE_APPEND_DATA | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr
    );

    if (s_hLogFile == INVALID_HANDLE_VALUE)
        return FALSE;

    // Get current file size
    LARGE_INTEGER liSize;
    if (GetFileSizeEx(s_hLogFile, &liSize))  // NOSONAR - SCOPE-01: declaration kept separate from if for readability
    {
        s_dwCurrentFileSize = static_cast<DWORD>(liSize.QuadPart);
    }

    // Seek to end for append
    SetFilePointer(s_hLogFile, 0, nullptr, FILE_END);

    // Check if file is empty and needs header
    if (s_dwCurrentFileSize == 0)
    {
        // Write UTF-16 LE BOM
        DWORD dwWritten = 0;
        WORD wBOM = 0xFEFF;
        WriteFile(s_hLogFile, &wBOM, sizeof(WORD), &dwWritten, nullptr);
        s_dwCurrentFileSize += dwWritten;

        WriteCSVHeader();
    }

    return TRUE;
}

// ================================================================
// Initialize Logger
// ================================================================
HRESULT EIDCSVLogger::Initialize(const EID_CSV_CONFIG& config)
{
    // BUG 7: create the critical section exactly once, even under concurrent
    // first-logons, via INIT_ONCE (LSASS-safe; no DllMain / loader-lock work).
    InitOnceExecuteOnce(&s_csLoggerInitOnce, EIDCSVLoggerInitCriticalSection, &s_csLogger, nullptr);
    s_csInitialized = TRUE;

    EnterCriticalSection(&s_csLogger);

    __try
    {
        // Store configuration
        s_config = config;

        // Close existing file if open
        if (s_hLogFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(s_hLogFile);
            s_hLogFile = INVALID_HANDLE_VALUE;
        }

        // If logging disabled, we're done
        if (!config.fEnabled)
            return S_OK;

        // Set log path
        if (config.szLogPath[0] != L'\0')
        {
            wcscpy_s(s_szCurrentLogPath, config.szLogPath);
        }
        else
        {
            wcscpy_s(s_szCurrentLogPath, EID_CSV_DEFAULT_LOG_PATH);
        }

        // Reset state
        s_dwCurrentFileSize = 0;
        s_fHeaderWritten = FALSE;

        // Open log file
        if (!EnsureLogFileOpen())
        {
            return HRESULT_FROM_WIN32(GetLastError());
        }

        return S_OK;
    }
    __finally
    {
        LeaveCriticalSection(&s_csLogger);
    }
}

// ================================================================
// Shutdown Logger
// ================================================================
void EIDCSVLogger::Shutdown()
{
    EnterCriticalSection(&s_csLogger);

    __try
    {
        if (s_hLogFile != INVALID_HANDLE_VALUE)
        {
            FlushFileBuffers(s_hLogFile);
            CloseHandle(s_hLogFile);
            s_hLogFile = INVALID_HANDLE_VALUE;
        }

        s_dwCurrentFileSize = 0;
        s_fHeaderWritten = FALSE;
    }
    __finally
    {
        LeaveCriticalSection(&s_csLogger);
    }
}

// ================================================================
// Update Configuration
// ================================================================
HRESULT EIDCSVLogger::UpdateConfig(const EID_CSV_CONFIG& config)
{
    EnterCriticalSection(&s_csLogger);

    __try
    {
        s_config = config;

        // If logging was disabled and now enabled, open file
        if (config.fEnabled && s_hLogFile == INVALID_HANDLE_VALUE)
        {
            wcscpy_s(s_szCurrentLogPath, config.szLogPath[0] ? config.szLogPath : EID_CSV_DEFAULT_LOG_PATH);
            s_dwCurrentFileSize = 0;
            s_fHeaderWritten = FALSE;
            if (!EnsureLogFileOpen())
                return HRESULT_FROM_WIN32(GetLastError());
        }
        // If logging was enabled and now disabled, close file
        else if (!config.fEnabled && s_hLogFile != INVALID_HANDLE_VALUE)
        {
            FlushFileBuffers(s_hLogFile);
            CloseHandle(s_hLogFile);
            s_hLogFile = INVALID_HANDLE_VALUE;
        }

        return S_OK;
    }
    __finally
    {
        LeaveCriticalSection(&s_csLogger);
    }
}

// ================================================================
// Get Current Configuration
// ================================================================
EID_CSV_CONFIG EIDCSVLogger::GetConfig()
{
    EnterCriticalSection(&s_csLogger);
    EID_CSV_CONFIG config = s_config;
    LeaveCriticalSection(&s_csLogger);
    return config;
}

// ================================================================
// Check if Enabled
// ================================================================
BOOL EIDCSVLogger::IsEnabled()
{
    return s_config.fEnabled && s_hLogFile != INVALID_HANDLE_VALUE;
}

// ================================================================
// Core Logging Function
// ================================================================
void EIDCSVLogger::LogEvent(  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    EID_EVENT_ID eventId,
    EID_SEVERITY severity,
    EID_OUTCOME outcome,
    PCWSTR pwszUsername,
    PCWSTR pwszAction,
    PCWSTR pwszMessage,
    PCWSTR pwszDomain,
    PCWSTR pwszSourceIP,
    DWORD dwProcessID,
    [[maybe_unused]] DWORD dwThreadID,
    DWORD dwSessionID,
    PCWSTR pwszResource,
    PCWSTR pwszReason)
{
    // Check if event should be logged
    if (!IsEventEnabled(eventId, severity))
        return;

    EnterCriticalSection(&s_csLogger);

    __try
    {
        // Ensure file is open
        if (!EnsureLogFileOpen())
            __leave;

        // Check file rotation
        ULONGLONG ullMaxBytes = static_cast<ULONGLONG>(s_config.dwMaxFileSizeMB) * 1024 * 1024;
        if (s_dwCurrentFileSize >= ullMaxBytes)  // NOSONAR - SCOPE-01: declaration kept separate from if for readability
        {
            RotateLogFile();
            if (!EnsureLogFileOpen())
                __leave;
        }

        // Stack-allocated buffer for building log line
        WCHAR szBuffer[4096];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
        DWORD dwWritten = 0;
        EID_CSV_COLUMN cols = s_config.dwColumns;
        BOOL fFirstField = TRUE;

        // BUG 4: single write-cap for the whole row. All field appends stay at or
        // below dwCap so the trailing CRLF (2 WCHAR) always fits. Attacker-influenced
        // audit fields (e.g. an oversized certificate subject/SAN) can drive dwWritten
        // to the buffer end, so every append below is bounds-checked against dwCap.
        const DWORD dwCap = _countof(szBuffer) - 2;  // reserve room for trailing CRLF

        // Helper lambda to write field with comma separator (bounds-checked)
        auto writeField = [&szBuffer, &dwWritten, &fFirstField, dwCap]([[maybe_unused]] PCWSTR pwszValue)  // NOSONAR - LSASS-01: C-style WCHAR buffer captured for LSASS safety
        {
            if (!fFirstField)
            {
                if (dwWritten < dwCap)
                    szBuffer[dwWritten++] = L',';
            }
            else
                fFirstField = FALSE;
            return dwWritten;
        };

        // BUG 4: append an escaped CSV field directly into szBuffer (instead of a
        // separate WriteFile per field) so the whole row can be emitted with ONE
        // WriteFile and stays atomic across the LSASS/LogonUI processes. This replaced
        // the old per-field writer, which interleaved rows between the two processes.
        // Bounds-checked and reserves 2 WCHAR at the tail for the CRLF.
        auto appendEscapedField = [&szBuffer, &dwWritten, dwCap](PCWSTR pwszValue)  // NOSONAR - LSASS-01: C-style WCHAR buffer captured for LSASS safety
        {
            if (!pwszValue || !pwszValue[0])
                return;

            // Check if field needs quoting
            BOOL fNeedsQuotes = FALSE;
            for (PCWSTR p = pwszValue; *p; p++)
            {
                if (*p == L',' || *p == L'"' || *p == L'\n' || *p == L'\r')
                {
                    fNeedsQuotes = TRUE;
                    break;
                }
            }

            if (!fNeedsQuotes)
            {
                // No escaping needed, copy as-is
                for (PCWSTR p = pwszValue; *p && dwWritten < dwCap; p++)
                    szBuffer[dwWritten++] = *p;
                return;
            }

            // Needs escaping: wrap in quotes, double inner quotes
            if (dwWritten < dwCap) szBuffer[dwWritten++] = L'"';
            for (PCWSTR p = pwszValue; *p; p++)
            {
                if (*p == L'"')
                {
                    if (dwWritten < dwCap) szBuffer[dwWritten++] = L'"';
                    if (dwWritten < dwCap) szBuffer[dwWritten++] = L'"';
                }
                else
                {
                    if (dwWritten < dwCap) szBuffer[dwWritten++] = *p;
                }
            }
            if (dwWritten < dwCap) szBuffer[dwWritten++] = L'"';
        };

        // BUG 4: truncate-safe formatted append for the numeric/name columns.
        // Plain swprintf_s invokes the CRT invalid-parameter handler when the count
        // argument is too small (buffer nearly full) — fatal in LSASS. _snwprintf_s
        // with _TRUNCATE instead truncates and returns -1 without aborting; we then
        // advance by the actual chars written so dwWritten never exceeds _countof-1.
        auto appendFormatted = [&szBuffer, &dwWritten, dwCap](PCWSTR pwszFormat, auto value)  // NOSONAR - LSASS-01: C-style WCHAR buffer captured for LSASS safety
        {
            if (dwWritten >= dwCap)
                return;
            size_t rem = _countof(szBuffer) - dwWritten;
            int written = _snwprintf_s(szBuffer + dwWritten, rem, _TRUNCATE, pwszFormat, value);
            if (written < 0)
                dwWritten += static_cast<DWORD>(wcslen(szBuffer + dwWritten));  // truncated: advance by actual
            else
                dwWritten += static_cast<DWORD>(written);
        };

        // Timestamp
        if (cols & EID_CSV_COLUMN::TIMESTAMP)
        {
            writeField(L"");
            if (dwWritten < dwCap)
            {
                FormatTimestamp(szBuffer + dwWritten, _countof(szBuffer) - dwWritten);
                dwWritten += static_cast<DWORD>(wcslen(szBuffer + dwWritten));
            }
        }

        // Event ID
        if (cols & EID_CSV_COLUMN::EVENT_ID)
        {
            writeField(L"");
            appendFormatted(L"%u", static_cast<DWORD>(eventId));  // NOSONAR - ENUM-01: enum cast to underlying value for format API
        }

        // Category
        if (cols & EID_CSV_COLUMN::CATEGORY)
        {
            writeField(L"");
            PCWSTR pwszCategory = GetCategoryName(GetEventCategory(eventId));
            appendFormatted(L"%s", pwszCategory);
        }

        // Severity
        if (cols & EID_CSV_COLUMN::SEVERITY)
        {
            writeField(L"");
            appendFormatted(L"%s", GetSeverityName(static_cast<UCHAR>(severity)));  // NOSONAR - ENUM-01: enum cast to underlying value for Win32 API
        }

        // Outcome
        if (cols & EID_CSV_COLUMN::OUTCOME)
        {
            writeField(L"");
            appendFormatted(L"%s", GetOutcomeName(static_cast<UCHAR>(outcome)));  // NOSONAR - ENUM-01: enum cast to underlying value for Win32 API
        }

        // Username
        if (cols & EID_CSV_COLUMN::USERNAME)
        {
            writeField(L"");
            appendEscapedField(pwszUsername ? pwszUsername : L"");
        }

        // Domain
        if (cols & EID_CSV_COLUMN::DOMAIN)
        {
            writeField(L"");
            appendEscapedField(pwszDomain);
        }

        // Source IP
        if (cols & EID_CSV_COLUMN::CLIENT_IP)
        {
            writeField(L"");
            appendEscapedField(pwszSourceIP);
        }

        // Action
        if (cols & EID_CSV_COLUMN::ACTION)
        {
            writeField(L"");
            appendEscapedField(pwszAction ? pwszAction : L"");
        }

        // Resource
        if (cols & EID_CSV_COLUMN::TARGET)
        {
            writeField(L"");
            appendEscapedField(pwszResource);
        }

        // Reason
        if (cols & EID_CSV_COLUMN::REASON)
        {
            writeField(L"");
            appendEscapedField(pwszReason);
        }

        // Session ID
        if (cols & EID_CSV_COLUMN::LOGIN_SESSION)
        {
            writeField(L"");
            appendFormatted(L"%u", dwSessionID);
        }

        // Process ID
        if (cols & EID_CSV_COLUMN::PROCESS_ID)
        {
            writeField(L"");
            appendFormatted(L"%u", dwProcessID ? dwProcessID : GetCurrentProcessId());
        }

        // Message
        if (cols & EID_CSV_COLUMN::MESSAGE)
        {
            writeField(L"");
            appendEscapedField(pwszMessage ? pwszMessage : L"");
        }

        // BUG 4: terminate the row and emit it with a SINGLE WriteFile so that on
        // local NTFS the append (< 64KB) is atomic and audit rows from the LSASS
        // and LogonUI processes never interleave or get dropped. appendEscapedField
        // reserved 2 WCHAR for the CRLF; clamp defensively in case numeric fields
        // filled the buffer, so a well-formed row is always written.
        if (dwWritten > _countof(szBuffer) - 2)
            dwWritten = _countof(szBuffer) - 2;
        szBuffer[dwWritten++] = L'\r';
        szBuffer[dwWritten++] = L'\n';

        if (WriteFile(s_hLogFile, szBuffer, dwWritten * sizeof(WCHAR), &dwWritten, nullptr))
            s_dwCurrentFileSize += dwWritten;

        // Flush for immediate visibility (optional, can be disabled for performance)
        // FlushFileBuffers(s_hLogFile);
    }
    __finally
    {
        LeaveCriticalSection(&s_csLogger);
    }
}

// ================================================================
// Convenience: Log Success
// ================================================================
void EIDCSVLogger::LogSuccess(EID_EVENT_ID eventId, PCWSTR pwszAction, PCWSTR pwszMessage)
{
    LogEvent(eventId, EID_SEVERITY::INFO, EID_OUTCOME::SUCCESS,
        nullptr, pwszAction, pwszMessage);
}

// ================================================================
// Convenience: Log Failure
// Note: Uses WARNING severity by default. For actual errors, call LogEvent directly with ERROR.
// ================================================================
void EIDCSVLogger::LogFailure(EID_EVENT_ID eventId, PCWSTR pwszAction, PCWSTR pwszReason)
{
    LogEvent(eventId, EID_SEVERITY::WARNING, EID_OUTCOME::FAILURE,
        nullptr, pwszAction, L"Failed", nullptr, nullptr, 0, 0, 0, nullptr, pwszReason);
}

// ================================================================
// Convenience: Log Auth Success
// ================================================================
void EIDCSVLogger::LogAuthSuccess(PCWSTR pwszUsername, PCWSTR pwszMessage)
{
    LogEvent(EID_EVENT_ID::AUTH_SUCCESS, EID_SEVERITY::INFO, EID_OUTCOME::SUCCESS,
        pwszUsername, L"Authentication", pwszMessage);
}

// ================================================================
// Convenience: Log Auth Failure
// Note: Authentication failures are logged at WARNING level, not ERROR.
// User entering wrong credentials is expected behavior, not a system error.
// ================================================================
void EIDCSVLogger::LogAuthFailure(PCWSTR pwszUsername, PCWSTR pwszReason)
{
    LogEvent(EID_EVENT_ID::AUTH_FAILURE, EID_SEVERITY::WARNING, EID_OUTCOME::FAILURE,
        pwszUsername, L"Authentication", L"Failed", nullptr, nullptr, 0, 0, 0, nullptr, pwszReason);
}

// ================================================================
// Flush Output
// ================================================================
void EIDCSVLogger::Flush()
{
    EnterCriticalSection(&s_csLogger);

    __try
    {
        if (s_hLogFile != INVALID_HANDLE_VALUE)
        {
            FlushFileBuffers(s_hLogFile);
        }
    }
    __finally
    {
        LeaveCriticalSection(&s_csLogger);
    }
}

// ================================================================
// Get Current File Size
// ================================================================
DWORD EIDCSVLogger::GetCurrentFileSize()
{
    EnterCriticalSection(&s_csLogger);
    DWORD dwSize = s_dwCurrentFileSize;
    LeaveCriticalSection(&s_csLogger);
    return dwSize;
}
