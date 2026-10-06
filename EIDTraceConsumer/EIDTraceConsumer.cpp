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
 *  EID Trace Consumer Service
 *
 *  Windows service that consumes EID ETW events and writes them to CSV.
 */

#include <Windows.h>
#include <tdh.h>
#include <evntrace.h>
#include <evntprov.h>
#include <strsafe.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdio.h>

// ================================================================
// BUG 10: rotation bounds. RotateDiagFile counts down from the file count, so an
// unclamped registry/policy value (e.g. 0xFFFFFFFF) drives a ~4-billion-iteration
// rename loop in this LocalSystem service. Ranges match EIDCardLibrary/CSVConfig.cpp;
// duplicated here because this project intentionally has no EIDCardLibrary include path.
// ================================================================
static DWORD ClampFileCount(DWORD dwValue)
{
    if (dwValue < 1) return 1;
    if (dwValue > 100) return 100;
    return dwValue;
}

static DWORD ClampMaxFileSizeMB(DWORD dwValue)
{
    if (dwValue < 1) return 1;
    if (dwValue > 1024) return 1024;
    return dwValue;
}

// Directory-trust helpers (EnsureLogDirSecured, EID_IsLogDirSafeForRotation, ...) are
// shared with the LSASS-side logger rather than duplicated here.
#include "../EIDCardLibrary/LogDirSecurity.h"

// Service name and display name
#define SERVICE_NAME             L"EIDTraceConsumer"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define SERVICE_DISPLAY_NAME      L"EID Trace Consumer"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define SERVICE_DESCRIPTION       L"Consumes EID authentication events and writes to CSV log files"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use

// ETW Provider GUID for EID Credential Provider
// {B4866A0A-DB08-4835-A26F-414B46F3244C}
static const GUID EID_PROVIDER_GUID =
    {0xB4866A0A, 0xDB08, 0x4835, {0xA2, 0x6F, 0x41, 0x4B, 0x46, 0xF3, 0x24, 0x4C}};

// Service status handle
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;  // NOSONAR - GLOBAL-01: pointer assigned at runtime
SERVICE_STATUS g_ServiceStatus = {0};  // NOSONAR - GLOBAL-01: runtime-mutable service state

// Name of the real-time ETW session this service creates and consumes from.
#define EID_SESSION_NAME          L"EIDTraceConsumer"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use

// Event trace consumer handle (OpenTrace) and the real-time session handle (StartTrace).
// The consumer must create its own session and enable the EID provider on it - otherwise
// OpenTrace(EID_SESSION_NAME) has no session to attach to and the CSV stays empty.
TRACEHANDLE gTraceHandle = 0;  // NOSONAR - GLOBAL-01: handle assigned at runtime
TRACEHANDLE g_hSession = 0;  // NOSONAR - GLOBAL-01: handle assigned at runtime
BOOL g_ServiceRunning = TRUE;  // NOSONAR - GLOBAL-01: runtime-mutable service state
HANDLE g_StopEvent = nullptr;  // NOSONAR - GLOBAL-01: handle assigned at runtime

// Registry key for configuration
#define EID_CSV_CONFIG_KEY L"SOFTWARE\\OpenAccessEID\\LogManager"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
// Group Policy key: values here override the local config (ADMX-managed).
#define EID_CSV_POLICY_KEY L"SOFTWARE\\Policies\\OpenAccessEID\\LogManager"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use

// CSV log file handle and state
WCHAR g_szCsvPath[MAX_PATH] = {0};  // NOSONAR - GLOBAL-01: runtime-mutable C-style path buffer
BOOL g_fCsvEnabled = FALSE;  // NOSONAR - GLOBAL-01: runtime-mutable service state

// Diagnostics (free-text provider traces) capture
HANDLE g_hDiagFile = INVALID_HANDLE_VALUE;  // NOSONAR - GLOBAL-01: handle assigned at runtime
WCHAR  g_szDiagPath[MAX_PATH] = {0};  // NOSONAR - GLOBAL-01: runtime-mutable C-style path buffer
DWORD  g_dwDiagFileSize = 0;  // NOSONAR - GLOBAL-01: runtime-mutable service state
BOOL   g_fDiagnosticsEnabled = FALSE;  // NOSONAR - GLOBAL-01: runtime-mutable service state
DWORD  g_dwDiagnosticsLevel = 4; // NOSONAR - GLOBAL-01: runtime-mutable; WINEVENT_LEVEL_INFO

// Configuration
DWORD g_dwMaxFileSizeMB = 64;  // NOSONAR - GLOBAL-01: runtime-mutable service state
DWORD g_dwFileCount = 5;  // NOSONAR - GLOBAL-01: runtime-mutable service state

// Forward declarations
VOID WINAPI ServiceMain(DWORD dwArgc, LPWSTR *lpszArgv);
DWORD WINAPI ServiceCtrlHandlerEx(DWORD dwCtrl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);
DWORD ServiceInit(DWORD dwArgc, LPWSTR *lpszArgv);
VOID ReportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
DWORD ServiceWorkerThread(LPVOID lpParam);

BOOL InstallService();
BOOL UninstallService();
BOOL StartServiceWrapper();
BOOL StopServiceWrapper();

// Real-time ETW session lifecycle (the session the consumer reads from)
BOOL CreateRealtimeSession();
void StopRealtimeSession();

// Configuration and diagnostics file management
BOOL LoadCsvConfiguration();
BOOL EnsureDiagFileOpen();
void WriteDiagnosticLine(const WCHAR* timestamp, const WCHAR* severity, DWORD dwProcessId, const WCHAR* message);
void RotateDiagFile();
void CloseDiagFile();

// ================================================================
// Configuration Loading
// ================================================================
BOOL LoadCsvConfiguration()
{
    HKEY hKey = nullptr;
    LONG err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, EID_CSV_CONFIG_KEY, 0, KEY_READ, &hKey);
    if (err != ERROR_SUCCESS)
    {
        wprintf(L"CSV logging: Config key not found, using defaults\n");
        g_fCsvEnabled = FALSE;
        return FALSE;
    }

    // Read CSVEnabled flag
    DWORD dwEnabled = 0;
    DWORD dwSize = sizeof(dwEnabled);
    err = RegQueryValueExW(hKey, L"CSVEnabled", nullptr, nullptr,
                          reinterpret_cast<LPBYTE>(&dwEnabled), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
    if (err == ERROR_SUCCESS)
    {
        g_fCsvEnabled = (dwEnabled != 0);
    }

    // Read CSV log path
    dwSize = sizeof(g_szCsvPath);
    err = RegQueryValueExW(hKey, L"CSVLogPath", nullptr, nullptr,
                          reinterpret_cast<LPBYTE>(g_szCsvPath), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
    if (err != ERROR_SUCCESS || g_szCsvPath[0] == L'\0')
    {
        wcscpy_s(g_szCsvPath, L"C:\\ProgramData\\OpenAccessEID\\logs\\events.csv");
    }

    // Read max file size
    dwSize = sizeof(g_dwMaxFileSizeMB);
    err = RegQueryValueExW(hKey, L"CSVMaxFileSize", nullptr, nullptr,
                          reinterpret_cast<LPBYTE>(&g_dwMaxFileSizeMB), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
    if (err != ERROR_SUCCESS)
    {
        g_dwMaxFileSizeMB = 64;
    }
    g_dwMaxFileSizeMB = ClampMaxFileSizeMB(g_dwMaxFileSizeMB);

    // Read file count
    dwSize = sizeof(g_dwFileCount);
    err = RegQueryValueExW(hKey, L"CSVFileCount", nullptr, nullptr,
                          reinterpret_cast<LPBYTE>(&g_dwFileCount), &dwSize);  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
    if (err != ERROR_SUCCESS)
    {
        g_dwFileCount = 5;
    }
    g_dwFileCount = ClampFileCount(g_dwFileCount);

    // Read diagnostics settings
    DWORD dwDiag = 0;
    dwSize = sizeof(dwDiag);
    if (RegQueryValueExW(hKey, L"DiagnosticsEnabled", nullptr, nullptr,
            reinterpret_cast<LPBYTE>(&dwDiag), &dwSize) == ERROR_SUCCESS)  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        g_fDiagnosticsEnabled = (dwDiag != 0);

    dwSize = sizeof(g_dwDiagnosticsLevel);
    if (RegQueryValueExW(hKey, L"DiagnosticsLevel", nullptr, nullptr,
            reinterpret_cast<LPBYTE>(&g_dwDiagnosticsLevel), &dwSize) != ERROR_SUCCESS)  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        g_dwDiagnosticsLevel = 4;

    RegCloseKey(hKey);

    // Group Policy overrides (HKLM\SOFTWARE\Policies\OpenAccessEID\LogManager) win over the
    // local config for the values this service consumes.
    HKEY hPolicy = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, EID_CSV_POLICY_KEY, 0, KEY_READ, &hPolicy) == ERROR_SUCCESS)
    {
        DWORD dwType = 0;
        DWORD dw = 0;
        DWORD cb = sizeof(dw);
        if (RegQueryValueExW(hPolicy, L"CSVEnabled", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dw), &cb) == ERROR_SUCCESS && dwType == REG_DWORD)  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
            g_fCsvEnabled = (dw != 0);

        WCHAR szPolicyPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
        DWORD cbPath = sizeof(szPolicyPath);
        if (RegQueryValueExW(hPolicy, L"CSVLogPath", nullptr, &dwType, reinterpret_cast<LPBYTE>(szPolicyPath), &cbPath) == ERROR_SUCCESS && dwType == REG_SZ && szPolicyPath[0] != L'\0')  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
        {
            szPolicyPath[MAX_PATH - 1] = L'\0';
            wcscpy_s(g_szCsvPath, szPolicyPath);
        }

        cb = sizeof(dw);
        if (RegQueryValueExW(hPolicy, L"CSVMaxFileSize", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dw), &cb) == ERROR_SUCCESS && dwType == REG_DWORD)  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
            g_dwMaxFileSizeMB = ClampMaxFileSizeMB(dw);

        cb = sizeof(dw);
        if (RegQueryValueExW(hPolicy, L"CSVFileCount", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dw), &cb) == ERROR_SUCCESS && dwType == REG_DWORD)  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
            g_dwFileCount = ClampFileCount(dw);

        cb = sizeof(dw);
        if (RegQueryValueExW(hPolicy, L"DiagnosticsEnabled", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dw), &cb) == ERROR_SUCCESS && dwType == REG_DWORD)  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
            g_fDiagnosticsEnabled = (dw != 0);

        cb = sizeof(dw);
        if (RegQueryValueExW(hPolicy, L"DiagnosticsLevel", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dw), &cb) == ERROR_SUCCESS && dwType == REG_DWORD)  // NOSONAR - BYTE-01: BYTE buffer interops with Win32 API
            g_dwDiagnosticsLevel = dw;

        RegCloseKey(hPolicy);
    }

    wprintf(L"CSV logging: %s, Path: %s, MaxSize: %u MB, Files: %u\n",
            g_fCsvEnabled ? L"Enabled" : L"Disabled",
            g_szCsvPath, g_dwMaxFileSizeMB, g_dwFileCount);

    // diagnostics.log lives in the same directory as the CSV log
    wcscpy_s(g_szDiagPath, g_szCsvPath);
    WCHAR* pSlash = wcsrchr(g_szDiagPath, L'\\');
    if (pSlash) { *(pSlash + 1) = L'\0'; wcscat_s(g_szDiagPath, L"diagnostics.log"); }  // NOSONAR - SCOPE-01: declaration kept outside if for readability
    else        { wcscpy_s(g_szDiagPath, L"C:\\ProgramData\\OpenAccessEID\\logs\\diagnostics.log"); }

    return g_fCsvEnabled;
}

// ================================================================
// Diagnostics File Management
// ================================================================
BOOL EnsureDiagFileOpen()
{
    if (g_hDiagFile != INVALID_HANDLE_VALUE)
        return TRUE;

    WCHAR szDir[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    wcscpy_s(szDir, g_szDiagPath);
    WCHAR* pLastSlash = wcsrchr(szDir, L'\\');
    if (pLastSlash)  // NOSONAR - SCOPE-01: declaration kept outside if for readability
    {
        *pLastSlash = L'\0';
        // M5: create the log directory with a restrictive DACL (Full to SYSTEM/Admins,
        // Read&Execute to Users), re-applying it if the directory already exists.
        // Refuse a directory that is a reparse point or not SYSTEM/Administrators-owned.
        if (!EnsureLogDirSecured(szDir))
            return FALSE;
    }

    // M5: FILE_FLAG_OPEN_REPARSE_POINT so a pre-planted symlink/junction at the
    // diagnostics path is opened as the reparse point (and fails) rather than followed.
    g_hDiagFile = CreateFileW(g_szDiagPath, GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (g_hDiagFile == INVALID_HANDLE_VALUE)
        return FALSE;

    LARGE_INTEGER liSize;
    if (GetFileSizeEx(g_hDiagFile, &liSize))  // NOSONAR - SCOPE-01: declaration kept outside if for readability
        g_dwDiagFileSize = static_cast<DWORD>(liSize.QuadPart);

    SetFilePointer(g_hDiagFile, 0, nullptr, FILE_END);

    if (g_dwDiagFileSize == 0)
    {
        DWORD dwWritten = 0;
        const BYTE bom[] = {0xEF, 0xBB, 0xBF};
        WriteFile(g_hDiagFile, bom, 3, &dwWritten, nullptr);
        g_dwDiagFileSize += dwWritten;
    }
    return TRUE;
}

void RotateDiagFile()
{
    if (g_hDiagFile != INVALID_HANDLE_VALUE)
    {
        FlushFileBuffers(g_hDiagFile);
        CloseHandle(g_hDiagFile);
        g_hDiagFile = INVALID_HANDLE_VALUE;
    }

    // This service runs as LocalSystem: never rename/delete through a directory that is a
    // junction or not owned by SYSTEM/Administrators. Skipping rotation leaves the file to
    // be re-vetted (and refused) by EnsureDiagFileOpen on the next write.
    if (!EID_IsLogDirSafeForRotation(g_szDiagPath))
    {
        g_dwDiagFileSize = 0;
        return;
    }

    // Keep up to g_dwFileCount rotated generations (mirrors CSVLogger's rotation).
    // The i > 1 count-down cannot underflow when g_dwFileCount is 0 or 1.
    DWORD dwCount = g_dwFileCount ? g_dwFileCount : 1;
    WCHAR szOld[MAX_PATH], szNew[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    swprintf_s(szOld, L"%s.%03u", g_szDiagPath, dwCount);
    DeleteFileW(szOld); // drop the oldest generation
    for (DWORD i = dwCount; i > 1; i--)
    {
        swprintf_s(szOld, L"%s.%03u", g_szDiagPath, i - 1);
        swprintf_s(szNew, L"%s.%03u", g_szDiagPath, i);
        MoveFileExW(szOld, szNew, MOVEFILE_REPLACE_EXISTING);
    }
    swprintf_s(szNew, L"%s.001", g_szDiagPath);
    MoveFileExW(g_szDiagPath, szNew, MOVEFILE_REPLACE_EXISTING);
    g_dwDiagFileSize = 0;
}

void WriteDiagnosticLine(const WCHAR* timestamp, const WCHAR* severity, DWORD dwProcessId, const WCHAR* message)
{
    if (!g_fDiagnosticsEnabled || !EnsureDiagFileOpen())
        return;

    ULONGLONG ullMaxBytes = static_cast<ULONGLONG>(g_dwMaxFileSizeMB) * 1024 * 1024;
    if (g_dwDiagFileSize >= ullMaxBytes)  // NOSONAR - SCOPE-01: declaration kept outside if for readability
    {
        RotateDiagFile();
        if (!EnsureDiagFileOpen())
            return;
    }

    char szTs[64] = {0};  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    char szSev[32] = {0};  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    char szMsg[3072] = {0};  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    WideCharToMultiByte(CP_UTF8, 0, timestamp, -1, szTs, sizeof(szTs), nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, severity, -1, szSev, sizeof(szSev), nullptr, nullptr);
    if (WideCharToMultiByte(CP_UTF8, 0, message, -1, szMsg, sizeof(szMsg), nullptr, nullptr) == 0)
        strcpy_s(szMsg, sizeof(szMsg), "(unconvertible message)");

    // The provider GUID is not access-controlled: any local process can write
    // events to it. Record which process wrote each line so a forged line can
    // be told apart from one written by the EID components.
    char szLine[4096];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    int len = sprintf_s(szLine, sizeof(szLine), "%s %s [pid %lu] %s\r\n", szTs, szSev,
        static_cast<unsigned long>(dwProcessId), szMsg);
    if (len > 0)
    {
        DWORD dwWritten = 0;
        WriteFile(g_hDiagFile, szLine, len, &dwWritten, nullptr);
        g_dwDiagFileSize += dwWritten;
    }
}

void CloseDiagFile()
{
    if (g_hDiagFile != INVALID_HANDLE_VALUE)
    {
        FlushFileBuffers(g_hDiagFile);
        CloseHandle(g_hDiagFile);
        g_hDiagFile = INVALID_HANDLE_VALUE;
    }
    g_dwDiagFileSize = 0;
}

// ================================================================
// ETW Event Parsing
// ================================================================

// Get severity name from level
const WCHAR* GetSeverityName(UCHAR level)
{
    switch (level)
    {
        case 1: return L"CRITICAL";
        case 2: return L"ERROR";
        case 3: return L"WARNING";
        case 4: return L"INFO";
        case 5: return L"VERBOSE";
        default: return L"UNKNOWN";
    }
}

// ================================================================
// ETW Callback for Events
// ================================================================
VOID WINAPI EventCallback(PEVENT_RECORD pEvent)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
    if (!pEvent || !g_fDiagnosticsEnabled)
        return;

    WCHAR szTimestamp[64] = {0};  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    WCHAR szMessage[1024] = {0};  // NOSONAR - LSASS-01: C-style buffer required by Win32 API

    // Format timestamp - convert FILETIME to SYSTEMTIME
    FILETIME ft;
    ft.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;

    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    swprintf_s(szTimestamp, ARRAYSIZE(szTimestamp),
        L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    // Try to get message from UserData
    if (pEvent->UserData && pEvent->UserDataLength > 0)
    {
        ULONG cchData = pEvent->UserDataLength / sizeof(WCHAR);
        if (cchData > 0 && cchData < ARRAYSIZE(szMessage))
        {
            // Copy by the known length; do not rely on the raw ETW payload being
            // null-terminated within UserDataLength.
            memcpy(szMessage, pEvent->UserData, cchData * sizeof(WCHAR));
            szMessage[cchData] = L'\0';
        }
    }

    // The payload is untrusted (anyone can write to the provider GUID): replace
    // CR/LF and every other control or line-separator character so a payload
    // cannot start a new, forged line in diagnostics.log.
    for (size_t i = 0; i < ARRAYSIZE(szMessage) && szMessage[i] != L'\0'; i++)
    {
        const WCHAR ch = szMessage[i];
        if (ch < 0x20 || ch == 0x7F || (ch >= 0x80 && ch <= 0x9F) || ch == 0x2028 || ch == 0x2029)
            szMessage[i] = L' ';
    }

    // If no user data, create a generic message
    if (szMessage[0] == L'\0')
    {
        swprintf_s(szMessage, ARRAYSIZE(szMessage),
            L"Event 0x%X from provider", pEvent->EventHeader.EventDescriptor.Id);
    }

    // Structured audit events carry an "[EID:NNNN]" prefix and are written to events.csv
    // by the in-process LSA logger. The consumer must NOT touch events.csv (its column
    // schema differs and would corrupt the file). Only free-text diagnostic traces are ours.
    if (wcsstr(szMessage, L"[EID:") != nullptr)
        return;

    UCHAR level = pEvent->EventHeader.EventDescriptor.Level;
    if (level == 0)
        level = 4; // EventWriteString with level 0 -> treat as INFO
    if (level > static_cast<UCHAR>(g_dwDiagnosticsLevel))
        return; // more verbose than the configured ceiling

    WriteDiagnosticLine(szTimestamp, GetSeverityName(level), pEvent->EventHeader.ProcessId,
                        szMessage[0] ? szMessage : L"(no message)");
}

// ================================================================
// Trace Session Management
// ================================================================
// Stop and delete the real-time session we created (safe to call if not started).
void StopRealtimeSession()
{
    if (g_hSession != 0)
    {
        EnableTraceEx2(g_hSession, &EID_PROVIDER_GUID,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, nullptr);

        struct
        {
            EVENT_TRACE_PROPERTIES Props;
            WCHAR LoggerName[128];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
        } sp;
        ZeroMemory(&sp, sizeof(sp));
        sp.Props.Wnode.BufferSize = sizeof(sp);
        sp.Props.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(g_hSession, nullptr, &sp.Props, EVENT_TRACE_CONTROL_STOP);
        g_hSession = 0;
    }
}

// Create the real-time ETW session and enable the EID provider on it. StartTrace copies the
// session name into the properties buffer at LoggerNameOffset, so the buffer must be large
// enough to hold EVENT_TRACE_PROPERTIES followed by the name.
BOOL CreateRealtimeSession()
{
    struct
    {
        EVENT_TRACE_PROPERTIES Props;
        WCHAR LoggerName[128];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    } sp;

    auto initProps = [&sp]()
    {
        ZeroMemory(&sp, sizeof(sp));
        sp.Props.Wnode.BufferSize = sizeof(sp);
        sp.Props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        sp.Props.Wnode.ClientContext = 1; // QPC timestamps
        sp.Props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        sp.Props.LogFileNameOffset = 0; // real-time: no backing file
        sp.Props.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    };

    initProps();
    ULONG status = StartTraceW(&g_hSession, EID_SESSION_NAME, &sp.Props);
    if (status == ERROR_ALREADY_EXISTS)
    {
        // A stale session from a previous run is still up - stop it and recreate.
        initProps();
        ControlTraceW(0, EID_SESSION_NAME, &sp.Props, EVENT_TRACE_CONTROL_STOP);
        initProps();
        status = StartTraceW(&g_hSession, EID_SESSION_NAME, &sp.Props);
    }
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"StartTrace failed: %u\n", status);
        g_hSession = 0;
        return FALSE;
    }

    // Enable the EID credential-provider ETW provider on our session at VERBOSE so that
    // INFO-level events (e.g. the tile disconnect/revive traces) are captured.
    status = EnableTraceEx2(g_hSession, &EID_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"EnableTraceEx2 failed: %u\n", status);
        StopRealtimeSession();
        return FALSE;
    }

    return TRUE;
}

BOOL StartTraceSession()
{
    // Reload configuration to check if CSV logging is enabled
    LoadCsvConfiguration();

    if (!g_fDiagnosticsEnabled)
    {
        wprintf(L"Diagnostics capture disabled, skipping trace session start\n");
        return TRUE; // Not an error - just disabled
    }

    // Create our own real-time session (and enable the provider on it) before consuming.
    // Without this, OpenTrace has no session to attach to and no events ever arrive.
    if (!CreateRealtimeSession())
    {
        return FALSE;
    }

    EVENT_TRACE_LOGFILE logfile = {};
    logfile.LoggerName = const_cast<LPWSTR>(EID_SESSION_NAME);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
    // EventRecordCallback (PEVENT_RECORD) requires PROCESS_TRACE_MODE_EVENT_RECORD; without it
    // ETW would invoke the legacy PEVENT_TRACE callback against our record-style handler.
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventCallback;
    logfile.Context = nullptr;

    gTraceHandle = OpenTrace(&logfile);
    if (gTraceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        wprintf(L"OpenTrace failed: %d\n", GetLastError());
        StopRealtimeSession();
        return FALSE;
    }

    wprintf(L"Trace session started successfully\n");
    return TRUE;
}

BOOL StopTraceSession()
{
    if (gTraceHandle != 0 && gTraceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(gTraceHandle);
        gTraceHandle = 0;
    }

    // Stop the real-time session we created so it does not linger after the service exits.
    StopRealtimeSession();

    CloseDiagFile();
    wprintf(L"Trace session stopped\n");
    return TRUE;
}

// ================================================================
// Service Worker Thread
// ================================================================
DWORD ServiceWorkerThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    wprintf(L"Service worker thread started\n");

    // Start the trace session
    if (!StartTraceSession())
    {
        ReportStatus(SERVICE_STOPPED, 1, 0);
        return 1;
    }

    // Main service loop - process events
    while (g_ServiceRunning)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    {
        // Wait for stop event with a short timeout
        DWORD dwWait = WaitForSingleObject(g_StopEvent, 1000);
        if (dwWait == WAIT_OBJECT_0)
        {
            // Stop event signaled
            break;
        }

        // Process trace events (with timeout for responsiveness)
        ULONG status = ProcessTrace(&gTraceHandle, 1, nullptr, nullptr);
        if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
        {
            wprintf(L"ProcessTrace failed: %u\n", status);
            // Try to restart trace session
            StopTraceSession();
            // Wait before retrying, but wake at once for a stop request. With diagnostics
            // off (the default) there is no trace to process, so the service spends most of
            // its time here; a plain Sleep kept it - and its executable, which the
            // uninstaller deletes straight after stopping it - running for up to five
            // seconds after the stop had been accepted.
            if (WaitForSingleObject(g_StopEvent, 5000) == WAIT_OBJECT_0)
            {
                break;
            }
            if (!StartTraceSession())
            {
                break;
            }
        }
    }

    // Stop the trace session
    StopTraceSession();

    ReportStatus(SERVICE_STOPPED, 0, 0);
    wprintf(L"Service worker thread exiting\n");
    return 0;
}

// ================================================================
// Service Main Entry Point
// ================================================================
VOID WINAPI ServiceMain(DWORD dwArgc, LPWSTR *lpszArgv)
{
    UNREFERENCED_PARAMETER(dwArgc);
    UNREFERENCED_PARAMETER(lpszArgv);

    g_StatusHandle = RegisterServiceCtrlHandlerExW(
        SERVICE_NAME,
        ServiceCtrlHandlerEx,
        nullptr
    );

    if (!g_StatusHandle)
    {
        wprintf(L"RegisterServiceCtrlHandlerEx failed: %d\n", GetLastError());
        return;
    }

    ReportStatus(SERVICE_START_PENDING, 0, 1000);

    // Create stop event
    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_StopEvent)
    {
        wprintf(L"CreateEvent failed: %d\n", GetLastError());
        ReportStatus(SERVICE_STOPPED, 1, 0);
        return;
    }

    // Load configuration
    LoadCsvConfiguration();

    // Create worker thread
    DWORD dwThreadId = 0;
    HANDLE hThread = CreateThread(
        nullptr,
        0,
        ServiceWorkerThread,
        nullptr,
        0,
        &dwThreadId
    );

    if (!hThread)
    {
        wprintf(L"CreateThread failed: %d\n", GetLastError());
        CloseHandle(g_StopEvent);
        ReportStatus(SERVICE_STOPPED, 1, 0);
        return;
    }

    ReportStatus(SERVICE_RUNNING, 0, 0);

    // Wait for worker thread to complete
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(g_StopEvent);

    ReportStatus(SERVICE_STOPPED, 0, 0);
    wprintf(L"Service exiting\n");
}

// ================================================================
// Service Control Handler
// ================================================================
DWORD WINAPI ServiceCtrlHandlerEx(DWORD dwCtrl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)  // NOSONAR - API-01: signature dictated by Windows/callback API
{
    UNREFERENCED_PARAMETER(dwEventType);
    UNREFERENCED_PARAMETER(lpEventData);
    UNREFERENCED_PARAMETER(lpContext);

    switch (dwCtrl)
    {
    case SERVICE_CONTROL_STOP:
        ReportStatus(SERVICE_STOP_PENDING, 0, 1000);
        g_ServiceRunning = FALSE;
        // Cancel the ProcessTrace call
        if (gTraceHandle != INVALID_PROCESSTRACE_HANDLE)
        {
            CloseTrace(gTraceHandle);
            gTraceHandle = INVALID_PROCESSTRACE_HANDLE;
        }
        SetEvent(g_StopEvent);
        ReportStatus(SERVICE_STOP_PENDING, 0, 1000);
        break;

    case SERVICE_CONTROL_SHUTDOWN:
        ReportStatus(SERVICE_STOP_PENDING, 0, 1000);  // NOSONAR - SWITCH-01: cases kept distinct for readability
        g_ServiceRunning = FALSE;
        if (gTraceHandle != INVALID_PROCESSTRACE_HANDLE)
        {
            CloseTrace(gTraceHandle);
            gTraceHandle = INVALID_PROCESSTRACE_HANDLE;
        }
        SetEvent(g_StopEvent);
        ReportStatus(SERVICE_STOP_PENDING, 0, 1000);
        break;

    case SERVICE_CONTROL_INTERROGATE:
        ReportStatus(g_ServiceStatus.dwCurrentState, 0, 0);
        break;

    default:
        break;
    }
    return 0;
}

// ================================================================
// Service Status Reporting
// ================================================================
VOID ReportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = dwCurrentState;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    g_ServiceStatus.dwWaitHint = dwWaitHint;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// ================================================================
// Service Installation/Removal
// ================================================================
BOOL InstallService()
{
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager)
    {
        wprintf(L"OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }

    // Get the path to the executable
    WCHAR szPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    GetModuleFileNameW(nullptr, szPath, MAX_PATH);

    // M6: quote the binary path so a directory such as "C:\Program Files\..."
    // cannot be hijacked via the unquoted-service-path privilege escalation.
    WCHAR szQuotedPath[MAX_PATH + 2];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
    StringCchPrintfW(szQuotedPath, ARRAYSIZE(szQuotedPath), L"\"%s\"", szPath);

    SC_HANDLE hService = CreateServiceW(
        hSCManager,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        szQuotedPath,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (!hService)
    {
        DWORD dwError = GetLastError();
        CloseServiceHandle(hSCManager);

        if (dwError == ERROR_SERVICE_EXISTS)
        {
            wprintf(L"Service already exists\n");
            return TRUE;
        }

        wprintf(L"CreateService failed: %d\n", dwError);
        return FALSE;
    }

    // Set service description
    SERVICE_DESCRIPTIONW desc;
    desc.lpDescription = const_cast<LPWSTR>(SERVICE_DESCRIPTION);  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified

    ChangeServiceConfig2W(
        hService,
        SERVICE_CONFIG_DESCRIPTION,
        &desc
    );

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    wprintf(L"Service installed successfully\n");
    return TRUE;
}

// How long -stop and -uninstall wait for the service process to exit.
#define SERVICE_STOP_TIMEOUT_MS 30000  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use

// Ask the service to stop (unless it already is) and wait until its process has exited.
// The uninstaller deletes EIDTraceConsumer.exe straight after -stop / -uninstall, and the file
// stays in use until the process is gone - which is after SERVICE_STOPPED has been reported,
// since the process still has to unwind and exit. Returning as soon as the stop request had
// been accepted left the executable (and so the installation folder) behind.
// hService needs SERVICE_STOP | SERVICE_QUERY_STATUS. Returns TRUE once the process has exited.
static BOOL StopServiceAndWait(SC_HANDLE hService)
{
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD cbNeeded = 0;
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &cbNeeded))  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
    {
        wprintf(L"QueryServiceStatusEx failed: %d\n", GetLastError());
        return FALSE;
    }
    if (ssp.dwCurrentState == SERVICE_STOPPED)
    {
        wprintf(L"Service is already stopped\n");
        return TRUE;
    }

    // Open the process while the service still runs, so the PID cannot have been reused.
    HANDLE hProcess = (ssp.dwProcessId != 0) ? OpenProcess(SYNCHRONIZE, FALSE, ssp.dwProcessId) : nullptr;

    if (ssp.dwCurrentState != SERVICE_STOP_PENDING)
    {
        wprintf(L"Stopping service...\n");
        SERVICE_STATUS status = {};
        if (!ControlService(hService, SERVICE_CONTROL_STOP, &status))
        {
            DWORD dwError = GetLastError();
            if (dwError != ERROR_SERVICE_NOT_ACTIVE && dwError != ERROR_SERVICE_CANNOT_ACCEPT_CTRL)
            {
                wprintf(L"ControlService failed: %d\n", dwError);
                if (hProcess)
                    CloseHandle(hProcess);
                return FALSE;
            }
        }
    }

    BOOL fStopped = FALSE;
    if (hProcess)
    {
        fStopped = (WaitForSingleObject(hProcess, SERVICE_STOP_TIMEOUT_MS) == WAIT_OBJECT_0);
        CloseHandle(hProcess);
    }
    else
    {
        // No handle on the process: the stopped state is the best available signal.
        const ULONGLONG ullDeadline = GetTickCount64() + SERVICE_STOP_TIMEOUT_MS;
        for (;;)
        {
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &cbNeeded) &&  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
                ssp.dwCurrentState == SERVICE_STOPPED)
            {
                fStopped = TRUE;
                break;
            }
            if (GetTickCount64() >= ullDeadline)
                break;
            Sleep(250);
        }
    }

    if (fStopped)
        wprintf(L"Service stopped\n");
    else
        wprintf(L"Service did not stop within %d seconds\n", SERVICE_STOP_TIMEOUT_MS / 1000);
    return fStopped;
}

BOOL UninstallService()
{
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCManager)
    {
        wprintf(L"OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }

    // SERVICE_QUERY_STATUS is needed to wait for the stop. The service used to be opened
    // without it, so the status read before stopping it was never filled in.
    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        SERVICE_NAME,
        DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS
    );

    if (!hService)
    {
        DWORD dwError = GetLastError();
        CloseServiceHandle(hSCManager);

        if (dwError == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            wprintf(L"Service does not exist\n");
            return TRUE;
        }

        wprintf(L"OpenService failed: %d\n", dwError);
        return FALSE;
    }

    // Stop the service and wait for its process to exit. Delete it even if that times out:
    // it is then removed as soon as the process does exit.
    StopServiceAndWait(hService);

    // Delete the service
    if (!DeleteService(hService))
    {
        wprintf(L"DeleteService failed: %d\n", GetLastError());
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    wprintf(L"Service uninstalled successfully\n");
    return TRUE;
}

BOOL StartServiceWrapper()
{
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCManager)
    {
        wprintf(L"OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }

    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        SERVICE_NAME,
        SERVICE_START | SERVICE_QUERY_STATUS
    );

    if (!hService)
    {
        wprintf(L"OpenService failed: %d\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    BOOL result = StartService(hService, 0, nullptr);
    if (!result)
    {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_SERVICE_ALREADY_RUNNING)
        {
            wprintf(L"Service is already running\n");
            result = TRUE;
        }
        else
        {
            wprintf(L"StartService failed: %d\n", dwError);
        }
    }
    else
    {
        wprintf(L"Service started successfully\n");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return result;
}

BOOL StopServiceWrapper()
{
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCManager)
    {
        wprintf(L"OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }

    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        SERVICE_NAME,
        SERVICE_STOP | SERVICE_QUERY_STATUS
    );

    if (!hService)
    {
        wprintf(L"OpenService failed: %d\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    BOOL result = StopServiceAndWait(hService);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return result;
}

// ================================================================
// Console Entry Point (for testing/standalone execution)
// ================================================================
int wmain(int argc, WCHAR* argv[])  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    if (argc > 1)
    {
        if (_wcsicmp(argv[1], L"-install") == 0)
        {
            return InstallService() ? 0 : 1;
        }
        else if (_wcsicmp(argv[1], L"-uninstall") == 0)
        {
            return UninstallService() ? 0 : 1;
        }
        else if (_wcsicmp(argv[1], L"-start") == 0)
        {
            return StartServiceWrapper() ? 0 : 1;
        }
        else if (_wcsicmp(argv[1], L"-stop") == 0)
        {
            return StopServiceWrapper() ? 0 : 1;
        }
        else if (_wcsicmp(argv[1], L"-console") == 0)
        {
            // Run in console mode for testing
            wprintf(L"Running in console mode...\n");
            LoadCsvConfiguration();
            if (!StartTraceSession())
            {
                wprintf(L"Failed to start trace session\n");
                return 1;
            }

            wprintf(L"Press Enter to stop...\n");
            getchar();

            StopTraceSession();
            return 0;
        }
        else
        {
            wprintf(L"Usage:\n");
            wprintf(L"  EIDTraceConsumer -install   Install service\n");
            wprintf(L"  EIDTraceConsumer -uninstall Uninstall service\n");
            wprintf(L"  EIDTraceConsumer -start     Start service\n");
            wprintf(L"  EIDTraceConsumer -stop      Stop service\n");
            wprintf(L"  EIDTraceConsumer -console   Run in console (testing)\n");
            return 1;
        }
    }
    else
    {
        // Run as service
        wprintf(L"Starting service...\n");

        SERVICE_TABLE_ENTRY dispatchTable[] =  // NOSONAR - LSASS-01: C-style array required by Win32 API
        {
            { const_cast<LPWSTR>(SERVICE_NAME), (LPSERVICE_MAIN_FUNCTION)ServiceMain },  // NOSONAR - CAST-01: Win32/COM interop cast, layout-verified
            { nullptr, nullptr }
        };

        if (!StartServiceCtrlDispatcherW(dispatchTable))
        {
            wprintf(L"StartServiceCtrlDispatcherW failed: %d\n", GetLastError());
            wprintf(L"This program must be run as a service or with command-line arguments\n");
            return 1;
        }
    }

    return 0;
}
