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
 *  Tracing function.
 */



/*
WINEVENT_LEVEL_CRITICAL Abnormal exit or termination events.
WINEVENT_LEVEL_ERROR Severe error events.
WINEVENT_LEVEL_WARNING Warning events such as allocation failures.
WINEVENT_LEVEL_INFO Non-error events such as entry or exit events.
WINEVENT_LEVEL_VERBOSE Detailed trace events.
*/

#pragma once

constexpr UCHAR WINEVENT_LEVEL_CRITICAL = 1;
constexpr UCHAR WINEVENT_LEVEL_ERROR    = 2;
constexpr UCHAR WINEVENT_LEVEL_WARNING  = 3;
constexpr UCHAR WINEVENT_LEVEL_INFO     = 4;
constexpr UCHAR WINEVENT_LEVEL_VERBOSE  = 5;

void EIDCardLibraryTracingRegister();
void EIDCardLibraryTracingUnRegister();

#define EIDCardLibraryTrace(dwLevel, ...) /* NOSONAR - LOG-01: __FILE__ retained for logging macro */ \
	EIDCardLibraryTraceEx(__FILE__,__LINE__,__FUNCTION__, dwLevel, __VA_ARGS__)  // NOSONAR - UAF-01: false positive - logging macro call passes __FILE__/__LINE__, no memory freed

// _Printf_format_string_ lets /analyze check every call site's arguments
// against its format string.
void EIDCardLibraryTraceEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction, UCHAR dwLevel, _Printf_format_string_ PCWSTR szFormat,...);

#define EIDCardLibraryDumpMemory(memory, memorysize) /* NOSONAR - LOG-01: __FILE__ retained for logging macro */ \
	EIDCardLibraryDumpMemoryEx(__FILE__,__LINE__,__FUNCTION__, memory, memorysize)

void EIDCardLibraryDumpMemoryEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, PVOID memory, DWORD memorysize);

/**
 *  Display a messagebox giving an error code
 */
void MessageBoxWin32Ex2(DWORD status, HWND hWnd, LPCSTR szFile, DWORD dwLine);
#define MessageBoxWin32(status) MessageBoxWin32Ex2 (status, NULL, __FILE__,__LINE__)  // NOSONAR - LOG-01: __FILE__ retained for logging macro
#define MessageBoxWin32Ex(status, hwnd ) MessageBoxWin32Ex2 (status, hwnd, __FILE__,__LINE__)  // NOSONAR - LOG-01: __FILE__ retained for logging macro

BOOL LookUpErrorMessage(PWSTR buf, int cch, DWORD err);

LONG EIDExceptionHandler( PEXCEPTION_POINTERS pExceptPtrs );
LONG EIDExceptionHandlerDebug( PEXCEPTION_POINTERS pExceptPtrs, BOOL fMustCrash );

BOOL StartLogging();
BOOL StopLogging();

// Security audit logging for security-relevant events
// These events are logged with elevated visibility for security monitoring
constexpr UCHAR SECURITY_AUDIT_SUCCESS  = 0;
constexpr UCHAR SECURITY_AUDIT_FAILURE  = 1;
constexpr UCHAR SECURITY_AUDIT_WARNING  = 2;

#define EIDSecurityAudit(dwAuditType, ...) /* NOSONAR - LOG-01: __FILE__ retained for logging macro */ \
	EIDSecurityAuditEx(__FILE__,__LINE__,__FUNCTION__, dwAuditType, __VA_ARGS__)

void EIDSecurityAuditEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction, UCHAR dwAuditType, _Printf_format_string_ PCWSTR szFormat,...);

// Enhanced error logging with operation context
// Provides structured error messages for easier debugging
// Format: "[ERROR_CONTEXT] Operation 'name' failed: hr=0x%08X, context_info
#define EIDLogErrorWithContext(operation, hr, ...) /* NOSONAR - LOG-01: __FILE__ retained for logging macro */ \
	EIDLogErrorWithContextEx(__FILE__, __LINE__, __FUNCTION__, operation, hr, __VA_ARGS__)

void EIDLogErrorWithContextEx(
	PCSTR szFile,
	DWORD dwLine,
	PCSTR szFunction,
	const char* operation,
	HRESULT hr,
	_In_opt_z_ _Printf_format_string_ PCWSTR szAdditionalContext,
	...);

// LSASS-safe stack trace capture for error diagnostics
// Uses CaptureStackBackTrace (not std::stacktrace - Phase 27 finding)
// Stack-allocated buffers only - no dynamic memory
#define EIDLogStackTrace(errorCode) /* NOSONAR - LOG-01: __FILE__ retained for logging macro */ \
	EIDLogStackTraceEx(__FILE__, __LINE__, __FUNCTION__, errorCode)

void EIDLogStackTraceEx(
	PCSTR szFile,
	DWORD dwLine,
	PCSTR szFunction,
	DWORD errorCode);

// ================================================================
// Structured CSV Logging
// ================================================================

// Include event definitions and CSV configuration
#include "EventDefinitions.h"  // NOSONAR - INCLUDE-01: include order significant for Windows SDK
#include "CSVConfig.h"

// Structured logging function that logs to both ETW and CSV
// This is the primary interface for security-relevant events
void EIDCardLibraryLogStructured(
    EID_EVENT_ID eventId,
    EID_SEVERITY severity,
    EID_OUTCOME outcome,
    PCWSTR pwszUsername,
    PCWSTR pwszAction,
    PCWSTR pwszMessage,
    PCWSTR pwszDomain = nullptr,
    PCWSTR pwszSourceIP = nullptr,
    DWORD dwProcessID = 0,
    DWORD dwThreadID = 0,
    DWORD dwSessionID = 0,
    PCWSTR pwszResource = nullptr,
    PCWSTR pwszReason = nullptr);

// CSV logging lifecycle functions
void EID_CSV_Initialize();
void EID_CSV_Shutdown();
BOOL EID_CSV_IsEnabled();
HRESULT EID_CSV_UpdateConfig(const EID_CSV_CONFIG& config);

// ================================================================
// Convenience Macros for Common Scenarios
// ================================================================

// Authentication success/failure logging
#define EID_LOG_AUTH_SUCCESS(user, msg) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::AUTH_SUCCESS, \
        EID_SEVERITY::INFO, EID_OUTCOME::SUCCESS, user, L"Authentication", msg)

#define EID_LOG_AUTH_FAILURE(user, reason) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::AUTH_FAILURE, \
        EID_SEVERITY::WARNING, EID_OUTCOME::FAILURE, user, L"Authentication", L"Failed", \
        nullptr, nullptr, 0, 0, 0, nullptr, reason)

// PIN verification logging
#define EID_LOG_PIN_SUCCESS(user) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::AUTH_PIN_SUCCESS, \
        EID_SEVERITY::INFO, EID_OUTCOME::SUCCESS, user, L"PIN Verification", L"PIN verified")

#define EID_LOG_PIN_FAILURE(user, reason) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::AUTH_PIN_FAILURE, \
        EID_SEVERITY::WARNING, EID_OUTCOME::FAILURE, user, L"PIN Verification", L"Failed", \
        nullptr, nullptr, 0, 0, 0, nullptr, reason)

// Certificate validation logging
#define EID_LOG_CERT_SUCCESS(subject) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::CERT_VALIDATE_SUCCESS, \
        EID_SEVERITY::INFO, EID_OUTCOME::SUCCESS, nullptr, L"Certificate Validation", subject)

#define EID_LOG_CERT_FAILURE(reason) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::CERT_VALIDATE_FAILURE, \
        EID_SEVERITY::ERROR, EID_OUTCOME::FAILURE, nullptr, L"Certificate Validation", L"Failed", \
        nullptr, nullptr, 0, 0, 0, nullptr, reason)

// Session logging
#define EID_LOG_SESSION_LOGON(user) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::SESSION_LOGON_SUCCESS, \
        EID_SEVERITY::INFO, EID_OUTCOME::SUCCESS, user, L"Logon", L"User logged on")

#define EID_LOG_SESSION_LOGOFF(user) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::SESSION_LOGOFF, \
        EID_SEVERITY::INFO, EID_OUTCOME::SUCCESS, user, L"Logoff", L"User logged off")

// Audit logging
#define EID_LOG_AUDIT_EXPORT(count) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::AUDIT_CREDENTIAL_EXPORT, \
        EID_SEVERITY::WARNING, EID_OUTCOME::SUCCESS, nullptr, L"Credential Export", \
        L"Credentials exported", nullptr, nullptr, 0, 0, 0, nullptr, nullptr)

#define EID_LOG_AUDIT_IMPORT(count) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::AUDIT_CREDENTIAL_IMPORT, \
        EID_SEVERITY::WARNING, EID_OUTCOME::SUCCESS, nullptr, L"Credential Import", \
        L"Credentials imported", nullptr, nullptr, 0, 0, 0, nullptr, nullptr)

// Configuration change logging
#define EID_LOG_CONFIG_CHANGE(setting, oldVal, newVal) \
    EIDCardLibraryLogStructured(EID_EVENT_ID::CONFIG_COLUMNS_CHANGED, \
        EID_SEVERITY::INFO, EID_OUTCOME::SUCCESS, nullptr, L"Configuration Change", \
        setting, nullptr, nullptr, 0, 0, 0, nullptr, nullptr)