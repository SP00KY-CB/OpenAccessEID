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


#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <evntprov.h>
#include <crtdbg.h>
#include <wmistr.h>
#include <evntrace.h>
// load lib on the Vista tracing function
#include <delayimp.h>
#define _CRTDBG_MAPALLOC  // NOSONAR - MACRO-02: CRT debug memory tracking macro
#include <DbgHelp.h>
#include <winhttp.h>

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "guid.h"
#include "StringConversion.h"
#include "CSVLogger.h"
#include "CSVConfig.h"
#include "EventDefinitions.h"
#include <string>
#include <array>

#pragma comment(lib,"Dbghelp")

REGHANDLE hPub;  // NOSONAR - RUNTIME-01: ETW registration handle, set by EventRegister()
WCHAR Section[100];  // NOSONAR - RUNTIME-01: Trace section buffer, filled at runtime

// SECURITY FIX #37: Add synchronization for trace globals (CWE-362)
// ETW EnableCallback can be called from any thread; protect shared state
static CRITICAL_SECTION g_csTrace;  // NOSONAR - RUNTIME-01: Critical section, must be mutable
static BOOL g_csTraceInitialized = FALSE;  // NOSONAR - RUNTIME-01: Initialization flag

// One-time registration of the ETW provider. This used to be a plain BOOL
// (bFirst) read without a lock by every trace call, so two threads tracing
// for the first time could both run InitializeCriticalSection on the same
// CRITICAL_SECTION and EventRegister twice (leaking a REGHANDLE). INIT_ONCE
// runs the registration exactly once and makes concurrent first callers wait
// for it (LSASS-safe, no DllMain involvement).
static INIT_ONCE g_TraceInitOnce = INIT_ONCE_STATIC_INIT;  // NOSONAR - RUNTIME-01: tracing initialization guard, set at runtime

// to enable tracing in kernel debugger, issue the following command in windbg : ed nt!Kd_DEFAULT_MASK  0xFFFFFFFF
// OR
// Open up the registry and go to this path,
// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter 
// and add the following value "DEFAULT" : REG_DWORD : 0xFFFFFFFF and then reboot
//
// Note : you don't need this in Windows XP as the tracing is shown automatically
/**
 *  Tracing function.
 *  Extract data using :
 * C:\Windows\System32\LogFiles\WMI>tracerpt EIDCredentialProvider.etl.001 -o c:\users\Adiant\Desktop\report.txt -of csv
 */

BOOL LookUpErrorMessage(PWSTR buf, int cch, DWORD err)
{
	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, err, 0, buf, cch, nullptr)) {
        return TRUE;
    }
    else 
	{
        swprintf_s(buf, cch, (err < 15000) ? L"Error number: %d" :
                                                  L"Error number: 0x%08X", err);
        return false;
    }
}

BOOL IsTracingEnabled = FALSE;  // NOSONAR - RUNTIME-01: ETW tracing state, modified by EnableCallback

void NTAPI EnableCallback(
  __in      LPCGUID SourceId,
  __in      ULONG IsEnabled,
  __in      UCHAR Level,
  __in      ULONGLONG MatchAnyKeyword,
  __in      ULONGLONG MatchAllKeywords,
  __in_opt  PEVENT_FILTER_DESCRIPTOR FilterData,  // NOSONAR - API-01: signature dictated by Windows/callback API
  __in_opt  PVOID CallbackContext
)
{
	UNREFERENCED_PARAMETER(SourceId);
	UNREFERENCED_PARAMETER(Level);
	UNREFERENCED_PARAMETER(MatchAnyKeyword);
	UNREFERENCED_PARAMETER(MatchAllKeywords);
	UNREFERENCED_PARAMETER(FilterData);
	UNREFERENCED_PARAMETER(CallbackContext);
	// SECURITY FIX #37: Synchronize access to IsTracingEnabled (CWE-362)
	if (g_csTraceInitialized)
	{
		EnterCriticalSection(&g_csTrace);
		IsTracingEnabled = (IsEnabled == EVENT_CONTROL_CODE_ENABLE_PROVIDER);
		LeaveCriticalSection(&g_csTrace);
	}
	else
	{
		IsTracingEnabled = (IsEnabled == EVENT_CONTROL_CODE_ENABLE_PROVIDER);
	}
}

static BOOL CALLBACK EIDTraceInitOnceCallback(PINIT_ONCE, PVOID, PVOID*)
{
	// SECURITY FIX #37: Initialize critical section for trace globals (CWE-362)
	InitializeCriticalSection(&g_csTrace);
	g_csTraceInitialized = TRUE;
	EventRegister(&CLSID_CEIDProvider,EnableCallback,nullptr,&hPub);
	return TRUE;
}

static void EIDEnsureTracingRegistered()
{
	InitOnceExecuteOnce(&g_TraceInitOnce, EIDTraceInitOnceCallback, nullptr, nullptr);
}

void EIDCardLibraryTracingRegister() {
	EIDEnsureTracingRegistered();
}

void EIDCardLibraryTracingUnRegister() {
	// Only undo a registration that actually completed. The INIT_ONCE is not
	// reset: this runs at unload, and tracing after it is a no-op (hPub == 0).
	BOOL fPending = FALSE;
	if (!InitOnceBeginInitialize(&g_TraceInitOnce, INIT_ONCE_CHECK_ONLY, &fPending, nullptr) || fPending)
	{
		return;
	}
	EventUnregister(hPub);
	hPub = 0;
	// SECURITY FIX #37: Clean up critical section
	if (g_csTraceInitialized)
	{
		g_csTraceInitialized = FALSE;
		DeleteCriticalSection(&g_csTrace);
	}
}

// see http://www.codeproject.com/Articles/16598/Get-Your-DLL-s-Path-Name for the "__ImageBase"
EXTERN_C IMAGE_DOS_HEADER __ImageBase;  // NOSONAR - RUNTIME-01: Linker-defined symbol

// Format into a fixed buffer without ever invoking the CRT invalid-parameter handler,
// which would terminate LSASS. Returns FALSE only when nothing usable was produced; a
// truncated message (ret == -1 with a non-empty, NUL-terminated buffer) is kept.
static BOOL EIDFormatTruncatedV(PWSTR pBuffer, size_t cchBuffer, PCWSTR szFormat, va_list ap)
{
	pBuffer[0] = L'\0';
	const int ret = _vsnwprintf_s(pBuffer, cchBuffer, _TRUNCATE, szFormat, ap);
	return (ret >= 0 || pBuffer[0] != L'\0') ? TRUE : FALSE;
}

void EIDCardLibraryTraceEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, UCHAR dwLevel, _Printf_format_string_ PCWSTR szFormat,...) {  // NOSONAR - VARIADIC-01: ETW tracing requires variadic format function
	_ASSERTE( _CrtCheckMemory( ) );
#ifndef _DEBUG
	UNREFERENCED_PARAMETER(dwLine);
	UNREFERENCED_PARAMETER(szFile);
#endif
	WCHAR Buffer[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	WCHAR Buffer2[356];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	va_list ap;

	EIDEnsureTracingRegistered();

	// _TRUNCATE, not a count equal to the buffer size: with an explicit count the
	// CRT treats output that does not fit as an invalid parameter and fast-fails,
	// which kills LSASS - and callers trace caller-controlled strings (user names)
	// before they are validated. With _TRUNCATE an over-long message is cut short
	// and ret is -1; the buffer is still NUL-terminated, so emit it anyway.
	va_start (ap, szFormat);
	const BOOL fFormatted = EIDFormatTruncatedV(Buffer, ARRAYSIZE(Buffer), szFormat, ap);
	va_end (ap);
	if (!fFormatted) return;
	Buffer[ARRAYSIZE(Buffer) - 1] = L'\0';
#ifdef _DEBUG
	_snwprintf_s(Buffer2,ARRAYSIZE(Buffer2),_TRUNCATE,L"%S(%d) : %S - %s\r\n",szFile,dwLine,szFunction,Buffer);
	OutputDebugString(Buffer2);
#endif
	_snwprintf_s(Buffer2,ARRAYSIZE(Buffer2),_TRUNCATE,L"%S(%d) : %s",szFunction,dwLine,Buffer);

	EventWriteString(hPub,dwLevel,0,Buffer2);

}


	// Exception codes that mean memory is already corrupt or the thread can no
	// longer run safely. Inside LSASS these must not be swallowed: carrying on
	// after a fault lets a caller probe the fault again and again without the
	// machine restarting, and leaves heap and loader locks in an unknown state.
	static BOOL EIDIsFatalException(DWORD dwCode)
	{
		switch (dwCode)
		{
		case EXCEPTION_ACCESS_VIOLATION:
		case EXCEPTION_IN_PAGE_ERROR:
		case EXCEPTION_ILLEGAL_INSTRUCTION:
		case EXCEPTION_PRIV_INSTRUCTION:
		case EXCEPTION_DATATYPE_MISALIGNMENT:
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		case EXCEPTION_STACK_OVERFLOW:
		case EXCEPTION_GUARD_PAGE:
		case 0xC0000374: // STATUS_HEAP_CORRUPTION
		case 0xC0000409: // STATUS_STACK_BUFFER_OVERRUN
			return TRUE;
		default:
			return FALSE;
		}
	}

	// common exception handler
	//
	// This used to write a MiniDumpNormal from inside the filter. A filter runs
	// before unwinding, so the dump caught the plaintext PIN still on the
	// LsaApLogonUserEx2 stack (the wipe is in a __finally that runs later); it
	// also called MiniDumpWriteDump in-process, which can deadlock on the
	// loader or heap lock held at the fault, and wrote one file per exception
	// with no limit. LSASS crash dumps are left to Windows Error Reporting
	// (LocalDumps), which an administrator can turn on when needed.
	LONG EIDExceptionHandlerDebug( PEXCEPTION_POINTERS pExceptPtrs, BOOL fMustCrash )
	{
		DWORD dwCode = (pExceptPtrs && pExceptPtrs->ExceptionRecord) ? pExceptPtrs->ExceptionRecord->ExceptionCode : 0;
		EIDCardLibraryTraceEx(__FILE__,__LINE__,__FUNCTION__,WINEVENT_LEVEL_WARNING,L"New Exception 0x%08X", dwCode);  // NOSONAR - LOG-01: __FILE__ retained for logging macro
		if (fMustCrash)
		{
			// crash on debug to allow kernel debugger to break where the exception was triggered
			return EXCEPTION_CONTINUE_SEARCH;
		}
		if (EIDIsFatalException(dwCode))
		{
			// Let it reach the process's unhandled-exception path (and WER).
			return EXCEPTION_CONTINUE_SEARCH;
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	LONG EIDExceptionHandler( PEXCEPTION_POINTERS pExceptPtrs )
	{
#ifdef _DEBUG
		return EIDExceptionHandlerDebug(pExceptPtrs, TRUE);
#else
		return EIDExceptionHandlerDebug(pExceptPtrs, FALSE);
#endif
	}

void EIDCardLibraryDumpMemoryEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, PVOID memoryParam, DWORD memorysize)  // NOSONAR - API-01: void* memory-dump signature and complexity retained by design
{
	DWORD i;
	DWORD j;
	std::array<UCHAR, 10> buffer;
	WCHAR szFormat[] = L"%3d %3d %3d %3d %3d %3d %3d %3d %3d %3d";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	WCHAR szFormat2[] = L"%c%c%c%c%c%c%c%c%c%c";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	PUCHAR memory = (PUCHAR) memoryParam;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	for (i = 0; i < memorysize; i++)
	{
		buffer[i%10] = memory[i];
		if (i%10 == 9) 
		{
			EIDCardLibraryTraceEx(szFile,dwLine,szFunction, WINEVENT_LEVEL_VERBOSE, szFormat,
				buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
				buffer[5],buffer[6],buffer[7],buffer[8],buffer[9]);
		}
		if ((i == memorysize-1) && (i%10 != 9))
		{
			// last bytes
			for (j = 0; j <10; j++)
			{
				buffer[j]=255;
			}
			for (j = memorysize - memorysize%10; j <memorysize; j++) 
			{
				buffer[j%10] = memory[j];
			}
			szFormat[(memorysize%10) * 4] = '\0';
			EIDCardLibraryTraceEx(szFile,dwLine,szFunction, WINEVENT_LEVEL_VERBOSE, szFormat,
				buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
				buffer[5],buffer[6],buffer[7],buffer[8],buffer[9]);
		}
	}
	for (i = 0; i < memorysize; i++)
	{
		buffer[i%10] = memory[i];
		if (buffer[i%10] < 30) buffer[i%10] = ' ';
		if (i%10 == 9) 
		{
			EIDCardLibraryTraceEx(szFile,dwLine,szFunction, WINEVENT_LEVEL_VERBOSE, szFormat2,
				buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
				buffer[5],buffer[6],buffer[7],buffer[8],buffer[9]);
		}
		if ((i == memorysize-1) && (i%10 != 9))
		{
			// last bytes
			for (j = 0; j <10; j++)
			{
				buffer[j]=' ';
			}
			for (j = memorysize - memorysize%10; j <memorysize; j++) 
			{
				buffer[j%10] = memory[j];
				if (buffer[j%10] < 30) buffer[j%10] = ' ';  // NOSONAR - COMPLEXITY-01: nested loop retained; logic verified
			}
			szFormat2[memorysize%10] = '\0';
			EIDCardLibraryTraceEx(szFile,dwLine,szFunction, WINEVENT_LEVEL_VERBOSE, szFormat2,
				buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
				buffer[5],buffer[6],buffer[7],buffer[8],buffer[9]);
		}
	}
}

/**
 *  Display a messagebox giving an error code
 */
void MessageBoxWin32Ex2(DWORD status, HWND hWnd, LPCSTR szFile, DWORD dwLine) {
	LPVOID Error = nullptr;
	wchar_t szMessage[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	wchar_t szTitle[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwFmtLen;
	_snwprintf_s(szTitle,ARRAYSIZE(szTitle),_TRUNCATE,L"%hs(%d)",szFile, dwLine);
	if (status >= WINHTTP_ERROR_BASE && status <= WINHTTP_ERROR_LAST)
	{
		// winhttp error message
		dwFmtLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER| FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE,
			GetModuleHandle(_T("winhttp.dll")),status,0,(LPTSTR)&Error,0,nullptr);
	}
	else
	{
		// system error message
		dwFmtLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
			nullptr,status,0,(LPTSTR)&Error,0,nullptr);
	}
	// FormatMessage only allocates Error on success; without this guard an unmapped
	// status code would leave Error uninitialized and be dereferenced and freed.
	if (dwFmtLen != 0 && Error != nullptr)
	{
		_snwprintf_s(szMessage,ARRAYSIZE(szMessage),_TRUNCATE,L"0x%08X - %s",status,(wchar_t *) Error);
		LocalFree(Error);
	}
	else
	{
		swprintf_s(szMessage,ARRAYSIZE(szMessage),L"0x%08X - (no message available)",status);
	}
	EIDCardLibraryTraceEx(szFile, dwLine, "MessageBoxWin32Ex2", WINEVENT_LEVEL_INFO, L"%s", szMessage);
	MessageBox(hWnd,szMessage, szTitle ,MB_ICONASTERISK);
}

// BUG 5: StartLogging now takes the trace level so the live ETW session is
// enabled at the policy/config TraceLevel instead of a hardcoded VERBOSE. The
// no-arg overload (declared in Tracing.h, called by DebugReport.cpp) preserves
// the previous behaviour by defaulting to VERBOSE when no config is supplied.
BOOL StartLogging(UCHAR level)
{
	BOOL fReturn = FALSE;
	TRACEHANDLE SessionHandle;
	struct _Prop
	{
		EVENT_TRACE_PROPERTIES TraceProperties;
		TCHAR LogFileName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		TCHAR LoggerName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	};
	_Prop Properties;
	ULONG err;
	__try
	{
		memset(&Properties, 0, sizeof(Properties));
		Properties.TraceProperties.Wnode.BufferSize = sizeof(Properties);
		Properties.TraceProperties.Wnode.Guid = CLSID_CEIDProvider;
		Properties.TraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		Properties.TraceProperties.Wnode.ClientContext = 1;
		Properties.TraceProperties.LogFileMode = 4864;
		Properties.TraceProperties.LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		Properties.TraceProperties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(TCHAR);
		Properties.TraceProperties.MaximumFileSize = 8;
		wcscpy_s(Properties.LogFileName,1024,L"c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl");
		DeleteFile(Properties.LogFileName);
		err = StartTrace(&SessionHandle, L"EIDCredentialProvider", &(Properties.TraceProperties));
		if (err != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"StartTrace 0x%08x", err);
			__leave;
		}
		err = EnableTraceEx(&CLSID_CEIDProvider,nullptr,SessionHandle,TRUE,level,0,0,0,nullptr);
		if (err != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EnableTraceEx 0x%08x", err);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		// NOSONAR - SEH-01: Empty finally block required for SEH completeness
	}
	return fReturn;
}

// Backward-compatible overload matching the Tracing.h declaration. Defaults to
// the previous hardcoded VERBOSE level when the caller has no configured level.
BOOL StartLogging()
{
	return StartLogging(static_cast<UCHAR>(WINEVENT_LEVEL_VERBOSE));
}

BOOL StopLogging()
{
	LONG err = 0;
	BOOL fReturn = FALSE;
	struct _Prop
	{
		EVENT_TRACE_PROPERTIES TraceProperties;
		TCHAR LogFileName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		TCHAR LoggerName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	};
	_Prop Properties;
	memset(&Properties, 0, sizeof(Properties));
	__try
	{
		Properties.TraceProperties.Wnode.BufferSize = sizeof(Properties);
		Properties.TraceProperties.Wnode.Guid = CLSID_CEIDProvider;
		Properties.TraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		Properties.TraceProperties.LogFileMode = 4864; 
		Properties.TraceProperties.LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		Properties.TraceProperties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(TCHAR);
		Properties.TraceProperties.MaximumFileSize = 8;
		err = ControlTrace(0, L"EIDCredentialProvider", &(Properties.TraceProperties),EVENT_TRACE_CONTROL_STOP);
		if (err != ERROR_SUCCESS && err != 0x00001069)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ControlTrace 0x%08x", err);
		}
		fReturn = TRUE;
	}
	__finally
	{
		// NOSONAR - SEH-01: Empty finally block required for SEH completeness
	}
	SetLastError(err);
	return fReturn;
}

// Security audit logging - provides visibility into security-relevant events
// Logs to ETW with security-specific formatting for SIEM/security monitoring tools
void EIDSecurityAuditEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, UCHAR dwAuditType, _Printf_format_string_ PCWSTR szFormat,...)  // NOSONAR - VARIADIC-01: ETW audit logging requires variadic format function
{
	UNREFERENCED_PARAMETER(szFile);
	WCHAR Buffer[512];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	WCHAR AuditBuffer[600];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	va_list ap;
	LPCWSTR pwszAuditPrefix;

	EIDEnsureTracingRegistered();

	// Determine audit type prefix for easy filtering
	switch (dwAuditType)
	{
	case SECURITY_AUDIT_SUCCESS:
		pwszAuditPrefix = L"[SECURITY-AUDIT-SUCCESS]";
		break;
	case SECURITY_AUDIT_FAILURE:
		pwszAuditPrefix = L"[SECURITY-AUDIT-FAILURE]";
		break;
	case SECURITY_AUDIT_WARNING:
		pwszAuditPrefix = L"[SECURITY-AUDIT-WARNING]";
		break;
	default:
		pwszAuditPrefix = L"[SECURITY-AUDIT]";
		break;
	}

	// ret == -1 with a non-empty buffer means "truncated": still emit the audit.
	va_start(ap, szFormat);
	const BOOL fFormatted = EIDFormatTruncatedV(Buffer, ARRAYSIZE(Buffer), szFormat, ap);
	va_end(ap);
	if (!fFormatted) return;

	// Format with security audit prefix and location info.
	// _snwprintf_s/_TRUNCATE, not swprintf_s: the prefix, function name and an already
	// 511-char-capable message can exceed AuditBuffer, and swprintf_s overflow invokes the
	// CRT invalid-parameter handler, which terminates LSASS. Truncating an audit line is
	// always preferable to killing the process that writes it.
	_snwprintf_s(AuditBuffer, ARRAYSIZE(AuditBuffer), _TRUNCATE, L"%s %S:%d - %s", pwszAuditPrefix, szFunction, dwLine, Buffer);

#ifdef _DEBUG
	OutputDebugString(AuditBuffer);
	OutputDebugString(L"\r\n");
#endif

	// Log security audits at ERROR level to ensure they are captured
	// Failures are logged at CRITICAL level for highest visibility
	UCHAR dwLevel = (dwAuditType == 1) ? WINEVENT_LEVEL_CRITICAL : WINEVENT_LEVEL_ERROR;
	EventWriteString(hPub, dwLevel, 0, AuditBuffer);

	// Also emit a structured row to events.csv (when CSV logging is enabled) so security audits are
	// SIEM-parseable, not just free-text in the diagnostics log. Buffer holds the formatted message.
	EID_EVENT_ID auditEventId = (dwAuditType == SECURITY_AUDIT_SUCCESS)
		? EID_EVENT_ID::AUDIT_ADMIN_ACTION : EID_EVENT_ID::AUDIT_SECURITY_VIOLATION;  // NOSONAR - ENUM-01: event-id selection
	EID_SEVERITY auditSeverity = (dwAuditType == SECURITY_AUDIT_FAILURE) ? EID_SEVERITY::ERROR
		: ((dwAuditType == SECURITY_AUDIT_WARNING) ? EID_SEVERITY::WARNING : EID_SEVERITY::INFO);
	EID_OUTCOME auditOutcome = (dwAuditType == SECURITY_AUDIT_SUCCESS) ? EID_OUTCOME::SUCCESS : EID_OUTCOME::FAILURE;
	EIDCardLibraryLogStructured(auditEventId, auditSeverity, auditOutcome, nullptr, L"Security Audit", Buffer);
}

// Enhanced error logging with structured context
// Format: [ERROR_CONTEXT] Function:line - Operation 'name' failed: hr=0x%08X, additional_context
void EIDLogErrorWithContextEx(  // NOSONAR - VARIADIC-01: Error logging requires variadic format function
	PCSTR szFile,
	DWORD dwLine,
	PCSTR szFunction,
	const char* operation,
	HRESULT hr,
	_In_opt_z_ _Printf_format_string_ PCWSTR szAdditionalContext,
	...)
{
	UNREFERENCED_PARAMETER(szFile);

	WCHAR ContextBuffer[256] = {0};  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	WCHAR FinalBuffer[512] = {0};  // NOSONAR - LSASS-01: C-style buffer for LSASS safety

	EIDEnsureTracingRegistered();

	// Format additional context if provided
	if (szAdditionalContext != nullptr)
	{
		va_list ap;
		va_start(ap, szAdditionalContext);
		const BOOL fFormatted = EIDFormatTruncatedV(ContextBuffer, ARRAYSIZE(ContextBuffer), szAdditionalContext, ap);
		va_end(ap);
		if (!fFormatted)
		{
			wcscpy_s(ContextBuffer, L"(context formatting error)");
		}
	}

	// Format final message with structured prefix
	if (szAdditionalContext != nullptr && ContextBuffer[0] != L'\0')
	{
		_snwprintf_s(FinalBuffer, ARRAYSIZE(FinalBuffer), _TRUNCATE,
			L"[ERROR_CONTEXT] %S:%d - Operation '%S' failed: hr=0x%08X, %s",
			szFunction, dwLine, operation, hr, ContextBuffer);
	}
	else
	{
		_snwprintf_s(FinalBuffer, ARRAYSIZE(FinalBuffer), _TRUNCATE,
			L"[ERROR_CONTEXT] %S:%d - Operation '%S' failed: hr=0x%08X",
			szFunction, dwLine, operation, hr);
	}

#ifdef _DEBUG
	OutputDebugString(FinalBuffer);
	OutputDebugString(L"\r\n");
#endif

	EventWriteString(hPub, WINEVENT_LEVEL_ERROR, 0, FinalBuffer);
}

// LSASS-safe stack trace capture for error diagnostics
// Uses CaptureStackBackTrace - reliable in LSASS context (Phase 27 finding)
// Stack-allocated buffer only - no dynamic memory allocation
void EIDLogStackTraceEx(
	PCSTR szFile,
	DWORD dwLine,
	PCSTR szFunction,
	DWORD errorCode)
{
	UNREFERENCED_PARAMETER(szFile);

	// Stack-allocated buffer - LSASS safe
	constexpr USHORT MAX_STACK_FRAMES = 16;
	PVOID stack[MAX_STACK_FRAMES];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety

	EIDEnsureTracingRegistered();

	// Log error context at ERROR level
	WCHAR ErrorBuffer[256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	_snwprintf_s(ErrorBuffer, ARRAYSIZE(ErrorBuffer), _TRUNCATE,
		L"[STACK_TRACE] %S:%d - Error code 0x%08X, call stack follows:",
		szFunction, dwLine, errorCode);

#ifdef _DEBUG
	OutputDebugString(ErrorBuffer);
	OutputDebugString(L"\r\n");
#endif
	EventWriteString(hPub, WINEVENT_LEVEL_ERROR, 0, ErrorBuffer);

	// Capture stack back trace
	USHORT frames = CaptureStackBackTrace(
		2,  // Skip this function and immediate caller
		MAX_STACK_FRAMES,
		stack,
		nullptr
	);

	// Log each frame at VERBOSE level (only visible when tracing enabled)
	for (USHORT i = 0; i < frames; ++i)
	{
		WCHAR FrameBuffer[128];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		swprintf_s(FrameBuffer, ARRAYSIZE(FrameBuffer),
			L"[STACK_TRACE]   frame[%u] = 0x%p", i, stack[i]);

#ifdef _DEBUG
		OutputDebugString(FrameBuffer);
		OutputDebugString(L"\r\n");
#endif
		EventWriteString(hPub, WINEVENT_LEVEL_VERBOSE, 0, FrameBuffer);
	}
}

// ================================================================
// Structured CSV Logging Implementation
// ================================================================

// BUG 7: Track CSV initialization with INIT_ONCE instead of an unsynchronized
// BOOL. Two concurrent first-logons (console + RDP) could otherwise both see the
// flag clear and double-run EID_CSV_Initialize. INIT_ONCE runs the init exactly
// once and blocks the second caller until it completes (LSASS-safe, no DllMain).
static INIT_ONCE g_CSVInitOnce = INIT_ONCE_STATIC_INIT;  // NOSONAR - RUNTIME-01: CSV initialization guard, set at runtime

static BOOL CALLBACK EIDCSVInitOnceCallback(PINIT_ONCE, PVOID, PVOID*)
{
	EID_CSV_Initialize();
	return TRUE;
}

// Structured logging function - logs to both ETW and CSV
void EIDCardLibraryLogStructured(  // NOSONAR - COMPLEXITY-01: parameter count dictated by structured-logging schema
    EID_EVENT_ID eventId,
    EID_SEVERITY severity,
    EID_OUTCOME outcome,
    PCWSTR pwszUsername,
    PCWSTR pwszAction,
    PCWSTR pwszMessage,
    PCWSTR pwszDomain,
    PCWSTR pwszSourceIP,
    DWORD dwProcessID,
    DWORD dwThreadID,
    DWORD dwSessionID,
    PCWSTR pwszResource,
    PCWSTR pwszReason)
{
	// Initialize CSV logger on first use (thread-safe, runs exactly once)
	InitOnceExecuteOnce(&g_CSVInitOnce, EIDCSVInitOnceCallback, nullptr, nullptr);

	// Build ETW message (with event ID prefix for correlation)
	// _TRUNCATE: pwszMessage can itself be a full 512-char audit buffer, and a
	// swprintf_s overflow fast-fails the process (LSASS).
	WCHAR szETWMessage[512];  // NOSONAR - LSASS-01: Stack-allocated buffer for LSASS safety
	_snwprintf_s(szETWMessage, ARRAYSIZE(szETWMessage), _TRUNCATE,
		L"[EID:%04u] %s: %s",
		static_cast<DWORD>(eventId),  // NOSONAR - ENUM-01: explicit cast to DWORD retained for logging
		pwszAction ? pwszAction : L"(no action)",
		pwszMessage ? pwszMessage : L"(no message)");

	// Log to ETW (existing functionality). The built message carries caller data
	// (user names, audit text), so it is an argument, never the format string.
	EIDCardLibraryTraceEx(__FILE__, __LINE__, __FUNCTION__,  // NOSONAR - LOG-01: __FILE__ retained for logging macro
		static_cast<UCHAR>(severity), L"%s", szETWMessage);  // NOSONAR - ENUM-01: explicit cast to UCHAR retained for logging

	// Log to CSV if enabled
	if (EID_CSV_IsEnabled())
	{
		EIDCSVLogger::LogEvent(
			eventId, severity, outcome,
			pwszUsername, pwszAction, pwszMessage,
			pwszDomain, pwszSourceIP,
			dwProcessID ? dwProcessID : GetCurrentProcessId(),
			dwThreadID ? dwThreadID : GetCurrentThreadId(),
			dwSessionID, pwszResource, pwszReason
		);
	}
}

// CSV lifecycle: Initialize (loads config and starts logger)
void EID_CSV_Initialize()
{
	EID_CSV_CONFIG config;
	HRESULT hr = EID_CSV_LoadConfig(config);

	// Even if config load fails, initialize with defaults
	if (FAILED(hr))
	{
		config = EID_CSV_CONFIG();
		wcscpy_s(config.szLogPath, EID_CSV_DEFAULT_LOG_PATH);
	}

	// Initialize the CSV logger
	if (config.fEnabled)
	{
		EIDCSVLogger::Initialize(config);
	}
}

// CSV lifecycle: Shutdown (closes log file)
void EID_CSV_Shutdown()
{
	EIDCSVLogger::Shutdown();
}

// CSV status: Check if logging is enabled
BOOL EID_CSV_IsEnabled()
{
	return EIDCSVLogger::IsEnabled();
}

// CSV configuration: Update at runtime
HRESULT EID_CSV_UpdateConfig(const EID_CSV_CONFIG& config)
{
	// Save to both JSON file and registry
	HRESULT hrJson = EID_CSV_SaveConfigToFile(EID_CSV_CONFIG_PATH, config);
	HRESULT hrReg = EID_CSV_SaveConfigToRegistry(config);

	// Update runtime logger
	HRESULT hrLogger = EIDCSVLogger::UpdateConfig(config);

	// Return success if logger update succeeded
	if (SUCCEEDED(hrLogger))
	{
		return hrLogger;
	}

	// Otherwise return the most specific error
	return FAILED(hrJson) ? hrJson : hrReg;
}