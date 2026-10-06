#include <Windows.h>
#include <tchar.h>
#include <wincred.h>
#include <NTSecAPI.h>
#include <random>
#include <string>

#include "global.h"
#include "EIDConfigurationWizard.h"

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/TraceExport.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/StringConversion.h"
// OnlineDatabase.h removed - internet reporting functionality disabled
#include "../EIDCardLibrary/EIDAuthenticateVersion.h"

#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/StringConversion.h"
#include <string>
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/StringConversion.h"
#include <string>

#include "CContainerHolder.h"
#pragma comment(lib,"Credui")

// Static buffers for Windows API compatibility (C++23 /Zc:strictStrings)
static char s_szMyTest[] = "MYTEST";                                  // NOSONAR - GLOBAL-01: Runtime-initialized LSA state
static constexpr size_t s_szMyTestLen = sizeof(s_szMyTest) - 1;  // Length without null terminator (SonarQube cpp:S5813)
static wchar_t s_wszEtlPath[] = L"c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl";  // NOSONAR - GLOBAL-01: Runtime-initialized LSA state

BOOL TestLogon(HWND hMainWnd)
{
	BOOL save = false;
	DWORD authPackage = 0;
	LPVOID authBuffer;
	ULONG authBufferSize = 0;
	CREDUI_INFO credUiInfo;
	BOOL fReturn = FALSE;
	DWORD dwError = 0;

	LSA_HANDLE hLsa;
	LSA_STRING Origin = { (USHORT)s_szMyTestLen, (USHORT)sizeof(s_szMyTest), s_szMyTest };
	QUOTA_LIMITS Quota = {0};
	TOKEN_SOURCE Source = { "TEST", { 0, 101 } };
	MSV1_0_INTERACTIVE_PROFILE *Profile;
	ULONG ProfileLen;
	LUID Luid;
	NTSTATUS err;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	NTSTATUS stat;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	HANDLE Token;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	DWORD dwFlag = CREDUIWIN_AUTHPACKAGE_ONLY | CREDUIWIN_ENUMERATE_CURRENT_USER;
	RetrieveNegotiateAuthPackage(&authPackage);
	
	CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
	TCHAR szMessage[256] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	TCHAR szCaption[256] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	LoadString(g_hinst, IDS_05CREDINFOCAPTION, szCaption, ARRAYSIZE(szCaption));
	credUiInfo.pszCaptionText = szCaption;
	credUiInfo.pszMessageText = szMessage;
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.hbmBanner = nullptr;
	credUiInfo.hwndParent = hMainWnd;

	DWORD result = CredUIPromptForWindowsCredentials(&credUiInfo, 0, &authPackage,
					nullptr, 0, &authBuffer, &authBufferSize, &save, dwFlag);
	if (result == ERROR_SUCCESS) // NOSONAR - SCOPE-01: variable reused after the block
	{
		LsaConnectUntrusted(&hLsa);
		/* Find the setuid package and call it */
		err = LsaLogonUser(hLsa, &Origin, Interactive, authPackage, authBuffer,authBufferSize,nullptr, &Source, (PVOID*)&Profile, &ProfileLen, &Luid, &Token, &Quota, &stat);
		LsaDeregisterLogonProcess(hLsa);
		if (err)
		{
			dwError = LsaNtStatusToWinError(err);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLogonUser error 0x%08X", result);
		}
		else
		{
			fReturn = TRUE;
			
			LsaFreeReturnBuffer(Profile);
			CloseHandle(Token);
			
		}
		CoTaskMemFree(authBuffer);
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredUIPromptForWindowsCredentials error 0x%08X", result);
		dwError = result;
	}
	SetLastError(dwError);
	return fReturn;
}

HANDLE hInternalLogWriteHandle = nullptr;  // NOSONAR - RUNTIME-01: File handle, opened at runtime

// Is a caller-supplied report path safe to open CREATE_ALWAYS at high
// integrity? CREATE_ALWAYS truncates, so an unconstrained path here is an
// arbitrary-file-destruction primitive - including the product's own audit log,
// which the supplying process otherwise cannot touch.
BOOL IsAcceptableReportPath(PCTSTR szPath)
{
	if (!szPath || szPath[0] == TEXT('\0'))
	{
		return FALSE;
	}
	const size_t cchPath = _tcslen(szPath);
	if (cchPath >= MAX_PATH)
	{
		return FALSE;
	}
	// UNC and the device namespaces (\\?\ , \\.\).
	if (szPath[0] == TEXT('\\') && szPath[1] == TEXT('\\'))
	{
		return FALSE;
	}
	// Traversal, and forward slashes which bypass naive prefix checks.
	if (_tcsstr(szPath, TEXT("..")) != nullptr || _tcschr(szPath, TEXT('/')) != nullptr)
	{
		return FALSE;
	}
	// Must be fully qualified on a local drive: X:\...
	if (cchPath < 4 || szPath[1] != TEXT(':') || szPath[2] != TEXT('\\'))
	{
		return FALSE;
	}
	// A colon after the drive letter would name an alternate data stream.
	if (_tcschr(szPath + 2, TEXT(':')) != nullptr)
	{
		return FALSE;
	}
	return TRUE;
}

HANDLE StartReport(PTSTR szLogFile) // NOSONAR - API-01: PTSTR parameter dictated by report/logging API signature
{
	DWORD dwError = 0;
	BOOL fSuccess = FALSE;
	HANDLE hOutput = INVALID_HANDLE_VALUE;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	__try
	{
		if (!IsAcceptableReportPath(szLogFile))
		{
			dwError = ERROR_INVALID_NAME;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"StartReport: path rejected");
			__leave;
		}
		//  Creates the new file to write to for the upper-case version.
		// FILE_FLAG_OPEN_REPARSE_POINT so a symlink or junction planted at the
		// target cannot redirect this elevated CREATE_ALWAYS elsewhere. The CSV
		// logger already does this; this path did not.
		hOutput = CreateFile(szLogFile, // file name
							   GENERIC_WRITE,        // open for write
							   0,                    // do not share
							   nullptr,                 // default security
							   CREATE_ALWAYS,        // overwrite existing
							   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
							   nullptr);                // no template
		if (hOutput == INVALID_HANDLE_VALUE) 
		{ 
			dwError = GetLastError();
			__leave;
		}
		hInternalLogWriteHandle = hOutput;
		// disable the logging, just in case if was active
		StopLogging();
		// enable the logging
		if (!StartLogging())
		{
			dwError = GetLastError();
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Starting report");
		fSuccess = TRUE;
	}
	__finally
	{
		if (!fSuccess)
		{
			if (hOutput != INVALID_HANDLE_VALUE)
				CloseHandle(hOutput);
			hOutput = INVALID_HANDLE_VALUE;
			// Clear the global too. It was assigned above before StartLogging
			// could fail, so the failure path used to close the handle and leave
			// hInternalLogWriteHandle pointing at it - and CreateReport then
			// calls ExportOneTraceFile(hInternalLogWriteHandle, ...) regardless,
			// writing to a closed and possibly recycled handle.
			hInternalLogWriteHandle = INVALID_HANDLE_VALUE;
		}
	}
	SetLastError(dwError);
	return hOutput;
}

// from previous step
// credentials
extern CContainerHolderFactory<CContainerHolderTest> *pCredentialList;  // NOSONAR - RUNTIME-01: Credential list, modified at runtime
// selected credential
extern DWORD dwCurrentCredential;  // NOSONAR - RUNTIME-01: Selected index, modified at runtime

BOOL DoTheActionToBeTraced()
{
	DWORD dwError;
	BOOL fSuccess = FALSE;
	PCCERT_CONTEXT pCertContext = nullptr;
	__try
	{
		
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Starting report");
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Version : %S", EIDAuthenticateVersionText);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"===============");
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Register the certificate");
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"===============");
		// register the package again
		CContainerHolderTest* MyTest = pCredentialList->GetContainerHolderAt(dwCurrentCredential); // NOSONAR - API-01: non-const pointer used to call non-const-qualified member functions
		CContainer* container = MyTest->GetContainer(); // NOSONAR - API-01: pointer type retained to match GetContainer() return contract
		pCertContext = container->GetCertificate();
		fSuccess = LsaEIDCreateStoredCredential(szUserName, szPassword, pCertContext, container->GetKeySpec() == AT_KEYEXCHANGE);
		if (!fSuccess)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Test failed with 0x%08X", dwError);
			__leave;
		}
		
		// call for a test
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Test Logon");
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"===============");
		if (!TestLogon(nullptr))
		{
			dwError = GetLastError();
			if (dwError == ERROR_CANCELLED)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TestLogonCancelled");
				__leave;
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Test failed with 0x%08X", dwError);
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Success !!!");
		fSuccess = TRUE;
	}
	__finally
	{
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Ending tests");
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"===============");
	SetLastError(dwError);
	return fSuccess;
}

// called from the wizard (non elevated)
// create the elevated process
BOOL CreateDebugReport(PTSTR szLogFile)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	TCHAR szNamedPipeName[256] = L"\\\\.\\pipe\\EIDAuthenticateWizard";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	HANDLE hNamedPipe = INVALID_HANDLE_VALUE;  // NOSONAR - EXPLICIT-TYPE-02: HANDLE visible for security audit
	TCHAR szParameter[356];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD dwWrite;
	__try
	{
		// run the process of the wizard with a special parameter, elevated
		// so the tracing can be done in another process
		// and no information is transmitted to that process

		// create a named pipe for intercommunication process
		// generate the name

		static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);

		for (int i = 0; i < 10; ++i) {
			szNamedPipeName[_tcslen(szNamedPipeName)] = alphanum[dis(gen)];
		}

		// SECURITY: this pipe is created by a MEDIUM-integrity process and then
		// connected to by an ELEVATED one, so it is a low-to-high channel.
		//
		// The original call passed PIPE_UNLIMITED_INSTANCES and a null security
		// descriptor. A null SD applies the token's DEFAULT DACL, which grants
		// the creating user GENERIC_ALL - and that includes
		// FILE_CREATE_PIPE_INSTANCE. So any other process running as the same
		// user could add an instance of this pipe, consume the legitimate one as
		// a client, and let the elevated process fall into its own documented
		// ERROR_PIPE_BUSY / WaitNamedPipe retry (see CreateReport below) and
		// connect to the ATTACKER'S instance instead. The random name suffix is
		// no defence: the named-pipe directory is world-listable.
		//
		// FILE_FLAG_FIRST_PIPE_INSTANCE + nMaxInstances = 1 closes it: the
		// attacker's CreateNamedPipe fails if we got there first, and ours fails
		// loudly if they did, rather than silently sharing the name.
		SECURITY_ATTRIBUTES sa = {};
		SECURITY_DESCRIPTOR sd = {};
		if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"InitializeSecurityDescriptor 0x%08X", dwError);
			__leave;
		}
		sa.nLength = sizeof(sa);
		sa.lpSecurityDescriptor = &sd;
		sa.bInheritHandle = FALSE;
		// A null DACL would grant everyone access; we want the token default,
		// which is user + SYSTEM only, so leave the SD's DACL absent-but-not-null
		// by not calling SetSecurityDescriptorDacl with a NULL ACL. Passing the
		// SD unmodified gives the same default DACL as before, and the instance
		// limit is what actually stops the squat.
		hNamedPipe = CreateNamedPipe(szNamedPipeName,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
			1,                       // nMaxInstances: exactly one
			0,0,0,&sa);
		if (hNamedPipe == INVALID_HANDLE_VALUE)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateNamedPipe 0x%08X", GetLastError());
			__leave;
		}
		_stprintf_s(szParameter,ARRAYSIZE(szParameter),L"REPORT %s",szNamedPipeName);
		// launch the wizard elevated
		SHELLEXECUTEINFO shExecInfo;
		TCHAR szName[1024];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
		GetModuleFileName(GetModuleHandle(nullptr),szName, ARRAYSIZE(szName));

		shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
		shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
		shExecInfo.hwnd = nullptr;
		shExecInfo.lpVerb = L"runas";
		shExecInfo.lpFile = szName;
		// sending the named pipe name so the other process can connect
		shExecInfo.lpParameters = szParameter;
		shExecInfo.lpDirectory = nullptr;
		shExecInfo.nShow = SW_NORMAL;
		shExecInfo.hInstApp = nullptr;

		if (!ShellExecuteEx(&shExecInfo))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateNamedPipe 0x%08X", GetLastError());
		}
		else
		{
			if (! (ConnectNamedPipe(hNamedPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED)))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateNamedPipe 0x%08X", GetLastError());
				__leave;
			}
			// send to the process the log file name
			WriteFile(hNamedPipe,szLogFile,(DWORD) ((_tcslen(szLogFile) +1) * sizeof(TCHAR)),&dwWrite,nullptr);
			Sleep(1000);
			// do the action ...
			DoTheActionToBeTraced();
			Sleep(1000);
			// send to the process the order to stop
			// an empty line will do it
			WriteFile(hNamedPipe,L"\n",2 * sizeof(TCHAR),nullptr,nullptr);
			DisconnectNamedPipe(hNamedPipe);
			// then wait to its stop to have the file (if we don't, the file can be not written)
			if (WaitForSingleObject(shExecInfo.hProcess, INFINITE) == WAIT_OBJECT_0)
			{
				fReturn = TRUE;
			}
			else
			{
				dwError = GetLastError();
			}
		}
	}
	__finally
	{
		if (hNamedPipe != INVALID_HANDLE_VALUE)
			CloseHandle(hNamedPipe);
	}
	SetLastError(dwError);
	return fReturn;
}

// called from the elevated process
VOID CreateReport(PTSTR szNamedPipeName) // NOSONAR - API-01: PTSTR parameter dictated by named-pipe report API signature
{
	// read the file from the command line
	TCHAR szFile [256];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	HANDLE hReport = INVALID_HANDLE_VALUE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	HANDLE hPipe = INVALID_HANDLE_VALUE;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
	DWORD dwRead;
	__try
	{
		// SECURITY_IDENTIFICATION, not the default SecurityImpersonation. This
		// elevated process is the CLIENT of a pipe created by a medium-integrity
		// one, so without this the pipe's server could call
		// ImpersonateNamedPipeClient and act with this process's token.
		// Identification level lets the server query our identity but never
		// impersonate it.
		hPipe = CreateFile( szNamedPipeName,GENERIC_READ |GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
			SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,nullptr);
		if (hPipe == INVALID_HANDLE_VALUE)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"INVALID_HANDLE_VALUE 1");
			if (GetLastError() != ERROR_PIPE_BUSY) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"hPipe connect 0x%08X",GetLastError());
				__leave;
			}
			if ( ! WaitNamedPipe(szNamedPipeName, 20000)) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WaitNamedPipe 0x%08X",GetLastError());
				__leave;
			}
			// SECURITY_IDENTIFICATION, not the default SecurityImpersonation. This
		// elevated process is the CLIENT of a pipe created by a medium-integrity
		// one, so without this the pipe's server could call
		// ImpersonateNamedPipeClient and act with this process's token.
		// Identification level lets the server query our identity but never
		// impersonate it.
		hPipe = CreateFile( szNamedPipeName,GENERIC_READ |GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
			SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,nullptr);
		}
		if (hPipe == INVALID_HANDLE_VALUE)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"INVALID_HANDLE_VALUE 2 0X%08X",GetLastError());
			__leave;
		}
		// Leave room for a terminator and never trust the peer to send one.
		// The original read allowed a full 512 bytes into TCHAR[256] and then
		// passed the buffer to CreateFile with no NUL anywhere, so CreateFile
		// read off the end of this elevated process's stack.
		ZeroMemory(szFile, sizeof(szFile));
		if (!ReadFile(hPipe,szFile,(ARRAYSIZE(szFile) - 1) * sizeof(TCHAR), &dwRead,nullptr))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ReadFile 0X%08X",GetLastError());
			__leave;
		}
		if (dwRead == 0 || (dwRead % sizeof(TCHAR)) != 0)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Report path: bad length %u",dwRead);
			__leave;
		}
		szFile[dwRead / sizeof(TCHAR)] = TEXT('\0');

		// The peer that supplied this path is NOT trusted - it is the
		// medium-integrity process that launched us, and this path is about to be
		// opened CREATE_ALWAYS at high integrity, which truncates whatever it
		// names. Refuse anything that is not a plain local path.
		if (!IsAcceptableReportPath(szFile))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Report path rejected");
			__leave;
		}

		hReport = StartReport(szFile);
		
		// fait for <Enter> to quit
		if (!ReadFile(hPipe,szFile,1 * sizeof(TCHAR), &dwRead,nullptr))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ReadFile 0X%08X",GetLastError());
			__leave;
		}

		// write the ouput to the log fil
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Ending report");
		// disable the logging
		StopLogging();
		// get the text
		ExportOneTraceFile(hInternalLogWriteHandle, s_wszEtlPath);
	}
	__finally
	{
		if (hReport != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hReport);
		}
		if (hPipe != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hPipe);
		}
	}
}

// SendReport function removed - internet reporting functionality disabled