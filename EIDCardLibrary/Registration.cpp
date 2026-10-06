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
#define SECURITY_WIN32
#include <sspi.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/StringConversion.h"
#include <string>

// BUG 5: level-taking overload of StartLogging (real logic lives in Tracing.cpp).
// Tracing.h only declares the no-arg StartLogging(); declare the overload locally
// so EnableLogging can start the live ETW session at the configured TraceLevel.
BOOL StartLogging(UCHAR level);


// Non-const string buffers for Windows API compatibility (AddSecurityPackage/DeleteSecurityPackage require LPWSTR)
static WCHAR s_wszAuthenticationPackageName[] = L"OpenAccessEIDPackage";  // NOSONAR - GLOBAL-01: Runtime-initialized LSA state


/** Used to append a string to a multi string reg key */
void AppendValueToMultiSz(HKEY hKey, LPCTSTR szKey, LPCTSTR szValue, LPCTSTR szData)
{
	HKEY hkResult;
	DWORD Status;
	Status=RegOpenKeyEx(hKey,szKey,0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE,&hkResult);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		return;
	}
	DWORD RegType;
	DWORD RegSize;
	PTSTR Buffer = nullptr;
	PTSTR Pointer;
	RegSize = 0;
	Status = RegQueryValueEx( hkResult,szValue,nullptr,&RegType,nullptr,&RegSize);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		RegCloseKey(hkResult);
		return;
	}
	RegSize += (DWORD) (_tcslen(szData) + 1 ) * sizeof(TCHAR);
	Buffer = (PTSTR) EIDAlloc(RegSize);
	if (!Buffer)
	{
		MessageBoxWin32(GetLastError());
		RegCloseKey(hkResult);
		return;
	}
	Status = RegQueryValueEx( hkResult,szValue,nullptr,&RegType,(LPBYTE)Buffer,&RegSize);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		RegCloseKey(hkResult);
		EIDFree(Buffer);
		return;
	}

	char bFound = FALSE;
	Pointer = Buffer;
	while (*Pointer) 
	{
		if (_tcscmp(Pointer,szData)==0) {
			bFound = TRUE;
			break;
		}
		Pointer = Pointer + _tcslen(Pointer) + 1;
	}
	if (bFound == FALSE) {
		// add the data
		_tcscpy_s(Pointer, _tcslen(szData) + 1, szData);
		Pointer[_tcslen(szData) + 1] = 0;
		RegSize += (DWORD) (_tcslen(szData) + 1 ) * sizeof(TCHAR);
		Status = RegSetValueEx(hkResult, szValue, 0, RegType, (PBYTE) Buffer, RegSize);
		if (Status != ERROR_SUCCESS) {
			MessageBoxWin32(Status);
		}
	}
	EIDFree(Buffer);
	RegCloseKey(hkResult);
}

/** Used to Remove a string to a multi string reg key */
void RemoveValueFromMultiSz(HKEY hKey, LPCTSTR szKey, LPCTSTR szValue, LPCTSTR szData)
{
	HKEY hkResult;
	DWORD Status;
	Status=RegOpenKeyEx(hKey,szKey,0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE,&hkResult);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		return;
	}
	DWORD RegType;
	DWORD RegSize;
	DWORD RegSizeOut;
	PTSTR BufferIn = nullptr;
	PTSTR BufferOut = nullptr;
	PTSTR PointerIn;
	PTSTR PointerOut;
	RegSize = 0;
	Status = RegQueryValueEx( hkResult,szValue,nullptr,&RegType,nullptr,&RegSize);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		RegCloseKey(hkResult);
		return;
	}
	BufferIn = (PTSTR) EIDAlloc(RegSize);
	if (!BufferIn)
	{
		MessageBoxWin32(GetLastError());
		RegCloseKey(hkResult);
		return;
	}
	BufferOut = (PTSTR) EIDAlloc(RegSize);
	if (!BufferOut)
	{
		MessageBoxWin32(GetLastError());
		EIDFree(BufferIn);
		RegCloseKey(hkResult);
		return;
	}
	Status = RegQueryValueEx( hkResult,szValue,nullptr,&RegType,(LPBYTE)BufferIn,&RegSize);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		EIDFree(BufferIn);
		EIDFree(BufferOut);
		RegCloseKey(hkResult);
		return;
	}

	PointerIn = BufferIn;
	PointerOut = BufferOut;
	RegSizeOut = 0;
	
	while (*PointerIn) 
	{
		// copy string if <> szData
		
		if (_tcscmp(PointerIn,szData)!=0) {			
			_tcscpy_s(PointerOut,(RegSize - RegSizeOut) /sizeof(TCHAR), PointerIn);
			RegSizeOut += (DWORD) (_tcslen(PointerOut) + 1) * sizeof(TCHAR);
			PointerOut += _tcslen(PointerOut) + 1;
		}
		PointerIn += _tcslen(PointerIn) + 1;
	}
	
	// last null char
	*PointerOut = 0;
	RegSizeOut += sizeof(TCHAR);
	
	Status = RegSetValueEx(hkResult, szValue, 0, RegType, (PBYTE) BufferOut, RegSizeOut);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
	}
	
	EIDFree(BufferIn);
	EIDFree(BufferOut);
	RegCloseKey(hkResult);
}



BOOL IsSecurityPackageLoaded(LPCTSTR szPackageName)
{
	NTSTATUS Status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	DWORD dwNbPackage;
	PSecPkgInfo pPackageInfo;
	BOOL fFound = FALSE;

	Status = EnumerateSecurityPackages(&dwNbPackage, &pPackageInfo);
	if (Status == SEC_E_OK)
	{
		for(DWORD dwI = 0; dwI < dwNbPackage; dwI++)
		{
			PTSTR szPackage = pPackageInfo[dwI].Name;
			if (_tcscmp(szPackage, szPackageName) == 0)
			{
				fFound = TRUE;
				break;
			}
		}
		FreeContextBuffer(pPackageInfo);
	}
	return fFound;
}

BOOL RegisterTheSecurityPackage()
{
	NTSTATUS Status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Starting...");
		if (IsSecurityPackageLoaded(AUTHENTICATIONPACKAGENAMET))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"The security package was loaded before");
			dwError = ERROR_FAIL_NOACTION_REBOOT;
			__leave;
		}
		SECURITY_PACKAGE_OPTIONS options = {sizeof(SECURITY_PACKAGE_OPTIONS)};
		Status = AddSecurityPackage(s_wszAuthenticationPackageName, &options);
		if (Status != SEC_E_OK)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to register the package 0x%08X 0x%08X",Status, GetLastError());
			dwError = LsaNtStatusToWinError(Status);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Sucessfully registered the package");
		fReturn = TRUE;
	}
	__finally
	{
		// SEH cleanup - no action needed
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL UnRegisterTheSecurityPackage()
{
	NTSTATUS Status;  // NOSONAR - EXPLICIT-TYPE-01: NTSTATUS visible for security audit
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	__try
	{
		// maybe use lsacallpackage to run UnloadPackage inside the SSP
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Starting...");
		if (!IsSecurityPackageLoaded(AUTHENTICATIONPACKAGENAMET))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"The security package was not loaded before");
			fReturn = TRUE;
			__leave;
		}
		Status = DeleteSecurityPackage(s_wszAuthenticationPackageName);
		if (Status != SEC_E_OK)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to unregister the package 0x%08X 0x%08X",Status, GetLastError());
			dwError = ERROR_FAIL_NOACTION_REBOOT;
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Sucessfully unregistered the package");
		fReturn = TRUE;
	}
	__finally
	{
		// SEH cleanup - no action needed
	}
	SetLastError(dwError);
	return fReturn;
}

/** Installation and uninstallation routine
*/

void OpenAccessEIDPackageDllRegister()
{
	// Remove any stale pre-v2.0.00 entry before adding the new one, so an in-place
	// upgrade cannot leave both names registered.
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", LEGACY_AUTHENTICATIONPACKAGENAMET);
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", LEGACY_AUTHENTICATIONPACKAGENAMET);
	// Register as Security Package (SSP interface)
	AppendValueToMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", AUTHENTICATIONPACKAGENAMET);
	// Also register as Authentication Package (AP interface) for LsaLookupAuthenticationPackage
	AppendValueToMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", AUTHENTICATIONPACKAGENAMET);
}

void OpenAccessEIDPackageDllUnRegister()
{
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", AUTHENTICATIONPACKAGENAMET);
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", AUTHENTICATIONPACKAGENAMET);
	// Strip the pre-v2.0.00 package name too. An upgrade where the old uninstaller never
	// ran would otherwise leave LSA referencing EIDAuthenticationPackage.dll after that
	// file has been deleted.
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", LEGACY_AUTHENTICATIONPACKAGENAMET);
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", LEGACY_AUTHENTICATIONPACKAGENAMET);
}

void EIDPasswordChangeNotificationDllRegister()
{
	AppendValueToMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Notification Packages", L"EIDPasswordChangeNotification");
}

void EIDPasswordChangeNotificationDllUnRegister()
{
	RemoveValueFromMultiSz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Notification Packages", L"EIDPasswordChangeNotification");
}


void EIDCredentialProviderDllRegister()
{
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{B4866A0A-DB08-4835-A26F-414B46F3244C}", 
		nullptr, REG_SZ, L"EidCredentialProvider",sizeof(L"EidCredentialProvider"));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\{B4866A0A-DB08-4835-A26F-414B46F3244C}", 
		nullptr, REG_SZ, L"EidCredentialProvider",sizeof(L"EidCredentialProvider"));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		L"CLSID\\{B4866A0A-DB08-4835-A26F-414B46F3244C}", 
		nullptr, REG_SZ, L"EidCredentialProvider",sizeof(L"EidCredentialProvider"));
	// Absolute path: a bare DLL name is resolved through the loading process's DLL search
	// path, so a CredUI host started from a writable directory could load a planted copy.
	// The installer copies the DLL to System32.
	RegSetKeyValue(	HKEY_CLASSES_ROOT,
		L"CLSID\\{B4866A0A-DB08-4835-A26F-414B46F3244C}\\InprocServer32",
		nullptr, REG_EXPAND_SZ, L"%SystemRoot%\\System32\\EIDCredentialProvider.dll",sizeof(L"%SystemRoot%\\System32\\EIDCredentialProvider.dll"));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		L"CLSID\\{B4866A0A-DB08-4835-A26F-414B46F3244C}\\InprocServer32",
		L"ThreadingModel",REG_SZ, L"Apartment",sizeof(L"Apartment"));
}

// Unregistering must never delete stored credentials: the uninstaller runs this on every
// uninstall AND on every upgrade (the old uninstaller runs first), and enrolments are meant
// to survive both. Credential removal is opt-in only, via the CleanupLsaCredentials export
// (uninstaller checkbox "Remove EID certificate mappings from users").
void EIDCredentialProviderDllUnRegister()
{
	RegDeleteTree(HKEY_CLASSES_ROOT, L"CLSID\\{B4866A0A-DB08-4835-A26F-414B46F3244C}");
	RegDeleteTree(HKEY_LOCAL_MACHINE, 
		L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{B4866A0A-DB08-4835-A26F-414B46F3244C}");
	RegDeleteTree(HKEY_LOCAL_MACHINE, 
		L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\{B4866A0A-DB08-4835-A26F-414B46F3244C}");
}

// The installer puts EIDConfigurationWizard.exe in $INSTDIR (not System32) and records $INSTDIR
// as HKLM\SOFTWARE\OpenAccessEID\InstallPath before it runs DllRegister. Returns the full path
// of the wizard; *pfExpand is TRUE when it falls back to the default folder written with an
// environment variable (so the value must be stored as REG_EXPAND_SZ).
static std::wstring GetConfigurationWizardPath(__out BOOL* pfExpand)
{
	WCHAR szInstallPath[MAX_PATH] = L"";  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
	DWORD cbInstallPath = sizeof(szInstallPath);
	LONG lStatus = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\OpenAccessEID", L"InstallPath",
		RRF_RT_REG_SZ, nullptr, szInstallPath, &cbInstallPath);
	std::wstring path;
	if (lStatus == ERROR_SUCCESS)
	{
		path = szInstallPath;
	}
	// The value is quoted in the command line below, so it must not contain a quote itself.
	if (path.empty() || path.find(L'"') != std::wstring::npos)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING, L"InstallPath unusable (0x%08x); using the default folder", lStatus);
		*pfExpand = TRUE;
		path = L"%ProgramFiles%\\OpenAccess EID";
	}
	else
	{
		*pfExpand = FALSE;
	}
	if (path.back() != L'\\')
	{
		path += L'\\';
	}
	path += L"EIDConfigurationWizard.exe";
	return path;
}

void EIDConfigurationWizardDllRegister()
{
	BOOL fExpand = FALSE;
	const std::wstring wizardPath = GetConfigurationWizardPath(&fExpand);
	const DWORD dwPathType = fExpand ? REG_EXPAND_SZ : REG_SZ;
	// Quoted: the install folder normally contains spaces ("Program Files").
	const std::wstring wizardCommand = L"\"" + wizardPath + L"\"";
	const std::wstring wizardTasks = wizardPath + L",-68";
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace\\{F5D846B4-14B0-11DE-B23C-27A355D89593}",
		nullptr,REG_SZ, L"EIDConfigurationWizard",sizeof(L"EIDConfigurationWizard"));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		L"CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}", 
		nullptr, REG_SZ, L"EIDConfigurationWizard",sizeof(L"EIDConfigurationWizard"));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		L"CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}",
		L"System.ApplicationName",REG_SZ, L"EID.EIDConfigurationWizard",sizeof(L"EID.EIDConfigurationWizard"));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		L"CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}",
		L"System.ControlPanel.Category",REG_SZ, L"10",sizeof(L"10"));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		L"CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}",
		L"LocalizedString",REG_EXPAND_SZ, L"Smart Card Logon",sizeof(L"Smart Card Logon"));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		L"CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}",
		L"InfoTip",REG_EXPAND_SZ, L"Smart Card Logon",sizeof(L"Smart Card Logon"));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		L"CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}\\DefaultIcon",
		nullptr,REG_EXPAND_SZ, L"%SystemRoot%\\system32\\imageres.dll,-58",
			sizeof(L"%SystemRoot%\\system32\\imageres.dll,-58"));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		L"CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}\\Shell\\Open\\Command",
		nullptr,dwPathType, wizardCommand.c_str(),
			(DWORD)((wizardCommand.size() + 1) * sizeof(WCHAR)));
	RegSetKeyValue(	HKEY_CLASSES_ROOT, 
		L"CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}",
		L"System.Software.TasksFileUrl",dwPathType, wizardTasks.c_str(),
			(DWORD)((wizardTasks.size() + 1) * sizeof(WCHAR)));
	

}

void EIDConfigurationWizardDllUnRegister()
{
	RegDeleteTree(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace\\{F5D846B4-14B0-11DE-B23C-27A355D89593}");
	RegDeleteTree(HKEY_CLASSES_ROOT, L"CLSID\\{F5D846B4-14B0-11DE-B23C-27A355D89593}");
}

// Trace configuration registry path: HKLM\SOFTWARE\OpenAccessEID\LogManager
static const TCHAR szTraceConfigKey[] = L"SOFTWARE\\OpenAccessEID\\LogManager";

// Default values for trace configuration
static const DWORD dwDefaultLevel = 4;  // WINEVENT_LEVEL_INFO
static const DWORD dwDefaultMaxSize = 64;  // MB
static const DWORD dwDefaultFileCounter = 5;  // Number of rotated files
static const BOOL fDefaultAutoStart = FALSE;

BOOL SetTraceConfig(DWORD dwLevel, LPCWSTR szLogPath, DWORD dwMaxSizeMB, DWORD dwFileCounter, BOOL fAutoStart)
{
	HKEY hKey = nullptr;
	LONG err = 0;
	BOOL fReturn = FALSE;

	// Validate trace level (must be 1-5)
	if (dwLevel < WINEVENT_LEVEL_CRITICAL || dwLevel > WINEVENT_LEVEL_VERBOSE)
	{
		dwLevel = dwDefaultLevel;
	}

	// Validate max file size (1-1024 MB)
	if (dwMaxSizeMB < 1 || dwMaxSizeMB > 1024)
	{
		dwMaxSizeMB = dwDefaultMaxSize;
	}

	// Validate file counter (1-100)
	if (dwFileCounter < 1 || dwFileCounter > 100)
	{
		dwFileCounter = dwDefaultFileCounter;
	}

	__try
	{
		// Create or open the registry key
		err = RegCreateKeyEx(HKEY_LOCAL_MACHINE, szTraceConfigKey, 0, nullptr,
			0, KEY_READ | KEY_WRITE, nullptr, &hKey, nullptr);
		if (err != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"RegCreateKeyEx failed: 0x%08X", err);
			__leave;
		}

		// Write trace level
		err = RegSetValueEx(hKey, L"TraceLevel", 0, REG_DWORD,
			(const BYTE*)&dwLevel, sizeof(DWORD));
		if (err != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"RegSetValueEx(TraceLevel) failed: 0x%08X", err);
			__leave;
		}

		// Write log file path
		if (szLogPath != nullptr && szLogPath[0] != L'\0')
		{
			err = RegSetValueEx(hKey, L"LogPath", 0, REG_SZ,
				(const BYTE*)szLogPath, (DWORD)((wcslen(szLogPath) + 1) * sizeof(WCHAR)));
			if (err != ERROR_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"RegSetValueEx(LogPath) failed: 0x%08X", err);
				__leave;
			}
		}

		// Write max file size
		err = RegSetValueEx(hKey, L"MaxFileSize", 0, REG_DWORD,
			(const BYTE*)&dwMaxSizeMB, sizeof(DWORD));
		if (err != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"RegSetValueEx(MaxFileSize) failed: 0x%08X", err);
			__leave;
		}

		// Write file counter
		err = RegSetValueEx(hKey, L"FileCounter", 0, REG_DWORD,
			(const BYTE*)&dwFileCounter, sizeof(DWORD));
		if (err != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"RegSetValueEx(FileCounter) failed: 0x%08X", err);
			__leave;
		}

		// Write auto-start flag
		DWORD dwAutoStart = fAutoStart ? 1 : 0;
		err = RegSetValueEx(hKey, L"AutoStart", 0, REG_DWORD,
			(const BYTE*)&dwAutoStart, sizeof(DWORD));
		if (err != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"RegSetValueEx(AutoStart) failed: 0x%08X", err);
			__leave;
		}

		fReturn = TRUE;
	}
	__finally
	{
		if (hKey != nullptr)
		{
			RegCloseKey(hKey);
		}
	}

	return fReturn;
}

BOOL GetTraceConfig(DWORD* pdwLevel, LPWSTR szLogPath, DWORD cchPath, DWORD* pdwMaxSizeMB, DWORD* pdwFileCounter, BOOL* pfAutoStart)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
	HKEY hKey = nullptr;
	LONG err = 0;
	BOOL fReturn = FALSE;
	DWORD dwType = 0;
	DWORD dwSize = 0;

	// Set default values
	if (pdwLevel != nullptr) *pdwLevel = dwDefaultLevel;
	if (szLogPath != nullptr && cchPath > 0)
		wcscpy_s(szLogPath, cchPath, L"c:\\windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl");
	if (pdwMaxSizeMB != nullptr) *pdwMaxSizeMB = dwDefaultMaxSize;
	if (pdwFileCounter != nullptr) *pdwFileCounter = dwDefaultFileCounter;
	if (pfAutoStart != nullptr) *pfAutoStart = fDefaultAutoStart;

	__try
	{
		// Open the registry key
		err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szTraceConfigKey, 0, KEY_READ, &hKey);
		if (err != ERROR_SUCCESS)
		{
			// Key doesn't exist yet, return defaults
			fReturn = TRUE;
			__leave;
		}

		// Read trace level
		if (pdwLevel != nullptr)
		{
			dwSize = sizeof(DWORD);
			err = RegQueryValueEx(hKey, L"TraceLevel", nullptr, &dwType,
				(LPBYTE)pdwLevel, &dwSize);
			if (err == ERROR_SUCCESS && dwType == REG_DWORD)
			{
				// Validate the read value
				if (*pdwLevel < WINEVENT_LEVEL_CRITICAL || *pdwLevel > WINEVENT_LEVEL_VERBOSE)
				{
					*pdwLevel = dwDefaultLevel;
				}
			}
			else
			{
				*pdwLevel = dwDefaultLevel;
			}
		}

		// Read log file path
		if (szLogPath != nullptr && cchPath > 0)
		{
			dwSize = cchPath * sizeof(WCHAR);
			err = RegQueryValueEx(hKey, L"LogPath", nullptr, &dwType,
				(LPBYTE)szLogPath, &dwSize);
			if (err != ERROR_SUCCESS || dwType != REG_SZ)
			{
				wcscpy_s(szLogPath, cchPath, L"c:\\windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl");
			}
		}

		// Read max file size
		if (pdwMaxSizeMB != nullptr)
		{
			dwSize = sizeof(DWORD);
			err = RegQueryValueEx(hKey, L"MaxFileSize", nullptr, &dwType,
				(LPBYTE)pdwMaxSizeMB, &dwSize);
			if (err != ERROR_SUCCESS || dwType != REG_DWORD)
			{
				*pdwMaxSizeMB = dwDefaultMaxSize;
			}
		}

		// Read file counter
		if (pdwFileCounter != nullptr)
		{
			dwSize = sizeof(DWORD);
			err = RegQueryValueEx(hKey, L"FileCounter", nullptr, &dwType,
				(LPBYTE)pdwFileCounter, &dwSize);
			if (err != ERROR_SUCCESS || dwType != REG_DWORD)
			{
				*pdwFileCounter = dwDefaultFileCounter;
			}
		}

		// Read auto-start flag
		if (pfAutoStart != nullptr)
		{
			DWORD dwAutoStart = 0;
			dwSize = sizeof(DWORD);
			err = RegQueryValueEx(hKey, L"AutoStart", nullptr, &dwType,
				(LPBYTE)&dwAutoStart, &dwSize);
			if (err == ERROR_SUCCESS && dwType == REG_DWORD)
			{
				*pfAutoStart = (dwAutoStart != 0);
			}
			else
			{
				*pfAutoStart = fDefaultAutoStart;
			}
		}

		fReturn = TRUE;
	}
	__finally
	{
		if (hKey != nullptr)
		{
			RegCloseKey(hKey);
		}
	}

	// GPO override: values under SOFTWARE\Policies\OpenAccessEID\LogManager win over local config,
	// so EnableLogging() (which builds the ETW autologger from these values) honours Group Policy.
	HKEY hPolicy = nullptr;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\OpenAccessEID\\LogManager", 0, KEY_READ, &hPolicy) == ERROR_SUCCESS)
	{
		DWORD dwPolType = 0;
		DWORD dwPolVal = 0;
		DWORD dwPolSize = 0;
		if (pdwLevel != nullptr)
		{
			dwPolSize = sizeof(DWORD);
			if (RegQueryValueEx(hPolicy, L"TraceLevel", nullptr, &dwPolType, (LPBYTE)&dwPolVal, &dwPolSize) == ERROR_SUCCESS
				&& dwPolType == REG_DWORD && dwPolVal >= WINEVENT_LEVEL_CRITICAL && dwPolVal <= WINEVENT_LEVEL_VERBOSE)
				*pdwLevel = dwPolVal;
		}
		if (szLogPath != nullptr && cchPath > 0)
		{
			WCHAR szPolPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API
			dwPolSize = sizeof(szPolPath);
			if (RegQueryValueEx(hPolicy, L"LogPath", nullptr, &dwPolType, (LPBYTE)szPolPath, &dwPolSize) == ERROR_SUCCESS
				&& dwPolType == REG_SZ && szPolPath[0] != L'\0')
			{
				szPolPath[MAX_PATH - 1] = L'\0';
				wcscpy_s(szLogPath, cchPath, szPolPath);
			}
		}
		if (pdwMaxSizeMB != nullptr)
		{
			dwPolSize = sizeof(DWORD);
			if (RegQueryValueEx(hPolicy, L"MaxFileSize", nullptr, &dwPolType, (LPBYTE)&dwPolVal, &dwPolSize) == ERROR_SUCCESS
				&& dwPolType == REG_DWORD && dwPolVal >= 1 && dwPolVal <= 1024)
				*pdwMaxSizeMB = dwPolVal;
		}
		if (pdwFileCounter != nullptr)
		{
			dwPolSize = sizeof(DWORD);
			if (RegQueryValueEx(hPolicy, L"FileCounter", nullptr, &dwPolType, (LPBYTE)&dwPolVal, &dwPolSize) == ERROR_SUCCESS
				&& dwPolType == REG_DWORD && dwPolVal >= 1 && dwPolVal <= 100)
				*pdwFileCounter = dwPolVal;
		}
		if (pfAutoStart != nullptr)
		{
			dwPolSize = sizeof(DWORD);
			if (RegQueryValueEx(hPolicy, L"AutoStart", nullptr, &dwPolType, (LPBYTE)&dwPolVal, &dwPolSize) == ERROR_SUCCESS
				&& dwPolType == REG_DWORD)
				*pfAutoStart = (dwPolVal != 0);
		}
		RegCloseKey(hPolicy);
	}

	return fReturn;
}

BOOL EnableLogging(BOOL fForceStartSession)
{
	struct RegEntry { LPCTSTR szSubKey; LPCTSTR szValueName; DWORD dwType; const void* pData; DWORD cbData; };

	static const TCHAR szBaseKey[] = L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider";
	static const TCHAR szGuidKey[] = L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider\\{B4866A0A-DB08-4835-A26F-414B46F3244C}";
	static const TCHAR szGuidValue[] = L"{B4866A0A-DB08-4835-A26F-414B46F3244C}";

	// Read configuration from registry
	DWORD dwConfigLevel;
	DWORD dwConfigMaxSize;
	DWORD dwConfigFileCounter;
	BOOL fConfigAutoStart;
	WCHAR szConfigPath[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer required by Win32 API

	GetTraceConfig(&dwConfigLevel, szConfigPath, MAX_PATH, &dwConfigMaxSize, &dwConfigFileCounter, &fConfigAutoStart);

	// Static values
	static const DWORD dw0 = 0;
	static const DWORD dw1 = 1;
	static const DWORD dw8 = 8;
	static const DWORD dw4864 = 4864;
	static const DWORD64 qw0 = 0;

	// Dynamic values from configuration
	DWORD dwEnableLevel = dwConfigLevel;
	DWORD dwMaxFileSize = dwConfigMaxSize;
	DWORD dwFileCounter = dwConfigFileCounter;
	DWORD dwStart = fConfigAutoStart ? 1 : 0;
	DWORD dwFileMax = dwConfigFileCounter + 3;  // Add buffer for FileMax

	// Use static array instead of vector to avoid C++ unwinding in SEH
	RegEntry entries[19];  // NOSONAR - LSASS-01: C-style array avoids C++ unwinding in SEH __try block
	DWORD dwPathSize = (DWORD)((wcslen(szConfigPath) + 1) * sizeof(WCHAR));  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity

	// Build registry entries dynamically based on configuration
	entries[0]  = { szBaseKey, L"Guid",            REG_SZ,    szGuidValue,   (DWORD)sizeof(szGuidValue) };
	entries[1]  = { szBaseKey, L"FileName",        REG_SZ,    szConfigPath,  dwPathSize };
	entries[2]  = { szBaseKey, L"FileMax",         REG_DWORD, &dwFileMax,     sizeof(DWORD) };
	entries[3]  = { szBaseKey, L"Start",           REG_DWORD, &dwStart,       sizeof(DWORD) };
	entries[4]  = { szBaseKey, L"BufferSize",      REG_DWORD, &dw8,           sizeof(DWORD) };
	entries[5]  = { szBaseKey, L"FlushTimer",      REG_DWORD, &dw0,           sizeof(DWORD) };
	entries[6]  = { szBaseKey, L"MaximumBuffers",  REG_DWORD, &dw0,           sizeof(DWORD) };
	entries[7]  = { szBaseKey, L"MinimumBuffers",  REG_DWORD, &dw0,           sizeof(DWORD) };
	entries[8]  = { szBaseKey, L"ClockType",       REG_DWORD, &dw1,           sizeof(DWORD) };
	entries[9]  = { szBaseKey, L"MaxFileSize",     REG_DWORD, &dwMaxFileSize, sizeof(DWORD) };
	entries[10] = { szBaseKey, L"LogFileMode",     REG_DWORD, &dw4864,        sizeof(DWORD) };
	entries[11] = { szBaseKey, L"FileCounter",     REG_DWORD, &dwFileCounter, sizeof(DWORD) };
	entries[12] = { szBaseKey, L"Status",          REG_DWORD, &dw0,           sizeof(DWORD) };
	entries[13] = { szGuidKey, L"Enabled",         REG_DWORD, &dw1,           sizeof(DWORD) };
	entries[14] = { szGuidKey, L"EnableLevel",     REG_DWORD, &dwEnableLevel, sizeof(DWORD) };
	entries[15] = { szGuidKey, L"EnableProperty",  REG_DWORD, &dw0,           sizeof(DWORD) };
	entries[16] = { szGuidKey, L"Status",          REG_DWORD, &dw0,           sizeof(DWORD) };
	entries[17] = { szGuidKey, L"MatchAllKeyword", REG_QWORD, &qw0,           sizeof(DWORD64) };
	entries[18] = { szGuidKey, L"MatchAnyKeyword", REG_QWORD, &qw0,           sizeof(DWORD64) };

	LONG err = 0;
	BOOL fReturn = FALSE;
	__try
	{
		for (int i = 0; i < 19; i++)  // NOSONAR - COMPLEXITY-01: raw index loop retained; SEH __leave semantics verified
		{
			err = RegSetKeyValue(HKEY_LOCAL_MACHINE, entries[i].szSubKey,
				entries[i].szValueName, entries[i].dwType, entries[i].pData, entries[i].cbData);
			if (err != ERROR_SUCCESS) __leave;
		}
		// BUG 5: only start the LIVE trace session when autostart is enabled by
		// config/GPO. The persisted autologger 'Start' value (entries[3]) is always
		// written above, but a boot task must NOT force a live VERBOSE capture when
		// policy set TraceAutoStart=Disabled. When it IS enabled, start at the
		// configured TraceLevel rather than a hardcoded VERBOSE.
		// fForceStartSession overrides the gate for an explicit operator request, which
		// would otherwise report success while starting nothing.
		if (fConfigAutoStart || fForceStartSession)
		{
			if (!StartLogging(static_cast<UCHAR>(dwConfigLevel)))
			{
				err = GetLastError();
				__leave;
			}
		}
		fReturn = TRUE;
	}
	__finally
	{
		// SEH cleanup - no action needed
	}
	SetLastError(err);
	return fReturn;
}

BOOL DisableLogging()
{
	BOOL fReturn = FALSE;
	LONG lReturn = 0;
	__try
	{
		lReturn = RegDeleteTree(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider");
		if (lReturn) __leave;
		if (!StopLogging())
		{
			lReturn = GetLastError();
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		// SEH cleanup - no action needed
	}
	SetLastError(lReturn);
	return fReturn;
}

BOOL IsLoggingEnabled()
{
	HKEY hkResult;
	DWORD Status;
	BOOL fReturn = FALSE;
	Status=RegOpenKeyEx(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EIDCredentialProvider",0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE,&hkResult);
	if (Status == ERROR_SUCCESS) {
		fReturn = TRUE;
		RegCloseKey(hkResult);
	}
	return fReturn;
}

BOOL Is64BitOS()
{
   BOOL bIs64BitOS = FALSE;

   // We check if the OS is 64 Bit
   using LPFN_ISWOW64PROCESS = BOOL (WINAPI*)(HANDLE, PBOOL);

   LPFN_ISWOW64PROCESS  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
      fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(L"kernel32"),"IsWow64Process");  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
 
   if (fnIsWow64Process && !fnIsWow64Process(GetCurrentProcess(),&bIs64BitOS))  // NOSONAR - SCOPE-01: function-pointer declaration kept separate for explicit typing
   {
      //error
   }
   return bIs64BitOS;
}

void EnableCrashDump(PTSTR szPath)
{
	DWORD dwDumpType = 2;
	DWORD dwFlag = 0;
#if defined _M_IX86
	if (Is64BitOS())
	{
		dwFlag = KEY_WOW64_64KEY;
	}
#endif
	DWORD Status;
	HKEY hkResult = nullptr;
	__try
	{
		Status=RegCreateKeyEx(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\lsass.exe",
			0,nullptr,0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE|dwFlag,nullptr,&hkResult,nullptr);
		if (Status != ERROR_SUCCESS) {MessageBoxWin32(Status); __leave;}
		Status = RegSetValueEx(hkResult,L"DumpFolder",0,REG_SZ, (PBYTE) szPath,((DWORD)sizeof(TCHAR))*((DWORD)_tcslen(szPath)+1));
		if (Status != ERROR_SUCCESS) {MessageBoxWin32(Status); __leave;}
		Status = RegSetValueEx(hkResult,L"DumpType",0, REG_DWORD, (PBYTE)&dwDumpType,sizeof(dwDumpType));
		if (Status != ERROR_SUCCESS) {MessageBoxWin32(Status); __leave;}
	}
	__finally
	{
		if (hkResult)
			RegCloseKey(hkResult);
	}
}

void DisableCrashDump()
{
	HKEY hkResult;
	DWORD Status;
	DWORD dwFlag = 0;
#if defined _M_IX86
	if (Is64BitOS())
	{
		dwFlag = KEY_WOW64_64KEY;
	}
#endif
	Status=RegOpenKeyEx(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps",0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE|dwFlag,&hkResult);
	if (Status == ERROR_SUCCESS) {
		RegDeleteKey(hkResult, L"lsass.exe");
		RegCloseKey(hkResult);
	}
}

BOOL IsCrashDumpEnabled()
{
	HKEY hkResult;
	DWORD Status;
	DWORD dwFlag = 0;
	BOOL fReturn = FALSE;
#if defined _M_IX86
	if (Is64BitOS())
	{
		dwFlag = KEY_WOW64_64KEY;
	}
#endif
	Status=RegOpenKeyEx(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\lsass.exe",0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE|dwFlag,&hkResult);
	if (Status == ERROR_SUCCESS) {
		fReturn = TRUE;
		RegCloseKey(hkResult);
	}
	return fReturn;
}