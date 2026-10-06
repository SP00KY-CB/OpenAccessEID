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
#include <MsiQuery.h>

#pragma comment(lib,"Msi.lib")

#include "../EIDCardLibrary/Registration.h"
#include "../EIDCardLibrary/Tracing.h"

extern "C"
{
	
	void NTAPI DllRegister()
	{
		OpenAccessEIDPackageDllRegister();
		EIDCredentialProviderDllRegister();
		EIDPasswordChangeNotificationDllRegister();
		EIDConfigurationWizardDllRegister();
		RegisterTheSecurityPackage();
	}

	void NTAPI DllUnRegister()
	{
		OpenAccessEIDPackageDllUnRegister();
		EIDCredentialProviderDllUnRegister();
		EIDPasswordChangeNotificationDllUnRegister();
		EIDConfigurationWizardDllUnRegister();
		UnRegisterTheSecurityPackage();
	}

	void NTAPI DllEnableLogging()
	{
		// Explicit operator action: start the live session too, rather than only writing the
		// autologger config and reporting success while no trace is actually running. Since
		// EIDLogManager was removed this verb is the only interactive way to turn tracing on.
		if (!EnableLogging(TRUE))
		{
			MessageBoxWin32(GetLastError());
		}
		else
		{
			MessageBoxWin32(0);
		}
	}

	void NTAPI DllDisableLogging()
	{
		if (!DisableLogging())
		{
			MessageBoxWin32(GetLastError());
		}
		else
		{
			MessageBoxWin32(0);
		}
	}

	// Silent variant for unattended use (e.g. a scheduled task). Re-applies the ETW autologger
	// configuration from the (now Group-Policy-aware) trace config with no UI, so ETW settings
	// managed via Group Policy take effect without EIDLogManager. rundll32-compatible signature.
	void CALLBACK DllApplyTraceConfigW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)  // NOSONAR - API-01: rundll32 entry-point signature
	{
		UNREFERENCED_PARAMETER(hwnd);
		UNREFERENCED_PARAMETER(hinst);
		UNREFERENCED_PARAMETER(lpszCmdLine);
		UNREFERENCED_PARAMETER(nCmdShow);
		EnableLogging();
	}

	int NTAPI Commit(MSIHANDLE hInstall)
	{
		UNREFERENCED_PARAMETER(hInstall);
		DWORD dwError = 0;
		int ret = ERROR_INSTALL_FAILURE;
		__try
		{
			if (!RegisterTheSecurityPackage())
			{
				dwError = GetLastError();
				__leave;
			}
			ret = ERROR_SUCCESS;
		}
		__finally
		{
			if (dwError == ERROR_FAIL_NOACTION_REBOOT)
			{
				// a deferred action cannot order a reboot through MSI functions (setmode, set property, ...)
				// hopefully, Wix has a immediate action which checks an ATOM to set the reboot flag
				GlobalAddAtom(TEXT("WcaDeferredActionRequiresReboot"));
				ret = ERROR_SUCCESS;
			}
			else if (dwError != 0)
			{
				MessageBoxWin32(dwError);
			}
		}
		return ret;
	}

	int NTAPI Uninstall(MSIHANDLE hInstall)
	{
		UNREFERENCED_PARAMETER(hInstall);
		DWORD dwError = 0;
		int ret = ERROR_INSTALL_FAILURE;
		__try
		{
			// Unregistration only. Stored credentials are kept, as they are by DllUnRegister:
			// removing every user's enrolment is the explicit, opt-in CleanupLsaCredentials
			// action, never a side effect of uninstalling.
			// this function is unimplemented and trigger the reboot,
			// but call it anyway
			if (!UnRegisterTheSecurityPackage())
			{
				dwError = GetLastError();
				__leave;
			}
			ret = ERROR_SUCCESS;
		}
		__finally
		{
			if (dwError == ERROR_FAIL_NOACTION_REBOOT)
			{
				GlobalAddAtom(TEXT("WcaDeferredActionRequiresReboot"));
				ret = ERROR_SUCCESS;
			}
			else if (dwError != 0)
			{
				MessageBoxWin32(dwError);
			}
		}
		return ret;
	}
}