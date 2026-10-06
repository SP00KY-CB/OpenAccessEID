#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#include "EIDConfigurationWizardElevated.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDConfigurationWizard/Common.h"

HINSTANCE g_hinst;  // NOSONAR - RUNTIME-01: HINSTANCE set by Windows at WinMain entry

INT_PTR CALLBACK	WndProc_RemovePolicy(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK	WndProc_ForcePolicy(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	g_hinst = hInstance;
	int iNumArgs;
	LPWSTR *pszCommandLine =  CommandLineToArgvW(lpCmdLine,&iNumArgs);
	if (!pszCommandLine)
	{
		return 1;
	}
	const BOOL fRemovePolicy = iNumArgs > 0 && _tcscmp(pszCommandLine[0],TEXT("DIALOGREMOVEPOLICY")) == 0;
	LocalFree(pszCommandLine);
	if (fRemovePolicy)
	{
		DialogBox(g_hinst, MAKEINTRESOURCE(IDD_DIALOGREMOVEPOLICY), nullptr, WndProc_RemovePolicy);
		return 0;
	} 
	else //if (_tcscmp(pszCommandLine[0],TEXT("DIALOGFORCEPOLICY")) == 0)
	{
		DialogBox(g_hinst, MAKEINTRESOURCE(IDD_DIALOGFORCEPOLICY), nullptr, WndProc_ForcePolicy);
		return 0;
	}
	return 0;
}