// EIDMigrateUI.h - Main header for EID Credential Migration Tool UI
// Copyright (c) 2026

#pragma once

#include <Windows.h>
#include <tchar.h>
#include <commctrl.h> // NOSONAR - INCLUDE-01: include casing per Windows SDK convention
#include <windowsx.h>
#include <string>
#include <vector>
#include <memory>

// Resource IDs
#include "resource.h"

// EIDCardLibrary includes
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/Registration.h"
#include "../EIDCardLibrary/StringConversion.h"

// EIDMigrate includes
#include "../EIDMigrate/EIDMigrate.h"
#include "../EIDMigrate/Export.h"
#include "../EIDMigrate/Import.h"
#include "../EIDMigrate/List.h"
#include "../EIDMigrate/Validate.h"
#include "../EIDMigrate/LsaClient.h"
#include "../EIDMigrate/FileCrypto.h"
#include "../EIDMigrate/Utils.h"
#include "../EIDMigrate/SecureMemory.h"

// Version information
#define EIDMIGRATEUI_APP_VERSION       L"1.0.0.1" // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define EIDMIGRATEUI_APP_COPYRIGHT     L"Copyright (C) 2026" // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#define EIDMIGRATEUI_APP_NAME          L"EID Credential Migration Tool" // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use

// Wizard page count
#define EIDMIGRATE_PAGE_COUNT          15  // NOSONAR - MACRO-01: macro constant retained for API/preprocessor use — maximum wizard pages (safety margin)

// Page indices (for programmatic navigation)
enum EIDMigratePage { // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
    PAGE_WELCOME = 0,
    PAGE_EXPORT_SELECT,
    PAGE_EXPORT_GROUPS,     // NEW: Group selection for export
    PAGE_EXPORT_CONFIRM,
    PAGE_EXPORT_PROGRESS,
    PAGE_EXPORT_COMPLETE,
    PAGE_IMPORT_SELECT,
    PAGE_IMPORT_OPTIONS,
    PAGE_IMPORT_GROUPS,     // NEW: Group selection for import
    PAGE_IMPORT_PREVIEW,
    PAGE_IMPORT_PROGRESS,
    PAGE_IMPORT_COMPLETE,
    PAGE_LIST_CREDENTIALS,
    PAGE_VALIDATE_FILE
};

// Wizard flow selection
enum WizardFlow { // NOSONAR - ENUM-01: enum kept for Win32/ABI compatibility
    FLOW_NONE = 0,
    FLOW_EXPORT,
    FLOW_IMPORT,
    FLOW_LIST,
    FLOW_VALIDATE,
    FLOW_REVOKE
};

// Shared wizard state structure
struct WIZARD_DATA { // NOSONAR - COMPLEXITY-01: field count required for wizard state; refactor deferred
    WizardFlow selectedFlow;
    BOOL fCredentialsFound;
    BOOL fFileDecrypted;
    BOOL fExportComplete;
    BOOL fImportComplete;
    DWORD dwCredentialCount;
    DWORD dwExportedCount;
    DWORD dwImportedCount;
    DWORD dwFailedCount;
    std::wstring wsOutputFile;
    std::wstring wsInputFile;
    SecureWString wsPassword;  // file passphrase; zeroed when released
    std::vector<CredentialInfo> credentials;
    std::vector<GroupInfo> groups;
    std::vector<std::wstring> SelectedGroups;  // Specific groups selected for export/import

    // Export options
    BOOL fValidateCerts;
    BOOL fIncludeGroups;

    // Import options
    BOOL fDryRun;
    BOOL fCreateUsers;
    BOOL fContinueOnError;
    BOOL fOverwrite;

    // File info (from import file header)
    std::wstring wsSourceMachine;
    std::wstring wsExportDate;
    DWORD dwFileCredentialCount;

    // Password prompts for users (username -> password map)
    std::vector<std::pair<std::wstring, std::wstring>> userPasswords;

    WIZARD_DATA() :
        selectedFlow(FLOW_NONE), // NOSONAR - INIT-01: member initialized in constructor init list
        fCredentialsFound(FALSE), // NOSONAR - INIT-01: member initialized in constructor init list
        fFileDecrypted(FALSE), // NOSONAR - INIT-01: member initialized in constructor init list
        fExportComplete(FALSE), // NOSONAR - INIT-01: member initialized in constructor init list
        fImportComplete(FALSE), // NOSONAR - INIT-01: member initialized in constructor init list
        dwCredentialCount(0), // NOSONAR - INIT-01: member initialized in constructor init list
        dwExportedCount(0), // NOSONAR - INIT-01: member initialized in constructor init list
        dwImportedCount(0), // NOSONAR - INIT-01: member initialized in constructor init list
        dwFailedCount(0), // NOSONAR - INIT-01: member initialized in constructor init list
        fValidateCerts(FALSE), // NOSONAR - INIT-01: member initialized in constructor init list
        fIncludeGroups(TRUE), // NOSONAR - INIT-01: member initialized in constructor init list
        fDryRun(TRUE), // NOSONAR - INIT-01: member initialized in constructor init list
        fCreateUsers(FALSE), // NOSONAR - INIT-01: member initialized in constructor init list
        fContinueOnError(FALSE), // NOSONAR - INIT-01: member initialized in constructor init list
        fOverwrite(FALSE), // NOSONAR - INIT-01: member initialized in constructor init list
        dwFileCredentialCount(0) // NOSONAR - INIT-01: member initialized in constructor init list
    {}

    void Reset() {
        selectedFlow = FLOW_NONE;
        fCredentialsFound = FALSE;
        fFileDecrypted = FALSE;
        fExportComplete = FALSE;
        fImportComplete = FALSE;
        dwCredentialCount = 0;
        dwExportedCount = 0;
        dwImportedCount = 0;
        dwFailedCount = 0;
        wsOutputFile.clear();
        wsInputFile.clear();
        SecureClear(wsPassword);
        credentials.clear();
        groups.clear();
        SelectedGroups.clear();
        fValidateCerts = FALSE;
        fIncludeGroups = TRUE;
        fDryRun = TRUE;
        fCreateUsers = FALSE;
        fContinueOnError = FALSE;
        fOverwrite = FALSE;
        dwFileCredentialCount = 0;
        wsSourceMachine.clear();
        wsExportDate.clear();
        userPasswords.clear();
    }
};

// Global wizard state
extern WIZARD_DATA g_wizardData; // NOSONAR - GLOBAL-01: global state assigned at runtime
extern HINSTANCE g_hinst; // NOSONAR - GLOBAL-01: pointer assigned at runtime
extern HWND g_hwndWizard; // NOSONAR - GLOBAL-01: pointer assigned at runtime
extern WizardFlow g_currentFlow;  // NOSONAR - GLOBAL-01: assigned at runtime — tracks current wizard flow (export/import)

// Message constants for worker thread communication
#define WM_USER_PROGRESS        (WM_USER + 100)
#define WM_USER_COMPLETE        (WM_USER + 101)
#define WM_USER_ERROR           (WM_USER + 102)
#define WM_USER_NAVIGATE        (WM_USER + 103)  // Navigate to specific page

// Forward declarations of dialog procedures
INT_PTR CALLBACK WndProc_01_Welcome(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_02_ExportSelect(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_03_ExportConfirm(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_04_ExportProgress(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_05_ExportComplete(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_06_ImportSelect(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_07_ImportOptions(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_08_ImportPreview(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_09_ImportProgress(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_10_ImportComplete(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_11_ListCredentials(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_12_ValidateFile(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_14_GroupSelect(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK WndProc_Progress(HWND, UINT, WPARAM, LPARAM);

// Password prompt dialog
BOOL ShowPasswordPromptDialog(
    _In_ HWND hwndParent,
    _In_ const std::wstring& wsUsername,
    _Out_ std::wstring& wsPassword,
    _Out_ BOOL& pfSkipped);

HRESULT SetUserPassword(
    _In_ const std::wstring& wsUsername,
    _In_ const std::wstring& wsPassword);

// Utility functions
BOOL IsUserAdmin();
std::wstring LoadStringResource(UINT uID);
void SetWindowIcon(HWND hwnd, int iconId = 0);
HRESULT GetCredentialCount(DWORD* pdwCount);
void FormatCredentialHash(const std::wstring& fullHash, std::wstring& truncated);
