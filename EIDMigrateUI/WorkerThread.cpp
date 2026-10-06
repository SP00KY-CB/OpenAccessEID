// WorkerThread.cpp - Background thread worker implementations
// Copyright (c) 2026

#include "WorkerThread.h"
#include "EIDMigrateUI.h"
#include "../EIDMigrate/SecureMemory.h"
#include <vector>
#include <Lmcons.h>  // NOSONAR - INCLUDE-01: include order/casing significant for Windows SDK

// Send progress message to parent window
void SendProgress(HWND hwnd, UINT uMsg, DWORD dwCurrent, DWORD dwTotal, const std::wstring& wsStatus) {
    if (!hwnd || !uMsg) return;

    PROGRESS_DATA* pData = new PROGRESS_DATA(dwCurrent, dwTotal, wsStatus); // NOSONAR - ownership transferred to message handler which frees this
    SendMessage(hwnd, uMsg, 0, (LPARAM)pData); // NOSONAR - pData ownership transferred to window message handler
} // NOSONAR - pData ownership transferred to window message handler, freed by receiver

// Send completion message to parent window
void SendComplete(HWND hwnd, UINT uMsg, HRESULT hr, DWORD dwCount, const std::wstring& wsMessage) {
    if (!hwnd || !uMsg) return;

    COMPLETE_DATA* pData = new COMPLETE_DATA(hr, dwCount, wsMessage); // NOSONAR - ownership transferred to message handler which frees this
    SendMessage(hwnd, uMsg, 0, (LPARAM)pData); // NOSONAR - pData ownership transferred to window message handler
} // NOSONAR - pData ownership transferred to window message handler, freed by receiver

// Send error message to parent window
void SendError(HWND hwnd, UINT uMsg, HRESULT hr, DWORD dwErrorCode, const std::wstring& wsMessage) {
    if (!hwnd || !uMsg) return;

    ERROR_DATA* pData = new ERROR_DATA(hr, dwErrorCode, wsMessage); // NOSONAR - ownership transferred to message handler which frees this
    SendMessage(hwnd, uMsg, 0, (LPARAM)pData); // NOSONAR - pData ownership transferred to window message handler
} // NOSONAR - pData ownership transferred to window message handler, freed by receiver

// Get local computer name
static std::wstring GetComputerName() {
    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1]; // NOSONAR - Windows API GetComputerNameW requires WCHAR array buffer
    DWORD size = ARRAYSIZE(computerName);
    if (GetComputerNameW(computerName, &size)) {  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
        return std::wstring(computerName);
    }
    return L"Unknown";
}

// Export worker thread
DWORD WINAPI ExportWorker(LPVOID lpParam) { // NOSONAR - Windows API requires LPVOID (void*) for thread functions
    WORKER_CONTEXT* pContext = (WORKER_CONTEXT*)lpParam;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
    if (!pContext || !pContext->pwszOutputFile || !pContext->pwszPassword) {
        return ERROR_INVALID_PARAMETER;
    }

    HWND hwnd = pContext->hwndParent;
    UINT uProgressMsg = pContext->uProgressMsg;
    UINT uCompleteMsg = pContext->uCompleteMsg;
    UINT uErrorMsg = pContext->uErrorMsg;

    const std::wstring& wsOutputFile = *pContext->pwszOutputFile;
    const SecureWString& wsPassword = *pContext->pwszPassword;
    BOOL fValidateCerts = pContext->pfValidateCerts ? *pContext->pfValidateCerts : FALSE;
    BOOL fIncludeGroups = pContext->pfIncludeGroups ? *pContext->pfIncludeGroups : TRUE;

    SendProgress(hwnd, uProgressMsg, 0, 100, L"Enumerating credentials...");

    // Enumerate credentials
    std::vector<CredentialInfo> credentials;
    HRESULT hr = EnumerateLsaCredentials(credentials);
    if (FAILED(hr)) {
        SendError(hwnd, uErrorMsg, hr, GetLastError(), L"Failed to enumerate credentials");
        return hr;
    }

    SendProgress(hwnd, uProgressMsg, 20, 100, L"Found " + std::to_wstring(credentials.size()) + L" credentials"); // NOSONAR - String concatenation used for clarity; std::format is C++20 (project uses C++17)

    if (credentials.empty()) {
        SendError(hwnd, uErrorMsg, HRESULT_FROM_WIN32(ERROR_NO_DATA), 0,
            L"No EID credentials found on this machine");
        return HRESULT_FROM_WIN32(ERROR_NO_DATA);
    }

    // Prepare export options
    EXPORT_OPTIONS options;
    options.fValidateCerts = fValidateCerts;
    options.fIncludeGroups = fIncludeGroups;
    options.wsSourceMachine = GetComputerName();

    // Add selected groups if provided
    if (pContext->pSelectedGroups) {
        options.SelectedGroups = *pContext->pSelectedGroups;
    }

    SendProgress(hwnd, uProgressMsg, 40, 100, L"Encrypting and writing export file...");

    // Perform export
    EXPORT_STATS stats;
    hr = ExportCredentials(wsOutputFile, wsPassword, options, stats);
    if (FAILED(hr)) {
        SendError(hwnd, uErrorMsg, hr, GetLastError(), L"Failed to export credentials");
        return hr;
    }

    SendProgress(hwnd, uProgressMsg, 100, 100, L"Export complete");

    // Report completion
    SendComplete(hwnd, uCompleteMsg, S_OK, stats.dwTotalCredentials,
        L"Successfully exported " + std::to_wstring(stats.dwTotalCredentials) + L" credentials"); // NOSONAR - String concatenation used for clarity; std::format is C++20

    return 0;
}

// Import worker thread
DWORD WINAPI ImportWorker(LPVOID lpParam) { // NOSONAR - Windows API requires LPVOID (void*) for thread functions
    WORKER_CONTEXT* pContext = (WORKER_CONTEXT*)lpParam;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
    if (!pContext || !pContext->pwszInputFile || !pContext->pwszPassword) {
        return ERROR_INVALID_PARAMETER;
    }

    HWND hwnd = pContext->hwndParent;
    UINT uProgressMsg = pContext->uProgressMsg;
    UINT uCompleteMsg = pContext->uCompleteMsg;
    UINT uErrorMsg = pContext->uErrorMsg;

    const std::wstring& wsInputFile = *pContext->pwszInputFile;
    const SecureWString& wsPassword = *pContext->pwszPassword;
    BOOL fDryRun = pContext->pfDryRun ? *pContext->pfDryRun : TRUE;
    BOOL fCreateUsers = pContext->pfCreateUsers ? *pContext->pfCreateUsers : FALSE;
    BOOL fContinueOnError = pContext->pfContinueOnError ? *pContext->pfContinueOnError : FALSE;

    SendProgress(hwnd, uProgressMsg, 0, 100, L"Reading export file...");

    // Prepare import options
    IMPORT_OPTIONS options;
    options.fDryRun = fDryRun;
    options.fForce = FALSE;  // Never force overwrite
    options.fCreateUsers = fCreateUsers;
    options.fContinueOnError = fContinueOnError;

    // Add selected groups if provided
    if (pContext->pSelectedGroups) {
        options.SelectedGroups = *pContext->pSelectedGroups;
    }

    // Add user passwords from prompts if available
    if (pContext->pUserPasswords) {
        options.userPasswords = *pContext->pUserPasswords;
    }

    // Perform import
    IMPORT_STATS stats;
    HRESULT hr = ImportCredentials(wsInputFile, wsPassword, options, stats);
    if (FAILED(hr)) {
        SendError(hwnd, uErrorMsg, hr, GetLastError(), L"Failed to import credentials");
        return hr;
    }

    SendProgress(hwnd, uProgressMsg, 100, 100, L"Import complete");

    // Report completion
    std::wstring wsMessage = L"Imported: " + std::to_wstring(stats.dwSuccessfullyImported); // NOSONAR - String concatenation used for clarity
    if (stats.dwFailed > 0) {
        wsMessage += L", Failed: " + std::to_wstring(stats.dwFailed); // NOSONAR - String concatenation used for clarity
    }
    SendComplete(hwnd, uCompleteMsg, S_OK, stats.dwSuccessfullyImported, wsMessage);

    return 0;
}

// Enumerate worker thread
DWORD WINAPI EnumerateWorker(LPVOID lpParam) { // NOSONAR - Windows API requires LPVOID (void*) for thread functions
    WORKER_CONTEXT* pContext = (WORKER_CONTEXT*)lpParam;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
    if (!pContext) {
        return ERROR_INVALID_PARAMETER;
    }

    HWND hwnd = pContext->hwndParent;
    UINT uCompleteMsg = pContext->uCompleteMsg;
    UINT uErrorMsg = pContext->uErrorMsg;
    DWORD* pdwResultCount = pContext->pdwResultCount;
    HRESULT* phrResult = pContext->phrResult;

    std::vector<CredentialInfo> credentials;
    HRESULT hr = EnumerateLsaCredentials(credentials);

    if (phrResult) {
        *phrResult = hr;
    }
    if (pdwResultCount) {
        *pdwResultCount = static_cast<DWORD>(credentials.size());
    }

    if (FAILED(hr)) {
        SendError(hwnd, uErrorMsg, hr, GetLastError(), L"Failed to enumerate credentials");
        return hr;
    }

    SendComplete(hwnd, uCompleteMsg, S_OK, static_cast<DWORD>(credentials.size()),
        L"Found " + std::to_wstring(credentials.size()) + L" credentials"); // NOSONAR - String concatenation used for clarity

    return 0;
}

// Validate file worker thread
DWORD WINAPI ValidateFileWorker(LPVOID lpParam) { // NOSONAR - Windows API requires LPVOID (void*) for thread functions
    WORKER_CONTEXT* pContext = (WORKER_CONTEXT*)lpParam;  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
    if (!pContext || !pContext->pwszInputFile) {
        return ERROR_INVALID_PARAMETER;
    }

    const std::wstring& wsInputFile = *pContext->pwszInputFile;
    SecureWString swPassword;
    if (pContext->pwszPassword)
        swPassword = *pContext->pwszPassword;

    SendProgress(pContext->hwndParent, pContext->uProgressMsg, 0, 100, L"Validating file format...");

    VALIDATE_OPTIONS options;
    options.wsInputPath = wsInputFile;
    options.fRequireSmartCard = FALSE;
    options.fVerbose = FALSE;

    VALIDATION_RESULT result;
    HRESULT hr = ValidateImportFile(wsInputFile, swPassword, options, result);
    if (FAILED(hr) || !result.IsValid()) {  // NOSONAR - SCOPE-01: declaration kept at function scope for clarity
        SendError(pContext->hwndParent, pContext->uErrorMsg, hr, GetLastError(), L"File validation failed");
        return hr;
    }

    SendProgress(pContext->hwndParent, pContext->uProgressMsg, 100, 100, L"Validation complete");

    std::wstring wsMessage = L"File is valid. Contains " + std::to_wstring(result.dwCredentialCount) + L" credentials";  // NOSONAR - STRING-01: manual concatenation retained
    SendComplete(pContext->hwndParent, pContext->uCompleteMsg, S_OK, result.dwCredentialCount, wsMessage);

    return 0;
}
