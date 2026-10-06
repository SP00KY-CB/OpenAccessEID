// WorkerThread.h - Background thread worker for async operations
// Copyright (c) 2026

#pragma once

#include <Windows.h>
#include <string>
#include <functional>
#include <vector>
#include "../EIDMigrate/SecureMemory.h"

// Worker thread context
struct WORKER_CONTEXT {
    HWND hwndParent;           // Parent window to send messages to
    UINT uProgressMsg;         // Message for progress updates
    UINT uCompleteMsg;         // Message for completion
    UINT uErrorMsg;            // Message for errors

    // Operation-specific data
    std::wstring* pwszOutputFile;
    std::wstring* pwszInputFile;
    SecureWString* pwszPassword;
    BOOL* pfValidateCerts;
    BOOL* pfIncludeGroups;
    BOOL* pfDryRun;
    BOOL* pfCreateUsers;
    BOOL* pfContinueOnError;
    DWORD* pdwResultCount;
    HRESULT* phrResult;

    // User passwords from prompts (username -> password map)
    std::vector<std::pair<std::wstring, std::wstring>>* pUserPasswords;

    // Selected groups for export/import
    std::vector<std::wstring>* pSelectedGroups;

    WORKER_CONTEXT() :
        hwndParent(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        uProgressMsg(0),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        uCompleteMsg(0),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        uErrorMsg(0),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pwszOutputFile(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pwszInputFile(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pwszPassword(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pfValidateCerts(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pfIncludeGroups(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pfDryRun(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pfCreateUsers(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pfContinueOnError(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pdwResultCount(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        phrResult(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pUserPasswords(nullptr),  // NOSONAR - INIT-01: constructor initializer list retained for clarity
        pSelectedGroups(nullptr)  // NOSONAR - INIT-01: constructor initializer list retained for clarity
    {}
};

// Progress data sent with WM_USER_PROGRESS
struct PROGRESS_DATA {
    DWORD dwCurrent;
    DWORD dwTotal;
    std::wstring wsStatus;

    PROGRESS_DATA() : dwCurrent(0), dwTotal(0) {}
    PROGRESS_DATA(DWORD c, DWORD t, const std::wstring& s)
        : dwCurrent(c), dwTotal(t), wsStatus(s) {}
};

// Completion data sent with WM_USER_COMPLETE
struct COMPLETE_DATA {
    HRESULT hrResult;
    DWORD dwItemCount;
    std::wstring wsMessage;

    COMPLETE_DATA() : hrResult(S_OK), dwItemCount(0) {}
    COMPLETE_DATA(HRESULT hr, DWORD c, const std::wstring& m)
        : hrResult(hr), dwItemCount(c), wsMessage(m) {}
};

// Error data sent with WM_USER_ERROR
struct ERROR_DATA {
    HRESULT hrResult;
    DWORD dwErrorCode;
    std::wstring wsMessage;

    ERROR_DATA() : hrResult(E_FAIL), dwErrorCode(0) {}
    ERROR_DATA(HRESULT hr, DWORD ec, const std::wstring& m)
        : hrResult(hr), dwErrorCode(ec), wsMessage(m) {}
};

// Worker thread entry points
DWORD WINAPI ExportWorker(LPVOID lpParam); // NOSONAR - Windows API requires LPVOID (void*) for thread functions
DWORD WINAPI ImportWorker(LPVOID lpParam); // NOSONAR - Windows API requires LPVOID (void*) for thread functions
DWORD WINAPI EnumerateWorker(LPVOID lpParam); // NOSONAR - Windows API requires LPVOID (void*) for thread functions
DWORD WINAPI ValidateFileWorker(LPVOID lpParam); // NOSONAR - Windows API requires LPVOID (void*) for thread functions

// Helper to send progress to parent window
void SendProgress(HWND hwnd, UINT uMsg, DWORD dwCurrent, DWORD dwTotal, const std::wstring& wsStatus = L"");

// Helper to send completion to parent window
void SendComplete(HWND hwnd, UINT uMsg, HRESULT hr, DWORD dwCount, const std::wstring& wsMessage);

// Helper to send error to parent window
void SendError(HWND hwnd, UINT uMsg, HRESULT hr, DWORD dwErrorCode, const std::wstring& wsMessage);
