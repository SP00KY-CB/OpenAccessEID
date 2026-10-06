#pragma once

// Directory-trust helpers for C:\ProgramData\OpenAccessEID, shared by the LSASS-side
// logger (EIDCardLibrary, via CSVConfig.h) and the EIDTraceConsumer service, which
// includes this header by relative path. Self-contained: Win32 only, no other
// EIDCardLibrary dependencies.

#include <Windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <wchar.h>

#ifndef EID_CSV_CONFIG_DIR
#define EID_CSV_CONFIG_DIR          L"C:\\ProgramData\\OpenAccessEID"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
#endif

// ================================================================
// M5: Restrictive DACL for the log/config directory.
// Full control to SYSTEM (SY) and Administrators (BA); Read&Execute only
// (0x1200a9, no create/write) to Users (BU). PAI = protected, no inheritance
// from the (Users-writable) ProgramData parent. Prevents a low-privileged
// user from planting files/symlinks that a SYSTEM writer would follow.
// ================================================================
#define EID_LOG_DIR_SDDL            L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use

// Build a SECURITY_ATTRIBUTES carrying the restrictive log-dir DACL above.
// On success returns TRUE, fills *psa and hands back the security descriptor in
// *ppSD; the caller MUST LocalFree(*ppSD) once CreateDirectoryW has returned.
// On failure returns FALSE and the caller should fall back to a NULL SD.
inline BOOL BuildLogDirSecurityAttributes(SECURITY_ATTRIBUTES* psa, PSECURITY_DESCRIPTOR* ppSD)
{
    if (ppSD)
        *ppSD = nullptr;
    if (!psa || !ppSD)
        return FALSE;

    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            EID_LOG_DIR_SDDL, SDDL_REVISION_1, &pSD, nullptr))
        return FALSE;

    psa->nLength = sizeof(SECURITY_ATTRIBUTES);
    psa->lpSecurityDescriptor = pSD;
    psa->bInheritHandle = FALSE;
    *ppSD = pSD;
    return TRUE;
}

// ================================================================
// Trust check for the product directory, the log directory and logging.json.
// C:\ProgramData lets any user create subdirectories, so before the installer (or a
// SYSTEM writer) creates C:\ProgramData\OpenAccessEID an unprivileged user can create
// it themselves, own it, plant logging.json in it, or turn it into a junction. SYSTEM
// code (LSASS, LogonUI, the trace consumer) must only trust an object that
//   (a) is not a reparse point (junction, mount point or symlink), and
//   (b) is owned by SYSTEM or Administrators - an unprivileged user can neither create
//       such an object nor take ownership of one.
// The object itself is opened with FILE_FLAG_OPEN_REPARSE_POINT, so the check never
// follows a link; FILE_FLAG_BACKUP_SEMANTICS lets the same call open a directory.
// ================================================================
inline BOOL EID_IsAdminOwnedNonReparse(PCWSTR pwszPath)
{
    if (!pwszPath || pwszPath[0] == L'\0')
        return FALSE;

    HANDLE hObject = CreateFileW(pwszPath, READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (hObject == INVALID_HANDLE_VALUE)
        return FALSE;

    BOOL fTrusted = FALSE;
    BY_HANDLE_FILE_INFORMATION info = {};
    if (GetFileInformationByHandle(hObject, &info) &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
    {
        PSID pOwner = nullptr;
        PSECURITY_DESCRIPTOR pOwnerSD = nullptr;
        if (GetSecurityInfo(hObject, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                &pOwner, nullptr, nullptr, nullptr, &pOwnerSD) == ERROR_SUCCESS)
        {
            fTrusted = (pOwner != nullptr && IsValidSid(pOwner) &&
                (IsWellKnownSid(pOwner, WinLocalSystemSid) ||
                 IsWellKnownSid(pOwner, WinBuiltinAdministratorsSid))) ? TRUE : FALSE;
            LocalFree(pOwnerSD);
        }
    }
    CloseHandle(hObject);
    return fTrusted;
}

// Create ONE directory with the restrictive DACL above, or - when it already exists -
// re-apply that DACL. CreateDirectoryW ignores its security attributes for an existing
// directory, so on every machine upgraded from an earlier build the directory would
// otherwise keep its inherited (Users-writable) ProgramData ACL and M5 would never
// actually take effect where it matters.
//
// An existing directory is first vetted with EID_IsAdminOwnedNonReparse. A directory a
// user pre-created (and owns), or a junction, is NOT "fixed up" by rewriting its DACL as
// SYSTEM - that would adopt the attacker's object (and SetNamedSecurityInfoW follows
// junctions). It is refused instead, and the caller must not write there.
// Returns TRUE only when the directory is safe to write to.
inline BOOL EID_EnsureSecuredDirectory(PCWSTR pwszDir)
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!BuildLogDirSecurityAttributes(&sa, &pSD))
    {
        // No SD to apply (out of memory): accept only a directory that is already trusted.
        CreateDirectoryW(pwszDir, nullptr);
        return EID_IsAdminOwnedNonReparse(pwszDir);
    }

    BOOL fSafe = FALSE;
    if (CreateDirectoryW(pwszDir, &sa))
    {
        // Created just now by this (SYSTEM/admin) process with the protected DACL.
        fSafe = TRUE;
    }
    else if (GetLastError() == ERROR_ALREADY_EXISTS && EID_IsAdminOwnedNonReparse(pwszDir))
    {
        PACL pDacl = nullptr;
        BOOL fDaclPresent = FALSE;
        BOOL fDaclDefaulted = FALSE;
        // SetNamedSecurityInfoW takes a non-const path; hand it a local copy rather
        // than casting away const. It is used (not the handle-based SetSecurityInfo)
        // because it also pushes the protected DACL down to existing children.
        WCHAR szDirCopy[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
        if (GetSecurityDescriptorDacl(pSD, &fDaclPresent, &pDacl, &fDaclDefaulted) && fDaclPresent &&
            wcsncpy_s(szDirCopy, MAX_PATH, pwszDir, _TRUNCATE) == 0)
        {
            // PROTECTED_DACL_SECURITY_INFORMATION matches the SDDL's "PAI" - it severs
            // inheritance from ProgramData rather than merging with it. Only a directory
            // whose DACL was actually replaced counts as safe: an admin-owned directory
            // that still carries an inherited Users-writable ACL is not.
            fSafe = (SetNamedSecurityInfoW(szDirCopy, SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, pDacl, nullptr) == ERROR_SUCCESS) ? TRUE : FALSE;
        }
    }
    LocalFree(pSD);
    return fSafe;
}

// Secure the log directory - and, for a directory inside the product directory, the
// product directory C:\ProgramData\OpenAccessEID first: a log directory is only as
// trustworthy as its parent. Returns FALSE when either is missing and cannot be
// created, is a reparse point, or is not owned by SYSTEM/Administrators; the caller
// must then disable file logging rather than write, rotate or delete anything there.
inline BOOL EnsureLogDirSecured(PCWSTR pwszDir)
{
    if (!pwszDir || pwszDir[0] == L'\0')
        return FALSE;

    const size_t cchBase = ARRAYSIZE(EID_CSV_CONFIG_DIR) - 1;
    if (_wcsnicmp(pwszDir, EID_CSV_CONFIG_DIR, cchBase) == 0 && pwszDir[cchBase] == L'\\')
    {
        if (!EID_EnsureSecuredDirectory(EID_CSV_CONFIG_DIR))
            return FALSE;
    }
    return EID_EnsureSecuredDirectory(pwszDir);
}

// Rotation guard: TRUE when the directory holding pwszLogPath (and, for a path inside
// the product directory, the product directory itself) is a real directory owned by
// SYSTEM/Administrators. Checked immediately before MoveFileExW/DeleteFileW so that a
// directory swapped for a junction since the log was opened cannot turn rotation into
// an arbitrary SYSTEM rename/delete elsewhere on the volume.
inline BOOL EID_IsLogDirSafeForRotation(PCWSTR pwszLogPath)
{
    if (!pwszLogPath || pwszLogPath[0] == L'\0')
        return FALSE;

    WCHAR szDir[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    if (wcsncpy_s(szDir, MAX_PATH, pwszLogPath, _TRUNCATE) != 0)  // over-long (STRUNCATE) or invalid: refuse
        return FALSE;
    WCHAR* pLastSlash = wcsrchr(szDir, L'\\');
    if (!pLastSlash)
        return FALSE;
    *pLastSlash = L'\0';

    const size_t cchBase = ARRAYSIZE(EID_CSV_CONFIG_DIR) - 1;
    if (_wcsnicmp(szDir, EID_CSV_CONFIG_DIR, cchBase) == 0 && szDir[cchBase] == L'\\')
    {
        if (!EID_IsAdminOwnedNonReparse(EID_CSV_CONFIG_DIR))
            return FALSE;
    }
    return EID_IsAdminOwnedNonReparse(szDir);
}
