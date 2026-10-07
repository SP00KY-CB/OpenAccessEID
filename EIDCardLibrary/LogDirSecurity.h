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
// Full control to SYSTEM (SY) and Administrators (BA), inherited by everything
// below. Users (BU) may list the folder (0x1200a9, CI only: folders, not files)
// but not read the files in it: the logs record logon activity, PIN failures
// and attempts left, and a user holding a read handle on a log blocked its
// rotation. PAI = protected, no inheritance from the (Users-writable)
// ProgramData parent. Prevents a low-privileged user from planting
// files/symlinks that a SYSTEM writer would follow. The installer applies the
// same DACL (OAEID_DATA_DIR_SDDL in Installer/Installerx64.nsi).
// ================================================================
#define EID_LOG_DIR_SDDL            L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;CI;0x1200a9;;;BU)"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use
// Explicit DACL for a log file that still carries the Users read ACE inherited
// from the previous directory DACL.
#define EID_LOG_FILE_SDDL           L"D:P(A;;FA;;;SY)(A;;FA;;;BA)"  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use

// Room a log path must leave below MAX_PATH for what is appended to it or to its
// directory: ".NNN" for a rotated generation, or "diagnostics.log".
#define EID_LOG_PATH_RESERVE        32  // NOSONAR - MACRO-01: Windows-style macro constant retained for API/preprocessor use

// A configured log path (logging.json, the registry or Group Policy) decides which
// directory a SYSTEM writer re-secures and renames and deletes in, so it is held to
// the product directory: a fully qualified X:\ path under EID_CSV_CONFIG_DIR, with no
// UNC or device prefix, no traversal, no forward slash and no alternate data stream,
// short enough for the suffixes above. Anything else is refused and the default used.
inline BOOL EID_IsAcceptableLogPath(PCWSTR pwszPath)
{
    if (!pwszPath)
        return FALSE;
    const size_t cch = wcsnlen(pwszPath, MAX_PATH);
    if (cch < 4 || cch >= MAX_PATH - EID_LOG_PATH_RESERVE)
        return FALSE;
    if (pwszPath[0] == L'\\' || pwszPath[1] != L':' || pwszPath[2] != L'\\')
        return FALSE;
    if (wcsstr(pwszPath, L"..") || wcschr(pwszPath, L'/') || wcschr(pwszPath + 2, L':'))
        return FALSE;
    const size_t cchRoot = ARRAYSIZE(EID_CSV_CONFIG_DIR) - 1;
    return (cch > cchRoot + 1 && _wcsnicmp(pwszPath, EID_CSV_CONFIG_DIR, cchRoot) == 0 &&
            pwszPath[cchRoot] == L'\\') ? TRUE : FALSE;
}

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
// The same check on an object already open (with READ_CONTROL | FILE_READ_ATTRIBUTES).
inline BOOL EID_IsAdminOwnedNonReparseHandle(HANDLE hObject)
{
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
    return fTrusted;
}

inline BOOL EID_IsAdminOwnedNonReparse(PCWSTR pwszPath)
{
    if (!pwszPath || pwszPath[0] == L'\0')
        return FALSE;

    HANDLE hObject = CreateFileW(pwszPath, READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (hObject == INVALID_HANDLE_VALUE)
        return FALSE;

    const BOOL fTrusted = EID_IsAdminOwnedNonReparseHandle(hObject);
    CloseHandle(hObject);
    return fTrusted;
}

// TRUE when the DACL has an ACE for Users (BU) that files inherit - the layout
// before the log files were closed to Users.
inline BOOL EID_DaclLetsUsersReadFiles(PACL pDacl)
{
    if (!pDacl)
        return FALSE;
    for (DWORD i = 0; i < pDacl->AceCount; i++)
    {
        PACE_HEADER pHeader = nullptr;
        if (!GetAce(pDacl, i, reinterpret_cast<LPVOID*>(&pHeader)) || !pHeader ||
            pHeader->AceType != ACCESS_ALLOWED_ACE_TYPE || (pHeader->AceFlags & OBJECT_INHERIT_ACE) == 0)
            continue;
        PSID pSid = &reinterpret_cast<ACCESS_ALLOWED_ACE*>(pHeader)->SidStart;
        if (IsValidSid(pSid) && IsWellKnownSid(pSid, WinBuiltinUsersSid))
            return TRUE;
    }
    return FALSE;
}

// Give each existing file directly in the (pinned) directory an explicit
// SYSTEM/Administrators-only DACL, removing the Users read ACE it inherited from
// the previous directory DACL. Each file is opened without following links and
// changed through that handle; reparse points, hard links (a link could lead to a
// file elsewhere) and files not owned by SYSTEM/Administrators are left alone.
inline void EID_CloseExistingLogFiles(PCWSTR pwszDir)
{
    PSECURITY_DESCRIPTOR pFileSD = nullptr;
    PACL pFileDacl = nullptr;
    BOOL fPresent = FALSE;
    BOOL fDefaulted = FALSE;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(EID_LOG_FILE_SDDL, SDDL_REVISION_1, &pFileSD, nullptr))
        return;
    WCHAR szPattern[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
    WIN32_FIND_DATAW fd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    if (GetSecurityDescriptorDacl(pFileSD, &fPresent, &pFileDacl, &fDefaulted) && fPresent &&
        _snwprintf_s(szPattern, MAX_PATH, _TRUNCATE, L"%s\\*", pwszDir) >= 0)
    {
        hFind = FindFirstFileExW(szPattern, FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, 0);
    }
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (fd.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
                continue;
            WCHAR szFile[MAX_PATH];  // NOSONAR - LSASS-01: C-style buffer for LSASS safety
            if (_snwprintf_s(szFile, MAX_PATH, _TRUNCATE, L"%s\\%s", pwszDir, fd.cFileName) < 0)
                continue;
            HANDLE hFile = CreateFileW(szFile, READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (hFile == INVALID_HANDLE_VALUE)
                continue;
            BY_HANDLE_FILE_INFORMATION info = {};
            if (GetFileInformationByHandle(hFile, &info) && info.nNumberOfLinks == 1 &&
                EID_IsAdminOwnedNonReparseHandle(hFile))
            {
                SetSecurityInfo(hFile, SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, pFileDacl, nullptr);
            }
            CloseHandle(hFile);
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    LocalFree(pFileSD);
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
    else if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        // Check and change the directory through ONE handle, so the directory that
        // is checked is the one whose DACL is written. It used to be checked through a
        // handle and then changed by path, and a directory swapped for a junction in
        // between had its target re-ACLed as SYSTEM. The handle is opened without
        // FILE_SHARE_DELETE, which also stops the directory (and the folders above it)
        // being renamed while the files in it are fixed up below.
        HANDLE hDir = CreateFileW(pwszDir, READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (hDir != INVALID_HANDLE_VALUE)
        {
            PACL pDacl = nullptr;
            BOOL fDaclPresent = FALSE;
            BOOL fDaclDefaulted = FALSE;
            if (EID_IsAdminOwnedNonReparseHandle(hDir) &&
                GetSecurityDescriptorDacl(pSD, &fDaclPresent, &pDacl, &fDaclDefaulted) && fDaclPresent)
            {
                // Files inherited Users read from the DACL before this one.
                BOOL fFixFiles = FALSE;
                PACL pOldDacl = nullptr;
                PSECURITY_DESCRIPTOR pOldSD = nullptr;
                if (GetSecurityInfo(hDir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, &pOldDacl, nullptr, &pOldSD) == ERROR_SUCCESS)
                {
                    fFixFiles = EID_DaclLetsUsersReadFiles(pOldDacl);
                    LocalFree(pOldSD);
                }
                // PROTECTED_DACL_SECURITY_INFORMATION matches the SDDL's "PAI" - it severs
                // inheritance from ProgramData rather than merging with it. Only a directory
                // whose DACL was actually replaced counts as safe: an admin-owned directory
                // that still carries an inherited Users-writable ACL is not.
                fSafe = (SetSecurityInfo(hDir, SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, pDacl, nullptr) == ERROR_SUCCESS) ? TRUE : FALSE;
                if (fSafe && fFixFiles)
                {
                    EID_CloseExistingLogFiles(pwszDir);
                }
            }
            CloseHandle(hDir);
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
