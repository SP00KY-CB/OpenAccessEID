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

#pragma once

#include <vector>
#include <Windows.h>

BOOL IsEIDPackageAvailable();

HRESULT LsaInitString(PSTRING pszDestinationString, PCSTR pszSourceString);

//get the authentication package that will be used for our logon attempt
HRESULT RetrieveNegotiateAuthPackage(
    ULONG * pulAuthPackage
    );



//packages the credentials into the buffer that the system expects
HRESULT EIDUnlockLogonPack(
    const EID_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
	const PEID_SMARTCARD_CSP_INFO pCspInfo,
    BYTE** prgb,
    DWORD* pcb
    );

//szAuthPackageValue must be freed by  LsaFreeMemory
HRESULT CallAuthPackage(LPCWSTR username ,LPWSTR * szAuthPackageValue, PULONG szAuthPackageLen);

// dwCspDataLength must be the length the LSA supplied for the CspData block
// (Logon.CspDataLength), not a value read out of the buffer being dumped.
VOID EIDDebugPrintEIDUnlockLogonStruct(UCHAR dwLevel, PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon, ULONG dwCspDataLength) ;

NTSTATUS RemapPointer(PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon, PVOID ClientAuthenticationBase, ULONG AuthenticationInformationLength);

PTSTR GetUsernameFromRid(__in DWORD dwRid);
DWORD GetRidFromUsername(LPTSTR szUsername);
BOOL HasAccountOnCurrentComputer(PWSTR szUserName);
BOOL IsCurrentUser(PWSTR szUserName);
BOOL IsAdmin(PWSTR szUserName);

BOOL LsaEIDCreateStoredCredential(__in PWSTR szUsername, __in PWSTR szPassword, __in PCCERT_CONTEXT pCertContext, __in BOOL fEncryptPassword);

BOOL LsaEIDRemoveStoredCredential(__in_opt PWSTR szUsername);

// Removes the stored credential of every local user (admin only). Destructive: call it only
// from an explicit operator action (CleanupLsaCredentials), never from (un)registration.
BOOL LsaEIDRemoveAllStoredCredential();

BOOL LsaEIDHasStoredCredential(__in_opt PWSTR szUsername);

DWORD LsaEIDGetRIDFromStoredCredential(__in PCCERT_CONTEXT pContext);

//BOOL CanEncryptPassword(__in_opt HCRYPTPROV hProv, __in_opt DWORD dwKeySpec,  __in_opt PCCERT_CONTEXT pCertContext);

//
// EIDMigrate LSA IPC Client Wrapper Functions
//

/**
 * Enumerate all EID credentials from LSA
 * Returns an array of EIDM_CREDENTIAL_SUMMARY structures
 * Requires Administrator privileges
 */
HRESULT LsaEIDEnumerateCredentials(_Out_ std::vector<EIDM_CREDENTIAL_SUMMARY>& credentials);

/**
 * Export a single EID credential from LSA
 * Returns complete EIDM_EXPORT_RESPONSE structure for the specified RID
 * Caller is responsible for freeing the returned pointer with EIDFree()
 * Requires Administrator privileges
 */
HRESULT LsaEIDExportCredential(_In_ DWORD dwRid, _Out_ PEIDM_EXPORT_RESPONSE* ppExportResponse);

/**
 * Import an EID credential to LSA
 * Takes complete credential data from export file and stores it in LSA
 * Returns EIDM_IMPORT_RESPONSE structure with result
 * Caller is responsible for freeing the returned pointer with EIDFree()
 * Requires Administrator privileges
 */
HRESULT LsaEIDImportCredential(
    _In_ const EIDM_IMPORT_REQUEST* pImportRequest,
    _In_reads_bytes_(cbPrivateData) const BYTE* pbPrivateData,
    _In_ DWORD cbPrivateData,
    _In_reads_bytes_(cbCertificate) const BYTE* pbCertificate,
    _In_ DWORD cbCertificate,
    _In_reads_bytes_(cbPassword) const BYTE* pbPassword,
    _In_ DWORD cbPassword,
    _Out_ PEIDM_IMPORT_RESPONSE* ppImportResponse);
