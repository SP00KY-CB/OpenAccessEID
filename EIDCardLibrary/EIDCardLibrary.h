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

// Suppress C4005 warnings for macro redefinitions from Windows SDK
// These warnings occur because Windows SDK headers (ntstatus.h, winnt.h, WinCred.h, etc.)
// define the same macros in different orders when included from different paths.
#pragma warning(push)
#pragma warning(disable:4005)

#include <NTSecAPI.h>

constexpr const char* AUTHENTICATIONPACKAGENAME = "OpenAccessEIDPackage";
constexpr const wchar_t* AUTHENTICATIONPACKAGENAMEW = L"OpenAccessEIDPackage";
#define AUTHENTICATIONPACKAGENAMET TEXT("OpenAccessEIDPackage")  // NOSONAR - MACRO-02: TEXT() requires macro context

// Package name used up to v1.3.00, before the project was renamed. Kept only so
// registration can strip stale entries from the LSA multi-sz values: an entry
// naming a DLL that no longer exists in System32 can leave a machine unable to
// authenticate, so this must outlive the rename.
#define LEGACY_AUTHENTICATIONPACKAGENAMET TEXT("EIDAuthenticationPackage")  // NOSONAR - MACRO-02: TEXT() requires macro context

// The Windows SDK (WinCred.h) defines CERT_HASH_LENGTH as 20 (SHA-1), but we use SHA-256 (32)
// Undefine first to ensure our definition takes precedence without warnings
// NOSONAR - MACRO-02: Cannot convert to constexpr because Windows SDK defines this as a macro.
// The preprocessor #undef/#define pattern is required to override the SDK value.
#undef CERT_HASH_LENGTH  // NOSONAR - INCLUDE-01: #undef overrides Windows SDK CERT_HASH_LENGTH macro
#define CERT_HASH_LENGTH 32  // NOSONAR - MACRO-02: SHA-256 hash length overriding Windows SDK SHA-1 default

#pragma warning(pop)

#include <utility>  // NOSONAR - INCLUDE-01: include placed after SDK macro setup; order significant
#include <array>

#include "ErrorHandling.h"

#define EIDAlloc(value) EIDAllocEx(__FILE__,__LINE__,__FUNCTION__,value)  // NOSONAR - MACRO-02: Debug macros require preprocessor
#define EIDFree(value) EIDFreeEx(__FILE__,__LINE__,__FUNCTION__,value)  // NOSONAR - MACRO-02: Debug macros require preprocessor

PVOID EIDAllocEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction,DWORD);
VOID EIDFreeEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction,PVOID);
VOID EIDImpersonate();
VOID EIDRevertToSelf();
BOOL EIDIsComponentInLSAContext();

// Secure DLL loading - prevents DLL hijacking by using full system paths
// Use this instead of LoadLibrary for system DLLs
HMODULE EIDLoadSystemLibrary(LPCTSTR szDllName);

// Window utility functions shared across Wizard and Elevated projects
VOID CenterWindow(HWND hWnd);
VOID SetIcon(HWND hWnd);

enum EID_INTERACTIVE_LOGON_SUBMIT_TYPE  // NOSONAR - ENUM-01: Unscoped enum required for Windows SDK compatibility
{
	EID_INTERACTIVE_LOGON_SUBMIT_TYPE_VANILLA = 13, //KerbCertificateLogon = 13
};

struct EID_INTERACTIVE_LOGON
{
    EID_INTERACTIVE_LOGON_SUBMIT_TYPE MessageType; // KerbCertificateLogon
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Pin;
	ULONG Flags;               // additional flags
    ULONG CspDataLength;
    PUCHAR CspData;            // contains the smartcard CSP data
};
using PEID_INTERACTIVE_LOGON = EID_INTERACTIVE_LOGON*;

struct EID_INTERACTIVE_UNLOCK_LOGON
{
    EID_INTERACTIVE_LOGON Logon;
    LUID LogonId;
};
using PEID_INTERACTIVE_UNLOCK_LOGON = EID_INTERACTIVE_UNLOCK_LOGON*;

enum EID_PROFILE_BUFFER_TYPE  // NOSONAR - ENUM-01: Unscoped enum required for Windows SDK compatibility
{
	EIDInteractiveProfile = 2,
};

#pragma pack(push, EID_SMARTCARD_CSP_INFO, 1)
// based on _KERB_SMARTCARD_CSP_INFO
struct EID_SMARTCARD_CSP_INFO
{
  DWORD dwCspInfoLen;
  DWORD MessageType;
  union {
    PVOID ContextInformation;
    ULONG64 SpaceHolderForWow64;
  } ;
  DWORD flags;
  DWORD KeySpec;
  ULONG nCardNameOffset;
  ULONG nReaderNameOffset;
  ULONG nContainerNameOffset;
  ULONG nCSPNameOffset;
  TCHAR bBuffer[sizeof(DWORD)];  // NOSONAR - LSASS-01: C-style buffer required by Win32/ABI struct
};
using PEID_SMARTCARD_CSP_INFO = EID_SMARTCARD_CSP_INFO*;
#pragma pack(pop, EID_SMARTCARD_CSP_INFO)

struct EID_INTERACTIVE_PROFILE
{
  EID_PROFILE_BUFFER_TYPE MessageType;
  USHORT LogonCount;
  USHORT BadPasswordCount;
  LARGE_INTEGER LogonTime;
  LARGE_INTEGER LogoffTime;
  LARGE_INTEGER KickOffTime;
  LARGE_INTEGER PasswordLastSet;
  LARGE_INTEGER PasswordCanChange;
  LARGE_INTEGER PasswordMustChange;
  UNICODE_STRING LogonScript;
  UNICODE_STRING HomeDirectory;
  UNICODE_STRING FullName;
  UNICODE_STRING ProfilePath;
  UNICODE_STRING HomeDirectoryDrive;
  UNICODE_STRING LogonServer;
  ULONG UserFlags;
};
using PEID_INTERACTIVE_PROFILE = EID_INTERACTIVE_PROFILE*;

enum class EID_CREDENTIAL_PROVIDER_READER_STATE
{
	EIDCPRSConnecting,
	EIDCPRSConnected,
	EIDCPRSDisconnected,
	EIDCPRSThreadFinished,
};

// Password encryption types for stored credentials
enum class EID_PRIVATE_DATA_TYPE
{
	eidpdtClearText = 1,   // Plaintext (not used)
	eidpdtCrypted = 2,     // Certificate-based encryption (RSA+AES)
	eidpdtDPAPI = 3,       // DPAPI encryption (machine-bound)
};

// Forward declaration of EID_PRIVATE_DATA structure
struct EID_PRIVATE_DATA;

enum EID_CALLPACKAGE_MESSAGE  // NOSONAR - ENUM-01: Unscoped enum required for Windows SDK compatibility
{
	EIDCMCreateStoredCredential,
	EIDCMUpdateStoredCredential,
	EIDCMRemoveStoredCredential,
	EIDCMHasStoredCredential,
	EIDCMRemoveAllStoredCredential,
	EIDCMGetStoredCredentialRid,
	EIDCMEIDGinaAuthenticationChallenge,
	EIDCMEIDGinaAuthenticationResponse,
	// EIDMigrate messages - Administrator only
	EIDCMEnumerateCredentials,         // Enumerate all stored credentials
	EIDCMExportCredential,             // Export full credential data
	EIDCMImportCredential,             // Import credential data
};

//Message used for LsaApCallPackage
struct EID_CALLPACKAGE_BUFFER
{
	EID_CALLPACKAGE_MESSAGE MessageType;
	DWORD dwError;
	DWORD dwRid;
	PWSTR wszPassword;		// Renamed from szPassword to avoid shadowing global
	USHORT usPasswordLen;	// can be 0 if null terminated
	PBYTE pbCertificate;
	USHORT dwCertificateSize;
	std::array<UCHAR, CERT_HASH_LENGTH> Hash; // to get challenge
	BOOL fEncryptPassword;
	// EIDCMCreateStoredCredential: proof that the caller holds the certificate's key - the
	// card's signature over EIDBuildEnrolmentStatement(dwRid, ftEnrolmentTime, certificate),
	// stored in the buffer like pbCertificate. Required unless the caller is an administrator.
	FILETIME ftEnrolmentTime;
	PBYTE pbEnrolmentSignature;
	USHORT usEnrolmentSignatureSize;
};
using PEID_CALLPACKAGE_BUFFER = EID_CALLPACKAGE_BUFFER*;

// Upper bound on an enrolment certificate accepted by the package. A smart card
// logon certificate is a few KB; the stored-credential blob (EID_PRIVATE_DATA)
// uses USHORT offsets/sizes, so an oversized certificate must be refused before
// any size arithmetic is done on it.
constexpr DWORD EID_MAX_CERTIFICATE_SIZE = 16384;

// Enrolment proof of possession: the statement the card signs (SHA-1, CryptSignHash) is
// "OpenAccessEID enrolment proof v2" (32 bytes), the RID (4 bytes, little endian), the
// FILETIME (8 bytes), the SHA-256 of the DER certificate (32 bytes) and the SHA-256 of
// this machine's account-domain SID (32 bytes), so a statement signed for RID n on one
// machine is no good for RID n on another.
constexpr DWORD EID_ENROLMENT_STATEMENT_SIZE = 32 + 4 + 8 + 32 + 32;
// An RSA-4096 signature is 512 bytes.
constexpr DWORD EID_MAX_ENROLMENT_SIGNATURE_SIZE = 512;
BOOL EIDBuildEnrolmentStatement(DWORD dwRid, const FILETIME* pftTime, PCCERT_CONTEXT pCertContext, PBYTE pbStatement, DWORD cbStatement);

struct EID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST
{
	EID_CALLPACKAGE_MESSAGE MessageType;
    DWORD dwRid;
};
using PEID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST = EID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST*;

struct EID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER
{
	DWORD dwError;
	DWORD dwChallengeType;
	PBYTE pbChallenge;
	DWORD dwChallengeSize;
};
using PEID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER = EID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER*;

struct EID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST
{
	EID_CALLPACKAGE_MESSAGE MessageType;
    DWORD dwRid;
	DWORD dwChallengeType;
	PBYTE pbChallenge;
	DWORD dwChallengeSize;
	PBYTE pbResponse;
	DWORD dwResponseSize;
};
using PEID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST = EID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST*;

struct EID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER
{
	DWORD dwError;
	UNICODE_STRING Password;
};
using PEID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER = EID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER*;


constexpr DWORD EID_CERTIFICATE_FLAG_USERSTORE = 0x00000001;

struct EID_NEGOCIATE_MESSAGE
{
	std::array<BYTE, 8> Signature;
	DWORD MessageType;
	DWORD Flags;
	USHORT TargetLen;
	USHORT TargetMaxLen;
	DWORD TargetOffset;
	USHORT WorkstationLen;
	USHORT WorkstationMaxLen;
	USHORT WorkstationOffset;
	std::array<UCHAR, CERT_HASH_LENGTH> Hash;
	DWORD Version;
};
using PEID_NEGOCIATE_MESSAGE = EID_NEGOCIATE_MESSAGE*;

struct EID_CHALLENGE_MESSAGE
{
	std::array<BYTE, 8> Signature;
	DWORD MessageType;
	DWORD Flags;
	DWORD UsernameLen;
	DWORD UsernameOffset;
	DWORD ChallengeLen;
	DWORD ChallengeOffset;
	DWORD Version;
};
using PEID_CHALLENGE_MESSAGE = EID_CHALLENGE_MESSAGE*;

struct EID_RESPONSE_MESSAGE
{
	std::array<BYTE, 8> Signature;
	DWORD MessageType;
	DWORD ResponseLen;
	DWORD ResponseOffset;
	DWORD Version;
};
using PEID_RESPONSE_MESSAGE = EID_RESPONSE_MESSAGE*;

enum class EID_MESSAGE_STATE
{
	EIDMSNone,
	EIDMSNegociate,
	EIDMSChallenge,
	EIDMSResponse,
	EIDMSComplete,
};

enum class EID_MESSAGE_TYPE
{
	EIDMTNegociate = 1,
	EIDMTChallenge = 2,
	EIDMTResponse = 3,
};

constexpr DWORD EID_MESSAGE_VERSION = 1;
// Signature is exactly 8 bytes (7 chars + null terminator) to match message Signature[8] fields
constexpr char EID_MESSAGE_SIGNATURE[8] = "EIDAuth";  // NOSONAR - LSASS-01: fixed-size signature buffer for wire protocol

enum class EID_SSP_CALLER
{
	EIDSSPInitialize,
	EIDSSPAccept,
};

struct EID_SSP_CALLBACK_MESSAGE
{
	EID_SSP_CALLER Caller;
	HANDLE hToken;
};
using PEID_SSP_CALLBACK_MESSAGE = EID_SSP_CALLBACK_MESSAGE*;

//
// EIDMigrate - Credential Migration Structures
//

// Maximum username length for EIDMigrate operations
constexpr DWORD EIDM_MAX_USERNAME_LENGTH = 256;

// Response structure for enumerate credentials
struct EIDM_ENUM_RESPONSE
{
	DWORD dwError;                            // Win32 error code (0 = SUCCESS)
	DWORD dwCredentialCount;                  // Number of credentials returned
	// Followed by: EIDM_CREDENTIAL_SUMMARY[dwCredentialCount]
};
using PEIDM_ENUM_RESPONSE = EIDM_ENUM_RESPONSE*;

// Credential summary structure
struct EIDM_CREDENTIAL_SUMMARY
{
	DWORD dwRid;                              // Relative ID of user account
	WCHAR wszUsername[EIDM_MAX_USERNAME_LENGTH];  // Username (null-terminated)  // NOSONAR - LSASS-01: C-style array required by Win32/ABI struct
	UCHAR CertificateHash[CERT_HASH_LENGTH];  // SHA-256 hash of certificate  // NOSONAR - LSASS-01: C-style array required by Win32/ABI struct
	EID_PRIVATE_DATA_TYPE EncryptionType;     // Password encryption type
	DWORD dwFlags;                            // Credential flags (reserved for future use)
};
using PEIDM_CREDENTIAL_SUMMARY = EIDM_CREDENTIAL_SUMMARY*;

// Response structure for export
struct EIDM_EXPORT_RESPONSE
{
	DWORD dwError;                            // Win32 error code (0 = SUCCESS)
	DWORD dwRid;                              // RID of exported credential
	DWORD dwPrivateDataSize;                  // Size of EID_PRIVATE_DATA structure
	DWORD dwCertificateSize;                  // Size of certificate data
	DWORD dwPasswordSize;                     // Size of encrypted password data  // NOSONAR - ENUM-01: struct member name retained for ABI compatibility
	EID_PRIVATE_DATA_TYPE EncryptionType;     // Password encryption type
	UCHAR CertificateHash[CERT_HASH_LENGTH];  // SHA-256 hash of certificate  // NOSONAR - LSASS-01: C-style array required by Win32/ABI struct
	WCHAR wszUsername[EIDM_MAX_USERNAME_LENGTH];  // Username (null-terminated)  // NOSONAR - LSASS-01: C-style array required by Win32/ABI struct
	// Following this structure in the buffer:
	// 1. EID_PRIVATE_DATA structure (dwPrivateDataSize bytes)
	// 2. Certificate data (dwCertificateSize bytes)
	// 3. Encrypted password data (dwPasswordSize bytes)
};
using PEIDM_EXPORT_RESPONSE = EIDM_EXPORT_RESPONSE*;

// Request structure for import
struct EIDM_IMPORT_REQUEST
{
	EID_CALLPACKAGE_MESSAGE MessageType;      // EIDCMImportCredential
	DWORD dwRid;                              // Target RID for credential
	DWORD dwPrivateDataSize;                  // Size of EID_PRIVATE_DATA structure
	DWORD dwCertificateSize;                  // Size of certificate data
	DWORD dwPasswordSize;                     // Size of encrypted password data  // NOSONAR - ENUM-01: struct member name retained for ABI compatibility
	EID_PRIVATE_DATA_TYPE EncryptionType;     // Password encryption type
	UCHAR CertificateHash[CERT_HASH_LENGTH];  // SHA-256 hash of certificate  // NOSONAR - LSASS-01: C-style array required by Win32/ABI struct
	WCHAR wszUsername[EIDM_MAX_USERNAME_LENGTH];  // Username (null-terminated)  // NOSONAR - LSASS-01: C-style array required by Win32/ABI struct
	DWORD dwFlags;                            // Flags (e.g., create user if not exists)
	// Following this structure in the buffer:
	// 1. EID_PRIVATE_DATA structure (dwPrivateDataSize bytes)
	// 2. Certificate data (dwCertificateSize bytes)
	// 3. Encrypted password data (dwPasswordSize bytes)
};
using PEIDM_IMPORT_REQUEST = EIDM_IMPORT_REQUEST*;

// Response structure for import
struct EIDM_IMPORT_RESPONSE
{
	DWORD dwError;                            // Win32 error code (0 = SUCCESS)
	DWORD dwRid;                              // RID of imported credential
	BOOL fUserCreated;                        // TRUE if user account was created
};
using PEIDM_IMPORT_RESPONSE = EIDM_IMPORT_RESPONSE*;