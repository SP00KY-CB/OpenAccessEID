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


NTSTATUS GetTokenInformationv2(LPCWSTR wszMachine,LPCWSTR wszDomain, LPCWSTR wszUser,LSA_TOKEN_INFORMATION_V2** TokenInformation);

NTSTATUS UserNameToToken(__in PLSA_UNICODE_STRING AccountName,
						__out PLSA_TOKEN_INFORMATION_V2 *Token,
						__out LPDWORD TokenLength,
						__out PNTSTATUS SubStatus
						);

// Account-restriction check (disabled, locked out, expired, logon hours,
// workstation). Returns STATUS_SUCCESS or a failure NTSTATUS, with the detail
// in *SubStatus; *ExpirationTime receives the latest time the resulting
// logon may last. Every path that issues a token for an account must call it.
NTSTATUS CheckAuthorization(PWSTR UserName, NTSTATUS *SubStatus, LARGE_INTEGER *ExpirationTime);

// This machine's account-domain SID, in EIDAlloc memory (EIDFree it), or NULL.
PSID EIDGetAccountDomainSid();
// The RID of a SID directly in this machine's account domain (domain SID plus
// one RID). FALSE, with ERROR_NONE_MAPPED, for any other SID.
BOOL EIDGetLocalAccountRid(__in PSID pSid, __out PDWORD pdwRid);
