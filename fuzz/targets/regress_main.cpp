/*
    OpenAccess EID - fuzz/regression harness
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

//=============================================================================
// Deterministic replay of the proof-of-concept inputs for the four defects
// found on 2026-07-30. Fast, no fuzzing, runs on every push.
//
// SCOPE - be precise about what this proves:
//   Each case asserts that the CANONICAL VALIDATOR rejects an input that the
//   pre-fix code accepted. That protects against a future change weakening a
//   validator, and it pins the exact byte patterns for the record.
//
//   It does NOT prove the production call sites invoke the validator - a
//   validator can be perfect and unused. That property is covered two ways:
//   the libFuzzer targets assert "validator says OK => the consumer's own
//   offset arithmetic stays in bounds", and the call-site wiring is reviewed
//   in the diff. See docs/FUZZING.md.
//
// Exit code = number of failing cases, so CI can gate on it.
//=============================================================================

#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>

#include "EIDCardLibrary.h"
#include "StoredCredentialManagement.h"
#include "InputValidation.h"
#include "LogDirSecurity.h"

namespace {

int g_failures = 0;
int g_total = 0;

void Check(const char* pszCase, bool fRejected, const char* pszWhy)
{
	g_total++;
	if (fRejected)
	{
		printf("  PASS  %-46s (rejected)\n", pszCase);
	}
	else
	{
		printf("  FAIL  %-46s ACCEPTED - %s\n", pszCase, pszWhy);
		g_failures++;
	}
}

void CheckAccepted(const char* pszCase, bool fAccepted)
{
	g_total++;
	if (fAccepted)
	{
		printf("  PASS  %-46s (accepted)\n", pszCase);
	}
	else
	{
		printf("  FAIL  %-46s REJECTED - benign input must still work\n", pszCase);
		g_failures++;
	}
}

//-------------------------------------------------------------------------
// Defect 1 - SSP token messages parsed with no length validation at all.
// CredentialManagement.cpp:443 / :495 before the fix.
//-------------------------------------------------------------------------
void TestTokenMessages()
{
	printf("\nDefect 1: SSP token messages (CredentialManagement.cpp:443,:495)\n");

	// 1a. UsernameLen = 0xFFFFFFFF. The consumer did
	//     EIDAlloc(UsernameLen + sizeof(WCHAR)) -> wraps to EIDAlloc(1),
	//     then memcpy'd 4 GB into it. Heap overflow inside LSASS.
	{
		std::vector<BYTE> token(sizeof(EID_CHALLENGE_MESSAGE) + 64, 0);
		auto* p = reinterpret_cast<EID_CHALLENGE_MESSAGE*>(token.data());
		memcpy(p->Signature.data(), EID_MESSAGE_SIGNATURE, p->Signature.size());
		p->MessageType = static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTChallenge);
		p->Version = EID_MESSAGE_VERSION;
		p->UsernameLen = 0xFFFFFFFF;
		p->UsernameOffset = sizeof(EID_CHALLENGE_MESSAGE);
		p->ChallengeLen = EID_CHALLENGE_LENGTH;
		p->ChallengeOffset = sizeof(EID_CHALLENGE_MESSAGE);
		Check("challenge: UsernameLen=0xFFFFFFFF (odd length)",
			!EIDValidateChallengeMessage(token.data(), static_cast<DWORD>(token.size())),
			"odd UsernameLen must be rejected");
	}

	// 1a-bis. The value above is caught by the ODD-length test, which runs
	//     first - so on its own it gives the terminator-wrap check no coverage
	//     at all. 0xFFFFFFFE is even, so it reaches TokenRegionFits and
	//     exercises the "UsernameLen + sizeof(WCHAR) must not wrap" rule that
	//     the original EIDAlloc(UsernameLen + sizeof(WCHAR)) defect depended on.
	{
		std::vector<BYTE> token(sizeof(EID_CHALLENGE_MESSAGE) + 64, 0);
		auto* p = reinterpret_cast<EID_CHALLENGE_MESSAGE*>(token.data());
		memcpy(p->Signature.data(), EID_MESSAGE_SIGNATURE, p->Signature.size());
		p->MessageType = static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTChallenge);
		p->Version = EID_MESSAGE_VERSION;
		p->UsernameLen = 0xFFFFFFFE;        // even, so it survives the parity test
		p->UsernameOffset = sizeof(EID_CHALLENGE_MESSAGE);
		p->ChallengeLen = EID_CHALLENGE_LENGTH;
		p->ChallengeOffset = sizeof(EID_CHALLENGE_MESSAGE);
		Check("challenge: UsernameLen=0xFFFFFFFE terminator wrap",
			!EIDValidateChallengeMessage(token.data(), static_cast<DWORD>(token.size())),
			"UsernameLen + sizeof(WCHAR) wraps to a 1-byte allocation");
	}

	// 1b. Offset far past the end of the token, used as a raw pointer
	//     displacement -> arbitrary OOB read relative to the LSASS heap.
	{
		std::vector<BYTE> token(sizeof(EID_CHALLENGE_MESSAGE) + 64, 0);
		auto* p = reinterpret_cast<EID_CHALLENGE_MESSAGE*>(token.data());
		memcpy(p->Signature.data(), EID_MESSAGE_SIGNATURE, p->Signature.size());
		p->MessageType = static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTChallenge);
		p->Version = EID_MESSAGE_VERSION;
		p->UsernameLen = 4;
		p->UsernameOffset = sizeof(EID_CHALLENGE_MESSAGE);
		p->ChallengeLen = 0x100;
		p->ChallengeOffset = 0xFFFFFF00;
		Check("challenge: ChallengeOffset past end",
			!EIDValidateChallengeMessage(token.data(), static_cast<DWORD>(token.size())),
			"offset outside token");
	}

	// 1c. Token shorter than the fixed header. The pre-fix code dereferenced
	//     MessageType before establishing any size at all.
	{
		std::vector<BYTE> token(8, 0);
		Check("challenge: token smaller than header",
			!EIDValidateChallengeMessage(token.data(), static_cast<DWORD>(token.size())),
			"header read would be OOB");
	}

	// 1d. Response message, same offset defect.
	{
		std::vector<BYTE> token(sizeof(EID_RESPONSE_MESSAGE) + 32, 0);
		auto* p = reinterpret_cast<EID_RESPONSE_MESSAGE*>(token.data());
		memcpy(p->Signature.data(), EID_MESSAGE_SIGNATURE, p->Signature.size());
		p->MessageType = static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTResponse);
		p->Version = EID_MESSAGE_VERSION;
		p->ResponseLen = 0xFFFFFFF0;
		p->ResponseOffset = sizeof(EID_RESPONSE_MESSAGE);
		Check("response: ResponseLen exceeds token",
			!EIDValidateResponseMessage(token.data(), static_cast<DWORD>(token.size())),
			"length outside token");
	}

	// 1f. Short challenge. The verifier reaches
	//     CryptSetHashParam(HP_HASHVAL, pbChallenge, 0), which copies the hash
	//     algorithm's FULL digest length (20 bytes for CALG_SHA) out of the
	//     buffer whatever its real size. A 1-byte challenge was therefore a
	//     19-byte heap over-read inside LSASS, reachable by any local SSPI
	//     caller - and the validator used to allow it because it only rejected
	//     ChallengeLen == 0. Found by adversarial review.
	{
		std::vector<BYTE> token(sizeof(EID_CHALLENGE_MESSAGE) + 64, 0);
		auto* p = reinterpret_cast<EID_CHALLENGE_MESSAGE*>(token.data());
		memcpy(p->Signature.data(), EID_MESSAGE_SIGNATURE, p->Signature.size());
		p->MessageType = static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTChallenge);
		p->Version = EID_MESSAGE_VERSION;
		p->ChallengeOffset = sizeof(EID_CHALLENGE_MESSAGE);
		p->ChallengeLen = 1;                 // fits the token, far short of the digest
		p->UsernameOffset = sizeof(EID_CHALLENGE_MESSAGE);
		p->UsernameLen = 0;
		Check("challenge: 1-byte challenge (digest over-read)",
			!EIDValidateChallengeMessage(token.data(), static_cast<DWORD>(token.size())),
			"challenge shorter than the digest the verifier copies");
	}

	// 1e. A well-formed token must still be accepted, or we have merely
	//     broken authentication instead of fixing it. Shaped like the token
	//     BuildChallengeMessage actually emits: full-length challenge first,
	//     then the username immediately after it.
	{
		const DWORD cbUserName = 16;
		std::vector<BYTE> token(sizeof(EID_CHALLENGE_MESSAGE) + EID_CHALLENGE_LENGTH + cbUserName, 0);
		auto* p = reinterpret_cast<EID_CHALLENGE_MESSAGE*>(token.data());
		memcpy(p->Signature.data(), EID_MESSAGE_SIGNATURE, p->Signature.size());
		p->MessageType = static_cast<DWORD>(EID_MESSAGE_TYPE::EIDMTChallenge);
		p->Version = EID_MESSAGE_VERSION;
		p->ChallengeOffset = sizeof(EID_CHALLENGE_MESSAGE);
		p->ChallengeLen = EID_CHALLENGE_LENGTH;
		p->UsernameOffset = p->ChallengeOffset + p->ChallengeLen;
		p->UsernameLen = cbUserName;
		CheckAccepted("challenge: well-formed token still valid",
			EIDValidateChallengeMessage(token.data(), static_cast<DWORD>(token.size())) != FALSE);
	}
}

//-------------------------------------------------------------------------
// Defects 2 and 3 - EID_SMARTCARD_CSP_INFO.
// dwCspInfoLen was never bounded against the length the LSA supplied, and
// the debug printer indexed bBuffer with a raw 32-bit offset.
//-------------------------------------------------------------------------
void TestCspInfo()
{
	printf("\nDefects 2+3: CSP info (Package.cpp:553,:628)\n");

	// Helper: allocate a CSP_INFO of a given real size.
	auto MakeCspInfo = [](DWORD cbReal) {
		std::vector<BYTE> buf(cbReal, 0);
		auto* p = reinterpret_cast<EID_SMARTCARD_CSP_INFO*>(buf.data());
		p->dwCspInfoLen = cbReal;
		return buf;
	};

	// 3a. THE defect: a 40-byte buffer declaring a 64 KB interior. Both
	//     downstream validators bounded their offsets against dwCspInfoLen,
	//     so this passed every check and read ~64 KB out of bounds.
	{
		auto buf = MakeCspInfo(40);
		auto* p = reinterpret_cast<EID_SMARTCARD_CSP_INFO*>(buf.data());
		p->dwCspInfoLen = 0x10000;
		p->nCardNameOffset = 0xFFF0;
		Check("cspinfo: dwCspInfoLen exceeds CspDataLength",
			!EIDValidateCspInfo(p, 40),
			"inner length is attacker data, must be bounded");
	}

	// 3b. Offset chosen so that offset * sizeof(WCHAR) overflows 32 bits.
	{
		auto buf = MakeCspInfo(128);
		auto* p = reinterpret_cast<EID_SMARTCARD_CSP_INFO*>(buf.data());
		p->nReaderNameOffset = 0xFFFFFFF0;
		Check("cspinfo: char offset multiply overflows",
			!EIDValidateCspInfo(p, 128),
			"offset scaling must be overflow-checked");
	}

	// 3c. Offset inside bounds but the string is never NUL-terminated, so
	//     _tcscmp / CryptAcquireContext walk past the end.
	{
		auto buf = MakeCspInfo(64);
		auto* p = reinterpret_cast<EID_SMARTCARD_CSP_INFO*>(buf.data());
		const DWORD hdr = static_cast<DWORD>(FIELD_OFFSET(EID_SMARTCARD_CSP_INFO, bBuffer));
		// Fill the whole tail with non-NUL WCHARs.
		for (DWORD off = hdr; off + 1 < 64; off += 2)
		{
			buf[off] = 0x41;
			buf[off + 1] = 0x00;
		}
		p->nContainerNameOffset = 1;
		Check("cspinfo: unterminated name string",
			!EIDValidateCspInfo(p, 64),
			"string must terminate inside the buffer");
	}

	// 3d. Accessor must refuse rather than hand back a pointer to re-check.
	{
		auto buf = MakeCspInfo(40);
		auto* p = reinterpret_cast<EID_SMARTCARD_CSP_INFO*>(buf.data());
		p->dwCspInfoLen = 0x10000;
		Check("cspinfo: accessor refuses invalid struct",
			EIDCspInfoStringAt(p, 40, 0xFFF0) == nullptr,
			"accessor returned a pointer into OOB memory");
	}

	// 3f. Offset whose WCHAR scaling wraps 32 bits and comes back around INSIDE
	//     the buffer, aliasing the fixed header. Found by adversarial review of
	//     the first cut of this module: the overflow guard subtracted a
	//     hardcoded 16 while the code added the real header size of 40, so
	//     0x7FFFFFF7 produced byte offset 22 (inside KeySpec). No ASan report,
	//     because the wrapped pointer is still in bounds - which is exactly why
	//     the fuzz oracle now checks the pointer lands inside bBuffer.
	{
		auto buf = MakeCspInfo(40);
		auto* p = reinterpret_cast<EID_SMARTCARD_CSP_INFO*>(buf.data());
		p->KeySpec = 1;                    // WCHAR at byte 22 is 0x0000
		p->nCardNameOffset = 0x7FFFFFF7;   // 40 + 0x7FFFFFF7*2 wraps to 22
		Check("cspinfo: char offset wraps back into header",
			!EIDValidateCspInfo(p, 40),
			"scaled offset wrapped and aliased the struct header");
	}

	// 3e. A REAL struct, laid out exactly the way CContainer.cpp builds one:
	//     four names packed end to end starting at offset ARRAYSIZE(bBuffer)==4,
	//     each NUL-terminated. This is the over-rejection guard for the whole
	//     logon path, so it must mirror what production actually emits - an
	//     earlier version of this case marked its only populated field absent
	//     and then validated a different offset into zero-filled padding, which
	//     would have passed no matter what the names contained.
	{
		const DWORD hdr = static_cast<DWORD>(FIELD_OFFSET(EID_SMARTCARD_CSP_INFO, bBuffer));
		const WCHAR* rgNames[] = {
			L"Gemalto IDPrime MD",                              // card
			L"Microsoft Base Smart Card Crypto Provider",        // csp
			L"eid-container",                                    // container
			L"Reader 0",                                         // reader
		};
		// CContainer.cpp starts the first name at bBuffer index 4.
		ULONG rgOffsets[ARRAYSIZE(rgNames)] = {};
		DWORD cchTotal = 4;   // CContainer.cpp: first name at bBuffer index 4
		for (size_t i = 0; i < ARRAYSIZE(rgNames); i++)
		{
			rgOffsets[i] = static_cast<ULONG>(cchTotal);
			cchTotal += static_cast<DWORD>(wcslen(rgNames[i])) + 1;
		}
		const DWORD cb = hdr + cchTotal * sizeof(WCHAR);
		auto buf = MakeCspInfo(cb);
		auto* p = reinterpret_cast<EID_SMARTCARD_CSP_INFO*>(buf.data());
		WCHAR* pBuf = reinterpret_cast<WCHAR*>(buf.data() + hdr);
		for (size_t i = 0; i < ARRAYSIZE(rgNames); i++)
		{
			wcscpy_s(pBuf + rgOffsets[i], wcslen(rgNames[i]) + 1, rgNames[i]);
		}
		p->nCardNameOffset      = rgOffsets[0];
		p->nCSPNameOffset       = rgOffsets[1];
		p->nContainerNameOffset = rgOffsets[2];
		p->nReaderNameOffset    = rgOffsets[3];

		CheckAccepted("cspinfo: production-shaped struct still valid",
			EIDValidateCspInfo(p, cb) != FALSE);

		// And every name must come back intact - validation that accepts the
		// struct but hands back the wrong bytes is its own kind of failure.
		bool fAllNamesMatch = true;
		for (size_t i = 0; i < ARRAYSIZE(rgNames); i++)
		{
			PCWSTR psz = EIDCspInfoStringAt(p, cb, rgOffsets[i]);
			if (!psz || wcscmp(psz, rgNames[i]) != 0)
			{
				fAllNamesMatch = false;
			}
		}
		CheckAccepted("cspinfo: all four names round-trip", fAllNamesMatch);
	}
}

//-------------------------------------------------------------------------
// Defect 4 - EID_PRIVATE_DATA blob.
// usPasswordLen == 0 underflowed dwRoundNumber; overlapping regions made the
// SecureZeroMemory span exceed the allocation.
//-------------------------------------------------------------------------
void TestPrivateData()
{
	printf("\nDefect 4: private-data blob (StoredCredentialManagement.cpp:77,:1751,:1768)\n");

	const DWORD hdr = static_cast<DWORD>(FIELD_OFFSET(EID_PRIVATE_DATA, Data));

	// 4a. usPasswordLen = 0 -> dwRoundNumber = 0 -> (dwRoundNumber - 1)
	//     underflows -> terminator written ~4 GB past a 2-byte allocation.
	{
		std::vector<BYTE> blob(hdr + 64, 0);
		auto* p = reinterpret_cast<EID_PRIVATE_DATA*>(blob.data());
		p->dwCertificatOffset = 0;
		p->dwCertificatSize = 16;
		p->dwSymetricKeyOffset = 16;
		p->dwSymetricKeySize = 16;
		p->dwPasswordOffset = 32;
		p->usPasswordLen = 0;
		Check("blob: usPasswordLen=0 underflow",
			!EIDValidatePrivateDataLayout(p, static_cast<DWORD>(blob.size())),
			"zero length underflows dwRoundNumber");
	}

	// 4b. Three regions overlapping at offset 0. Each fits individually, so the
	//     old per-region check passed, and the old cleanup SUMMED the sizes for
	//     SecureZeroMemory and overran the allocation.
	//
	//     Note what this case does and does not prove today: EIDPrivateDataSpan
	//     now takes the MAX of the region ends, so the span would be safe here
	//     even without the overlap rejection. This guards the structural rule
	//     (no writer overlaps regions), not a memory-safety property.
	{
		const DWORD cbData = 32;
		std::vector<BYTE> blob(hdr + cbData, 0);
		auto* p = reinterpret_cast<EID_PRIVATE_DATA*>(blob.data());
		p->dwCertificatOffset = 0;  p->dwCertificatSize = static_cast<USHORT>(cbData);
		p->dwSymetricKeyOffset = 0; p->dwSymetricKeySize = static_cast<USHORT>(cbData);
		p->dwPasswordOffset = 0;    p->usPasswordLen = static_cast<USHORT>(cbData);
		Check("blob: overlapping regions inflate zeroize span",
			!EIDValidatePrivateDataLayout(p, static_cast<DWORD>(blob.size())),
			"sum of sizes exceeds allocation");
	}

	// 4c. Region extending one byte past the data area.
	{
		const DWORD cbData = 32;
		std::vector<BYTE> blob(hdr + cbData, 0);
		auto* p = reinterpret_cast<EID_PRIVATE_DATA*>(blob.data());
		p->dwCertificatOffset = 0;   p->dwCertificatSize = 16;
		p->dwSymetricKeyOffset = 16; p->dwSymetricKeySize = 8;
		p->dwPasswordOffset = 24;    p->usPasswordLen = 9;   // 24+9 = 33 > 32
		Check("blob: region overruns data area by one",
			!EIDValidatePrivateDataLayout(p, static_cast<DWORD>(blob.size())),
			"off-by-one at the region boundary");
	}

	// 4d. Blob smaller than the header.
	{
		std::vector<BYTE> blob(4, 0);
		Check("blob: smaller than header",
			!EIDValidatePrivateDataLayout(reinterpret_cast<EID_PRIVATE_DATA*>(blob.data()), 4),
			"header read would be OOB");
	}

	// 4f. Block-length arithmetic. CryptGetKeyParam(KP_BLOCKLEN) returns the
	//     block size in BITS (128 for AES) but the encrypt/decrypt loops used it
	//     as a BYTE count. Whenever a length is an exact multiple of that value
	//     the final round was computed as zero-length, which silently truncated
	//     the stored password on the way in and failed outright with NTE_BAD_LEN
	//     on the way out. Both were confirmed against live CryptoAPI: a
	//     63-character password enrolled fine and could never be decrypted.
	//
	//     This asserts the corrected rule directly: a zero remainder means a
	//     FULL final block.
	{
		const DWORD dwBlockLen = 128;   // KP_BLOCKLEN as reported for AES
		const struct { DWORD cbInput; DWORD cbExpectedFinal; const char* pszWhy; } cases[] = {
			{  2, 2,           "1 char" },
			{126, 126,         "63 chars - ciphertext lands on the boundary" },
			{128, dwBlockLen,  "64 chars - exact multiple, was 0" },
			{130, 2,           "65 chars" },
			{256, dwBlockLen,  "128 chars - exact multiple, was 0" },
		};
		bool fAllCorrect = true;
		for (size_t i = 0; i < ARRAYSIZE(cases); i++)
		{
			const DWORD dwRemainder = cases[i].cbInput % dwBlockLen;
			const DWORD dwFinal = dwRemainder ? dwRemainder : dwBlockLen;
			if (dwFinal != cases[i].cbExpectedFinal || dwFinal == 0)
			{
				printf("  FAIL  final-block length for %-46s got %u want %u\n",
					cases[i].pszWhy, dwFinal, cases[i].cbExpectedFinal);
				fAllCorrect = false;
			}
		}
		CheckAccepted("blob: final block is never zero-length", fAllCorrect);
	}

	// 4e. Well-formed blob accepted, and its zeroize span must be inside the
	//     allocation - the property the fix depends on.
	{
		const DWORD cbData = 48;
		std::vector<BYTE> blob(hdr + cbData, 0);
		auto* p = reinterpret_cast<EID_PRIVATE_DATA*>(blob.data());
		p->dwCertificatOffset = 0;   p->dwCertificatSize = 16;
		p->dwSymetricKeyOffset = 16; p->dwSymetricKeySize = 16;
		p->dwPasswordOffset = 32;    p->usPasswordLen = 16;
		const DWORD cbBlob = static_cast<DWORD>(blob.size());
		CheckAccepted("blob: benign layout still valid",
			EIDValidatePrivateDataLayout(p, cbBlob) != FALSE);

		const DWORD dwSpan = EIDPrivateDataSpan(p, cbBlob);
		g_total++;
		if (dwSpan > 0 && dwSpan <= cbBlob)
		{
			printf("  PASS  %-46s (span %u <= %u)\n", "blob: zeroize span within allocation", dwSpan, cbBlob);
		}
		else
		{
			printf("  FAIL  %-46s span %u vs allocation %u\n", "blob: zeroize span within allocation", dwSpan, cbBlob);
			g_failures++;
		}
	}
}

//-------------------------------------------------------------------------
// Config loader hardening (CSVConfig.cpp).
//
// The rotation values and the log path both come from logging.json - the only
// config source that parses untrusted bytes, and the only one that was missing
// the clamps the registry/GPO/trace-consumer loaders all apply. The log path
// additionally drives EnsureLogDirSecured, which rewrites a directory's DACL
// as SYSTEM, so an unconstrained path there is an arbitrary-ACL rewrite.
//
// The rotation clamp is reimplemented here rather than linked: CSVConfig.cpp pulls
// in the tracing and JSON machinery, which the standalone harness cannot host. The
// log path rule is the real one (EID_IsAcceptableLogPath in LogDirSecurity.h, a
// self-contained header), shared by CSVConfig.cpp and EIDTraceConsumer.
//-------------------------------------------------------------------------
DWORD ClampRotation(long long llValue)
{
	return (llValue < 1) ? 1 : (llValue > 100 ? 100 : static_cast<DWORD>(llValue));
}

// EID_CSV_IsAcceptableLogPath in CSVConfig.cpp is this, plus a MAX_PATH bound.
bool IsAcceptableLogPathRule(const std::wstring& wsPath)
{
	return wsPath.length() < MAX_PATH && EID_IsAcceptableLogPath(wsPath.c_str()) != FALSE;
}

void TestConfigLoader()
{
	printf("\nConfig loader: rotation clamps and logPath (CSVConfig.cpp)\n");

	// The reported case: a negative count truncated to DWORD became 0xFFFFFFFF
	// and drove ~4.29 billion GetFileAttributesW calls holding s_csLogger.
	const struct { long long llIn; DWORD dwWant; const char* pszWhy; } rgClamp[] = {
		{        -1, 1,   "negative (was 0xFFFFFFFF)" },
		{         0, 1,   "zero" },
		{         5, 5,   "typical value passes through" },
		{       100, 100, "upper bound" },
		{      1000, 100, "above upper bound" },
		{ 4294967295LL, 100, "0xFFFFFFFF" },
	};
	bool fClampsOk = true;
	for (size_t i = 0; i < ARRAYSIZE(rgClamp); i++)
	{
		const DWORD dwGot = ClampRotation(rgClamp[i].llIn);
		if (dwGot != rgClamp[i].dwWant)
		{
			printf("  FAIL  clamp %-44s got %u want %u\n", rgClamp[i].pszWhy, dwGot, rgClamp[i].dwWant);
			fClampsOk = false;
		}
	}
	CheckAccepted("config: rotation values clamped to [1,100]", fClampsOk);

	// Paths that must be refused before any DACL work happens.
	const wchar_t* rgBad[] = {
		L"",                                                  // empty
		L"\\\\server\\share\\evil.csv",                       // UNC
		L"\\\\?\\C:\\ProgramData\\OpenAccessEID\\x.csv",   // device namespace
		L"C:\\ProgramData\\OpenAccessEID\\..\\..\\x.csv",  // traversal
		L"C:/ProgramData/OpenAccessEID/x.csv",             // forward slashes
		L"C:\\Windows\\System32\\x.csv",                       // outside the product dir
		L"C:\\ProgramData\\OpenAccessEIDEvil\\x.csv",      // prefix look-alike
		L"x.csv",                                              // relative
		L"C:\\ProgramData\\OpenAccessEID\\x.csv:ads",      // alternate data stream
		L"C:\\ProgramData\\OpenAccessEID",                  // the directory itself
	};
	bool fRejectsOk = true;
	for (size_t i = 0; i < ARRAYSIZE(rgBad); i++)
	{
		if (IsAcceptableLogPathRule(rgBad[i]))
		{
			printf("  FAIL  logPath accepted but should be refused: '%ls'\n", rgBad[i]);
			fRejectsOk = false;
		}
	}
	// A path with no room left for ".NNN" or "diagnostics.log" (string functions
	// in the trace consumer used to abort the service on it).
	std::wstring wsLong = L"C:\\ProgramData\\OpenAccessEID\\";
	wsLong.append(MAX_PATH - wsLong.length() - 10, L'a');
	if (IsAcceptableLogPathRule(wsLong))
	{
		printf("  FAIL  logPath with no room for rotation suffixes accepted\n");
		fRejectsOk = false;
	}
	CheckAccepted("config: hostile logPath values refused", fRejectsOk);

	// And the legitimate one must still work, or logging silently stops.
	CheckAccepted("config: default logPath still accepted",
		IsAcceptableLogPathRule(L"C:\\ProgramData\\OpenAccessEID\\logs\\events.csv"));
}

} // namespace

int main()
{
	printf("EID input-validation regression replay\n");
	printf("======================================\n");

	TestTokenMessages();
	TestCspInfo();
	TestPrivateData();
	TestConfigLoader();

	printf("\n%d/%d checks passed.\n", g_total - g_failures, g_total);
	if (g_failures != 0)
	{
		printf("REGRESSION: %d check(s) failed.\n", g_failures);
	}
	return g_failures;
}
