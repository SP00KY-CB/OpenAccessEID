/*
    OpenAccess EID - fuzz target: interactive-logon submit buffer
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
// EID_INTERACTIVE_UNLOCK_LOGON is the richest attacker-controlled surface in
// the product: any local process can hand one to LsaLogonUser. It carries three
// UNICODE_STRING offset/length pairs (UserName, LogonDomainName, Pin) whose
// Buffer fields are CLIENT-SPACE OFFSETS to be rebased, plus a CspData block
// with its own interior layout - all inside one caller-supplied length.
//
// RemapPointer in Package.cpp is the choke point that validates and rebases it.
// It lives in EIDCardLibrary and drags in the LSA dispatch table, so it cannot
// be linked into this standalone harness. What IS linkable is the set of rules
// it depends on, which is what this target exercises:
//
//   * the bounds rule SafeCheckBufferOverflow applies to each (offset, length)
//     pair before rebasing, reimplemented here and checked against the same
//     arithmetic the production code performs; and
//   * EIDValidateCspInfo, called for real, on the interior of the same buffer.
//
// ORACLE: a submit buffer that passes every check must yield rebased pointers
// that all land inside the buffer, and a CspData interior whose declared length
// fits the block the caller described. Anything else is an ASan report or an
// explicit oracle violation.
//
// This target exists because docs/FUZZING.md previously implied the submit
// buffer was covered when only its sub-structures were.
//=============================================================================

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "EIDCardLibrary.h"
#include "InputValidation.h"
#include "oracle.h"

namespace {

// Mirror of SafeCheckBufferOverflow (Package.cpp): TRUE means "would overflow".
bool WouldOverflow(ULONG_PTR offset, ULONG length, ULONG limit)
{
	if (offset > MAXULONG_PTR - length)
	{
		return true;
	}
	return offset + length > limit;
}

// Mirror of the per-UNICODE_STRING rule RemapPointer applies
// (IsCountedStringHeaderValid, then the bounds check). Length may not exceed
// MaximumLength, an absent (NULL) Buffer must carry no length, and both
// MaximumLength and Length are bounds-checked, in that order.
bool CountedStringFits(const UNICODE_STRING& us, ULONG cbBuffer)
{
	if (us.Length > us.MaximumLength)
	{
		return false;
	}
	if (us.Buffer == nullptr)
	{
		// absent field: nothing to rebase, but a length with no buffer is
		// rejected (it reached memcpy_s(..., NULL, Length) in the logon path)
		return us.Length == 0 && us.MaximumLength == 0;
	}
	const ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(us.Buffer);
	if (WouldOverflow(offset, us.MaximumLength, cbBuffer)) return false;
	if (WouldOverflow(offset, us.Length, cbBuffer))        return false;
	return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	// Must at least hold the fixed struct - RemapPointer now refuses anything
	// smaller, because it reads these fields to validate them.
	if (size < sizeof(EID_INTERACTIVE_UNLOCK_LOGON) || size > (1u << 20))
	{
		return 0;
	}

	// Exact-size, aligned copy so ASan brackets the submit buffer precisely.
	void* pRaw = _aligned_malloc(size, 8);
	if (!pRaw)
	{
		return 0;
	}
	memcpy(pRaw, data, size);

	auto* pUnlock = static_cast<PEID_INTERACTIVE_UNLOCK_LOGON>(pRaw);
	const ULONG cbBuffer = static_cast<ULONG>(size);
	BYTE* pBase = static_cast<BYTE*>(pRaw);

	const bool fUserNameOk = CountedStringFits(pUnlock->Logon.UserName, cbBuffer);
	const bool fDomainOk   = CountedStringFits(pUnlock->Logon.LogonDomainName, cbBuffer);
	const bool fPinOk      = CountedStringFits(pUnlock->Logon.Pin, cbBuffer);

	bool fCspOk = true;
	if (pUnlock->Logon.CspData != nullptr)
	{
		const ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(pUnlock->Logon.CspData);
		fCspOk = !WouldOverflow(offset, pUnlock->Logon.CspDataLength, cbBuffer);
	}
	else
	{
		fCspOk = (pUnlock->Logon.CspDataLength == 0);
	}

	if (fUserNameOk && fDomainOk && fPinOk && fCspOk)
	{
		// Every accepted counted string must rebase to a range inside the
		// buffer, and reading it must stay in bounds. This is the arithmetic
		// LsaApLogonUserEx2 performs immediately afterwards.
		const UNICODE_STRING* rgStrings[] = {
			&pUnlock->Logon.UserName,
			&pUnlock->Logon.LogonDomainName,
			&pUnlock->Logon.Pin,
		};
		volatile WCHAR wchSink = 0;
		for (size_t i = 0; i < ARRAYSIZE(rgStrings); i++)
		{
			EID_ORACLE_REQUIRE(rgStrings[i]->Length <= rgStrings[i]->MaximumLength,
				"a validated UNICODE_STRING has Length > MaximumLength");
			if (rgStrings[i]->Buffer == nullptr)
			{
				EID_ORACLE_REQUIRE(rgStrings[i]->Length == 0,
					"a validated UNICODE_STRING has a NULL Buffer with a non-zero Length");
				continue;
			}
			const ULONG_PTR off = reinterpret_cast<ULONG_PTR>(rgStrings[i]->Buffer);
			const BYTE* pStart = pBase + off;
			EID_ORACLE_REQUIRE(pStart >= pBase && pStart <= pBase + cbBuffer,
				"a validated UNICODE_STRING rebased outside the submit buffer");
			EID_ORACLE_REQUIRE(off + rgStrings[i]->Length <= cbBuffer,
				"a validated UNICODE_STRING extends past the submit buffer");
			const WCHAR* pwsz = reinterpret_cast<const WCHAR*>(pStart);
			for (USHORT cch = 0; cch < rgStrings[i]->Length / sizeof(WCHAR); cch++)
			{
				wchSink ^= pwsz[cch];
			}
		}
		(void)wchSink;

		// CspData: the outer bound is established, so now apply the real
		// interior validator and read every name it blesses - exactly what the
		// logon path does once RemapPointer returns.
		if (pUnlock->Logon.CspData != nullptr)
		{
			const ULONG_PTR off = reinterpret_cast<ULONG_PTR>(pUnlock->Logon.CspData);
			auto* pCspInfo = reinterpret_cast<const EID_SMARTCARD_CSP_INFO*>(pBase + off);
			const DWORD cbCspData = pUnlock->Logon.CspDataLength;

			if (EIDValidateCspInfo(pCspInfo, cbCspData))
			{
				EID_ORACLE_REQUIRE(pCspInfo->dwCspInfoLen <= cbCspData,
					"CspInfo accepted with an interior length exceeding CspDataLength");
				EID_ORACLE_REQUIRE(off + cbCspData <= cbBuffer,
					"CspData block extends past the submit buffer");

				const ULONG rgOffsets[] = {
					pCspInfo->nCardNameOffset,
					pCspInfo->nReaderNameOffset,
					pCspInfo->nContainerNameOffset,
					pCspInfo->nCSPNameOffset,
				};
				for (size_t i = 0; i < ARRAYSIZE(rgOffsets); i++)
				{
					PCWSTR psz = EIDCspInfoStringAt(pCspInfo, cbCspData, rgOffsets[i]);
					if (psz)
					{
						const BYTE* pRet = reinterpret_cast<const BYTE*>(psz);
						EID_ORACLE_REQUIRE(pRet >= pBase && pRet < pBase + cbBuffer,
							"a CSP name pointer landed outside the submit buffer");
						(void)wcslen(psz);
					}
				}
			}
		}
	}

	_aligned_free(pRaw);
	return 0;
}
