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

#include <utility>

enum class GPOPolicy
{
  AllowSignatureOnlyKeys,
  AllowCertificatesWithNoEKU,
  AllowTimeInvalidCertificates,
  AllowIntegratedUnblock,
  ReverseSubject,
  X509HintsNeeded,
  IntegratedUnblockPromptString,
  CertPropEnabledString,
  CertPropRootEnabledString,
  RootsCleanupOption,
  FilterDuplicateCertificates,
  ForceReadingAllCertificates,
  scforceoption,
  scremoveoption,
  EnforceCSPWhitelist,  // Security: block CSP providers not in whitelist
  RequireCardBoundCredentials,  // Security (H3): when set, only card-wrapped (crypted) credentials may be created/used/imported
  RequireRevocationCheck,  // Security (M1): when set, "revocation unknown" (no local CRL) is a hard failure (fail-closed)
  PinDelayThreshold,  // Logon tile: wrong PINs allowed before each further one starts a countdown
  PinDelaySeconds,  // Logon tile: length of that countdown; 0 = no countdown
  PinAttemptsReserved,  // Logon tile: card PIN attempts held back until the card is re-inserted; 0 = none
};

// Validates that a GPOPolicy enum value is within valid bounds to prevent array overflow
// Marked constexpr+noexcept for compile-time evaluation and LSASS compatibility
constexpr bool IsValidPolicy(GPOPolicy policy) noexcept
{
    return policy >= GPOPolicy::AllowSignatureOnlyKeys && policy <= GPOPolicy::PinAttemptsReserved;
}

// Compile-time validation of GPOPolicy enum bounds
static_assert(IsValidPolicy(GPOPolicy::AllowSignatureOnlyKeys), "AllowSignatureOnlyKeys must be a valid policy");
static_assert(IsValidPolicy(GPOPolicy::PinAttemptsReserved), "PinAttemptsReserved must be a valid policy");

// 0 when the policy is not configured.
DWORD GetPolicyValue(GPOPolicy Policy);
// dwDefault when the policy is not configured, so that 0 can be a configured value.
DWORD GetPolicyValueOrDefault(GPOPolicy Policy, DWORD dwDefault);
BOOL SetPolicyValue(GPOPolicy Policy, DWORD dwValue);
