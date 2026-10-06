> **Prerelease.** Build-verified and code-reviewed, not yet runtime-tested. This release
> swaps the LSA authentication package and changes code inside LSASS; a failure on the
> logon path locks users out. Do not deploy until `docs/VM_TEST_PLAN.md` Parts R and Z
> have passed on this exact build.

**EID Authentication is now OpenAccess EID.** This release also carries 20 security
fixes, and the project returns to its original license, LGPL-2.1.

## Upgrading from EID Authentication v1.3.00

Run the new installer. It detects the old installation, removes it (keeping
enrollments), and installs OpenAccess EID in its place. **A reboot is required**:
Windows reads its LSA authentication-package list only at boot.

**Smart-card enrollments are preserved.** Stored credentials, certificates and the
smart-card policies (`RequireCardBoundCredentials`, `RequireRevocationCheck` and the
rest) carry over, so users do not re-enrol.

> **Correction (after release):** the paragraph above is wrong. The uninstaller of
> v1.3.00 - and of v2.0.00 itself - deletes every user's stored credential while
> unregistering, whatever its cleanup checkboxes say, and an upgrade runs it. Users
> must re-enrol after upgrading from these versions. Fixed in the next release: its
> uninstaller keeps stored credentials unless "Remove EID certificate mappings from
> users" is ticked, and its installer warns before running an older uninstaller.

| Item | New location | Action |
|---|---|---|
| LSA package | `OpenAccessEIDPackage.dll` (was `EIDAuthenticationPackage.dll`) | Update any scripts that name the DLL. |
| Logs and `logging.json` | `C:\ProgramData\OpenAccessEID` | Re-point SIEM collectors. The installer moves the old folder; if a file is held open it leaves the old folder in place and says so. |
| Logging settings | `HKLM\SOFTWARE\OpenAccessEID\LogManager` | None - copied across. |
| Group Policy template | `OpenAccessEID.admx`, namespace `OpenAccessEID.Policies` | **Re-apply logging policies with the new template** and update any central PolicyDefinitions store. Settings made through the old template are not carried over. |
| Install folder, Start Menu, scheduled task | `OpenAccess EID` | None. |

Component names keep the `EID` prefix, all GUIDs are unchanged, and the stored-credential
format is identical to v1.3.00.

## Security fixes

All of these are present in v1.3.00.

**Highest severity**

- **Arbitrary DLL load into LSASS.** A client-supplied card name could steer the
  minidriver loader outside System32 via `..\` traversal, running attacker code in `lsass.exe`.
- **PIN and password left in LSASS memory on failed logons.** The wrong-PIN path, which an
  attacker can drive at will, left the plaintext PIN on the stack; two paths leaked the
  decrypted Windows password. All eighteen exit paths now wipe.
- **SSP token messages had no length validation**, including an allocation-size wrap that
  turned a 4 GB copy into a one-byte buffer.
- **Null-pointer dereference in LSASS reachable from any local process**, terminating LSASS.

**Correctness defects with security impact**

- Passwords of 57-63 characters enrolled successfully and could then never log on;
  64-character passwords were stored truncated.
- A stack buffer overflow on export passphrases of 17-32 characters.
- A use-after-free on every PBKDF2 iteration during credential import and export.

**Also fixed:** authorization comparing only the trailing RID instead of the full SID; no
challenge freshness in the SSP; a 32-byte LSASS heap disclosure; unscrubbed credential-blob
frees; a named-pipe hijack giving file create/truncate at high integrity; seventeen
installer helper launches by bare name; missing log-rotation clamps in the JSON config
loader; an unconstrained `logPath`; and the PIN leaking to the COM heap on every keystroke.

Fuzzing (MSVC libFuzzer + AddressSanitizer) now runs in CI: five targets plus a
deterministic regression binary.

## Behaviour changes

- **Fresh installs enable `RequireCardBoundCredentials` by default.** Signature-only cards
  cannot enrol while it is set. Upgrades keep the existing value.
- **Empty passwords are refused at enrolment** instead of being stored in a corrupt state.
- **Upgrades no longer reset smart-card policies.** The uninstaller deletes the policy key;
  the installer now saves and restores it around the upgrade, and waits for the old
  uninstaller to finish instead of running alongside it.

## License and attribution

OpenAccess EID is derived from EIDAuthenticate Community Edition by Vincent Le Toux
(Copyright (C) 2009 Vincent Le Toux, (C) 2009-2011 My Smart Logon). His copyright notices
have been restored throughout, and the project is licensed under LGPL-2.1, the license of
the original work. v1.3.00 was published as GPL-3.0. This fork is not affiliated with or
endorsed by My Smart Logon.

## Verifying these artifacts

`SHA256SUMS.txt` is generated during the release build and lists every shipped binary.

```
certutil -hashfile EIDInstallx64.exe SHA256
gh attestation verify EIDInstallx64.exe --repo SP00KY-CB/OpenAccessEID
```
