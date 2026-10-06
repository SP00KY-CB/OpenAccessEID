# Fuzzing OpenAccess EID

This project fuzzes its own parsers on Windows, with MSVC's libFuzzer and
AddressSanitizer. Quick commands live in [`../fuzz/README.md`](../fuzz/README.md);
this document explains what is covered, what deliberately is not, and why the
OpenSSF Scorecard Fuzzing check will stay at zero.

## Why this exists

On 2026-07-30 a review of the parsers handling attacker-influenced input found
four memory-safety defects, three of them reachable in LSASS:

1. The SSP challenge and response token handlers performed **no length
   validation at all** — no `cbBuffer` check, not even against `sizeof` the
   fixed header — while using attacker-controlled offsets as raw pointer
   displacements.
2. The unlock-logon debug printer indexed the CSP-info buffer with raw 32-bit
   attacker offsets and printed the results with `%s`, and wrote a terminator at
   up to index 32767 of a 1000-element stack array. It ran unconditionally on
   every logon attempt.
3. `EID_SMARTCARD_CSP_INFO.dwCspInfoLen` was never bounded against the length
   the LSA supplied, while both downstream validators bounded their offsets
   against it.
4. A zero `usPasswordLen` underflowed the decrypt loop's round counter, and
   three cleanup paths derived a `SecureZeroMemory` length by summing region
   sizes that were only ever individually bounded.

The instructive detail is defect 2: a careful manual hardening pass had added a
`Pin.Length` bound twenty-five lines *below* the debug printer and missed the
identical exposure just above it. Reviews miss what they are not looking at.
A fuzzer does not have a reading order.

## Architecture

All offset and length rules live in `EIDCardLibrary/InputValidation.{h,cpp}`.
That module is **pure and total**: no allocation, no tracing, no LSA, registry
or CryptoAPI calls, and it never reads outside the `(pointer, size)` pair the
caller supplies. Two properties follow:

- The production call sites share exactly one implementation of each rule.
  Before this, the private-data layout rule existed in three places that
  disagreed on whether the header size was `sizeof` or `FIELD_OFFSET`, and the
  CSP-info rule existed in two places with different field sets — one of which
  compared byte counts against offsets used to index a `TCHAR[]`, permitting a
  2× overrun.
- Fuzz targets link that one translation unit and nothing else, so they run
  outside LSASS with no smart card present.

### The oracle pattern

A target that merely calls a validator and drops the answer finds almost
nothing: it only detects crashes *inside* the validator. Each target here goes
further and asserts the property the production code actually depends on:

> validator returns TRUE ⇒ the consumer's own arithmetic stays in bounds.

After validating, the target performs the same copies and reads the real
consumer performs, against an exact-sized ASan allocation. A validator that
wrongly returns TRUE therefore produces a heap-buffer-overflow report with a
stack trace instead of passing silently.

**Be precise about how much each assertion is worth.** Most of the
`EID_ORACLE_REQUIRE` checks are, given the current validators, tautologies —
they cannot fire unless a validator is later weakened. That makes them
regression detectors, not bug finders, and they are worth keeping on those
terms. Two specific claims deserve care:

- Removing the `dwCspInfoLen <= dwCspDataLength` check does make the `cspinfo`
  target die within 30 seconds — but the crash is a `heap-buffer-overflow`
  *inside the validator itself*, so a target that merely called the validator
  and discarded the answer would find it just as fast. That experiment
  demonstrates the harness works; it does **not** demonstrate that the oracle
  adds anything.
- The assertion that **does** earn its place is the pointer-range check in
  `fuzz_cspinfo.cpp`: `EIDCspInfoStringAt` must return a pointer inside
  `bBuffer`. It caught a real defect in the committed validator that ASan was
  structurally blind to — an offset whose WCHAR scaling wrapped 32 bits and
  came back around *inside* the buffer, aliasing the fixed header. In-bounds
  pointers produce no sanitizer report by definition, so only a semantic
  assertion can catch that class.

The lesson generalises: ASan finds out-of-bounds access; an oracle is what
finds *wrong but in-bounds* results. Write assertions about meaning, not just
about memory.

## Coverage

| Target | Covers |
|---|---|
| `cspinfo` | `EID_SMARTCARD_CSP_INFO` interior: inner-vs-outer length, WCHAR-unit offset scaling, NUL termination of all four name fields |
| `tokenmessage` | SSP challenge and response tokens: header size, offset/length pairs, the `+ sizeof(WCHAR)` allocation wrap |
| `privatedata` | Stored-credential blob: per-region bounds, region overlap, the zeroize span, the round-counter underflow |
| `json` | The hand-rolled `JsonParser` reached from `.eidm` import — memory safety only |
| `remappointer` | The interactive-logon submit buffer: three `UNICODE_STRING` offset/length pairs plus the `CspData` block, all inside one caller-supplied length |
| `regress` | Deterministic replay of every defect's PoC input, plus benign inputs that must still be accepted |

`remappointer` covers the entry point an unprivileged caller actually reaches
through `LsaLogonUser`. `RemapPointer` itself needs the LSA dispatch table and
cannot be linked standalone, so the target exercises the rules it depends on —
the `SafeCheckBufferOverflow` bounds rule per pair, and the real
`EIDValidateCspInfo` over the same buffer's interior — and asserts that a buffer
passing every check rebases entirely inside itself.

The regression binary also asserts **benign inputs are still accepted**. Over-
rejection in this code path does not fail safe — it locks users out of the
machine — so "reject everything" must not be able to pass the suite.

## Deliberate non-targets

Not fuzzing something is a decision worth recording, so it is not silently
revisited:

- **Certificate and CRL import.** `InstallCrlFromFile` caps the read at 10 MB
  and hands the bytes straight to `CertCreateCRLContext`; the configuration
  wizard's base64 path goes to `CryptStringToBinary`. There is no manual
  parsing — a target here would be fuzzing `crypt32.dll`.
- **Smart-card responses.** There is no `SCardTransmit` anywhere in the
  repository and no manual APDU or TLV walking. Card data arrives through the
  vendor minidriver's `pfnCard*` entry points and `CryptGetKeyParam`, which
  report their own sizes.
- **The CSV audit log.** Write-only; the repository contains no CSV reader.
- **The ETW trace consumer.** Bounds `UserData` against `UserDataLength`
  correctly and reads only typed `REG_DWORD`/`REG_SZ` configuration values.
- **Profile enumeration during uninstall.** `NTUSER.DAT` is parsed by the
  kernel via `RegLoadKey`, not by this code, and the path is admin-only.
- **Network and RPC.** There are none — no sockets, and no `.idl`/MIDL
  interfaces (the `<Midl>` blocks in the vcxproj files are empty VS defaults).

### Named pipe: a real IPC surface, hardened but not fuzzed

`EIDConfigurationWizard/DebugReport.cpp:239` creates a named pipe
(`CreateNamedPipe`, `ConnectNamedPipe`, `WriteFile`) to talk to the elevated
helper it launches via `ShellExecuteEx`/`runas`. The pipe name carries a
10-character `mt19937` suffix and the security descriptor is `nullptr`, i.e. the
default DACL.

That is a low-integrity-to-high-integrity channel. It has since been hardened —
single-instance creation with `FILE_FLAG_FIRST_PIPE_INSTANCE`,
`SECURITY_IDENTIFICATION` on both client opens, a bounded and NUL-terminated
read, path validation, and `FILE_FLAG_OPEN_REPARSE_POINT` on the elevated
`CreateFile` — but it is **still not fuzzed**, because doing so means driving a
pipe protocol rather than calling a pure function. Do not read its absence from
the target list as a judgement that it is now safe.

## The JSON parser reaches further than the import path

`JsonParser` throws `std::runtime_error` on malformed input by design, so every
caller must catch. Two call chains matter, and the second is the serious one:

1. **`.eidm` credential import.** EIDMigrate has only four `catch` sites and
   none covers `JsonToExportData`, so a malformed export file terminates the
   tool. Admin-supplied file, admin-context tool: an availability bug worth
   fixing, not a security boundary.

2. **Logging configuration, inside LSASS.** `EID_CSV_LoadConfigFromFile`
   (`EIDCardLibrary/CSVConfig.cpp`) is reached from
   `EIDCardLibraryLogStructured` → `InitOnceExecuteOnce` →
   `EIDCSVInitOnceCallback` → `EID_CSV_Initialize` → `EID_CSV_LoadConfig`. That
   runs **in the LSA package**, and an exception escaping an `InitOnce` callback
   is a process crash. The file read was already wrapped in a `try`; the parse —
   the part that consumes untrusted bytes — was not. Now fixed: the parse is
   guarded and falls back to the default configuration, because refusing to
   start the logger is strictly worse than starting it with defaults.

   On a correctly installed machine the installer creates
   `C:\ProgramData\OpenAccessEID` owned by Administrators, with inheritance
   removed: SYSTEM/Administrators full control and Users read-only, so a standard
   user cannot write `logging.json`. The loader also ignores `logging.json` unless
   both the file and that directory are owned by SYSTEM or Administrators and
   neither is a reparse point. Disk corruption, or a bad file written by an
   administrator, remain ways to reach the parser with bad bytes.

The `json` target catches the exception so it reports memory faults only. Do not
widen that catch and call these gaps closed — they are fixed by adding handling
at the call sites, which is what item 2 above did.

## Scorecard will not credit this

The OpenSSF Scorecard Fuzzing check passes only via a fixed set of probes —
OSS-Fuzz, ClusterFuzzLite, OneFuzz, Go-native fuzzing, and property-based
testing for some managed languages. (The exact probe list moves between
Scorecard releases; re-check it rather than trusting this paragraph verbatim.)
**Custom fuzz targets earn nothing**, and all three C/C++ routes are closed here:

- **OneFuzz is gone.** Microsoft ended development in August 2023 and archived
  the repository that November. The probe still exists; the platform does not.
- **OSS-Fuzz and ClusterFuzzLite build inside Linux Docker images with clang.**
  This codebase is Win32-only — LSA, CryptoAPI, SCard, toolset v143.
- OSS-Fuzz additionally requires a project to have "a significant user base
  and/or be critical to global IT infrastructure."

Earning the badge honestly would mean porting these parsers to clang/Linux
behind Win32 shims — substantial work, and the shimmed code is not what ships.
The repository accepts a permanent zero on that check. Scorecard's own
documentation notes that a low Fuzzing score is not a definitive indication of
risk; this is exactly such a case.

## Triage workflow

1. CI fails and uploads a `fuzz-crashes-<run id>` artifact.
2. Download it and replay the reproducer (see `fuzz/README.md` for the exact
   command, including the ASan DLL PATH fix-up).
3. Fix the rule in `InputValidation.cpp` — not at the call site. If a call site
   needs its own check, that is a signal the rule belongs in the module.
4. Add the crashing input as a case in `fuzz/targets/regress_main.cpp` and a
   named seed in `fuzz/Seed-Corpus.ps1`, so the defect can never return
   silently.
5. Re-run `.\fuzz\Run-Fuzzers.ps1 -Regress` and confirm the new case passes.
