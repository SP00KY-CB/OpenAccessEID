# OpenAccess EID — VM Test Plan

> ## v2.0.00 prerelease gate
>
> The v2.0.00 prerelease combines two changes: the security hardening from
> `security-fuzzing-hardening` (Part Z below) and the rename from EID
> Authentication to OpenAccess EID (Part R). Run **both parts** on the
> prerelease installer before promoting it. The rename swaps the LSA
> authentication package, which gates every logon on the machine, so a build
> that compiles proves nothing here.
>
> ## Part R — rename and upgrade from EID Authentication v1.3.00
>
> | # | Step | Expected | ✓ | Notes |
> |---|------|----------|---|-------|
> | R1 | On a VM with **v1.3.00 installed and a card enrolled**, set `RequireCardBoundCredentials` and one other smart-card policy to non-default values and enable CSV logging. Snapshot. Run **this build's** installer interactively. | The prompt names "EID Authentication (the former name of OpenAccess EID)" and says the installer replaces the old uninstaller's credential-deleting step. The old uninstaller runs and **finishes before** the new install continues; its cleanup checkboxes are unchecked; leave them. After install, a warning about Group Policy appears. | ☐ | |
> | R2 | Before rebooting, check `HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider`. | Both policy values from R1 are still present. | ☐ | |
> | R3 | Reboot, then **log on with the enrolled card, without re-enrolling**. | Succeeds: the installer ran the v1.3.00 uninstaller with this build's `DllUnRegister` substituted (U1), so the enrolment survived. No re-enrol notice was shown. `%TEMP%\OpenAccessEID-install.log` (of the account that ran the installer) records the substitution. **Rollback trigger.** | ☐ | |
> | R4 | `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages"` and `/v "Security Packages"`. | Both list `OpenAccessEIDPackage` and neither lists `EIDAuthenticationPackage`. **Rollback trigger** if the old name remains. | ☐ | |
> | R5 | Check `C:\Windows\System32`. | `OpenAccessEIDPackage.dll`, `EIDCredentialProvider.dll` and `EIDPasswordChangeNotification.dll` present; `EIDAuthenticationPackage.dll` absent. | ☐ | |
> | R6 | Check `C:\ProgramData`. | `OpenAccessEID\` holds the previous `logs\events.csv` and `logging.json`; `EIDAuthentication\` is gone (or, if the installer logged that the move failed or that the old folder was not owned by SYSTEM/Administrators, still holds the old logs). `icacls C:\ProgramData\OpenAccessEID` shows no inherited ACEs: SYSTEM and Administrators Full, Users read. New events are written under `OpenAccessEID\logs`. | ☐ | |
> | R7 | Check `HKLM\SOFTWARE\OpenAccessEID\LogManager`. | Holds the CSV logging settings from R1. `HKLM\SOFTWARE\EIDAuthentication` no longer exists. | ☐ | |
> | R8 | Task Scheduler. | `OpenAccess EID\Apply Trace Config` exists; `EID Authentication\Apply Trace Config` does not. | ☐ | |
> | R9 | Start Menu, Apps & Features, `C:\Program Files`. | Only "OpenAccess EID" entries; no "EID Authentication" folder, shortcut or uninstall entry. | ☐ | |
> | R10 | Copy `OpenAccessEID.admx`/`.adml` into `%WINDIR%\PolicyDefinitions` (the installer does this), open `gpedit.msc`. | An **OpenAccess EID** category shows every policy; setting one writes under `HKLM\SOFTWARE\Policies\OpenAccessEID\LogManager`. `EIDAuthentication.admx` is gone. | ☐ | |
> | R11 | Restore the R1 snapshot and repeat the upgrade **silently**: `EIDInstallx64.exe /S`. Reboot, log on with the card without re-enrolling. | No prompts or dialogs; logon succeeds with the existing enrolment. | ☐ | |
> | R12 | Install v2.0.00 over itself (repair/reinstall) and reboot. | Prompt names "OpenAccess EID"; policies and logging settings survive; card logon succeeds. | ☐ | |
> | R13 | Fresh VM: install v2.0.00, reboot, enrol, log on. | Succeeds; logs under `C:\ProgramData\OpenAccessEID\logs\events.csv`; no `EIDAuthentication` anywhere in the registry (`reg query HKLM /f EIDAuthentication /s`). | ☐ | |
> | R14 | Uninstall, reboot. | Both LSA lists are clean of `OpenAccessEIDPackage`; the machine still logs on with a password. | ☐ | |
>
> **Rollback trigger:** any ❌ on R3, R4, R11 or R14.

> ## Part U — installer upgrade and hardening (this build)
>
> One row (or more) per installer behaviour changed in this build. "LSASS
> holds the DLL" means: a machine where OpenAccess EID is installed and has been
> rebooted since, so LSASS has `OpenAccessEIDPackage.dll` and
> `EIDPasswordChangeNotification.dll` loaded. Warnings that a silent install
> cannot show are appended to `%TEMP%\OpenAccessEID-install.log` of the account
> running the installer (`C:\Windows\Temp` when it runs as SYSTEM).
>
> | # | Step | Expected | ✓ | Notes |
> |---|------|----------|---|-------|
> | U1 | **v2.0.00 → this build, interactive.** VM with v2.0.00 installed, rebooted, a card enrolled; snapshot it (the "U1 snapshot"). Run this build's installer; leave the old uninstaller's checkboxes unticked. Before rebooting, `dir C:\Windows\System32\OpenAccessEIDPackage.dll*`. Reboot, log on with the card **without re-enrolling**. | The install log has "Substituted this version's unregistration step…". Before the reboot System32 holds `OpenAccessEIDPackage.dll`, `OpenAccessEIDPackage.dll.oaeid-new` and one or more `*.oaeid-old-{GUID}` files. Logon succeeds; no re-enrol notice was shown. **Rollback trigger.** | ☐ | |
> | U2 | **v2.0.00 → this build, silent:** restore the U1 snapshot, `EIDInstallx64.exe /S`, reboot, log on with the card. | Logon succeeds with the existing enrolment. | ☐ | |
> | U3 | **Refusal path.** Restore the U1 snapshot. As admin, deny yourself write access to System32's copy so the substitution fails: `icacls C:\Windows\System32\OpenAccessEIDPackage.dll /deny *S-1-5-32-544:(D)` (undo afterwards with `/remove:d *S-1-5-32-544`). Run `EIDInstallx64.exe /S`, then check `echo %ERRORLEVEL%` (or the process exit code) and the install log. Then run it interactively. | Silent: the installer exits with code 2 **before** running the old uninstaller (v2.0.00 still installed, enrolment intact); the log says the upgrade was refused and names `/WIPEENROLMENTS=1`. Interactive: a Yes/No warning (default No); No leaves v2.0.00 untouched. | ☐ | |
> | U4 | Repeat U3 silently with `EIDInstallx64.exe /S /WIPEENROLMENTS=1`, reboot. | Upgrade completes; the install log has the re-enrol NOTICE; card logon needs re-enrolment. Interactively (Yes in U3) the same notice is shown as a dialog. | ☐ | |
> | U5 | **DLL survives the reboot (upgrade from this build).** On a machine with this build installed and rebooted (LSASS holds the DLLs), install the next build over it. Before rebooting: `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v PendingFileRenameOperations`. Reboot. | The pending list deletes `…\OpenAccessEIDPackage.dll` / `EIDPasswordChangeNotification.dll` (queued by the old uninstaller) and **later** renames `….dll.oaeid-new` onto the same names. After reboot all three DLLs exist in System32 with the new build's file version, no `.oaeid-new` / `.oaeid-old-*` files are left, and card logon works. **Rollback trigger.** | ☐ | |
> | U6 | **Fresh-install data folder race.** Clean VM. As a standard user, run a loop that keeps trying to create `C:\ProgramData\OpenAccessEID\logs` and a junction `C:\ProgramData\OpenAccessEID\LsaProtectionBackup` (e.g. `for /l %i in (0,0,1) do @(mkdir C:\ProgramData\OpenAccessEID\logs & mklink /J C:\ProgramData\OpenAccessEID\LsaProtectionBackup C:\Users\Public) 2>nul`). Install as admin. | Every attempt inside the new folder fails with "Access is denied": the folder is created with its protected DACL in the same call (install log: "Created C:\ProgramData\OpenAccessEID (owner Administrators…)"). `dir /a C:\ProgramData\OpenAccessEID` shows only `logs`; `icacls` shows owner Administrators, no inherited ACEs, SYSTEM/Administrators Full, Users read. | ☐ | |
> | U7 | As a standard user create `C:\ProgramData\OpenAccessEID` and keep a handle open in it (`cmd /k cd /d C:\ProgramData\OpenAccessEID`). Install as admin (interactive), then again with `/S`. Also try pre-creating `C:\ProgramData\OpenAccessEID.untrusted-test`. | Pre-created names do not matter (the suffix is a random GUID). If the open handle blocks the move, the installer retries for about ten seconds, then shows (interactive) and logs (both) a warning that file logging stays off until an administrator removes the folder. | ☐ | |
> | U8 | **DACL check.** As admin, create `C:\ProgramData\OpenAccessEID` owned by Administrators but add `icacls … /grant *S-1-5-32-545:(OI)(CI)M`. Install. | The folder is treated as untrusted (a non-admin has Modify) and moved aside to `OpenAccessEID.untrusted-{GUID}`; a fresh, locked folder replaces it. A folder that grants Users only read is kept. | ☐ | |
> | U9 | **PowerShell unavailable.** On a VM with an existing `C:\ProgramData\OpenAccessEID` (with a `logging.json`), block `powershell.exe` (AppLocker/WDAC deny, or temporarily rename it under both System32 and SysWOW64 on a throwaway VM). Install. | The install log says the folder could not be checked and was **moved aside** to `C:\ProgramData\OpenAccessEID.untrusted-{GUID}` rather than adopted; a fresh `OpenAccessEID` (with `logs`) is created, owner Administrators, SYSTEM/Administrators Full, Users read; the moved folder's owner and ACL are unchanged. Copy `logging.json` back by hand. (The uninstaller then warns that it could not confirm the LSA lists are clean - expected.) | ☐ | |
> | U10 | **Custom install folder.** (a) As a standard user create `C:\EIDTest` and a file in it; as admin run `EIDInstallx64.exe /D=C:\EIDTest`. (b) As admin create `C:\EIDTools` with an admin-owned file in it; `icacls C:\EIDTools > before.txt`; `/D=C:\EIDTools`. (c) As a standard user create an **empty** `C:\EIDEmpty`; `/D=C:\EIDEmpty`. (d) `/D=C:\EIDNew` (not existing). (e) Make `C:\EIDLink` a junction to a user folder and use `/D=C:\EIDLink`. | (a) and (b): refused - "already exists, is not empty and is not an OpenAccess EID installation" - and **nothing in the folder changed**: `icacls` matches `before.txt` (owner, inherited ACEs, Users/Authenticated Users entries all still there). (c) installs: the empty folder was removed and created again, owner Administrators, no inherited ACEs, SYSTEM/Administrators Full, Users read; the standard user has no ACE on it. (d) installs with the same ACL; the trace consumer service starts. (e) refused (junction); the target folder's ACL is unchanged. | ☐ | |
> | U11 | **Uninstall order and LSA lists.** Enrol, then uninstall with "Remove EID certificate mappings" ticked. Separately: install, then add a stray `OpenAccessEIDPackage` entry to `Security Packages` by hand twice (duplicate), uninstall with boxes unticked. | First: the uninstall log shows the credential-mapping removal **before** "Unregistering components…", and mappings are gone. Second: the log says entries were left and removed; `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa` lists none of `OpenAccessEIDPackage`, `EIDAuthenticationPackage`, `EIDPasswordChangeNotification`; every other entry (e.g. `scecli`, `kerberos`) is still there in its original order. | ☐ | |
> | U12 | **LSA protection backup.** Set `RunAsPPL=2` and (if present) note `RunAsPPLBoot`. Run `Disable-LsaProtection.ps1`, then run it again with `-EnableAuditMode`. Check `RunAsPPL.backup.txt`. Uninstall. | The backup still records `RunAsPPL = 2` (the second run kept it). The uninstaller warns that LSA protection is still off and keeps the script at `C:\ProgramData\OpenAccessEID\LsaProtectionBackup\Disable-LsaProtection.ps1`. | ☐ | |
> | U13 | Run the kept script with `-Restore`, then check the registry and the backup folder. | `RunAsPPL` is **2** again (not forced to 1); `RunAsPPLBoot` is restored if it was recorded and untouched if it was "unset"; the backup is renamed `RunAsPPL.restored-<timestamp>.txt`, so a later uninstall gives no warning. Without a backup file, `-Restore` still sets `RunAsPPL=1` as before. | ☐ | |
> | U14 | **Forbidden install folders (refused before anything changes).** Save `icacls "C:\Program Files" > pf.txt`. Run, one at a time, `EIDInstallx64.exe /D=C:\`, `/D=C:\Program Files`, `/D=C:\Program Files (x86)`, `/D=C:\PROGRA~1`, `/D=C:\Windows`, `/D=C:\Windows\Temp\EID`, `/D=C:\ProgramData`, `/D=C:\Users`, `/D=\\localhost\c$\EID`. Then, with **v2.0.00 installed**, set `HKLM\SOFTWARE\OpenAccessEID\InstallPath` to `C:\Program Files` in the 64-bit view (`reg add HKLM\SOFTWARE\OpenAccessEID /v InstallPath /d "C:\Program Files" /f /reg:64`) and run this build's installer **without** `/D=` (interactive and `/S`). | Every run stops at once with "is a drive root, a network path, or a Windows system folder" (shown, and in the install log; `/S` exits with code 2). In the InstallPath case the installer takes the registry value as the install folder (no `/D=` given) and the stop comes **before** the "already installed - uninstall it now?" prompt, so v2.0.00 is still installed. `icacls "C:\Program Files"` still matches `pf.txt` (TrustedInstaller, ALL APPLICATION PACKAGES and ALL RESTRICTED APPLICATION PACKAGES entries present). | ☐ | |
> | U15 | **Previous installation folder with leftovers.** Restore the U1 snapshot (v2.0.00). As admin, put an extra file `notes.txt` in `C:\Program Files\OpenAccess EID`. Upgrade. Separately, on a clean VM install this build, then as admin create `C:\Program Files\OpenAccess EID\extra.txt` and make a standard user its owner (`icacls … /setowner <user>`), uninstall leaving the file, and install again. | First: accepted (the folder the old uninstaller ran over); the install log says its permissions were reset; `icacls` shows owner Administrators, no inherited ACEs. Second: refused ("already exists, is not empty and is not an OpenAccess EID installation" - the uninstaller removed `EIDUninstall.exe` and the `InstallPath` value, so the folder is no longer recognised); nothing in it changed; remove `extra.txt` and the install succeeds. | ☐ | |
> | U16 | **Planted data folder (fresh install).** Clean VM. As a standard user: `mkdir C:\ProgramData\OpenAccessEID` and `mklink /J C:\ProgramData\OpenAccessEID\LsaProtectionBackup C:\Users\Public`. Install as admin. | The install log says `C:\ProgramData\OpenAccessEID` was moved aside to `OpenAccessEID.untrusted-{GUID}` (the junction goes with it); a fresh folder is created with its protected DACL; nothing is written to `C:\Users\Public`. | ☐ | |
> | U17 | **Uninstaller will not write through a planted backup folder.** Installed machine. As admin: run `Disable-LsaProtection.ps1` (creates the backup), then replace `C:\ProgramData\OpenAccessEID\LsaProtectionBackup` by a junction to `C:\Users\Public\x` that holds a copy of `RunAsPPL.backup.txt`. Uninstall. Repeat with a real `LsaProtectionBackup` folder whose owner is a standard user. | The uninstall log says `C:\ProgramData\OpenAccessEID` holds a junction or an item not owned by SYSTEM/Administrators and is not written to; the warning tells the administrator which values to restore by hand; **no** `Disable-LsaProtection.ps1` appears in `C:\Users\Public\x` (or in the user-owned folder). | ☐ | |
> | U18 | **Disable-LsaProtection.ps1 refuses an untrusted backup.** As admin: run the script (creates the backup), then `icacls C:\ProgramData\OpenAccessEID\LsaProtectionBackup\RunAsPPL.backup.txt /setowner <standard user>`. Run `-Restore`; run the script again without `-Restore`. Then restore the owner and instead grant `*S-1-5-32-545:(M)` on `LsaProtectionBackup`; run `-Restore`. Finally rename `C:\ProgramData\OpenAccessEID` away and run the script. | Each run stops with "Refusing to use the LSA Protection backup: …" (or "does not exist. Install (or reinstall) OpenAccess EID…") and **changes nothing**: `RunAsPPL`/`RunAsPPLBoot` are as before and the backup file is not renamed. With the owner and ACL restored, `-Restore` works as in U13. | ☐ | |
> | U19 | **Old uninstaller cancelled.** Restore the U1 snapshot. Note the file version of `C:\Windows\System32\OpenAccessEIDPackage.dll`. Run this build's installer interactively, answer Yes, then press **Cancel** in the v2.0.00 uninstaller. Repeat, and this time make the old uninstaller fail part-way (e.g. kill `EIDUninstall.exe`/`Au_.exe` in Task Manager while it runs). | Cancel: the installer stops with "The uninstaller of the installed version was cancelled or did not finish (exit code 1)"; the install log records it and "Put the original …OpenAccessEIDPackage.dll back in place". System32 holds `OpenAccessEIDPackage.dll` with the **v2.0.00** file version and no `*.oaeid-old-*` file (a queued delete of the GUID-named file in `PendingFileRenameOperations` is expected and harmless). v2.0.00 is still listed in Apps & Features; reboot and log on with the card: works. Killed: the installer also stops (non-zero exit code); running it again completes the upgrade. | ☐ | |
> | U20 | **Uninstall before the post-install reboot.** Clean VM: install this build, do **not** reboot, uninstall. `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v PendingFileRenameOperations`; `dir C:\Windows\System32\*.oaeid-new`. Reboot. Repeat as an upgrade (this build over this build, no reboot, then uninstall). | Before the reboot: no `*.oaeid-new` files are left (or each is queued for deletion), and every `…\<name>.oaeid-new → <name>` rename in the pending list is followed **later** by a delete of `<name>`. After the reboot System32 holds none of `OpenAccessEIDPackage.dll`, `EIDCredentialProvider.dll`, `EIDPasswordChangeNotification.dll`, and no `.oaeid-*` file. | ☐ | |
> | U21 | **Local smart-card policy survives the upgrade.** Restore the U1 snapshot. In `secpol.msc` set "Interactive logon: Require Windows Hello for Business or smart card" = Enabled and "Interactive logon: Smart card removal behavior" = Lock Workstation; set the Smart Card Removal Policy service to Automatic and start it. **Keep a password-capable admin session or snapshot** (smart card is now required). Upgrade interactively; restore the snapshot and upgrade with `/S`. | After each upgrade: `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v scforceoption` = 0x1, `reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v scremoveoption` = 1, `sc qc ScPolicySvc` = AUTO_START and `sc query ScPolicySvc` = RUNNING; the install log has "Restored scforceoption…", "Restored scremoveoption…" and the ScPolicySvc line. With the policies **not** set before the upgrade, neither value exists afterwards and the service is left at manual. | ☐ | |
> | U22 | **Custom folder: parents created protected, folder held in place.** (a) `C:\EIDDeep` does not exist: `EIDInstallx64.exe /D=C:\EIDDeep\Sub\EID`. (b) As a standard user create `C:\UserDir`; as admin run `/D=C:\UserDir\EID` while the standard user runs `for /l %i in (0,0,1) do @ren C:\UserDir UserDir2 2>nul` (stop the loop when the install finishes). (c) Create `C:\EIDSubst`, `subst X: C:\EIDSubst` and use `/D=X:\EID`; then `mklink /J C:\EIDJ C:\EIDTarget` and use `/D=C:\EIDJ\EID`. | (a) installs; the install log has "Created C:\EIDDeep…" and "Created C:\EIDDeep\Sub…"; `icacls` on both shows owner Administrators, no inherited ACEs, SYSTEM/Administrators Full, Users read. (b) Every rename fails while the installer runs; the install completes in `C:\UserDir\EID` and `sc qc EIDTraceConsumer` points there. (c) Both refused with "is really C:\EIDSubst\EID" / "is really C:\EIDTarget\EID" (a junction, symbolic link or mapped drive above the folder). | ☐ | |
> | U23 | **Folder holding `EIDUninstall.exe` is checked before its permissions change.** As admin create `C:\EIDFake`, copy any file into it as `EIDUninstall.exe`, add `notes.txt` and `icacls C:\EIDFake\notes.txt /setowner <standard user>`; `icacls C:\EIDFake /t > before.txt`. Run `/D=C:\EIDFake`. Then make every file admin-owned again, block PowerShell (as in U9) and repeat. | First: refused with "holds EIDUninstall.exe, but it or something in it is not owned by SYSTEM/Administrators…"; `icacls C:\EIDFake /t` still matches `before.txt` (no permission was changed). Second: refused with "…its contents could not be checked…", again with nothing changed. | ☐ | |
> | U24 | **ScPolicySvc start type preserved exactly.** Restore the U1 snapshot. (a) `sc config ScPolicySvc start= disabled`; upgrade. (b) Restore; `sc config ScPolicySvc start= delayed-auto`; upgrade. (c) Restore; leave it at the default (manual); upgrade. | (a) `sc qc ScPolicySvc` = DISABLED after the upgrade (the old uninstaller set it to manual; the install log says it was set back to `start= disabled`). (b) AUTO_START (DELAYED) and running. (c) DEMAND_START, and no ScPolicySvc line in the install log. | ☐ | |
>
> **Rollback trigger:** any ❌ on U1, U2, U5, U11, U14, U19 or U21.

> ## Part V — behaviour changes in this build (LSA package, credential provider, EIDMigrate)
>
> These changes are deliberate, but each one changes what an existing
> deployment sees. Use real hardware where it says so: a virtual or emulated
> card does not exercise the PIV paths.
>
> | # | Step | Expected | ✓ | Notes |
> |---|------|----------|---|-------|
> | V1 | **One card, one account.** Enrol card A on local user `alice`. Then, as `bob` (or for `bob` in the configuration wizard / `EIDManageUsers`), try to enrol the same card A. Remove `alice`'s enrolment and enrol `bob` again. | The second enrolment is refused with error **183** (`ERROR_ALREADY_EXISTS`, "Cannot create a file when that file already exists"); `EIDMigrate import` of an export that holds the same certificate for a second account reports the same error as HRESULT **`0x800700B7`**. `alice` still logs on with card A. After `alice`'s enrolment is removed, `bob` enrols and logs on. | ☐ | |
> | V2 | **PIV / default-container fallback (real cards).** With a **YubiKey (PIV)** and an **Idemia IDOne PIV** card (and any other PIV card in use): enrol, lock/unlock, log off/log on, change the Windows password, log on again. Then enter a wrong PIN once. | Every step works as before. The wrong PIN gives the usual wrong-PIN message and decrements the retry counter once; it does **not** silently retry another container. (The default container is now tried only when opening the named key container fails with `NTE_BAD_KEYSET`, `NTE_KEYSET_NOT_DEF` or `SCARD_E_NO_KEY_CONTAINER`.) **Rollback trigger** if a PIV card that worked on the previous build no longer enrols or logs on. | ☐ | |
> | V3 | **SSP network authentication (expected not to work).** If any deployment uses the SSP for network authentication, run that scenario between two machines running **this build**, then with one machine on the **previous build**. With tracing on, note what the client (initiator) side does. | Fails in every combination - **expected in this build**: network (SSP) authentication between machines does not work. The client side is not refused up front: `SpInitLsaModeContext` creates a context, and building the response message then fails with `SEC_E_UNKNOWN_CREDENTIALS`. (Previous build ↔ this build would fail anyway: the messages are not wire-compatible.) Interactive smart-card logon is unaffected. **Rollback trigger** only if a deployment depends on SSP network authentication. | ☐ | |
> | V4 | **Unresolvable group (domain).** Groups are read live at logon (`NetUserGetGroups` / `NetUserGetLocalGroups`), so deleting a local group tests nothing: it is simply no longer listed. Instead, on a domain-joined VM, make an enrolled domain user a member of a domain group whose **name no longer maps to a SID** from the member machine - an orphaned group (for example, delete or rename it on the DC that answers the group enumeration while the member's name lookups still go to a DC that has not replicated, or any other way your lab produces one). Log on with the card (tracing on). Optional: make the group lookup fail for another reason (name lookups to the DC blocked while the group enumeration still works) and log on again. | Logon succeeds. The trace (ETW / `C:\ProgramData\OpenAccessEID\logs`) records that the group's name did not map to a SID (`ERROR_NONE_MAPPED`) and that it was skipped; it is not in `whoami /groups`, every other group is. Optional step: the logon **fails** - only `ERROR_NONE_MAPPED` is skipped, any other lookup error fails the logon. | ☐ | |
> | V5 | **Certificate details link hidden on secure surfaces.** With a card inserted, look at the OpenAccess EID tile on the logon screen, on the lock screen (Win+L), and in a UAC prompt that asks for credentials (e.g. "Run as administrator" from a standard user) - once with the secure desktop on and once with it **off** (`PromptOnSecureDesktop` = 0). Then open a CredUI prompt from an ordinary user process that does not ask for the secure prompt (e.g. the Remote Desktop client's credential prompt). | No certificate-details link on the logon screen, the lock screen or either UAC prompt (the UAC prompt is hosted by a SYSTEM process even without the secure desktop). The link is shown only in the CredUI prompt of the user process. Enrolment and logon are otherwise unchanged. | ☐ | |
> | V6 | **EIDMigrate format v2.** Export with this build (`EIDMigrate.exe export -local -output v2.eid -password <16+ chars>`), then `EIDMigrate.exe list -input v2.eid …` / `validate`. Import a file exported by v2.0.00 or v1.3.00 with this build. Try to import `v2.eid` with the previous build. | `validate` succeeds. `list` prints the JSON payload's `formatVersion` **"1.0"** - the payload schema, not the file header - so it does **not** show 2; the header version 2 is visible only in the trace, or indirectly (the previous build rejects the file). The file round-trips into another VM running this build. The old (v1) file imports. The previous build rejects `v2.eid` (unsupported version) - expected: upgrade the importing machine first. | ☐ | |
> | V7 | **GINA path refuses card-bound credentials.** Only where a GINA (or another client of the `EIDCMEIDGinaAuthenticationChallenge` / `EIDCMEIDGinaAuthenticationResponse` calls) is in use: enrol a user with `RequireCardBoundCredentials` = 1 (card-bound, encrypted credential) and authenticate through that GINA path; then do the same for a user enrolled with the policy off. | Card-bound user: refused with `ERROR_NOT_SUPPORTED` (50); the trace has "GINA authentication not supported for crypted credential" and a `[POLICY_DENY]` audit event. The same user logs on normally through the credential provider. Other user: works through the GINA path as before. | ☐ | |
>
> **Rollback trigger:** any ❌ on V2 or V4 (users locked out), or V1 refusing a first enrolment.

> ## Part Z — additional gate for `security-fuzzing-hardening` (PR #54)
>
> This branch changes code on the interactive logon path, inside LSASS, in the
> installer, and in the credential export format. The rows below are **in
> addition to** everything already in this document, and each one exists because
> a specific defect was fixed there. Run them on a build from this branch.
>
> | # | Step | Expected | ✓ | Notes |
> |---|------|----------|---|-------|
> | Z1 | Smart-card logon, correct PIN. | Logon succeeds. **The whole branch is void if this fails** — it touches the CSP-info validator, the submit-buffer bounds check, the minidriver load path and the challenge length rule. | ☐ | |
> | Z2 | Smart-card logon, **wrong** PIN, then correct PIN. | Wrong PIN is refused with the usual message and the retry succeeds. Exercises the rewritten `__try/__finally` that now wipes the PIN on all eighteen exits. | ☐ | |
> | Z3 | Enrol a user with a **57–63 character** password, then log on with the card. | Both succeed. Before this branch, enrolment reported success and every later logon failed with `NTE_BAD_LEN` — the stored ciphertext landed exactly on the block boundary. | ☐ | |
> | Z4 | Enrol a user with a **64 character** password, then log on. | Both succeed. This length previously stored a truncated (effectively empty) password. | ☐ | |
> | Z5 | Enrol with an ordinary 8–20 character password and log on. | Succeeds — confirms the block-length change did not disturb the common case. | ☐ | |
> | Z6 | On a machine with an existing enrolment from **this build**, install the next build over it (upgrade) and log on without re-enrolling; then uninstall with the cleanup boxes unticked, reinstall, log on. | Both logons succeed: neither the upgrade nor the plain uninstall deletes stored credentials. (Upgrades from v1.3.00/v2.0.00 are covered by R3, R11 and U1-U4.) | ☐ | |
> | Z7 | Fresh install on a clean VM, then check `HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider\RequireCardBoundCredentials`. | Value is **1**. New installs are card-bound by default now. | ☐ | |
> | Z8 | Upgrade an existing install that has the policy at 0 (or absent). | Value is **unchanged**. An upgrade must never silently re-lock an existing signature-only enrolment. | ☐ | |
> | Z9 | With `RequireCardBoundCredentials=1`, attempt to enrol a **signature-only** card. | Enrolment is refused with a clear error. This is the intended trade for Z7. | ☐ | |
> | Z10 | Full install → uninstall → reinstall cycle. | All succeed. Seventeen helper launches in the installer moved from bare names to `$SYSDIR` absolute paths; a typo would surface here. | ☐ | |
> | Z11 | Silent install `EIDInstallx64.exe /S`, then silent uninstall. | Both complete without a prompt. | ☐ | |
> | Z12 | Confirm the scheduled task `OpenAccess EID\Apply Trace Config` exists after install and runs at boot. | Task present; trace config applied. Its `/TR` payload also changed to an absolute path. | ☐ | |
> | Z13 | `EIDMigrate` export to `.eidm` with a **17–32 character** passphrase, then import it on another VM. | Round-trips. That passphrase length previously overflowed a 32-byte stack buffer in the HMAC key path. | ☐ | |
> | Z14 | Import an `.eidm` produced by **v1.3.00**. | Imports successfully — the iteration count is now read from the file header rather than assumed. | ☐ | |
> | Z15 | Run the configuration wizard's **debug report** feature end to end. | Report is produced. The named pipe is now single-instance with `SECURITY_IDENTIFICATION`, and the path it receives is validated. | ☐ | |
> | Z16 | Corrupt `C:\ProgramData\OpenAccessEID\logging.json` (invalid JSON), then log on. | Logon succeeds, LSASS does not crash, and an ETW `[CONFIG_REJECT]` event is recorded. | ☐ | |
> | Z17 | Set `logPath` in `logging.json` to a path outside `C:\ProgramData\OpenAccessEID`. | Rejected; the default log path is retained. | ☐ | |
> | Z18 | Uninstall with "Remove EID certificate mappings from users" **ticked**, reinstall, try the old card. | Card logon is no longer possible until re-enrolment; the uninstall trace shows `CleanupLsaCredentials` removing the mappings. | ☐ | |
> | Z19 | On a clean VM, as a **standard user**, create `C:\ProgramData\OpenAccessEID` with a `logging.json` in it; then install as admin. | Installer logs that the folder was moved aside to `OpenAccessEID.untrusted-*` and creates a fresh, locked-down folder. | ☐ | |
> | Z20 | As admin, `icacls C:\ProgramData\OpenAccessEID\logging.json /setowner <a standard user>`, then log on. | `logging.json` is ignored with an ETW `[CONFIG_REJECT]` event; logging falls back to registry/defaults. | ☐ | |
>
> **Rollback trigger:** any ❌ on Z1, Z2, Z5, Z6, Z8 or Z10. Those are the rows
> where a failure means existing users are locked out or cannot install.

---

## Original plan (security-uplift)

**Purpose:** Verify the `security-uplift` branch on a clean VM before merging to
`quality-fixes`. This is the explicit gate from `SECURITY_REVIEW.md`: every High/Medium
finding is code-complete, but nothing has been exercised end-to-end on a real machine.

**Branch under test:** `security-uplift` @ `43721a5`
**Installer:** `Installer\EIDInstallx64.exe` (rebuilt from this branch — confirm timestamp is
newer than commit `43721a5`, i.e. after 2026-07-15 22:20)
**Cards on hand:** MyEID Aventra (decrypt-capable), YubiKey PIV (decrypt-capable)

Work top to bottom. Tick each box; record the observed result in the Notes column when it
differs from Expected. A single ❌ on any **Core regression** or **must-block** row is a
merge blocker.

---

## Part A — Environment setup

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| A1 | Fresh Windows 11 VM (matching target build), **local account** only, not domain-joined. | Clean baseline. | ☐ | |
| A2 | Take a VM snapshot named `baseline-preinstall`. | Restore point exists. | ☐ | |
| A3 | Install the smart-card minidriver(s) for your card(s) if not already present (the installer bundles them under the Complete install type). | Card visible in `certutil -scinfo`. | ☐ | |
| A4 | Copy `EIDInstallx64.exe` to the VM. Verify its SHA-256 against `Installer\SHA256SUMS.txt`. | Hash matches. | ☐ | |
| A5 | Run the installer elevated → Complete. Reboot. | Installs with no errors; reboots clean. | ☐ | |
| A6 | Confirm files: `OpenAccessEIDPackage.dll`, `EIDCredentialProvider.dll` registered; `EIDConfigurationWizard.exe`, `EIDMigrate.exe`, `EIDMigrateUI.exe`, `EIDManageUsers.exe`, `EIDTraceConsumer.exe` present. **`EIDLogManager.exe` must be absent** (removed on this branch). | All present except EIDLogManager. | ☐ | |
| A7 | Take snapshot `installed-clean`. | Restore point exists. | ☐ | |

---

## Part B — Core regression (must still work)

These prove the security hardening didn't break the product. Any ❌ blocks merge.

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| B1 | Launch **EIDConfigurationWizard**, enroll the local account with the card (Option 2: real Windows password as backup). | Enrollment completes; cert bound to account. | ☐ | |
| B2 | Sign out. At the logon screen, select the smart-card tile, enter PIN. | Logs on from certificate only (no password typed). | ☐ | |
| B3 | Lock the workstation (Win+L), unlock with card + PIN. | Unlocks. | ☐ | |
| B4 | Wrong PIN at logon. | Rejected gracefully, no crash, retry allowed. | ☐ | |
| B5 | Remove card / no card present at logon. | Message tile shown; cannot log on with card. No secure-desktop wizard/reset dialog appears (M4). | ☐ | |
| B6 | Post-logon, confirm DPAPI-protected resource opens (proves stored password backup works). | Accessible. | ☐ | |
| B7 | Enroll a **second** account using the YubiKey (Option 1: blank password + blank-password GPO set). Log on with it. | Smart-card-only logon works. | ☐ | |
| B8 | Reboot; LSASS stable across several logon/lock cycles. | No LSASS crash, no event-log faults. | ☐ | |

---

## Part C — Security fix verification

Each row cites the finding. "must-block" rows are attacks the fix should now **prevent** —
a ❌ (i.e. the attack succeeds) is a merge blocker.

### H1 / H2 / M7 / M8 — LSASS memory safety

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-H1 | From an **unprivileged** user, exercise the credential-management IPC path (create/has/remove stored credential) via the normal UI flows, and with any available fuzz/malformed submit-buffer harness. | LSASS validates buffer; malformed input rejected with clean error, **no LSASS crash/read** (must-block). | ☐ | |
| C-H2 | Attempt enrollment / credential store with an over-length key blob (>32 bytes) if a test path allows. | Bounded copy; rejected, no overflow (must-block). | ☐ | |
| C-M7 | `EIDMigrate validate -i <crafted.eidm>` with an oversized/Forged `PayloadLength`. | Rejected with bounds error, no OOB/DoS (must-block). | ☐ | |
| C-M8 | Import a file with malformed `EID_PRIVATE_DATA` sizes. | Parse rejects; no underflow. | ☐ | |

### H3 — Card-bound stored credentials (`RequireCardBoundCredentials`)

Policy key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider`,
DWORD `RequireCardBoundCredentials` (default 0/off).

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-H3a | With policy **off** (default), confirm existing behavior unchanged (B1–B6 already cover this). | Baseline works. | ☐ | |
| C-H3b | Set `RequireCardBoundCredentials=1`. Re-enroll / log on with the decrypt-capable card. | Only card-wrapped (eidpdtCrypted) creds created & used; logon succeeds. | ☐ | |
| C-H3c | With policy **on**, attempt to create/import a DPAPI/ClearText (non-card-bound) credential. | Refused (must-block). | ☐ | |
| C-H3d | With policy **on**, confirm a previously stored DPAPI/ClearText cred is **not** usable at logon. | Rejected. | ☐ | |

### M1 — Offline certificate revocation

Policy key: same subkey, DWORD `RequireRevocationCheck` (default 0/off, fail-closed when 1).

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-M1a | `EIDMigrate import-crl -i <valid-signed.crl>` (CLI). | CRL installed; signature verified. | ☐ | |
| C-M1b | `EIDMigrate import-crl -i <tampered-or-wrong-signer.crl>`. | Rejected — signature check fails (must-block). | ☐ | |
| C-M1c | **EIDMigrateUI → "Manage certificate revocation"** page: install a signed CRL + toggle `RequireRevocationCheck`. | GUI installs CRL and sets policy; no CLI needed. | ☐ | |
| C-M1d | With `RequireRevocationCheck=1` and a CRL that **revokes** the card's cert installed, attempt logon. | Logon denied — revoked cert rejected (must-block). | ☐ | |
| C-M1e | With `RequireRevocationCheck=1` but **no** CRL available (revocation "unknown"). | Fail-closed: logon denied. | ☐ | |
| C-M1f | Confirm the auth stack does **cache-only** checking — pull the network / stay air-gapped; a valid non-revoked cert with a cached CRL still logs on, and no outbound network attempt occurs. | Logon works offline; no network calls (Wireshark/loopback check optional). | ☐ | |

### M2 — Elevated trust-anchor install requires confirmation

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-M2a | Run `EIDConfigurationWizardElevated.exe TRUST <cert>` (or via the wizard's elevated path). | Per-cert confirmation dialog shows **subject / issuer / SHA-1**, defaults to **No**; declining aborts install (must-block: no silent machine-wide root install). | ☐ | |
| C-M2b | Run `EIDConfigurationWizardElevated.exe ENABLESIGNATUREONLY` (and `ENABLENOEKU`, `ENABLETIMEINVALID`). | Each prompts for confirmation before weakening the GPO; declining aborts. | ☐ | |
| C-M2c | Confirm the policy keys are admin-write only (unprivileged user cannot set them). | Access denied for standard user. | ☐ | |

### M3 — Import validates the certificate

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-M3a | `EIDMigrate import` (with `-force`) of a file whose cert is **self-signed / untrusted / wrong-EKU / revoked**, in production mode. | Import rejects the credential (chain + EKU + offline revocation reused via `IsTrustedCertificate`) (must-block). | ☐ | |
| C-M3b | Import of a file with a **valid, trusted, correct-EKU** cert. | Import succeeds. | ☐ | |

### H4 — Migration file provenance

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-H4a | `EIDMigrate export` on the issuing machine, then `EIDMigrate import`/`validate` on the VM. | CLI surfaces the provenance stamp (source **machine / operator / time**) held inside the AES-GCM+HMAC payload. | ☐ | |
| C-H4b | `EIDMigrate import -i <file> -expect-source <correct-machine>`. | Proceeds. | ☐ | |
| C-H4c | `EIDMigrate import -i <file> -expect-source <wrong-machine>`. | Refused before any account/password/group change (must-block). | ☐ | |
| C-H4d | Tamper with the `.eidm` bytes, then import with the correct passphrase. | AES-GCM/HMAC integrity fails; import aborts. | ☐ | |

### M5 / M6 — Install / service hardening

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-M5 | Inspect ACLs on SYSTEM-written log dirs (CSV logger / trace consumer output). Attempt a junction/reparse redirect as a lower-priv writer. | Explicit DACL present; reparse redirect refused (must-block). | ☐ | |
| C-M6 | `sc qc <EID trace/consumer service>` — inspect `BINARY_PATH_NAME`. | Path is quoted (no unquoted-service-path CWE-428). | ☐ | |

### Audit / SIEM (supporting)

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| C-AUD1 | After exercising H1/H2/H3 paths and a migration, inspect the structured audit output (events CSV) and the event pipeline. | Security-control events emitted; migration audit routed to pipeline; CSV is SIEM-parseable (header + rows). | ☐ | |

---

## Part D — Group Policy / logging via GPO (EIDLogManager removed)

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| D1 | Load the ADMX/ADML (`Installer\PolicyDefinitions`) into the VM's local policy store; confirm the OpenAccess EID policy nodes appear (incl. ETW trace-session settings). | Policies visible in `gpedit.msc`. | ☐ | |
| D2 | Set trace/logging via GPO; confirm `EIDTraceConsumer` honors it (no EIDLogManager app needed). | Tracing controlled by policy. | ☐ | |
| D3 | Confirm no leftover EIDLogManager registration/shortcuts. | None. | ☐ | |

---

## Part E — Teardown

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| E1 | Uninstall via the installer's uninstaller (includes certificate cleanup). | Clean removal; account reverts to password logon. | ☐ | |
| E2 | Reboot; confirm normal password logon restored. | Logs on. | ☐ | |
| E3 | Restore `baseline-preinstall` snapshot to release the VM. | Clean. | ☐ | |

---

## Sign-off

- [ ] All **Core regression** (Part B) passed.
- [ ] All **must-block** attack rows in Part C blocked as expected.
- [ ] No LSASS crash observed at any point.
- [ ] Result recorded → clear to merge `security-uplift` → `quality-fixes`.

**Tester:** ____________  **Date:** ____________  **VM build:** ____________

## Uninstaller certificate cleanup (PR #53)

1. Install the build, enrol a user (creates root CA `CN=EID:<machine>` in
   LocalMachine Root and a user certificate issued by it).
2. Verify presence: `certutil -store root | findstr EID:` shows the CA;
   the enrolled user's My store contains the issued certificate.
3. Uninstall with "Remove EID Root Certificate Authority..." TICKED.
4. Verify: `certutil -store root | findstr EID:` -> nothing;
   `certutil -store ca | findstr EID:` -> nothing; enrolled user's My store
   has no cert issued by `EID:<machine>` (log on as that user or load the
   hive); `certutil -key | findstr /i <CA container>` -> gone.
5. Reinstall, uninstall again with the box UNTICKED -> CA cert, user certs
   and key container all survive.

## Uninstall leftovers and wrong-PIN protection

Uninstall (the trace consumer service used to outlive the uninstaller's delete,
leaving `EIDTraceConsumer.exe` and the installation folder behind):

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| L1 | Install, reboot, confirm `sc query EIDTraceConsumer` is RUNNING (diagnostics off, the default). Uninstall interactively. | The uninstall log shows `Service stopped` and `Service uninstalled successfully`. `C:\Program Files\OpenAccess EID` is gone **before** rebooting; `sc query EIDTraceConsumer` reports the service does not exist. | ☐ | |
| L2 | Repeat L1 with diagnostics capture enabled by policy. | Same result. | ☐ | |
| L3 | Repeat L1 as a silent uninstall (`EIDUninstall.exe /S`). | Same result. | ☐ | |
| L4 | Upgrade from **v2.1.00_TEST_REL** (whose uninstaller does not wait for the service). | Install completes with no "Error opening file for writing" prompt for `EIDTraceConsumer.exe`; after the reboot `sc query EIDTraceConsumer` is RUNNING from `C:\Program Files\OpenAccess EID\EIDTraceConsumer.exe`. | ☐ | |

Wrong-PIN protection at the logon / unlock tile. Use a minidriver card (for example MyEID) whose PIN allows **8** wrong attempts and that can be unblocked with its PUK; check the count first. Rows P1-P7 use the default policies (delay from the 5th wrong PIN for 10 seconds; the card's last attempt held back).

| # | Step | Expected | ✓ | Notes |
|---|------|----------|---|-------|
| P1 | Enter a wrong PIN four times. | Each is refused with the usual "N retries" message; no wait between attempts. | ☐ | |
| P2 | Enter a fifth wrong PIN and dismiss the error. | The PIN box and Submit button are hidden and the tile reads "Too many incorrect PINs. Try again in N seconds.", counting down from 10 once a second. The screen stays responsive. At 0 the PIN box comes back with focus. | ☐ | |
| P3 | Enter a sixth wrong PIN. | Another 10-second countdown (the card now has 2 attempts left). | ☐ | |
| P4 | Enter a seventh wrong PIN. | The card has 1 attempt left: no countdown; the tile reads "This card has only 1 PIN attempt left before it is blocked. Remove the card and insert it again to try again." with no PIN box, and stays like that however long you wait. The card is **not** blocked. | ☐ | |
| P5 | Remove the card and insert it again, then enter the correct PIN. | The PIN box comes back at once, with no countdown. Logon succeeds, and the card's retry counter is back to 8 (a later wrong PIN reports 7 retries). | ☐ | |
| P6 | Repeat P1-P4, then during a countdown (P2) remove and re-insert the card. | The PIN box comes back at once and five more wrong PINs are allowed before the next countdown. | ☐ | |
| P7 | Repeat until the hold (P4), re-insert, and enter a wrong PIN once more. | That one attempt is allowed and the card is now blocked ("maximum number of PIN entry attempts"). Unblock it with the PUK. | ☐ | |
| P8 | `gpedit.msc` → Computer Configuration → Administrative Templates → Windows Components → OpenAccess EID. | "Delay PIN entry after repeated wrong PINs" (5 / 10) and "Hold back the card's last PIN attempts until it is re-inserted" (1) are listed with those defaults. | ☐ | |
| P9 | Enable the delay with 2 wrong PINs and 20 seconds, and the hold with 3 attempts. Repeat from P1. | The countdown starts at the 2nd wrong PIN and lasts 20 seconds; the hold starts as soon as the card reports 3 attempts left. | ☐ | |
| P10 | Enable the delay with 0 seconds and the hold with 0. Repeat from P1 (unblock afterwards). | No countdown and no hold: every wrong PIN is sent to the card, which blocks after its 8th. | ☐ | |
| P11 | With a PIV card used through the Windows built-in PIV driver (no vendor minidriver), enter wrong PINs. | The countdown applies; the hold does not (the driver does not report remaining attempts), as documented. | ☐ | |
