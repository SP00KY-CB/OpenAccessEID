;--------------------------------
;Include Modern UI

  !include "MUI2.nsh"
  !include "nsDialogs.nsh"
  !include "X64.nsh"
  !include "WinVer.nsh"
  !include "FileFunc.nsh"

;--------------------------------
;General

  ;Name and file
  Name "OpenAccess EID"
  OutFile "EIDInstallx64.exe"

  ;Installer icon (optional - copied by build.ps1 if exists)
  Icon "installer.ico"
  UninstallIcon "installer.ico"

  ;Default installation folder
  InstallDir "$PROGRAMFILES64\OpenAccess EID"

  ;The installation folder of a previous installation (InstallPath, written
  ;to the 64-bit registry view) is read in .onInit, not with InstallDirRegKey:
  ;that reads the 32-bit view, where the value never is.

  ;Request application privileges for Windows Vista
  RequestExecutionLevel admin

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages

  !insertmacro MUI_PAGE_LICENSE "License.txt"
  !insertmacro MUI_PAGE_COMPONENTS
  Page custom ShowSecurityOptions LeaveSecurityOptions
  !insertmacro MUI_PAGE_INSTFILES
  !insertmacro MUI_PAGE_FINISH

  ; Custom uninstall page for certificate/cleanup options
  UninstPage custom un.ShowUninstallOptions un.LeaveUninstallOptions

  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  !insertmacro MUI_UNPAGE_FINISH
;--------------------------------
;Languages

  !insertmacro MUI_LANGUAGE "English"
  !insertmacro MUI_LANGUAGE "French"

;--------------------------------
;Install types
;
;  1 = Core     - application only (existing behaviour)
;  2 = Complete - application + bundled smart-card minidrivers
;                 (MyEID / YubiKey / Idemia IDOne PIV). All minidriver
;                 packages are embedded in the installer at build time -
;                 no internet access is required at install time.

  InstType "Core"
  InstType "Complete"

;--------------------------------
;Variables for size calculation

  Var /GLOBAL InstallSize

;--------------------------------
;Security option (install-time question)

  Var /GLOBAL RequireCardBound
  Var /GLOBAL RequireCardBoundCheckbox
  ; 1 once the Security Options page has actually been presented, so an explicit
  ; operator choice can be told apart from the silent (/S) default.
  Var /GLOBAL SecurityPageShown

;--------------------------------
;Upgrade state

  ; 1 when .onInit found and removed an installation made under the product's
  ; former name, EID Authentication (v1.3.00 and earlier). The Core section
  ; then finishes the migration and warns about orphaned Group Policy.
  Var /GLOBAL MigratedFromLegacy

  ; 1 when the uninstaller of the version being replaced deleted every user's
  ; stored credential (v2.0.00 and earlier, when its unregistration step could
  ; not be swapped for this version's - see NeutraliseOldUnregister). The Core
  ; section then tells the operator that users must re-enrol.
  Var /GLOBAL EnrolmentsWiped

  ; The folder the previous version's uninstaller has just run over (.onInit),
  ; once it finished successfully. PrepareInstallDir accepts that folder even
  ; when the uninstaller left something in it.
  Var /GLOBAL PrevInstallDir

  ; Set by NeutraliseOldUnregister when it put the substitute package DLL in
  ; place: the System32 path, and where the original was renamed to ("" when
  ; there was no original). UndoNeutraliseOldUnregister puts things back if the
  ; old uninstaller is cancelled or fails.
  Var /GLOBAL NeutralisedDll
  Var /GLOBAL NeutralisedAside

  ; Local security policy that uninstallers of every version so far delete
  ; (scforceoption, scremoveoption) and the Smart Card Removal Policy service
  ; start type they reset. Saved before the old uninstaller runs and put back
  ; afterwards - see SaveLocalSmartCardPolicy.
  Var /GLOBAL SavedScForceOption
  Var /GLOBAL SavedScForceOptionType
  Var /GLOBAL SavedScRemoveOption
  Var /GLOBAL SavedScRemoveOptionType
  Var /GLOBAL SavedScPolicySvcStart
  Var /GLOBAL SavedScPolicySvcDelayed

  ; Handle on $INSTDIR, opened by PinInstallDir without FILE_SHARE_DELETE, so
  ; that neither the folder nor any folder above it can be renamed or replaced
  ; while the Core section writes into it. 0 when not open.
  Var /GLOBAL InstallDirHandle

;--------------------------------
;Constants and macros

  ; The DACL the runtime applies to its log directory (EID_LOG_DIR_SDDL): owner
  ; Administrators; protected (nothing inherited from the parent); Full control
  ; for SYSTEM and Administrators and read/execute for Users, inherited by
  ; everything below. Also used for the installation folder.
  !define OAEID_DIR_SDDL "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
  ; The same without the owner, for a token that may not assign Administrators
  ; as owner (CreateProtectedDir falls back to it; LockEIDDirectory then sets
  ; the owner).
  !define OAEID_DIR_SDDL_DACL "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

  ; Uninstaller: an install or upgrade that has not been followed by a reboot
  ; has queued "<name>.oaeid-new -> <name>" (InstallSystemDll), which would put
  ; the DLL back after this uninstall. Delete the staged copy (now, or at the
  ; reboot), and queue a delete of <name> itself: PendingFileRenameOperations
  ; is processed in the order the entries were queued, so that delete runs
  ; after the rename. Call with x64 file system redirection disabled.
  !macro OAEID_CancelStagedDll NAME
    Delete /REBOOTOK "$SYSDIR\${NAME}.oaeid-new"
    ; MOVEFILE_DELAY_UNTIL_REBOOT (4) with no destination: delete at the reboot.
    System::Call 'kernel32::MoveFileExW(w "$SYSDIR\${NAME}", p 0, i 4) i .r0'
  !macroend

;--------------------------------
;Uninstaller Variables

  Var /GLOBAL Uninstall_RemoveMappings
  Var /GLOBAL Uninstall_RemoveCertificates

;--------------------------------
;Installer Sections

Section "Core" SecCore
  SectionIn RO 1 2

  ; Initialize install size counter
  StrCpy $InstallSize 0

  ;--------------------------------------------------------------------
  ; Migration from EID Authentication (v1.3.00 and earlier), part 2.
  ; Part 1 in .onInit has already copied the LogManager settings across and
  ; run the old uninstaller, which deregistered the legacy LSA package
  ; (EIDAuthenticationPackage), scheduled its DLL for deletion and removed
  ; the old registry keys. What is left is state the old uninstaller does not
  ; own.
  ;--------------------------------------------------------------------
  ${If} $MigratedFromLegacy == 1
    DetailPrint "Completing migration from EID Authentication..."

    ; Logs, logging.json and the LSA-protection backup. A rename (not a copy)
    ; keeps the directory's protected DACL and cannot lose an audit trail
    ; half-way. If it fails - a file still held open, or the new directory
    ; already exists - the old directory is left untouched.
    ; Any user can create C:\ProgramData\EIDAuthentication, so it is only moved
    ; when it and everything in it is owned by SYSTEM/Administrators and holds
    ; no junction or symlink; renaming a planted tree into the new location
    ; would hand the SYSTEM logger the attacker's directory.
    ${If} ${FileExists} "C:\ProgramData\EIDAuthentication\*.*"
      ${IfNot} ${FileExists} "C:\ProgramData\OpenAccessEID\*.*"
        Push "C:\ProgramData\EIDAuthentication"
        Call IsEIDDataTreeTrusted
        Pop $R0
        ${If} $R0 != 1
          DetailPrint "WARNING: C:\ProgramData\EIDAuthentication is a junction, or it or something in it is not owned by SYSTEM/Administrators or can be modified by other users, or it could not be checked; not moved. Existing logs remain there."
        ${Else}
          ClearErrors
          Rename "C:\ProgramData\EIDAuthentication" "C:\ProgramData\OpenAccessEID"
          ${If} ${Errors}
            DetailPrint "WARNING: could not move C:\ProgramData\EIDAuthentication; existing logs remain there."
          ${Else}
            DetailPrint "Moved logs and configuration to C:\ProgramData\OpenAccessEID."
          ${EndIf}
        ${EndIf}
      ${Else}
        DetailPrint "C:\ProgramData\OpenAccessEID already exists; existing logs remain in C:\ProgramData\EIDAuthentication."
      ${EndIf}
    ${EndIf}

    ; Belt and braces: remove anything an interrupted old uninstaller may
    ; have left behind under the old name.
    nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Delete /F /TN "EID Authentication\Apply Trace Config"'
    Delete "$WINDIR\PolicyDefinitions\EIDAuthentication.admx"
    Delete "$WINDIR\PolicyDefinitions\en-US\EIDAuthentication.adml"
    RMDir /r "$SMPROGRAMS\EID Authentication"
    Delete "$DESKTOP\EID Authentication Configuration.lnk"
  ${EndIf}

  ; Create and lock down C:\ProgramData\OpenAccessEID (logs and logging.json)
  ; before anything runs as SYSTEM against it. Also covers a directory just
  ; renamed from the legacy location above.
  DetailPrint "Securing C:\ProgramData\OpenAccessEID..."
  Call SecureEIDDataDir

  ; Create the installation directory and lock it down before anything is put
  ; in it. EIDTraceConsumer.exe runs from here as SYSTEM and the System32 DLLs
  ; are copied from here, and /D= (or the InstallPath registry value) can point
  ; $INSTDIR anywhere - including a folder a standard user can write to, or one
  ; that is not ours at all. PrepareInstallDir checks the folder BEFORE it
  ; changes any permission, and stops the installation if it is not a new or
  ; empty folder or a previous OpenAccess EID installation. It also leaves a
  ; handle open on the folder, so that neither it nor any folder above it can
  ; be renamed or replaced until the end of this section (UnpinInstallDir).
  Call PrepareInstallDir
  SetOutPath "$INSTDIR"

  ; Install DLL files to Program Files
  FILE "..\x64\Release\OpenAccessEIDPackage.dll"
  Push "$INSTDIR\OpenAccessEIDPackage.dll"
  Call AddFileSize

  FILE "..\x64\Release\EIDCredentialProvider.dll"
  Push "$INSTDIR\EIDCredentialProvider.dll"
  Call AddFileSize

  FILE "..\x64\Release\EIDPasswordChangeNotification.dll"
  Push "$INSTDIR\EIDPasswordChangeNotification.dll"
  Call AddFileSize

  ; Install all executable files
  FILE "..\x64\Release\EIDConfigurationWizard.exe"
  Push "$INSTDIR\EIDConfigurationWizard.exe"
  Call AddFileSize

  FILE "..\x64\Release\EIDConfigurationWizardElevated.exe"
  Push "$INSTDIR\EIDConfigurationWizardElevated.exe"
  Call AddFileSize

  FILE "..\x64\Release\EIDMigrate.exe"
  Push "$INSTDIR\EIDMigrate.exe"
  Call AddFileSize

  FILE "..\x64\Release\EIDMigrateUI.exe"
  Push "$INSTDIR\EIDMigrateUI.exe"
  Call AddFileSize

  FILE "..\x64\Release\EIDManageUsers.exe"
  Push "$INSTDIR\EIDManageUsers.exe"
  Call AddFileSize

  ; The previous version's uninstaller (run by .onInit) stopped the trace
  ; consumer service, but up to v2.1.00 it did not wait for the service process
  ; to exit, so its EIDTraceConsumer.exe may still be in use here.
  ${If} ${FileExists} "$INSTDIR\EIDTraceConsumer.exe"
    Push "$INSTDIR\EIDTraceConsumer.exe"
    Call RemoveTraceConsumerExe
  ${EndIf}
  FILE "..\x64\Release\EIDTraceConsumer.exe"
  Push "$INSTDIR\EIDTraceConsumer.exe"
  Call AddFileSize

  ; Install icon for DisplayIcon (installed programs list)
  FILE "cred_provider.ico"

  ; Install Group Policy administrative templates (ADMX/ADML) so the
  ; custom OpenAccess EID policies appear in gpedit.msc.
  ; Destination: %WINDIR%\PolicyDefinitions (picked up by Group Policy
  ; Editor automatically on next launch).
  DetailPrint "Installing Group Policy templates..."
  SetOutPath "$WINDIR\PolicyDefinitions"
  File "PolicyDefinitions\OpenAccessEID.admx"
  SetOutPath "$WINDIR\PolicyDefinitions\en-US"
  File "PolicyDefinitions\en-US\OpenAccessEID.adml"
  SetOutPath "$INSTDIR"

  ; Install manual-run administrator tools. Disable-LsaProtection.ps1 must
  ; NOT be executed by the installer - the sysadmin has to read the warning
  ; page and type a confirmation phrase. Ship it under $INSTDIR\tools\ so
  ; it is always available locally after install.
  DetailPrint "Installing administrator tools..."
  SetOutPath "$INSTDIR\tools"
  File "tools\Disable-LsaProtection.ps1"
  SetOutPath "$INSTDIR"

  ; Copy DLLs to System32 (required for LSA and Credential Provider).
  ; LSASS and LogonUI keep these mapped, and the uninstaller that just ran has
  ; usually queued their deletion for the next reboot - InstallSystemDll makes
  ; sure the new copy is what is left after that reboot.
  ${DisableX64FSRedirection}
  Push "OpenAccessEIDPackage.dll"
  Call InstallSystemDll
  Push "EIDCredentialProvider.dll"
  Call InstallSystemDll
  Push "EIDPasswordChangeNotification.dll"
  Call InstallSystemDll

  ; Create Start Menu folder and shortcuts for all executables
  CreateDirectory "$SMPROGRAMS\OpenAccess EID"
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Configuration Wizard.lnk" "$INSTDIR\EIDConfigurationWizard.exe" "" "$INSTDIR\EIDConfigurationWizard.exe" 0
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Credential Migration (CLI).lnk" "$INSTDIR\EIDMigrate.exe" "" "$INSTDIR\EIDMigrate.exe" 0
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Credential Migration (GUI).lnk" "$INSTDIR\EIDMigrateUI.exe" "" "$INSTDIR\EIDMigrateUI.exe" 0
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Manage Users.lnk" "$INSTDIR\EIDManageUsers.exe" "" "$INSTDIR\EIDManageUsers.exe" 0
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Trace Consumer.lnk" "$INSTDIR\EIDTraceConsumer.exe" "" "$INSTDIR\EIDTraceConsumer.exe" 0
  ; Elevated PowerShell shortcut for the LSA Protection toggle script.
  ; Uses -NoExit so the warning page and outcome remain visible after the
  ; script returns; ExecutionPolicy Bypass scoped to this process only.
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Disable LSA Protection (manual).lnk" \
    "powershell.exe" \
    '-NoProfile -NoExit -ExecutionPolicy Bypass -File "$INSTDIR\tools\Disable-LsaProtection.ps1"' \
    "$INSTDIR\cred_provider.ico" 0 SW_SHOWNORMAL "" \
    "Manually disable Windows LSA Protection so unsigned EID DLLs can load. Reads a warning page and requires confirmation."
  CreateShortcut "$SMPROGRAMS\OpenAccess EID\Uninstall.lnk" "$INSTDIR\EIDUninstall.exe" "" "$INSTDIR\EIDUninstall.exe" 0

  ; Create desktop shortcut pointing to Program Files
  CreateShortcut "$DESKTOP\OpenAccess EID Configuration.lnk" "$INSTDIR\EIDConfigurationWizard.exe"

  ; Create uninstaller in installation directory
  WriteUninstaller "$INSTDIR\EIDUninstall.exe"

  ; Write installation path to registry
  SetRegView 64
  WriteRegStr HKLM "Software\OpenAccessEID" "InstallPath" "$INSTDIR"

  ; Security policy: RequireCardBoundCredentials (from the install-time question).
  ; 1 = only card-wrapped (crypted) credentials may be created / used at logon / imported;
  ; the Windows password can then never be recovered without the smart card.
  ; Write the value when the operator actually saw the Security Options page and made a
  ; choice there (including on upgrade/repair - otherwise ticking the box would silently
  ; do nothing). For silent (/S) installs the page never runs, so fall back to writing
  ; only when the policy has never been configured: that preserves an admin's prior
  ; choice and never re-locks an existing non-card-bound enrollment out of logon.
  ClearErrors
  ReadRegDWORD $0 HKLM "SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" "RequireCardBoundCredentials"
  ${If} ${Errors}
  ${OrIf} $SecurityPageShown == 1
    WriteRegDWORD HKLM "SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" "RequireCardBoundCredentials" $RequireCardBound
  ${EndIf}

  ; Uninstall info
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "DisplayName" "OpenAccess EID"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "UninstallString" "$INSTDIR\EIDUninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "Publisher" "OpenAccess EID"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "DisplayIcon" "$INSTDIR\cred_provider.ico"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "NoRepair" 1
  ; Tells a future installer that this version's uninstaller keeps stored
  ; credentials (only the opt-in cleanup checkbox removes them). Uninstallers of
  ; v2.0.00 and earlier deleted them during unregistration.
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "KeepsEnrolmentsOnUninstall" 1

  ; Convert total install size from bytes to KB and write to registry
  IntOp $InstallSize $InstallSize / 1024
  ; Add ~100 KB for uninstaller and directory structures
  IntOp $InstallSize $InstallSize + 100
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID" "EstimatedSize" $InstallSize

  ; Register authentication package (from System32)
  ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",DllRegister'

  ; Configure Smart Card services to start automatically on boot. The
  ; default state on Windows is "Manual (Trigger Start)" which only
  ; starts the services when a reader is already attached - if the user
  ; plugs the reader in after logon, or sign-in needs the service before
  ; any trigger has fired, the Credential Provider will not see any
  ; readers. Forcing start= auto ensures SCardSvr and its device
  ; enumerator are running before the logon UI appears.
  DetailPrint "Configuring Smart Card services for automatic startup..."
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config SCardSvr start= auto'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config ScDeviceEnum start= auto'
  nsExec::ExecToLog '"$SYSDIR\net.exe" start SCardSvr'
  nsExec::ExecToLog '"$SYSDIR\net.exe" start ScDeviceEnum'

  ; Install and start the ETW trace consumer service. Without this the CSV
  ; logging (configured via Group Policy / the LogManager registry key) has no
  ; consumer and never produces files. The executable self-registers as an
  ; auto-start service via -install.
  DetailPrint "Installing EID Trace Consumer service..."
  nsExec::ExecToLog '"$INSTDIR\EIDTraceConsumer.exe" -install'
  nsExec::ExecToLog '"$INSTDIR\EIDTraceConsumer.exe" -start'

  ; Apply the (Group Policy-aware) ETW trace-session config to the WMI autologger now, and create a
  ; boot-time scheduled task that re-applies it each boot so Group Policy changes to the logging/ETW
  ; settings take effect without EIDLogManager. Runs as SYSTEM (needs HKLM autologger write).
  ; $SYSDIR resolves to the real System32 here (x64 FS redirection is disabled above).
  DetailPrint "Applying trace configuration and scheduling the GPO-apply task..."
  nsExec::ExecToLog '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",DllApplyTraceConfigW'
  nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Create /F /RU SYSTEM /RL HIGHEST /SC ONSTART /TN "OpenAccess EID\Apply Trace Config" /TR "$SYSDIR\rundll32.exe $SYSDIR\OpenAccessEIDPackage.dll,DllApplyTraceConfigW"'

  SetPluginUnload manual
  SetRebootFlag true

  ${If} $MigratedFromLegacy == 1
    MessageBox MB_OK|MB_ICONEXCLAMATION "EID Authentication has been upgraded to OpenAccess EID.$\n$\nGroup Policy set through the old EIDAuthentication administrative template is NOT carried over. After rebooting, apply the OpenAccess EID template and re-apply any logging policies.$\n$\nA reboot is required before smart-card logon uses the new version." /SD IDOK
  ${EndIf}

  ; Always recorded, and shown unless silent: after this, every enrolled user is
  ; locked out of smart-card logon until they enrol again.
  ${If} $EnrolmentsWiped == 1
    Push "NOTICE: the uninstaller of the previous version deleted every user's stored smart-card credential. Users must re-enrol their cards before they can log on with them."
    Call InstallLog
    MessageBox MB_OK|MB_ICONEXCLAMATION "The uninstaller of the previous version deleted every user's stored smart-card credential.$\n$\nUsers must re-enrol their cards before they can log on with them." /SD IDOK
  ${EndIf}

  ; Everything has been written to $INSTDIR, the System32 copies made and the
  ; trace consumer service registered from it: release the folder.
  Call UnpinInstallDir

SectionEnd

;--------------------------------
;Smart Card Minidrivers  (Complete install type)
;
;  These sections install vendor smart-card minidrivers that are
;  BUNDLED INTO THE INSTALLER at build time. No network access is
;  required at install time - suitable for isolated / air-gapped
;  deployments.
;
;  Each vendor package is extracted into $PLUGINSDIR (auto-cleaned
;  on installer exit) and installed with the appropriate tool:
;    - MyEID  (ZIP containing INF+DLL+CAT)  -> Expand-Archive + pnputil -i -a
;    - YubiKey (signed MSI)                  -> msiexec /i /qn /norestart
;    - IDOne PIV (CAB from Windows Update)   -> expand.exe + pnputil -i -a
;
;  Failures are logged as warnings and do not abort the Core install.
;
;  The bundled files live in Installer\drivers\ and are staged by
;  build.ps1 (download + SHA-256 verification). See the README.md
;  in that directory.

SectionGroup /e "Smart Card Minidrivers" SecMinidrivers

Section /o "MyEID Minidriver (Aventra)" SecMyEIDMinidriver
  SectionIn 2

  InitPluginsDir
  SetOutPath "$PLUGINSDIR\MyEID"
  File "drivers\MyEID_Minidriver.zip"

  DetailPrint "Extracting MyEID Minidriver..."
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command ' \
    'try { Expand-Archive -LiteralPath "$PLUGINSDIR\MyEID\MyEID_Minidriver.zip" -DestinationPath "$PLUGINSDIR\MyEID\x" -Force; exit 0 } ' \
    'catch { Write-Error $_.Exception.Message; exit 1 }' \
    ''
  Pop $0
  ${If} $0 != 0
    DetailPrint "WARNING: MyEID extraction failed (code $0) - skipping"
    Goto MyEIDDone
  ${EndIf}

  DetailPrint "Installing MyEID Minidriver (pnputil)..."
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command ' \
    '$inf = Get-ChildItem -Path "$PLUGINSDIR\MyEID\x" -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Select-Object -First 1; ' \
    'if (-not $inf) { Write-Error "No INF found in MyEID archive"; exit 2 }; ' \
    '& pnputil.exe -i -a $inf.FullName | Out-Host; ' \
    'exit $LASTEXITCODE' \
    ''
  Pop $0
  ${If} $0 = 0
    DetailPrint "MyEID Minidriver installed successfully"
  ${Else}
    DetailPrint "WARNING: MyEID Minidriver install returned code $0"
  ${EndIf}

MyEIDDone:
SectionEnd

Section /o "YubiKey Minidriver (Yubico)" SecYubiKeyMinidriver
  SectionIn 2

  InitPluginsDir
  SetOutPath "$PLUGINSDIR\YubiKey"
  File "drivers\YubiKey-Minidriver-5.0.4.273-x64.msi"

  DetailPrint "Installing YubiKey Minidriver (msiexec)..."
  nsExec::ExecToLog '"$SYSDIR\msiexec.exe" /i "$PLUGINSDIR\YubiKey\YubiKey-Minidriver-5.0.4.273-x64.msi" /qn /norestart'
  Pop $0
  ${If} $0 = 0
    DetailPrint "YubiKey Minidriver installed successfully"
  ${ElseIf} $0 = 3010
    DetailPrint "YubiKey Minidriver installed successfully (reboot required)"
    SetRebootFlag true
  ${Else}
    DetailPrint "WARNING: YubiKey Minidriver install returned code $0"
  ${EndIf}
SectionEnd

Section /o "IDOne PIV Minidriver (Idemia / Windows Update)" SecWUMinidriver
  SectionIn 2

  InitPluginsDir
  SetOutPath "$PLUGINSDIR\WU"
  File "drivers\WindowsUpdate_Minidriver.cab"
  CreateDirectory "$PLUGINSDIR\WU\x"

  DetailPrint "Extracting CAB contents..."
  nsExec::ExecToLog '"$SYSDIR\expand.exe" -F:* "$PLUGINSDIR\WU\WindowsUpdate_Minidriver.cab" "$PLUGINSDIR\WU\x"'
  Pop $0
  ${If} $0 != 0
    DetailPrint "WARNING: CAB extraction failed (code $0) - skipping"
    Goto WUDone
  ${EndIf}

  DetailPrint "Adding INF driver(s) to the driver store..."
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command ' \
    '$infs = Get-ChildItem -Path "$PLUGINSDIR\WU\x" -Recurse -Filter *.inf -ErrorAction SilentlyContinue; ' \
    'if (-not $infs) { Write-Error "No INF found in CAB"; exit 2 }; ' \
    'foreach ($inf in $infs) { Write-Host ("Installing: " + $inf.FullName); & pnputil.exe -i -a $inf.FullName | Out-Host }; ' \
    'exit 0' \
    ''
  Pop $0
  ${If} $0 = 0
    DetailPrint "IDOne PIV Minidriver installed successfully"
  ${Else}
    DetailPrint "WARNING: IDOne PIV Minidriver install returned code $0"
  ${EndIf}

WUDone:
SectionEnd

SectionGroupEnd

;--------------------------------
;Descriptions

  ;Language strings
  LangString DESC_SecCore ${LANG_ENGLISH} "Core OpenAccess EID components: LSA Authentication Package, Credential Provider, Configuration Wizard, Log Manager, Migrate CLI/UI, and Manage Users tool. Always installed."
  LangString DESC_SecCore ${LANG_FRENCH}  "Composants principaux OpenAccess EID: LSA, Credential Provider, assistant de configuration et outils associes. Toujours installes."

  LangString DESC_SecMinidrivers ${LANG_ENGLISH} "Smart card minidrivers bundled with the installer. No internet access required at install time. Auto-selected for the Complete install type."
  LangString DESC_SecMinidrivers ${LANG_FRENCH}  "Minidrivers de carte a puce fournis avec l'installateur. Aucun acces Internet requis. Selectionnes automatiquement pour l'installation Complete."

  LangString DESC_SecMyEID ${LANG_ENGLISH} "Aventra MyEID minidriver v3.0.1.2 (Certified). Bundled in the installer; extracts and installs via pnputil."
  LangString DESC_SecMyEID ${LANG_FRENCH}  "Minidriver Aventra MyEID v3.0.1.2 (Certifie). Inclus dans l'installateur; extrait et installe via pnputil."

  LangString DESC_SecYubiKey ${LANG_ENGLISH} "YubiKey Smart Card Minidriver 5.0.4.273 (x64). Bundled signed MSI installed silently via msiexec."
  LangString DESC_SecYubiKey ${LANG_FRENCH}  "Minidriver YubiKey 5.0.4.273 (x64). MSI signe inclus, installe silencieusement via msiexec."

  LangString DESC_SecWU ${LANG_ENGLISH} "IDOne PIV minidriver from the Microsoft Update catalog. Bundled signed CAB; extracted and added to the driver store via pnputil."
  LangString DESC_SecWU ${LANG_FRENCH}  "Minidriver IDOne PIV du catalogue Microsoft Update. CAB signe inclus; extrait et ajoute au magasin de pilotes via pnputil."

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore}              $(DESC_SecCore)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMinidrivers}       $(DESC_SecMinidrivers)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMyEIDMinidriver}   $(DESC_SecMyEID)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecYubiKeyMinidriver} $(DESC_SecYubiKey)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecWUMinidriver}      $(DESC_SecWU)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Install-time Security Options page

Function ShowSecurityOptions
  !insertmacro MUI_HEADER_TEXT "Security Options" "Choose how OpenAccess EID protects stored credentials."

  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 60u "When 'Require card-bound credentials' is enabled, each user's Windows password is only ever stored sealed to their smart card, so it cannot be recovered from this machine without the card (and PIN).$\n$\nRecommended for decrypt-capable cards such as MyEID (Aventra) and YubiKey (PIV). Leave it OFF if you use signature-only cards, which cannot use card-bound storage and would otherwise fail to enrol / log on."
  Pop $0

  ${NSD_CreateCheckbox} 10u 68u 100% 12u "Require card-bound credentials (RequireCardBoundCredentials policy)"
  Pop $RequireCardBoundCheckbox
  ${If} $RequireCardBound == 1
    ${NSD_Check} $RequireCardBoundCheckbox
  ${EndIf}

  nsDialogs::Show
FunctionEnd

Function LeaveSecurityOptions
  ${NSD_GetState} $RequireCardBoundCheckbox $RequireCardBound
  StrCpy $SecurityPageShown 1
FunctionEnd

;--------------------------------
;Helper Functions for Certificate Cleanup

Function un.ShowUninstallOptions
  ; Create custom page with checkboxes for uninstall options
  !insertmacro MUI_HEADER_TEXT "Cleanup Options" "Choose what to remove besides the program files."

  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 40u "Select additional cleanup options. Both are off by default so that reinstalling keeps existing enrollments working."
  Pop $0

  ; Checkbox for removing EID certificate mappings from users (LSA credentials)
  ; Default UNCHECKED: destructive cleanup is opt-in (a temporary uninstall/upgrade
  ; must not destroy enrollments)
  ${NSD_CreateCheckbox} 10u 50u 100% 12u "Remove EID certificate mappings from users"
  Pop $Uninstall_RemoveMappings

  ; Checkbox for removing EID root CA + issued certificates
  ${NSD_CreateCheckbox} 10u 70u 100% 24u "Remove EID Root Certificate Authority and all EID-issued user certificates from this machine, including the CA private key (irreversible)"
  Pop $Uninstall_RemoveCertificates

  nsDialogs::Show
FunctionEnd

Function un.LeaveUninstallOptions
  ; Get the state of checkboxes when leaving the page
  ${NSD_GetState} $Uninstall_RemoveMappings $Uninstall_RemoveMappings
  ${NSD_GetState} $Uninstall_RemoveCertificates $Uninstall_RemoveCertificates
FunctionEnd

;--------------------------------
;Uninstaller Section

Section "Uninstall"

  ; Opt-in removal of stored credentials (if the checkbox was selected) comes
  ; first: it asks the package loaded in LSASS to delete them, so it has to run
  ; while the package is still registered.
  ${If} $Uninstall_RemoveMappings = 1
    ; This requires calling into the DLL since NSIS cannot directly manipulate LSA
    DetailPrint "Removing EID credential mappings from LSA..."
    ${DisableX64FSRedirection}
    ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",CleanupLsaCredentials' $1
    ${If} $1 != 0
      DetailPrint "Note: LSA cleanup returned code $1 (may be expected if not installed)"
    ${EndIf}
    ${EnableX64FSRedirection}
  ${Else}
    DetailPrint "Skipping LSA credential mapping removal (not selected)"
  ${EndIf}

  ; Unregister all components (from System32)
  ${DisableX64FSRedirection}
  DetailPrint "Unregistering components..."
  ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",DllUnRegister' $0
  ${If} $0 != 0
    DetailPrint "Warning: DllUnRegister returned error code $0 - continuing with manual cleanup"
  ${EndIf}

  ; rundll32 exits 0 whether or not DllUnRegister worked, so check the LSA
  ; package lists themselves and take out any of our names still there. Left
  ; in, they point LSASS at DLLs that are deleted at the reboot.
  InitPluginsDir
  File "/oname=$PLUGINSDIR\Remove-EIDLsaRegistration.ps1" "scripts\Remove-EIDLsaRegistration.ps1"
  Push "$PLUGINSDIR\Remove-EIDLsaRegistration.ps1"
  System::Call 'kernel32::SetEnvironmentVariable(t "OAEID_SCRIPT", t s)'
  nsExec::ExecToLog /TIMEOUT=120000 `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create([IO.File]::ReadAllText($$env:OAEID_SCRIPT))); exit $$LASTEXITCODE"`
  Pop $0
  ${If} $0 == 10
    DetailPrint "LSA package lists checked: no OpenAccess EID entries left."
  ${ElseIf} $0 == 13
    DetailPrint "DllUnRegister had left OpenAccess EID entries in the LSA package lists; removed them."
  ${Else}
    DetailPrint "WARNING: could not confirm that the LSA package lists are clean (result $0)."
    MessageBox MB_OK|MB_ICONEXCLAMATION "Could not confirm that Windows no longer loads the OpenAccess EID LSA packages (result $0).$\n$\nBefore rebooting, check these values under$\nHKLM\SYSTEM\CurrentControlSet\Control\Lsa$\n  Security Packages, Authentication Packages, Notification Packages$\nand remove OpenAccessEIDPackage, EIDAuthenticationPackage and EIDPasswordChangeNotification if listed." /SD IDOK
  ${EndIf}

  ${EnableX64FSRedirection}

  ; Conditionally remove certificates created by the software (if checkbox was selected).
  ; Native cleanup inside the package DLL (still present - deleted later in this
  ; section): sweeps machine stores and every user profile, deletes the CA key.
  ${If} $Uninstall_RemoveCertificates = 1
    DetailPrint "Removing EID certificates (machine stores and all user profiles)..."
    ${DisableX64FSRedirection}
    ; rundll32 discards the entry point's HRESULT and exits 0 unless it fails to launch,
    ; so $2 only catches a launch failure - per-certificate results go to the ETW trace.
    ExecWait '"$SYSDIR\rundll32.exe" "$SYSDIR\OpenAccessEIDPackage.dll",CleanupEIDCertificates' $2
    ${If} $2 != 0
      DetailPrint "Warning: could not run certificate cleanup (code $2) - certificates remain"
    ${EndIf}
    ${EnableX64FSRedirection}
  ${Else}
    DetailPrint "Skipping certificate removal (not selected)"
  ${EndIf}

  ; Delete Start Menu shortcuts and folder
  Delete "$SMPROGRAMS\OpenAccess EID\Configuration Wizard.lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Credential Migration (CLI).lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Credential Migration (GUI).lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Manage Users.lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Trace Consumer.lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Disable LSA Protection (manual).lnk"
  Delete "$SMPROGRAMS\OpenAccess EID\Uninstall.lnk"
  RMDir "$SMPROGRAMS\OpenAccess EID"

  ; Delete desktop shortcut
  Delete "$DESKTOP\OpenAccess EID Configuration.lnk"

  ; Delete System32 files (LSA-locked, require reboot)
  ${DisableX64FSRedirection}
  Delete /REBOOTOK "$SYSDIR\OpenAccessEIDPackage.dll"
  Delete /REBOOTOK "$SYSDIR\EIDCredentialProvider.dll"
  Delete /REBOOTOK "$SYSDIR\EIDPasswordChangeNotification.dll"
  ; Uninstalling before the reboot that follows an install or upgrade: cancel
  ; the queued "<name>.oaeid-new -> <name>" rename (see the macro).
  !insertmacro OAEID_CancelStagedDll "OpenAccessEIDPackage.dll"
  !insertmacro OAEID_CancelStagedDll "EIDCredentialProvider.dll"
  !insertmacro OAEID_CancelStagedDll "EIDPasswordChangeNotification.dll"

  ; Delete ETW log files
  Delete /REBOOTOK "$SYSDIR\LogFiles\WMI\EIDCredentialProvider.etl"

  ${EnableX64FSRedirection}

  ; Remove Group Policy administrative templates
  Delete "$WINDIR\PolicyDefinitions\OpenAccessEID.admx"
  Delete "$WINDIR\PolicyDefinitions\en-US\OpenAccessEID.adml"

  ; Delete Program Files installation - DLLs
  Delete "$INSTDIR\OpenAccessEIDPackage.dll"
  Delete "$INSTDIR\EIDCredentialProvider.dll"
  Delete "$INSTDIR\EIDPasswordChangeNotification.dll"

  ; Delete Program Files installation - Executables
  Delete "$INSTDIR\EIDConfigurationWizard.exe"
  Delete "$INSTDIR\EIDConfigurationWizardElevated.exe"
  Delete "$INSTDIR\EIDMigrate.exe"
  Delete "$INSTDIR\EIDMigrateUI.exe"
  Delete "$INSTDIR\EIDManageUsers.exe"

  ; Stop and remove the ETW trace consumer service before deleting its binary,
  ; otherwise the running service holds the file open and leaves a stale service.
  ; Remove the trace-config GPO-apply scheduled task
  nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Delete /F /TN "OpenAccess EID\Apply Trace Config"'
  ; Both wait (up to 30 seconds) for the service process to exit.
  nsExec::ExecToLog '"$INSTDIR\EIDTraceConsumer.exe" -stop'
  Pop $0
  nsExec::ExecToLog '"$INSTDIR\EIDTraceConsumer.exe" -uninstall'
  Pop $0
  ${If} $0 != 0
    DetailPrint "Warning: removing the EID Trace Consumer service returned $0 - it is removed once its process exits"
  ${EndIf}
  Push "$INSTDIR\EIDTraceConsumer.exe"
  Call un.RemoveTraceConsumerExe
  Delete "$INSTDIR\cred_provider.ico"

  ; Disable-LsaProtection.ps1 keeps its backup of the original RunAsPPL values
  ; until -Restore has put them back. If the backup is still there, LSA
  ; protection is most likely still off: keep a copy of the script next to the
  ; backup and tell the administrator how to restore it.
  ; The copy is written only when C:\ProgramData\OpenAccessEID and everything
  ; in it (LsaProtectionBackup included) is owned by SYSTEM/Administrators,
  ; holds no junction or symbolic link and cannot be changed by other users
  ; (Test-EIDDirectoryTree.ps1). Otherwise a planted LsaProtectionBackup - a
  ; junction, say - would have this elevated uninstaller write a script
  ; wherever it points. Once that check has passed, nobody but an
  ; administrator can change the folder, so writing to it by path is safe.
  ${If} ${FileExists} "C:\ProgramData\OpenAccessEID\LsaProtectionBackup\RunAsPPL.backup.txt"
    File "/oname=$PLUGINSDIR\Test-EIDDirectoryTree.ps1" "scripts\Test-EIDDirectoryTree.ps1"
    Push "$PLUGINSDIR\Test-EIDDirectoryTree.ps1"
    System::Call 'kernel32::SetEnvironmentVariable(t "OAEID_SCRIPT", t s)'
    Push "C:\ProgramData\OpenAccessEID"
    System::Call 'kernel32::SetEnvironmentVariable(t "OAEID_PATH", t s)'
    ${DisableX64FSRedirection}
    nsExec::ExecToLog /TIMEOUT=120000 `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create([IO.File]::ReadAllText($$env:OAEID_SCRIPT))) -Path $$env:OAEID_PATH; exit $$LASTEXITCODE"`
    Pop $0
    ${EnableX64FSRedirection}
    ClearErrors
    ${If} $0 == 10
      CopyFiles /SILENT "$INSTDIR\tools\Disable-LsaProtection.ps1" "C:\ProgramData\OpenAccessEID\LsaProtectionBackup\Disable-LsaProtection.ps1"
    ${Else}
      DetailPrint "C:\ProgramData\OpenAccessEID is a junction, holds one, or holds something not owned by SYSTEM/Administrators or that other users can change, or it could not be checked (result $0); not writing into it."
      SetErrors
    ${EndIf}
    ${If} ${Errors}
      DetailPrint "WARNING: LSA protection (RunAsPPL) was turned off with Disable-LsaProtection.ps1 and not restored, and the script could not be kept. Restore the values recorded in C:\ProgramData\OpenAccessEID\LsaProtectionBackup\RunAsPPL.backup.txt by hand, then reboot."
      MessageBox MB_OK|MB_ICONEXCLAMATION "LSA protection (RunAsPPL) was turned off with Disable-LsaProtection.ps1 and has not been restored.$\n$\nRestore the values recorded in$\nC:\ProgramData\OpenAccessEID\LsaProtectionBackup\RunAsPPL.backup.txt$\nunder HKLM\SYSTEM\CurrentControlSet\Control\Lsa, then reboot." /SD IDOK
    ${Else}
      DetailPrint "WARNING: LSA protection (RunAsPPL) was turned off with Disable-LsaProtection.ps1 and not restored. The script was kept at C:\ProgramData\OpenAccessEID\LsaProtectionBackup\Disable-LsaProtection.ps1; run it with -Restore as administrator, then reboot."
      MessageBox MB_OK|MB_ICONEXCLAMATION "LSA protection (RunAsPPL) was turned off with Disable-LsaProtection.ps1 and has not been restored. It stays off after this uninstall.$\n$\nThe script has been kept. To turn LSA protection back on, run as administrator:$\n$\npowershell -NoProfile -ExecutionPolicy Bypass -File $\"C:\ProgramData\OpenAccessEID\LsaProtectionBackup\Disable-LsaProtection.ps1$\" -Restore$\n$\nthen reboot." /SD IDOK
    ${EndIf}
  ${EndIf}

  ; Delete administrator tools
  Delete "$INSTDIR\tools\Disable-LsaProtection.ps1"
  RMDir "$INSTDIR\tools"

  ; Delete uninstaller
  Delete "$INSTDIR\EIDUninstall.exe"

  ; Remove installation directory. If something above could only be queued
  ; for deletion at the reboot, remove the folder at the reboot as well (after
  ; those files, which were queued first). Not recursive: anything else in it
  ; is not ours, and is left alone along with the folder.
  ClearErrors
  RMDir "$INSTDIR"
  ${If} ${Errors}
  ${AndIf} ${FileExists} "$INSTDIR\*.*"
    RMDir /REBOOTOK "$INSTDIR"
  ${EndIf}

  ; Remove registry keys
  SetRegView 64

  ; Remove installation path registry
  DeleteRegKey HKLM "Software\OpenAccessEID"

  ; Remove Credential Provider registry keys
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{B4866A0A-DB08-4835-A26F-414B46F3244C}"
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{B4866A0A-DB08-4835-A26F-414B46F3244C}"
  DeleteRegKey HKCR "CLSID\{B4866A0A-DB08-4835-A26F-414B46F3244C}"

  ; Remove Configuration Wizard registry keys
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{F5D846B4-14B0-11DE-B23C-27A355D89593}"
  DeleteRegKey HKCR "CLSID\{F5D846B4-14B0-11DE-B23C-27A355D89593}"

  ; Remove WMI Autologger for EIDCredentialProvider
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Control\WMI\Autologger\EIDCredentialProvider"

  ; Remove crash dump configuration for lsass.exe
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\lsass.exe"

  ; Remove GPO policy values set by the Configuration Wizard
  DeleteRegKey HKLM "SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider"
  DeleteRegValue HKLM "Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "scremoveoption"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Policies\System" "scforceoption"

  ; Reset ScPolicySvc service to demand-start (installer may have set it to auto-start)
  DetailPrint "Resetting Smart Card Removal Policy service..."
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config ScPolicySvc start= demand'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop ScPolicySvc'

  ; Restore Smart Card services to their Windows default (demand / trigger
  ; start). The installer forced these to auto-start; leave them stopped
  ; and revert to demand so Windows' trigger-start behaviour takes over.
  DetailPrint "Restoring Smart Card services to default startup..."
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config SCardSvr start= demand'
  nsExec::ExecToLog '"$SYSDIR\sc.exe" config ScDeviceEnum start= demand'

  ; Remove uninstall information
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID"

  SetPluginUnload manual
  SetRebootFlag true

  MessageBox MB_OK "OpenAccess EID has been uninstalled. Please reboot your computer to complete the removal."

SectionEnd

;--------------------------------
;Helper function to calculate file size and add to total

Function AddFileSize
  ; This function receives a file path on the stack
  ; Adds the file size to the $InstallSize variable

  Pop $0  ; File path

  ; Get file size by opening and seeking to end
  FileOpen $1 $0 "r"

  ${If} $1 != ""
    FileSeek $1 0 END $2  ; Seek to end, get position (file size in bytes)
    FileClose $1

    ; Add file size to running total
    IntOp $InstallSize $InstallSize + $2
  ${EndIf}
FunctionEnd

;--------------------------------
;Install log

; Push <text> / Call InstallLog: DetailPrint <text> and append it to
; %TEMP%\OpenAccessEID-install.log, so an unattended (/S) install keeps a
; record of every warning it could not show. Also usable from .onInit, where
; DetailPrint has nowhere to print.
Function InstallLog
  Exch $R0
  Push $R1
  DetailPrint "$R0"
  ClearErrors
  FileOpen $R1 "$TEMP\OpenAccessEID-install.log" a
  ${IfNot} ${Errors}
    FileSeek $R1 0 END
    FileWrite $R1 "$R0$\r$\n"
    FileClose $R1
  ${EndIf}
  Pop $R1
  Pop $R0
FunctionEnd

;--------------------------------
;System32 DLL installation

; Push <file name> / Call InstallSystemDll
; Installs $INSTDIR\<file name> as $SYSDIR\<file name> (call with x64 file
; system redirection disabled) so that the new file is what is there after the
; next reboot. LSASS (and LogonUI) keep the current copy mapped, so it cannot be
; overwritten in place, and the uninstaller that ran before this install has
; usually queued "delete $SYSDIR\<file name>" for that reboot. So:
;   1. stage the new file next to it as <file name>.oaeid-new;
;   2. rename the current copy aside (Windows allows renaming a mapped DLL) and
;      queue the renamed file for deletion;
;   3. copy the staged file into place now, so this session (DllRegister, the
;      trace config) already uses the new version;
;   4. queue a reboot-time rename of the staged file over <file name>.
;      PendingFileRenameOperations is processed in the order the entries were
;      queued, so this runs after any delete of <file name> queued earlier and
;      leaves the new file in place.
; Stops the installation if the new file cannot even be staged: registering
; packages whose DLL is missing would leave LSA pointing at nothing.
Function InstallSystemDll
  Exch $R9
  Push $R8
  Push $R7
  StrCpy $R8 "$SYSDIR\$R9.oaeid-new"

  Push "$INSTDIR\$R9"
  System::Call 'kernel32::CopyFile(t s, t R8, i 0) i .R7'
  ${If} $R7 = 0
    Push "ERROR: could not write $R8. Installation stopped; nothing has been registered with LSA."
    Call InstallLog
    MessageBox MB_OK|MB_ICONSTOP "Could not write$\n$R8$\n$\nThe installation has been stopped before anything was registered with Windows. Free some disk space or check that no security product blocks writes to System32, then run the installer again." /SD IDOK
    Call UnpinInstallDir
    Abort
  ${EndIf}

  ${If} ${FileExists} "$SYSDIR\$R9"
    System::Call 'ole32::CoCreateGuid(g .s)'
    Pop $R7
    StrCpy $R7 "$SYSDIR\$R9.oaeid-old-$R7"
    ClearErrors
    Rename "$SYSDIR\$R9" "$R7"
    ${IfNot} ${Errors}
      Delete /REBOOTOK "$R7"
    ${EndIf}
  ${EndIf}

  System::Call 'kernel32::CopyFile(t R8, t "$SYSDIR\$R9", i 0) i .R7'
  ${If} $R7 = 0
    Push "WARNING: $SYSDIR\$R9 is in use and could not be replaced now; the new version takes its place at the next reboot."
    Call InstallLog
  ${EndIf}

  ; MOVEFILE_REPLACE_EXISTING (1) | MOVEFILE_DELAY_UNTIL_REBOOT (4). Queued
  ; whatever happened above, so a delete queued earlier cannot win.
  System::Call 'kernel32::MoveFileEx(t R8, t "$SYSDIR\$R9", i 5) i .R7'
  ${If} $R7 = 0
    Push "ERROR: could not schedule $R8 to replace $SYSDIR\$R9 at the next reboot. If $SYSDIR\$R9 is missing after rebooting, run this installer again before rebooting a second time."
    Call InstallLog
    MessageBox MB_OK|MB_ICONEXCLAMATION "Could not schedule the new $R9 to be put in place at the next reboot.$\n$\nAfter rebooting, check that $SYSDIR\$R9 exists. If it does not, run this installer again." /SD IDOK
  ${EndIf}
  SetRebootFlag true

  Pop $R7
  Pop $R8
  Pop $R9
FunctionEnd

;--------------------------------
;Trace consumer executable removal

; Push <path of EIDTraceConsumer.exe> / Call [un.]RemoveTraceConsumerExe
; The trace consumer service keeps its executable in use until its process has
; exited, which can be some seconds after the stop request was accepted - and
; the -stop / -uninstall of v2.1.00 and earlier did not wait for it at all. A
; single Delete made too early failed silently and left the file behind, and
; with it the installation folder (RMDir only removes an empty folder). So the
; delete is retried for up to 30 seconds. If the file is still in use after
; that, it is renamed aside (Windows allows renaming a running executable) and
; the renamed copy is deleted at the next reboot: queuing a reboot-time delete
; of the path itself would also delete the EIDTraceConsumer.exe an upgrade
; writes there before that reboot.
!macro OAEID_RemoveTraceConsumerExeFn UN
Function ${UN}RemoveTraceConsumerExe
  Exch $R9
  Push $R8
  StrCpy $R8 0
  ${DoWhile} ${FileExists} "$R9"
    Delete "$R9"
    ${IfNot} ${FileExists} "$R9"
      ${Break}
    ${EndIf}
    IntOp $R8 $R8 + 1
    ${If} $R8 >= 60
      ${Break}
    ${EndIf}
    Sleep 500
  ${Loop}

  ${If} ${FileExists} "$R9"
    System::Call 'ole32::CoCreateGuid(g .s)'
    Pop $R8
    StrCpy $R8 "$R9.oaeid-old-$R8"
    ClearErrors
    Rename "$R9" "$R8"
    ${If} ${Errors}
      !if "${UN}" == "un."
        ; A plain uninstall runs from a temporary copy and nothing is written to
        ; this path afterwards. Run in place ($EXEDIR is the installation
        ; folder), it is the installer of an upgrade that is running it, and
        ; that writes a new EIDTraceConsumer.exe here - which a reboot-time
        ; delete of the path would remove.
        ${If} $EXEDIR != $INSTDIR
          Delete /REBOOTOK "$R9"
          DetailPrint "WARNING: $R9 is still in use; it will be deleted at the next reboot."
        ${Else}
          DetailPrint "WARNING: $R9 is still in use and could not be moved aside."
        ${EndIf}
      !else
        DetailPrint "WARNING: $R9 is still in use by the previous version's trace consumer service and could not be moved aside."
      !endif
    ${Else}
      Delete /REBOOTOK "$R8"
      DetailPrint "$R9 was still in use; moved aside, to be deleted at the next reboot."
    ${EndIf}
  ${EndIf}

  Pop $R8
  Pop $R9
FunctionEnd
!macroend
!insertmacro OAEID_RemoveTraceConsumerExeFn ""
!insertmacro OAEID_RemoveTraceConsumerExeFn "un."

;--------------------------------
;Upgrade from uninstallers that delete enrolments

; Call NeutraliseOldUnregister / Pop <"1" | "0">
; Uninstallers of v2.0.00 and earlier run
;   rundll32 <System32>\<package DLL>,DllUnRegister
; and that DllUnRegister deletes every user's stored credential. This puts this
; version's package DLL - whose DllUnRegister only removes registrations - at
; that path first, so the old uninstaller runs it instead and the enrolments
; survive the upgrade. The DLL LSASS has loaded is renamed aside (Windows allows
; renaming a mapped DLL) and deleted at the next reboot; the old uninstaller then
; deletes the substitute, which nothing has mapped, at once. v1.3.00 and earlier
; use EIDAuthenticationPackage.dll; this version's DllUnRegister also removes
; registrations made under that name. Only the cleanup actions the operator
; ticks in the old uninstaller (none in a silent run) remove anything.
; "1" when the substitute is in place, "0" otherwise (the old DLL is then left
; exactly as it was).
Function NeutraliseOldUnregister
  Push $R9
  Push $R8
  Push $R7
  ${If} $MigratedFromLegacy == 1
    StrCpy $R9 "$SYSDIR\EIDAuthenticationPackage.dll"
  ${Else}
    StrCpy $R9 "$SYSDIR\OpenAccessEIDPackage.dll"
  ${EndIf}
  StrCpy $R8 0

  InitPluginsDir
  ClearErrors
  File "/oname=$PLUGINSDIR\OpenAccessEIDPackage.dll" "..\x64\Release\OpenAccessEIDPackage.dll"
  ${If} ${Errors}
    Push "Could not extract the substitute package DLL to $PLUGINSDIR."
    Call InstallLog
  ${Else}
    ${DisableX64FSRedirection}
    StrCpy $R7 ""
    ${If} ${FileExists} "$R9"
      System::Call 'ole32::CoCreateGuid(g .s)'
      Pop $R7
      StrCpy $R7 "$R9.oaeid-old-$R7"
      ClearErrors
      Rename "$R9" "$R7"
      ${If} ${Errors}
        Push "Could not rename $R9 aside."
        Call InstallLog
        StrCpy $R7 "failed"
      ${EndIf}
    ${EndIf}
    ${If} $R7 != "failed"
      ; bFailIfExists: the path has just been vacated.
      Push "$PLUGINSDIR\OpenAccessEIDPackage.dll"
      System::Call 'kernel32::CopyFile(t s, t R9, i 1) i .R8'
      ${If} $R8 = 0
        StrCpy $R8 0
        Push "Could not copy the substitute package DLL to $R9."
        Call InstallLog
        ; Put the original back so the old uninstaller still has its DLL.
        ${If} $R7 != ""
          Rename "$R7" "$R9"
        ${EndIf}
      ${Else}
        StrCpy $R8 1
        ${If} $R7 != ""
          Delete /REBOOTOK "$R7"
        ${EndIf}
        StrCpy $NeutralisedDll $R9
        StrCpy $NeutralisedAside $R7
        Push "Substituted this version's unregistration step for the old uninstaller's ($R9), so stored credentials are kept."
        Call InstallLog
      ${EndIf}
    ${EndIf}
    ${EnableX64FSRedirection}
  ${EndIf}

  StrCpy $R9 $R8
  Pop $R7
  Pop $R8
  Exch $R9
FunctionEnd

;--------------------------------
;ProgramData and installation folder hardening
;
; Any user can create a subdirectory of C:\ProgramData, so the product directory
; (or the legacy C:\ProgramData\EIDAuthentication) may already exist owned by an
; unprivileged user, be a junction, or hold a planted logging.json or junction.
; LSASS and the trace consumer write and rotate logs there as SYSTEM, and the
; trace consumer runs as SYSTEM from the installation folder. So the installer
; creates both folders with their protected DACL already in place, in the same
; call that creates them (CreateProtectedDir), and keeps an existing folder only
; when it can show that the folder is ours and that nothing in it can be changed
; by anyone but SYSTEM and Administrators. Permissions are changed natively,
; through a handle opened on the folder itself (LockEIDDirectory), never by
; path. The trust check is a PowerShell script from Installer\scripts,
; extracted to $PLUGINSDIR.

; Extracts the installer's PowerShell helper to $PLUGINSDIR.
Function ExtractEIDScripts
  InitPluginsDir
  File "/oname=$PLUGINSDIR\Test-EIDDirectoryTree.ps1" "scripts\Test-EIDDirectoryTree.ps1"
FunctionEnd

; Push <script file name> / Push <path> / Call RunEIDScript / Pop <result>
; Runs $PLUGINSDIR\<script> -Path <path> and returns its exit code, or nsExec's
; "error"/"timeout". The script is read and run as a script block, so a
; machine-wide PowerShell execution policy cannot block it, and the two strings
; travel in environment variables, so no quoting in a path can break the
; command line.
Function RunEIDScript
  Exch $R0
  Exch
  Exch $R1
  Push $R2
  Call ExtractEIDScripts
  Push "$PLUGINSDIR\$R1"
  System::Call 'kernel32::SetEnvironmentVariable(t "OAEID_SCRIPT", t s)'
  System::Call 'kernel32::SetEnvironmentVariable(t "OAEID_PATH", t R0)'
  nsExec::ExecToLog /TIMEOUT=120000 `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create([IO.File]::ReadAllText($$env:OAEID_SCRIPT))) -Path $$env:OAEID_PATH; exit $$LASTEXITCODE"`
  Pop $R2
  StrCpy $R0 $R2
  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd

; Push <path> / Call IsEIDDataTreeTrusted / Pop <result>:
;   "1" <path> and everything below it is owned by SYSTEM (S-1-5-18) or
;       Administrators (S-1-5-32-544), nothing is a reparse point, and no ACE
;       lets anyone but SYSTEM, Administrators or CREATOR OWNER write, create,
;       delete, change permissions or take ownership;
;   "0" not trusted (including an ACL that cannot be read);
;   "2" the check could not run: PowerShell missing, blocked, timed out or in
;       constrained language mode. That is neither answer: it does not show
;       that the folder can be trusted.
; The check stops at the first reparse point, so it never walks into a
; junction's target. See Installer\scripts\Test-EIDDirectoryTree.ps1.
Function IsEIDDataTreeTrusted
  Exch $R9
  Push "Test-EIDDirectoryTree.ps1"
  Push $R9
  Call RunEIDScript
  Pop $R9
  ${If} $R9 == 10
    StrCpy $R9 1
  ${ElseIf} $R9 == 11
    StrCpy $R9 0
  ${Else}
    StrCpy $R9 2
  ${EndIf}
  Exch $R9
FunctionEnd

; Push <directory> / Call CreateProtectedDir / Pop <result>
; Creates <directory> (its parent must exist) with the protected DACL
; ${OAEID_DIR_SDDL} passed to CreateDirectoryW itself, so the folder never
; exists, even for an instant, with permissions that would let a standard user
; add anything to it. Owner Administrators is asked for in the same call; a
; token that may not assign it (ERROR_INVALID_OWNER) gets the same DACL without
; it, and the caller then sets the owner with LockEIDDirectory.
;   "1"      created;
;   "exists" ERROR_ALREADY_EXISTS: something (a folder, a file or a junction)
;            already has that name - it was NOT created by this call;
;   "0"      any other failure.
Function CreateProtectedDir
  Exch $R9
  Push $R8
  Push $R7
  Push $R6
  Push $R5
  Push $R4
  StrCpy $R4 0
  ${Do}
    ${If} $R4 == 0
      Push "${OAEID_DIR_SDDL}"
    ${Else}
      Push "${OAEID_DIR_SDDL_DACL}"
    ${EndIf}
    ; SDDL_REVISION_1
    System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w s, i 1, *p .R8, p 0) i .R7'
    ${If} $R7 = 0
      StrCpy $R5 "0"
      ${ExitDo}
    ${EndIf}
    ; SECURITY_ATTRIBUTES { nLength, lpSecurityDescriptor, bInheritHandle }
    System::Call '*(&l4, p R8, i 0) p .R6'
    System::Call 'kernel32::CreateDirectoryW(w R9, p R6) i .R7 ?e'
    Pop $R5
    System::Free $R6
    System::Call 'kernel32::LocalFree(p R8)'
    ${If} $R7 <> 0
      StrCpy $R5 "1"
      ${ExitDo}
    ${ElseIf} $R5 = 183
      StrCpy $R5 "exists"
      ${ExitDo}
    ${ElseIf} $R5 = 1307
    ${AndIf} $R4 == 0
      StrCpy $R4 1
    ${Else}
      StrCpy $R5 "0"
      ${ExitDo}
    ${EndIf}
  ${Loop}
  StrCpy $R9 $R5
  Pop $R4
  Pop $R5
  Pop $R6
  Pop $R7
  Pop $R8
  Exch $R9
FunctionEnd

; Push <directory> / Call LockEIDDirectory / Pop <"1" | "0">
; Owner Administrators and a protected DACL that replaces every other ACE: Full
; control for SYSTEM and Administrators, read/execute for Users, inherited by
; everything below (${OAEID_DIR_SDDL}, the runtime's EID_LOG_DIR_SDDL).
; The folder is opened once with FILE_FLAG_OPEN_REPARSE_POINT, checked through
; that handle to be a directory and not a junction, symbolic link or other
; reparse point, and owner and DACL are written in one call through the same
; handle. So the folder that is checked is the folder that is changed: swapping
; it for a junction after the check changes nothing.
Function LockEIDDirectory
  Exch $R9
  Push $R8
  Push $R7
  Push $R6
  Push $R5
  Push $R4
  Push $R3
  Push $R2
  Push $R1
  Push $R0
  StrCpy $R4 0
  ; FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER; share
  ; read/write/delete; OPEN_EXISTING; FILE_FLAG_BACKUP_SEMANTICS (needed to
  ; open a directory) | FILE_FLAG_OPEN_REPARSE_POINT.
  System::Call 'kernel32::CreateFileW(w R9, i 0xE0080, i 7, p 0, i 3, i 0x02200000, p 0) p .R8 ?e'
  Pop $R7
  ${If} $R8 = -1
  ${OrIf} $R8 == 4294967295
  ${OrIf} $R8 = 0
    Push "WARNING: could not open $R9 to change its permissions (error $R7)."
    Call InstallLog
  ${Else}
    ; BY_HANDLE_FILE_INFORMATION is 52 bytes; dwFileAttributes comes first.
    System::Call '*(&i52) p .R6'
    System::Call 'kernel32::GetFileInformationByHandle(p R8, p R6) i .R7'
    StrCpy $R5 0
    ${If} $R7 <> 0
      System::Call '*$R6(i .R5)'
    ${EndIf}
    System::Free $R6
    IntOp $R7 $R5 & 0x410
    ${If} $R7 <> 0x10
      Push "WARNING: not changing the permissions of $R9: it is not a directory, or it is a junction, symbolic link or other reparse point."
      Call InstallLog
    ${Else}
      Push "${OAEID_DIR_SDDL}"
      System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w s, i 1, *p .R3, p 0) i .R7'
      ${If} $R7 <> 0
        System::Call 'advapi32::GetSecurityDescriptorOwner(p R3, *p .R2, *i .R1) i .R7'
        System::Call 'advapi32::GetSecurityDescriptorDacl(p R3, *i .R1, *p .R0, *i .R1) i .R6'
        ${If} $R7 <> 0
        ${AndIf} $R6 <> 0
          ; SE_FILE_OBJECT; OWNER_ | DACL_ | PROTECTED_DACL_SECURITY_INFORMATION
          System::Call 'advapi32::SetSecurityInfo(p R8, i 1, i 0x80000005, p R2, p 0, p R0, p 0) i .R7'
          ${If} $R7 = 0
            StrCpy $R4 1
          ${Else}
            Push "WARNING: could not set the owner and permissions of $R9 (error $R7)."
            Call InstallLog
          ${EndIf}
        ${EndIf}
        System::Call 'kernel32::LocalFree(p R3)'
      ${EndIf}
    ${EndIf}
    System::Call 'kernel32::CloseHandle(p R8)'
  ${EndIf}
  StrCpy $R9 $R4
  Pop $R0
  Pop $R1
  Pop $R2
  Pop $R3
  Pop $R4
  Pop $R5
  Pop $R6
  Pop $R7
  Pop $R8
  Exch $R9
FunctionEnd

; Push <path> / Push <destination prefix> / Call MoveAside / Pop <new path, or "">
; Renames <path> to <destination prefix>.untrusted-<random GUID>. The suffix is
; random, so a standard user cannot pre-create the destination to block the
; move; a failed rename (typically a handle held open) is retried for about ten
; seconds. "" when it never succeeded.
Function MoveAside
  Exch $R8
  Exch
  Exch $R9
  Push $R7
  Push $R6
  StrCpy $R6 0
  ${Do}
    IntOp $R6 $R6 + 1
    System::Call 'ole32::CoCreateGuid(g .s)'
    Pop $R7
    StrCpy $R7 "$R8.untrusted-$R7"
    ClearErrors
    Rename "$R9" "$R7"
    ${IfNot} ${Errors}
      ${ExitDo}
    ${EndIf}
    StrCpy $R7 ""
    ${If} $R6 >= 5
      ${ExitDo}
    ${EndIf}
    Sleep 2000
  ${Loop}
  StrCpy $R9 $R7
  Pop $R6
  Pop $R7
  Exch
  Pop $R8
  Exch $R9
FunctionEnd

; Shown and recorded when an untrusted folder cannot be moved out of the way:
; until an administrator deals with it, OpenAccess EID writes no log files.
; Push <path> / Call WarnNotMovedAside
Function WarnNotMovedAside
  Exch $R9
  Push "WARNING: $R9 is a junction, is not owned by SYSTEM/Administrators, can be modified by other users or could not be checked, and could not be moved aside. OpenAccess EID will NOT write log files until an administrator deletes or renames it and runs this installer again."
  Call InstallLog
  MessageBox MB_OK|MB_ICONEXCLAMATION "$R9$\n$\nis a junction, is not owned by SYSTEM/Administrators, can be modified by other users or could not be checked, and could not be moved aside (something may be holding it open).$\n$\nOpenAccess EID will NOT write log files until an administrator deletes or renames it and runs this installer again. Smart-card logon is not affected." /SD IDOK
  Pop $R9
FunctionEnd

; Create C:\ProgramData\OpenAccessEID and its logs directory, owned by
; Administrators, with inheritance from ProgramData removed: Full control to
; SYSTEM and Administrators, read-only to Users (the same DACL the runtime
; applies, EID_LOG_DIR_SDDL).
;   - The folder is created by CreateProtectedDir, with that DACL from the
;     first instant: no standard user can ever add anything to it, so there is
;     nothing to check or move out of it afterwards.
;   - If the name is already taken, the existing folder is kept only when it
;     is a real directory and IsEIDDataTreeTrusted shows that it and
;     everything in it is owned by SYSTEM/Administrators, holds no junction
;     and cannot be changed by anyone else. Nobody else can then change it, so
;     its permissions are reset (LockEIDDirectory) and it is used.
;   - Anything else that holds the name - a folder that fails the check, one
;     that could not be checked (PowerShell blocked or in constrained language
;     mode), a junction, a file - is moved aside to
;     OpenAccessEID.untrusted-<GUID>, never adopted, and a new folder is
;     created in its place. Taking ownership of it would launder whatever was
;     planted inside.
; logs is created last, inside the locked folder, so it inherits the protected
; DACL and is owned by whoever runs the installer (Administrators or SYSTEM).
Function SecureEIDDataDir
  StrCpy $R9 "C:\ProgramData\OpenAccessEID"
  StrCpy $R6 0

  ${Do}
    IntOp $R6 $R6 + 1
    Push $R9
    Call CreateProtectedDir
    Pop $R0
    ${If} $R0 == 1
      ; CreateProtectedDir could only ask for owner Administrators when the
      ; token allowed it (otherwise the owner is the installing account), so
      ; set the owner here, as PrepareInstallDir does. Nobody but SYSTEM and
      ; Administrators can change the new folder, so this is safe by path.
      Push $R9
      Call LockEIDDirectory
      Pop $R0
      ${If} $R0 != 1
        Push "WARNING: created $R9 (SYSTEM and Administrators Full, Users read) but could not make Administrators its owner; OpenAccess EID may refuse to write logs there. Run this installer again."
        Call InstallLog
        Return
      ${EndIf}
      Push "Created $R9 (owner Administrators; SYSTEM and Administrators Full, Users read)."
      Call InstallLog
      ${ExitDo}
    ${ElseIf} $R0 != "exists"
      Push "WARNING: could not create $R9; OpenAccess EID will not write log files until it exists with permissions restricted to SYSTEM and Administrators. Run this installer again."
      Call InstallLog
      Return
    ${EndIf}

    ; The name was already taken before this call.
    StrCpy $R0 0
    System::Call 'kernel32::GetFileAttributesW(w R9) i .R1'
    ${If} $R1 <> -1
      IntOp $R1 $R1 & 0x410
      ${If} $R1 = 0x10
        Push $R9
        Call IsEIDDataTreeTrusted
        Pop $R0
      ${EndIf}
    ${EndIf}
    ${If} $R0 == 1
      Push $R9
      Call LockEIDDirectory
      Pop $R0
      ${If} $R0 != 1
        Push "WARNING: could not secure $R9; OpenAccess EID will refuse to write logs there."
        Call InstallLog
        Return
      ${EndIf}
      Push "Kept the existing $R9: it and everything in it is owned by SYSTEM/Administrators and cannot be changed by other users."
      Call InstallLog
      ${ExitDo}
    ${EndIf}

    ; Not shown to be trusted: move it aside, then create a new one. A
    ; standard user who keeps re-creating the name is given up on after three
    ; rounds.
    ${If} $R6 > 3
      Push $R9
      Call WarnNotMovedAside
      Return
    ${EndIf}
    Push $R9
    Push $R9
    Call MoveAside
    Pop $R8
    ${If} $R8 == ""
      Push $R9
      Call WarnNotMovedAside
      Return
    ${EndIf}
    ${If} $R0 == 2
      Push "WARNING: $R9 already existed and could not be checked (PowerShell did not run, or runs in constrained language mode); moved aside to $R8 rather than adopted. Copy logging.json back from there after checking it, if it is yours."
    ${Else}
      Push "WARNING: $R9 was a junction or file, not owned by SYSTEM/Administrators, or modifiable by other users; moved aside to $R8 for review."
    ${EndIf}
    Call InstallLog
  ${Loop}

  CreateDirectory "$R9\logs"
FunctionEnd

;--------------------------------
;Installation folder checks

; Push <path> / Call CanonicalisePath / Pop <full, long path without a
; trailing backslash, or "" when it cannot be resolved>
; ".", ".." and short (8.3) names are resolved, so "C:\PROGRA~1\.\" and
; "C:\Program Files" compare equal (case-insensitively, as StrCmp does).
Function CanonicalisePath
  Exch $R9
  Push $R8
  Push $R7
  System::Call 'kernel32::GetFullPathNameW(w R9, i ${NSIS_MAX_STRLEN}, w .R8, p 0) i .R7'
  ${If} $R7 = 0
  ${OrIf} $R7 >= ${NSIS_MAX_STRLEN}
    StrCpy $R9 ""
  ${Else}
    StrCpy $R9 $R8
    ; Only resolves short names for a path that exists; otherwise keep it.
    System::Call 'kernel32::GetLongPathNameW(w R9, w .R8, i ${NSIS_MAX_STRLEN}) i .R7'
    ${If} $R7 > 0
    ${AndIf} $R7 < ${NSIS_MAX_STRLEN}
      StrCpy $R9 $R8
    ${EndIf}
    StrLen $R7 $R9
    ${If} $R7 > 3
      StrCpy $R8 $R9 1 -1
      ${If} $R8 == "\"
        StrCpy $R9 $R9 -1
      ${EndIf}
    ${EndIf}
  ${EndIf}
  Pop $R7
  Pop $R8
  Exch $R9
FunctionEnd

; Used by IsForbiddenInstallDir: $R8 = 1 when <path> resolves to $R9.
!macro OAEID_ForbidSame PATH
  StrCpy $R6 "${PATH}"
  ${If} $R6 != ""
    Push $R6
    Call CanonicalisePath
    Pop $R6
    ${If} $R6 != ""
    ${AndIf} $R6 == $R9
      StrCpy $R8 1
    ${EndIf}
  ${EndIf}
!macroend

; Push <canonical path> / Call IsForbiddenInstallDir / Pop <"1" | "0">
; "1" for a folder OpenAccess EID must never take over (LockEIDDirectory would
; replace its DACL, and the DACL of everything below it): a drive root, a
; network or device path (\\server\share, \\?\...), the Windows folder or
; anything inside it, Program Files, Program Files (x86), their Common Files,
; the ProgramData root and the Users folder (and Users\Public).
Function IsForbiddenInstallDir
  Exch $R9
  Push $R8
  Push $R7
  Push $R6
  StrCpy $R8 0
  StrLen $R7 $R9
  ${If} $R7 <= 3
    StrCpy $R8 1
  ${EndIf}
  ; Anything but "X:\..." - UNC, device and relative paths.
  StrCpy $R7 $R9 1 1
  ${If} $R7 != ":"
    StrCpy $R8 1
  ${EndIf}
  StrCpy $R7 $R9 2
  ${If} $R7 == "\\"
    StrCpy $R8 1
  ${EndIf}
  ${If} $R8 == 0
    !insertmacro OAEID_ForbidSame "$WINDIR"
    !insertmacro OAEID_ForbidSame "$PROGRAMFILES64"
    !insertmacro OAEID_ForbidSame "$PROGRAMFILES32"
    !insertmacro OAEID_ForbidSame "$COMMONFILES64"
    !insertmacro OAEID_ForbidSame "$COMMONFILES32"
    ReadEnvStr $R7 "ProgramData"
    !insertmacro OAEID_ForbidSame "$R7"
    ReadEnvStr $R7 "ALLUSERSPROFILE"
    !insertmacro OAEID_ForbidSame "$R7"
    ReadEnvStr $R7 "PUBLIC"
    !insertmacro OAEID_ForbidSame "$R7"
    ReadRegStr $R7 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" "ProfilesDirectory"
    ExpandEnvStrings $R7 $R7
    !insertmacro OAEID_ForbidSame "$R7"
    ReadEnvStr $R7 "SystemDrive"
    !insertmacro OAEID_ForbidSame "$R7\Users"
    ; Anything inside the Windows folder.
    Push $WINDIR
    Call CanonicalisePath
    Pop $R6
    ${If} $R6 != ""
      StrLen $R7 "$R6\"
      StrCpy $R7 $R9 $R7
      ${If} $R7 == "$R6\"
        StrCpy $R8 1
      ${EndIf}
    ${EndIf}
  ${EndIf}
  StrCpy $R9 $R8
  Pop $R6
  Pop $R7
  Pop $R8
  Exch $R9
FunctionEnd

; Push <directory> / Call IsDirEmpty / Pop <"1" | "0">
; "1" when <directory> can be listed and holds nothing (hidden and system
; entries included). "0" when it holds anything or cannot be listed.
Function IsDirEmpty
  Exch $R9
  Push $R8
  Push $R7
  Push $R6
  StrCpy $R7 1
  ClearErrors
  FindFirst $R8 $R6 "$R9\*"
  ${If} ${Errors}
    StrCpy $R7 0
  ${Else}
    ${Do}
      ${If} $R6 != "."
      ${AndIf} $R6 != ".."
      ${AndIf} $R6 != ""
        StrCpy $R7 0
        ${ExitDo}
      ${EndIf}
      ClearErrors
      FindNext $R8 $R6
      ${If} ${Errors}
        ${ExitDo}
      ${EndIf}
    ${Loop}
    FindClose $R8
  ${EndIf}
  StrCpy $R9 $R7
  Pop $R6
  Pop $R7
  Pop $R8
  Exch $R9
FunctionEnd

; Push <reason> / Call RefuseInstallDir: records and shows why $INSTDIR is not
; used, then stops the installation (closing the handle PinInstallDir keeps
; on it, if any).
Function RefuseInstallDir
  Exch $R9
  Call UnpinInstallDir
  Push "ERROR: installation folder $INSTDIR: $R9 Installation stopped."
  Call InstallLog
  MessageBox MB_OK|MB_ICONSTOP "The installation folder$\n$INSTDIR$\n$R9$\n$\nOpenAccess EID runs a SYSTEM service from this folder, so it will not install there. Choose another folder." /SD IDOK
  Abort
FunctionEnd

; Call UnpinInstallDir
; Closes the handle PinInstallDir opened on $INSTDIR, if it is open. Safe to
; call at any time, including from .onInit and .onInstFailed.
Function UnpinInstallDir
  ${If} $InstallDirHandle != ""
  ${AndIf} $InstallDirHandle != 0
    System::Call 'kernel32::CloseHandle(p $InstallDirHandle)'
  ${EndIf}
  StrCpy $InstallDirHandle 0
FunctionEnd

; Call PinInstallDir
; Opens $INSTDIR (the canonical path PrepareInstallDir checked) and keeps the
; handle in $InstallDirHandle until UnpinInstallDir. The handle does not share
; delete access, so while it is open Windows refuses to rename or delete the
; folder or any folder above it: a custom /D= folder under a parent that a
; standard user controls cannot be swapped for another folder while the
; installer works in it. Through the handle (opened with
; FILE_FLAG_OPEN_REPARSE_POINT) the folder must be a directory and not a
; reparse point, and its final path must be $INSTDIR itself - not reached
; through a junction, symbolic link or mapped drive somewhere above it.
; Stops the installation otherwise.
Function PinInstallDir
  Push $R9
  Push $R8
  Push $R7
  Call UnpinInstallDir
  ; FILE_READ_ATTRIBUTES; FILE_SHARE_READ | FILE_SHARE_WRITE (no
  ; FILE_SHARE_DELETE); OPEN_EXISTING; FILE_FLAG_BACKUP_SEMANTICS (needed to
  ; open a directory) | FILE_FLAG_OPEN_REPARSE_POINT.
  System::Call 'kernel32::CreateFileW(w "$INSTDIR", i 0x80, i 3, p 0, i 3, i 0x02200000, p 0) p .R9 ?e'
  Pop $R8
  ${If} $R9 = -1
  ${OrIf} $R9 == 4294967295
  ${OrIf} $R9 = 0
    Push "could not be opened to hold it in place during the installation (error $R8)."
    Call RefuseInstallDir
  ${EndIf}
  StrCpy $InstallDirHandle $R9

  ; BY_HANDLE_FILE_INFORMATION is 52 bytes; dwFileAttributes comes first.
  StrCpy $R7 0
  System::Call '*(&i52) p .R8'
  System::Call 'kernel32::GetFileInformationByHandle(p R9, p R8) i .R7'
  ${If} $R7 <> 0
    System::Call '*$R8(i .R7)'
  ${EndIf}
  System::Free $R8
  IntOp $R7 $R7 & 0x410
  ${If} $R7 <> 0x10
    Push "is not a folder, or is a junction, symbolic link or other reparse point."
    Call RefuseInstallDir
  ${EndIf}

  ; FILE_NAME_NORMALIZED | VOLUME_NAME_DOS: "\\?\C:\...".
  System::Call 'kernel32::GetFinalPathNameByHandleW(p R9, w .R8, i ${NSIS_MAX_STRLEN}, i 0) i .R7'
  ${If} $R7 = 0
  ${OrIf} $R7 >= ${NSIS_MAX_STRLEN}
    Push "could not be checked (its final path could not be read)."
    Call RefuseInstallDir
  ${EndIf}
  StrCpy $R7 $R8 4
  ${If} $R7 == "\\?\"
    StrCpy $R8 $R8 "" 4
  ${EndIf}
  ${If} $R8 != $INSTDIR
    ; A folder created just now may have been named with a short (8.3)
    ; name, which CanonicalisePath can only resolve once it exists.
    Push $INSTDIR
    Call CanonicalisePath
    Pop $R7
    ${If} $R7 != $R8
      Push "is really $R8: a folder above it is a junction, symbolic link or mapped drive, or the folder was replaced while the installer was using it. Use the real path of a new or empty folder."
      Call RefuseInstallDir
    ${EndIf}
    StrCpy $INSTDIR $R8
    Push $R8
    Call IsForbiddenInstallDir
    Pop $R7
    ${If} $R7 == 1
      Push "is a drive root, a network path, or a Windows system folder (Windows, Program Files, Common Files, ProgramData, Users)."
      Call RefuseInstallDir
    ${EndIf}
  ${EndIf}
  Pop $R7
  Pop $R8
  Pop $R9
FunctionEnd

; Push <canonical folder> / Call CreateInstallParents / Pop <"1" | "0">
; Creates every folder above <folder> that does not exist yet, top down, with
; CreateProtectedDir (then owner Administrators, LockEIDDirectory), rather than
; letting them inherit the drive root's permissions - which on the system
; drive let any authenticated user add, rename and delete in a new folder.
; "0" when one of them could not be created that way (or was created by
; something else in the meantime).
Function CreateInstallParents
  Exch $R9
  Push $R8
  Push $R7
  Push $R6
  StrCpy $R7 0
  ${GetParent} $R9 $R8
  ${DoWhile} $R8 != ""
    ${If} ${FileExists} "$R8\*.*"
      ${ExitDo}
    ${EndIf}
    Push $R8
    IntOp $R7 $R7 + 1
    ${GetParent} $R8 $R8
  ${Loop}
  ; The missing folders are on the stack, the top-most one pushed last.
  StrCpy $R9 1
  ${DoWhile} $R7 > 0
    Pop $R8
    IntOp $R7 $R7 - 1
    ${If} $R9 == 1
      Push $R8
      Call CreateProtectedDir
      Pop $R6
      ${If} $R6 == 1
        Push $R8
        Call LockEIDDirectory
        Pop $R6
      ${EndIf}
      ${If} $R6 != 1
        Push "ERROR: could not create $R8 with permissions restricted to SYSTEM and Administrators (result $R6)."
        Call InstallLog
        StrCpy $R9 0
      ${Else}
        Push "Created $R8 (owner Administrators; SYSTEM and Administrators Full, Users read)."
        Call InstallLog
      ${EndIf}
    ${EndIf}
  ${Loop}
  Pop $R6
  Pop $R7
  Pop $R8
  Exch $R9
FunctionEnd

; Call PrepareInstallDir
; Makes $INSTDIR a folder that only SYSTEM and Administrators can change, or
; stops the installation. Everything is decided BEFORE any permission is
; changed, so a wrong /D= or InstallPath value cannot strip the ACL (and
; TrustedInstaller's or ALL APPLICATION PACKAGES' access) from a folder that is
; not ours:
;   - a drive root, a network or device path, the Windows folder or anything
;     in it, Program Files, Program Files (x86), their Common Files, the
;     ProgramData root and the Users folder are refused (IsForbiddenInstallDir);
;   - a junction, symbolic link or other reparse point, or a file, is refused,
;     and so is a folder reached through one (PinInstallDir);
;   - a folder that does not exist is created by CreateProtectedDir, with the
;     protected DACL from the first instant, and so is any missing folder
;     above it (CreateInstallParents);
;   - an existing EMPTY folder is removed and created again the same way, so
;     its old owner and permissions are never adopted;
;   - an existing non-empty folder is accepted only when it is a previous
;     OpenAccess EID installation:
;       - the folder the old uninstaller has just run over (.onInit): its
;         permissions are reset (LockEIDDirectory), after which everything in
;         it must pass IsEIDDataTreeTrusted;
;       - a folder holding EIDUninstall.exe: anyone could have put that file
;         there, so everything in it must pass IsEIDDataTreeTrusted FIRST, and
;         only then are its permissions reset.
;     Any other non-empty folder is refused, and nothing in it is changed.
; $INSTDIR is replaced by the canonical path that was checked, and is held
; open (PinInstallDir) so that it cannot be moved or replaced until the Core
; section closes it (UnpinInstallDir).
Function PrepareInstallDir
  Push $INSTDIR
  Call CanonicalisePath
  Pop $R9
  Push $R9
  Call IsForbiddenInstallDir
  Pop $R0
  ${If} $R0 == 1
    Push "is a drive root, a network path, or a Windows system folder (Windows, Program Files, Common Files, ProgramData, Users). Nothing in it was changed."
    Call RefuseInstallDir
  ${EndIf}
  StrCpy $INSTDIR $R9

  System::Call 'kernel32::GetFileAttributesW(w R9) i .R0'
  ${If} $R0 <> -1
    IntOp $R1 $R0 & 0x400
    ${If} $R1 <> 0
      Push "is a junction, symbolic link or other reparse point."
      Call RefuseInstallDir
    ${EndIf}
    IntOp $R1 $R0 & 0x10
    ${If} $R1 = 0
      Push "is a file, not a folder."
      Call RefuseInstallDir
    ${EndIf}

    ; Hold it in place before anything is decided about it.
    Call PinInstallDir
    StrCpy $R9 $INSTDIR

    ; 1 = the folder the previous version's uninstaller ran over; 2 = holds
    ; this product's uninstaller; 0 = neither.
    StrCpy $R2 0
    ${If} $PrevInstallDir != ""
      Push $PrevInstallDir
      Call CanonicalisePath
      Pop $R1
      ${If} $R1 == $R9
        StrCpy $R2 1
      ${EndIf}
    ${EndIf}
    ${If} $R2 == 0
    ${AndIf} ${FileExists} "$R9\EIDUninstall.exe"
      StrCpy $R2 2
    ${EndIf}

    ${If} $R2 == 0
      Push $R9
      Call IsDirEmpty
      Pop $R1
      ${If} $R1 != 1
        Push "already exists, is not empty and is not an OpenAccess EID installation. Nothing in it was changed. Choose a new or empty folder."
        Call RefuseInstallDir
      ${EndIf}
      ; Empty: remove it and create it again below, rather than adopt it. The
      ; handle would stop the removal.
      Call UnpinInstallDir
      ClearErrors
      RMDir $R9
      ${If} ${Errors}
        Push "is an existing empty folder that could not be replaced (it may be open in another program). Nothing in it was changed."
        Call RefuseInstallDir
      ${EndIf}
    ${Else}
      ; Only holds EIDUninstall.exe: check it before changing anything.
      ${If} $R2 == 2
        Push $R9
        Call IsEIDDataTreeTrusted
        Pop $R1
        ${If} $R1 == 0
          Push "holds EIDUninstall.exe, but it or something in it is not owned by SYSTEM/Administrators, can be modified by other users, or is a junction. Nothing in it was changed. Uninstall that copy, or choose a new or empty folder."
          Call RefuseInstallDir
        ${ElseIf} $R1 != 1
          Push "holds EIDUninstall.exe, but its contents could not be checked (PowerShell did not run, or runs in constrained language mode). Nothing in it was changed. Uninstall that copy first, or choose a new or empty folder."
          Call RefuseInstallDir
        ${EndIf}
      ${EndIf}
      Push "$R9 is a previous OpenAccess EID installation folder; resetting its permissions."
      Call InstallLog
      Push $R9
      Call LockEIDDirectory
      Pop $R1
      ${If} $R1 != 1
        Push "could not have its permissions restricted to SYSTEM and Administrators."
        Call RefuseInstallDir
      ${EndIf}
      ; The folder the old uninstaller ran over: check what it left behind.
      ${If} $R2 == 1
        Push $R9
        Call IsEIDDataTreeTrusted
        Pop $R1
        ${If} $R1 == 0
          Push "contains files or folders that are not owned by SYSTEM/Administrators, that other users can modify, or a junction. Remove them, or choose another folder."
          Call RefuseInstallDir
        ${ElseIf} $R1 == 2
          Push "WARNING: could not check the contents of $INSTDIR (PowerShell did not run, or runs in constrained language mode); its permissions have been restricted."
          Call InstallLog
        ${EndIf}
      ${EndIf}
      Return
    ${EndIf}
  ${EndIf}

  ; A new folder (or an empty one just removed).
  Push $R9
  Call CreateInstallParents
  Pop $R1
  ${If} $R1 != 1
    Push "could not be created: a folder above it could not be created with permissions restricted to SYSTEM and Administrators."
    Call RefuseInstallDir
  ${EndIf}
  Push $R9
  Call CreateProtectedDir
  Pop $R1
  ${If} $R1 == "exists"
    Push "was created by something else while the installer was creating it. Nothing in it was changed."
    Call RefuseInstallDir
  ${ElseIf} $R1 != 1
    Push "could not be created with permissions restricted to SYSTEM and Administrators."
    Call RefuseInstallDir
  ${EndIf}
  Call PinInstallDir
  StrCpy $R9 $INSTDIR
  ; Owner Administrators, also where CreateProtectedDir could not ask for it.
  Push $R9
  Call LockEIDDirectory
  Pop $R1
  ${If} $R1 != 1
    Push "could not have its permissions restricted to SYSTEM and Administrators."
    Call RefuseInstallDir
  ${EndIf}
  ; The handle now holds the folder in place, and only SYSTEM and
  ; Administrators can change it. It must be the empty folder just created: a
  ; folder swapped in between its creation and PinInstallDir (by renaming a
  ; parent a standard user controls) could hold anything.
  Push $R9
  Call IsDirEmpty
  Pop $R1
  ${If} $R1 != 1
    Push "was replaced by another folder while the installer was creating it."
    Call RefuseInstallDir
  ${EndIf}
FunctionEnd

; Call UndoNeutraliseOldUnregister
; Reverses NeutraliseOldUnregister when the old uninstaller was cancelled or
; failed, so the installed version is left as it was: the original package DLL
; is renamed back over the substitute in one step (MOVEFILE_REPLACE_EXISTING).
; NeutraliseOldUnregister queued the original's GUID-suffixed name for deletion
; at the next reboot; once it has its own name again, that queued delete finds
; nothing to delete. With no original, the substitute is simply deleted.
Function UndoNeutraliseOldUnregister
  ${If} $NeutralisedDll == ""
    Return
  ${EndIf}
  Push $R9
  ${DisableX64FSRedirection}
  ${If} $NeutralisedAside != ""
    System::Call 'kernel32::MoveFileExW(w "$NeutralisedAside", w "$NeutralisedDll", i 1) i .R9'
    ${If} $R9 = 0
      Push "ERROR: could not put the original $NeutralisedDll back. It is at $NeutralisedAside, which is deleted at the next reboot: rename it back to $NeutralisedDll before rebooting."
      Call InstallLog
      MessageBox MB_OK|MB_ICONSTOP "Could not put the installed version's package DLL back.$\n$\nBefore rebooting, rename$\n$NeutralisedAside$\nback to$\n$NeutralisedDll$\n(it is otherwise deleted at the next reboot)." /SD IDOK
    ${Else}
      Push "Put the original $NeutralisedDll back in place."
      Call InstallLog
    ${EndIf}
  ${Else}
    Delete "$NeutralisedDll"
  ${EndIf}
  ${EnableX64FSRedirection}
  StrCpy $NeutralisedDll ""
  StrCpy $NeutralisedAside ""
  Pop $R9
FunctionEnd

;--------------------------------
;Local smart-card security policy across the old uninstaller

; Push <key under HKLM> / Push <value name> / Call GetHKLM64ValueType /
; Pop <REG_* type number, or "" when the value (or key) is absent>
; Reads the 64-bit registry view whatever SetRegView says.
Function GetHKLM64ValueType
  Exch $R9
  Exch
  Exch $R8
  Push $R7
  Push $R6
  Push $R5
  StrCpy $R5 ""
  ; HKEY_LOCAL_MACHINE (0x80000002, sign-extended); KEY_QUERY_VALUE |
  ; KEY_WOW64_64KEY.
  System::Call 'advapi32::RegOpenKeyExW(p -2147483646, w R8, i 0, i 0x101, *p .R7) i .R6'
  ${If} $R6 = 0
    System::Call 'advapi32::RegQueryValueExW(p R7, w R9, p 0, *i .R6, p 0, p 0) i .R8'
    ${If} $R8 = 0
      StrCpy $R5 $R6
    ${EndIf}
    System::Call 'advapi32::RegCloseKey(p R7)'
  ${EndIf}
  StrCpy $R9 $R5
  Pop $R5
  Pop $R6
  Pop $R7
  Pop $R8
  Exch $R9
FunctionEnd

; Saves <value> of HKLM\<key>, with its type: "sz", "expand" (REG_EXPAND_SZ),
; "dword", or "" when it is absent (or of a type that is not restored).
!macro OAEID_SaveRegValue KEY NAME VALUE TYPE
  ClearErrors
  ReadRegStr ${VALUE} HKLM "${KEY}" "${NAME}"
  ${If} ${Errors}
    ; ReadRegStr reads a REG_DWORD as a decimal string and sets the error flag.
    ${If} ${VALUE} == ""
      StrCpy ${TYPE} ""
    ${Else}
      StrCpy ${TYPE} "dword"
    ${EndIf}
  ${Else}
    ; REG_SZ or REG_EXPAND_SZ (read unexpanded); keep which.
    Push "${KEY}"
    Push "${NAME}"
    Call GetHKLM64ValueType
    Pop ${TYPE}
    ${If} ${TYPE} == 2
      StrCpy ${TYPE} "expand"
    ${Else}
      StrCpy ${TYPE} "sz"
    ${EndIf}
  ${EndIf}
!macroend

; Writes a value saved by OAEID_SaveRegValue back, with its type, only if it
; is now absent.
!macro OAEID_RestoreRegValue KEY NAME VALUE TYPE
  ${If} ${TYPE} != ""
    ClearErrors
    ReadRegStr $R9 HKLM "${KEY}" "${NAME}"
    ${If} ${Errors}
    ${AndIf} $R9 == ""
      ${If} ${TYPE} == "dword"
        WriteRegDWORD HKLM "${KEY}" "${NAME}" ${VALUE}
      ${ElseIf} ${TYPE} == "expand"
        WriteRegExpandStr HKLM "${KEY}" "${NAME}" ${VALUE}
      ${Else}
        WriteRegStr HKLM "${KEY}" "${NAME}" ${VALUE}
      ${EndIf}
      Push "Restored ${NAME} (${VALUE}) under HKLM\${KEY}, which the previous version's uninstaller removed."
      Call InstallLog
    ${EndIf}
  ${EndIf}
!macroend

; Call SaveLocalSmartCardPolicy (before the old uninstaller runs)
; Uninstallers of every version so far delete two local security policy values
; that an administrator may have set (secpol.msc / local Group Policy) and that
; the Configuration Wizard can also set:
;   HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
;     scforceoption  "Interactive logon: Require Windows Hello for Business
;                     or smart card"
;   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
;     scremoveoption "Interactive logon: Smart card removal behavior"
; and set the Smart Card Removal Policy service (ScPolicySvc), which enforces
; scremoveoption, back to manual start and stop it. Without this an upgrade
; would silently turn smart-card-only logon and the removal behaviour off, or
; turn on a service an administrator had disabled. The service's start type
; is saved whatever it is (Start and DelayedAutostart).
Function SaveLocalSmartCardPolicy
  !insertmacro OAEID_SaveRegValue "Software\Microsoft\Windows\CurrentVersion\Policies\System" "scforceoption" $SavedScForceOption $SavedScForceOptionType
  !insertmacro OAEID_SaveRegValue "Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "scremoveoption" $SavedScRemoveOption $SavedScRemoveOptionType
  ClearErrors
  ReadRegDWORD $SavedScPolicySvcStart HKLM "SYSTEM\CurrentControlSet\Services\ScPolicySvc" "Start"
  ${If} ${Errors}
    StrCpy $SavedScPolicySvcStart ""
  ${EndIf}
  ClearErrors
  ReadRegDWORD $SavedScPolicySvcDelayed HKLM "SYSTEM\CurrentControlSet\Services\ScPolicySvc" "DelayedAutostart"
  ${If} ${Errors}
  ${OrIf} $SavedScPolicySvcDelayed == ""
    StrCpy $SavedScPolicySvcDelayed 0
  ${EndIf}
FunctionEnd

; Call RestoreLocalSmartCardPolicy (after the old uninstaller has run)
Function RestoreLocalSmartCardPolicy
  Push $R9
  Push $R8
  Push $R7
  !insertmacro OAEID_RestoreRegValue "Software\Microsoft\Windows\CurrentVersion\Policies\System" "scforceoption" $SavedScForceOption $SavedScForceOptionType
  !insertmacro OAEID_RestoreRegValue "Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "scremoveoption" $SavedScRemoveOption $SavedScRemoveOptionType

  ; ScPolicySvc: put back the start type it had (the uninstaller sets manual
  ; and stops it). DelayedAutostart only matters for automatic start (2).
  ${If} $SavedScPolicySvcStart != ""
    ClearErrors
    ReadRegDWORD $R9 HKLM "SYSTEM\CurrentControlSet\Services\ScPolicySvc" "Start"
    ClearErrors
    ReadRegDWORD $R8 HKLM "SYSTEM\CurrentControlSet\Services\ScPolicySvc" "DelayedAutostart"
    ${If} ${Errors}
    ${OrIf} $R8 == ""
      StrCpy $R8 0
    ${EndIf}
    StrCpy $R7 ""
    ${If} $R9 != $SavedScPolicySvcStart
      StrCpy $R7 "changed"
    ${ElseIf} $SavedScPolicySvcStart == 2
    ${AndIf} $R8 != $SavedScPolicySvcDelayed
      StrCpy $R7 "changed"
    ${EndIf}
    ${If} $R7 == "changed"
      ${If} $SavedScPolicySvcStart == 2
        ${If} $SavedScPolicySvcDelayed <> 0
          StrCpy $R7 "delayed-auto"
        ${Else}
          StrCpy $R7 "auto"
        ${EndIf}
      ${ElseIf} $SavedScPolicySvcStart == 3
        StrCpy $R7 "demand"
      ${ElseIf} $SavedScPolicySvcStart == 4
        StrCpy $R7 "disabled"
      ${Else}
        StrCpy $R7 ""
        Push "WARNING: the Smart Card Removal Policy service (ScPolicySvc) had start type $SavedScPolicySvcStart before the previous version's uninstaller ran, which this installer does not restore; it is now $R9. Check it with sc qc ScPolicySvc."
        Call InstallLog
      ${EndIf}
      ${If} $R7 != ""
        nsExec::ExecToLog '"$SYSDIR\sc.exe" config ScPolicySvc start= $R7'
        Pop $R8
        ${If} $R8 != 0
          Push "WARNING: could not set the Smart Card Removal Policy service (ScPolicySvc) back to start= $R7, as it was before the previous version's uninstaller ran (sc.exe result $R8)."
          Call InstallLog
        ${Else}
          ${If} $SavedScPolicySvcStart == 2
            nsExec::ExecToLog '"$SYSDIR\sc.exe" start ScPolicySvc'
            Pop $R8
          ${EndIf}
          Push "Set the Smart Card Removal Policy service (ScPolicySvc) back to start= $R7, as it was before the previous version's uninstaller ran."
          Call InstallLog
        ${EndIf}
      ${EndIf}
    ${EndIf}
  ${EndIf}
  Pop $R7
  Pop $R8
  Pop $R9
FunctionEnd

;--------------------------------
;Installation failed

; Abort in a section (RefuseInstallDir, InstallSystemDll) already closes the
; handle on $INSTDIR; this covers any other way the installation can fail.
Function .onInstFailed
  Call UnpinInstallDir
FunctionEnd

;--------------------------------
;Initializer function

Function .onInit
  ${If} ${RunningX64}
  ${Else}
    MessageBox MB_OK "This installer is designed for 64bits only"
    Abort
  ${EndIf}

  StrCpy $InstallDirHandle 0

  ; The folder of the installation being replaced (InstallPath, in the 64-bit
  ; registry view), unless /D= names one. NSIS has already taken /D= off
  ; $CMDLINE and put it in $INSTDIR, so look for it in the process command
  ; line - and treat any $INSTDIR other than the default as chosen by /D=, in
  ; case that command line was too long to read in full.
  StrCpy $R8 0
  ${If} $INSTDIR != "$PROGRAMFILES64\OpenAccess EID"
    StrCpy $R8 1
  ${Else}
    System::Call 'kernel32::GetCommandLineW() w .R9'
    StrLen $R7 $R9
    StrCpy $R6 0
    ${DoWhile} $R6 < $R7
      StrCpy $R5 $R9 4 $R6
      ${If} $R5 S== " /D="
        StrCpy $R8 1
        ${ExitDo}
      ${EndIf}
      IntOp $R6 $R6 + 1
    ${Loop}
  ${EndIf}
  ${If} $R8 == 0
    SetRegView 64
    ReadRegStr $R9 HKLM "Software\OpenAccessEID" "InstallPath"
    ${If} $R9 != ""
      StrCpy $INSTDIR $R9
    ${EndIf}
  ${EndIf}

  ; This installer has no folder page, so $INSTDIR (the default, /D= or the
  ; InstallPath registry value) is final here. Refuse a drive root or a system
  ; folder now, before an installed version is uninstalled; the Core section
  ; (PrepareInstallDir) checks the rest, whichever of the three it came from.
  Push $INSTDIR
  Call CanonicalisePath
  Pop $R9
  Push $R9
  Call IsForbiddenInstallDir
  Pop $R9
  ${If} $R9 == 1
    Push "is a drive root, a network path, or a Windows system folder (Windows, Program Files, Common Files, ProgramData, Users). Nothing was changed."
    Call RefuseInstallDir
  ${EndIf}

  ; Default for the security option.
  ;
  ; SECURITY: with this policy OFF, a credential may be sealed via the DPAPI
  ; path - CryptProtectData with CRYPTPROTECT_LOCAL_MACHINE and NO entropy - so
  ; the stored Windows password is recoverable by any administrator with no card
  ; and no PIN. The product's central claim only holds when this is ON.
  ;
  ; So: default ON for a genuinely FRESH install, and leave existing deployments
  ; alone. Defaulting ON unconditionally would silently re-lock existing
  ; non-card-bound (signature-only) enrollments out of logon on upgrade/repair,
  ; because silent (/S) installs never show the Security Options page.
  SetRegView 64
  StrCpy $MigratedFromLegacy 0
  StrCpy $EnrolmentsWiped 0
  StrCpy $PrevInstallDir ""
  StrCpy $NeutralisedDll ""
  StrCpy $NeutralisedAside ""
  ; Current install location, else one made under the former product name.
  ReadRegStr $9 HKLM "Software\OpenAccessEID" "InstallPath"
  ${If} $9 == ""
    ReadRegStr $9 HKLM "Software\EIDAuthentication" "InstallPath"
  ${EndIf}
  ${If} $9 == ""
    ; No prior installation - nothing can be re-locked, so be secure by default.
    StrCpy $RequireCardBound 1
  ${Else}
    ; Upgrade or repair: preserve today's behaviour and let the value already in
    ; force (read below) decide.
    StrCpy $RequireCardBound 0
  ${EndIf}
  StrCpy $SecurityPageShown 0

  ; On upgrade/repair, seed the checkbox from the policy value already in force so the
  ; page reflects reality instead of always rendering unchecked. This also means an
  ; admin who deliberately set 0 keeps 0.
  ClearErrors
  ReadRegDWORD $0 HKLM "SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" "RequireCardBoundCredentials"
  ${IfNot} ${Errors}
    StrCpy $RequireCardBound $0
  ${EndIf}

  ; Check for an existing installation - current name first, then the former
  ; EID Authentication name (v1.3.00 and earlier).
  SetRegView 64
  StrCpy $5 "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID"
  StrCpy $6 "OpenAccess EID"
  ReadRegStr $0 HKLM "Software\OpenAccessEID" "InstallPath"
  ${If} $0 == ""
    ReadRegStr $0 HKLM "Software\EIDAuthentication" "InstallPath"
    ${If} $0 != ""
      StrCpy $5 "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication"
      StrCpy $6 "EID Authentication (the former name of OpenAccess EID)"
      StrCpy $MigratedFromLegacy 1
    ${EndIf}
  ${EndIf}
  StrCmp $0 "" CheckInstallEnd 0

  ; Uninstallers of v2.0.00 and earlier delete every user's stored credential
  ; while unregistering, whatever the cleanup checkboxes say. Newer ones keep
  ; them and record that with this marker (written by the Core section). For the
  ; older ones, NeutraliseOldUnregister (below) swaps in this version's
  ; unregistration step before running them.
  ClearErrors
  ReadRegDWORD $4 HKLM "$5" "KeepsEnrolmentsOnUninstall"
  ${If} $4 == 1
    StrCpy $3 "Smart-card enrollments and stored credentials are kept."
  ${Else}
    StrCpy $3 "The uninstaller of this older version deletes every user's stored smart-card credential. The installer replaces that step so that enrollments are kept; if it cannot, you will be asked before anything is removed."
  ${EndIf}

  ; Installation found - ask user to uninstall first
  MessageBox MB_YESNO "$6 is already installed at:$\n$0$\n$\nIt must be uninstalled first. $3$\n$\nUninstall it now?" /SD IDYES IDYES DoUninstall IDNO AbortInstall

  DoUninstall:
    InitPluginsDir

    ; The uninstaller deletes the whole smart-card policy key, which holds
    ; RequireCardBoundCredentials, RequireRevocationCheck and the other
    ; policies an administrator chose. Keep a copy and put it back afterwards
    ; so an upgrade does not silently reset them.
    ClearErrors
    nsExec::ExecToLog '"$SYSDIR\reg.exe" export "HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" "$PLUGINSDIR\sccp-policy.reg" /y /reg:64'
    Pop $7
    ; It also deletes the local security policy values scforceoption and
    ; scremoveoption and resets the Smart Card Removal Policy service.
    Call SaveLocalSmartCardPolicy

    ; Logging settings live under the install key, which the uninstaller also
    ; deletes. Migrating from the former name, copy them to the new key (which
    ; the old uninstaller never touches); otherwise keep a copy to put back.
    ; Whether the new LogManager key existed before, so that a cancelled
    ; upgrade can remove the copy made here.
    StrCpy $R4 0
    ClearErrors
    EnumRegValue $R5 HKLM "SOFTWARE\OpenAccessEID\LogManager" 0
    ${If} ${Errors}
      StrCpy $R4 1
    ${EndIf}
    ${If} $MigratedFromLegacy == 1
      nsExec::ExecToLog '"$SYSDIR\reg.exe" copy "HKLM\SOFTWARE\EIDAuthentication\LogManager" "HKLM\SOFTWARE\OpenAccessEID\LogManager" /s /f /reg:64'
      Pop $8
      StrCpy $8 1
    ${Else}
      nsExec::ExecToLog '"$SYSDIR\reg.exe" export "HKLM\SOFTWARE\OpenAccessEID\LogManager" "$PLUGINSDIR\logmanager.reg" /y /reg:64'
      Pop $8
    ${EndIf}

    ; _?= makes ExecWait genuinely wait. Without it an NSIS uninstaller
    ; re-launches itself from a temporary copy and returns at once, so it
    ; would run concurrently with this install - and delete keys the new
    ; version has just written (credential provider CLSID, policies).
    ReadRegStr $1 HKLM "$5" "UninstallString"
    ${If} ${FileExists} "$1"
      ; An uninstaller that wipes enrolments: run it with this version's
      ; DllUnRegister in place of its own. If that cannot be arranged, an
      ; interactive upgrade asks; a silent one stops unless /WIPEENROLMENTS=1
      ; says that losing every enrolment is accepted.
      ${If} $4 != 1
        Call NeutraliseOldUnregister
        Pop $R0
        ${If} $R0 != 1
          ${If} ${Silent}
            ${GetParameters} $R1
            ClearErrors
            ${GetOptions} $R1 "/WIPEENROLMENTS=" $R2
            ${If} ${Errors}
            ${OrIf} $R2 != 1
              Push "ERROR: upgrade refused. The uninstaller of the installed version ($6) deletes every user's stored smart-card credential, and this installer could not replace that step (details above). The installed version has not been touched. Upgrade interactively, or run again with /WIPEENROLMENTS=1 to accept that every user must re-enrol."
              Call InstallLog
              Abort
            ${EndIf}
          ${Else}
            MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 "The installer could not stop the uninstaller of the installed version from deleting every user's stored smart-card credential.$\n$\nIf you continue, every enrolled user must re-enrol their card after the upgrade.$\n$\nContinue anyway?" IDYES WipeAccepted
            Push "Upgrade cancelled: the old uninstaller would have deleted every stored smart-card credential."
            Call InstallLog
            Abort
            WipeAccepted:
          ${EndIf}
          StrCpy $EnrolmentsWiped 1
          Push "WARNING: running the old uninstaller unchanged; it deletes every user's stored smart-card credential."
          Call InstallLog
        ${EndIf}
      ${EndIf}

      ; An NSIS uninstaller exits 0 when it finished, 1 when the operator
      ; cancelled it and 2 when it stopped part-way.
      ClearErrors
      ${If} ${Silent}
        ExecWait '"$1" /S _?=$0' $R3
      ${Else}
        ExecWait '"$1" _?=$0' $R3
      ${EndIf}
      ${If} ${Errors}
        StrCpy $R3 "not started"
      ${EndIf}
      ${If} $R3 == 0
        ; Run in place, the uninstaller cannot delete itself or its directory.
        Delete "$1"
        RMDir "$0"
        StrCpy $PrevInstallDir $0
      ${EndIf}
    ${Else}
      StrCpy $R3 0
    ${EndIf}

    ; Put back what was saved, whatever happened: an uninstaller that stopped
    ; part-way may already have deleted it. Each step only adds what is missing.
    ${If} $7 == 0
      nsExec::ExecToLog '"$SYSDIR\reg.exe" import "$PLUGINSDIR\sccp-policy.reg" /reg:64'
      Pop $7
    ${EndIf}
    ${If} $8 == 0
      nsExec::ExecToLog '"$SYSDIR\reg.exe" import "$PLUGINSDIR\logmanager.reg" /reg:64'
      Pop $8
    ${EndIf}
    Call RestoreLocalSmartCardPolicy

    ; Cancelled or failed: leave the installed version as it was and stop.
    ${If} $R3 != 0
      Call UndoNeutraliseOldUnregister
      ${If} $MigratedFromLegacy == 1
      ${AndIf} $R4 == 1
        DeleteRegKey HKLM "SOFTWARE\OpenAccessEID\LogManager"
        DeleteRegKey /ifempty HKLM "SOFTWARE\OpenAccessEID"
      ${EndIf}
      Push "ERROR: the uninstaller of the installed version ($6) was cancelled or did not finish (exit code $R3). Installation stopped; nothing of this version was installed."
      Call InstallLog
      MessageBox MB_OK|MB_ICONSTOP "The uninstaller of the installed version was cancelled or did not finish (exit code $R3).$\n$\nThe installation has been stopped. If the uninstaller was cancelled, the installed version is unchanged. If it stopped part-way, run this installer again." /SD IDOK
      Abort
    ${EndIf}
    Goto CheckInstallEnd

  AbortInstall:
    Abort

  CheckInstallEnd:
FunctionEnd
