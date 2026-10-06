#requires -Version 5.1

<#
.SYNOPSIS
    Disables Windows LSA Protection (RunAsPPL) so unsigned LSA plug-ins can load.

.DESCRIPTION
    OpenAccess EID ships three DLLs that Windows loads into LSASS:
      - OpenAccessEIDPackage.dll   (LSA Authentication Package)
      - EIDCredentialProvider.dll      (Credential Provider)
      - EIDPasswordChangeNotification.dll (Password Change Notification)

    When Windows "LSA Protection" (a.k.a. RunAsPPL / Protected Process Light)
    is enabled, LSASS will REFUSE to load any plug-in that is not signed with
    a Microsoft-issued certificate. The beta builds from this project are
    currently UNSIGNED, which means they will silently fail to load on any
    machine where LSA Protection is active.

    This script disables LSA Protection on the local machine so the beta
    build can be tested. Re-enabling it is a single command (documented in
    the 'Re-enable' section below) plus a reboot.

    This script is MANUAL-RUN ONLY. It is shipped with the installer but is
    never executed automatically. It must be run by a system administrator
    who understands and accepts the security impact.

.NOTES
    Authoritative Microsoft reference:
    https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

    If you would prefer signed binaries so you do NOT have to disable LSA
    Protection, please raise an issue at:
    https://github.com/SP00KY-CB/OpenAccessEID/issues
    and request a code-signed release.
#>

[CmdletBinding()]
param(
    [switch] $EnableAuditMode,
    [switch] $Restore,
    [switch] $NonInteractive
)

$ErrorActionPreference = 'Stop'

$currentId = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin   = (New-Object Security.Principal.WindowsPrincipal $currentId).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'This script needs Administrator rights. Re-launching elevated...' -ForegroundColor Yellow
    $psArgs = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch] -and $kv.Value.IsPresent) {
            $psArgs += "-$($kv.Key)"
        }
    }
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $psArgs -Verb RunAs | Out-Null
    } catch {
        Write-Host 'Elevation was cancelled. No changes made.' -ForegroundColor Red
    }
    return
}

$LsaKey        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$AuditKey      = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe'
$DataDir       = Join-Path $env:ProgramData 'OpenAccessEID'
$BackupDir     = Join-Path $DataDir 'LsaProtectionBackup'
$BackupFile    = Join-Path $BackupDir 'RunAsPPL.backup.txt'

# The backup decides what -Restore writes into the LSA key, so it is only
# written or read where a standard user cannot have planted or changed it:
# C:\ProgramData\OpenAccessEID, LsaProtectionBackup and the backup file must
# each be a real folder or file (not a junction, symbolic link or other
# reparse point), owned by SYSTEM or Administrators, and give nobody else a
# right to write, delete, change permissions or take ownership. Checked
# outermost first: once a folder passes, nobody else can swap what is in it.
# Returns $null when the item passes, else the reason it does not.
function Get-UntrustedReason {
    param([string] $LiteralPath)
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if ((([int] $item.Attributes) -band 0x400) -ne 0) {
        return "$LiteralPath is a junction, symbolic link or other reparse point"
    }
    $acl = Get-Acl -LiteralPath $LiteralPath
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (@('S-1-5-18', 'S-1-5-32-544') -notcontains $owner) {
        return "$LiteralPath is owned by $owner, not by SYSTEM or Administrators"
    }
    # WriteData/CreateFiles, AppendData/CreateDirectories, WriteExtendedAttributes,
    # DeleteSubdirectoriesAndFiles, WriteAttributes, Delete, ChangePermissions,
    # TakeOwnership, GENERIC_ALL, GENERIC_WRITE (as Test-EIDDirectoryTree.ps1).
    $writeMask = 0x500D0156
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $ace.IdentityReference.Value
        if (@('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0') -contains $sid) { continue }
        if (([int] $ace.FileSystemRights -band $writeMask) -ne 0) {
            return "$LiteralPath lets $sid modify it"
        }
    }
    return $null
}

# Throws unless $DataDir, $BackupDir and (with -IncludeFile) $BackupFile pass
# Get-UntrustedReason.
function Assert-TrustedBackupLocation {
    param([switch] $IncludeFile)
    $paths = @($DataDir, $BackupDir)
    if ($IncludeFile) { $paths += $BackupFile }
    foreach ($p in $paths) {
        $reason = Get-UntrustedReason -LiteralPath $p
        if ($reason) {
            throw "Refusing to use the LSA Protection backup: $reason. Nothing was changed. Check $DataDir by hand (a standard user may have planted it), remove what does not belong there, then run this script again."
        }
    }
}

function Write-Banner {
    param([string] $Text, [ConsoleColor] $Color = 'Yellow')
    $line = '=' * 72
    Write-Host ''
    Write-Host $line -ForegroundColor $Color
    Write-Host $Text -ForegroundColor $Color
    Write-Host $line -ForegroundColor $Color
    Write-Host ''
}

function Get-LsaProtectionState {
    $ppl = $null
    try {
        $ppl = (Get-ItemProperty -Path $LsaKey -Name 'RunAsPPL' -ErrorAction Stop).RunAsPPL
    } catch {
        $ppl = $null
    }

    $pplBoot = $null
    try {
        $pplBoot = (Get-ItemProperty -Path $LsaKey -Name 'RunAsPPLBoot' -ErrorAction Stop).RunAsPPLBoot
    } catch {
        $pplBoot = $null
    }

    $secureBoot = $false
    try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBoot = $false }

    $winver = [System.Environment]::OSVersion.Version

    [pscustomobject]@{
        RunAsPPL        = $ppl
        RunAsPPLBoot    = $pplBoot
        SecureBoot      = $secureBoot
        OSBuild         = $winver.Build
        OSVersion       = "$($winver.Major).$($winver.Minor).$($winver.Build)"
        UefiLockLikely  = ($ppl -eq 1) -and $secureBoot
    }
}

function Show-WarningPage {
    param($State)

    Clear-Host
    Write-Banner 'WARNING: YOU ARE ABOUT TO WEAKEN A CORE WINDOWS SECURITY BOUNDARY' 'Red'

    Write-Host "This script will disable LSA Protection (RunAsPPL) on this computer." -ForegroundColor White
    Write-Host ""
    Write-Host "What LSA Protection does:" -ForegroundColor Cyan
    Write-Host "  LSA Protection runs LSASS.exe as a Protected Process Light (PPL)." -ForegroundColor Gray
    Write-Host "  This prevents unsigned code from being injected into LSASS and" -ForegroundColor Gray
    Write-Host "  blocks credential-theft tools such as Mimikatz from dumping" -ForegroundColor Gray
    Write-Host "  cached passwords, Kerberos tickets, and NTLM hashes from memory." -ForegroundColor Gray
    Write-Host ""
    Write-Host "What this script will change:" -ForegroundColor Cyan
    Write-Host "  Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ForegroundColor Gray
    Write-Host "    RunAsPPL     (DWORD) -> 0    [currently: $($State.RunAsPPL)]" -ForegroundColor Gray
    if ($null -ne $State.RunAsPPLBoot) {
        Write-Host "    RunAsPPLBoot (DWORD) -> 0    [currently: $($State.RunAsPPLBoot)] (Windows 11 24H2+)" -ForegroundColor Gray
    }
    Write-Host "  Backup written to:" -ForegroundColor Gray
    Write-Host "    $BackupFile" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Security impact of disabling LSA Protection:" -ForegroundColor Cyan
    Write-Host "  * Malware running with admin/SYSTEM privileges can read LSASS memory" -ForegroundColor Gray
    Write-Host "  * Credential-theft tools (Mimikatz et al.) will work against this host" -ForegroundColor Gray
    Write-Host "  * Unsigned LSA plug-ins (including the OpenAccess EID beta) will load" -ForegroundColor Gray
    Write-Host "  * Credential Guard (if present) continues to provide SOME isolation" -ForegroundColor Gray
    Write-Host "    but NTLM/Kerberos cache memory is no longer hardened against dumping." -ForegroundColor Gray
    Write-Host ""
    Write-Host "When to use this:" -ForegroundColor Cyan
    Write-Host "  * Beta / dev testing of unsigned OpenAccess EID builds." -ForegroundColor Gray
    Write-Host "  * Dedicated lab machines only." -ForegroundColor Gray
    Write-Host "  * NEVER on production workstations, domain controllers, or shared hosts." -ForegroundColor Gray
    Write-Host "  * NEVER on machines with domain credentials or cached admin tokens" -ForegroundColor Gray
    Write-Host "    that you care about." -ForegroundColor Gray
    Write-Host ""
    Write-Host "Alternative: request a signed release" -ForegroundColor Cyan
    Write-Host "  If you cannot disable LSA Protection, you can request a code-signed" -ForegroundColor Gray
    Write-Host "  build by opening an issue at:" -ForegroundColor Gray
    Write-Host "    https://github.com/SP00KY-CB/OpenAccessEID/issues" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Current state of this machine:" -ForegroundColor Cyan
    Write-Host "  OS version      : $($State.OSVersion)" -ForegroundColor Gray
    Write-Host "  Secure Boot     : $($State.SecureBoot)" -ForegroundColor Gray
    Write-Host "  RunAsPPL        : $(if ($null -eq $State.RunAsPPL)      { '(not set) -> LSA Protection OFF' } else { "$($State.RunAsPPL)" })" -ForegroundColor Gray
    Write-Host "  RunAsPPLBoot    : $(if ($null -eq $State.RunAsPPLBoot)  { '(not set)' }                      else { "$($State.RunAsPPLBoot)" })" -ForegroundColor Gray

    if ($State.UefiLockLikely) {
        Write-Host ""
        Write-Host "CAUTION: Secure Boot is ON and RunAsPPL=1 (UEFI lock variant)." -ForegroundColor Red
        Write-Host "A UEFI variable may have been stored when LSA Protection was enabled." -ForegroundColor Red
        Write-Host "If the registry change alone does not take effect after reboot, you" -ForegroundColor Red
        Write-Host "will need the Microsoft LsaPplConfig.efi Opt-out tool:" -ForegroundColor Red
        Write-Host "  https://www.microsoft.com/download/details.aspx?id=40897" -ForegroundColor Red
    }

    if ($null -eq $State.RunAsPPL -or $State.RunAsPPL -eq 0) {
        Write-Host ""
        Write-Host "NOTE: LSA Protection is already OFF on this host." -ForegroundColor Green
        Write-Host "      No changes are required. You can exit safely." -ForegroundColor Green
    }

    Write-Host ""
}

function Confirm-Proceed {
    param([string] $ExpectedPhrase)
    Write-Host "To proceed, type the phrase in capitals: " -NoNewline -ForegroundColor Yellow
    Write-Host $ExpectedPhrase -ForegroundColor White -NoNewline
    Write-Host "  (anything else cancels)" -ForegroundColor Yellow
    Write-Host ">> " -NoNewline
    $typed = Read-Host
    return ($typed -ceq $ExpectedPhrase)
}

function Save-CurrentState {
    param($State)
    # Never overwrite an existing backup: it records the state from before LSA
    # Protection was first turned off, which is what -Restore must put back. A
    # second run (say with -EnableAuditMode) would otherwise record "0".
    # The installer creates $DataDir with permissions only SYSTEM and
    # Administrators can change; LsaProtectionBackup inherits them.
    if (-not (Test-Path -LiteralPath $DataDir)) {
        throw "$DataDir does not exist. Install (or reinstall) OpenAccess EID, which creates it with the right permissions, then run this script again. Nothing was changed."
    }
    if (Test-Path -LiteralPath $BackupFile) {
        Assert-TrustedBackupLocation -IncludeFile
        Write-Host "  Keeping the existing backup of the original state: $BackupFile" -ForegroundColor Green
        return
    }
    if (-not (Test-Path -LiteralPath $BackupDir)) {
        $reason = Get-UntrustedReason -LiteralPath $DataDir
        if ($reason) {
            throw "Refusing to write the LSA Protection backup: $reason. Nothing was changed."
        }
        New-Item -Path $BackupDir -ItemType Directory | Out-Null
    }
    Assert-TrustedBackupLocation
    $lines = @(
        "# OpenAccess EID - LSA Protection state backup",
        "# Created: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ') UTC",
        "# Use these values if you want to manually restore the original state.",
        "",
        "RunAsPPL         = $(if ($null -eq $State.RunAsPPL)     { '<unset>' } else { $State.RunAsPPL })",
        "RunAsPPLBoot     = $(if ($null -eq $State.RunAsPPLBoot) { '<unset>' } else { $State.RunAsPPLBoot })",
        "SecureBoot       = $($State.SecureBoot)",
        "OSVersion        = $($State.OSVersion)"
    )
    Set-Content -LiteralPath $BackupFile -Value $lines -Encoding UTF8
    Write-Host "  Backed up prior state to: $BackupFile" -ForegroundColor Green
}

function Set-LsaRunAsPPL {
    param([int] $Value)
    Set-ItemProperty -Path $LsaKey -Name 'RunAsPPL' -Value $Value -Type DWord
    Write-Host "  RunAsPPL set to $Value" -ForegroundColor Green

    # RunAsPPLBoot exists only on Windows 11 24H2 and later; it is changed only
    # where it is already present. A failure to write it is not swallowed.
    $probe = Get-ItemProperty -Path $LsaKey -Name 'RunAsPPLBoot' -ErrorAction SilentlyContinue
    if ($null -ne $probe -and $null -ne $probe.RunAsPPLBoot) {
        Set-ItemProperty -Path $LsaKey -Name 'RunAsPPLBoot' -Value $Value -Type DWord
        Write-Host "  RunAsPPLBoot set to $Value" -ForegroundColor Green
    } else {
        Write-Host '  RunAsPPLBoot is not present on this OS build; left unchanged.' -ForegroundColor Gray
    }
}

function Read-StateBackup {
    # Returns the RunAsPPL / RunAsPPLBoot values recorded by Save-CurrentState.
    # $null means the value did not exist before this script changed anything.
    $values = @{ RunAsPPL = $null; RunAsPPLBoot = $null }
    $found = @{}
    foreach ($line in Get-Content -LiteralPath $BackupFile) {
        if ($line -match '^\s*(RunAsPPL|RunAsPPLBoot)\s*=\s*(\S+)\s*$') {
            $name = $Matches[1]
            $raw = $Matches[2]
            if ($raw -eq '<unset>') {
                $values[$name] = $null
            } elseif ($raw -match '^\d+$') {
                $values[$name] = [int] $raw
            } else {
                throw "Unrecognised value '$raw' for $name in $BackupFile"
            }
            $found[$name] = $true
        }
    }
    if (-not $found['RunAsPPL']) {
        throw "$BackupFile does not record RunAsPPL"
    }
    return $values
}

function Format-BackupValue {
    param($Value)
    if ($null -eq $Value) { return '(not set)' }
    return "$Value"
}

function Restore-LsaValue {
    param([string] $Name, $Value, [switch] $LeaveIfUnset)
    if ($null -ne $Value) {
        Set-ItemProperty -Path $LsaKey -Name $Name -Value $Value -Type DWord
        Write-Host "  $Name restored to $Value" -ForegroundColor Green
    } elseif ($LeaveIfUnset) {
        Write-Host "  $Name was not set before; left unchanged" -ForegroundColor Gray
    } else {
        if ($null -ne (Get-ItemProperty -Path $LsaKey -Name $Name -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $LsaKey -Name $Name
        }
        Write-Host "  $Name removed (it was not set before)" -ForegroundColor Green
    }
}

function Enable-LsaAuditMode {
    if (-not (Test-Path $AuditKey)) {
        New-Item -Path $AuditKey -Force | Out-Null
    }
    Set-ItemProperty -Path $AuditKey -Name 'AuditLevel' -Value 8 -Type DWord
    Write-Host "  AuditLevel set to 0x8 at:" -ForegroundColor Green
    Write-Host "    $AuditKey" -ForegroundColor Gray
    Write-Host "  CodeIntegrity events 3065/3066 (audit mode) or 3033/3063 (enforcement)" -ForegroundColor Gray
    Write-Host "  will be logged under:" -ForegroundColor Gray
    Write-Host "    Event Viewer > Applications and Services Logs > Microsoft >" -ForegroundColor Gray
    Write-Host "    Windows > CodeIntegrity > Operational" -ForegroundColor Gray
}

function Invoke-Restore {
    Write-Banner 'Restore mode: re-enable LSA Protection' 'Cyan'
    $backup = $null
    if (Test-Path -LiteralPath $BackupFile) {
        # A planted "backup" could keep LSA Protection off; refuse it.
        Assert-TrustedBackupLocation -IncludeFile
        $backup = Read-StateBackup
        Write-Host "Backup found at $BackupFile" -ForegroundColor Cyan
        Write-Host "Will restore the values recorded there:" -ForegroundColor Cyan
        Write-Host "  RunAsPPL     -> $(Format-BackupValue $backup.RunAsPPL)" -ForegroundColor Gray
        Write-Host "  RunAsPPLBoot -> $(Format-BackupValue $backup.RunAsPPLBoot)" -ForegroundColor Gray
    } else {
        Write-Host "No backup found at $BackupFile" -ForegroundColor Yellow
        Write-Host "Will set RunAsPPL = 1 (LSA Protection, with UEFI variable on Secure Boot hosts)." -ForegroundColor Yellow
    }
    if (-not $NonInteractive -and -not (Confirm-Proceed 'RESTORE')) {
        Write-Host 'Cancelled.' -ForegroundColor Red
        return
    }
    if ($null -eq $backup) {
        Set-LsaRunAsPPL -Value 1
    } else {
        Restore-LsaValue -Name 'RunAsPPL' -Value $backup.RunAsPPL
        # Set-LsaRunAsPPL only ever changes RunAsPPLBoot where it already
        # existed, so "not set" in the backup means it was never touched.
        Restore-LsaValue -Name 'RunAsPPLBoot' -Value $backup.RunAsPPLBoot -LeaveIfUnset
        # Retire the backup: its presence is how the uninstaller (and the next
        # run of this script) tell that LSA Protection is still turned off.
        $retired = Join-Path $BackupDir ('RunAsPPL.restored-{0}.txt' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Move-Item -LiteralPath $BackupFile -Destination $retired
        Write-Host "  Backup applied and kept as $retired" -ForegroundColor Green
    }
    Write-Host ''
    Write-Host 'Reboot required to take effect.' -ForegroundColor Cyan
}

# ------------------------------ main ---------------------------------------

if ($Restore) {
    Invoke-Restore
    return
}

$state = Get-LsaProtectionState
Show-WarningPage -State $state

if ($null -eq $state.RunAsPPL -or $state.RunAsPPL -eq 0) {
    if (-not $EnableAuditMode) {
        Write-Host 'Nothing to do. Exiting.' -ForegroundColor Green
        return
    }
}

if (-not $NonInteractive) {
    if (-not (Confirm-Proceed 'DISABLE LSA PROTECTION')) {
        Write-Host ''
        Write-Host 'Cancelled. No changes made.' -ForegroundColor Red
        return
    }
}

Write-Banner 'Applying changes' 'Cyan'
Save-CurrentState -State $state
Set-LsaRunAsPPL -Value 0

if ($EnableAuditMode) {
    Write-Host ''
    Write-Host 'Enabling LSASS audit mode...' -ForegroundColor Cyan
    Enable-LsaAuditMode
}

Write-Banner 'Reboot required' 'Yellow'
Write-Host 'The registry change does NOT take effect until this machine reboots.' -ForegroundColor Yellow
Write-Host ''
Write-Host 'After reboot, confirm LSA Protection is OFF:' -ForegroundColor Cyan
Write-Host '  Event Viewer > Windows Logs > System - look for "WinInit" event 12.' -ForegroundColor Gray
Write-Host '  If LSASS started WITHOUT a protection level, LSA Protection is OFF.' -ForegroundColor Gray
Write-Host ''
Write-Host 'To re-enable LSA Protection later:' -ForegroundColor Cyan
Write-Host '  powershell -ExecutionPolicy Bypass -File ' -NoNewline -ForegroundColor Gray
Write-Host "`"$PSCommandPath`" -Restore" -ForegroundColor Gray
Write-Host '  (then reboot)' -ForegroundColor Gray

if ($state.UefiLockLikely) {
    Write-Host ''
    Write-Banner 'Follow-up needed: UEFI lock variable may still be set' 'Red'
    Write-Host 'Your machine had RunAsPPL=1 with Secure Boot. If after reboot LSASS' -ForegroundColor Yellow
    Write-Host 'still starts as protected (WinInit event 12 with level 4), you will' -ForegroundColor Yellow
    Write-Host 'need to clear the UEFI variable using the Microsoft Opt-out tool:' -ForegroundColor Yellow
    Write-Host '  https://www.microsoft.com/download/details.aspx?id=40897' -ForegroundColor White
}
