# Test-EIDDirectoryTree.ps1 - run by the OpenAccess EID installer
# (Installerx64.nsi, IsEIDDataTreeTrusted); not meant to be run by hand.
#
# Decides whether -Path and everything below it can be trusted by code that
# runs as SYSTEM (LSASS, the trace consumer service):
#   - every item is owned by SYSTEM (S-1-5-18) or Administrators (S-1-5-32-544);
#   - nothing is a junction, symbolic link or other reparse point (the walk
#     stops there and never follows one);
#   - no allow ACE gives anyone other than SYSTEM, Administrators or
#     CREATOR OWNER (harmless once every owner is SYSTEM/Administrators) a
#     right to write, create, delete, change permissions or take ownership.
#     Read/execute for Users (or anyone) is fine.
#
# Exit codes, read by the installer:
#   10 = trusted
#   11 = not trusted (including an ACL or folder that cannot be read)
#   12 = cannot evaluate here (PowerShell not in FullLanguage mode)
#   anything else = PowerShell did not run the check; the installer treats
#   that as "could not check", never as either answer.

param(
    [Parameter(Mandatory = $true)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Output "Cannot check ${Path}: PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode."
    exit 12
}

$trustedOwners = @('S-1-5-18', 'S-1-5-32-544')
# May hold any right.
$trustedTrustees = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0')
# WriteData/CreateFiles, AppendData/CreateDirectories, WriteExtendedAttributes,
# DeleteSubdirectoriesAndFiles, WriteAttributes, Delete, ChangePermissions
# (WRITE_DAC), TakeOwnership (WRITE_OWNER), GENERIC_ALL, GENERIC_WRITE.
$writeMask = 0x500D0156

function Test-EIDItem {
    param($Item)
    if ((([int] $Item.Attributes) -band 0x400) -ne 0) {
        Write-Output "Not trusted: $($Item.FullName) is a junction, symbolic link or other reparse point."
        exit 11
    }
    $acl = Get-Acl -LiteralPath $Item.FullName
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trustedOwners -notcontains $owner) {
        Write-Output "Not trusted: $($Item.FullName) is owned by $owner."
        exit 11
    }
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $ace.IdentityReference.Value
        if ($trustedTrustees -contains $sid) { continue }
        if (([int] $ace.FileSystemRights -band $writeMask) -ne 0) {
            Write-Output "Not trusted: $($Item.FullName) grants $sid write/delete/permission rights ($($ace.FileSystemRights))."
            exit 11
        }
    }
}

function Test-EIDTree {
    param($Directory)
    foreach ($child in @(Get-ChildItem -LiteralPath $Directory.FullName -Force)) {
        Test-EIDItem $child
        # Test-EIDItem has already refused a reparse point, so this never
        # descends into a junction's target.
        if ($child.PSIsContainer) { Test-EIDTree $child }
    }
}

try {
    $root = Get-Item -LiteralPath $Path -Force
    Test-EIDItem $root
    if ($root.PSIsContainer) { Test-EIDTree $root }
    Write-Output "Trusted: $Path"
    exit 10
} catch {
    Write-Output "Not trusted: could not check ${Path}: $($_.Exception.Message)"
    exit 11
}
