# Test-EIDInstallParents.ps1 - run by the OpenAccess EID installer
# (Installerx64.nsi, CheckInstallParents); not meant to be run by hand.
#
# -Path is the installation folder; it need not exist yet. The trace consumer
# service runs from it as SYSTEM and administrators run its tools, so nobody
# but SYSTEM, Administrators and TrustedInstaller may be able to swap it for
# another folder once it is installed - by renaming or deleting a folder above
# it, or by giving themselves the right to. Every folder above -Path that
# exists, up to the root of the volume, must therefore be:
#   - not a junction, symbolic link or other reparse point (the walk never
#     follows one);
#   - owned by SYSTEM (S-1-5-18), Administrators (S-1-5-32-544) or
#     TrustedInstaller - an owner can always change the permissions;
#   - free of allow ACEs that apply to the folder itself (inherit-only ACEs
#     are skipped) and give anyone else DELETE, WRITE_DAC, WRITE_OWNER or
#     GENERIC_ALL (rename, delete or re-permission the folder), or
#     FILE_DELETE_CHILD (rename or delete the folder below it). CREATOR OWNER
#     and OWNER RIGHTS stand for the owner, which is checked above.
# Deny ACEs are not taken into account, so a folder can be refused that a
# deny entry would in fact protect; that errs on the safe side.
#
# Exit codes, read by the installer:
#   10 = every existing folder above -Path passes
#   11 = one does not (or its ACL or attributes cannot be read)
#   12 = cannot evaluate here (PowerShell not in FullLanguage mode)
#   anything else = PowerShell did not run the check; the installer treats
#   that as "could not check", never as either answer.

param(
    [Parameter(Mandatory = $true)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Output "Cannot check the folders above ${Path}: PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode."
    exit 12
}

$trustedOwners = @(
    'S-1-5-18',
    'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)
# May hold any right: the trusted owners, CREATOR OWNER and OWNER RIGHTS.
$trustedTrustees = $trustedOwners + @('S-1-3-0', 'S-1-3-4')
# DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL.
$selfMask = 0x100D0000
# FILE_DELETE_CHILD (DeleteSubdirectoriesAndFiles), GENERIC_ALL.
$childMask = 0x10000040

function Test-EIDParent {
    param($Item)
    if ((([int] $Item.Attributes) -band 0x400) -ne 0) {
        Write-Output "Not safe: $($Item.FullName) is a junction, symbolic link or other reparse point."
        exit 11
    }
    $acl = Get-Acl -LiteralPath $Item.FullName
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trustedOwners -notcontains $owner) {
        Write-Output "Not safe: $($Item.FullName) is owned by $owner, who can change its permissions."
        exit 11
    }
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        $sid = $ace.IdentityReference.Value
        if ($trustedTrustees -contains $sid) { continue }
        $rights = [int] $ace.FileSystemRights
        if (($rights -band $selfMask) -ne 0) {
            Write-Output "Not safe: $($Item.FullName) lets $sid rename, delete or change the permissions of it ($($ace.FileSystemRights))."
            exit 11
        }
        if (($rights -band $childMask) -ne 0) {
            Write-Output "Not safe: $($Item.FullName) lets $sid rename or delete the folders in it ($($ace.FileSystemRights))."
            exit 11
        }
    }
}

try {
    $parent = [IO.Path]::GetDirectoryName($Path.TrimEnd('\'))
    $checked = 0
    while ($parent) {
        $item = $null
        try {
            $item = Get-Item -LiteralPath $parent -Force
        } catch [System.Management.Automation.ItemNotFoundException] {
            # Not created yet: the installer creates it, protected.
        }
        if ($null -ne $item) {
            Test-EIDParent $item
            $checked++
        }
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    if ($checked -eq 0) {
        Write-Output "Not safe: no folder above $Path exists."
        exit 11
    }
    Write-Output "Safe: no folder above $Path can be renamed or re-permissioned by other users."
    exit 10
} catch {
    Write-Output "Not safe: could not check the folders above ${Path}: $($_.Exception.Message)"
    exit 11
}
