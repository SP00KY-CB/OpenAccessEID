# Remove-EIDLsaRegistration.ps1 - run by the OpenAccess EID uninstaller
# (Installerx64.nsi, Uninstall section) after DllUnRegister; not meant to be
# run by hand.
#
# rundll32 exits 0 whether or not DllUnRegister worked, so the uninstaller
# cannot tell from its exit code whether LSA still names the package. This
# checks the three LSA lists under HKLM\SYSTEM\CurrentControlSet\Control\Lsa
# and removes any OpenAccess EID name still in them (current and pre-v2.0.00
# names), leaving every other entry untouched and in order. Left in place,
# the names would make LSASS look for DLLs that are deleted at the reboot.
#
# Exit codes, read by the uninstaller:
#   10 = none of our names were listed
#   13 = some were listed and have been removed
#   11 = some are listed and could not be removed
#   12 = cannot run here (PowerShell not in FullLanguage mode)
#   anything else = PowerShell did not run the script

$ErrorActionPreference = 'Stop'

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Output "Cannot check the LSA package lists: PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode."
    exit 12
}

$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$ourNames = @('OpenAccessEIDPackage', 'EIDAuthenticationPackage', 'EIDPasswordChangeNotification')
$lists = @('Security Packages', 'Authentication Packages', 'Notification Packages')

try {
    $removed = $false
    $properties = Get-ItemProperty -LiteralPath $lsaKey
    foreach ($list in $lists) {
        $property = $properties.PSObject.Properties[$list]
        if ($null -eq $property -or $null -eq $property.Value) { continue }
        $before = @($property.Value)
        $after = @($before | Where-Object { $ourNames -notcontains $_ })
        if ($after.Count -eq $before.Count) { continue }
        # An empty list is stored the way Windows stores it: one empty string.
        if ($after.Count -eq 0) { $after = @('') }
        Set-ItemProperty -LiteralPath $lsaKey -Name $list -Value ([string[]] $after) -Type MultiString
        Write-Output "Removed OpenAccess EID entries from '$list'."
        $removed = $true
    }
    if ($removed) { exit 13 }
    Write-Output 'The LSA package lists hold no OpenAccess EID entries.'
    exit 10
} catch {
    Write-Output "Could not clean the LSA package lists: $($_.Exception.Message)"
    exit 11
}
