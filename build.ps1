<#
.SYNOPSIS
    Build OpenAccess EID Project

.DESCRIPTION
    This script builds all components of the OpenAccess EID system:
    - OpenAccessEIDPackage.dll (LSA authentication package)
    - EIDCredentialProvider.dll (Credential Provider v2)
    - EIDPasswordChangeNotification.dll (Password change notification)
    - EIDConfigurationWizard.exe (Configuration tool)
    - EIDCardLibrary (shared library)
    - EIDMigrate.exe (Credential migration CLI utility, x64 only)
    - EIDMigrateUI.exe (Credential migration GUI wizard, x64 only)
    - EIDManageUsers.exe (User account management tool, x64 only)
    - Installer (NSIS installer for Release builds)

.PARAMETER Configuration
    Build configuration: Debug or Release (default: Release)

.PARAMETER Platform
    Target platform: x64 (default: x64). This project is x64 only.

.EXAMPLE
    .\build.ps1
    Builds Release configuration for x64 platform

.EXAMPLE
    .\build.ps1 Debug x64
    Builds Debug configuration for x64 platform
#>

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Building OpenAccess EID" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Configuration: $Configuration" -ForegroundColor White
Write-Host "Platform: $Platform" -ForegroundColor White
Write-Host ""

# ---------------------------------------------------------------------------
# Bundled smart-card minidrivers  (Complete install type)
# ---------------------------------------------------------------------------
# These vendor packages are staged into Installer\drivers\ so the resulting
# NSIS installer is self-contained — no internet access required at install
# time. See Installer\drivers\README.md for the full rationale.
#
# The manifest (URL + SHA-256) and staging logic live in the shared script
# Installer\Stage-Minidrivers.ps1 - the single source of truth used both here
# and by the VirusTotal packaging workflow (.github/workflows/scan-artifacts.yml).
# To update a driver, edit the manifest in that script.
# ---------------------------------------------------------------------------
# Dot-sourced (not &) so the shared $BundledDrivers manifest is imported into
# this scope for the SHA-256 manifest step further below; the script also
# downloads/verifies the files as a side effect of being sourced.
. (Join-Path $PSScriptRoot 'Installer\Stage-Minidrivers.ps1')
$driversDir = Join-Path $PSScriptRoot 'Installer\drivers'

# Find Visual Studio 2022 installation
$devEnvPath = $null

# Try VSWhere first (Microsoft's official VS detection tool)
$vsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWherePath) {
    $vsPath = & $vsWherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vsPath) {
        $devEnvPath = Join-Path $vsPath "Common7\IDE\devenv.com"
    }
}

# Fallback to common paths if VSWhere fails
if (-not $devEnvPath) {
    $vsEditions = @("Community", "Professional", "Enterprise", "BuildTools")
    $vsBasePath = "C:\Program Files\Microsoft Visual Studio\2022"

    foreach ($edition in $vsEditions) {
        $testPath = Join-Path $vsBasePath "$edition\Common7\IDE\devenv.com"
        if (Test-Path $testPath) {
            $devEnvPath = $testPath
            break
        }
    }
}

if (-not $devEnvPath) {
    Write-Host "ERROR: Visual Studio 2022 not found" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please ensure Visual Studio 2022 is installed with:" -ForegroundColor Yellow
    Write-Host "  - Desktop development with C++" -ForegroundColor Yellow
    Write-Host "  - Windows SDK 10.0.22621.0 or later" -ForegroundColor Yellow
    Write-Host "  - Platform Toolset v143 (VS 2022 Build Tools)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Download from: https://visualstudio.microsoft.com/downloads/" -ForegroundColor Cyan
    exit 1
}

Write-Host "Found Visual Studio at: $devEnvPath" -ForegroundColor Gray

# Release builds compile with /Qspectre (SpectreMitigation in
# Directory.Build.props), which links against the Spectre-mitigated CRT.
# Without that VS component the failure is a cryptic MSB8040 mid-build, so
# check up front and explain the fix instead.
if ($Configuration -eq "Release") {
    # devenv.com lives at <vsRoot>\Common7\IDE\devenv.com
    $vsRoot = $devEnvPath | Split-Path -Parent | Split-Path -Parent | Split-Path -Parent
    $spectreLib = Get-ChildItem (Join-Path $vsRoot "VC\Tools\MSVC\*\lib\spectre\x64\libcmt.lib") -ErrorAction SilentlyContinue
    if (-not $spectreLib) {
        Write-Host "ERROR: Spectre-mitigated libraries not found" -ForegroundColor Red
        Write-Host ""
        Write-Host "Release builds require the VS component 'MSVC v143 - C++ x64/x86 Spectre-mitigated libs (Latest)'." -ForegroundColor Yellow
        Write-Host "Install it with either:" -ForegroundColor Yellow
        Write-Host "  - Visual Studio Installer > Modify > Individual components > search 'spectre'" -ForegroundColor Yellow
        Write-Host "  - Or run (elevated):" -ForegroundColor Yellow
        Write-Host "    & `"`${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\setup.exe`" modify ``" -ForegroundColor Cyan
        Write-Host "      --installPath `"$vsRoot`" ``" -ForegroundColor Cyan
        Write-Host "      --add Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre --passive --norestart" -ForegroundColor Cyan
        exit 1
    }
    Write-Host "Spectre-mitigated libs: $(Split-Path $spectreLib[0].FullName)" -ForegroundColor Gray
}

# Copy icons to project directories (if they exist)
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Processing Icons" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$iconsSourceDir = "icons"
$iconMappings = @(
    # Credential Provider Tile Image (BMP)
    @{ Source = "cred_tile_image.bmp"; Destination = "EIDCredentialProvider\SmartcardCredentialProvider.bmp" }
    # Configuration Wizard Icon
    @{ Source = "app_configuration_wizard.ico"; Destination = "EIDConfigurationWizard\app.ico" }
    # Migrate CLI Icon
    @{ Source = "app_migrate_cli.ico"; Destination = "EIDMigrate\app.ico" }
    # Migrate UI Icon
    @{ Source = "app_migrate_gui.ico"; Destination = "EIDMigrateUI\app.ico" }
    # Manage Users Icon
    @{ Source = "app_migrate_gui.ico"; Destination = "EIDManageUsers\app.ico" }
    # Trace Consumer Icon
    @{ Source = "app_trace_consumer.ico"; Destination = "EIDTraceConsumer\app.ico" }
    # Installer Icon
    @{ Source = "app_installer.ico"; Destination = "Installer\installer.ico" }
    # Credential Provider Icon (for DisplayIcon in installed programs)
    @{ Source = "cred_provider.ico"; Destination = "Installer\cred_provider.ico" }
)

$iconsCopied = 0
$iconsMissing = 0
$placeholdersUsed = 0

# Placeholder icon - use an existing committed icon as fallback
$placeholderIcon = "icons\app_installer.ico"
$placeholderExists = Test-Path $placeholderIcon

if (Test-Path $iconsSourceDir) {
    foreach ($mapping in $iconMappings) {
        $sourcePath = Join-Path $iconsSourceDir $mapping.Source
        $destPath = $mapping.Destination

        # Create destination directory if it doesn't exist
        $destDir = Split-Path $destPath -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        if (Test-Path $sourcePath) {
            # Copy custom icon (overwrite existing)
            Copy-Item -Path $sourcePath -Destination $destPath -Force
            Write-Host "  Copied: $($mapping.Source) -> $destPath" -ForegroundColor Green
            $iconsCopied++
        } elseif ($placeholderExists -and ($mapping.Destination -notlike "*SmartcardCredentialProvider.bmp")) {
            # Use placeholder icon for .ico files (not for credential provider BMP)
            # Skip if destination is the same as placeholder (avoid self-copy)
            if ($destPath -ne $placeholderIcon) {
                Copy-Item -Path $placeholderIcon -Destination $destPath -Force
                Write-Host "  Placeholder: $placeholderIcon -> $destPath" -ForegroundColor DarkGray
                $placeholdersUsed++
            } else {
                Write-Host "  Skipped: $($mapping.Source) (original exists)" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "  Skipped: $($mapping.Source) (not found, no placeholder available)" -ForegroundColor DarkGray
            $iconsMissing++
        }
    }
} else {
    Write-Host "  Icons directory not found - using placeholder icons" -ForegroundColor Yellow
    # Use placeholder for all when icons/ directory doesn't exist
    foreach ($mapping in $iconMappings) {
        $destPath = $mapping.Destination
        $destDir = Split-Path $destPath -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        if ($placeholderExists -and ($mapping.Destination -notlike "*SmartcardCredentialProvider.bmp") -and ($destPath -ne $placeholderIcon)) {
            Copy-Item -Path $placeholderIcon -Destination $destPath -Force
            $placeholdersUsed++
        }
    }
    $iconsMissing = $iconMappings.Count - $placeholdersUsed
}

if ($iconsCopied -gt 0) {
    Write-Host ""
    Write-Host "Custom icons copied: $iconsCopied" -ForegroundColor Green
}
if ($placeholdersUsed -gt 0) {
    Write-Host "Placeholder icons used: $placeholdersUsed (default icons)" -ForegroundColor DarkGray
}
if ($iconsMissing -gt 0) {
    Write-Host "Icons missing: $iconsMissing" -ForegroundColor Yellow
}

# Clean previous build artifacts
Write-Host ""
Write-Host "Cleaning previous build..." -ForegroundColor Yellow
$buildDir = "x64\$Configuration"
if (Test-Path $buildDir) {
    Remove-Item -Path $buildDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Build the solution
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Building solution: OpenAccessEID.sln" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Build output will be logged to build.log" -ForegroundColor White

$buildArgs = @(
    "OpenAccessEID.sln",
    "/Rebuild",
    "$Configuration|$Platform"
)

& $devEnvPath @buildArgs 2>&1 | Tee-Object -FilePath "build.log"

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "BUILD FAILED with error code $LASTEXITCODE" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Check the output above for detailed error information" -ForegroundColor Yellow
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "BUILD SUCCEEDED" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output files in ${buildDir}:" -ForegroundColor White

$outputFiles = Get-ChildItem -Path $buildDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.dll', '.exe' }
$outputFiles | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor White }

# Display file sizes for verification
Write-Host ""
Write-Host "File sizes:" -ForegroundColor White
$outputFiles | ForEach-Object {
    $color = "Gray"
    if ($_.Name -eq "EIDMigrate.exe") { $color = "Cyan" }
    if ($_.Name -eq "EIDMigrateUI.exe") { $color = "Cyan" }
    if ($_.Name -eq "EIDManageUsers.exe") { $color = "Cyan" }
    Write-Host "  $($_.Name) - $($_.Length) bytes" -ForegroundColor $color
}

# Note about EIDMigrate tools
Write-Host ""
Write-Host "NOTE: EIDMigrate.exe is a CLI credential migration utility (x64 only)." -ForegroundColor Cyan
Write-Host "      EIDMigrateUI.exe is a GUI wizard for credential migration (x64 only)." -ForegroundColor Cyan
Write-Host "      EIDManageUsers.exe is a user account management tool (x64 only)." -ForegroundColor Cyan
Write-Host "      Use with caution in production environments." -ForegroundColor Yellow

# Build installer (Release only)
if ($Configuration -eq "Release") {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Building NSIS Installer" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    # Find NSIS installation - check multiple common paths
    $makensisPath = $null
    $nsisSearchPaths = @(
        "C:\Program Files (x86)\NSIS\makensis.exe",
        "C:\Program Files\NSIS\makensis.exe",
        "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
        "${env:ProgramFiles}\NSIS\makensis.exe",
        "C:\NSIS\makensis.exe",
        "${env:ProgramFiles}\Nsis\makensis.exe"
    )

    foreach ($path in $nsisSearchPaths) {
        if (Test-Path $path) {
            $makensisPath = $path
            Write-Host "Found NSIS at: $makensisPath" -ForegroundColor Gray
            break
        }
    }

    # Also check if makensis is in PATH
    if (-not $makensisPath) {
        $makensisInPath = Get-Command "makensis.exe" -ErrorAction SilentlyContinue
        if ($makensisInPath) {
            $makensisPath = $makensisInPath.Source
            Write-Host "Found NSIS in PATH: $makensisPath" -ForegroundColor Gray
        }
    }

    if ($makensisPath) {
        # NSIS 3.08 and earlier let Everyone delete and re-create the
        # installer's plugins folder ($PLUGINSDIR, CVE-2023-37378). A
        # SYSTEM-context deployment puts that folder in C:\Windows\Temp, so a
        # standard user could swap the DLLs the installer loads as SYSTEM.
        # Installerx64.nsi refuses such a compiler as well; checking here
        # gives a plain message. CI pins 3.13.0.
        $nsisMinimum = [version]'3.9'
        $nsisVersionText = (& $makensisPath /VERSION | Out-String).Trim()
        $nsisVersion = $null
        if ($nsisVersionText -match '^v?(\d+)\.(\d+)') {
            $nsisVersion = [version]"$([int]$Matches[1]).$([int]$Matches[2])"
        }
        if ($null -eq $nsisVersion -or $nsisVersion -lt $nsisMinimum) {
            Write-Host ""
            Write-Host "============================================================" -ForegroundColor Red
            Write-Host "INSTALLER BUILD FAILED: NSIS 3.09 or later is required" -ForegroundColor Red
            Write-Host "============================================================" -ForegroundColor Red
            Write-Host "$makensisPath reports version '$nsisVersionText'." -ForegroundColor Yellow
            Write-Host "NSIS 3.08 and earlier let a standard user take over the installer's plugins folder when it runs as SYSTEM (CVE-2023-37378)." -ForegroundColor Yellow
            Write-Host "Install a current NSIS (CI uses 3.13.0): choco install nsis --version 3.13.0 -y" -ForegroundColor Cyan
            exit 1
        }
        Write-Host "NSIS version: $nsisVersionText" -ForegroundColor Gray

        # Delete old installer
        $installerPath = "Installer\EIDInstallx64.exe"
        if (Test-Path $installerPath) {
            Remove-Item -Path $installerPath -Force
        }

        # Handle installer icon - check if it exists after copying
        $nsiFile = "Installer\Installerx64.nsi"
        $nsiBackup = $null
        $installerIconExists = Test-Path "Installer\installer.ico"

        if (-not $installerIconExists) {
            Write-Host "  Note: installer.ico not found - using NSIS default icon" -ForegroundColor DarkGray
            # Temporarily comment out Icon directives in NSI file
            $nsiContent = Get-Content $nsiFile -Raw
            $nsiBackup = $nsiContent
            $nsiContentModified = $nsiContent -replace '(^\s*Icon\s+")', '#$1'
            $nsiContentModified = $nsiContentModified -replace '(^\s*UninstallIcon\s+")', '#$1'
            Set-Content -Path $nsiFile -Value $nsiContentModified -NoNewline
        }

        Push-Location "Installer"
        try {
            # Run NSIS and capture output
            $nsisOutput = & $makensisPath "Installerx64.nsi" 2>&1
            $nsisExitCode = $LASTEXITCODE

            # Display NSIS output
            $nsisOutput | ForEach-Object { Write-Host $_ }

            if ($nsisExitCode -ne 0) {
                Write-Host ""
                Write-Host "============================================================" -ForegroundColor Red
                Write-Host "INSTALLER BUILD FAILED with exit code $nsisExitCode" -ForegroundColor Red
                Write-Host "============================================================" -ForegroundColor Red
                Write-Host "Check the NSIS output above for errors" -ForegroundColor Yellow
                # Restore NSI file before exiting
                if ($null -ne $nsiBackup) {
                    Set-Content -Path $nsiFile -Value $nsiBackup -NoNewline
                }
                Pop-Location
                exit 1
            }
        }
        catch {
            Write-Host ""
            Write-Host "============================================================" -ForegroundColor Red
            Write-Host "INSTALLER BUILD FAILED" -ForegroundColor Red
            Write-Host "============================================================" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
            # Restore NSI file before exiting
            if ($null -ne $nsiBackup) {
                Set-Content -Path $nsiFile -Value $nsiBackup -NoNewline
            }
            Pop-Location
            exit 1
        }
        finally {
            Pop-Location
            # Restore NSI file if it was modified
            if ($null -ne $nsiBackup) {
                Set-Content -Path $nsiFile -Value $nsiBackup -NoNewline
            }
        }

        if (Test-Path $installerPath) {
            $installerFile = Get-Item $installerPath
            Write-Host ""
            Write-Host "============================================================" -ForegroundColor Green
            Write-Host "INSTALLER BUILD SUCCEEDED" -ForegroundColor Green
            Write-Host "============================================================" -ForegroundColor Green
            Write-Host "Output: $installerPath" -ForegroundColor White
            $sizeKB = [math]::Round($installerFile.Length / 1KB, 1)
            $sizeMB = [math]::Round($installerFile.Length / 1MB, 2)
            Write-Host "Size: $sizeMB MB ($sizeKB KB)" -ForegroundColor White
            Write-Host ""
            Write-Host "Installer includes:" -ForegroundColor White
            Write-Host "  - LSA Authentication Package" -ForegroundColor Gray
            Write-Host "  - Credential Provider v2" -ForegroundColor Gray
            Write-Host "  - Password Change Notification" -ForegroundColor Gray
            Write-Host "  - Configuration Wizard" -ForegroundColor Gray
            Write-Host "  - EIDMigrate.exe (CLI credential migration utility)" -ForegroundColor Gray
            Write-Host "  - EIDMigrateUI.exe (GUI credential migration wizard)" -ForegroundColor Gray
            Write-Host "  - EIDManageUsers.exe (User account management tool)" -ForegroundColor Gray
            Write-Host "  - Start Menu folder with all application shortcuts" -ForegroundColor Gray
            Write-Host "  - Certificate cleanup script (CleanupCertificates.ps1)" -ForegroundColor Gray
            Write-Host "  - Uninstaller with certificate removal" -ForegroundColor Gray
            Write-Host ""
        } else {
            Write-Host ""
            Write-Host "============================================================" -ForegroundColor Red
            Write-Host "INSTALLER BUILD FAILED" -ForegroundColor Red
            Write-Host "============================================================" -ForegroundColor Red
            Write-Host "Installer file was not created" -ForegroundColor Yellow
            Write-Host "Check Installer\Installerx64.nsi for errors" -ForegroundColor Yellow
            exit 1
        }
    } else {
        Write-Host ""
        Write-Host "WARNING: NSIS not found in common locations or PATH" -ForegroundColor Yellow
        Write-Host "Skipping installer build" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To build the installer, install NSIS from https://nsis.sourceforge.io/" -ForegroundColor Cyan
        Write-Host "Make sure NSIS is added to PATH during installation" -ForegroundColor Cyan
    }
}

# ---------------------------------------------------------------------------
# SHA-256 manifest for release artifacts  (supply-chain / SBOM helper)
# ---------------------------------------------------------------------------
# Writes Installer\SHA256SUMS.txt listing the installer + every .dll / .exe
# shipped in x64\$Configuration\. Downstream consumers (and anyone receiving
# the release over offline media) can verify integrity with:
#     certutil -hashfile <file> SHA256
# or, on Linux/macOS:
#     sha256sum -c SHA256SUMS.txt
# ---------------------------------------------------------------------------
if ($Configuration -eq "Release") {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Generating SHA-256 manifest" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $manifestPath = Join-Path $PSScriptRoot 'Installer\SHA256SUMS.txt'
    $lines = @()
    $lines += "# OpenAccess EID - SHA-256 manifest"
    $lines += ("# Generated: {0}  (UTC)" -f ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')))
    $lines += ("# Configuration: {0}   Platform: {1}" -f $Configuration, $Platform)
    $lines += "# Format: <sha256>  <relative-path>"
    $lines += ""

    $targets = @()
    $installerExe = Join-Path $PSScriptRoot 'Installer\EIDInstallx64.exe'
    if (Test-Path $installerExe) { $targets += $installerExe }

    $buildOutDir = Join-Path $PSScriptRoot "$Platform\$Configuration"
    if (Test-Path $buildOutDir) {
        $targets += Get-ChildItem -Path $buildOutDir -File -Recurse |
                    Where-Object { $_.Extension -in '.dll', '.exe' } |
                    Select-Object -ExpandProperty FullName
    }

    foreach ($d in $BundledDrivers) {
        $bundled = Join-Path $driversDir $d.File
        if (Test-Path $bundled) { $targets += $bundled }
    }

    $policyDir = Join-Path $PSScriptRoot 'Installer\PolicyDefinitions'
    if (Test-Path $policyDir) {
        $targets += Get-ChildItem -Path $policyDir -File -Recurse |
                    Where-Object { $_.Extension -in '.admx', '.adml' } |
                    Select-Object -ExpandProperty FullName
    }

    $rootPrefix = $PSScriptRoot.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    foreach ($t in ($targets | Sort-Object)) {
        $hash = (Get-FileHash -Path $t -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($t.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $rel = $t.Substring($rootPrefix.Length)
        } else {
            $rel = $t
        }
        $lines += ("{0}  {1}" -f $hash, $rel)
        Write-Host ("  {0}  {1}" -f $hash.Substring(0, 12), $rel) -ForegroundColor Gray
    }

    Set-Content -Path $manifestPath -Value $lines -Encoding UTF8
    Write-Host ""
    Write-Host ("Manifest written: {0}  ({1} entries)" -f $manifestPath, ($targets.Count)) -ForegroundColor Green
    Write-Host ""

    # ------------------------------------------------------------------
    # Optional: generate CycloneDX SBOM if Microsoft.Sbom.Tool is present
    # ------------------------------------------------------------------
    $sbomTool = Get-Command sbom-tool.exe -ErrorAction SilentlyContinue
    if (-not $sbomTool) {
        Write-Host "sbom-tool not found on PATH - skipping SBOM generation." -ForegroundColor DarkGray
        Write-Host "  Install with: dotnet tool install --global Microsoft.Sbom.DotNetTool" -ForegroundColor DarkGray
        Write-Host ""
    } else {
        Write-Host "Generating SPDX SBOM via sbom-tool..." -ForegroundColor Cyan
        $sbomOut = Join-Path $PSScriptRoot 'Installer\sbom'
        if (Test-Path $sbomOut) { Remove-Item -Recurse -Force $sbomOut }
        New-Item -ItemType Directory -Path $sbomOut -Force | Out-Null
        & $sbomTool.Source generate `
            -b $buildOutDir `
            -bc $PSScriptRoot `
            -pn 'OpenAccessEID' `
            -pv '1.0.0' `
            -ps 'OpenAccess EID Contributors' `
            -nsb 'https://github.com/SP00KY-CB/OpenAccessEID' `
            -m $sbomOut 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
        if ($LASTEXITCODE -eq 0) {
            Write-Host ("SBOM written under: {0}" -f $sbomOut) -ForegroundColor Green
        } else {
            Write-Host ("sbom-tool exited with code {0} - SBOM may be incomplete" -f $LASTEXITCODE) -ForegroundColor Yellow
        }
        Write-Host ""
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Build Complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Configuration: $Configuration" -ForegroundColor White
Write-Host "Platform: $Platform" -ForegroundColor White
Write-Host "All components built successfully" -ForegroundColor Green
Write-Host ""
