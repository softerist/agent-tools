<#
.SYNOPSIS
    Adds Unix-compatible tools (grep, sed, awk, etc.) to the Windows system PATH.

.DESCRIPTION
    Discovers Git-for-Windows and exposes its bundled Unix tools on Windows.
    Optionally creates priority .cmd shims, installs PowerShell profile
    fallback functions for missing commands, and provides alias-compat
    wrappers (rm, cp, mv, ls, cat, etc.) that accept common Unix flags.

    Default mode writes to Machine scope and requires elevation.
    Use -UserScope for per-user installs without elevation.

.PARAMETER CreateShims
    Generate .cmd shim files and prepend shim directory to PATH scope.
    Machine scope uses Git\shims; User scope uses LocalAppData\UnixTools\shims.

.PARAMETER AddMingw
    Also add Git's mingw64\bin to selected PATH scope.

.PARAMETER AddGitCmd
    Also add Git's cmd directory to selected PATH scope.

.PARAMETER NormalizePath
    Remove duplicate and trailing-backslash entries from selected PATH scope.

.PARAMETER InstallProfileShims
    Install PowerShell profile blocks for missing-command shims and
    alias-compat wrappers (rm, cp, mv, ls, cat, sort, diff, tee, sleep).

.PARAMETER InstallOptionalTools
    Install missing optional CLI tools (rg, fd, jq, yq, bat, eza, fzf, ag, ack, ncat)
    using winget/choco/scoop when available.

.PARAMETER InstallFull
    Run the full setup in one command:
    -AddMingw -AddGitCmd -NormalizePath -InstallOptionalTools
    -CreateShims -InstallProfileShims

.PARAMETER UserScope
    Use user-level installation mode:
    - No admin required
    - PATH changes are written to User scope
    - Shim directory is stored under LocalAppData

.PARAMETER Uninstall
    Remove shim directory, PATH entries, profile blocks, and optional tools
    previously installed by this script.

.PARAMETER LogPath
    Path to a transcript log file for this run.

.PARAMETER Help
    Show this help message and exit (works without elevation).

.EXAMPLE
    .\Enable-UnixToolsSystemWide.ps1
    Adds Git usr\bin to Machine PATH (default scope).

.EXAMPLE
    .\Enable-UnixToolsSystemWide.ps1 -CreateShims
    Creates priority shims and prepends shim dir to PATH.

.EXAMPLE
    .\Enable-UnixToolsSystemWide.ps1 -CreateShims -InstallProfileShims
    Full setup: shims + profile fallback functions + alias-compat wrappers.

.EXAMPLE
    .\Enable-UnixToolsSystemWide.ps1 -CreateShims -InstallOptionalTools
    Installs missing optional tools first, then creates shims.

.EXAMPLE
    .\Enable-UnixToolsSystemWide.ps1 -InstallFull
    Runs full setup (PATH + optional tools + shims + profile wrappers).

.EXAMPLE
    .\Enable-UnixToolsSystemWide.ps1 -InstallFull -UserScope
    Runs full setup in user scope without admin requirements.

.EXAMPLE
    .\Enable-UnixToolsSystemWide.ps1 -Uninstall
    Removes all shims, PATH entries, and profile blocks.

.EXAMPLE
    .\Enable-UnixToolsSystemWide.ps1 -Help
    Shows usage without requiring Administrator elevation.
#>
# Enable-UnixToolsSystemWide.ps1
# Adds Unix-compatible tools (grep, sed, awk, etc.) to the system PATH
# Run in an elevated PowerShell for Machine scope.
# Use -UserScope for per-user installation without elevation.
#
# Usage:
#   .\Enable-UnixToolsSystemWide.ps1
#   .\Enable-UnixToolsSystemWide.ps1 -CreateShims
#   .\Enable-UnixToolsSystemWide.ps1 -AddMingw -AddGitCmd
#   .\Enable-UnixToolsSystemWide.ps1 -CreateShims -AddMingw -AddGitCmd
#   .\Enable-UnixToolsSystemWide.ps1 -NormalizePath
#   .\Enable-UnixToolsSystemWide.ps1 -InstallProfileShims
#   .\Enable-UnixToolsSystemWide.ps1 -CreateShims -InstallProfileShims
#   .\Enable-UnixToolsSystemWide.ps1 -InstallOptionalTools
#   .\Enable-UnixToolsSystemWide.ps1 -CreateShims -InstallOptionalTools
#   .\Enable-UnixToolsSystemWide.ps1 -InstallFull
#   .\Enable-UnixToolsSystemWide.ps1 -InstallFull -UserScope
#   .\Enable-UnixToolsSystemWide.ps1 -InstallProfileShims -LogPath C:\Temp\unix-tools-install.log
#   .\Enable-UnixToolsSystemWide.ps1 -Uninstall

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$CreateShims,
    [switch]$AddMingw,
    [switch]$AddGitCmd,
    [switch]$NormalizePath,
    [switch]$InstallProfileShims,
    [switch]$InstallOptionalTools,
    [switch]$InstallFull,
    [switch]$UserScope,
    [switch]$Uninstall,
    [string]$LogPath,
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ScriptVersion = "2.1.0"
$script:PathScope = if ($UserScope) { "User" } else { "Machine" }
$script:PathDisplay = "$($script:PathScope) PATH"

# ======================== Functions ========================

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if ($script:PathScope -eq "User") {
        if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warning "Running in UserScope mode (admin not required)."
        }
        return
    }
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run PowerShell as Administrator, or use -UserScope."
    }
}

function Get-GitRoot {
    $candidates = @(
        "C:\Program Files\Git",
        "C:\Program Files (x86)\Git"
    ) | Where-Object { Test-Path $_ }

    foreach ($c in $candidates) { return $c }

    $regKeys = @(
        "HKLM:\SOFTWARE\GitForWindows",
        "HKLM:\SOFTWARE\WOW6432Node\GitForWindows"
    )
    foreach ($k in $regKeys) {
        if (Test-Path $k) {
            $p = (Get-ItemProperty $k -ErrorAction SilentlyContinue).InstallPath
            if ($p -and (Test-Path $p)) { return $p }
        }
    }

    throw "Could not find Git installation. Install Git for Windows (winget install --id Git.Git -e) and re-run."
}

function Assert-PathLength([string]$PathValue, [string]$Scope = "Machine") {
    if ([string]::IsNullOrWhiteSpace($PathValue)) { return }

    $len = $PathValue.Length
    if ($len -ge 32760) {
        throw "$Scope PATH length ($len) is too close to the Windows environment variable limit."
    }
    if ($len -ge 2048) {
        Write-Warning "$Scope PATH length is $len characters (legacy tools may fail around 2048)."
    }
}

function Add-MachinePathPrepend([string]$pathToPrepend) {
    $scope = $script:PathScope
    $norm = $pathToPrepend.Trim().TrimEnd('\')
    if (-not (Test-Path $norm)) {
        throw "Path does not exist: $norm"
    }

    $current = [Environment]::GetEnvironmentVariable("Path", $scope)
    if (-not $current) { $current = "" }

    $parts = $current.Split(';') | Where-Object { $_ -and $_.Trim() -ne "" }

    # Remove existing entry (case-insensitive)
    $parts = $parts | Where-Object {
        -not $_.Trim().TrimEnd('\').Equals($norm, [StringComparison]::OrdinalIgnoreCase)
    }

    $newPath = (@($norm) + $parts) -join ';'
    Assert-PathLength -PathValue $newPath -Scope $scope
    [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
}

function Add-MachinePathEntries([string[]]$pathsToAdd) {
    $scope = $script:PathScope
    $current = [Environment]::GetEnvironmentVariable("Path", $scope)
    if (-not $current) { $current = "" }

    $parts = $current.Split(';') | Where-Object { $_ -and $_.Trim() -ne "" }
    $set = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)

    foreach ($p in $parts) { [void]$set.Add($p.Trim().TrimEnd('\')) }

    $changed = $false
    foreach ($p in $pathsToAdd) {
        $norm = $p.Trim().TrimEnd('\')
        if (Test-Path $norm) {
            if (-not $set.Contains($norm)) {
                $parts += $norm
                [void]$set.Add($norm)
                $changed = $true
            }
        }
    }

    if ($changed) {
        $newPath = $parts -join ';'
        Assert-PathLength -PathValue $newPath -Scope $scope
        [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
    }

    return $changed
}

function Remove-MachinePathEntries([string[]]$pathsToRemove) {
    $scope = $script:PathScope
    $current = [Environment]::GetEnvironmentVariable("Path", $scope)
    if (-not $current) { return $false }

    $parts = $current.Split(';') | Where-Object { $_ -and $_.Trim() -ne "" }
    $removeSet = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $pathsToRemove) {
        if (-not [string]::IsNullOrWhiteSpace($p)) {
            [void]$removeSet.Add($p.Trim().TrimEnd('\'))
        }
    }

    $newParts = @()
    foreach ($p in $parts) {
        $norm = $p.Trim().TrimEnd('\')
        if (-not $removeSet.Contains($norm)) { $newParts += $norm }
    }

    if (($newParts -join ';') -eq ($parts -join ';')) { return $false }
    $newPath = $newParts -join ';'
    Assert-PathLength -PathValue $newPath -Scope $scope
    [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
    return $true
}

function Update-MachinePathEntries {
    $scope = $script:PathScope
    $current = [Environment]::GetEnvironmentVariable("Path", $scope)
    if (-not $current) { return }

    $parts = $current.Split(';') | Where-Object { $_ -and $_.Trim() -ne "" }

    $seen = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    $newParts = New-Object System.Collections.Generic.List[string]

    foreach ($p in $parts) {
        $n = $p.Trim().TrimEnd('\')
        if ($n -and $seen.Add($n)) { $newParts.Add($n) }
    }

    $newPath = $newParts -join ';'
    Assert-PathLength -PathValue $newPath -Scope $scope
    [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
}

function New-DirectoryIfMissing([string]$dir) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}

function Write-ShimCmd([string]$shimDir, [string]$name, [string]$targetExePath) {
    if (-not (Test-Path $targetExePath)) { return $false }

    $shimPath = Join-Path $shimDir "$name.cmd"
    $safeTarget = $targetExePath -replace '%', '%%'
    $content = @(
        "@echo off"
        "setlocal"
        "set ""_unix_tool=$safeTarget"""
        """%_unix_tool%"" %*"
    ) -join "`r`n"
    Set-Content -Path $shimPath -Value $content -Encoding ASCII
    return $true
}

function Find-Tool([string]$toolName, [string[]]$searchDirs) {
    foreach ($dir in $searchDirs) {
        $exePath = Join-Path $dir "$toolName.exe"
        if (Test-Path $exePath) { return $exePath }
    }
    return $null
}

function Find-ToolInPath([string]$toolName, [string]$excludeDir = $null, [hashtable]$AppIndex = $null) {
    if ($AppIndex -and $AppIndex.ContainsKey($toolName)) {
        return $AppIndex[$toolName]
    }

    # Search system PATH for a real executable (useful for ripgrep and non-Git tools).
    try {
        $apps = Get-Command $toolName -CommandType Application -All -ErrorAction SilentlyContinue
        if (-not $apps) { return $null }

        foreach ($app in $apps) {
            $src = $app.Source
            if (-not $src) { continue }
            if ([System.IO.Path]::GetExtension($src) -ne ".exe") { continue }
            if ($excludeDir) {
                $normExclude = $excludeDir.Trim().TrimEnd('\')
                if ($src.StartsWith($normExclude, [StringComparison]::OrdinalIgnoreCase)) { continue }
            }
            return $src
        }
    } catch {}
    return $null
}

function Get-ApplicationCommandIndex([string]$excludeDir = $null) {
    $index = @{}
    try {
        $apps = Get-Command -CommandType Application -All -ErrorAction SilentlyContinue
        foreach ($app in $apps) {
            $name = [System.IO.Path]::GetFileNameWithoutExtension($app.Name)
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            if ($index.ContainsKey($name)) { continue }

            $src = $app.Source
            if ([string]::IsNullOrWhiteSpace($src)) { continue }
            if ([System.IO.Path]::GetExtension($src) -ne ".exe") { continue }

            if ($excludeDir) {
                $normExclude = $excludeDir.Trim().TrimEnd('\')
                if ($src.StartsWith($normExclude, [StringComparison]::OrdinalIgnoreCase)) { continue }
            }
            $index[$name] = $src
        }
    } catch {}
    return $index
}

function Get-OptionalToolCatalog {
    return @(
        [pscustomobject]@{ Command = "rg";  WingetId = "BurntSushi.ripgrep.MSVC"; ChocoId = "ripgrep"; ScoopId = "ripgrep" },
        [pscustomobject]@{ Command = "fd";  WingetId = "sharkdp.fd";               ChocoId = "fd";      ScoopId = "fd"      },
        [pscustomobject]@{ Command = "jq";  WingetId = "jqlang.jq";                ChocoId = "jq";      ScoopId = "jq"      },
        [pscustomobject]@{ Command = "yq";  WingetId = "MikeFarah.yq";             ChocoId = "yq";      ScoopId = "yq"      },
        [pscustomobject]@{ Command = "bat"; WingetId = "sharkdp.bat";              ChocoId = "bat";     ScoopId = "bat"     },
        [pscustomobject]@{ Command = "eza"; WingetId = "eza-community.eza";        ChocoId = "eza";     ScoopId = "eza"     },
        [pscustomobject]@{ Command = "fzf"; WingetId = "junegunn.fzf";             ChocoId = "fzf";     ScoopId = "fzf"     },
        [pscustomobject]@{ Command = "ag";  WingetId = "JFLarvoire.Ag";            ChocoId = "ag";      ScoopId = "ag"      },
        [pscustomobject]@{ Command = "ack"; WingetId = $null;                      ChocoId = $null;     ScoopId = "ack"     },
        [pscustomobject]@{ Command = "ncat";WingetId = "Insecure.Nmap";            ChocoId = "nmap";    ScoopId = "nmap"    }
    )
}

function Ensure-OptionalPackageManagers {
    $wingetAvailable = [bool](Get-Command winget -ErrorAction SilentlyContinue)
    $scoopAvailable  = [bool](Get-Command scoop  -ErrorAction SilentlyContinue)
    $chocoAvailable  = [bool](Get-Command choco  -ErrorAction SilentlyContinue)

    if (-not $scoopAvailable) {
        Write-Host "  [INFO] scoop not found. Attempting scoop bootstrap..." -ForegroundColor DarkGray
        $scoopScriptUrls = @(
            "https://raw.githubusercontent.com/scoopinstaller/install/master/install.ps1",
            "https://get.scoop.sh"
        )
        try {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  [INFO] Could not set execution policy for CurrentUser: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
        foreach ($url in $scoopScriptUrls) {
            if ($scoopAvailable) { break }
            try {
                Write-Host "  [INFO] Running scoop bootstrap from: $url" -ForegroundColor DarkGray
                Invoke-RestMethod -Uri $url | Invoke-Expression
            } catch {
                Write-Host "  [INFO] scoop bootstrap attempt failed ($url): $($_.Exception.Message)" -ForegroundColor DarkGray
            }
            $scoopAvailable = [bool](Get-Command scoop -ErrorAction SilentlyContinue)
        }
        if ($scoopAvailable) {
            Write-Host "  [OK] scoop installed." -ForegroundColor Green
        } else {
            Write-Host "  [INFO] scoop bootstrap failed from all configured URLs." -ForegroundColor DarkGray
        }
    }

    if (-not $wingetAvailable) {
        Write-Host "  [INFO] winget not found. Attempting winget recovery..." -ForegroundColor DarkGray
        try {
            if (Get-Command Add-AppxPackage -ErrorAction SilentlyContinue) {
                Add-AppxPackage -RegisterByFamilyName -MainPackage "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe" -ErrorAction Stop | Out-Null
            }
        } catch {
            Write-Host "  [INFO] winget App Installer recovery failed: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
        $wingetAvailable = [bool](Get-Command winget -ErrorAction SilentlyContinue)
        if (-not $wingetAvailable -and $scoopAvailable) {
            try {
                Write-Host "  [INFO] Attempting winget install via scoop..." -ForegroundColor DarkGray
                & scoop install winget
            } catch {
                Write-Host "  [INFO] winget install via scoop failed: $($_.Exception.Message)" -ForegroundColor DarkGray
            }
            $wingetAvailable = [bool](Get-Command winget -ErrorAction SilentlyContinue)
        }
        if ($wingetAvailable) {
            Write-Host "  [OK] winget available." -ForegroundColor Green
        }
    }

    return [pscustomobject]@{
        Winget = $wingetAvailable
        Scoop  = $scoopAvailable
        Choco  = $chocoAvailable
    }
}

function Get-OptionalToolsStatePath {
    $base = if ($script:PathScope -eq "User") {
        if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
    } else {
        $env:ProgramData
    }
    $stateDir = Join-Path $base "UnixToolsSystemWide"
    return Join-Path $stateDir "optional-tools-installed.json"
}

function Read-OptionalToolState {
    $statePath = Get-OptionalToolsStatePath
    if (-not (Test-Path $statePath)) { return @() }

    try {
        $raw = Get-Content -Path $statePath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $data = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
        return @($data)
    } catch {
        return @()
    }
}

function Write-OptionalToolState([object[]]$Records) {
    $statePath = Get-OptionalToolsStatePath
    $stateDir = Split-Path -Parent $statePath
    if ($stateDir -and -not (Test-Path $stateDir)) {
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    }

    if (-not $Records -or $Records.Count -eq 0) {
        if (Test-Path $statePath) {
            Remove-Item -Path $statePath -Force -ErrorAction SilentlyContinue
        }
        return
    }

    $json = $Records | ConvertTo-Json -Depth 6
    Set-Content -Path $statePath -Value $json -Encoding UTF8
}

function Install-MissingOptionalTools([object[]]$Catalog) {
    if (-not $Catalog -or $Catalog.Count -eq 0) { return @() }

    $pm = Ensure-OptionalPackageManagers
    $wingetAvailable = [bool]$pm.Winget
    $chocoAvailable  = [bool]$pm.Choco
    $scoopAvailable  = [bool]$pm.Scoop
    $newlyInstalled = @()

    foreach ($tool in $Catalog) {
        $commandName = [string]$tool.Command
        if ([string]::IsNullOrWhiteSpace($commandName)) { continue }

        if (Get-Command $commandName -ErrorAction SilentlyContinue) {
            Write-Host "  [OK] Optional tool already installed: $commandName" -ForegroundColor Green
            continue
        }

        $installed = $false
        $attempted = @()
        $managerUsed = $null
        $packageIdUsed = $null

        if ($wingetAvailable -and $tool.WingetId) {
            $attempted += "winget"
            Write-Host "  [INFO] Installing $commandName via winget ($($tool.WingetId))..." -ForegroundColor DarkGray
            & winget install --id $tool.WingetId --exact --source winget --accept-package-agreements --accept-source-agreements
            if ($LASTEXITCODE -eq 0) {
                $installed = $true
                $managerUsed = "winget"
                $packageIdUsed = [string]$tool.WingetId
            }
        }

        if (-not $installed -and $scoopAvailable -and $tool.ScoopId) {
            $attempted += "scoop"
            Write-Host "  [INFO] Installing $commandName via scoop ($($tool.ScoopId))..." -ForegroundColor DarkGray
            & scoop install $tool.ScoopId
            if ($LASTEXITCODE -eq 0) {
                $installed = $true
                $managerUsed = "scoop"
                $packageIdUsed = [string]$tool.ScoopId
            }
        }

        if (-not $installed -and $chocoAvailable -and $tool.ChocoId) {
            $attempted += "choco"
            Write-Host "  [INFO] Installing $commandName via choco ($($tool.ChocoId))..." -ForegroundColor DarkGray
            & choco install $tool.ChocoId -y
            if ($LASTEXITCODE -eq 0) {
                $installed = $true
                $managerUsed = "choco"
                $packageIdUsed = [string]$tool.ChocoId
            }
        }

        if ($installed) {
            $newlyInstalled += [pscustomobject]@{
                Command    = $commandName
                Manager    = $managerUsed
                PackageId  = $packageIdUsed
                InstalledAt = (Get-Date).ToString("o")
            }
            Write-Host "  [OK] Installed optional tool: $commandName" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] Optional tool not installed: $commandName" -ForegroundColor DarkGray
            if ($attempted.Count -gt 0) {
                Write-Host "       Attempted via: $($attempted -join ', ')" -ForegroundColor DarkGray
            } else {
                Write-Host "       No supported package manager detected (winget/choco/scoop)." -ForegroundColor DarkGray
            }
        }
    }

    if ($newlyInstalled.Count -gt 0) {
        $existing = @(Read-OptionalToolState)
        $byCommand = @{}
        foreach ($item in $existing) {
            $cmd = [string]$item.Command
            if (-not [string]::IsNullOrWhiteSpace($cmd)) { $byCommand[$cmd] = $item }
        }
        foreach ($item in $newlyInstalled) {
            $cmd = [string]$item.Command
            if (-not [string]::IsNullOrWhiteSpace($cmd)) { $byCommand[$cmd] = $item }
        }
        $merged = @($byCommand.Values | Sort-Object Command)
        Write-OptionalToolState -Records $merged
        Refresh-SessionPath
    }
    return $newlyInstalled
}

function Uninstall-TrackedOptionalTools {
    $tracked = @(Read-OptionalToolState)
    if ($tracked.Count -eq 0) { return 0 }

    $removedCount = 0
    $remaining = @()
    foreach ($item in $tracked) {
        $commandName = [string]$item.Command
        $manager = [string]$item.Manager
        $packageId = [string]$item.PackageId

        if ([string]::IsNullOrWhiteSpace($manager) -or [string]::IsNullOrWhiteSpace($packageId)) {
            $remaining += $item
            continue
        }

        $ok = $false
        switch ($manager.ToLowerInvariant()) {
            "winget" {
                if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                    break
                }
                Write-Host "  [INFO] Uninstalling optional tool: $commandName via winget ($packageId)..." -ForegroundColor DarkGray
                & winget uninstall --id $packageId --exact --source winget --accept-source-agreements
                $ok = ($LASTEXITCODE -eq 0)
                break
            }
            "choco" {
                if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                    break
                }
                Write-Host "  [INFO] Uninstalling optional tool: $commandName via choco ($packageId)..." -ForegroundColor DarkGray
                & choco uninstall $packageId -y
                $ok = ($LASTEXITCODE -eq 0)
                break
            }
            "scoop" {
                if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
                    break
                }
                Write-Host "  [INFO] Uninstalling optional tool: $commandName via scoop ($packageId)..." -ForegroundColor DarkGray
                & scoop uninstall $packageId
                $ok = ($LASTEXITCODE -eq 0)
                break
            }
            default {
                break
            }
        }

        if ($ok) {
            $removedCount++
            Write-Host "  [OK] Removed optional tool: $commandName" -ForegroundColor Green
        } else {
            $remaining += $item
        }
    }

    Write-OptionalToolState -Records $remaining
    if ($removedCount -gt 0) {
        Refresh-SessionPath
    }
    return $removedCount
}

function Start-ScriptTranscript([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Start-Transcript -Path $Path -Append -Force | Out-Null
    return $true
}

function Stop-ScriptTranscript {
    try { Stop-Transcript | Out-Null } catch {}
}

function Broadcast-EnvironmentChange {
    try {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class NativeMethods {
  [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
  public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
}
"@ -ErrorAction SilentlyContinue

        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x1A
        $result = [UIntPtr]::Zero

        [NativeMethods]::SendMessageTimeout(
            $HWND_BROADCAST, $WM_SETTINGCHANGE,
            [UIntPtr]::Zero, "Environment", 2, 5000, [ref]$result
        ) | Out-Null
    } catch {
        # non-fatal
    }
}

function Refresh-SessionPath {
    $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [Environment]::GetEnvironmentVariable("Path","User")
}

$script:ProfileBackupPath = $null
function Backup-ProfileFile {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)

    if (-not (Test-Path $ProfilePath)) { return $null }
    if ($script:ProfileBackupPath) { return $script:ProfileBackupPath }

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backup = "$ProfilePath.bak-$stamp"
    Copy-Item -Path $ProfilePath -Destination $backup -Force
    $script:ProfileBackupPath = $backup
    return $backup
}

function Upsert-ProfileBlock {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$StartMarker,
        [Parameter(Mandatory = $true)][string]$EndMarker,
        [Parameter(Mandatory = $true)][string]$BlockBody
    )

    $profileDir = Split-Path -Parent $ProfilePath
    if ($profileDir -and -not (Test-Path $profileDir)) {
        New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    }
    if (-not (Test-Path $ProfilePath)) {
        New-Item -ItemType File -Path $ProfilePath -Force | Out-Null
    }

    $existing = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
    if ($null -eq $existing) { $existing = "" }

    $newBlock = @(
        $StartMarker
        $BlockBody
        $EndMarker
        ""
    ) -join "`r`n"

    # Normalize by removing any existing complete or orphaned marker lines first,
    # then append exactly one canonical block.
    $blockPattern = "(?ms)^\s*$([regex]::Escape($StartMarker))\s*$.*?^\s*$([regex]::Escape($EndMarker))\s*(\r?\n)?"
    $startLinePattern = "(?m)^\s*$([regex]::Escape($StartMarker))\s*(\r?\n)?"
    $endLinePattern = "(?m)^\s*$([regex]::Escape($EndMarker))\s*(\r?\n)?"

    $updated = [regex]::Replace($existing, $blockPattern, "")
    $updated = [regex]::Replace($updated, $startLinePattern, "")
    $updated = [regex]::Replace($updated, $endLinePattern, "")

    if ($updated.Length -gt 0 -and -not $updated.EndsWith("`r`n")) {
        $updated += "`r`n"
    }
    $updated += $newBlock

    Set-Content -Path $ProfilePath -Value $updated -Encoding UTF8
}

function Remove-ProfileBlock {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$StartMarker,
        [Parameter(Mandatory = $true)][string]$EndMarker
    )

    if (-not (Test-Path $ProfilePath)) { return }

    $existing = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
    if ($null -eq $existing -or $existing.Length -eq 0) { return }

    # Remove all complete marker blocks, plus any orphan marker lines.
    $pattern = "(?ms)^\s*$([regex]::Escape($StartMarker))\s*$.*?^\s*$([regex]::Escape($EndMarker))\s*(\r?\n)?"
    $updated = [regex]::Replace($existing, $pattern, "")

    $startLinePattern = "(?m)^\s*$([regex]::Escape($StartMarker))\s*(\r?\n)?"
    $endLinePattern = "(?m)^\s*$([regex]::Escape($EndMarker))\s*(\r?\n)?"
    $updated = [regex]::Replace($updated, $startLinePattern, "")
    $updated = [regex]::Replace($updated, $endLinePattern, "")

    if ($updated -ne $existing) {
        Set-Content -Path $ProfilePath -Value $updated -Encoding UTF8
    }
}

function Remove-ManagedProfileBlocks {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)

    if (-not (Test-Path $ProfilePath)) { return }
    $lines = Get-Content -Path $ProfilePath -ErrorAction SilentlyContinue
    if ($null -eq $lines) { return }

    $startPattern = '^\s*#\s*>>>\s*(?:unix-tools|git-tools)-[A-Za-z0-9-]+\s*>>>\s*$'
    $endPattern = '^\s*#\s*<<<\s*(?:unix-tools|git-tools)-[A-Za-z0-9-]+\s*<<<\s*$'

    $out = New-Object System.Collections.Generic.List[string]
    $skipDepth = 0
    foreach ($line in $lines) {
        if ($line -match $startPattern) {
            $skipDepth++
            continue
        }
        if ($line -match $endPattern) {
            if ($skipDepth -gt 0) { $skipDepth-- }
            continue
        }
        if ($skipDepth -eq 0) { $out.Add($line) }
    }

    $updated = $out -join "`r`n"
    if ($updated.Length -gt 0 -and -not $updated.EndsWith("`r`n")) {
        $updated += "`r`n"
    }
    Set-Content -Path $ProfilePath -Value $updated -Encoding UTF8
}

function Remove-InstalledProfileShims {
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $backup = Backup-ProfileFile -ProfilePath $profilePath
    if ($backup) { Write-Host "[INFO] Profile backup: $backup" -ForegroundColor DarkGray }
    Remove-ManagedProfileBlocks -ProfilePath $profilePath
    $markers = @(
        @{ Start = "# >>> unix-tools-missing-shims >>>"; End = "# <<< unix-tools-missing-shims <<<" },
        @{ Start = "# >>> unix-tools-alias-compat >>>"; End = "# <<< unix-tools-alias-compat <<<" },
        @{ Start = "# >>> git-tools-missing-shims >>>"; End = "# <<< git-tools-missing-shims <<<" },
        @{ Start = "# >>> git-tools-alias-compat >>>"; End = "# <<< git-tools-alias-compat <<<" }
    )

    foreach ($m in $markers) {
        Remove-ProfileBlock -ProfilePath $profilePath -StartMarker $m.Start -EndMarker $m.End
    }
}

function Install-ProfileMissingShims {
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $backup = Backup-ProfileFile -ProfilePath $profilePath
    if ($backup) { Write-Host "[INFO] Profile backup: $backup" -ForegroundColor DarkGray }
    $startMarker = "# >>> unix-tools-missing-shims >>>"
    $endMarker   = "# <<< unix-tools-missing-shims <<<"
    $legacyStart = "# >>> git-tools-missing-shims >>>"
    $legacyEnd   = "# <<< git-tools-missing-shims <<<"

    $blockBody = @'
# Add Unix-style shims only when a command is missing.
# This avoids overriding Git-for-Windows or third-party tools already on PATH.
function Add-UnixShimIfMissing {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Body
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Set-Item -Path ("Function:\Global:" + $Name) -Value $Body
    }
}

Add-UnixShimIfMissing -Name "export" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Assignments)
    foreach ($item in $Assignments) {
        $parts = $item -split "=", 2
        if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0])) {
            throw "usage: export NAME=VALUE [NAME2=VALUE2 ...]"
        }
        [System.Environment]::SetEnvironmentVariable($parts[0], $parts[1], "Process")
    }
}

Add-UnixShimIfMissing -Name "rev" -Body {
    param([string[]]$Path)

    $reverseLine = {
        param([string]$line)
        if ([string]::IsNullOrEmpty($line)) { return "" }
        $chars = $line.ToCharArray()
        [array]::Reverse($chars)
        return (-join $chars)
    }

    if ($Path -and $Path.Count -gt 0) {
        Get-Content -Path $Path | ForEach-Object { & $reverseLine $_ }
    } else {
        $input | ForEach-Object { & $reverseLine $_ }
    }
}

Add-UnixShimIfMissing -Name "unset" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Names)
    foreach ($name in $Names) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            Remove-Item -Path ("Env:" + $name) -ErrorAction SilentlyContinue
        }
    }
}

Add-UnixShimIfMissing -Name "mkdirp" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not [string]::IsNullOrWhiteSpace($path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

Add-UnixShimIfMissing -Name "ll" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    Get-ChildItem -Force @Args
}

Add-UnixShimIfMissing -Name "clear-hist" -Body {
    Clear-History
    if ([type]::GetType("Microsoft.PowerShell.PSConsoleReadLine, Microsoft.PowerShell.PSReadLine")) {
        [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
    }
}

Add-UnixShimIfMissing -Name "clear" -Body {
    Clear-Host
}

Add-UnixShimIfMissing -Name "pwd" -Body {
    (Get-Location).Path
}

Add-UnixShimIfMissing -Name "history" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $items = Get-History
    if ($ArgList.Count -gt 0) {
        $count = 0
        if ([int]::TryParse($ArgList[0], [ref]$count) -and $count -gt 0) {
            $items | Select-Object -Last $count
            return
        }
    }
    $items
}

Add-UnixShimIfMissing -Name "touch" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Paths)
    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if (Test-Path -Path $path) {
            (Get-Item -Path $path).LastWriteTime = Get-Date
        } else {
            New-Item -ItemType File -Path $path -Force | Out-Null
        }
    }
}

Add-UnixShimIfMissing -Name "head" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $count = 10
    $paths = @()
    $i = 0
    while ($i -lt $ArgList.Count) {
        $a = $ArgList[$i]
        if ($a -eq "-n" -and $i + 1 -lt $ArgList.Count) {
            $count = [int]$ArgList[$i + 1]
            $i += 2
            continue
        }
        if ($a -match "^-n\d+$") {
            $count = [int]($a.Substring(2))
            $i++
            continue
        }
        if ($a.StartsWith("-") -and $a -ne "--") { throw "head: unsupported option $a (fallback supports -n)" }
        if ($a -ne "--") { $paths += $a }
        $i++
    }
    if ($paths.Count -gt 0) { Get-Content -Path $paths -TotalCount $count } else { @($input) | Select-Object -First $count }
}

Add-UnixShimIfMissing -Name "tail" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $count = 10
    $follow = $false
    $paths = @()
    $i = 0
    while ($i -lt $ArgList.Count) {
        $a = $ArgList[$i]
        if ($a -eq "-n" -and $i + 1 -lt $ArgList.Count) {
            $count = [int]$ArgList[$i + 1]
            $i += 2
            continue
        }
        if ($a -match "^-n\d+$") {
            $count = [int]($a.Substring(2))
            $i++
            continue
        }
        if ($a -eq "-f") { $follow = $true; $i++; continue }
        if ($a.StartsWith("-") -and $a -ne "--") { throw "tail: unsupported option $a (fallback supports -n, -f)" }
        if ($a -ne "--") { $paths += $a }
        $i++
    }
    if ($paths.Count -eq 0) { throw "usage: tail [-n COUNT] [-f] [file...]" }
    if ($follow) { Get-Content -Path $paths -Tail $count -Wait } else { Get-Content -Path $paths -Tail $count }
}

Add-UnixShimIfMissing -Name "wc" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $linesOnly = $false
    $wordsOnly = $false
    $files = @()
    foreach ($a in $ArgList) {
        if ($a -eq "-l") { $linesOnly = $true; continue }
        if ($a -eq "-w") { $wordsOnly = $true; continue }
        if ($a.StartsWith("-")) { throw "wc: unsupported option $a (fallback supports -l, -w)" }
        $files += $a
    }
    if ($files.Count -eq 0) { throw "usage: wc [-l] [-w] [file...]" }
    foreach ($file in $files) {
        $content = Get-Content -Path $file
        $lineCount = $content.Count
        $wordCount = ($content | Measure-Object -Word).Words
        if ($linesOnly) { "$lineCount $file" }
        elseif ($wordsOnly) { "$wordCount $file" }
        else { "$lineCount $wordCount $file" }
    }
}

function Invoke-GrepShim {
    param(
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList,
        [object[]]$InputItems,
        [switch]$SimpleMatch
    )

    $ignoreCase = $false
    $lineNumber = $false
    $invert = $false
    $recursive = $false
    $pattern = $null
    $paths = @()

    foreach ($a in $ArgList) {
        if ($a -eq "--") { continue }
        if ($a.StartsWith("--")) { throw "grep: unsupported option $a (fallback supports -i, -n, -v, -r, -R)" }
        if ($a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'i' { $ignoreCase = $true; break }
                    'n' { $lineNumber = $true; break }
                    'v' { $invert = $true; break }
                    'r' { $recursive = $true; break }
                    'R' { $recursive = $true; break }
                    default { throw "grep: unsupported option -$ch (fallback supports -i, -n, -v, -r, -R)" }
                }
            }
            continue
        }

        if ($null -eq $pattern) {
            $pattern = $a
        } else {
            $paths += $a
        }
    }

    if ([string]::IsNullOrWhiteSpace($pattern)) {
        throw "usage: grep [-i] [-n] [-v] [-r] <pattern> [file|dir ...]"
    }

    $result = $null
    $caseSensitive = -not $ignoreCase
    if ($paths.Count -gt 0) {
        if ($recursive) {
            $targets = @()
            foreach ($p in $paths) {
                if (Test-Path -Path $p -PathType Container) { $targets += (Join-Path $p "*") }
                else { $targets += $p }
            }
            $result = Select-String -Pattern $pattern -Path $targets -Recurse -SimpleMatch:$SimpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
        } else {
            $result = Select-String -Pattern $pattern -Path $paths -SimpleMatch:$SimpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
        }
    } else {
        if ($InputItems -and $InputItems.Count -gt 0) {
            $result = $InputItems | Select-String -Pattern $pattern -SimpleMatch:$SimpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert
        } else {
            $defaultPath = if ($recursive) { @(".\*") } else { @(".") }
            $result = Select-String -Pattern $pattern -Path $defaultPath -Recurse:$recursive -SimpleMatch:$SimpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
        }
    }

    if ($lineNumber) {
        $result | ForEach-Object { "{0}:{1}:{2}" -f $_.Path, $_.LineNumber, $_.Line }
    } else {
        $result
    }
}

Add-UnixShimIfMissing -Name "grep" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    Invoke-GrepShim -ArgList $ArgList -InputItems @($input)
}

Add-UnixShimIfMissing -Name "egrep" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    Invoke-GrepShim -ArgList $ArgList -InputItems @($input)
}

Add-UnixShimIfMissing -Name "fgrep" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    Invoke-GrepShim -ArgList $ArgList -InputItems @($input) -SimpleMatch
}

Add-UnixShimIfMissing -Name "nc" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $ncat = Get-Command ncat -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ncat) {
        throw "nc: command not found. Install ncat (winget install --id Insecure.Nmap --exact) or run Enable-UnixToolsSystemWide.ps1 -InstallOptionalTools."
    }
    & $ncat.Source @ArgList
}

Add-UnixShimIfMissing -Name "which" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Names)
    foreach ($name in $Names) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) {
            if ($cmd.Source) { $cmd.Source }
            elseif ($cmd.Definition) { $cmd.Definition }
            else { $cmd.Name }
        }
    }
}

Add-UnixShimIfMissing -Name "man" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -eq 0) { throw "usage: man <command>" }
    Get-Help $ArgList[0] -Full
}

Add-UnixShimIfMissing -Name "source" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -eq 0) { throw "usage: source <script> [args...]" }
    $path = $ArgList[0]
    $rest = @()
    if ($ArgList.Count -gt 1) { $rest = $ArgList[1..($ArgList.Count - 1)] }
    . $path @rest
}

Add-UnixShimIfMissing -Name "apropos" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -eq 0) { throw "usage: apropos <keyword>" }
    $pattern = "*" + (($ArgList -join " ").Trim()) + "*"
    Get-Help $pattern -ErrorAction SilentlyContinue |
        Select-Object Name, Synopsis |
        Sort-Object Name
}

Add-UnixShimIfMissing -Name "make" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $alt = @("mingw32-make", "nmake")
    foreach ($name in $alt) {
        $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) {
            & $cmd.Source @ArgList
            return
        }
    }
    throw "make: command not found. Install make or run with -AddMingw so mingw32-make can be discovered."
}

Add-UnixShimIfMissing -Name "open" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -eq 0) {
        Start-Process -FilePath "."
        return
    }
    foreach ($target in $ArgList) {
        Start-Process -FilePath $target
    }
}

Add-UnixShimIfMissing -Name "xdg-open" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    open @ArgList
}

Add-UnixShimIfMissing -Name "rename" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -ne 2) { throw "usage: rename <old-path> <new-name|new-path>" }
    $oldPath = $ArgList[0]
    $newSpec = $ArgList[1]
    if ($newSpec -match '[\\/]' -or [System.IO.Path]::IsPathRooted($newSpec)) {
        Move-Item -Path $oldPath -Destination $newSpec -Force
    } else {
        Rename-Item -Path $oldPath -NewName $newSpec -Force
    }
}

Add-UnixShimIfMissing -Name "dos2unix" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -eq 0) { throw "usage: dos2unix <file...>" }
    foreach ($path in $ArgList) {
        $text = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        $out = ($text -replace "`r`n", "`n") -replace "`r", "`n"
        Set-Content -LiteralPath $path -Value $out -NoNewline -Encoding utf8NoBOM
    }
}

Add-UnixShimIfMissing -Name "unix2dos" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -eq 0) { throw "usage: unix2dos <file...>" }
    foreach ($path in $ArgList) {
        $text = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        $normalized = ($text -replace "`r`n", "`n") -replace "`r", "`n"
        $out = $normalized -replace "`n", "`r`n"
        Set-Content -LiteralPath $path -Value $out -NoNewline -Encoding utf8NoBOM
    }
}

Add-UnixShimIfMissing -Name "vdir" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    Get-ChildItem -Force @ArgList | Format-Table Mode, LastWriteTime, Length, Name -AutoSize
}

Add-UnixShimIfMissing -Name "link" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -ne 2) { throw "usage: link <target> <linkpath>" }
    New-Item -ItemType HardLink -Path $ArgList[1] -Target $ArgList[0] -Force | Out-Null
}

Add-UnixShimIfMissing -Name "tput" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -eq 0) { throw "usage: tput <clear|reset|cols|lines>" }
    switch ($ArgList[0]) {
        "clear" { Clear-Host; return }
        "reset" { Clear-Host; return }
        "cols" { [Console]::WindowWidth; return }
        "lines" { [Console]::WindowHeight; return }
        default { throw "tput: fallback supports clear, reset, cols, lines" }
    }
}

Add-UnixShimIfMissing -Name "sync" -Body {
    [GC]::Collect()
}

Add-UnixShimIfMissing -Name "at" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -lt 2) { throw "usage: at HH:mm <command...>" }
    $time = $ArgList[0]
    if ($time -notmatch '^\d{1,2}:\d{2}$') { throw "at: time format must be HH:mm" }
    $commandText = ($ArgList[1..($ArgList.Count - 1)] -join " ")
    $taskName = "unix-at-" + ([guid]::NewGuid().ToString("N").Substring(0, 8))
    & schtasks /Create /SC ONCE /TN $taskName /TR $commandText /ST $time /F | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "at: failed to create scheduled task." }
    Write-Output $taskName
}

Add-UnixShimIfMissing -Name "aspell" -Body {
    throw "aspell: fallback unavailable. Install aspell and re-run setup to get executable pass-through."
}

Add-UnixShimIfMissing -Name "bc" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $expr = if ($ArgList.Count -gt 0) { $ArgList -join " " } else { ($input | Out-String).Trim() }
    if ([string]::IsNullOrWhiteSpace($expr)) { throw "usage: bc <expression>" }
    $table = New-Object System.Data.DataTable
    $result = $table.Compute($expr, $null)
    Write-Output $result
}

Add-UnixShimIfMissing -Name "base64" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $decode = $false
    $wrap = 76
    $files = @()
    $i = 0
    while ($i -lt $ArgList.Count) {
        $a = $ArgList[$i]
        if ($a -eq "--") { $i++; continue }
        if ($a -eq "-d" -or $a -eq "--decode") { $decode = $true; $i++; continue }
        if ($a -eq "-w" -and $i + 1 -lt $ArgList.Count) { $wrap = [int]$ArgList[$i + 1]; $i += 2; continue }
        if ($a.StartsWith("-")) { throw "base64: unsupported option $a (fallback supports -d/--decode, -w N)" }
        $files += $a
        $i++
    }

    if ($decode) {
        $encoded = if ($files.Count -gt 0) {
            Get-Content -LiteralPath $files[0] -Raw -ErrorAction Stop
        } else {
            (@($input) -join "`n")
        }
        $clean = ($encoded -replace '\s+', '')
        if ([string]::IsNullOrWhiteSpace($clean)) { return }
        [byte[]]$decodedBytes = [Convert]::FromBase64String($clean)
        $stdout = [Console]::OpenStandardOutput()
        $stdout.Write($decodedBytes, 0, $decodedBytes.Length)
        return
    }

    [byte[]]$bytes = if ($files.Count -gt 0) {
        [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $files[0]).Path)
    } else {
        [System.Text.Encoding]::UTF8.GetBytes((@($input) -join "`n"))
    }

    $encodedOut = [Convert]::ToBase64String($bytes)
    if ($wrap -gt 0) {
        for ($pos = 0; $pos -lt $encodedOut.Length; $pos += $wrap) {
            $len = [Math]::Min($wrap, $encodedOut.Length - $pos)
            $encodedOut.Substring($pos, $len)
        }
    } else {
        $encodedOut
    }
}

Add-UnixShimIfMissing -Name "base32" -Body {
    throw "base32: fallback unavailable. Install a real base32 tool (Git coreutils/busybox) for full support."
}

Add-UnixShimIfMissing -Name "cksum" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)

    function Get-Crc32Value {
        param([byte[]]$Bytes)
        $crc = [uint32]0xFFFFFFFF
        foreach ($b in $Bytes) {
            $crc = $crc -bxor [uint32]$b
            for ($j = 0; $j -lt 8; $j++) {
                if (($crc -band 1) -ne 0) {
                    $crc = ($crc -shr 1) -bxor [uint32]0xEDB88320
                } else {
                    $crc = $crc -shr 1
                }
            }
        }
        return (-bnot $crc) -band [uint32]0xFFFFFFFF
    }

    $targets = if ($ArgList.Count -gt 0) { $ArgList } else { @() }
    if ($targets.Count -eq 0) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes((@($input) -join "`n"))
        $crc = Get-Crc32Value -Bytes $bytes
        "{0} {1}" -f $crc, $bytes.Length
        return
    }

    foreach ($path in $targets) {
        $resolved = (Resolve-Path -LiteralPath $path).Path
        $bytes = [System.IO.File]::ReadAllBytes($resolved)
        $crc = Get-Crc32Value -Bytes $bytes
        "{0} {1} {2}" -f $crc, $bytes.Length, $path
    }
}

Add-UnixShimIfMissing -Name "sum" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    # Compatibility fallback: reuse cksum output format.
    cksum @ArgList
}

Add-UnixShimIfMissing -Name "pv" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $count = 0L
    $start = Get-Date
    foreach ($item in $input) {
        $line = [string]$item
        $count += [System.Text.Encoding]::UTF8.GetByteCount($line + [Environment]::NewLine)
        $item
    }
    $elapsed = (Get-Date) - $start
    Write-Host ("[pv fallback] transferred {0} bytes in {1:n2}s" -f $count, $elapsed.TotalSeconds) -ForegroundColor DarkGray
}

Add-UnixShimIfMissing -Name "pr" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -eq 0) {
        $i = 1
        foreach ($line in $input) {
            "{0,6}  {1}" -f $i, $line
            $i++
        }
        return
    }
    foreach ($path in $ArgList) {
        "==== {0} ====" -f $path
        $i = 1
        Get-Content -LiteralPath $path | ForEach-Object {
            "{0,6}  {1}" -f $i, $_
            $i++
        }
    }
}

Add-UnixShimIfMissing -Name "cpio" -Body {
    throw "cpio: fallback unavailable. Install cpio executable to use this command."
}

Add-UnixShimIfMissing -Name "cal" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $now = Get-Date
    $month = $now.Month
    $year = $now.Year
    if ($ArgList.Count -eq 1) { $month = [int]$ArgList[0] }
    if ($ArgList.Count -ge 2) { $year = [int]$ArgList[1] }
    $first = [datetime]::new($year, $month, 1)
    $days = [datetime]::DaysInMonth($year, $month)
    "{0} {1}" -f $first.ToString("MMMM"), $year
    "Su Mo Tu We Th Fr Sa"
    $offset = [int]$first.DayOfWeek
    $line = ("   " * $offset)
    for ($d = 1; $d -le $days; $d++) {
        $line += ("{0,2} " -f $d)
        if ((($offset + $d) % 7) -eq 0) {
            $line.TrimEnd()
            $line = ""
        }
    }
    if ($line.Trim().Length -gt 0) { $line.TrimEnd() }
}
'@

    Remove-ProfileBlock -ProfilePath $profilePath -StartMarker $legacyStart -EndMarker $legacyEnd
    Upsert-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker -BlockBody $blockBody
    Write-Host "[OK] Installed/updated missing-command profile shims in: $profilePath" -ForegroundColor Green
}

function Install-ProfileAliasCompat {
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $backup = Backup-ProfileFile -ProfilePath $profilePath
    if ($backup) { Write-Host "[INFO] Profile backup: $backup" -ForegroundColor DarkGray }
    $startMarker = "# >>> unix-tools-alias-compat >>>"
    $endMarker   = "# <<< unix-tools-alias-compat <<<"
    $legacyStart = "# >>> git-tools-alias-compat >>>"
    $legacyEnd   = "# <<< git-tools-alias-compat <<<"

    $blockBody = @'
# Prefer external Unix tools over PowerShell aliases/functions when available.
# If no external tool exists, install a PowerShell fallback with common Unix flags.
function Set-UnixCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Fallback
    )

    $app = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($app) {
        # If a built-in alias exists (e.g., cp), repoint it to the external app.
        $existingAlias = Get-Alias -Name $Name -ErrorAction SilentlyContinue
        if ($existingAlias) {
            try {
                if (($existingAlias.Options -band [System.Management.Automation.ScopedItemOptions]::AllScope) -ne 0) {
                    New-Alias -Name $Name -Value $app.Name -Scope Global -Option AllScope -Force -ErrorAction Stop
                } else {
                    Set-Alias -Name $Name -Value $app.Name -Scope Global -Force -ErrorAction Stop
                }
            } catch {
                Remove-Item ("Alias:" + $Name) -Force -ErrorAction SilentlyContinue
                Remove-Item ("Alias:Global:" + $Name) -Force -ErrorAction SilentlyContinue
            }
        }
        Remove-Item ("Function:" + $Name) -Force -ErrorAction SilentlyContinue
        Remove-Item ("Function:Global:" + $Name) -Force -ErrorAction SilentlyContinue
        return
    }

    Remove-Item ("Alias:" + $Name) -Force -ErrorAction SilentlyContinue
    Remove-Item ("Alias:Global:" + $Name) -Force -ErrorAction SilentlyContinue
    Set-Item -Path ("Function:\Global:" + $Name) -Value $Fallback
}

function Show-UnsupportedFlag {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$Flag,
        [Parameter(Mandatory = $true)][string]$SupportedFlags,
        [Parameter(Mandatory = $true)][string]$Usage
    )

    $message = @(
        "$($Command): unsupported option '$Flag'",
        "Supported flags in fallback: $SupportedFlags",
        "",
        "Tip: run Show-UnixCoverageReport -IncludeMissing to see command/flag coverage.",
        "",
        "How to add support for this flag:",
        "1) Open `$PROFILE and find marker: # >>> unix-tools-alias-compat >>>",
        "2) Find: Set-UnixCommand -Name '$Command' -Fallback { ... }",
        "3) Extend that parser switch/if to handle '$Flag'",
        "4) Or update installer block and re-run: Enable-UnixToolsSystemWide.ps1 -InstallProfileShims",
        "",
        "Usage: $Usage"
    ) -join [Environment]::NewLine

    throw $message
}

$script:UnixFallbackCoverage = [ordered]@{
    rm    = [ordered]@{ CoveredFlags = "-r, -R, -f, --"; UnsupportedFlags = "Any other short/long option" }
    cp    = [ordered]@{ CoveredFlags = "-r, -R, -f, -n, --"; UnsupportedFlags = "Any other short/long option" }
    mv    = [ordered]@{ CoveredFlags = "-f, -n, --"; UnsupportedFlags = "Any other short/long option" }
    mkdir = [ordered]@{ CoveredFlags = "-p, -v, --"; UnsupportedFlags = "Any other short/long option" }
    ls    = [ordered]@{ CoveredFlags = "-a, -l, -t, -r, -h, --"; UnsupportedFlags = "Any other short/long option" }
    cat   = [ordered]@{ CoveredFlags = "-n, -s, --"; UnsupportedFlags = "Any other short/long option" }
    sort  = [ordered]@{ CoveredFlags = "-u, -r, -n, -f, --"; UnsupportedFlags = "Any other short/long option" }
    diff  = [ordered]@{ CoveredFlags = "-u, -q, --"; UnsupportedFlags = "Any other short/long option" }
    tee   = [ordered]@{ CoveredFlags = "-a, -i, --"; UnsupportedFlags = "Any other short/long option" }
    sleep = [ordered]@{ CoveredFlags = "NUMBER[s|m|h|d]"; UnsupportedFlags = "Invalid value or unsupported suffix" }
}

$script:UnixMissingShimCoverage = [ordered]@{
    export     = [ordered]@{ CoveredFlags = "NAME=VALUE [NAME2=VALUE2 ...]"; UnsupportedFlags = "N/A (assignment syntax fallback)" }
    rev        = [ordered]@{ CoveredFlags = "[file ...] or stdin"; UnsupportedFlags = "N/A (line reverse fallback)" }
    unset      = [ordered]@{ CoveredFlags = "NAME [NAME2 ...]"; UnsupportedFlags = "N/A (name list fallback)" }
    mkdirp     = [ordered]@{ CoveredFlags = "<dir ...>"; UnsupportedFlags = "N/A (compat wrapper)" }
    ll         = [ordered]@{ CoveredFlags = "[path ...]"; UnsupportedFlags = "N/A (compat wrapper)" }
    'clear-hist' = [ordered]@{ CoveredFlags = "(no flags)"; UnsupportedFlags = "All flags unsupported" }
    clear      = [ordered]@{ CoveredFlags = "(no flags)"; UnsupportedFlags = "All flags unsupported" }
    pwd        = [ordered]@{ CoveredFlags = "(no flags)"; UnsupportedFlags = "All flags unsupported" }
    history    = [ordered]@{ CoveredFlags = "[count]"; UnsupportedFlags = "Any flag option" }
    touch      = [ordered]@{ CoveredFlags = "<file ...>"; UnsupportedFlags = "Any flag option" }
    head       = [ordered]@{ CoveredFlags = "-n, -nCOUNT"; UnsupportedFlags = "Any other short/long option" }
    tail       = [ordered]@{ CoveredFlags = "-n, -nCOUNT, -f"; UnsupportedFlags = "Any other short/long option" }
    wc         = [ordered]@{ CoveredFlags = "-l, -w"; UnsupportedFlags = "Any other short/long option" }
    grep       = [ordered]@{ CoveredFlags = "-i, -n, -v, -r, -R"; UnsupportedFlags = "Any other short/long option" }
    egrep      = [ordered]@{ CoveredFlags = "-i, -n, -v, -r, -R"; UnsupportedFlags = "Any other short/long option" }
    fgrep      = [ordered]@{ CoveredFlags = "-i, -n, -v, -r, -R"; UnsupportedFlags = "Any other short/long option" }
    nc         = [ordered]@{ CoveredFlags = "[ncat-compatible args...]"; UnsupportedFlags = "Delegated to ncat when installed" }
    which      = [ordered]@{ CoveredFlags = "<command ...>"; UnsupportedFlags = "Any flag option" }
    man        = [ordered]@{ CoveredFlags = "<command>"; UnsupportedFlags = "Any flag option" }
    source     = [ordered]@{ CoveredFlags = "<script> [args...]"; UnsupportedFlags = "Any flag option" }
    apropos    = [ordered]@{ CoveredFlags = "<keyword>"; UnsupportedFlags = "Any flag option" }
    make       = [ordered]@{ CoveredFlags = "[make args...]"; UnsupportedFlags = "Delegated to mingw32-make/nmake when available" }
    open       = [ordered]@{ CoveredFlags = "[path|url ...]"; UnsupportedFlags = "Any flag option" }
    'xdg-open' = [ordered]@{ CoveredFlags = "[path|url ...]"; UnsupportedFlags = "Any flag option" }
    rename     = [ordered]@{ CoveredFlags = "<old-path> <new-name|new-path>"; UnsupportedFlags = "Any flag option" }
    dos2unix   = [ordered]@{ CoveredFlags = "<file ...>"; UnsupportedFlags = "Any flag option" }
    unix2dos   = [ordered]@{ CoveredFlags = "<file ...>"; UnsupportedFlags = "Any flag option" }
    vdir       = [ordered]@{ CoveredFlags = "[path ...]"; UnsupportedFlags = "Any flag option" }
    link       = [ordered]@{ CoveredFlags = "<target> <linkpath>"; UnsupportedFlags = "Any flag option" }
    tput       = [ordered]@{ CoveredFlags = "clear|reset|cols|lines"; UnsupportedFlags = "Any other capability token" }
    sync       = [ordered]@{ CoveredFlags = "(no flags)"; UnsupportedFlags = "All flags unsupported" }
    at         = [ordered]@{ CoveredFlags = "HH:mm <command...>"; UnsupportedFlags = "Any other syntax" }
    aspell     = [ordered]@{ CoveredFlags = "(none in fallback)"; UnsupportedFlags = "Fallback unavailable (install executable)" }
    bc         = [ordered]@{ CoveredFlags = "<expression>"; UnsupportedFlags = "Any flag option" }
    base64     = [ordered]@{ CoveredFlags = "-d, --decode, -w N, [file]"; UnsupportedFlags = "Any other short/long option" }
    base32     = [ordered]@{ CoveredFlags = "(none in fallback)"; UnsupportedFlags = "Fallback unavailable (install executable)" }
    cksum      = [ordered]@{ CoveredFlags = "[file ...] or stdin"; UnsupportedFlags = "Any flag option" }
    sum        = [ordered]@{ CoveredFlags = "[file ...] or stdin"; UnsupportedFlags = "Any flag option" }
    pv         = [ordered]@{ CoveredFlags = "stdin passthrough"; UnsupportedFlags = "Any flag option" }
    pr         = [ordered]@{ CoveredFlags = "[file ...] or stdin"; UnsupportedFlags = "Any flag option" }
    cpio       = [ordered]@{ CoveredFlags = "(none in fallback)"; UnsupportedFlags = "Fallback unavailable (install executable)" }
    cal        = [ordered]@{ CoveredFlags = "[month] [year]"; UnsupportedFlags = "Any flag option" }
}

function Convert-UnixCoverageEntry {
    param([Parameter(Mandatory = $true)]$Entry)

    if ($Entry -is [string]) {
        return [pscustomobject]@{
            CoveredFlags = $Entry
            UnsupportedFlags = "Any unsupported option gets friendly guidance"
        }
    }

    $covered = ""
    $unsupported = "Any unsupported option gets friendly guidance"
    if ($Entry.PSObject.Properties['CoveredFlags']) { $covered = [string]$Entry.CoveredFlags }
    if ($Entry.PSObject.Properties['UnsupportedFlags']) { $unsupported = [string]$Entry.UnsupportedFlags }

    [pscustomobject]@{
        CoveredFlags = $covered
        UnsupportedFlags = $unsupported
    }
}

function Get-UnixFallbackCoverage {
    $script:UnixFallbackCoverage.GetEnumerator() | ForEach-Object {
        $normalized = Convert-UnixCoverageEntry -Entry $_.Value
        [pscustomobject]@{
            Command = $_.Key
            CoveredFlags = $normalized.CoveredFlags
            UnsupportedFlags = $normalized.UnsupportedFlags
        }
    }
}

function Get-UnixCoverageReport {
    param([switch]$IncludeMissing)

    $catalog = New-Object System.Collections.Generic.List[object]
    foreach ($e in $script:UnixFallbackCoverage.GetEnumerator()) {
        $normalized = Convert-UnixCoverageEntry -Entry $e.Value
        $catalog.Add([pscustomobject]@{
            Command = $e.Key
            Group = "alias-compat"
            CoveredFlags = $normalized.CoveredFlags
            UnsupportedFlags = $normalized.UnsupportedFlags
        }) | Out-Null
    }

    if ($IncludeMissing) {
        foreach ($e in $script:UnixMissingShimCoverage.GetEnumerator()) {
            $normalized = Convert-UnixCoverageEntry -Entry $e.Value
            $catalog.Add([pscustomobject]@{
                Command = $e.Key
                Group = "missing-shim"
                CoveredFlags = $normalized.CoveredFlags
                UnsupportedFlags = $normalized.UnsupportedFlags
            }) | Out-Null
        }
    }

    $commandCache = @{}
    $uniqueNames = $catalog | Select-Object -ExpandProperty Command -Unique
    foreach ($n in $uniqueNames) {
        $commandCache[$n] = @(Get-Command $n -All -ErrorAction SilentlyContinue)
    }

    foreach ($item in $catalog) {
        $name = $item.Command
        $all = @()
        if ($commandCache.ContainsKey($name)) { $all = @($commandCache[$name]) }
        $resolution = "missing"
        $source = ""

        if ($all.Count -gt 0) {
            $app = $all | Where-Object { $_.CommandType -eq "Application" } | Select-Object -First 1
            if ($app) {
                $resolution = "pass-through"
                $source = $app.Source
            } else {
                $fn = $all | Where-Object { $_.CommandType -eq "Function" } | Select-Object -First 1
                if ($fn) {
                    $resolution = "fallback"
                    $source = "Function:$($fn.Name)"
                } else {
                    $alias = $all | Where-Object { $_.CommandType -eq "Alias" } | Select-Object -First 1
                    if ($alias) {
                        $resolution = "alias"
                        $source = "Alias->$($alias.Definition)"
                    } else {
                        $first = $all | Select-Object -First 1
                        $resolution = $first.CommandType.ToString().ToLowerInvariant()
                        if ($first.Source) { $source = $first.Source }
                        elseif ($first.Definition) { $source = $first.Definition }
                    }
                }
            }
        }

        $passThroughFlags = switch ($resolution) {
            "pass-through" { "All executable flags pass through" }
            "alias" { "Alias target decides" }
            default { "-" }
        }

        $effectiveUnsupportedFlags = switch ($resolution) {
            "pass-through" { "-" }
            "alias" { "Depends on alias target implementation" }
            "fallback" { $item.UnsupportedFlags }
            default { "Command not currently available" }
        }

        $unsupportedBehavior = switch ($resolution) {
            "pass-through" { "Delegated to executable behavior" }
            "fallback" { "Friendly message + add-support guidance" }
            "alias" { "Depends on alias target implementation" }
            default { "Command not currently available" }
        }

        [pscustomobject]@{
            Command = $name
            Group = $item.Group
            Resolution = $resolution
            CoveredFlags = $item.CoveredFlags
            PassThroughFlags = $passThroughFlags
            UnsupportedFlags = $effectiveUnsupportedFlags
            UnsupportedBehavior = $unsupportedBehavior
            Source = $source
        }
    }
}

function Show-UnixCoverageReport {
    param([switch]$IncludeMissing)
    Get-UnixCoverageReport -IncludeMissing:$IncludeMissing |
        Sort-Object Group, Command |
        Format-Table Command, Group, Resolution, CoveredFlags, PassThroughFlags, UnsupportedFlags -AutoSize
}

Set-UnixCommand -Name "rm" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $recurse = $false
    $force = $false
    $paths = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "rm" -Flag $a -SupportedFlags "-r, -R, -f, --" -Usage "rm [-rf] [--] <path...>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'r' { $recurse = $true; break }
                    'R' { $recurse = $true; break }
                    'f' { $force = $true; break }
                    default { Show-UnsupportedFlag -Command "rm" -Flag ("-" + $ch) -SupportedFlags "-r, -R, -f, --" -Usage "rm [-rf] [--] <path...>" }
                }
            }
        } else {
            $paths += $a
        }
    }
    if ($paths.Count -eq 0) { throw "usage: rm [-rf] [--] <path...>" }
    Remove-Item -Path $paths -Recurse:$recurse -Force:$force
}

Set-UnixCommand -Name "cp" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $recurse = $false
    $force = $false
    $noClobber = $false
    $items = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "cp" -Flag $a -SupportedFlags "-r, -R, -f, -n, --" -Usage "cp [-rfn] [--] <src...> <dest>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'r' { $recurse = $true; break }
                    'R' { $recurse = $true; break }
                    'f' { $force = $true; break }
                    'n' { $noClobber = $true; break }
                    default { Show-UnsupportedFlag -Command "cp" -Flag ("-" + $ch) -SupportedFlags "-r, -R, -f, -n, --" -Usage "cp [-rfn] [--] <src...> <dest>" }
                }
            }
        } else {
            $items += $a
        }
    }
    if ($items.Count -lt 2) { throw "usage: cp [-rfn] [--] <src...> <dest>" }
    $dest = $items[-1]
    $src = $items[0..($items.Count - 2)]

    if (-not $noClobber) {
        Copy-Item -Path $src -Destination $dest -Recurse:$recurse -Force:$force
        return
    }

    foreach ($s in $src) {
        $target = $dest
        if (Test-Path -Path $dest -PathType Container) {
            $target = Join-Path $dest (Split-Path -Leaf $s)
        }
        if (Test-Path -Path $target) { continue }
        Copy-Item -Path $s -Destination $dest -Recurse:$recurse -Force:$force
    }
}

Set-UnixCommand -Name "mv" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $force = $false
    $noClobber = $false
    $items = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "mv" -Flag $a -SupportedFlags "-f, -n, --" -Usage "mv [-fn] [--] <src...> <dest>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'f' { $force = $true; break }
                    'n' { $noClobber = $true; break }
                    default { Show-UnsupportedFlag -Command "mv" -Flag ("-" + $ch) -SupportedFlags "-f, -n, --" -Usage "mv [-fn] [--] <src...> <dest>" }
                }
            }
        } else {
            $items += $a
        }
    }
    if ($items.Count -lt 2) { throw "usage: mv [-fn] [--] <src...> <dest>" }
    $dest = $items[-1]
    $src = $items[0..($items.Count - 2)]
    if (-not $noClobber) {
        Move-Item -Path $src -Destination $dest -Force:$force
        return
    }

    foreach ($s in $src) {
        $target = $dest
        if (Test-Path -Path $dest -PathType Container) {
            $target = Join-Path $dest (Split-Path -Leaf $s)
        }
        if (Test-Path -Path $target) { continue }
        Move-Item -Path $s -Destination $dest -Force:$force
    }
}

Set-UnixCommand -Name "mkdir" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $p = $false
    $verbose = $false
    $paths = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "mkdir" -Flag $a -SupportedFlags "-p, -v, --" -Usage "mkdir [-pv] [--] <dir...>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'p' { $p = $true; break }
                    'v' { $verbose = $true; break }
                    default { Show-UnsupportedFlag -Command "mkdir" -Flag ("-" + $ch) -SupportedFlags "-p, -v, --" -Usage "mkdir [-pv] [--] <dir...>" }
                }
            }
        } else {
            $paths += $a
        }
    }
    if ($paths.Count -eq 0) { throw "usage: mkdir [-pv] [--] <dir...>" }
    foreach ($path in $paths) {
        New-Item -ItemType Directory -Path $path -Force:$p | Out-Null
        if ($verbose) { "mkdir: created directory '$path'" }
    }
}

Set-UnixCommand -Name "ls" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $all = $false
    $long = $false
    $sortTime = $false
    $reverse = $false
    $paths = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "ls" -Flag $a -SupportedFlags "-a, -l, -t, -r, -h, --" -Usage "ls [-lathr] [--] [path...]"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'a' { $all = $true; break }
                    'l' { $long = $true; break }
                    't' { $sortTime = $true; break }
                    'r' { $reverse = $true; break }
                    'h' { break }
                    default { Show-UnsupportedFlag -Command "ls" -Flag ("-" + $ch) -SupportedFlags "-a, -l, -t, -r, -h, --" -Usage "ls [-lathr] [--] [path...]" }
                }
            }
        } else {
            $paths += $a
        }
    }
    if ($paths.Count -eq 0) { $paths = @(".") }
    $items = Get-ChildItem -Path $paths -Force:$all
    if ($sortTime) { $items = $items | Sort-Object LastWriteTime -Descending }
    if ($reverse) {
        $arr = @($items)
        if ($arr.Count -gt 1) { [array]::Reverse($arr) }
        $items = $arr
    }
    if ($long) {
        $rows = $items | ForEach-Object {
            $displayName = $_.Name
            $target = $null
            if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                if ($_.PSObject.Properties.Match('LinkTarget').Count -gt 0) { $target = $_.LinkTarget }
                if (-not $target -and $_.PSObject.Properties.Match('Target').Count -gt 0) { $target = $_.Target }
                if ($target -is [array]) { $target = $target -join ", " }
                if ($target) { $displayName = "$displayName -> $target" }
            }
            [pscustomobject]@{
                Mode = $_.Mode
                LastWriteTime = $_.LastWriteTime
                Length = if ($_.PSIsContainer) { '' } else { $_.Length }
                Name = $displayName
            }
        }
        $rows | Format-Table Mode, LastWriteTime, Length, Name -AutoSize
    } else {
        $items
    }
}

Set-UnixCommand -Name "cat" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $number = $false
    $squeezeBlank = $false
    $paths = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "cat" -Flag $a -SupportedFlags "-n, -s, --" -Usage "cat [-ns] [--] [file...]"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'n' { $number = $true; break }
                    's' { $squeezeBlank = $true; break }
                    default { Show-UnsupportedFlag -Command "cat" -Flag ("-" + $ch) -SupportedFlags "-n, -s, --" -Usage "cat [-ns] [--] [file...]" }
                }
            }
            continue
        }
        $paths += $a
    }

    $lines = if ($paths.Count -gt 0) { Get-Content -Path $paths } else { @($input) }
    if ($squeezeBlank) {
        $out = New-Object System.Collections.Generic.List[string]
        $prevBlank = $false
        foreach ($line in $lines) {
            $isBlank = [string]::IsNullOrWhiteSpace($line)
            if ($isBlank -and $prevBlank) { continue }
            $out.Add($line)
            $prevBlank = $isBlank
        }
        $lines = $out
    }
    if ($number) {
        $i = 0
        $lines | ForEach-Object { $i++; "{0,6}  {1}" -f $i, $_ }
    } else {
        $lines
    }
}

Set-UnixCommand -Name "sort" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $unique = $false
    $descending = $false
    $numeric = $false
    $ignoreCase = $false
    $paths = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "sort" -Flag $a -SupportedFlags "-u, -r, -n, -f, --" -Usage "sort [-urnf] [--] [file...]"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'u' { $unique = $true; break }
                    'r' { $descending = $true; break }
                    'n' { $numeric = $true; break }
                    'f' { $ignoreCase = $true; break }
                    default { Show-UnsupportedFlag -Command "sort" -Flag ("-" + $ch) -SupportedFlags "-u, -r, -n, -f, --" -Usage "sort [-urnf] [--] [file...]" }
                }
            }
            continue
        }
        $paths += $a
    }

    $lines = if ($paths.Count -gt 0) { Get-Content -Path $paths } else { @($input) }
    $opts = @{}
    if ($unique) { $opts.Unique = $true }
    if ($descending) { $opts.Descending = $true }
    $opts.CaseSensitive = -not $ignoreCase

    if ($numeric) {
        $sorted = $lines | Sort-Object {[double]($_ -as [double])} @opts
    } else {
        $sorted = $lines | Sort-Object @opts
    }
    $sorted
}

Set-UnixCommand -Name "diff" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $files = @()
    $brief = $false
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "diff" -Flag $a -SupportedFlags "-u, -q, --" -Usage "diff [-uq] [--] <file1> <file2>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'u' { break }
                    'q' { $brief = $true; break }
                    default { Show-UnsupportedFlag -Command "diff" -Flag ("-" + $ch) -SupportedFlags "-u, -q, --" -Usage "diff [-uq] [--] <file1> <file2>" }
                }
            }
            continue
        }
        $files += $a
    }
    if ($files.Count -lt 2) { throw "usage: diff [-uq] [--] <file1> <file2>" }
    $result = Compare-Object -ReferenceObject (Get-Content -Path $files[0]) -DifferenceObject (Get-Content -Path $files[1])
    if ($brief) {
        if ($result) { "Files $($files[0]) and $($files[1]) differ" }
        return
    }
    $result
}

Set-UnixCommand -Name "tee" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    $append = $false
    $ignoreInterrupt = $false
    $files = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "tee" -Flag $a -SupportedFlags "-a, -i, --" -Usage "tee [-ai] [--] <file...>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'a' { $append = $true; break }
                    'i' { $ignoreInterrupt = $true; break }
                    default { Show-UnsupportedFlag -Command "tee" -Flag ("-" + $ch) -SupportedFlags "-a, -i, --" -Usage "tee [-ai] [--] <file...>" }
                }
            }
            continue
        }
        $files += $a
    }

    $lines = @($input)
    if ($files.Count -eq 0) { return $lines }
    foreach ($file in $files) {
        if ($append) { $lines | Add-Content -Path $file }
        else { $lines | Set-Content -Path $file }
    }
    $lines
}

Set-UnixCommand -Name "sleep" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
    if ($ArgList.Count -eq 0) { throw "usage: sleep <seconds>" }
    if ($ArgList[0].StartsWith("-")) {
        Show-UnsupportedFlag -Command "sleep" -Flag $ArgList[0] -SupportedFlags "NUMBER[s|m|h|d]" -Usage "sleep <seconds>|<number>[s|m|h|d]"
        return
    }
    $spec = $ArgList[0]
    $m = [regex]::Match($spec, '^\s*(?<n>\d+(?:\.\d+)?)(?<u>[smhd]?)\s*$')
    if (-not $m.Success) {
        Show-UnsupportedFlag -Command "sleep" -Flag $spec -SupportedFlags "NUMBER[s|m|h|d]" -Usage "sleep <seconds>|<number>[s|m|h|d]"
        return
    }
    $seconds = [double]$m.Groups['n'].Value
    switch ($m.Groups['u'].Value) {
        'm' { $seconds *= 60; break }
        'h' { $seconds *= 3600; break }
        'd' { $seconds *= 86400; break }
        default { }
    }
    Start-Sleep -Seconds $seconds
}
'@

    Remove-ProfileBlock -ProfilePath $profilePath -StartMarker $legacyStart -EndMarker $legacyEnd
    Upsert-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker -BlockBody $blockBody
    Write-Host "[OK] Installed/updated alias-compat profile shims in: $profilePath" -ForegroundColor Green
}

# ======================== Main Script ========================

# ---- Help (works without elevation) ----
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    return
}

if ($InstallFull -and $Uninstall) {
    throw "Cannot combine -InstallFull with -Uninstall. Choose one mode."
}

if ($InstallFull) {
    $AddMingw = $true
    $AddGitCmd = $true
    $NormalizePath = $true
    $InstallOptionalTools = $true
    $CreateShims = $true
    $InstallProfileShims = $true
}

$transcriptStarted = Start-ScriptTranscript -Path $LogPath
try {
Write-Host "`n=== Unix Tools Enabler v$ScriptVersion ===" -ForegroundColor Magenta
Write-Host "Adds Unix-compatible tools to Windows PATH ($($script:PathScope) scope)`n" -ForegroundColor Cyan
if ($InstallFull) {
    Write-Host "[INFO] -InstallFull enabled: AddMingw/AddGitCmd/NormalizePath/InstallOptionalTools/CreateShims/InstallProfileShims" -ForegroundColor DarkGray
}

Assert-Admin

$gitRoot = $null
try {
    $gitRoot = Get-GitRoot
    Write-Host "[OK] Git found at: $gitRoot`n" -ForegroundColor Green
} catch {
    if (-not $Uninstall) { throw }
    Write-Host "[INFO] Git installation not detected; uninstall will still clean profile and known shim paths." -ForegroundColor DarkGray
}

$gitUsrBin   = $null
$gitMingwBin = $null
$gitCmd      = $null
$shimDir     = $null
$userShimRoot = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
$userShimDir  = Join-Path $userShimRoot "UnixTools\shims"
if ($gitRoot) {
    $gitUsrBin   = Join-Path $gitRoot "usr\bin"
    $gitMingwBin = Join-Path $gitRoot "mingw64\bin"
    $gitCmd      = Join-Path $gitRoot "cmd"
    # Machine scope keeps shims under Git; user scope keeps shims under LocalAppData.
    if ($script:PathScope -eq "User") {
        $shimDir = $userShimDir
    } else {
        $shimDir = Join-Path $gitRoot "shims"
    }
}

$didChange = $false

if ($Uninstall) {
    Write-Host "=== Uninstall Mode ===" -ForegroundColor Yellow

    if ($script:PathScope -eq "User") {
        $candidateShimDirs = @($userShimDir)
        if ($shimDir) { $candidateShimDirs += $shimDir }
    } else {
        $candidateShimDirs = @(
            "C:\Program Files\Git\shims",
            "C:\Program Files (x86)\Git\shims"
        )
        if ($shimDir) { $candidateShimDirs += $shimDir }
    }
    $candidateShimDirs = $candidateShimDirs | Select-Object -Unique

    if ($PSCmdlet.ShouldProcess($PROFILE.CurrentUserCurrentHost, "Remove unix-tools profile shim blocks")) {
        Remove-InstalledProfileShims
        $didChange = $true
        Write-Host "[OK] Removed profile shim blocks (unix-tools/git-tools markers)" -ForegroundColor Green
    }

    foreach ($sd in $candidateShimDirs) {
        if ($PSCmdlet.ShouldProcess($script:PathDisplay, "Remove shim directory entry $sd")) {
            if (Remove-MachinePathEntries -pathsToRemove @($sd)) {
                $didChange = $true
                Write-Host "[OK] Removed from $($script:PathDisplay): $sd" -ForegroundColor Green
            }
        }
        if (Test-Path $sd -PathType Container) {
            if ($PSCmdlet.ShouldProcess($sd, "Delete generated .cmd shims")) {
                Get-ChildItem $sd -Filter *.cmd -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                try { Remove-Item $sd -Force -ErrorAction Stop } catch { }
                $didChange = $true
                Write-Host "[OK] Removed shim files from: $sd" -ForegroundColor Green
            }
        }
    }

    if ($PSCmdlet.ShouldProcess("Optional tools", "Uninstall optional tools previously installed by this script")) {
        $removedOptional = Uninstall-TrackedOptionalTools
        if ($removedOptional -gt 0) {
            $didChange = $true
            Write-Host "[OK] Removed $removedOptional tracked optional tool(s)." -ForegroundColor Green
        } else {
            Write-Host "[INFO] No tracked optional tools were removed." -ForegroundColor DarkGray
        }
    }

    if ($didChange) {
        Broadcast-EnvironmentChange
        Refresh-SessionPath
        Write-Host "[OK] Environment refresh broadcasted" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Nothing to uninstall." -ForegroundColor DarkGray
    }

    Write-Host "`nDone!`n" -ForegroundColor Green
    return
}

# ======================== Step 1: Add Tool Directories to PATH ========================

Write-Host "=== Step 1: Add tool directories to $($script:PathDisplay) ===" -ForegroundColor Yellow

$pathsToAdd = @($gitUsrBin)

if ($AddMingw) {
    if (Test-Path $gitMingwBin) { $pathsToAdd += $gitMingwBin }
    else { Write-Host "[INFO] mingw64\bin not found; skipping" -ForegroundColor DarkGray }
}

if ($AddGitCmd) {
    if (Test-Path $gitCmd) { $pathsToAdd += $gitCmd }
    else { Write-Host "[INFO] cmd not found; skipping" -ForegroundColor DarkGray }
}

$changed = $false
if ($PSCmdlet.ShouldProcess($script:PathDisplay, "Add tool directories")) {
    $changed = Add-MachinePathEntries $pathsToAdd
}

if ($changed) {
    $didChange = $true
    Write-Host "[OK] Added tool directories to $($script:PathDisplay)" -ForegroundColor Green
} else {
    Write-Host "[OK] Tool directories already in $($script:PathDisplay)" -ForegroundColor Yellow
}

if ($NormalizePath) {
    if ($PSCmdlet.ShouldProcess($script:PathDisplay, "Normalize PATH entries")) {
        Update-MachinePathEntries
        $didChange = $true
        Write-Host "[OK] Normalized $($script:PathDisplay) (removed duplicates/trailing slashes)" -ForegroundColor Green
    }
}

# ======================== Step 1b: Install Optional Tools (Optional) ========================

$optionalToolCatalog = Get-OptionalToolCatalog
if ($InstallOptionalTools) {
    Write-Host "`n=== Step 1b: Install missing optional CLI tools ===" -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess("Optional tools", "Install missing optional tools via package managers")) {
        $installedOptional = @(Install-MissingOptionalTools -Catalog $optionalToolCatalog)
        if ($installedOptional.Count -gt 0) {
            $didChange = $true
            Write-Host "[OK] Installed $($installedOptional.Count) missing optional tool(s)." -ForegroundColor Green
            Write-Host "[INFO] Tracking file: $(Get-OptionalToolsStatePath)" -ForegroundColor DarkGray
        } else {
            Write-Host "[OK] No optional tool installs were needed." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Skipped by -WhatIf/-Confirm: optional tool installation." -ForegroundColor DarkGray
    }
} else {
    Write-Host "`n=== Step 1b: Optional tools ===" -ForegroundColor Yellow
    Write-Host "Skipped. Use -InstallOptionalTools to auto-install rg/fd/jq/yq/bat/eza/fzf/ag/ack/ncat when missing." -ForegroundColor DarkGray
}

# ======================== Step 2: Create Shims (Optional) ========================

if ($CreateShims) {
    Write-Host "`n=== Step 2: Create priority shims ===" -ForegroundColor Yellow
    Write-Host "Shim location: $shimDir" -ForegroundColor Cyan

    if ($PSCmdlet.ShouldProcess($shimDir, "Create/refresh shim .cmd files and prepend shim dir to $($script:PathDisplay)")) {
        New-DirectoryIfMissing $shimDir

        # Clear stale shims (avoid dead shims after Git upgrades)
        Get-ChildItem $shimDir -Filter *.cmd -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

        # Coverage baseline expanded from common Unix/Linux command references.
        $toolsToShim = @(
            # Text search & processing
            "grep", "egrep", "fgrep", "sed", "awk", "gawk",
            "apropos", "aspell",

            # File ops (NOTE: rd shim won't override CMD/PowerShell built-in)
            "find", "cat", "cp", "mv", "rm", "rmdir", "touch", "ln", "ls",
            "pwd", "basename", "dirname", "realpath", "file", "which", "vdir", "link", "rename",
            "chmod", "chown", "chgrp", "stat", "install", "mktemp", "setfacl", "getfacl",
            "readlink", "truncate",

            # Text manipulation
            "sort", "uniq", "tr", "cut", "paste", "join", "comm", "split",
            "fmt", "fold", "expand", "unexpand", "strings", "nl",
            "shuf", "csplit", "tsort", "numfmt", "column",

            # File viewing
            "less", "more", "head", "tail", "tac", "rev", "od", "xxd",

            # Comparison
            "diff", "diff3", "cmp", "patch", "sdiff",

            # Compression / archives
            "tar", "gzip", "gunzip", "zip", "unzip", "bzip2", "bunzip2", "xz", "unxz", "cpio",

            # Stream processing
            "xargs", "tee", "wc", "iconv", "pv",

            # Utilities
            "env", "expr", "seq", "yes", "base32", "base64", "printf", "echo", "test", "true", "false",
            "bc", "cal", "cksum", "sum", "sync", "tput", "pr", "at",
            "tty", "nproc", "timeout", "factor", "stdbuf", "printenv",
            "dircolors", "pathchk", "mkfifo", "users", "logname", "groups",
            "date", "sleep", "time", "uname", "hostname", "whoami", "id", "who", "w", "last",
            "md5sum", "sha1sum", "sha256sum",
            "df", "du", "dd", "man", "whereis", "locate", "updatedb", "crontab",
            "ps", "top", "kill", "killall", "pkill", "pgrep", "nice", "renice", "nohup",
            "free", "uptime", "vmstat", "dmesg", "lsof", "htop", "watch",
            "sudo", "su",

            # Network
            "curl", "wget", "ping", "traceroute", "nslookup", "dig", "host", "whois",
            "netstat", "ss", "ifconfig", "ip", "route", "arp", "ncat",
            "ssh", "ssh-keygen", "ssh-agent", "ssh-add", "scp", "sftp", "ftp", "telnet", "rsync", "nc",
            "open", "xdg-open",

            # Shells
            "bash", "sh", "perl", "make",

            # Editors
            "nano", "vi", "vim", "dos2unix", "unix2dos",

            # Security / crypto
            "openssl", "gpg"
        )

        # Optional third-party tools that may already be installed in PATH.
        $externalTools = @($optionalToolCatalog | ForEach-Object { $_.Command })

        $searchDirs = @($gitUsrBin)
        if ($AddMingw -and (Test-Path $gitMingwBin)) { $searchDirs += $gitMingwBin }
        $appIndex = Get-ApplicationCommandIndex -excludeDir $shimDir

        $shimmed = 0
        $notFound = 0
        $notFoundTools = New-Object System.Collections.Generic.List[string]

        # Shim discovered Unix tools from configured search dirs; if missing there,
        # try PATH executables so we can also cover non-Git providers.
        foreach ($tool in $toolsToShim) {
            $toolPath = Find-Tool -toolName $tool -searchDirs $searchDirs
            if (-not $toolPath) {
                $toolPath = Find-ToolInPath -toolName $tool -excludeDir $shimDir -AppIndex $appIndex
                if (-not $toolPath -and $tool -eq "nc") {
                    # nmap ships ncat.exe; expose it as nc when nc.exe is absent.
                    $toolPath = Find-ToolInPath -toolName "ncat" -excludeDir $shimDir -AppIndex $appIndex
                }
            }
            if ($toolPath) {
                if (Write-ShimCmd -shimDir $shimDir -name $tool -targetExePath $toolPath) { $shimmed++ }
            } else {
                $notFound++
                $notFoundTools.Add($tool) | Out-Null
            }
        }

        # Shim optional third-party tools if installed
        foreach ($tool in $externalTools) {
            $toolPath = Find-ToolInPath -toolName $tool -excludeDir $shimDir -AppIndex $appIndex
            if ($toolPath) {
                if (Write-ShimCmd -shimDir $shimDir -name $tool -targetExePath $toolPath) {
                    $shimmed++
                    Write-Host "  [OK] Found external tool: $tool" -ForegroundColor Green
                }
            } else {
                Write-Host "  [INFO] Optional tool not installed: $tool" -ForegroundColor DarkGray
            }
        }

        Add-MachinePathPrepend $shimDir
        $didChange = $true
        Write-Host "[OK] Created $shimmed shims in $shimDir (stale shims cleared first)" -ForegroundColor Green
        Write-Host "[OK] Shim directory prepended to $($script:PathDisplay) (takes priority)" -ForegroundColor Green
        if ($notFound -gt 0) {
            Write-Host "[INFO] $notFound requested tools not found (normal)" -ForegroundColor DarkGray
            $missing = @($notFoundTools | Sort-Object -Unique)
            Write-Host "[INFO] Missing tools: $($missing -join ', ')" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "Skipped by -WhatIf/-Confirm: shim generation and PATH prepend." -ForegroundColor DarkGray
    }
} else {
    Write-Host "`n=== Step 2: Shims ===" -ForegroundColor Yellow
    Write-Host "Skipped. Use -CreateShims for guaranteed priority." -ForegroundColor DarkGray
}

# ======================== Step 2b: Install Profile Shims (Optional) ========================

if ($InstallProfileShims) {
    Write-Host "`n=== Step 2b: Install profile shims and alias compatibility ===" -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess($PROFILE.CurrentUserCurrentHost, "Install/update unix-tools profile shim blocks")) {
        Install-ProfileMissingShims
        Install-ProfileAliasCompat
        $didChange = $true
    } else {
        Write-Host "Skipped by -WhatIf/-Confirm: profile shim installation." -ForegroundColor DarkGray
    }
} else {
    Write-Host "`n=== Step 2b: Profile shims ===" -ForegroundColor Yellow
    Write-Host "Skipped. Use -InstallProfileShims to add missing PowerShell-only commands and alias compatibility wrappers." -ForegroundColor DarkGray
}

# ======================== Step 3: Broadcast / Refresh ========================

Write-Host "`n=== Step 3: Notify system of environment changes ===" -ForegroundColor Yellow
if ($didChange) {
    Broadcast-EnvironmentChange
    Write-Host "[OK] Notified Windows Explorer of PATH changes" -ForegroundColor Green
} else {
    Write-Host "[INFO] No environment changes were applied in this run." -ForegroundColor DarkGray
}

# ======================== Step 4: Verification ========================

Write-Host "`n=== Step 4: Verification ===" -ForegroundColor Yellow
Refresh-SessionPath

$verifyTools = @("grep","sed","awk","find","bash")
$verifyCommandCache = @{}
foreach ($tool in $verifyTools) {
    $verifyCommandCache[$tool] = @(Get-Command $tool -All -ErrorAction SilentlyContinue)
}

foreach ($tool in $verifyTools) {
    $cmds = @($verifyCommandCache[$tool])
    if (-not $cmds) {
        Write-Host "  [FAIL] $tool (not found in this session; open a NEW terminal)" -ForegroundColor Red
        continue
    }

    $top = $cmds | Select-Object -First 3
    $lines = @()
    foreach ($c in $top) {
        $src = $c.Source
        if ($CreateShims -and $src -like "*\shims\*") {
            $shimContent = Get-Content $src -Raw -ErrorAction SilentlyContinue
            $target = $null
            if ($shimContent -match '"([^"]+\.exe)"') { $target = $matches[1] }
            if ($target) { $lines += "shim -> $(Split-Path $target -Leaf)" }
            else         { $lines += "shim" }
        } elseif ($src -like "*\Git\*") {
            $lines += "Git -> $(Split-Path $src -Leaf)"
        } else {
            $lines += "$(Split-Path $src -Leaf)"
        }
    }

    Write-Host ("  [OK] {0} -> {1}" -f $tool, ($lines -join " | ")) -ForegroundColor Green
}

if ($InstallProfileShims) {
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $profileText = Get-Content -Path $profilePath -Raw -ErrorAction SilentlyContinue
    $hasMissingBlock = $profileText -and $profileText.Contains("# >>> unix-tools-missing-shims >>>") -and $profileText.Contains("# <<< unix-tools-missing-shims <<<")
    $hasAliasBlock = $profileText -and $profileText.Contains("# >>> unix-tools-alias-compat >>>") -and $profileText.Contains("# <<< unix-tools-alias-compat <<<")

    if ($hasMissingBlock) {
        Write-Host "  [OK] missing-command profile shims block present in $profilePath" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] missing-command profile shims block not found in $profilePath" -ForegroundColor Red
    }

    if ($hasAliasBlock) {
        Write-Host "  [OK] alias-compat profile shims block present in $profilePath" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] alias-compat profile shims block not found in $profilePath" -ForegroundColor Red
    }
}

Write-Host "`n=== Important Notes ===" -ForegroundColor Yellow
Write-Host "- Shell built-ins (rd, dir, copy, del) CANNOT be overridden by shims" -ForegroundColor White
Write-Host "- Use Unix equivalents instead: rm -r (for rd), ls (for dir), cp (for copy)" -ForegroundColor White
Write-Host "- Optional extras: rg, fd, jq, yq, bat, eza, fzf, ag, ack, ncat (use -InstallOptionalTools)" -ForegroundColor White
Write-Host "- On -Uninstall, tracked optional tools installed by this script are removed." -ForegroundColor White
Write-Host "- One-shot setup: .\Enable-UnixToolsSystemWide.ps1 -InstallFull" -ForegroundColor White
Write-Host "- User-scope setup: .\Enable-UnixToolsSystemWide.ps1 -InstallFull -UserScope" -ForegroundColor White
if ($CreateShims) {
    Write-Host "- Shims are located in: $shimDir" -ForegroundColor Cyan
    if ($script:PathScope -eq "Machine") {
        Write-Host "- Uninstalling Git will remove shims automatically" -ForegroundColor Cyan
    } else {
        Write-Host "- User-scope shims are managed under LocalAppData and are removed by -Uninstall -UserScope" -ForegroundColor Cyan
    }
}
if ($InstallProfileShims) {
    Write-Host "- Missing-command profile shims installed for: export, rev, unset, mkdirp, ll, clear-hist, clear, pwd, history, touch, head, tail, wc, grep, egrep, fgrep, nc, which, man, source, apropos, make, open, xdg-open, rename, dos2unix, unix2dos, vdir, link, tput, sync, at, aspell, bc, cal, base64, base32, cksum, sum, pv, pr, cpio" -ForegroundColor Cyan
    Write-Host "- Alias-compat wrappers installed for common commands: rm, cp, mv, mkdir, ls, cat, sort, diff, tee, sleep" -ForegroundColor Cyan
    Write-Host "- Profile shims are idempotent and stored in marker blocks under your profile" -ForegroundColor Cyan
    Write-Host "- Coverage report command: Show-UnixCoverageReport -IncludeMissing" -ForegroundColor Cyan
}
if ($InstallOptionalTools) {
    Write-Host "- Optional tool auto-install attempted via winget/choco/scoop for missing commands." -ForegroundColor Cyan
    Write-Host "- Installed optional tools are tracked for clean removal during -Uninstall." -ForegroundColor Cyan
}
Write-Host "- Uninstall support: .\Enable-UnixToolsSystemWide.ps1 -Uninstall (Machine) or -Uninstall -UserScope (User)" -ForegroundColor White

Write-Host "`n=== Next Steps ===" -ForegroundColor Yellow
Write-Host "1) Close this terminal" -ForegroundColor White
Write-Host "2) Open a NEW PowerShell/CMD window" -ForegroundColor White
Write-Host "3) Test:" -ForegroundColor White
Write-Host "   where.exe grep" -ForegroundColor Cyan
Write-Host "   grep --version" -ForegroundColor Cyan
Write-Host "   Get-Command grep -All" -ForegroundColor Cyan
if ($InstallProfileShims) {
    Write-Host "   export DEMO_VAR=ok" -ForegroundColor Cyan
    Write-Host "   'stressed' | rev" -ForegroundColor Cyan
    Write-Host "   rm -rf .\tmp" -ForegroundColor Cyan
    Write-Host "   ls -la" -ForegroundColor Cyan
    Write-Host "   Show-UnixCoverageReport -IncludeMissing" -ForegroundColor Cyan
}
if ($InstallOptionalTools) {
    Write-Host "   rg --version" -ForegroundColor Cyan
    Write-Host "   fd --version" -ForegroundColor Cyan
    Write-Host "   jq --version" -ForegroundColor Cyan
}

Write-Host "`nDone!`n" -ForegroundColor Green

} finally {
    if ($transcriptStarted) {
        Stop-ScriptTranscript
    }
}

