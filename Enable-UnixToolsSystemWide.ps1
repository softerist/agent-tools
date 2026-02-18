# Enable-UnixToolsSystemWide.ps1
# Adds Unix-compatible tools (grep, sed, awk, etc.) to the system PATH
# Run in an elevated PowerShell (Run as Administrator)
#
# Usage:
#   .\Enable-UnixToolsSystemWide.ps1
#   .\Enable-UnixToolsSystemWide.ps1 -CreateShims
#   .\Enable-UnixToolsSystemWide.ps1 -AddMingw -AddGitCmd
#   .\Enable-UnixToolsSystemWide.ps1 -CreateShims -AddMingw -AddGitCmd
#   .\Enable-UnixToolsSystemWide.ps1 -NormalizePath
#   .\Enable-UnixToolsSystemWide.ps1 -InstallProfileShims
#   .\Enable-UnixToolsSystemWide.ps1 -CreateShims -InstallProfileShims

param(
    [switch]$CreateShims,
    [switch]$AddMingw,
    [switch]$AddGitCmd,
    [switch]$NormalizePath,
    [switch]$InstallProfileShims
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ======================== Functions ========================

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run PowerShell as Administrator."
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

function Prepend-ToMachinePath([string]$pathToPrepend) {
    $norm = $pathToPrepend.Trim().TrimEnd('\')
    if (-not (Test-Path $norm)) {
        throw "Path does not exist: $norm"
    }

    $current = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (-not $current) { $current = "" }

    $parts = $current.Split(';') | Where-Object { $_ -and $_.Trim() -ne "" }

    # Remove existing entry (case-insensitive)
    $parts = $parts | Where-Object {
        -not $_.Trim().TrimEnd('\').Equals($norm, [StringComparison]::OrdinalIgnoreCase)
    }

    $newPath = (@($norm) + $parts) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
}

function Append-ToMachinePath([string[]]$pathsToAdd) {
    $current = [Environment]::GetEnvironmentVariable("Path", "Machine")
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
        [Environment]::SetEnvironmentVariable("Path", ($parts -join ';'), "Machine")
    }

    return $changed
}

function Normalize-MachinePath {
    $current = [Environment]::GetEnvironmentVariable("Path","Machine")
    if (-not $current) { return }

    $parts = $current.Split(';') | Where-Object { $_ -and $_.Trim() -ne "" }

    $seen = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    $newParts = New-Object System.Collections.Generic.List[string]

    foreach ($p in $parts) {
        $n = $p.Trim().TrimEnd('\')
        if ($n -and $seen.Add($n)) { $newParts.Add($n) }
    }

    [Environment]::SetEnvironmentVariable("Path", ($newParts -join ';'), "Machine")
}

function Ensure-Dir([string]$dir) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}

function Write-ShimCmd([string]$shimDir, [string]$name, [string]$targetExePath) {
    if (-not (Test-Path $targetExePath)) { return $false }

    $shimPath = Join-Path $shimDir "$name.cmd"
    $content = "@echo off`r`n""$targetExePath"" %*`r`n"
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

function Find-ToolInPath([string]$toolName, [string]$excludeDir = $null) {
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

    $pattern = "(?s)$([regex]::Escape($StartMarker)).*?$([regex]::Escape($EndMarker))\r?\n?"
    if ([regex]::IsMatch($existing, $pattern)) {
        $updated = [regex]::Replace($existing, $pattern, $newBlock, 1)
    } else {
        if ($existing.Length -gt 0 -and -not $existing.EndsWith("`r`n")) {
            $existing += "`r`n"
        }
        $updated = $existing + $newBlock
    }

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

    $pattern = "(?s)$([regex]::Escape($StartMarker)).*?$([regex]::Escape($EndMarker))\r?\n?"
    if ([regex]::IsMatch($existing, $pattern)) {
        $updated = [regex]::Replace($existing, $pattern, "", 1)
        Set-Content -Path $ProfilePath -Value $updated -Encoding UTF8
    }
}

function Install-ProfileMissingShims {
    $profilePath = $PROFILE.CurrentUserCurrentHost
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
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
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
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $items = Get-History
    if ($Args.Count -gt 0) {
        $count = 0
        if ([int]::TryParse($Args[0], [ref]$count) -and $count -gt 0) {
            $items | Select-Object -Last $count
            return
        }
    }
    $items
}

Add-UnixShimIfMissing -Name "grep" -Body {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)

    $ignoreCase = $false
    $lineNumber = $false
    $invert = $false
    $recursive = $false
    $pattern = $null
    $paths = @()

    foreach ($a in $Args) {
        if ($a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'i' { $ignoreCase = $true; continue }
                    'n' { $lineNumber = $true; continue }
                    'v' { $invert = $true; continue }
                    'r' { $recursive = $true; continue }
                    'R' { $recursive = $true; continue }
                    default { throw "grep: unsupported option -$ch (fallback supports -i, -n, -v, -r)" }
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

    $isCaseSensitive = -not $ignoreCase
    $result = $null

    if ($paths.Count -gt 0) {
        if ($recursive) {
            $targets = @()
            foreach ($p in $paths) {
                if (Test-Path -Path $p -PathType Container) { $targets += (Join-Path $p "*") }
                else { $targets += $p }
            }
            $result = Select-String -Pattern $pattern -Path $targets -Recurse -CaseSensitive:$isCaseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
        } else {
            $result = Select-String -Pattern $pattern -Path $paths -CaseSensitive:$isCaseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
        }
    } else {
        $inputItems = @($input)
        if ($inputItems.Count -gt 0) {
            $result = $inputItems | Select-String -Pattern $pattern -CaseSensitive:$isCaseSensitive -NotMatch:$invert
        } else {
            $defaultPath = if ($recursive) { @(".\*") } else { @(".") }
            $result = Select-String -Pattern $pattern -Path $defaultPath -Recurse:$recursive -CaseSensitive:$isCaseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
        }
    }

    if ($lineNumber) {
        $result | ForEach-Object { "{0}:{1}:{2}" -f $_.Path, $_.LineNumber, $_.Line }
    } else {
        $result
    }
}
'@

    Remove-ProfileBlock -ProfilePath $profilePath -StartMarker $legacyStart -EndMarker $legacyEnd
    Upsert-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker -BlockBody $blockBody
    Write-Host "✓ Installed/updated missing-command profile shims in: $profilePath" -ForegroundColor Green
}

function Install-ProfileAliasCompat {
    $profilePath = $PROFILE.CurrentUserCurrentHost
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
        "$Command: unsupported option '$Flag'",
        "Supported flags in fallback: $SupportedFlags",
        "",
        "How to add support for this flag:",
        "1) Open `$PROFILE and find marker: # >>> unix-tools-alias-compat >>>",
        "2) Find: Set-UnixCommand -Name ""$Command"" -Fallback { ... }",
        "3) Extend that parser switch/if to handle '$Flag'",
        "4) Or update installer block and re-run: Enable-UnixToolsSystemWide.ps1 -InstallProfileShims",
        "",
        "Usage: $Usage"
    ) -join [Environment]::NewLine

    throw $message
}

Set-UnixCommand -Name "rm" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $recurse = $false
    $force = $false
    $paths = @()
    foreach ($a in $Args) {
        if ($a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'r' { $recurse = $true; continue }
                    'R' { $recurse = $true; continue }
                    'f' { $force = $true; continue }
                    default { Show-UnsupportedFlag -Command "rm" -Flag ("-" + $ch) -SupportedFlags "-r, -R, -f" -Usage "rm [-rf] <path...>" }
                }
            }
        } else {
            $paths += $a
        }
    }
    if ($paths.Count -eq 0) { throw "usage: rm [-rf] <path...>" }
    Remove-Item -Path $paths -Recurse:$recurse -Force:$force
}

Set-UnixCommand -Name "cp" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $recurse = $false
    $force = $false
    $items = @()
    foreach ($a in $Args) {
        if ($a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'r' { $recurse = $true; continue }
                    'R' { $recurse = $true; continue }
                    'f' { $force = $true; continue }
                    default { Show-UnsupportedFlag -Command "cp" -Flag ("-" + $ch) -SupportedFlags "-r, -R, -f" -Usage "cp [-rf] <src...> <dest>" }
                }
            }
        } else {
            $items += $a
        }
    }
    if ($items.Count -lt 2) { throw "usage: cp [-rf] <src...> <dest>" }
    $dest = $items[-1]
    $src = $items[0..($items.Count - 2)]
    Copy-Item -Path $src -Destination $dest -Recurse:$recurse -Force:$force
}

Set-UnixCommand -Name "mv" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $force = $false
    $items = @()
    foreach ($a in $Args) {
        if ($a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'f' { $force = $true; continue }
                    default { Show-UnsupportedFlag -Command "mv" -Flag ("-" + $ch) -SupportedFlags "-f" -Usage "mv [-f] <src...> <dest>" }
                }
            }
        } else {
            $items += $a
        }
    }
    if ($items.Count -lt 2) { throw "usage: mv [-f] <src...> <dest>" }
    $dest = $items[-1]
    $src = $items[0..($items.Count - 2)]
    Move-Item -Path $src -Destination $dest -Force:$force
}

Set-UnixCommand -Name "mkdir" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $p = $false
    $paths = @()
    foreach ($a in $Args) {
        if ($a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'p' { $p = $true; continue }
                    default { Show-UnsupportedFlag -Command "mkdir" -Flag ("-" + $ch) -SupportedFlags "-p" -Usage "mkdir [-p] <dir...>" }
                }
            }
        } else {
            $paths += $a
        }
    }
    if ($paths.Count -eq 0) { throw "usage: mkdir [-p] <dir...>" }
    foreach ($path in $paths) {
        New-Item -ItemType Directory -Path $path -Force:$p | Out-Null
    }
}

Set-UnixCommand -Name "ls" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $all = $false
    $long = $false
    $paths = @()
    foreach ($a in $Args) {
        if ($a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'a' { $all = $true; continue }
                    'l' { $long = $true; continue }
                    default { Show-UnsupportedFlag -Command "ls" -Flag ("-" + $ch) -SupportedFlags "-a, -l" -Usage "ls [-la] [path...]" }
                }
            }
        } else {
            $paths += $a
        }
    }
    if ($paths.Count -eq 0) { $paths = @(".") }
    $items = Get-ChildItem -Path $paths -Force:$all
    if ($long) {
        $items | Format-Table Mode, LastWriteTime, @{N='Length';E={ if ($_.PSIsContainer) { '' } else { $_.Length } }}, Name -AutoSize
    } else {
        $items
    }
}

Set-UnixCommand -Name "cat" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $number = $false
    $paths = @()
    foreach ($a in $Args) {
        if ($a -eq "-n") { $number = $true; continue }
        if ($a -match '^-[A-Za-z]+$') { Show-UnsupportedFlag -Command "cat" -Flag $a -SupportedFlags "-n" -Usage "cat [-n] [file...]" }
        $paths += $a
    }

    $lines = if ($paths.Count -gt 0) { Get-Content -Path $paths } else { @($input) }
    if ($number) {
        $i = 0
        $lines | ForEach-Object { $i++; "{0,6}  {1}" -f $i, $_ }
    } else {
        $lines
    }
}

Set-UnixCommand -Name "sort" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $unique = $false
    $paths = @()
    foreach ($a in $Args) {
        if ($a -eq "-u") { $unique = $true; continue }
        if ($a -match '^-[A-Za-z]+$') { Show-UnsupportedFlag -Command "sort" -Flag $a -SupportedFlags "-u" -Usage "sort [-u] [file...]" }
        $paths += $a
    }

    $lines = if ($paths.Count -gt 0) { Get-Content -Path $paths } else { @($input) }
    if ($unique) { $lines | Sort-Object -Unique } else { $lines | Sort-Object }
}

Set-UnixCommand -Name "diff" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $files = @()
    foreach ($a in $Args) {
        if ($a -eq "-u") { continue }
        if ($a -match '^-[A-Za-z]+$') { Show-UnsupportedFlag -Command "diff" -Flag $a -SupportedFlags "-u" -Usage "diff [-u] <file1> <file2>" }
        $files += $a
    }
    if ($files.Count -lt 2) { throw "usage: diff [-u] <file1> <file2>" }
    Compare-Object -ReferenceObject (Get-Content -Path $files[0]) -DifferenceObject (Get-Content -Path $files[1])
}

Set-UnixCommand -Name "tee" -Fallback {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $append = $false
    $files = @()
    foreach ($a in $Args) {
        if ($a -eq "-a") { $append = $true; continue }
        if ($a -match '^-[A-Za-z]+$') { Show-UnsupportedFlag -Command "tee" -Flag $a -SupportedFlags "-a" -Usage "tee [-a] <file...>" }
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
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    if ($Args.Count -eq 0) { throw "usage: sleep <seconds>" }
    $seconds = [double]$Args[0]
    Start-Sleep -Seconds $seconds
}
'@

    Remove-ProfileBlock -ProfilePath $profilePath -StartMarker $legacyStart -EndMarker $legacyEnd
    Upsert-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker -BlockBody $blockBody
    Write-Host "✓ Installed/updated alias-compat profile shims in: $profilePath" -ForegroundColor Green
}

# ======================== Main Script ========================

Write-Host "`n=== Unix Tools System-Wide Enabler ===" -ForegroundColor Magenta
Write-Host "Adds Unix-compatible tools to the system PATH`n" -ForegroundColor Cyan

Assert-Admin

$gitRoot = Get-GitRoot
Write-Host "✓ Git found at: $gitRoot`n" -ForegroundColor Green

$gitUsrBin   = Join-Path $gitRoot "usr\bin"
$gitMingwBin = Join-Path $gitRoot "mingw64\bin"
$gitCmd      = Join-Path $gitRoot "cmd"

# Dynamic shim directory inside Git installation
$shimDir = Join-Path $gitRoot "shims"

# ======================== Step 1: Add Tool Directories to PATH ========================

Write-Host "=== Step 1: Add tool directories to Machine PATH ===" -ForegroundColor Yellow

$pathsToAdd = @($gitUsrBin)

if ($AddMingw) {
    if (Test-Path $gitMingwBin) { $pathsToAdd += $gitMingwBin }
    else { Write-Host "ℹ mingw64\bin not found; skipping" -ForegroundColor DarkGray }
}

if ($AddGitCmd) {
    if (Test-Path $gitCmd) { $pathsToAdd += $gitCmd }
    else { Write-Host "ℹ cmd not found; skipping" -ForegroundColor DarkGray }
}

$changed = Append-ToMachinePath $pathsToAdd

if ($changed) { Write-Host "✓ Added tool directories to Machine PATH" -ForegroundColor Green }
else          { Write-Host "✓ Tool directories already in Machine PATH" -ForegroundColor Yellow }

if ($NormalizePath) {
    Normalize-MachinePath
    Write-Host "✓ Normalized Machine PATH (removed duplicates/trailing slashes)" -ForegroundColor Green
}

# ======================== Step 2: Create Shims (Optional) ========================

if ($CreateShims) {
    Write-Host "`n=== Step 2: Create priority shims ===" -ForegroundColor Yellow
    Write-Host "Shim location: $shimDir" -ForegroundColor Cyan

    Ensure-Dir $shimDir

    # Clear stale shims (avoid dead shims after Git upgrades)
    Get-ChildItem $shimDir -Filter *.cmd -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

    # Coverage baseline expanded from common Unix/Linux command references.
    $toolsToShim = @(
        # Text search & processing
        "grep", "sed", "awk", "gawk",

        # File ops (NOTE: rd shim won't override CMD/PowerShell built-in)
        "find", "cat", "cp", "mv", "rm", "rmdir", "touch", "ln", "ls",
        "pwd", "basename", "dirname", "realpath", "file", "which",
        "chmod", "chown", "chgrp", "stat", "install", "mktemp", "setfacl", "getfacl",

        # Text manipulation
        "sort", "uniq", "tr", "cut", "paste", "join", "comm", "split",
        "fmt", "fold", "expand", "unexpand", "strings", "nl",

        # File viewing
        "less", "more", "head", "tail", "tac", "rev", "od",

        # Comparison
        "diff", "diff3", "cmp", "patch", "sdiff",

        # Compression / archives
        "tar", "gzip", "gunzip", "zip", "unzip", "bzip2", "bunzip2", "xz", "unxz",

        # Stream processing
        "xargs", "tee", "wc",

        # Utilities
        "env", "expr", "seq", "yes", "base64", "printf",
        "date", "sleep", "time", "uname", "hostname", "whoami", "id", "who", "w", "last",
        "md5sum", "sha1sum", "sha256sum",
        "df", "du", "dd", "man", "whereis", "locate", "updatedb", "crontab",
        "ps", "top", "kill", "killall", "pkill", "pgrep", "nice", "renice", "nohup",
        "free", "uptime", "vmstat", "dmesg", "lsof",
        "sudo", "su",

        # Network
        "curl", "wget", "ping", "traceroute", "nslookup", "dig", "host",
        "netstat", "ss", "ifconfig", "ip", "route", "arp",
        "ssh", "scp", "sftp", "ftp", "telnet", "rsync",

        # Shells
        "bash", "sh",

        # Editors
        "nano", "vi", "vim"
    )

    # Optional third-party tools that may already be installed in PATH.
    $externalTools = @(
        "rg", "fd", "jq", "yq", "bat", "eza", "fzf"
    )

    $searchDirs = @($gitUsrBin)
    if ($AddMingw -and (Test-Path $gitMingwBin)) { $searchDirs += $gitMingwBin }

    $shimmed = 0
    $notFound = 0

    # Shim discovered Unix tools from configured search dirs; if missing there,
    # try PATH executables so we can also cover non-Git providers.
    foreach ($tool in $toolsToShim) {
        $toolPath = Find-Tool -toolName $tool -searchDirs $searchDirs
        if (-not $toolPath) {
            $toolPath = Find-ToolInPath -toolName $tool -excludeDir $shimDir
        }
        if ($toolPath) {
            if (Write-ShimCmd -shimDir $shimDir -name $tool -targetExePath $toolPath) { $shimmed++ }
        } else {
            $notFound++
        }
    }

    # Shim optional third-party tools if installed
    foreach ($tool in $externalTools) {
        $toolPath = Find-ToolInPath -toolName $tool -excludeDir $shimDir
        if ($toolPath) {
            if (Write-ShimCmd -shimDir $shimDir -name $tool -targetExePath $toolPath) {
                $shimmed++
                Write-Host "  ✓ Found external tool: $tool" -ForegroundColor Green
            }
        } else {
            Write-Host "  ℹ Optional tool not installed: $tool" -ForegroundColor DarkGray
        }
    }

    Prepend-ToMachinePath $shimDir
    Write-Host "✓ Created $shimmed shims in $shimDir (stale shims cleared first)" -ForegroundColor Green
    Write-Host "✓ Shim directory prepended to Machine PATH (takes priority)" -ForegroundColor Green
    if ($notFound -gt 0) { Write-Host "ℹ $notFound requested tools not found (normal)" -ForegroundColor DarkGray }
} else {
    Write-Host "`n=== Step 2: Shims ===" -ForegroundColor Yellow
    Write-Host "Skipped. Use -CreateShims for guaranteed priority." -ForegroundColor DarkGray
}

# ======================== Step 2b: Install Profile Shims (Optional) ========================

if ($InstallProfileShims) {
    Write-Host "`n=== Step 2b: Install profile shims and alias compatibility ===" -ForegroundColor Yellow
    Install-ProfileMissingShims
    Install-ProfileAliasCompat
} else {
    Write-Host "`n=== Step 2b: Profile shims ===" -ForegroundColor Yellow
    Write-Host "Skipped. Use -InstallProfileShims to add missing PowerShell-only commands and alias compatibility wrappers." -ForegroundColor DarkGray
}

# ======================== Step 3: Broadcast / Refresh ========================

Write-Host "`n=== Step 3: Notify system of environment changes ===" -ForegroundColor Yellow
Broadcast-EnvironmentChange
Write-Host "✓ Notified Windows Explorer of PATH changes" -ForegroundColor Green

# ======================== Step 4: Verification ========================

Write-Host "`n=== Step 4: Verification ===" -ForegroundColor Yellow
Refresh-SessionPath

$verifyTools = @("grep","sed","awk","find","bash")
foreach ($tool in $verifyTools) {
    $cmds = Get-Command $tool -All -ErrorAction SilentlyContinue
    if (-not $cmds) {
        Write-Host "  ✗ $tool (not found in this session; open a NEW terminal)" -ForegroundColor Red
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
            if ($target) { $lines += "shim → $(Split-Path $target -Leaf)" }
            else         { $lines += "shim" }
        } elseif ($src -like "*\Git\*") {
            $lines += "Git → $(Split-Path $src -Leaf)"
        } else {
            $lines += "$(Split-Path $src -Leaf)"
        }
    }

    Write-Host ("  ✓ {0} → {1}" -f $tool, ($lines -join " | ")) -ForegroundColor Green
}

if ($InstallProfileShims) {
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $profileText = Get-Content -Path $profilePath -Raw -ErrorAction SilentlyContinue
    $hasMissingBlock = $profileText -and $profileText.Contains("# >>> unix-tools-missing-shims >>>") -and $profileText.Contains("# <<< unix-tools-missing-shims <<<")
    $hasAliasBlock = $profileText -and $profileText.Contains("# >>> unix-tools-alias-compat >>>") -and $profileText.Contains("# <<< unix-tools-alias-compat <<<")

    if ($hasMissingBlock) {
        Write-Host "  ✓ missing-command profile shims block present in $profilePath" -ForegroundColor Green
    } else {
        Write-Host "  ✗ missing-command profile shims block not found in $profilePath" -ForegroundColor Red
    }

    if ($hasAliasBlock) {
        Write-Host "  ✓ alias-compat profile shims block present in $profilePath" -ForegroundColor Green
    } else {
        Write-Host "  ✗ alias-compat profile shims block not found in $profilePath" -ForegroundColor Red
    }
}

Write-Host "`n=== Important Notes ===" -ForegroundColor Yellow
Write-Host "• Shell built-ins (rd, dir, copy, del) CANNOT be overridden by shims" -ForegroundColor White
Write-Host "• Use Unix equivalents instead: rm -r (for rd), ls (for dir), cp (for copy)" -ForegroundColor White
Write-Host "• Optional extras if desired: rg, fd, jq, yq, bat, eza, fzf (install via winget/choco/scoop)" -ForegroundColor White
if ($CreateShims) {
    Write-Host "• Shims are located in: $shimDir" -ForegroundColor Cyan
    Write-Host "• Uninstalling Git will remove shims automatically" -ForegroundColor Cyan
}
if ($InstallProfileShims) {
    Write-Host "• Missing-command profile shims installed for: export, rev, unset, mkdirp, ll, clear-hist, clear, pwd, history, grep" -ForegroundColor Cyan
    Write-Host "• Alias-compat wrappers installed for common commands: rm, cp, mv, mkdir, ls, cat, sort, diff, tee, sleep" -ForegroundColor Cyan
    Write-Host "• Profile shims are idempotent and stored in marker blocks under your profile" -ForegroundColor Cyan
}

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
}

Write-Host "`nDone! 🎉`n" -ForegroundColor Green

