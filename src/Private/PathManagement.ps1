function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    $warnOnStderr = $false
    if ($Arguments -and $Arguments -contains '-WarnOnStderr') {
        $warnOnStderr = $true
        $Arguments = @($Arguments | Where-Object { $_ -ne '-WarnOnStderr' })
    }
    if ($warnOnStderr) {
        $output = & $Command @Arguments 2>&1
        $stderr = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $stdout = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
        $stdout
        foreach ($line in $stderr) { Write-Warning "[$Command stderr] $line" }
    }
    else {
        & $Command @Arguments
    }
    return $LASTEXITCODE
}

function Backup-PathVariable {
    param([string]$Scope = "Machine")
    $current = [Environment]::GetEnvironmentVariable("Path", $Scope)
    if ([string]::IsNullOrWhiteSpace($current)) { return }
    $backupDir = if ($Scope -eq "User") {
        $userBase = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
        Join-Path $userBase "UnixToolsSystemWide"
    }
    else {
        Join-Path $env:ProgramData "UnixToolsSystemWide"
    }
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $file = Join-Path $backupDir "path-backup-$Scope-$stamp.txt"
    Write-AtomicUtf8File -Path $file -Content $current
    Write-Verbose "PATH backup saved: $file"
    Write-Status -Type detail -Label "PATH backup saved" -Detail (Split-Path $file -Leaf)
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if ($script:PathScope -eq "User") {
        if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warning "Running in UserScope mode (admin not required)."
        }
        return $true
    }
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($script:DryRun) {
            Write-Warning "Running in DryRun mode (admin checks relaxed)."
            return $true
        }
        Write-Footer -Type fail -Message "Administrator rights are required for Machine scope."
        Write-Dim "Re-run PowerShell as Administrator, or use -UserScope."
        Write-Dim "Example: .\Enable-UnixTools.ps1 -InstallFull -UserScope"
        Write-BlankLine
        return $false
    }
    return $true
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

    $cmd = Get-Command git -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        $gitExe = [string]$cmd.Source
        $gitDir = Split-Path -Parent $gitExe
        $gitLeaf = (Split-Path -Leaf $gitDir).ToLowerInvariant()
        if ($gitLeaf -eq "cmd" -or $gitLeaf -eq "bin") {
            $rootFromCmd = Split-Path -Parent $gitDir
            if ($rootFromCmd -and (Test-Path (Join-Path $rootFromCmd "usr\bin"))) {
                return $rootFromCmd
            }
        }
    }

    $gitInstallHelp = @(
        "Could not find a valid Git for Windows installation (expected usr\bin under Git root).",
        "Install Git, then re-run this script:",
        "  1) winget: winget install --id Git.Git --exact --source winget",
        "  2) Download: https://git-scm.com/download/win",
        "  3) PowerShell bootstrap (Chocolatey + Git):",
        "     Set-ExecutionPolicy Bypass -Scope Process -Force;",
        "     [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;",
        "     irm https://community.chocolatey.org/install.ps1 | iex;",
        "     choco install git -y"
    ) -join [Environment]::NewLine

    throw $gitInstallHelp
}

function Write-PackageManagerInstallGuidance {
    Write-Dim "Install a package manager, then re-run with -InstallOptionalTools."
    Write-Dim "  winget: https://aka.ms/getwinget"
    Write-Dim "  choco:  Set-ExecutionPolicy Bypass -Scope Process -Force;"
    Write-Dim "         irm https://community.chocolatey.org/install.ps1 | iex"
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

function Set-ScopedPathValue {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$PathValue,
        [Parameter(Mandatory = $true)][string]$Scope
    )

    Assert-PathLength -PathValue $PathValue -Scope $Scope
    if ($script:DryRun) {
        Write-DryRun "[Environment]::SetEnvironmentVariable('Path', '...len=$($PathValue.Length)...', '$Scope')"
        return
    }

    [Environment]::SetEnvironmentVariable("Path", $PathValue, $Scope)
}

function Add-MachinePathPrepend([string]$pathToPrepend) {
    $scope = $script:PathScope
    $norm = $pathToPrepend.Trim().TrimEnd('\')
    if (-not $script:DryRun -and -not (Test-Path $norm)) {
        throw "Path does not exist: $norm"
    }

    $current = [Environment]::GetEnvironmentVariable("Path", $scope)
    if (-not $current) { $current = "" }

    $parts = $current.Split(';') | Where-Object { $_ -and $_.Trim() -ne "" }

    $parts = $parts | Where-Object {
        -not $_.Trim().TrimEnd('\').Equals($norm, [StringComparison]::OrdinalIgnoreCase)
    }

    $newPath = (@($norm) + $parts) -join ';'
    Set-ScopedPathValue -PathValue $newPath -Scope $scope
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
        Set-ScopedPathValue -PathValue $newPath -Scope $scope
    }

    return $changed
}

function Remove-MachinePathEntries {
    param([string[]]$pathsToRemove)

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
    Set-ScopedPathValue -PathValue $newPath -Scope $scope
    return $true
}

function Update-MachinePathEntries {
    param()

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
    Set-ScopedPathValue -PathValue $newPath -Scope $scope
}

function New-DirectoryIfMissing {
    param([string]$dir)

    Initialize-Directory -Path $dir
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
    if ($script:DryRun) {
        Write-DryRun "Write-AtomicAsciiFile '$shimPath' (Create shim for $name -> $targetExePath)"
        return $true
    }
    Write-AtomicAsciiFile -Path $shimPath -Content $content
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

    try {
        $apps = Get-Command $toolName -CommandType Application -All -ErrorAction SilentlyContinue
        if (-not $apps) { return $null }

        $bestApp = $apps |
        Where-Object {
            $_.Source -and
            [System.IO.Path]::GetExtension($_.Source) -eq '.exe' -and
            (-not $excludeDir -or -not $_.Source.StartsWith($excludeDir.Trim().TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase))
        } |
        Sort-Object @{ Expression = { Get-ApplicationSourcePriority -Source $_.Source -Name $toolName } }, @{ Expression = { $_.Source } } |
        Select-Object -First 1
        if ($bestApp) { return $bestApp.Source }
    }
    catch { Write-Verbose "Ignored error in Find-ToolInPath: $($_.Exception.Message)" }
    return $null
}

function Get-ApplicationCommandIndex([string]$excludeDir = $null) {
    $index = @{}
    try {
        $apps = Get-Command -CommandType Application -All -ErrorAction SilentlyContinue
        foreach ($app in $apps) {
            $name = [System.IO.Path]::GetFileNameWithoutExtension($app.Name)
            if ([string]::IsNullOrWhiteSpace($name)) { continue }

            $src = $app.Source
            if ([string]::IsNullOrWhiteSpace($src)) { continue }
            if ([System.IO.Path]::GetExtension($src) -ne ".exe") { continue }

            if ($excludeDir) {
                $normExclude = $excludeDir.Trim().TrimEnd('\')
                if ($src.StartsWith($normExclude, [StringComparison]::OrdinalIgnoreCase)) { continue }
            }

            if (-not $index.ContainsKey($name) -or (Get-ApplicationSourcePriority -Source $src -Name $name) -lt (Get-ApplicationSourcePriority -Source $index[$name] -Name $name)) {
                $index[$name] = $src
            }
        }
    }
    catch { Write-Verbose "Ignored error in Get-ApplicationCommandIndex: $($_.Exception.Message)" }
    return $index
}

function Initialize-OptionalPackageManagers {
    $wingetAvailable = [bool](Get-Command winget -ErrorAction SilentlyContinue)
    $chocoAvailable = [bool](Get-Command choco  -ErrorAction SilentlyContinue)

    if (-not $wingetAvailable) {
        Write-Dim "winget not found. Attempting recovery..."
        try {
            if (Get-Command Add-AppxPackage -ErrorAction SilentlyContinue) {
                Add-AppxPackage -RegisterByFamilyName -MainPackage "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe" -ErrorAction Stop | Out-Null
            }
        }
        catch {
            Write-Dim "winget recovery failed: $($_.Exception.Message)"
        }
        $wingetAvailable = [bool](Get-Command winget -ErrorAction SilentlyContinue)
        if ($wingetAvailable) {
            Write-Status -Type ok -Label "winget recovered" -Indent
        }
    }

    return [pscustomobject]@{
        Winget = $wingetAvailable
        Choco  = $chocoAvailable
    }
}

function Send-EnvironmentChange {
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
        $WM_SETTINGCHANGE = [uint]0x1A
        [UIntPtr]$result = [UIntPtr]::Zero

        [NativeMethods]::SendMessageTimeout(
            $HWND_BROADCAST, $WM_SETTINGCHANGE,
            [UIntPtr]::Zero, "Environment", [uint]2, [uint]5000, [ref]$result
        ) | Out-Null
    }
    catch {
        Write-Verbose "WM_SETTINGCHANGE broadcast failed: $($_.Exception.Message)"
    }
}

function Update-SessionPath {
    param()

    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
    [Environment]::GetEnvironmentVariable("Path", "User")
}

