#Requires -Version 5.1
<#
.SYNOPSIS
    Adds Unix-compatible tools (grep, sed, awk, etc.) to the Windows system PATH.

.DESCRIPTION
    Discovers Git-for-Windows and exposes its bundled Unix tools on Windows.
    Optionally creates priority .cmd shims, installs PowerShell profile
    fallback functions for missing commands, provides alias-compat
    wrappers (rm, cp, mv, ls, cat, etc.) that accept common Unix flags,
    and wires optional smart-shell integrations such as predictive
    suggestions, fuzzy navigation, Git explorers, and file explorers.

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
    Install inline PowerShell profile shims (missing-command + alias-compat)
    managed directly by this script.

.PARAMETER InstallOptionalTools
    Install missing optional CLI tools (rg, fd, jq, yq, bat, eza, fzf, ag,
    zoxide, lazygit, yazi, etc.) and optional PowerShell modules
    (CompletionPredictor, PSFzf, ZLocation, posh-git, Terminal-Icons,
    powershell-yaml, etc.) when available.

.PARAMETER InstallTerminalSetup
    Install Oh My Posh themes and Nerd Font support for Windows Terminal/VS Code.

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
    Remove shim directory, PATH entries, and profile blocks installed by this script.

.PARAMETER UninstallOptionalTools
    When used together with -Uninstall, also remove optional tools tracked by this script.

.PARAMETER UninstallFont
    Remove the Nerd Font installed by this script.

.PARAMETER Theme
    Oh My Posh theme name to use for generated prompt configuration.

.PARAMETER ThemesDir
    Directory that contains Oh My Posh theme files.

.PARAMETER ProfileStartupMode
    Startup mode for generated profile integrations:
    Fast = minimal startup imports with on-demand interactive features.
    Legacy = eager interactive imports for compatibility.

.PARAMETER PromptInitMode
    Prompt initialization mode for generated Oh My Posh profile block:
    Lazy = minimal prompt first, then initialize Oh My Posh on a later prompt.
    Eager = initialize Oh My Posh during profile load.
    Off = do not install the prompt block.

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
    .\Enable-UnixToolsSystemWide.ps1 -Uninstall -UninstallOptionalTools
    Removes all shims, PATH entries, profile blocks, and tracked optional tools.

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
#   .\Enable-UnixToolsSystemWide.ps1 -InstallProfileShims -ProfileStartupMode Fast -PromptInitMode Lazy
#   .\Enable-UnixToolsSystemWide.ps1 -InstallProfileShims -LogPath C:\Temp\unix-tools-install.log
#   .\Enable-UnixToolsSystemWide.ps1 -Uninstall
#   .\Enable-UnixToolsSystemWide.ps1 -Uninstall -UninstallOptionalTools

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Default')]
param(
    [switch]$CreateShims,
    [switch]$AddMingw,
    [switch]$AddGitCmd,
    [switch]$NormalizePath,
    [switch]$InstallProfileShims,
    [switch]$InstallOptionalTools,
    [switch]$InstallTerminalSetup,
    [switch]$InstallFull,
    [switch]$UserScope,
    [switch]$Uninstall,
    [switch]$UninstallOptionalTools,
    [switch]$UninstallFont,
    [string]$Theme = "lightgreen",
    [string]$ThemesDir,
    [ValidateSet('Fast', 'Legacy')][string]$ProfileStartupMode = 'Fast',
    [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Lazy',
    [string]$LogPath,
    [Alias('h')]
    [switch]$Help,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ScriptVersion = "2.4.0"
$script:PathScope = if ($UserScope) { "User" } else { "Machine" }
$script:PathDisplay = "$($script:PathScope) PATH"
$script:DryRun = $DryRun.IsPresent

# Enforce TLS 1.2+ only for all web requests (drops insecure TLS 1.0/1.1).
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13
}
catch {
    Write-Verbose "TLS 1.3 is unavailable in this host: $($_.Exception.Message)"
}

# Default to non-interactive behavior unless caller explicitly asks for confirmation.
if (-not $PSBoundParameters.ContainsKey('Confirm')) {
    $ConfirmPreference = 'None'
}

# ======================== Functions ========================

# ======================== Output Theming ========================

# Detect whether the terminal supports Unicode box-drawing characters.
# Falls back to ASCII on raster-font consoles (e.g., legacy conhost).
$script:UseUnicode = $true
try {
    if ($Host.UI.RawUI.FontFamily -and $Host.UI.RawUI.FontFamily.Name -match 'Raster|Terminal|Fixedsys') {
        $script:UseUnicode = $false
    }
}
catch {
    Write-Verbose "Font-family detection unavailable in this host: $($_.Exception.Message)"
}

# Icon/box-drawing character sets.
if ($script:UseUnicode) {
    $script:UI = @{
        Ok     = [string][char]0x2713  # ✓
        Fail   = [string][char]0x2717  # ✗
        Info   = [string][char]0x25CF  # ●
        Detail = [string][char]0x25C6  # ◆
        Warn   = [string][char]0x26A0  # ⚠
        Skip   = [string][char]0x25CB  # ○
        Arrow  = [string][char]0x2192  # →
        HLine  = [string][char]0x2500  # ─
        TL     = [string][char]0x256D  # ╭
        TR     = [string][char]0x256E  # ╮
        BL     = [string][char]0x2570  # ╰
        BR     = [string][char]0x256F  # ╯
        VLine  = [string][char]0x2502  # │
    }
}
else {
    $script:UI = @{
        Ok = '+'; Fail = 'x'; Info = '*'; Detail = '>'; Warn = '!'
        Skip = 'o'; Arrow = '->'; HLine = '-'; TL = '+'; TR = '+'
        BL = '+'; BR = '+'; VLine = '|'
    }
}

function Write-Header {
    param(
        [string]$Title = "Unix Tools for Windows",
        [string]$Version = $ScriptVersion,
        [string]$Scope = $script:PathScope,
        [string]$Mode = ""
    )
    $ui = $script:UI
    $inner = "$Title"
    $right = "v$Version"
    $modeText = if ($Mode) { "$Scope scope $($ui.Detail) $Mode" } else { "$Scope scope" }

    # Calculate box width based on content
    $contentWidth = [Math]::Max($inner.Length + $right.Length + 6, $modeText.Length + 4)
    $boxWidth = [Math]::Max($contentWidth, 48)

    $topBorder = "  $($ui.TL)$($ui.HLine * $boxWidth)$($ui.TR)"
    $bottomBorder = "  $($ui.BL)$($ui.HLine * $boxWidth)$($ui.BR)"

    $pad1 = $boxWidth - $inner.Length - $right.Length - 2
    $line1Content = " $inner$(' ' * [Math]::Max($pad1, 0))$right "

    $pad2 = $boxWidth - $modeText.Length - 1
    $line2Content = " $modeText$(' ' * [Math]::Max($pad2, 0))"

    Write-Host ""
    Write-Host $topBorder -ForegroundColor DarkCyan
    Write-Host -NoNewline "  $($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host -NoNewline $line1Content -ForegroundColor White
    Write-Host "$($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host -NoNewline "  $($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host -NoNewline $line2Content -ForegroundColor DarkGray
    Write-Host "$($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host $bottomBorder -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-Section {
    param([Parameter(Mandatory)][string]$Title)
    $ui = $script:UI
    $lineLen = [Math]::Max(50 - $Title.Length - 2, 6)
    $section = "  $($ui.HLine * 3) $Title $($ui.HLine * $lineLen)"
    Write-Host ""
    Write-Host $section -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('ok', 'fail', 'info', 'detail', 'warn', 'skip')][string]$Type,
        [Parameter(Mandatory)][string]$Label,
        [string]$Detail = "",
        [switch]$Indent
    )
    $ui = $script:UI
    $prefix = if ($Indent) { "    " } else { "  " }

    $icon = switch ($Type) {
        'ok' { $ui.Ok }
        'fail' { $ui.Fail }
        'info' { $ui.Info }
        'detail' { $ui.Detail }
        'warn' { $ui.Warn }
        'skip' { $ui.Skip }
    }
    $color = switch ($Type) {
        'ok' { 'Green' }
        'fail' { 'Red' }
        'info' { 'DarkGray' }
        'detail' { 'DarkCyan' }
        'warn' { 'Yellow' }
        'skip' { 'DarkGray' }
    }

    # Fixed-width label column for alignment
    $labelWidth = 24
    $paddedLabel = if ($Label.Length -ge $labelWidth) { $Label } else { $Label + (' ' * ($labelWidth - $Label.Length)) }

    Write-Host -NoNewline "$prefix" -ForegroundColor White
    Write-Host -NoNewline "$icon " -ForegroundColor $color
    Write-Host -NoNewline "$paddedLabel" -ForegroundColor White
    if ($Detail) {
        Write-Host " $Detail" -ForegroundColor DarkGray
    }
    else {
        Write-Host ""
    }
}

function Write-Dim {
    param([Parameter(Mandatory)][string]$Text, [switch]$Indent)
    $prefix = if ($Indent) { "      " } else { "  " }
    Write-Host "$prefix$Text" -ForegroundColor DarkGray
}

function Write-CompactList {
    param(
        [Parameter(Mandatory)][string[]]$Items,
        [int]$MaxWidth = 70,
        [string]$Prefix = "      "
    )
    if ($Items.Count -eq 0) { return }
    $line = $Prefix
    foreach ($item in $Items) {
        if (($line.Length + $item.Length + 1) -gt $MaxWidth -and $line.Length -gt $Prefix.Length) {
            Write-Host $line -ForegroundColor DarkGray
            $line = $Prefix
        }
        $line += "$item "
    }
    if ($line.Length -gt $Prefix.Length) {
        Write-Host $line -ForegroundColor DarkGray
    }
}

function Write-Footer {
    param(
        [string]$Message = "Done",
        [ValidateSet('ok', 'fail', 'warn')][string]$Type = 'ok'
    )
    $ui = $script:UI
    $icon = switch ($Type) {
        'ok' { $ui.Ok }
        'fail' { $ui.Fail }
        'warn' { $ui.Warn }
    }
    $color = switch ($Type) {
        'ok' { 'Green' }
        'fail' { 'Red' }
        'warn' { 'Yellow' }
    }

    $inner = " $icon $Message"
    $boxWidth = [Math]::Max($inner.Length + 2, 48)
    $pad = $boxWidth - $inner.Length

    $contentInner = "$inner$(' ' * [Math]::Max($pad, 0))"

    $topBorder = "  $($ui.TL)$($ui.HLine * $boxWidth)$($ui.TR)"
    $bottomBorder = "  $($ui.BL)$($ui.HLine * $boxWidth)$($ui.BR)"

    Write-Host ""
    Write-Host $topBorder -ForegroundColor DarkCyan
    Write-Host -NoNewline "  $($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host -NoNewline $contentInner -ForegroundColor $color
    Write-Host "$($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host $bottomBorder -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-DryRun {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "  [DRYRUN] $Text" -ForegroundColor DarkGray
}

# ======================== Core Functions ========================

function Invoke-NativeCommand {
    <#
    .SYNOPSIS
        Runs a native executable and returns its exit code reliably.
        Avoids stale $LASTEXITCODE from previous commands.
        Use -WarnOnStderr to log stderr lines as warnings.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    # Note: WarnOnStderr is extracted manually to avoid interfering with ValueFromRemainingArguments.
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
    New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction SilentlyContinue | Out-Null
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $file = Join-Path $backupDir "path-backup-$Scope-$stamp.txt"
    Set-Content -Path $file -Value $current -Encoding UTF8
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
        return $true
    }
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($script:DryRun) {
            Write-Warning "Running in DryRun mode (admin checks relaxed)."
            return $true
        }
        Write-Footer -Type fail -Message "Administrator rights are required for Machine scope."
        Write-Host "  Re-run PowerShell as Administrator, or use -UserScope." -ForegroundColor DarkGray
        Write-Host "  Example: .\Enable-UnixTools.ps1 -InstallFull -UserScope" -ForegroundColor DarkGray
        Write-Host ""
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
    Assert-PathLength -PathValue $newPath -Scope $scope
    if ($script:DryRun) {
        Write-Host "[DRYRUN] [Environment]::SetEnvironmentVariable('Path', '...len=$($newPath.Length)...', '$scope')" -ForegroundColor DarkGray
    }
    else {
        [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
    }
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
        if ($script:DryRun) {
            Write-Host "[DRYRUN] [Environment]::SetEnvironmentVariable('Path', '...len=$($newPath.Length)...', '$scope')" -ForegroundColor DarkGray
        }
        else {
            [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
        }
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
    if ($script:DryRun) {
        Write-Host "[DRYRUN] [Environment]::SetEnvironmentVariable('Path', '...len=$($newPath.Length)...', '$scope')" -ForegroundColor DarkGray
    }
    else {
        [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
    }
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
    if ($script:DryRun) {
        Write-Host "[DRYRUN] [Environment]::SetEnvironmentVariable('Path', '...len=$($newPath.Length)...', '$scope')" -ForegroundColor DarkGray
    }
    else {
        [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
    }
}

function New-DirectoryIfMissing([string]$dir) {
    if ($script:DryRun) {
        if (-not (Test-Path $dir)) {
            Write-Host "[DRYRUN] New-Item -ItemType Directory -Path '$dir'" -ForegroundColor DarkGray
        }
    }
    else {
        New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue | Out-Null
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
    if ($script:DryRun) {
        Write-Host "[DRYRUN] Set-Content '$shimPath' (Create shim for $name -> $targetExePath)" -ForegroundColor DarkGray
        return $true
    }
    Set-Content -Path $shimPath -Value $content -Encoding ASCII -Force
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
    }
    catch { Write-Verbose "Ignored error in Get-ApplicationCommandIndex: $($_.Exception.Message)" }
    return $index
}

function Get-OptionalToolCatalog {
    return @(
        [pscustomobject]@{ Command = "rg"; WingetId = "BurntSushi.ripgrep.MSVC"; ChocoId = "ripgrep" },
        [pscustomobject]@{ Command = "fd"; WingetId = "sharkdp.fd"; ChocoId = "fd" },
        [pscustomobject]@{ Command = "jq"; WingetId = "jqlang.jq"; ChocoId = "jq" },
        [pscustomobject]@{ Command = "yq"; WingetId = "MikeFarah.yq"; ChocoId = "yq" },
        [pscustomobject]@{ Command = "bat"; WingetId = "sharkdp.bat"; ChocoId = "bat" },
        [pscustomobject]@{ Command = "eza"; WingetId = "eza-community.eza"; ChocoId = "eza" },
        [pscustomobject]@{ Command = "fzf"; WingetId = "junegunn.fzf"; ChocoId = "fzf" },
        [pscustomobject]@{ Command = "ag"; WingetId = "JFLarvoire.Ag"; ChocoId = "ag" },
        
        [pscustomobject]@{ Command = "zoxide"; WingetId = "ajeetdsouza.zoxide"; ChocoId = "zoxide" },
        [pscustomobject]@{ Command = "delta"; WingetId = "dandavison.delta"; ChocoId = "delta" },
        [pscustomobject]@{ Command = "gh"; WingetId = "GitHub.cli"; ChocoId = "gh" },
        [pscustomobject]@{ Command = "lazygit"; WingetId = "JesseDuffield.lazygit"; ChocoId = "lazygit" },
        [pscustomobject]@{ Command = "yazi"; WingetId = "sxyazi.yazi"; ChocoId = "yazi" },
        [pscustomobject]@{ Command = "dust"; WingetId = "bootandy.dust"; ChocoId = "du-dust" },
        [pscustomobject]@{ Command = "procs"; WingetId = "dalance.procs"; ChocoId = "procs" },
        [pscustomobject]@{ Command = "oh-my-posh"; WingetId = "JanDeDobbeleer.OhMyPosh"; ChocoId = "oh-my-posh" }
    )
}

function Get-OptionalPowerShellModuleCatalog {
    return @(
        [pscustomobject]@{ ModuleName = "CompletionPredictor"; Repository = "PSGallery" },
        [pscustomobject]@{ ModuleName = "Microsoft.WinGet.CommandNotFound"; Repository = "PSGallery" },
        [pscustomobject]@{ ModuleName = "PSFzf"; Repository = "PSGallery" },
        [pscustomobject]@{ ModuleName = "ZLocation"; Repository = "PSGallery" },
        [pscustomobject]@{ ModuleName = "posh-git"; Repository = "PSGallery" },
        [pscustomobject]@{ ModuleName = "Terminal-Icons"; Repository = "PSGallery" },
        [pscustomobject]@{ ModuleName = "powershell-yaml"; Repository = "PSGallery" }
    )
}

function Get-SmartShellOptionalModuleNames {
    return @(Get-OptionalPowerShellModuleCatalog | Select-Object -ExpandProperty ModuleName)
}

function Get-ProfileSmartShellBlockBody {
    param(
        [ValidateSet('Fast', 'Legacy')][string]$StartupMode = 'Fast'
    )

    $moduleLines = (Get-SmartShellOptionalModuleNames | ForEach-Object { "            '{0}'" -f $_ }) -join "`r`n"
    $legacyInit = ""
    if ($StartupMode -eq 'Legacy') {
        $legacyInit = @'
    Enable-UnixInteractiveFeatures

'@
    }

    $blockBody = @'
# Enable smart-shell integrations: prediction, fuzzy navigation, Git/file explorers.
# Startup mode: __STARTUP_MODE__
if ($Host.Name -eq 'ConsoleHost' -or $Host.Name -eq 'Visual Studio Code Host') {
    $script:SmartShellExeCache = @{}
    $script:UnixInteractiveFeaturesEnabled = $false
    $winGetLinks = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links'
    $winGetPackages = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
    if ((Test-Path -LiteralPath $winGetLinks) -and -not (($env:PATH -split ';') -contains $winGetLinks)) {
        $env:PATH = "$winGetLinks;$env:PATH"
    }

    function global:Resolve-SmartShellExecutable {
        param(
            [Parameter(Mandatory = $true)]
            [string[]]$Candidates,
            [switch]$AllowPackageScan
        )

        foreach ($candidate in $Candidates) {
            $cacheKey = "{0}:{1}" -f $candidate.ToLowerInvariant(), $AllowPackageScan.ToString().ToLowerInvariant()
            if ($script:SmartShellExeCache.ContainsKey($cacheKey)) {
                $cached = $script:SmartShellExeCache[$cacheKey]
                if ($cached) { return $cached }
                continue
            }

            $cmd = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cmd) {
                $script:SmartShellExeCache[$cacheKey] = $cmd.Source
                return $cmd.Source
            }

            foreach ($dir in @($winGetLinks, 'C:\Program Files\Git\shims')) {
                if (-not [string]::IsNullOrWhiteSpace($dir)) {
                    $path = Join-Path $dir $candidate
                    if (Test-Path -LiteralPath $path -PathType Leaf) {
                        $script:SmartShellExeCache[$cacheKey] = $path
                        return $path
                    }
                }
            }

            if ($AllowPackageScan -and (Test-Path -LiteralPath $winGetPackages)) {
                $pkgPath = Get-ChildItem -Path $winGetPackages -Recurse -Filter $candidate -File -ErrorAction SilentlyContinue |
                    Select-Object -First 1 -ExpandProperty FullName
                if ($pkgPath) {
                    $script:SmartShellExeCache[$cacheKey] = $pkgPath
                    return $pkgPath
                }
            }

            $script:SmartShellExeCache[$cacheKey] = $null
        }
    }

    function global:Enable-UnixInteractiveFeatures {
        if ($script:UnixInteractiveFeaturesEnabled) {
            return
        }

        foreach ($module in @(
__MODULE_LINES__
        )) {
            if (Get-Module -ListAvailable $module) {
                Import-Module $module -ErrorAction SilentlyContinue
            }
        }

        if (Get-Module PSReadLine -ErrorAction SilentlyContinue) {
            if (-not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) {
                try {
                    $predictionSource = if (Get-Module CompletionPredictor -ErrorAction SilentlyContinue) { 'HistoryAndPlugin' } else { 'History' }
                    Set-PSReadLineOption -PredictionSource $predictionSource
                    Set-PSReadLineOption -PredictionViewStyle InlineView
                }
                catch {
                    Write-Verbose "PSReadLine interactive features unavailable: $($_.Exception.Message)"
                }
            }
        }

        if (Get-Command Set-PsFzfOption -ErrorAction SilentlyContinue) {
            Set-PsFzfOption -EnableAliasFuzzyZLocation:$true -AltCCommand { Invoke-FuzzyZLocation }
        }

        $script:UnixInteractiveFeaturesEnabled = $true
    }

    if (Get-Module -ListAvailable PSReadLine) {
        Import-Module PSReadLine -ErrorAction SilentlyContinue
        if (-not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) {
            try {
                Set-PSReadLineOption -PredictionSource History
                Set-PSReadLineOption -PredictionViewStyle InlineView
            }
            catch {
                Write-Verbose "PSReadLine prediction setup unavailable: $($_.Exception.Message)"
            }
        }
    }

__LEGACY_INIT__
    $zoxideExe = Resolve-SmartShellExecutable -Candidates @('zoxide.exe', 'zoxide.cmd')
    if ($zoxideExe) {
        Invoke-Expression (& $zoxideExe init powershell --cmd j | Out-String)
    }

    function global:y {
        $yaziExe = Resolve-SmartShellExecutable -Candidates @('yazi.exe', 'ya.exe', 'yazi.cmd', 'ya.cmd') -AllowPackageScan
        if (-not $yaziExe) {
            throw "yazi is not available on PATH. Re-run setup with -InstallOptionalTools or restart PowerShell."
        }

        $tmp = (New-TemporaryFile).FullName
        try {
            & $yaziExe @args --cwd-file="$tmp"
            if (Test-Path -LiteralPath $tmp) {
                $cwd = Get-Content -Path $tmp -Encoding UTF8 -ErrorAction SilentlyContinue
                if ($cwd -and $cwd -ne $PWD.Path -and (Test-Path -LiteralPath $cwd -PathType Container)) {
                    Set-Location -LiteralPath (Resolve-Path -LiteralPath $cwd).Path
                }
            }
        }
        finally {
            Remove-Item -Path $tmp -ErrorAction SilentlyContinue
        }
    }

    function global:lg {
        $lazygitExe = Resolve-SmartShellExecutable -Candidates @('lazygit.exe', 'lazygit.cmd') -AllowPackageScan
        if (-not $lazygitExe) {
            throw "lazygit is not available on PATH. Re-run setup with -InstallOptionalTools."
        }

        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("lazygit-cwd-{0}.txt" -f [guid]::NewGuid())
        try {
            $env:LAZYGIT_NEW_DIR_FILE = $tmp
            & $lazygitExe @args
            if (Test-Path -LiteralPath $tmp) {
                $cwd = (Get-Content -Path $tmp -Encoding UTF8 -ErrorAction SilentlyContinue | Select-Object -First 1)
                if ($cwd -and $cwd -ne $PWD.Path -and (Test-Path -LiteralPath $cwd -PathType Container)) {
                    Set-Location -LiteralPath (Resolve-Path -LiteralPath $cwd).Path
                }
            }
        }
        finally {
            Remove-Item env:LAZYGIT_NEW_DIR_FILE -ErrorAction SilentlyContinue
            Remove-Item -Path $tmp -ErrorAction SilentlyContinue
        }
    }
}
'@

    $blockBody = $blockBody.Replace('__STARTUP_MODE__', $StartupMode)
    $blockBody = $blockBody.Replace('__MODULE_LINES__', $moduleLines)
    $blockBody = $blockBody.Replace('__LEGACY_INIT__', $legacyInit)
    return $blockBody
}

function Get-ProfilePromptBlockBody {
    param(
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [string]$Theme = 'pure',
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Lazy'
    )

    if ($PromptInitMode -eq 'Off') {
        return $null
    }

    $configPath = Join-Path $ThemesDir ("{0}.omp.json" -f $Theme)
    if ($PromptInitMode -eq 'Eager') {
        $blockBody = @'
# Oh My Posh theme configuration
# Prompt init mode: Eager
if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {
    $configPath = "__CONFIG_PATH__"
    oh-my-posh init pwsh --config "$configPath" | Invoke-Expression
}
'@
        return $blockBody.Replace('__CONFIG_PATH__', $configPath)
    }

    $blockBody = @'
# Oh My Posh theme configuration
# Prompt init mode: Lazy
if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {
    $configPath = "__CONFIG_PATH__"
    $script:UnixToolsPromptState = 'Pending'
    $script:UnixToolsPromptWarningShown = $false

    function global:Get-UnixToolsMinimalPrompt {
        return "PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) "
    }

    function global:Initialize-UnixToolsPrompt {
        if ($script:UnixToolsPromptState -eq 'Loaded') { return $true }
        if ($script:UnixToolsPromptState -eq 'Failed') { return $false }

        try {
            oh-my-posh init pwsh --config "$configPath" | Invoke-Expression
            $script:UnixToolsPromptState = 'Loaded'
            return $true
        }
        catch {
            $script:UnixToolsPromptState = 'Failed'
            if (-not $script:UnixToolsPromptWarningShown) {
                Write-Warning "oh-my-posh init failed: $($_.Exception.Message)"
                $script:UnixToolsPromptWarningShown = $true
            }
            return $false
        }
    }

    function global:prompt {
        if ($script:UnixToolsPromptState -eq 'Pending') {
            $script:UnixToolsPromptState = 'Warmup'
            return Get-UnixToolsMinimalPrompt
        }

        if ($script:UnixToolsPromptState -eq 'Warmup') {
            if (Initialize-UnixToolsPrompt) {
                $currentPrompt = Get-Command prompt -CommandType Function -ErrorAction SilentlyContinue
                if ($currentPrompt -and $currentPrompt.ScriptBlock -ne $MyInvocation.MyCommand.ScriptBlock) {
                    return & $currentPrompt.ScriptBlock
                }
            }
        }

        return Get-UnixToolsMinimalPrompt
    }
}
'@

    return $blockBody.Replace('__CONFIG_PATH__', $configPath)
}

function Find-LegacyInlineShimBlock {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)

    $result = [ordered]@{
        Found      = $false
        Removed    = $false
        Status     = 'NotFound'
        StartLine  = $null
        EndLine    = $null
        HeaderLine = $null
        GuardLine  = $null
        Detail     = ''
    }

    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) {
        return [pscustomobject]$result
    }

    $lines = Get-Content -Path $ProfilePath -ErrorAction SilentlyContinue
    if (-not $lines) {
        return [pscustomobject]$result
    }

    $headerMatches = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'Fast Unix-like shims for PowerShell \(\$PROFILE\)') {
            $headerMatches += $i
        }
    }

    if ($headerMatches.Count -gt 1) {
        $result.Status = 'Ambiguous'
        $result.Detail = 'Multiple legacy inline shim headers found.'
        return [pscustomobject]$result
    }

    if ($headerMatches.Count -eq 0) {
        return [pscustomobject]$result
    }

    $headerIndex = $headerMatches[0]
    $guardMatches = @()
    $guardSearchEnd = [Math]::Min($lines.Count - 1, $headerIndex + 60)
    for ($i = $headerIndex; $i -le $guardSearchEnd; $i++) {
        if ($lines[$i].Trim() -eq 'if (-not $script:__UnixShimsInitialized) {') {
            $guardMatches += $i
        }
    }

    if ($guardMatches.Count -ne 1) {
        $result.Status = 'Ambiguous'
        $result.Detail = 'Could not uniquely identify the legacy inline shim guard.'
        return [pscustomobject]$result
    }

    $guardIndex = $guardMatches[0]
    $startIndex = $headerIndex
    while ($startIndex -gt 0) {
        $previousLine = $lines[$startIndex - 1]
        if ([string]::IsNullOrWhiteSpace($previousLine) -or $previousLine.TrimStart().StartsWith('#')) {
            $startIndex--
            continue
        }
        break
    }

    $braceDepth = 0
    $sawOpeningBrace = $false
    $endIndex = $null
    for ($i = $guardIndex; $i -lt $lines.Count; $i++) {
        foreach ($character in $lines[$i].ToCharArray()) {
            if ($character -eq '{') {
                $braceDepth++
                $sawOpeningBrace = $true
                continue
            }

            if ($character -eq '}') {
                if ($sawOpeningBrace) {
                    $braceDepth--
                    if ($braceDepth -eq 0) {
                        $endIndex = $i
                        break
                    }
                }
            }
        }

        if ($null -ne $endIndex) {
            break
        }
    }

    if ($null -eq $endIndex) {
        $result.Status = 'Ambiguous'
        $result.Detail = 'Could not determine the end of the legacy inline shim block.'
        return [pscustomobject]$result
    }

    $result.Found = $true
    $result.Status = 'Found'
    $result.StartLine = $startIndex + 1
    $result.EndLine = $endIndex + 1
    $result.HeaderLine = $headerIndex + 1
    $result.GuardLine = $guardIndex + 1
    $result.Detail = "legacy inline shim block lines $($result.StartLine)-$($result.EndLine)"
    return [pscustomobject]$result
}

function Remove-LegacyInlineProfileShims {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)

    $block = Find-LegacyInlineShimBlock -ProfilePath $ProfilePath
    if ($block.Status -ne 'Found') {
        return $block
    }

    $lines = Get-Content -Path $ProfilePath -ErrorAction SilentlyContinue
    if ($null -eq $lines) {
        return [pscustomobject]@{
            Found      = $false
            Removed    = $false
            Status     = 'NotFound'
            StartLine  = $null
            EndLine    = $null
            HeaderLine = $null
            GuardLine  = $null
            Detail     = 'Profile file disappeared before legacy cleanup.'
        }
    }

    $updatedLines = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $lineNumber = $i + 1
        if ($lineNumber -ge $block.StartLine -and $lineNumber -le $block.EndLine) {
            continue
        }
        $updatedLines.Add($lines[$i]) | Out-Null
    }

    $updated = $updatedLines -join "`r`n"
    if ($updated.Length -gt 0 -and -not $updated.EndsWith("`r`n")) {
        $updated += "`r`n"
    }

    if ($script:DryRun) {
        Write-Host "[DRYRUN] Set-Content '$ProfilePath' (removed legacy inline profile shim block)" -ForegroundColor DarkGray
    }
    else {
        $tmp = "$ProfilePath.tmp"
        try {
            Set-Content -Path $tmp -Value $updated -Encoding UTF8
            Move-Item -Path $tmp -Destination $ProfilePath -Force
        }
        catch {
            Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
            throw
        }
    }

    $block.Removed = $true
    $block.Status = 'Removed'
    return $block
}

function Get-ProfileMetadataValue {
    param(
        [string]$Text,
        [Parameter(Mandatory = $true)][string]$Key
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $pattern = "(?m)^\s*#\s*$([regex]::Escape($Key)):\s*(.+?)\s*$"
    $match = [regex]::Match($Text, $pattern)
    if ($match.Success) {
        return $match.Groups[1].Value.Trim()
    }

    return $null
}

function Get-ProfileInstallationState {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)

    $profileText = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
    $hasMissingBlock = $profileText -and $profileText.Contains("# >>> unix-tools-missing-shims >>>") -and $profileText.Contains("# <<< unix-tools-missing-shims <<<")
    $hasAliasBlock = $profileText -and $profileText.Contains("# >>> unix-tools-alias-compat >>>") -and $profileText.Contains("# <<< unix-tools-alias-compat <<<")
    $hasSmartShellBlock = $profileText -and $profileText.Contains("# >>> unix-tools-smart-shell >>>") -and $profileText.Contains("# <<< unix-tools-smart-shell <<<")
    $hasTerminalBlock = $profileText -and $profileText.Contains("# >>> unix-tools-terminal-setup >>>") -and $profileText.Contains("# <<< unix-tools-terminal-setup <<<")
    $hasFastBlock = $profileText -and $profileText.Contains("# >>> unix-tools-fast-shims >>>") -and $profileText.Contains("# <<< unix-tools-fast-shims <<<")
    $legacyBlock = Find-LegacyInlineShimBlock -ProfilePath $ProfilePath

    [pscustomobject]@{
        HasManagedBlocks     = ($hasMissingBlock -and $hasAliasBlock -and $hasSmartShellBlock)
        HasMissingBlock      = [bool]$hasMissingBlock
        HasAliasBlock        = [bool]$hasAliasBlock
        HasSmartShellBlock   = [bool]$hasSmartShellBlock
        HasTerminalBlock     = [bool]$hasTerminalBlock
        HasLegacyFastBlock   = [bool]$hasFastBlock
        LegacyInlineStatus   = $legacyBlock.Status
        HasLegacyInlineBlock = [bool]$legacyBlock.Found
        StartupMode          = if ($hasSmartShellBlock) { Get-ProfileMetadataValue -Text $profileText -Key 'Startup mode' } else { 'NotInstalled' }
        PromptInitMode       = if ($hasTerminalBlock) { Get-ProfileMetadataValue -Text $profileText -Key 'Prompt init mode' } else { 'Off' }
    }
}

function Install-MissingOptionalPowerShellModules([object[]]$Catalog) {
    if (-not $Catalog -or $Catalog.Count -eq 0) { return @() }

    $psResource = Get-Command Install-PSResource -ErrorAction SilentlyContinue
    $powerShellGet = Get-Command Install-Module -ErrorAction SilentlyContinue
    if (-not $psResource -and -not $powerShellGet) {
        Write-Status -Type warn -Label "No module installer" -Detail "PowerShell modules cannot be auto-installed"
        return @()
    }

    $newlyInstalled = @()
    foreach ($module in $Catalog) {
        $moduleName = [string]$module.ModuleName
        $repository = if ($module.Repository) { [string]$module.Repository } else { "PSGallery" }
        if ([string]::IsNullOrWhiteSpace($moduleName)) { continue }

        if (Get-Module -ListAvailable $moduleName) {
            continue
        }

        $installed = $false
        $managerUsed = $null

        try {
            if ($script:DryRun) {
                if ($psResource) {
                    Write-DryRun "Install-PSResource $moduleName -Repository $repository -Scope CurrentUser -TrustRepository -Quiet"
                    $managerUsed = "psresourceget"
                }
                else {
                    Write-DryRun "Install-Module $moduleName -Repository $repository -Scope CurrentUser -Force -AllowClobber"
                    $managerUsed = "powershellget"
                }
                $installed = $true
            }
            elseif ($psResource) {
                Install-PSResource -Name $moduleName -Repository $repository -Scope CurrentUser -TrustRepository -Quiet -ErrorAction Stop
                $managerUsed = "psresourceget"
                $installed = $true
            }
            else {
                Install-Module -Name $moduleName -Repository $repository -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                $managerUsed = "powershellget"
                $installed = $true
            }
        }
        catch {
            Write-Status -Type warn -Label "Module install failed" -Detail "${moduleName}: $($_.Exception.Message)" -Indent
        }

        if (-not $script:DryRun -and $installed -and -not (Get-Module -ListAvailable $moduleName)) {
            $installed = $false
            Write-Status -Type warn -Label "Module missing" -Detail "$moduleName not detected after install" -Indent
        }

        if ($installed) {
            $newlyInstalled += [pscustomobject]@{
                Kind          = "PowerShellModule"
                Command       = $null
                ModuleName    = $moduleName
                Manager       = $managerUsed
                PackageId     = $moduleName
                InstalledAt   = (Get-Date).ToString("o")
                ScriptVersion = $ScriptVersion
            }
            Write-Status -Type ok -Label "Module installed" -Detail "$moduleName via $managerUsed" -Indent
        }
    }

    if ($newlyInstalled.Count -gt 0) {
        $existing = @(Read-OptionalToolState)
        $records = New-Object System.Collections.Generic.List[object]
        $moduleMap = @{}

        foreach ($item in $existing) {
            $kind = if ($item.PSObject.Properties["Kind"]) { [string]$item.Kind } else { "" }
            $name = if ($item.PSObject.Properties["ModuleName"]) { [string]$item.ModuleName } else { "" }
            if ($kind -eq "PowerShellModule" -and -not [string]::IsNullOrWhiteSpace($name)) {
                $moduleMap[$name] = $item
            }
            else {
                $records.Add($item) | Out-Null
            }
        }

        foreach ($item in $newlyInstalled) {
            $moduleMap[[string]$item.ModuleName] = $item
        }

        foreach ($item in ($moduleMap.Values | Sort-Object ModuleName)) {
            $records.Add($item) | Out-Null
        }

        Write-OptionalToolState -Records @($records)
    }

    return $newlyInstalled
}

function Save-TerminalThemes {
    param([Parameter(Mandatory = $true)][string]$ThemesDir)

    if ($script:DryRun) {
        Write-Host "[DRYRUN] Download and extract Oh My Posh themes to '$ThemesDir'" -ForegroundColor DarkGray
        return
    }

    if (Test-Path $ThemesDir) {
        Write-Status -Type info -Label "Themes directory" -Detail "already exists, skipping download" -Indent
        return
    }

    $zip = Join-Path $env:TEMP "omp-themes-$([guid]::NewGuid().ToString().Split('-')[0]).zip"
    try {
        Write-Status -Type detail -Label "Downloading themes" -Detail "oh-my-posh/releases/latest" -Indent
        Invoke-WebRequest -Uri "https://github.com/JanDeDobbeleer/oh-my-posh/releases/latest/download/themes.zip" -OutFile $zip -ErrorAction Stop
        New-DirectoryIfMissing $ThemesDir
        Write-Status -Type detail -Label "Extracting themes" -Detail $ThemesDir -Indent
        Expand-Archive -Path $zip -DestinationPath $ThemesDir -Force -ErrorAction Stop
    }
    catch {
        Write-Status -Type warn -Label "Themes failed" -Detail $_.Exception.Message -Indent
    }
    finally {
        if (Test-Path $zip) { Remove-Item -Path $zip -Force -ErrorAction SilentlyContinue }
    }
}

function Install-NerdFont {
    if ($script:DryRun) {
        Write-Host "[DRYRUN] Download and install CaskaydiaCove Nerd Font" -ForegroundColor DarkGray
        return
    }

    $fontDirs = @(
        (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"),
        (Join-Path $env:WINDIR "Fonts")
    )
    $fontFileFound = $fontDirs | Where-Object { Test-Path $_ } | ForEach-Object {
        (Get-ChildItem -Path $_ -Filter "CascadiaCode*" -ErrorAction SilentlyContinue),
        (Get-ChildItem -Path $_ -Filter "CaskaydiaCove*" -ErrorAction SilentlyContinue)
    } | Where-Object { $_ -ne $null } | Select-Object -First 1
    
    if ($fontFileFound) {
        Write-Status -Type ok -Label "Nerd Font" -Detail "CaskaydiaCove already installed, skipping" -Indent
        return
    }



    $zip = Join-Path $env:TEMP "CascadiaCode-$([guid]::NewGuid().ToString().Split('-')[0]).zip"
    $dir = Join-Path $env:TEMP "CascadiaCode-$([guid]::NewGuid().ToString().Split('-')[0])"
    try {
        Write-Status -Type detail -Label "Downloading font" -Detail "ryanoasis/nerd-fonts" -Indent
        Invoke-WebRequest -Uri "https://github.com/ryanoasis/nerd-fonts/releases/latest/download/CascadiaCode.zip" -OutFile $zip -ErrorAction Stop
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Expand-Archive -Path $zip -DestinationPath $dir -Force -ErrorAction Stop
        
        Write-Status -Type detail -Label "Installing font" -Detail "copying to User and System Fonts (silent)" -Indent
        
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $installLocations = @(
            @{ Scope = "User"; Dir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"; Reg = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" }
        )
        if ($isAdmin) {
            $installLocations += @{ Scope = "System"; Dir = Join-Path $env:WINDIR "Fonts"; Reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" }
        }

        foreach ($loc in $installLocations) {
            if (-not (Test-Path $loc.Dir)) {
                New-Item -ItemType Directory -Path $loc.Dir -Force | Out-Null
            }
        }
        
        Get-ChildItem -Path $dir -Include "*.ttf", "*.otf" -Recurse | ForEach-Object {
            $fontKeyName = $_.BaseName
            if ($_.Extension -eq ".ttf") { $fontKeyName += " (TrueType)" }
            if ($_.Extension -eq ".otf") { $fontKeyName += " (OpenType)" }
            
            foreach ($loc in $installLocations) {
                $targetPath = Join-Path $loc.Dir $_.Name
                Copy-Item -Path $_.FullName -Destination $targetPath -Force
                Set-ItemProperty -Path $loc.Reg -Name $fontKeyName -Value $targetPath -Force
            }
        }
    }
    catch {
        Write-Status -Type warn -Label "Font install failed" -Detail $_.Exception.Message -Indent
    }
    finally {
        if (Test-Path $zip) { Remove-Item -Path $zip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $dir) { Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Uninstall-NerdFont {
    Write-Status -Type detail -Label "Uninstalling font" -Detail "removing CaskaydiaCove from User and System Fonts" -Indent
    $removedCount = 0

    $fontLocations = @(
        @{ Dir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"; Reg = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" },
        @{ Dir = Join-Path $env:WINDIR "Fonts"; Reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" }
    )

    foreach ($loc in $fontLocations) {
        # 1. Clean Registry (even if files are missing or moved)
        if (Test-Path $loc.Reg) {
            $regProps = Get-ItemProperty -Path $loc.Reg -ErrorAction SilentlyContinue
            if ($regProps) {
                # Find any property names containing Cascadia or Caskaydia
                $matchingKeys = $regProps.PSObject.Properties | Where-Object { $_.Name -match "Cascadia|Caskaydia" } | ForEach-Object { $_.Name }
                foreach ($key in $matchingKeys) {
                    Remove-ItemProperty -Path $loc.Reg -Name $key -Force -ErrorAction SilentlyContinue
                    $removedCount++
                }
            }
        }

        # 2. Clean Files
        if (Test-Path $loc.Dir) {
            $filesPath = Join-Path $loc.Dir "*Cas*.ttf"
            $otfPath = Join-Path $loc.Dir "*Cas*.otf"
            $fontFiles = @(Get-ChildItem -Path $filesPath -ErrorAction SilentlyContinue) + @(Get-ChildItem -Path $otfPath -ErrorAction SilentlyContinue)
            foreach ($f in $fontFiles) {
                if ($f.Name -match "CascadiaCode|CaskaydiaCove") {
                    Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
                    $removedCount++
                }
            }
        }
    }
    
    if ($removedCount -gt 0) {
        Write-Status -Type ok -Label "Nerd Font" -Detail "removed $removedCount font files/registry keys" -Indent
        return $true
    }
    else {
        Write-Status -Type info -Label "Nerd Font" -Detail "not found in User or System Fonts" -Indent
        return $false
    }
}

function Set-TerminalFonts {
    Write-Status -Type detail -Label "Configuring Editors" -Detail "injecting CaskaydiaCove NF into WT and VSCode" -Indent
    
    # 1. Windows Terminal
    $wtPaths = Get-ChildItem -Path "$env:LOCALAPPDATA\Packages" -Filter "Microsoft.WindowsTerminal*" -Directory -ErrorAction SilentlyContinue 
    foreach ($wtDir in $wtPaths) {
        $wtSettings = Join-Path $wtDir.FullName "LocalState\settings.json"
        if (Test-Path $wtSettings) {
            $content = Get-Content $wtSettings -Raw
            if ($content -notmatch '"face"\s*:\s*"CaskaydiaCove[^"]*"' -and $content -notmatch '"fontFace"\s*:\s*"CaskaydiaCove[^"]*"') {
                if ($content -match '"defaults"\s*:\s*\{\s*\}') {
                    $content = $content -replace '"defaults"\s*:\s*\{\s*\}', '"defaults": { "font": { "face": "CaskaydiaCove NF" } }'
                    Set-Content -Path $wtSettings -Value $content -Encoding UTF8
                } elseif ($content -match '"defaults"\s*:\s*\{') {
                    $content = $content -replace '("defaults"\s*:\s*\{)(\s*"[^"]+")', ('$1' + "`n            `"font`": { `"face`": `"CaskaydiaCove NF`" }," + '$2')
                    Set-Content -Path $wtSettings -Value $content -Encoding UTF8
                }
            }
        }
    }

    # 2. VS Code
    $vscodeSettingsDirs = @(
        (Join-Path $env:APPDATA "Code\User"),
        (Join-Path $env:APPDATA "Code - Insiders\User")
    )
    foreach ($dir in $vscodeSettingsDirs) {
        $vscodePath = Join-Path $dir "settings.json"
        if (Test-Path $vscodePath) {
            $content = Get-Content $vscodePath -Raw
            if ($content -match '"editor\.fontFamily"\s*:') {
                if ($content -notmatch 'CaskaydiaCove NF') {
                    $content = $content -replace '("editor\.fontFamily"\s*:\s*)"([^"]+)"', ('$1"' + "CaskaydiaCove NF, `$2" + '"')
                    Set-Content -Path $vscodePath -Value $content -Encoding UTF8
                }
            }
            else {
                $content = $content -replace '^\{\s*', "{`n    `"editor.fontFamily`": `"CaskaydiaCove NF, Consolas, 'Courier New', monospace`",`n"
                Set-Content -Path $vscodePath -Value $content -Encoding UTF8
            }
        }
    }
    
    Write-Status -Type ok -Label "Configuration" -Detail "WT and VSCode updated to use Nerd Font" -Indent
}

function Install-TerminalSetup {
    param(
        [Parameter(Mandatory = $true)][string]$ThemesDir
    )

    Write-Section "Terminal Setup"
    
    Save-TerminalThemes -ThemesDir $ThemesDir
    Install-NerdFont
    Set-TerminalFonts
}

function Get-CoreShimToolCatalog {
    return @(
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

function Get-OptionalToolsStatePath {
    $base = if ($script:PathScope -eq "User") {
        if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
    }
    else {
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
    }
    catch {
        return @()
    }
}

function Write-OptionalToolState([object[]]$Records) {
    $statePath = Get-OptionalToolsStatePath
    $stateDir = Split-Path -Parent $statePath
    if ($stateDir -and -not (Test-Path $stateDir)) {
        if ($script:DryRun) {
            Write-Host "[DRYRUN] New-Item -ItemType Directory -Path '$stateDir'" -ForegroundColor DarkGray
        }
        else {
            New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
        }
    }

    if (-not $Records -or $Records.Count -eq 0) {
        if (Test-Path $statePath) {
            if ($script:DryRun) {
                Write-Host "[DRYRUN] Remove-Item -Path '$statePath'" -ForegroundColor DarkGray
            }
            else {
                Remove-Item -Path $statePath -Force -ErrorAction SilentlyContinue
            }
        }
        return
    }

    $json = $Records | ConvertTo-Json -Depth 6
    if ($script:DryRun) {
        Write-Host "[DRYRUN] Set-Content '$statePath' (JSON data)" -ForegroundColor DarkGray
    }
    else {
        $tmp = "$statePath.tmp"
        try {
            Set-Content -Path $tmp -Value $json -Encoding UTF8
            Move-Item -Path $tmp -Destination $statePath -Force
        }
        catch {
            Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
            throw
        }
    }
}

function Install-MissingOptionalTools([object[]]$Catalog) {
    if (-not $Catalog -or $Catalog.Count -eq 0) { return @() }

    $pmProbe = @(Initialize-OptionalPackageManagers)
    $pm = @(
        $pmProbe | Where-Object {
            $_ -and
            $_.PSObject -and
            $_.PSObject.Properties["Winget"] -and
            $_.PSObject.Properties["Choco"]
        }
    ) | Select-Object -Last 1

    if (-not $pm) {
        Write-Status -Type warn -Label "No package manager" -Detail "missing tools cannot be auto-installed"
        Write-PackageManagerInstallGuidance
        return @()
    }

    $wingetAvailable = [bool]$pm.PSObject.Properties["Winget"].Value
    $chocoAvailable = [bool]$pm.PSObject.Properties["Choco"].Value
    $hasAnyPackageManager = $wingetAvailable -or $chocoAvailable
    $newlyInstalled = @()

    if (-not $hasAnyPackageManager) {
        $missingCommands = @(
            $Catalog |
            Where-Object {
                $_.Command -and -not (Get-Command ([string]$_.Command) -CommandType Application -ErrorAction SilentlyContinue)
            } |
            ForEach-Object { [string]$_.Command }
        )

        if ($missingCommands.Count -gt 0) {
            Write-Status -Type warn -Label "No package manager" -Detail "cannot auto-install missing tools"
            Write-Dim "Missing: $($missingCommands -join ', ')"
            Write-PackageManagerInstallGuidance
        }
        return @()
    }

    foreach ($tool in $Catalog) {
        $commandName = [string]$tool.Command
        if ([string]::IsNullOrWhiteSpace($commandName)) { continue }

        if (Get-Command $commandName -CommandType Application -ErrorAction SilentlyContinue) {
            continue
        }

        $installed = $false
        $attempted = @()
        $attemptedExit = @{}
        $managerUsed = $null
        $packageIdUsed = $null

        if ($wingetAvailable -and $tool.WingetId) {
            $attempted += "winget"
            Write-Dim "Installing $commandName via winget ($($tool.WingetId))..."
            if ($script:DryRun) {
                Write-DryRun "winget install --id $($tool.WingetId) ..."
                $exitCode = 0
            }
            else {
                $exitCode = Invoke-NativeCommand winget install --id $tool.WingetId --exact --source winget --accept-package-agreements --accept-source-agreements
            }
            $attemptedExit['winget'] = $exitCode
            if ($exitCode -eq 0) {
                $installed = $true
                $managerUsed = "winget"
                $packageIdUsed = [string]$tool.WingetId
            }
        }

        if (-not $installed -and $chocoAvailable -and $tool.ChocoId) {
            $attempted += "choco"
            Write-Dim "Installing $commandName via choco ($($tool.ChocoId))..."
            if ($script:DryRun) {
                Write-DryRun "choco install $($tool.ChocoId) -y"
                $exitCode = 0
            }
            else {
                $exitCode = Invoke-NativeCommand choco install $tool.ChocoId -y
            }
            $attemptedExit['choco'] = $exitCode
            if ($exitCode -eq 0) {
                $installed = $true
                $managerUsed = "choco"
                $packageIdUsed = [string]$tool.ChocoId
            }
        }

        if (-not $installed) {
            Update-SessionPath
            if (Get-Command $commandName -CommandType Application -ErrorAction SilentlyContinue) {
                $installed = $true
                if (-not $managerUsed) { $managerUsed = "detected" }
                if (-not $packageIdUsed) { $packageIdUsed = "n/a" }
            }
        }

        if ($installed) {
            $newlyInstalled += [pscustomobject]@{
                Command       = $commandName
                Manager       = $managerUsed
                PackageId     = $packageIdUsed
                InstalledAt   = (Get-Date).ToString("o")
                ScriptVersion = $ScriptVersion
            }
            Write-Status -Type ok -Label "Installed" -Detail "$commandName via $managerUsed" -Indent
        }
        else {
            Write-Status -Type info -Label "Not installed" -Detail "$commandName" -Indent
            if ($attempted.Count -gt 0) {
                Write-Dim "Attempted via: $($attempted -join ', ')" -Indent
                $exitDetails = @()
                foreach ($m in $attempted) {
                    if ($attemptedExit.ContainsKey($m)) {
                        $exitDetails += ("{0}={1}" -f $m, $attemptedExit[$m])
                    }
                }
                if ($exitDetails.Count -gt 0) {
                    Write-Dim "Exit codes: $($exitDetails -join ', ')" -Indent
                }
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
        Update-SessionPath
    }
    return $newlyInstalled
}

function Uninstall-TrackedOptionalTools {
    $tracked = @(Read-OptionalToolState)
    if ($tracked.Count -eq 0) { return 0 }

    $removedCount = 0
    $remaining = @()
    foreach ($item in $tracked) {
        $kind = if ($item.PSObject.Properties["Kind"]) { [string]$item.Kind } else { "" }
        $commandName = [string]$item.Command
        $moduleName = if ($item.PSObject.Properties["ModuleName"]) { [string]$item.ModuleName } else { "" }
        $manager = [string]$item.Manager
        $packageId = [string]$item.PackageId

        if ($kind -eq "PowerShellModule" -or -not [string]::IsNullOrWhiteSpace($moduleName)) {
            if ([string]::IsNullOrWhiteSpace($moduleName)) {
                $remaining += $item
                continue
            }

            $ok = $false
            try {
                if ($script:DryRun) {
                    if ($manager -eq "psresourceget") {
                        Write-Host "[DRYRUN] Uninstall-PSResource $moduleName" -ForegroundColor DarkGray
                    }
                    else {
                        Write-Host "[DRYRUN] Uninstall-Module $moduleName -AllVersions -Force" -ForegroundColor DarkGray
                    }
                    $ok = $true
                }
                elseif ($manager -eq "psresourceget" -and (Get-Command Uninstall-PSResource -ErrorAction SilentlyContinue)) {
                    Uninstall-PSResource -Name $moduleName -Scope CurrentUser -Quiet -ErrorAction Stop
                    $ok = $true
                }
                elseif (Get-Command Uninstall-Module -ErrorAction SilentlyContinue) {
                    Uninstall-Module -Name $moduleName -AllVersions -Force -ErrorAction Stop
                    $ok = $true
                }
            }
            catch {
                Write-Status -Type warn -Label "Module uninstall failed" -Detail "${moduleName}: $($_.Exception.Message)"
            }

            if ($ok) {
                $removedCount++
                Write-Status -Type ok -Label "Module removed" -Detail $moduleName
            }
            else {
                $remaining += $item
            }
            continue
        }

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
                if ($script:DryRun) {
                    Write-Host "[DRYRUN] winget uninstall --id $packageId ..." -ForegroundColor DarkGray
                    $exitCode = 0
                }
                else {
                    $exitCode = Invoke-NativeCommand winget uninstall --id $packageId --exact --source winget --accept-source-agreements
                }
                $ok = ($exitCode -eq 0)
                break
            }
            "choco" {
                if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                    break
                }
                Write-Host "  [INFO] Uninstalling optional tool: $commandName via choco ($packageId)..." -ForegroundColor DarkGray
                if ($script:DryRun) {
                    Write-Host "[DRYRUN] choco uninstall $packageId -y" -ForegroundColor DarkGray
                    $exitCode = 0
                }
                else {
                    $exitCode = Invoke-NativeCommand choco uninstall $packageId -y
                }
                $ok = ($exitCode -eq 0)
                break
            }
            default {
                break
            }
        }

        if ($ok) {
            $removedCount++
            Write-Host "  [OK] Removed optional tool: $commandName" -ForegroundColor Green
        }
        else {
            $remaining += $item
        }
    }

    Write-OptionalToolState -Records $remaining
    if ($removedCount -gt 0) {
        Update-SessionPath
    }
    return $removedCount
}

function Start-ScriptTranscript([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $resolved = [System.IO.Path]::GetFullPath($Path)
    $sensitiveRoots = @($env:WINDIR, $env:SYSTEMROOT) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    foreach ($root in $sensitiveRoots) {
        if ($resolved.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
            throw "LogPath must not point inside the Windows system directory: $resolved"
        }
    }
    $dir = Split-Path -Parent $resolved
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Start-Transcript -Path $resolved -Append -Force | Out-Null
    return $true
}

function Stop-ScriptTranscript {
    try {
        Stop-Transcript | Out-Null
    }
    catch {
        Write-Verbose "No active transcript to stop: $($_.Exception.Message)"
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
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
    [Environment]::GetEnvironmentVariable("Path", "User")
}

$script:ProfileBackupPath = $null
function Backup-ProfileFile {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)

    if (-not (Test-Path $ProfilePath)) { return $null }
    if ($script:ProfileBackupPath) { return $script:ProfileBackupPath }

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backup = "$ProfilePath.bak-$stamp"
    if ($script:DryRun) {
        Write-Host "[DRYRUN] Backup-ProfileFile: $ProfilePath -> $backup" -ForegroundColor DarkGray
    }
    else {
        Copy-Item -Path $ProfilePath -Destination $backup -Force
    }
    $script:ProfileBackupPath = $backup
    return $backup
}

function Set-ProfileBlock {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$StartMarker,
        [Parameter(Mandatory = $true)][string]$EndMarker,
        [Parameter(Mandatory = $true)][string]$BlockBody
    )

    $profileDir = Split-Path -Parent $ProfilePath
    if ($profileDir -and -not (Test-Path $profileDir)) {
        if ($script:DryRun) {
            Write-Host "[DRYRUN] New-Item -ItemType Directory -Path '$profileDir'" -ForegroundColor DarkGray
        }
        else {
            New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
        }
    }
    if (-not (Test-Path $ProfilePath)) {
        if ($script:DryRun) {
            Write-Host "[DRYRUN] New-Item -ItemType File -Path '$ProfilePath'" -ForegroundColor DarkGray
        }
        else {
            New-Item -ItemType File -Path $ProfilePath -Force | Out-Null
        }
    }

    $existing = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
    if ($null -eq $existing) { $existing = "" }

    $newBlock = @(
        $StartMarker
        $BlockBody
        $EndMarker
        ""
    ) -join "`r`n"


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

    if ($script:DryRun) {
        Write-Host "[DRYRUN] Set-Content '$ProfilePath' (updated profile block)" -ForegroundColor DarkGray
    }
    else {
        $tmp = "$ProfilePath.tmp"
        try {
            Set-Content -Path $tmp -Value $updated -Encoding UTF8
            Move-Item -Path $tmp -Destination $ProfilePath -Force
        }
        catch {
            Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
            throw
        }
    }
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

    $pattern = "(?ms)^\s*$([regex]::Escape($StartMarker))\s*$.*?^\s*$([regex]::Escape($EndMarker))\s*(\r?\n)?"
    $updated = [regex]::Replace($existing, $pattern, "")

    $startLinePattern = "(?m)^\s*$([regex]::Escape($StartMarker))\s*(\r?\n)?"
    $endLinePattern = "(?m)^\s*$([regex]::Escape($EndMarker))\s*(\r?\n)?"
    $updated = [regex]::Replace($updated, $startLinePattern, "")
    $updated = [regex]::Replace($updated, $endLinePattern, "")

    if ($updated -ne $existing) {
        if ($script:DryRun) {
            Write-Host "[DRYRUN] Set-Content '$ProfilePath' (removed profile block)" -ForegroundColor DarkGray
        }
        else {
            # Atomic write: temp+rename to prevent partial writes.
            $tmp = "$ProfilePath.tmp"
            try {
                Set-Content -Path $tmp -Value $updated -Encoding UTF8
                Move-Item -Path $tmp -Destination $ProfilePath -Force
            }
            catch {
                Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
                throw
            }
        }
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
    if ($script:DryRun) {
        Write-Host "[DRYRUN] Set-Content '$ProfilePath' (removed managed blocks)" -ForegroundColor DarkGray
    }
    else {
        $tmp = "$ProfilePath.tmp"
        try {
            Set-Content -Path $tmp -Value $updated -Encoding UTF8
            Move-Item -Path $tmp -Destination $ProfilePath -Force
        }
        catch {
            Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
            throw
        }
    }
}

function Remove-InstalledProfileShims {
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $backup = Backup-ProfileFile -ProfilePath $profilePath
    if ($backup) { Write-Verbose "Profile backup: $backup" }
    Remove-ManagedProfileBlocks -ProfilePath $profilePath
    $markers = @(
        @{ Start = "# >>> unix-tools-fast-shims >>>"; End = "# <<< unix-tools-fast-shims <<<" },
        @{ Start = "# >>> unix-tools-missing-shims >>>"; End = "# <<< unix-tools-missing-shims <<<" },
        @{ Start = "# >>> unix-tools-alias-compat >>>"; End = "# <<< unix-tools-alias-compat <<<" },
        @{ Start = "# >>> unix-tools-smart-shell >>>"; End = "# <<< unix-tools-smart-shell <<<" },
        @{ Start = "# >>> codex-smart-shell >>>"; End = "# <<< codex-smart-shell <<<" },
        @{ Start = "# >>> git-tools-missing-shims >>>"; End = "# <<< git-tools-missing-shims <<<" },
        @{ Start = "# >>> git-tools-alias-compat >>>"; End = "# <<< git-tools-alias-compat <<<" },
        @{ Start = "# >>> unix-tools-terminal-setup >>>"; End = "# <<< unix-tools-terminal-setup <<<" }
    )

    foreach ($m in $markers) {
        Remove-ProfileBlock -ProfilePath $profilePath -StartMarker $m.Start -EndMarker $m.End
    }

    $legacyResult = Remove-LegacyInlineProfileShims -ProfilePath $profilePath
    switch ($legacyResult.Status) {
        'Removed' {
            Write-Status -Type ok -Label "Legacy inline shims" -Detail $legacyResult.Detail
        }
        'Ambiguous' {
            Write-Status -Type warn -Label "Legacy inline shims" -Detail $legacyResult.Detail
        }
    }

    return $legacyResult
}

function Install-ProfileInlineShims {
    param(
        [string]$ThemesDir,
        [string]$Theme = "pure",
        [ValidateSet('Fast', 'Legacy')][string]$StartupMode = 'Fast',
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptMode = 'Lazy'
    )
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $backup = Backup-ProfileFile -ProfilePath $profilePath
    if ($backup) { Write-Status -Type detail -Label "Profile backup" -Detail (Split-Path $backup -Leaf) }

    Remove-InstalledProfileShims
    Install-ProfileMissingShims
    Install-ProfileAliasCompat
    Install-ProfileSmartShell -StartupMode $StartupMode
    if ($ThemesDir -and $PromptMode -ne 'Off') {
        Install-ProfileOhMyPosh -ThemesDir $ThemesDir -Theme $Theme -PromptInitMode $PromptMode
    }
    Write-Status -Type ok -Label "Profile blocks" -Detail "inline (startup=$StartupMode, prompt=$PromptMode) -> $profilePath"
    return "inline"
}

function Install-ProfileMissingShims {
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $backup = Backup-ProfileFile -ProfilePath $profilePath
    if ($backup) { Write-Verbose "Profile backup: $backup" }
    $startMarker = "# >>> unix-tools-missing-shims >>>"
    $endMarker = "# <<< unix-tools-missing-shims <<<"
    $legacyStart = "# >>> git-tools-missing-shims >>>"
    $legacyEnd = "# <<< git-tools-missing-shims <<<"

    $genericFallbackBlock = ""

    $blockBody = @'
# Add Unix-style shims with lazy executable resolution for fast startup.
# Each shim checks for a real executable at invocation time and caches results.
$script:__UnixExeCache = @{}
$script:__UnixExeMissing = New-Object object

function Get-UnixShimExecutable {
    param([Parameter(Mandatory = $true)][string]$Name)
    $key = $Name.ToLowerInvariant()
    if ($script:__UnixExeCache.ContainsKey($key)) {
        $cached = $script:__UnixExeCache[$key]
        if ($cached -eq $script:__UnixExeMissing) { return $null }
        return $cached
    }

    $app = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($app) {
        $script:__UnixExeCache[$key] = $app
        return $app
    }

    $script:__UnixExeCache[$key] = $script:__UnixExeMissing
    return $null
}

function Clear-UnixShimCache {
    if ($script:__UnixExeCache) { $script:__UnixExeCache.Clear() }
}

function Reset-UnixShimName {
    param([Parameter(Mandatory = $true)][string]$Name)
    Remove-Item ("Alias:" + $Name) -Force -ErrorAction SilentlyContinue
    Remove-Item ("Alias:Global:" + $Name) -Force -ErrorAction SilentlyContinue
    Remove-Item ("Function:" + $Name) -Force -ErrorAction SilentlyContinue
    Remove-Item ("Function:Global:" + $Name) -Force -ErrorAction SilentlyContinue
}

function Add-UnixShimIfMissing {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Body
    )

    Reset-UnixShimName -Name $Name

    $fb = $Body
    $wrapper = {
        $commandName = $MyInvocation.MyCommand.Name
        $app = Get-UnixShimExecutable -Name $commandName
        if ($app) {
            if ($MyInvocation.ExpectingInput) {
                $input | & $app.Source @args
            }
            else {
                & $app.Source @args
            }
            return
        }

        if ($MyInvocation.ExpectingInput) {
            $input | & $fb @args
        }
        else {
            & $fb @args
        }
    }.GetNewClosure()

    Set-Item -Path ("Function:\Global:" + $Name) -Value $wrapper
}

Add-UnixShimIfMissing -Name "export" -Body {
    $Assignments = @($args)
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
    $Names = @($args)
    foreach ($name in $Names) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            Remove-Item -Path ("Env:" + $name) -ErrorAction SilentlyContinue
        }
    }
}

Add-UnixShimIfMissing -Name "mkdirp" -Body {
    $Paths = @($args)
    foreach ($path in $Paths) {
        if (-not [string]::IsNullOrWhiteSpace($path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

Add-UnixShimIfMissing -Name "ll" -Body {
    $ArgList = @($args)
    Get-ChildItem -Force @ArgList
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
    $ArgList = @($args)
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
    $Paths = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
    Invoke-GrepShim -ArgList $ArgList -InputItems @($input)
}

Add-UnixShimIfMissing -Name "egrep" -Body {
    $ArgList = @($args)
    Invoke-GrepShim -ArgList $ArgList -InputItems @($input)
}

Add-UnixShimIfMissing -Name "fgrep" -Body {
    $ArgList = @($args)
    Invoke-GrepShim -ArgList $ArgList -InputItems @($input) -SimpleMatch
}

Add-UnixShimIfMissing -Name "rgf" -Body {
    $Pattern = $args[0]
    if (-not $Pattern) { throw "rgf: pattern required. Usage: rgf <pattern> [path ...]" }
    $Rest = @()
    if ($args.Count -gt 1) { $Rest = $args[1..($args.Count - 1)] }
    $rg = Get-Command rg -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $rg) {
        throw "rgf: ripgrep 'rg' not found. Install with -InstallOptionalTools or winget install --id BurntSushi.ripgrep.MSVC --exact."
    }
    & $rg.Source -n -F -- $Pattern @Rest
}
function Invoke-RgFallback {
    param(
        [object[]]$ArgList,
        [object[]]$InputItems
    )

    $patterns = New-Object System.Collections.Generic.List[string]
    $paths = New-Object System.Collections.Generic.List[string]
    $ignoreCase = $false
    $lineNumber = $false
    $invert = $false
    $simpleMatch = $false
    $recursive = $true

    $i = 0
    while ($i -lt $ArgList.Count) {
        $a = [string]$ArgList[$i]

        if ($a -eq "--") {
            if ($i + 1 -lt $ArgList.Count) {
                for ($j = $i + 1; $j -lt $ArgList.Count; $j++) {
                    $paths.Add([string]$ArgList[$j]) | Out-Null
                }
            }
            break
        }

        if ($a -eq "-e") {
            if ($i + 1 -ge $ArgList.Count) { throw "rg fallback: -e requires a pattern value" }
            $patterns.Add([string]$ArgList[$i + 1]) | Out-Null
            $i += 2
            continue
        }

        if ($a.StartsWith("-e") -and $a.Length -gt 2) {
            $patterns.Add($a.Substring(2)) | Out-Null
            $i++
            continue
        }

        switch ($a) {
            "-n"            { $lineNumber = $true; $i++; continue }
            "--line-number" { $lineNumber = $true; $i++; continue }
            "-i"            { $ignoreCase = $true; $i++; continue }
            "--ignore-case" { $ignoreCase = $true; $i++; continue }
            "-S"            { $i++; continue } # Smart-case is a no-op in this fallback.
            "--smart-case"  { $i++; continue }
            "-F"            { $simpleMatch = $true; $i++; continue }
            "--fixed-strings" { $simpleMatch = $true; $i++; continue }
            "-v"            { $invert = $true; $i++; continue }
            "--invert-match" { $invert = $true; $i++; continue }
            "-r"            { $recursive = $true; $i++; continue }
            "-R"            { $recursive = $true; $i++; continue }
        }

        if ($a.StartsWith("--")) {
            throw "rg fallback: unsupported option $a (supports -e, -n, -i, -S, -F, -v, -r, -R). Install ripgrep for full support."
        }

        if ($a -match '^-[A-Za-z]+$') {
            $unsupported = @()
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'n' { $lineNumber = $true; break }
                    'i' { $ignoreCase = $true; break }
                    'S' { break }
                    'F' { $simpleMatch = $true; break }
                    'v' { $invert = $true; break }
                    'r' { $recursive = $true; break }
                    'R' { $recursive = $true; break }
                    default { $unsupported += "-$ch"; break }
                }
            }
            if ($unsupported.Count -gt 0) {
                throw "rg fallback: unsupported option(s) $($unsupported -join ', ') (supports -e, -n, -i, -S, -F, -v, -r, -R). Install ripgrep for full support."
            }
            $i++
            continue
        }

        if ($patterns.Count -eq 0) {
            $patterns.Add($a) | Out-Null
        } else {
            $paths.Add($a) | Out-Null
        }
        $i++
    }

    if ($patterns.Count -eq 0) {
        throw "usage: rg [-n] [-S] [-i] [-F] [-v] [-e PATTERN ...] [PATTERN] [path ...]"
    }

    $caseSensitive = -not $ignoreCase
    $result = $null

    if ($paths.Count -gt 0) {
        $targets = @()
        foreach ($p in $paths) {
            if (Test-Path -Path $p -PathType Container) {
                $targets += (Join-Path $p "*")
            } else {
                $targets += $p
            }
        }
        $result = Select-String -Pattern @($patterns) -Path $targets -Recurse:$recursive -SimpleMatch:$simpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
    } elseif ($InputItems -and $InputItems.Count -gt 0) {
        $result = $InputItems | Select-String -Pattern @($patterns) -SimpleMatch:$simpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert
    } else {
        $result = Select-String -Pattern @($patterns) -Path @(".\*") -Recurse:$true -SimpleMatch:$simpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
    }

    if ($lineNumber) {
        $result | ForEach-Object { "{0}:{1}:{2}" -f $_.Path, $_.LineNumber, $_.Line }
    } else {
        $result
    }
}
Add-UnixShimIfMissing -Name "rgs" -Body {
    $ArgList = @($args)
    $stdinItems = @($input)
    $rg = Get-Command rg -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $rg) {
        Invoke-RgFallback -ArgList $ArgList -InputItems $stdinItems
        return
    }

    if ($stdinItems.Count -gt 0) {
        $output = $stdinItems | & $rg.Source @ArgList 2>&1
    } else {
        $output = & $rg.Source @ArgList 2>&1
    }
    $exit = $LASTEXITCODE
    if ($exit -eq 0) {
        $output
        return
    }

    if (-not ($ArgList -contains "--")) {
        $flagToken = $null
        foreach ($line in @($output)) {
            if ([string]$line -match "unrecognized flag (.+)$") {
                $flagToken = $matches[1].Trim()
                break
            }
        }
        if ($flagToken) {
            $idx = [Array]::IndexOf($ArgList, $flagToken)
            if ($idx -ge 0) {
                $fixedArgs = @()
                if ($idx -gt 0) { $fixedArgs += $ArgList[0..($idx - 1)] }
                $fixedArgs += "--"
                $fixedArgs += $ArgList[$idx..($ArgList.Count - 1)]
                $retry = & $rg.Source @fixedArgs 2>&1
                $retryExit = $LASTEXITCODE
                if ($retryExit -eq 0) {
                    $retry
                    return
                }
                $output = $retry
                $exit = $retryExit
            }
        }
    }

    foreach ($line in @($output)) {
        [Console]::Error.WriteLine([string]$line)
    }
    $global:LASTEXITCODE = $exit
}
if (-not (Get-Command rgl -ErrorAction SilentlyContinue)) {
    Set-Alias -Name rgl -Value rgf -Scope Global
}
Add-UnixShimIfMissing -Name "rg" -Body {
    $ArgList = @($args)
    $stdinItems = @($input)
    $rgExe = Get-Command rg -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($rgExe) {
        if ($stdinItems.Count -gt 0) {
            $stdinItems | & $rgExe.Source @ArgList
        } else {
            & $rgExe.Source @ArgList
        }
        return
    }
    Invoke-RgFallback -ArgList $ArgList -InputItems $stdinItems
}

Add-UnixShimIfMissing -Name "nc" -Body {
    $ArgList = @($args)
    $ncat = Get-Command ncat -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ncat) {
        throw "nc: command not found. Install ncat (winget install --id Insecure.Nmap --exact)."
    }
    & $ncat.Source @ArgList
}

Add-UnixShimIfMissing -Name "which" -Body {
    $Names = @($args)
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
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: man <command>" }
    Get-Help $ArgList[0] -Full
}

Add-UnixShimIfMissing -Name "source" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: source <script> [args...]" }
    $path = $ArgList[0]
    if (-not (Test-Path $path)) { throw "source: file not found: $path" }
    # Canonicalize path to prevent traversal attacks.
    $path = (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path
    if (-not $path.EndsWith('.ps1') -and -not $path.EndsWith('.psm1')) {
        Write-Warning "source: dot-sourcing non-PowerShell file: $path"
    }
    $rest = @()
    if ($ArgList.Count -gt 1) { $rest = $ArgList[1..($ArgList.Count - 1)] }
    . $path @rest
}

Add-UnixShimIfMissing -Name "apropos" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: apropos <keyword>" }
    $pattern = "*" + (($ArgList -join " ").Trim()) + "*"
    Get-Help $pattern -ErrorAction SilentlyContinue |
        Select-Object Name, Synopsis |
        Sort-Object Name
}

Add-UnixShimIfMissing -Name "make" -Body {
    $ArgList = @($args)
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
    $ArgList = @($args)
    # Block potentially dangerous URI schemes.
    $dangerousSchemes = @('javascript', 'vbscript', 'data', 'shell')
    if ($ArgList.Count -eq 0) {
        Write-Verbose "open: launching current directory"
        Start-Process -FilePath "."
        return
    }
    foreach ($target in $ArgList) {
        foreach ($scheme in $dangerousSchemes) {
            if ($target -match "^${scheme}:") {
                throw "open: blocked potentially dangerous URI scheme '${scheme}:'"
            }
        }
        Write-Verbose "open: launching '$target'"
        Start-Process -FilePath $target
    }
}

Add-UnixShimIfMissing -Name "xdg-open" -Body {
    $ArgList = @($args)
    open @ArgList
}

Add-UnixShimIfMissing -Name "rename" -Body {
    $ArgList = @($args)
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
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: dos2unix <file...>" }
    foreach ($path in $ArgList) {
        $text = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        $out = ($text -replace "`r`n", "`n") -replace "`r", "`n"
        Set-Content -LiteralPath $path -Value $out -NoNewline -Encoding utf8NoBOM
    }
}

Add-UnixShimIfMissing -Name "unix2dos" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: unix2dos <file...>" }
    foreach ($path in $ArgList) {
        $text = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        $normalized = ($text -replace "`r`n", "`n") -replace "`r", "`n"
        $out = $normalized -replace "`n", "`r`n"
        Set-Content -LiteralPath $path -Value $out -NoNewline -Encoding utf8NoBOM
    }
}

Add-UnixShimIfMissing -Name "vdir" -Body {
    $ArgList = @($args)
    Get-ChildItem -Force @ArgList | Format-Table Mode, LastWriteTime, Length, Name -AutoSize
}

Add-UnixShimIfMissing -Name "link" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -ne 2) { throw "usage: link <target> <linkpath>" }
    New-Item -ItemType HardLink -Path $ArgList[1] -Target $ArgList[0] -Force | Out-Null
}

Add-UnixShimIfMissing -Name "tput" -Body {
    $ArgList = @($args)
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
    $ArgList = @($args)
    if ($ArgList.Count -lt 2) { throw "usage: at HH:mm <command...>" }
    $time = $ArgList[0]
    # Strict 24-hour time validation to prevent injection via /ST parameter.
    if ($time -notmatch '^([01]\d|2[0-3]):[0-5]\d$') { throw "at: time format must be HH:mm (24-hour, e.g. 09:30 or 14:00)" }
    $commandText = ($ArgList[1..($ArgList.Count - 1)] -join " ")
    $taskName = "unix-at-" + ([guid]::NewGuid().ToString("N").Substring(0, 8))
    # Properly quote the command to prevent injection via schtasks /TR.
    $escapedCmd = $commandText -replace '"', '\"'
    $wrappedCommand = "cmd /c `"$escapedCmd`" & schtasks /Delete /TN $taskName /F"
    & schtasks /Create /SC ONCE /TN $taskName /TR "`"$wrappedCommand`"" /ST $time /F | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "at: failed to create scheduled task." }
    Write-Output $taskName
}

Add-UnixShimIfMissing -Name "aspell" -Body {
    throw "aspell: fallback unavailable. Install aspell and re-run setup to get executable pass-through."
}

Add-UnixShimIfMissing -Name "bc" -Body {
    $ArgList = @($args)
    $expr = if ($ArgList.Count -gt 0) { $ArgList -join " " } else { ($input | Out-String).Trim() }
    if ([string]::IsNullOrWhiteSpace($expr)) { throw "usage: bc <expression>" }
    # Validate expression against a safe allowlist (digits, operators, parens, decimal).
    if ($expr -notmatch '^[\d\s\+\-\*/\(\)\.,]+$') {
        throw "bc: expression contains disallowed characters (only digits, operators, parens, decimal allowed)"
    }
    $table = New-Object System.Data.DataTable
    $result = $table.Compute($expr, $null)
    Write-Output $result
}

Add-UnixShimIfMissing -Name "base64" -Body {
    $ArgList = @($args)
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
        # WARNING: Writes raw decoded bytes to stdout. This matches Unix base64 -d behavior
        # but callers should be aware that arbitrary binary content may be emitted.
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
    $ArgList = @($args)

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
    $ArgList = @($args)
    # Compatibility fallback: reuse cksum output format.
    cksum @ArgList
}

Add-UnixShimIfMissing -Name "pv" -Body {
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
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

__UNIX_GENERIC_FALLBACK_BLOCK__
'@
    $blockBody = $blockBody.Replace("__UNIX_GENERIC_FALLBACK_BLOCK__", $genericFallbackBlock)

    Remove-ProfileBlock -ProfilePath $profilePath -StartMarker $legacyStart -EndMarker $legacyEnd
    Set-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker -BlockBody $blockBody
    Write-Status -Type ok -Label "Profile blocks" -Detail "missing-shims updated -> $profilePath"
}

function Install-ProfileAliasCompat {
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $backup = Backup-ProfileFile -ProfilePath $profilePath
    if ($backup) { Write-Verbose "Profile backup: $backup" }
    $startMarker = "# >>> unix-tools-alias-compat >>>"
    $endMarker = "# <<< unix-tools-alias-compat <<<"
    $legacyStart = "# >>> git-tools-alias-compat >>>"
    $legacyEnd = "# <<< git-tools-alias-compat <<<"

    $blockBody = @'
# Prefer external Unix tools over PowerShell aliases/functions when available.
# If no external tool exists, install a PowerShell fallback with common Unix flags.
if (-not (Get-Command Get-UnixShimExecutable -CommandType Function -ErrorAction SilentlyContinue)) {
    $script:__UnixExeCache = @{}
    $script:__UnixExeMissing = New-Object object
    function Get-UnixShimExecutable {
        param([Parameter(Mandatory = $true)][string]$Name)
        $key = $Name.ToLowerInvariant()
        if ($script:__UnixExeCache.ContainsKey($key)) {
            $cached = $script:__UnixExeCache[$key]
            if ($cached -eq $script:__UnixExeMissing) { return $null }
            return $cached
        }
        $app = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($app) {
            $script:__UnixExeCache[$key] = $app
            return $app
        }
        $script:__UnixExeCache[$key] = $script:__UnixExeMissing
        return $null
    }
}

if (-not (Get-Command Reset-UnixShimName -CommandType Function -ErrorAction SilentlyContinue)) {
    function Reset-UnixShimName {
        param([Parameter(Mandatory = $true)][string]$Name)
        Remove-Item ("Alias:" + $Name) -Force -ErrorAction SilentlyContinue
        Remove-Item ("Alias:Global:" + $Name) -Force -ErrorAction SilentlyContinue
        Remove-Item ("Function:" + $Name) -Force -ErrorAction SilentlyContinue
        Remove-Item ("Function:Global:" + $Name) -Force -ErrorAction SilentlyContinue
    }
}

function Set-UnixCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Fallback
    )

    Reset-UnixShimName -Name $Name
    $fb = $Fallback
    $wrapper = {
        $commandName = $MyInvocation.MyCommand.Name
        $app = Get-UnixShimExecutable -Name $commandName
        if ($app) {
            if ($MyInvocation.ExpectingInput) {
                $input | & $app.Source @args
            }
            else {
                & $app.Source @args
            }
            return
        }

        if ($MyInvocation.ExpectingInput) {
            $input | & $fb @args
        }
        else {
            & $fb @args
        }
    }.GetNewClosure()

    Set-Item -Path ("Function:\Global:" + $Name) -Value $wrapper
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
    rgf        = [ordered]@{ CoveredFlags = "<pattern> [path ...] (fixed string, line numbers)"; UnsupportedFlags = "Delegated to rg executable" }
    rgl        = [ordered]@{ CoveredFlags = "Alias to rgf"; UnsupportedFlags = "Same as rgf" }
    rgs        = [ordered]@{ CoveredFlags = "[rg args...] passthrough to rg executable with Select-String fallback"; UnsupportedFlags = "Fallback mode supports -e, -n, -i, -S, -F, -v, -r, -R only" }
    rg         = [ordered]@{ CoveredFlags = "Uses rg executable when present; fallback supports -e, -n, -i, -S, -F, -v, -r, -R"; UnsupportedFlags = "Fallback mode supports a subset of rg flags" }
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
    $ArgList = @($args)
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
    Write-Verbose "rm: removing $($paths.Count) path(s): $($paths -join ', ') (recurse=$recurse, force=$force)"
    Remove-Item -Path $paths -Recurse:$recurse -Force:$force
}

Set-UnixCommand -Name "cp" -Fallback {
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    $ArgList = @($args)
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
    Set-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker -BlockBody $blockBody
    Write-Status -Type ok -Label "Profile blocks" -Detail "alias-compat updated -> $profilePath"
}

function Install-ProfileOhMyPosh {
    param(
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [string]$Theme = "pure",
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Lazy'
    )
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $backup = Backup-ProfileFile -ProfilePath $profilePath
    if ($backup) { Write-Verbose "Profile backup: $backup" }
    
    $startMarker = "# >>> unix-tools-terminal-setup >>>"
    $endMarker = "# <<< unix-tools-terminal-setup <<<"

    $blockBody = Get-ProfilePromptBlockBody -ThemesDir $ThemesDir -Theme $Theme -PromptInitMode $PromptInitMode
    if ([string]::IsNullOrWhiteSpace($blockBody)) {
        Remove-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker
        Write-Status -Type ok -Label "Profile blocks" -Detail "terminal-setup skipped (prompt mode Off)"
        return
    }

    Set-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker -BlockBody $blockBody
    Write-Status -Type ok -Label "Profile blocks" -Detail "terminal-setup updated ($PromptInitMode) -> $profilePath"
}

function Install-ProfileSmartShell {
    param(
        [ValidateSet('Fast', 'Legacy')][string]$StartupMode = 'Fast'
    )

    $profilePath = $PROFILE.CurrentUserCurrentHost
    $backup = Backup-ProfileFile -ProfilePath $profilePath
    if ($backup) { Write-Verbose "Profile backup: $backup" }
    $startMarker = "# >>> unix-tools-smart-shell >>>"
    $endMarker = "# <<< unix-tools-smart-shell <<<"

    $blockBody = Get-ProfileSmartShellBlockBody -StartupMode $StartupMode
    Set-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker -BlockBody $blockBody
    Write-Status -Type ok -Label "Profile blocks" -Detail "smart-shell updated ($StartupMode) -> $profilePath"
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
if ($Uninstall -and ($CreateShims -or $AddMingw -or $AddGitCmd -or $InstallProfileShims -or $InstallOptionalTools -or $InstallTerminalSetup -or $InstallFull -or $UninstallFont)) {
    throw "Cannot combine -Uninstall with install switches. Use -Uninstall alone."
}
if ($UninstallOptionalTools -and -not $Uninstall) {
    throw "-UninstallOptionalTools requires -Uninstall."
}

if ($InstallFull) {
    $AddMingw = $true
    $AddGitCmd = $true
    $NormalizePath = $true
    $InstallOptionalTools = $true
    $InstallTerminalSetup = $true
    $CreateShims = $true
    $InstallProfileShims = $true
}

$transcriptStarted = Start-ScriptTranscript -Path $LogPath
try {
    if (-not $ThemesDir) {
        $base = if ($script:PathScope -eq "User") {
            if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
        }
        else {
            $env:ProgramData
        }
        $ThemesDir = Join-Path $base "oh-my-posh-themes\themes"
    }

    $installMode = if ($InstallFull) { "Full install" } elseif ($Uninstall -or $UninstallFont) { "Uninstall" } else { "Custom" }
    Write-Header -Mode $installMode

    if (-not (Assert-Admin)) {
        return
    }

    if (-not $script:DryRun) {
        Backup-PathVariable -Scope $script:PathScope
    }

    $gitRoot = $null
    try {
        $gitRoot = Get-GitRoot
        Write-Status -Type detail -Label "Git discovered" -Detail $gitRoot
    }
    catch {
        if (-not $Uninstall -and -not $UninstallFont) { throw }
        Write-Status -Type info -Label "Git not found" -Detail "uninstall will clean known paths"
    }

    $gitUsrBin = $null
    $gitMingwBin = $null
    $gitCmd = $null
    $shimDir = $null
    $userShimRoot = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
    $userShimDir = Join-Path $userShimRoot "UnixTools\shims"
    if ($gitRoot) {
        $gitUsrBin = Join-Path $gitRoot "usr\bin"
        $gitMingwBin = Join-Path $gitRoot "mingw64\bin"
        $gitCmd = Join-Path $gitRoot "cmd"
        if ($script:PathScope -eq "User") {
            $shimDir = $userShimDir
        }
        else {
            $shimDir = Join-Path $gitRoot "shims"
        }
    }

    $didChange = $false

    if ($UninstallFont) {
        Write-Section "Uninstall Font"
        if (Uninstall-NerdFont) {
            $didChange = $true
            Send-EnvironmentChange
            Update-SessionPath
        }

        if (-not $Uninstall -and -not $InstallFull -and -not $CreateShims -and -not $AddMingw -and -not $AddGitCmd -and -not $NormalizePath -and -not $InstallProfileShims -and -not $InstallOptionalTools -and -not $InstallTerminalSetup) {
            Write-Footer -Message "Font uninstall complete" -Type ok
            return
        }
    }

    if ($Uninstall) {
        Write-Section "Uninstall"

        if ($script:PathScope -eq "User") {
            $candidateShimDirs = @($userShimDir)
            if ($shimDir) { $candidateShimDirs += $shimDir }
        }
        else {
            $candidateShimDirs = @(
                "C:\Program Files\Git\shims",
                "C:\Program Files (x86)\Git\shims"
            )
            if ($shimDir) { $candidateShimDirs += $shimDir }
        }
        $candidateShimDirs = $candidateShimDirs | Select-Object -Unique

        if ($PSCmdlet.ShouldProcess($PROFILE.CurrentUserCurrentHost, "Remove unix-tools profile shim blocks")) {
            $removalResult = Remove-InstalledProfileShims
            $didChange = $true
            $removalDetail = if ($removalResult.Status -eq 'Removed') { "unix-tools markers cleaned + legacy inline block removed" } else { "unix-tools markers cleaned" }
            Write-Status -Type ok -Label "Profile blocks removed" -Detail $removalDetail
        }

        $legacyFastScriptCandidates = @()
        if ($script:PathScope -eq "User") {
            if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
                $legacyFastScriptCandidates += (Join-Path $env:LOCALAPPDATA "UnixTools\Enable-UnixToolsFast.ps1")
            }
            if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
                $legacyFastScriptCandidates += (Join-Path $env:USERPROFILE "UnixTools\Enable-UnixToolsFast.ps1")
            }
        }
        else {
            if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
                $legacyFastScriptCandidates += (Join-Path $env:ProgramData "UnixToolsSystemWide\Enable-UnixToolsFast.ps1")
            }
        }
        foreach ($legacyFastPath in ($legacyFastScriptCandidates | Select-Object -Unique)) {
            if (-not (Test-Path -LiteralPath $legacyFastPath -PathType Leaf)) { continue }
            if ($PSCmdlet.ShouldProcess($legacyFastPath, "Remove legacy Enable-UnixToolsFast.ps1 copy")) {
                if ($script:DryRun) {
                    Write-DryRun "Remove-Item '$legacyFastPath' -Force"
                }
                else {
                    Remove-Item -LiteralPath $legacyFastPath -Force -ErrorAction SilentlyContinue
                    $legacyFastDir = Split-Path -Parent $legacyFastPath
                    if ($legacyFastDir -and (Test-Path -LiteralPath $legacyFastDir -PathType Container)) {
                        $remaining = Get-ChildItem -Path $legacyFastDir -Force -ErrorAction SilentlyContinue
                        if (-not $remaining) {
                            Remove-Item -LiteralPath $legacyFastDir -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                $didChange = $true
                Write-Status -Type ok -Label "Legacy script removed" -Detail (Split-Path $legacyFastPath -Leaf)
            }
        }

        foreach ($sd in $candidateShimDirs) {
            if ($PSCmdlet.ShouldProcess($script:PathDisplay, "Remove shim directory entry $sd")) {
                if (Remove-MachinePathEntries -pathsToRemove @($sd)) {
                    $didChange = $true
                    Write-Status -Type ok -Label "PATH entry removed" -Detail $sd
                }
            }
            if (Test-Path $sd -PathType Container) {
                if ($PSCmdlet.ShouldProcess($sd, "Delete generated .cmd shims")) {
                    if ($script:DryRun) {
                        Write-DryRun "Remove shim files from '$sd'"
                    }
                    else {
                        Get-ChildItem $sd -Filter *.cmd -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                        try {
                            Remove-Item $sd -Force -ErrorAction Stop
                        }
                        catch {
                            Write-Verbose "Shim directory not removed cleanly '$sd': $($_.Exception.Message)"
                        }
                    }
                    $didChange = $true
                    Write-Status -Type ok -Label "Shim files removed" -Detail $sd
                }
            }
        }

        if ($UninstallOptionalTools) {
            if ($PSCmdlet.ShouldProcess("Optional tools", "Uninstall optional tools previously installed by this script")) {
                $removedOptional = Uninstall-TrackedOptionalTools
                if ($removedOptional -gt 0) {
                    $didChange = $true
                    Write-Status -Type ok -Label "Optional items removed" -Detail "$removedOptional item(s)"
                }
                else {
                    Write-Status -Type info -Label "Optional tools" -Detail "none tracked"
                }
            }
        }
        else {
            Write-Status -Type info -Label "Optional tools" -Detail "preserved (use -UninstallOptionalTools to remove tracked items)"
        }

        if ($didChange) {
            Send-EnvironmentChange
            Update-SessionPath
            Write-Status -Type ok -Label "Environment refreshed" -Detail "WM_SETTINGCHANGE broadcasted"
        }
        else {
            Write-Status -Type info -Label "Nothing to uninstall"
        }

        Write-Footer -Message "Uninstall complete" -Type ok
        return
    }

    # ======================== Path Configuration ========================

    Write-Section "Path Configuration"

    $pathsToAdd = @($gitUsrBin)

    if ($AddMingw) {
        if (Test-Path $gitMingwBin) { $pathsToAdd += $gitMingwBin }
        else { Write-Status -Type info -Label "mingw64\bin" -Detail "not found, skipping" }
    }

    if ($AddGitCmd) {
        if (Test-Path $gitCmd) { $pathsToAdd += $gitCmd }
        else { Write-Status -Type info -Label "cmd" -Detail "not found, skipping" }
    }

    $changed = $false
    if ($PSCmdlet.ShouldProcess($script:PathDisplay, "Add tool directories")) {
        $changed = Add-MachinePathEntries $pathsToAdd
    }

    if ($changed) {
        $didChange = $true
        Write-Status -Type ok -Label "Tool directories added" -Detail "to $($script:PathDisplay)"
    }
    else {
        Write-Status -Type ok -Label "Tool directories" -Detail "already in $($script:PathDisplay)"
    }

    if ($NormalizePath) {
        if ($PSCmdlet.ShouldProcess($script:PathDisplay, "Normalize PATH entries")) {
            Update-MachinePathEntries
            $didChange = $true
            Write-Status -Type ok -Label "PATH normalized" -Detail "removed duplicates/trailing slashes"
        }
    }

    # ======================== Terminal Setup ========================
    if ($InstallTerminalSetup) {
        if ($PSCmdlet.ShouldProcess("Terminal Setup", "Install Oh My Posh themes and Nerd Fonts")) {
            Install-TerminalSetup -ThemesDir $ThemesDir
            $didChange = $true
        }
    }

    # ======================== Optional Tools ========================

    $optionalToolCatalog = Get-OptionalToolCatalog
    $optionalModuleCatalog = Get-OptionalPowerShellModuleCatalog
    if ($InstallOptionalTools) {
        Write-Section "Optional Tools"
        if ($PSCmdlet.ShouldProcess("Optional tools", "Install missing optional tools via package managers")) {
            $presentBefore = @($optionalToolCatalog | Where-Object {
                    $_.Command -and (Get-Command ([string]$_.Command) -CommandType Application -ErrorAction SilentlyContinue)
                } | ForEach-Object { [string]$_.Command })
            $presentModulesBefore = @($optionalModuleCatalog | Where-Object {
                    $_.ModuleName -and (Get-Module -ListAvailable ([string]$_.ModuleName))
                } | ForEach-Object { [string]$_.ModuleName })

            $installedOptional = @(Install-MissingOptionalTools -Catalog $optionalToolCatalog)
            $installedOptionalModules = @(Install-MissingOptionalPowerShellModules -Catalog $optionalModuleCatalog)
            Update-SessionPath

            $presentAfter = @($optionalToolCatalog | Where-Object {
                    $_.Command -and (Get-Command ([string]$_.Command) -CommandType Application -ErrorAction SilentlyContinue)
                } | ForEach-Object { [string]$_.Command })
            $missingAfter = @($optionalToolCatalog | Where-Object {
                    $_.Command -and -not (Get-Command ([string]$_.Command) -CommandType Application -ErrorAction SilentlyContinue)
                } | ForEach-Object { [string]$_.Command })
            $newlyDetected = @($presentAfter | Where-Object { $_ -notin $presentBefore })
            $alreadyPresent = @($presentBefore | Sort-Object -Unique)
            $presentAfter = @($presentAfter | Sort-Object -Unique)
            $missingAfter = @($missingAfter | Sort-Object -Unique)
            $presentModulesAfter = @($optionalModuleCatalog | Where-Object {
                    $_.ModuleName -and (Get-Module -ListAvailable ([string]$_.ModuleName))
                } | ForEach-Object { [string]$_.ModuleName })
            $missingModulesAfter = @($optionalModuleCatalog | Where-Object {
                    $_.ModuleName -and -not (Get-Module -ListAvailable ([string]$_.ModuleName))
                } | ForEach-Object { [string]$_.ModuleName })
            $newModulesDetected = @($presentModulesAfter | Where-Object { $_ -notin $presentModulesBefore })
            $alreadyPresentModules = @($presentModulesBefore | Sort-Object -Unique)
            $presentModulesAfter = @($presentModulesAfter | Sort-Object -Unique)
            $missingModulesAfter = @($missingModulesAfter | Sort-Object -Unique)

            if ($alreadyPresent.Count -gt 0) {
                Write-Status -Type ok -Label "$($alreadyPresent.Count) present before run" -Detail ($alreadyPresent -join ' ')
            }

            if ($newlyDetected.Count -gt 0) {
                Write-Status -Type ok -Label "$($newlyDetected.Count) present after install attempt" -Detail ($newlyDetected -join ' ')
            }

            if ($installedOptional.Count -gt 0) {
                $didChange = $true
                Write-Status -Type ok -Label "$($installedOptional.Count) newly installed"
            }

            if ($alreadyPresentModules.Count -gt 0) {
                Write-Status -Type ok -Label "$($alreadyPresentModules.Count) modules present" -Detail ($alreadyPresentModules -join ', ')
            }

            if ($newModulesDetected.Count -gt 0) {
                Write-Status -Type ok -Label "$($newModulesDetected.Count) modules present after install" -Detail ($newModulesDetected -join ', ')
            }

            if ($installedOptionalModules.Count -gt 0) {
                $didChange = $true
                Write-Status -Type ok -Label "$($installedOptionalModules.Count) modules newly installed"
            }

            if ($missingAfter.Count -gt 0) {
                Write-Status -Type warn -Label "$($missingAfter.Count) still missing" -Detail ($missingAfter -join ', ')
            }
            else {
                Write-Status -Type ok -Label "All optional tools available after run" -Detail ($presentAfter -join ' ')
            }

            if ($missingModulesAfter.Count -gt 0) {
                Write-Status -Type warn -Label "$($missingModulesAfter.Count) modules still missing" -Detail ($missingModulesAfter -join ', ')
            }
            else {
                Write-Status -Type ok -Label "All optional modules available after run" -Detail ($presentModulesAfter -join ', ')
            }
        }
        else {
            Write-Status -Type skip -Label "Optional tools" -Detail "skipped by -WhatIf/-Confirm"
        }
    }
    else {
    }

    # ======================== Shims ========================

    if ($CreateShims) {
        Write-Section "Shims"

        if ($PSCmdlet.ShouldProcess($shimDir, "Create/refresh shim .cmd files and prepend shim dir to $($script:PathDisplay)")) {
            New-DirectoryIfMissing $shimDir

            # Clear stale shims (avoid dead shims after Git upgrades)
            if ($script:DryRun) {
                Write-DryRun "Clear stale shims in '$shimDir'"
            }
            else {
                Get-ChildItem $shimDir -Filter *.cmd -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }

            $toolsToShim = Get-CoreShimToolCatalog
            $externalTools = @($optionalToolCatalog | ForEach-Object { $_.Command })
            $searchDirs = @($gitUsrBin)
            if ($AddMingw -and (Test-Path $gitMingwBin)) { $searchDirs += $gitMingwBin }
            $appIndex = Get-ApplicationCommandIndex -excludeDir $shimDir

            $shimmed = 0
            $notFound = 0
            $notFoundTools = New-Object System.Collections.Generic.List[string]
            $externalFound = New-Object System.Collections.Generic.List[string]

            foreach ($tool in $toolsToShim) {
                $toolPath = Find-Tool -toolName $tool -searchDirs $searchDirs
                if (-not $toolPath) {
                    $toolPath = Find-ToolInPath -toolName $tool -excludeDir $shimDir -AppIndex $appIndex
                    if (-not $toolPath -and $tool -eq "nc") {
                        $toolPath = Find-ToolInPath -toolName "ncat" -excludeDir $shimDir -AppIndex $appIndex
                    }
                }
                if ($toolPath) {
                    if (Write-ShimCmd -shimDir $shimDir -name $tool -targetExePath $toolPath) { $shimmed++ }
                }
                else {
                    $notFound++
                    $notFoundTools.Add($tool) | Out-Null
                }
            }

            foreach ($tool in $externalTools) {
                $toolPath = Find-ToolInPath -toolName $tool -excludeDir $shimDir -AppIndex $appIndex
                if ($toolPath) {
                    if (Write-ShimCmd -shimDir $shimDir -name $tool -targetExePath $toolPath) {
                        $shimmed++
                        $externalFound.Add($tool) | Out-Null
                    }
                }
            }

            Add-MachinePathPrepend $shimDir

            if (-not $script:DryRun) {
                try {
                    if ($script:PathScope -eq "User") {
                        & icacls $shimDir /inheritance:r /grant "${env:USERNAME}:(OI)(CI)F" 2>&1 | Out-Null
                    }
                    else {
                        & icacls $shimDir /inheritance:r /grant "BUILTIN\Administrators:(OI)(CI)F" /grant "BUILTIN\Users:(OI)(CI)RX" 2>&1 | Out-Null
                    }
                    Write-Status -Type ok -Label "ACLs secured" -Detail "read-only for non-admins"
                }
                catch {
                    Write-Status -Type warn -Label "ACL warning" -Detail $_.Exception.Message
                }
            }
            else {
                Write-DryRun "icacls '$shimDir' /inheritance:r /grant ..."
            }

            $didChange = $true
            Write-Status -Type ok -Label "$shimmed shims created" -Detail $shimDir
            Write-Status -Type ok -Label "Shim dir prepended" -Detail "to $($script:PathDisplay) (priority)"

            if ($externalFound.Count -gt 0) {
                Write-Status -Type ok -Label "$($externalFound.Count) external tools" -Detail ($externalFound -join ' ')
            }

            if ($notFound -gt 0) {
                Write-Status -Type info -Label "$notFound tools not found" -Detail "(normal)"
                $missing = @($notFoundTools | Sort-Object -Unique)
                Write-CompactList -Items $missing
            }
        }
        else {
            Write-Status -Type skip -Label "Shims" -Detail "skipped by -WhatIf/-Confirm"
        }
    }
    else {
        # Don't show section if not requested
    }

    # ======================== Profile ========================

    if ($InstallProfileShims) {
        Write-Section "Profile"
        if ($PSCmdlet.ShouldProcess($PROFILE.CurrentUserCurrentHost, "Install/update unix-tools profile shim blocks")) {
            Install-ProfileInlineShims -ThemesDir $ThemesDir -Theme $Theme -StartupMode $ProfileStartupMode -PromptMode $PromptInitMode
            $profilePath = $PROFILE.CurrentUserCurrentHost
            $expectedHash = $null
            if (Test-Path $profilePath) {
                $expectedHash = (Get-FileHash -Path $profilePath -Algorithm SHA256).Hash
            }
            $isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            try {
                if (Test-Path $profilePath) {
                    if ($isElevated) {
                        Write-Status -Type warn -Label "Elevated session" -Detail "reload skipped (open new terminal)"
                    }
                    else {
                        $currentHash = (Get-FileHash -Path $profilePath -Algorithm SHA256).Hash
                        if ($expectedHash -and $currentHash -ne $expectedHash) {
                            Write-Status -Type warn -Label "Profile modified" -Detail "reload skipped for safety"
                        }
                        else {
                            . $profilePath
                            Write-Status -Type ok -Label "Profile reloaded" -Detail ". `$PROFILE"
                        }
                    }
                }
            }
            catch {
                Write-Status -Type warn -Label "Profile reload failed" -Detail $_.Exception.Message
            }
            Write-Status -Type ok -Label "Profile shims written" -Detail "missing-command + alias-compat + smart-shell ($ProfileStartupMode / $PromptInitMode)"
            $didChange = $true
        }
        else {
            Write-Status -Type skip -Label "Profile shims" -Detail "skipped by -WhatIf/-Confirm"
        }
    }
    else {
    }

    # ======================== Environment ========================

    Write-Section "Environment"
    if ($didChange) {
        Send-EnvironmentChange
        Write-Status -Type ok -Label "WM_SETTINGCHANGE" -Detail "broadcasted"
    }
    else {
        Write-Status -Type info -Label "No changes" -Detail "nothing to broadcast"
    }

    # ======================== Verification ========================

    Write-Section "Verification"
    Update-SessionPath

    $verifyTools = @("grep", "sed", "awk", "find", "bash")
    $verifyCommandCache = @{}
    foreach ($tool in $verifyTools) {
        $verifyCommandCache[$tool] = @(Get-Command $tool -All -ErrorAction SilentlyContinue)
    }

    foreach ($tool in $verifyTools) {
        $cmds = @($verifyCommandCache[$tool])
        if (-not $cmds) {
            Write-Status -Type fail -Label $tool -Detail "not found (open a NEW terminal)"
            continue
        }

        $ui = $script:UI
        $top = $cmds | Select-Object -First 3
        $lines = @()
        foreach ($c in $top) {
            $src = $c.Source
            if ($CreateShims -and $src -like "*\shims\*") {
                $shimContent = Get-Content $src -Raw -ErrorAction SilentlyContinue
                $target = $null
                if ($shimContent -match '"([^"]+\.exe)"') { $target = $matches[1] }
                if ($target) { $lines += "shim $($ui.Arrow) $(Split-Path $target -Leaf)" }
                else { $lines += "shim" }
            }
            elseif ($src -like "*\Git\*") {
                $lines += "Git $($ui.Arrow) $(Split-Path $src -Leaf)"
            }
            else {
                $lines += "$(Split-Path $src -Leaf)"
            }
        }

        Write-Status -Type ok -Label $tool -Detail ($lines -join " | ")
    }

    if ($InstallProfileShims) {
        $profilePath = $PROFILE.CurrentUserCurrentHost
        if ($script:DryRun) {
            Write-Status -Type info -Label "Profile blocks" -Detail "skipped in DryRun"
        }
        else {
            $profileState = Get-ProfileInstallationState -ProfilePath $profilePath

            if ($profileState.HasManagedBlocks) {
                Write-Status -Type ok -Label "Profile blocks" -Detail "present in `$PROFILE"
            }
            elseif ($profileState.HasMissingBlock -or $profileState.HasAliasBlock -or $profileState.HasSmartShellBlock) {
                Write-Status -Type warn -Label "Profile blocks" -Detail "partial install detected"
            }
            elseif ($profileState.HasLegacyFastBlock) {
                Write-Status -Type warn -Label "Profile blocks" -Detail "legacy fast-shim detected (re-run -InstallProfileShims)"
            }
            else {
                Write-Status -Type fail -Label "Profile blocks" -Detail "not found in `$PROFILE"
            }

            $legacyDetail = switch ($profileState.LegacyInlineStatus) {
                'Found' { 'present (cleanup still needed)' }
                'Ambiguous' { 'ambiguous signature detected (manual review needed)' }
                default { 'not detected' }
            }
            $startupModeDetail = if ([string]::IsNullOrWhiteSpace($profileState.StartupMode)) { 'Unknown' } else { $profileState.StartupMode }
            $promptModeDetail = if ([string]::IsNullOrWhiteSpace($profileState.PromptInitMode)) { 'Unknown' } else { $profileState.PromptInitMode }

            Write-Status -Type info -Label "Legacy inline shims" -Detail $legacyDetail
            Write-Status -Type info -Label "Startup mode" -Detail $startupModeDetail
            Write-Status -Type info -Label "Prompt init mode" -Detail $promptModeDetail
        }
    }

    # ======================== Footer ========================

    Write-Footer -Message "Done $($ui.Arrow) open a new terminal to use tools" -Type ok

    $tryCommands = @("grep --version")
    if ($InstallProfileShims) { $tryCommands += @("ls -la", "'stressed' | rev") }
    if ($InstallOptionalTools) { $tryCommands += @("rg --version", "fd --version") }
    $tryLine = "  Try:  " + ($tryCommands -join " $([char]0x00B7) ")
    Write-Host $tryLine -ForegroundColor DarkCyan
    Write-Host ""

}
finally {
    if ($transcriptStarted) {
        Stop-ScriptTranscript
    }
}
