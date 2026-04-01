function Start-ScriptTranscript {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([bool])]
    param(
        [string]$Path,
        [psobject]$RuntimeContext
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $resolved = [System.IO.Path]::GetFullPath($Path)
    $sensitiveRoots = @($env:WINDIR, $env:SYSTEMROOT) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    foreach ($root in $sensitiveRoots) {
        if ($resolved.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
            throw "LogPath must not point inside the Windows system directory: $resolved"
        }
    }

    $dir = Split-Path -Parent $resolved
    Initialize-Directory -Path $dir -RuntimeContext $RuntimeContext

    Start-Transcript -Path $resolved -Append -Force | Out-Null
    return $true
}

function Get-ManagedUserProfilePathList {
    $profilePaths = New-Object System.Collections.Generic.List[string]

    $currentHostProfilePath = $null
    $allHostsProfilePath = $null
    try {
        $currentHostProfilePath = $PROFILE.CurrentUserCurrentHost
    }
    catch {
        $currentHostProfilePath = $null
    }

    try {
        $allHostsProfilePath = $PROFILE.CurrentUserAllHosts
    }
    catch {
        $allHostsProfilePath = $null
    }

    if (-not [string]::IsNullOrWhiteSpace($currentHostProfilePath)) {
        $profilePaths.Add($currentHostProfilePath) | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($allHostsProfilePath)) {
        $profilePaths.Add($allHostsProfilePath) | Out-Null
    }

    $userHome = if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $env:USERPROFILE
    }
    elseif (-not [string]::IsNullOrWhiteSpace($HOME)) {
        $HOME
    }
    else {
        $null
    }

    if (-not [string]::IsNullOrWhiteSpace($userHome)) {
        $profilePaths.Add((Join-Path $userHome 'Documents\PowerShell\profile.ps1')) | Out-Null
        $profilePaths.Add((Join-Path $userHome 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1')) | Out-Null
        $profilePaths.Add((Join-Path $userHome 'Documents\PowerShell\Microsoft.VSCode_profile.ps1')) | Out-Null
        $profilePaths.Add((Join-Path $userHome 'Documents\WindowsPowerShell\profile.ps1')) | Out-Null
        $profilePaths.Add((Join-Path $userHome 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1')) | Out-Null
    }

    return @($profilePaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Test-IsDryRunEnabled {
    param([psobject]$RuntimeContext)

    return [bool](Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext).DryRun
}

function Stop-ScriptTranscript {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    try {
        Stop-Transcript | Out-Null
    }
    catch {
        Write-Verbose "No active transcript to stop: $($_.Exception.Message)"
    }
}

function Initialize-Directory {
    param(
        [string]$Path,
        [psobject]$RuntimeContext
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (Test-Path -LiteralPath $Path -PathType Container) { return }

    if (Test-IsDryRunEnabled -RuntimeContext $RuntimeContext) {
        Write-DryRun "New-Item -ItemType Directory -Path '$Path'"
        return
    }

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Write-AtomicTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content,
        [ValidateSet('UTF8', 'ASCII')][string]$Encoding = 'UTF8',
        [psobject]$RuntimeContext
    )

    $parent = Split-Path -Parent $Path
    Initialize-Directory -Path $parent -RuntimeContext $RuntimeContext

    if (Test-IsDryRunEnabled -RuntimeContext $RuntimeContext) {
        Write-DryRun "Write-AtomicTextFile '$Path' -Encoding $Encoding"
        return
    }

    $tmp = "$Path.tmp"
    try {
        Set-Content -Path $tmp -Value $Content -Encoding $Encoding
        Move-Item -Path $tmp -Destination $Path -Force
    }
    catch {
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Write-AtomicUtf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content,
        [psobject]$RuntimeContext
    )

    Write-AtomicTextFile -Path $Path -Content $Content -Encoding UTF8 -RuntimeContext $RuntimeContext
}

function Write-AtomicAsciiFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content,
        [psobject]$RuntimeContext
    )

    Write-AtomicTextFile -Path $Path -Content $Content -Encoding ASCII -RuntimeContext $RuntimeContext
}

function Backup-ProfileFile {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [psobject]$RuntimeContext
    )

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext

    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) { return $null }
    $backupMap = $RuntimeContext.ProfileBackupPathMap
    if ($null -eq $backupMap) {
        $backupMap = @{}
        $RuntimeContext.ProfileBackupPathMap = $backupMap
    }

    $existingBackupPath = if ($backupMap.ContainsKey($ProfilePath)) { $backupMap[$ProfilePath] } else { $null }
    if ($existingBackupPath) { return $existingBackupPath }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = "$ProfilePath.bak-$stamp"
    if (Test-IsDryRunEnabled -RuntimeContext $RuntimeContext) {
        Write-DryRun "Backup-ProfileFile: $ProfilePath -> $backup"
    }
    else {
        Copy-Item -Path $ProfilePath -Destination $backup -Force
    }

    $backupMap[$ProfilePath] = $backup
    $RuntimeContext.ProfileBackupPath = $backup
    return $backup
}

function Set-ProfileBlock {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$StartMarker,
        [Parameter(Mandatory = $true)][string]$EndMarker,
        [Parameter(Mandatory = $true)][string]$BlockBody,
        [psobject]$RuntimeContext
    )

    $existing = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
    if ($null -eq $existing) { $existing = '' }

    $newBlock = @(
        $StartMarker
        $BlockBody
        $EndMarker
        ''
    ) -join "`r`n"

    $blockPattern = "(?ms)^\s*$([regex]::Escape($StartMarker))\s*$.*?^\s*$([regex]::Escape($EndMarker))\s*(\r?\n)?"
    $startLinePattern = "(?m)^\s*$([regex]::Escape($StartMarker))\s*(\r?\n)?"
    $endLinePattern = "(?m)^\s*$([regex]::Escape($EndMarker))\s*(\r?\n)?"

    $updated = [regex]::Replace($existing, $blockPattern, '')
    $updated = [regex]::Replace($updated, $startLinePattern, '')
    $updated = [regex]::Replace($updated, $endLinePattern, '')

    if ($updated.Length -gt 0 -and -not $updated.EndsWith("`r`n")) {
        $updated += "`r`n"
    }
    $updated += $newBlock

    Write-AtomicUtf8File -Path $ProfilePath -Content $updated -RuntimeContext $RuntimeContext
}

function Remove-ProfileBlock {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$StartMarker,
        [Parameter(Mandatory = $true)][string]$EndMarker,
        [psobject]$RuntimeContext
    )

    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) { return }

    $existing = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrEmpty($existing)) { return }

    $pattern = "(?ms)^\s*$([regex]::Escape($StartMarker))\s*$.*?^\s*$([regex]::Escape($EndMarker))\s*(\r?\n)?"
    $updated = [regex]::Replace($existing, $pattern, '')

    $startLinePattern = "(?m)^\s*$([regex]::Escape($StartMarker))\s*(\r?\n)?"
    $endLinePattern = "(?m)^\s*$([regex]::Escape($EndMarker))\s*(\r?\n)?"
    $updated = [regex]::Replace($updated, $startLinePattern, '')
    $updated = [regex]::Replace($updated, $endLinePattern, '')

    if ($updated -ne $existing) {
        Write-AtomicUtf8File -Path $ProfilePath -Content $updated -RuntimeContext $RuntimeContext
    }
}
