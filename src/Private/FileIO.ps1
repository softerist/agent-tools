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
    Ensure-DirectoryExists -Path $dir

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

function Ensure-DirectoryExists {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (Test-Path -LiteralPath $Path -PathType Container) { return }

    if ($script:DryRun) {
        Write-DryRun "New-Item -ItemType Directory -Path '$Path'"
        return
    }

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Write-AtomicTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content,
        [ValidateSet('UTF8', 'ASCII')][string]$Encoding = 'UTF8'
    )

    $parent = Split-Path -Parent $Path
    Ensure-DirectoryExists -Path $parent

    if ($script:DryRun) {
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
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )

    Write-AtomicTextFile -Path $Path -Content $Content -Encoding UTF8
}

function Write-AtomicAsciiFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )

    Write-AtomicTextFile -Path $Path -Content $Content -Encoding ASCII
}

function Backup-ProfileFile {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)

    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) { return $null }
    if ($script:ProfileBackupPath) { return $script:ProfileBackupPath }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = "$ProfilePath.bak-$stamp"
    if ($script:DryRun) {
        Write-DryRun "Backup-ProfileFile: $ProfilePath -> $backup"
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

    Write-AtomicUtf8File -Path $ProfilePath -Content $updated
}

function Remove-ProfileBlock {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$StartMarker,
        [Parameter(Mandatory = $true)][string]$EndMarker
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
        Write-AtomicUtf8File -Path $ProfilePath -Content $updated
    }
}
