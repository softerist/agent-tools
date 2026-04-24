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
    $hasLoaderBlock = $profileText -and $profileText.Contains('# >>> unix-tools-profile >>>') -and $profileText.Contains('# <<< unix-tools-profile <<<')

    [pscustomobject]@{
        HasManagedBlocks = [bool]$hasLoaderBlock
        HasLoaderBlock   = [bool]$hasLoaderBlock
        StartupMode      = if ($hasLoaderBlock) { Get-ProfileMetadataValue -Text $profileText -Key 'Startup mode' } else { 'NotInstalled' }
        PromptInitMode   = if ($hasLoaderBlock) { Get-ProfileMetadataValue -Text $profileText -Key 'Prompt init mode' } else { 'Off' }
        SupportRoot      = if ($hasLoaderBlock) { Get-ProfileMetadataValue -Text $profileText -Key 'Support root' } else { $null }
    }
}

function Remove-ManagedProfileBlockSet {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Profile mutation confirmation is handled by the caller before this helper runs.')]
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [psobject]$RuntimeContext
    )

    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) { return $false }

    $existing = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($existing)) { return $false }

    $pattern = "(?ms)^\s*# >>> unix-tools-profile >>>\s*$.*?^\s*# <<< unix-tools-profile <<<\s*(\r?\n)?"
    $updated = [regex]::Replace($existing, $pattern, '')

    if ($updated -eq $existing) {
        return $false
    }

    Write-AtomicUtf8File -Path $ProfilePath -Content $updated -RuntimeContext $RuntimeContext
    return $true
}

function Remove-InstalledProfileSupport {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The uninstall orchestration flow owns ShouldProcess for this internal helper.')]
    param([psobject]$RuntimeContext)

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    $profilePaths = @(Get-ManagedUserProfilePathList)
    $removedPaths = New-Object System.Collections.Generic.List[string]

    foreach ($profilePath in $profilePaths) {
        $hadManagedBlock = (Get-ProfileInstallationState -ProfilePath $profilePath).HasManagedBlocks
        if (-not $hadManagedBlock) {
            continue
        }

        $backup = Backup-ProfileFile -ProfilePath $profilePath -RuntimeContext $RuntimeContext
        if ($backup) { Write-Verbose "Profile backup: $backup" }

        if (Remove-ManagedProfileBlockSet -ProfilePath $profilePath -RuntimeContext $RuntimeContext) {
            $removedPaths.Add($profilePath) | Out-Null
        }
    }

    $removedPayload = $false
    if (Get-Command Get-ManagedProfileSupportRoot -CommandType Function -ErrorAction SilentlyContinue) {
        $supportRoot = Get-ManagedProfileSupportRoot -RuntimeContext $RuntimeContext
        $removedPayload = Test-Path -LiteralPath $supportRoot -PathType Container
    }

    if (Get-Command Remove-ManagedProfileSupportPayload -CommandType Function -ErrorAction SilentlyContinue) {
        Remove-ManagedProfileSupportPayload -RuntimeContext $RuntimeContext | Out-Null
    }

    return [pscustomobject]@{
        Status = if ($removedPaths.Count -gt 0 -or $removedPayload) { 'Removed' } else { 'NotFound' }
        Detail = if ($removedPaths.Count -gt 0) { $removedPaths -join ', ' } else { '' }
    }
}
