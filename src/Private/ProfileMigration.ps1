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

function Remove-LegacyInlineProfileShimBlock {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Profile mutation confirmation is handled by the caller before this helper runs.')]
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [psobject]$RuntimeContext
    )

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

    Write-AtomicUtf8File -Path $ProfilePath -Content $updated -RuntimeContext $RuntimeContext

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
    $hasLoaderBlock = $profileText -and $profileText.Contains('# >>> unix-tools-profile >>>') -and $profileText.Contains('# <<< unix-tools-profile <<<')
    $hasMissingBlock = $profileText -and $profileText.Contains('# >>> unix-tools-missing-shims >>>') -and $profileText.Contains('# <<< unix-tools-missing-shims <<<')
    $hasAliasBlock = $profileText -and $profileText.Contains('# >>> unix-tools-alias-compat >>>') -and $profileText.Contains('# <<< unix-tools-alias-compat <<<')
    $hasSmartShellBlock = $profileText -and $profileText.Contains('# >>> unix-tools-smart-shell >>>') -and $profileText.Contains('# <<< unix-tools-smart-shell <<<')
    $hasTerminalBlock = $profileText -and $profileText.Contains('# >>> unix-tools-terminal-setup >>>') -and $profileText.Contains('# <<< unix-tools-terminal-setup <<<')
    $hasFastBlock = $profileText -and $profileText.Contains('# >>> unix-tools-fast-shims >>>') -and $profileText.Contains('# <<< unix-tools-fast-shims <<<')
    $legacyBlock = Find-LegacyInlineShimBlock -ProfilePath $ProfilePath

    [pscustomobject]@{
        HasManagedBlocks     = [bool]($hasLoaderBlock -or ($hasMissingBlock -and $hasAliasBlock -and $hasSmartShellBlock))
        HasLoaderBlock       = [bool]$hasLoaderBlock
        HasMissingBlock      = [bool]$hasMissingBlock
        HasAliasBlock        = [bool]$hasAliasBlock
        HasSmartShellBlock   = [bool]$hasSmartShellBlock
        HasTerminalBlock     = [bool]$hasTerminalBlock
        HasLegacyFastBlock   = [bool]$hasFastBlock
        LegacyInlineStatus   = $legacyBlock.Status
        HasLegacyInlineBlock = [bool]$legacyBlock.Found
        StartupMode          = if ($hasLoaderBlock) { Get-ProfileMetadataValue -Text $profileText -Key 'Startup mode' } elseif ($hasSmartShellBlock) { Get-ProfileMetadataValue -Text $profileText -Key 'Startup mode' } else { 'NotInstalled' }
        PromptInitMode       = if ($hasLoaderBlock) { Get-ProfileMetadataValue -Text $profileText -Key 'Prompt init mode' } elseif ($hasTerminalBlock) { Get-ProfileMetadataValue -Text $profileText -Key 'Prompt init mode' } else { 'Off' }
        SupportRoot          = if ($hasLoaderBlock) { Get-ProfileMetadataValue -Text $profileText -Key 'Support root' } else { $null }
    }
}

function Remove-ManagedProfileBlockSet {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Profile mutation confirmation is handled by the caller before this helper runs.')]
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [psobject]$RuntimeContext
    )

    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) { return }

    $existing = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($existing)) { return }

    $updated = $existing
    foreach ($markerPair in @(
            @{ Start = '# >>> unix-tools-profile >>>'; End = '# <<< unix-tools-profile <<<' },
            @{ Start = '# >>> unix-tools-fast-shims >>>'; End = '# <<< unix-tools-fast-shims <<<' },
            @{ Start = '# >>> unix-tools-missing-shims >>>'; End = '# <<< unix-tools-missing-shims <<<' },
            @{ Start = '# >>> unix-tools-alias-compat >>>'; End = '# <<< unix-tools-alias-compat <<<' },
            @{ Start = '# >>> unix-tools-smart-shell >>>'; End = '# <<< unix-tools-smart-shell <<<' },
            @{ Start = '# >>> codex-smart-shell >>>'; End = '# <<< codex-smart-shell <<<' },
            @{ Start = '# >>> git-tools-missing-shims >>>'; End = '# <<< git-tools-missing-shims <<<' },
            @{ Start = '# >>> git-tools-alias-compat >>>'; End = '# <<< git-tools-alias-compat <<<' },
            @{ Start = '# >>> unix-tools-terminal-setup >>>'; End = '# <<< unix-tools-terminal-setup <<<' }
        )) {
        $pattern = "(?ms)^\s*$([regex]::Escape($markerPair.Start))\s*$.*?^\s*$([regex]::Escape($markerPair.End))\s*(\r?\n)?"
        $updated = [regex]::Replace($updated, $pattern, '')
    }

    if ($updated -ne $existing) {
        Write-AtomicUtf8File -Path $ProfilePath -Content $updated -RuntimeContext $RuntimeContext
    }
}

function Remove-InstalledProfileSupport {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'The uninstall orchestration flow owns ShouldProcess for this internal helper.')]
    param([psobject]$RuntimeContext)

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    $profilePaths = @(Get-ManagedUserProfilePathList)
    $removedLegacyPaths = New-Object System.Collections.Generic.List[string]
    $ambiguousLegacyPaths = New-Object System.Collections.Generic.List[string]
    foreach ($profilePath in $profilePaths) {
        $backup = Backup-ProfileFile -ProfilePath $profilePath -RuntimeContext $RuntimeContext
        if ($backup) { Write-Verbose "Profile backup: $backup" }

        Remove-ManagedProfileBlockSet -ProfilePath $profilePath -RuntimeContext $RuntimeContext
        $legacyResult = Remove-LegacyInlineProfileShimBlock -ProfilePath $profilePath -RuntimeContext $RuntimeContext

        switch ($legacyResult.Status) {
            'Removed' {
                $removedLegacyPaths.Add($profilePath) | Out-Null
            }
            'Ambiguous' {
                $ambiguousLegacyPaths.Add($profilePath) | Out-Null
            }
        }
    }

    if (Get-Command Remove-ManagedProfileSupportPayload -CommandType Function -ErrorAction SilentlyContinue) {
        Remove-ManagedProfileSupportPayload -RuntimeContext $RuntimeContext | Out-Null
    }

    if ($removedLegacyPaths.Count -gt 0) {
        Write-Status -Type ok -Label 'Legacy inline shims' -Detail ("removed from " + ($removedLegacyPaths -join ', ')) -RuntimeContext $RuntimeContext
    }
    if ($ambiguousLegacyPaths.Count -gt 0) {
        Write-Status -Type warn -Label 'Legacy inline shims' -Detail ("ambiguous in " + ($ambiguousLegacyPaths -join ', ')) -RuntimeContext $RuntimeContext
    }

    return [pscustomobject]@{
        Status = if ($ambiguousLegacyPaths.Count -gt 0) { 'Ambiguous' } elseif ($removedLegacyPaths.Count -gt 0) { 'Removed' } else { 'NotFound' }
        Detail = if ($ambiguousLegacyPaths.Count -gt 0) { $ambiguousLegacyPaths -join ', ' } elseif ($removedLegacyPaths.Count -gt 0) { $removedLegacyPaths -join ', ' } else { '' }
    }
}
