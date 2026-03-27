$repoRoot = Split-Path $PSScriptRoot -Parent
$scriptPath = Join-Path $repoRoot 'Enable-UnixTools.ps1'
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-ScriptFunction -ScriptPath $scriptPath -Names @(
    'Find-LegacyInlineShimBlock',
    'Remove-LegacyInlineProfileShimBlock',
    'Get-ProfileMetadataValue',
    'Get-ProfileInstallationState',
    'Set-ProfileBlock'
)

$script:DryRun = $false

Describe 'Legacy profile migration helpers' {
    It 'finds and removes a legacy inline shim block while preserving other profile content' {
        $profilePath = New-TestTempPath -Extension '.ps1'
        try {
            $profileText = @'
# ============================================================================
# Fast Unix-like shims for PowerShell ($PROFILE)
# Goals:
#   - Fast startup
# ============================================================================

if (-not $script:__UnixShimsInitialized) {
    $script:__UnixShimsInitialized = $true

    function Test-LegacyShim {
        if ($true) {
            "ok"
        }
    }
}

Set-Alias foo bar
'@
            Set-Content -Path $profilePath -Value $profileText -Encoding UTF8

            $found = Find-LegacyInlineShimBlock -ProfilePath $profilePath
            $found.Status | Should Be 'Found'

            $result = Remove-LegacyInlineProfileShimBlock -ProfilePath $profilePath
            $result.Status | Should Be 'Removed'

            $updated = Get-Content -Path $profilePath -Raw
            ($updated -match 'Fast Unix-like shims for PowerShell') | Should Be $false
            ($updated -match 'Set-Alias foo bar') | Should Be $true
        }
        finally {
            Remove-Item -Path $profilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports ambiguous legacy content when multiple headers are present' {
        $profilePath = New-TestTempPath -Extension '.ps1'
        try {
            $profileText = @'
# Fast Unix-like shims for PowerShell ($PROFILE)
if (-not $script:__UnixShimsInitialized) {
}

# Fast Unix-like shims for PowerShell ($PROFILE)
if (-not $script:__UnixShimsInitialized) {
}
'@
            Set-Content -Path $profilePath -Value $profileText -Encoding UTF8

            $result = Find-LegacyInlineShimBlock -ProfilePath $profilePath
            $result.Status | Should Be 'Ambiguous'
        }
        finally {
            Remove-Item -Path $profilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports managed block state plus startup and prompt modes' {
        $profilePath = New-TestTempPath -Extension '.ps1'
        try {
            $profileText = @'
# >>> unix-tools-missing-shims >>>
# <<< unix-tools-missing-shims <<<
# >>> unix-tools-alias-compat >>>
# <<< unix-tools-alias-compat <<<
# >>> unix-tools-smart-shell >>>
# Startup mode: Fast
# <<< unix-tools-smart-shell <<<
# >>> unix-tools-terminal-setup >>>
# Prompt init mode: Lazy
# <<< unix-tools-terminal-setup <<<
'@
            Set-Content -Path $profilePath -Value $profileText -Encoding UTF8

            $state = Get-ProfileInstallationState -ProfilePath $profilePath
            $state.HasManagedBlocks | Should Be $true
            $state.StartupMode | Should Be 'Fast'
            $state.PromptInitMode | Should Be 'Lazy'
            $state.HasLegacyInlineBlock | Should Be $false
        }
        finally {
            Remove-Item -Path $profilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'updates an existing profile block file without move-item collisions' {
        $profilePath = New-TestTempPath -Extension '.ps1'
        try {
            Set-Content -Path $profilePath -Value "# existing`r`n" -Encoding UTF8

            Set-ProfileBlock -ProfilePath $profilePath -StartMarker '# >>> test-block >>>' -EndMarker '# <<< test-block <<<' -BlockBody "line one`r`nline two"
            Set-ProfileBlock -ProfilePath $profilePath -StartMarker '# >>> test-block >>>' -EndMarker '# <<< test-block <<<' -BlockBody "line three"

            $updated = Get-Content -Path $profilePath -Raw
            ($updated -match '# >>> test-block >>>') | Should Be $true
            ($updated -match 'line three') | Should Be $true
            ($updated -match 'line one') | Should Be $false
        }
        finally {
            Remove-Item -Path $profilePath -Force -ErrorAction SilentlyContinue
        }
    }
}
