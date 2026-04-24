$repoRoot = Split-Path $PSScriptRoot -Parent
$scriptPath = Join-Path $repoRoot 'Enable-UnixTools.ps1'
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-ScriptFunction -ScriptPath $scriptPath -Names @(
    'Get-ProfileMetadataValue',
    'Get-ProfileInstallationState',
    'Remove-ManagedProfileBlockSet',
    'Set-ProfileBlock'
)

$script:DryRun = $false

Describe 'Managed profile helpers' {
    It 'reports managed loader block state plus startup and prompt modes' {
        $profilePath = New-TestTempPath -Extension '.ps1'
        try {
            $profileText = @'
# >>> unix-tools-profile >>>
# Startup mode: Fast
# Prompt init mode: Lazy
# Support root: C:\Users\demo\AppData\Local\UnixToolsSystemWide\profile
. 'C:\Users\demo\AppData\Local\UnixToolsSystemWide\profile\UnixTools.ProfileLoader.ps1'
# <<< unix-tools-profile <<<
'@
            Set-Content -Path $profilePath -Value $profileText -Encoding UTF8

            $state = Get-ProfileInstallationState -ProfilePath $profilePath
            $state.HasManagedBlocks | Should Be $true
            $state.HasLoaderBlock | Should Be $true
            $state.StartupMode | Should Be 'Fast'
            $state.PromptInitMode | Should Be 'Lazy'
            $state.SupportRoot | Should Be 'C:\Users\demo\AppData\Local\UnixToolsSystemWide\profile'
        }
        finally {
            Remove-Item -Path $profilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'removes the managed loader block while preserving other profile content' {
        $profilePath = New-TestTempPath -Extension '.ps1'
        try {
            $profileText = @'
Set-Alias before before.exe
# >>> unix-tools-profile >>>
# Startup mode: Fast
# Prompt init mode: Off
. 'C:\Support\UnixTools.ProfileLoader.ps1'
# <<< unix-tools-profile <<<
Set-Alias after after.exe
'@
            Set-Content -Path $profilePath -Value $profileText -Encoding UTF8

            Remove-ManagedProfileBlockSet -ProfilePath $profilePath | Should Be $true

            $updated = Get-Content -Path $profilePath -Raw
            ($updated -match '# >>> unix-tools-profile >>>') | Should Be $false
            ($updated -match 'Set-Alias before before.exe') | Should Be $true
            ($updated -match 'Set-Alias after after.exe') | Should Be $true
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
