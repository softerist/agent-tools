$repoRoot = Split-Path $PSScriptRoot -Parent
$scriptPath = Join-Path $repoRoot 'Enable-UnixTools.ps1'
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-ScriptFunctions -ScriptPath $scriptPath -Names @(
    'Get-OptionalPowerShellModuleCatalog',
    'Get-SmartShellOptionalModuleNames',
    'Get-ProfileSmartShellBlockBody',
    'Get-ProfilePromptBlockBody'
)

Describe 'Generated profile blocks' {
    It 'builds a fast smart-shell block with deferred interactive features' {
        $block = Get-ProfileSmartShellBlockBody -StartupMode Fast

        ($block -match 'function global:Enable-UnixInteractiveFeatures') | Should Be $true
        ($block -match '(?m)^\s*Enable-UnixInteractiveFeatures\s*$') | Should Be $false
        ($block -match 'PSScriptAnalyzer') | Should Be $false
        ($block -match 'Set-PSReadLineOption -PredictionSource History') | Should Be $true
    }

    It 'builds a legacy smart-shell block that eagerly enables interactive features' {
        $block = Get-ProfileSmartShellBlockBody -StartupMode Legacy

        ($block -match '(?m)^\s*Enable-UnixInteractiveFeatures\s*$') | Should Be $true
        ($block -match '# Startup mode: Legacy') | Should Be $true
    }

    It 'builds a lazy prompt block with warmup state' {
        $block = Get-ProfilePromptBlockBody -ThemesDir 'C:\Themes' -Theme 'lightgreen' -PromptInitMode Lazy

        ($block -match '# Prompt init mode: Lazy') | Should Be $true
        ($block -match "UnixToolsPromptState = 'Pending'") | Should Be $true
        ($block -match 'function global:prompt') | Should Be $true
    }

    It 'builds an eager prompt block without warmup state' {
        $block = Get-ProfilePromptBlockBody -ThemesDir 'C:\Themes' -Theme 'lightgreen' -PromptInitMode Eager

        ($block -match '# Prompt init mode: Eager') | Should Be $true
        ($block -match "UnixToolsPromptState = 'Pending'") | Should Be $false
    }

    It 'returns no prompt block when prompt mode is off' {
        $block = Get-ProfilePromptBlockBody -ThemesDir 'C:\Themes' -Theme 'lightgreen' -PromptInitMode Off
        $block | Should Be $null
    }
}
