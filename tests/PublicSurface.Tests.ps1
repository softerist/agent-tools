$repoRoot = Split-Path $PSScriptRoot -Parent
$scriptPath = Join-Path $repoRoot 'Enable-UnixTools.ps1'
$modulePath = Join-Path $repoRoot 'Enable-UnixTools.psd1'
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-ScriptFunction -ScriptPath $scriptPath -Names @('Get-OptionalPowerShellModuleCatalog')

Describe 'Public surface and docs' {
    It 'keeps module wrapper parameters aligned with script parameters' {
        Import-Module $modulePath -Force

        $commonParameters = @(
            'Confirm', 'Debug', 'ErrorAction', 'ErrorVariable',
            'InformationAction', 'InformationVariable', 'OutBuffer', 'OutVariable',
            'PipelineVariable', 'ProgressAction', 'Verbose', 'WarningAction',
            'WarningVariable', 'WhatIf'
        )

        $wrapperParameters = @(
            (Get-Command Enable-UnixTools).Parameters.Keys |
                Where-Object { $_ -notin $commonParameters }
        )
        $expectedParameters = @((Get-ScriptParameterNameList -ScriptPath $scriptPath) + 'ArgumentList' | Sort-Object -Unique)

        ((@($wrapperParameters | Sort-Object)) -join ',') | Should Be (($expectedParameters) -join ',')
    }

    It 'keeps the module wrapper prompt default aligned with the script entrypoint' {
        $moduleText = Get-Content -Path (Join-Path $repoRoot 'Enable-UnixTools.psm1') -Raw
        $scriptText = Get-Content -Path $scriptPath -Raw

        ($scriptText -match "PromptInitMode = 'Lazy'") | Should Be $true
        ($moduleText -match "PromptInitMode = 'Lazy'") | Should Be $true
    }

    It 'does not include PSScriptAnalyzer in optional shell modules' {
        $moduleNames = @(Get-OptionalPowerShellModuleCatalog | Select-Object -ExpandProperty ModuleName)
        ($moduleNames -contains 'PSScriptAnalyzer') | Should Be $false
    }

    It 'documents only supported commands and uninstall options' {
        $readmePath = Join-Path $repoRoot 'README.md'
        $readmeText = Get-Content -Path $readmePath -Raw

        ($readmeText -match 'RepairWinget') | Should Be $false
        ($readmeText -match 'UninstallOptionalTools') | Should Be $true
        ($readmeText -match 'ProfileStartupMode Fast') | Should Be $true
        ($readmeText -match 'PromptInitMode Lazy') | Should Be $true
    }

    It 'guards optional-tool uninstall behind the explicit uninstall switch' {
        $scriptText = Get-Content -Path (Join-Path $repoRoot 'src\Private\MainOrchestration.ps1') -Raw

        ($scriptText -match 'if \(\$UninstallOptionalTools\)') | Should Be $true
        ($scriptText -match 'preserved \(use -UninstallOptionalTools to remove tracked items\)') | Should Be $true
    }
}
