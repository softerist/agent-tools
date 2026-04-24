$repoRoot = Split-Path $PSScriptRoot -Parent
$modulePath = Join-Path $repoRoot 'Enable-UnixTools.psd1'
$publishPath = Join-Path $repoRoot 'publish.ps1'
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-ScriptFunction -ScriptPath $publishPath -Names @(
    'Get-DefaultReadmeContent',
    'Get-DefaultAboutHelpContent',
    'Initialize-ModulePackage'
)

Import-ScriptFunction -ScriptPath $modulePath -Names @(
    'New-EnableUnixToolsRuntimeContext',
    'Get-ManagedProfileSupportFileNameList',
    'Get-ProfileInstallationState',
    'Install-ProfileInlineSupport',
    'Remove-InstalledProfileSupport',
    'Invoke-ProfileSetupFlow'
)

function New-IntegrationUserState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Integration test helper provisions isolated temporary user state.')]
    param()

    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-int-' + [guid]::NewGuid())
    $localAppData = Join-Path $root 'LocalAppData'
    $userProfile = Join-Path $root 'UserProfile'
    $appData = Join-Path $root 'AppData'
    $pwshDocumentsDir = Join-Path $userProfile 'Documents\PowerShell'
    $windowsPowerShellDocumentsDir = Join-Path $userProfile 'Documents\WindowsPowerShell'
    $allHostsProfilePath = Join-Path $pwshDocumentsDir 'profile.ps1'
    $profilePath = Join-Path $pwshDocumentsDir 'Microsoft.PowerShell_profile.ps1'
    $vsCodeProfilePath = Join-Path $pwshDocumentsDir 'Microsoft.VSCode_profile.ps1'
    $windowsPowerShellAllHostsProfilePath = Join-Path $windowsPowerShellDocumentsDir 'profile.ps1'
    $windowsPowerShellProfilePath = Join-Path $windowsPowerShellDocumentsDir 'Microsoft.PowerShell_profile.ps1'

    foreach ($dir in @($localAppData, $userProfile, $appData, $pwshDocumentsDir, $windowsPowerShellDocumentsDir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    return [pscustomobject]@{
        Root        = $root
        LocalAppData = $localAppData
        UserProfile = $userProfile
        AppData     = $appData
        AllHostsProfilePath = $allHostsProfilePath
        ProfilePath = $profilePath
        VSCodeProfilePath = $vsCodeProfilePath
        WindowsPowerShellAllHostsProfilePath = $windowsPowerShellAllHostsProfilePath
        WindowsPowerShellProfilePath = $windowsPowerShellProfilePath
        SupportRoot = Join-Path $localAppData 'UnixToolsSystemWide\profile'
    }
}

function Invoke-WithTemporaryUserState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'Integration tests intentionally swap PROFILE to isolate user state.')]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock
    )

    $state = New-IntegrationUserState
    $originalProfile = $global:PROFILE
    $originalLocalAppData = $env:LOCALAPPDATA
    $originalUserProfile = $env:USERPROFILE
    $originalAppData = $env:APPDATA
    $originalPath = $env:Path

    try {
        $env:LOCALAPPDATA = $state.LocalAppData
        $env:USERPROFILE = $state.UserProfile
        $env:APPDATA = $state.AppData
        $global:PROFILE = [pscustomobject]@{
            CurrentUserAllHosts = $state.AllHostsProfilePath
            CurrentUserCurrentHost = $state.ProfilePath
        }

        & $ScriptBlock $state
    }
    finally {
        $env:LOCALAPPDATA = $originalLocalAppData
        $env:USERPROFILE = $originalUserProfile
        $env:APPDATA = $originalAppData
        $env:Path = $originalPath
        $global:PROFILE = $originalProfile
        Remove-Module Enable-UnixTools -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $state.Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Initialize-IntegrationState {
    param(
        [switch]$DryRun
    )

    $manifest = Import-PowerShellDataFile -Path $modulePath
    return New-EnableUnixToolsRuntimeContext `
        -RepoRoot $repoRoot `
        -SourceRoot (Join-Path $repoRoot 'src') `
        -ManifestPath $modulePath `
        -HelpPath (Join-Path $repoRoot 'Enable-UnixTools.ps1') `
        -Version ([string]$manifest.ModuleVersion) `
        -PathScope 'User' `
        -DryRun:$DryRun.IsPresent
}

Describe 'Integration flows' {
    It 'imports the module and keeps the compatibility alias aligned with the singular function' {
        Remove-Module Enable-UnixTools -Force -ErrorAction SilentlyContinue
        Import-Module $modulePath -Force

        $aliasCommand = Get-Command Enable-UnixTools
        $functionCommand = Get-Command Enable-UnixTool
        $commonParameters = @(
            'Confirm', 'Debug', 'ErrorAction', 'ErrorVariable',
            'InformationAction', 'InformationVariable', 'OutBuffer', 'OutVariable',
            'PipelineVariable', 'ProgressAction', 'Verbose', 'WarningAction',
            'WarningVariable', 'WhatIf'
        )

        $aliasCommand.CommandType | Should Be 'Alias'
        $aliasCommand.ResolvedCommandName | Should Be 'Enable-UnixTool'
        $functionCommand.CommandType | Should Be 'Function'

        $aliasParameters = @($aliasCommand.Parameters.Keys | Where-Object { $_ -notin $commonParameters } | Sort-Object)
        $functionParameters = @($functionCommand.Parameters.Keys | Where-Object { $_ -notin $commonParameters } | Sort-Object)
        (($aliasParameters) -join ',') | Should Be (($functionParameters) -join ',')
    }

    It 'does not materialize profile support when install is invoked with WhatIf through the module alias' {
        Invoke-WithTemporaryUserState {
            param($state)

            Import-Module $modulePath -Force

            Enable-UnixTools -UserScope -PromptInitMode Off -WhatIf

            (Test-Path -LiteralPath $state.AllHostsProfilePath -PathType Leaf) | Should Be $false
            (Test-Path -LiteralPath $state.ProfilePath -PathType Leaf) | Should Be $false
            (Test-Path -LiteralPath $state.VSCodeProfilePath -PathType Leaf) | Should Be $false
            (Test-Path -LiteralPath $state.WindowsPowerShellAllHostsProfilePath -PathType Leaf) | Should Be $false
            (Test-Path -LiteralPath $state.WindowsPowerShellProfilePath -PathType Leaf) | Should Be $false
            (Test-Path -LiteralPath $state.SupportRoot -PathType Container) | Should Be $false
        }
    }

    It 'preserves profile support during DryRun uninstall through the module function' {
        Invoke-WithTemporaryUserState {
            param($state)

            $profileText = @'
# >>> unix-tools-profile >>>
# Startup mode: Fast
# Prompt init mode: Off
# Support root: TEMP
. 'TEMP\UnixTools.ProfileLoader.ps1'
# <<< unix-tools-profile <<<
'@ -replace 'TEMP', [regex]::Escape($state.SupportRoot).Replace('\\', '\')
            Set-Content -Path $state.ProfilePath -Value $profileText -Encoding UTF8
            New-Item -ItemType Directory -Path $state.SupportRoot -Force | Out-Null
            Set-Content -Path (Join-Path $state.SupportRoot 'UnixTools.ProfileLoader.ps1') -Value '# loader' -Encoding UTF8

            $beforeProfile = Get-Content -Path $state.ProfilePath -Raw

            Import-Module $modulePath -Force
            Enable-UnixTool -UserScope -Uninstall -DryRun

            (Get-Content -Path $state.ProfilePath -Raw) | Should Be $beforeProfile
            (Test-Path -LiteralPath (Join-Path $state.SupportRoot 'UnixTools.ProfileLoader.ps1') -PathType Leaf) | Should Be $true
        }
    }

    It 'installs and removes managed profile support against isolated user state' {
        Invoke-WithTemporaryUserState {
            param($state)

            $runtimeContext = Initialize-IntegrationState

            Install-ProfileInlineSupport -ThemesDir (Join-Path $state.Root 'Themes') -Theme 'lightgreen' -StartupMode Fast -PromptMode Off -RuntimeContext $runtimeContext | Out-Null

            $allHostsState = Get-ProfileInstallationState -ProfilePath $state.AllHostsProfilePath
            $allHostsState.HasManagedBlocks | Should Be $true
            $installedState = Get-ProfileInstallationState -ProfilePath $state.ProfilePath
            $installedState.HasManagedBlocks | Should Be $true
            $installedState.StartupMode | Should Be 'Fast'
            $installedState.PromptInitMode | Should Be 'Off'
            $vsCodeProfileState = Get-ProfileInstallationState -ProfilePath $state.VSCodeProfilePath
            $vsCodeProfileState.HasManagedBlocks | Should Be $true
            $windowsPowerShellAllHostsProfileState = Get-ProfileInstallationState -ProfilePath $state.WindowsPowerShellAllHostsProfilePath
            $windowsPowerShellAllHostsProfileState.HasManagedBlocks | Should Be $true
            $windowsPowerShellProfileState = Get-ProfileInstallationState -ProfilePath $state.WindowsPowerShellProfilePath
            $windowsPowerShellProfileState.HasManagedBlocks | Should Be $true

            foreach ($fileName in Get-ManagedProfileSupportFileNameList) {
                (Test-Path -LiteralPath (Join-Path $state.SupportRoot $fileName) -PathType Leaf) | Should Be $true
            }

            Set-Content -Path (Join-Path $state.SupportRoot 'UnixTools.ObsoleteCache.ps1') -Value '# stale managed cache' -Encoding UTF8

            Remove-InstalledProfileSupport -RuntimeContext $runtimeContext | Out-Null

            $removedAllHostsState = Get-ProfileInstallationState -ProfilePath $state.AllHostsProfilePath
            $removedAllHostsState.HasManagedBlocks | Should Be $false
            $removedState = Get-ProfileInstallationState -ProfilePath $state.ProfilePath
            $removedState.HasManagedBlocks | Should Be $false
            $removedVSCodeProfileState = Get-ProfileInstallationState -ProfilePath $state.VSCodeProfilePath
            $removedVSCodeProfileState.HasManagedBlocks | Should Be $false
            $removedWindowsPowerShellAllHostsState = Get-ProfileInstallationState -ProfilePath $state.WindowsPowerShellAllHostsProfilePath
            $removedWindowsPowerShellAllHostsState.HasManagedBlocks | Should Be $false
            $removedWindowsPowerShellState = Get-ProfileInstallationState -ProfilePath $state.WindowsPowerShellProfilePath
            $removedWindowsPowerShellState.HasManagedBlocks | Should Be $false
            (Test-Path -LiteralPath $state.SupportRoot -PathType Container) | Should Be $false
        }
    }

    It 'imports the staged package and exposes both commands without regenerating behavior drift' {
        $manifest = Import-PowerShellDataFile -Path $modulePath
        $package = Initialize-ModulePackage `
            -SourceScript (Join-Path $repoRoot 'Enable-UnixTools.ps1') `
            -Name 'Enable-UnixTools' `
            -Version ([string]$manifest.ModuleVersion) `
            -ModuleDescription 'integration smoke'

        try {
            Invoke-WithTemporaryUserState {
                param($state)

                Import-Module (Join-Path $package.ModulePath 'Enable-UnixTools.psd1') -Force

                (Get-Command Enable-UnixTool).CommandType | Should Be 'Function'
                (Get-Command Enable-UnixTools).ResolvedCommandName | Should Be 'Enable-UnixTool'

                Enable-UnixTools -UserScope -PromptInitMode Off -WhatIf

                (Test-Path -LiteralPath $state.AllHostsProfilePath -PathType Leaf) | Should Be $false
                (Test-Path -LiteralPath $state.ProfilePath -PathType Leaf) | Should Be $false
                (Test-Path -LiteralPath $state.VSCodeProfilePath -PathType Leaf) | Should Be $false
                (Test-Path -LiteralPath $state.WindowsPowerShellAllHostsProfilePath -PathType Leaf) | Should Be $false
                (Test-Path -LiteralPath $state.WindowsPowerShellProfilePath -PathType Leaf) | Should Be $false
                (Test-Path -LiteralPath $state.SupportRoot -PathType Container) | Should Be $false
            }
        }
        finally {
            Remove-Item -LiteralPath $package.StagingRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'the full-install profile setup flow materializes managed profile support for the active user profile' {
        Invoke-WithTemporaryUserState {
            param($state)

            $runtimeContext = Initialize-IntegrationState
            $stateBag = [pscustomobject]@{
                DidChange = $false
            }
            $cmdletStub = [pscustomobject]@{}
            $cmdletStub | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value {
                param($target, $action)
                $null = $target
                $null = $action
                return $true
            }

            Invoke-ProfileSetupFlow -Cmdlet $cmdletStub -State $stateBag -InstallFull -ThemesDir (Join-Path $state.Root 'Themes') -Theme 'lightgreen' -PromptInitMode Off -RuntimeContext $runtimeContext

            $allHostsState = Get-ProfileInstallationState -ProfilePath $state.AllHostsProfilePath
            $allHostsState.HasManagedBlocks | Should Be $true
            $installedState = Get-ProfileInstallationState -ProfilePath $state.ProfilePath
            $installedState.HasManagedBlocks | Should Be $true
            $installedState.StartupMode | Should Be 'Fast'
            $installedState.PromptInitMode | Should Be 'Off'
            $vsCodeProfileState = Get-ProfileInstallationState -ProfilePath $state.VSCodeProfilePath
            $vsCodeProfileState.HasManagedBlocks | Should Be $true
            $windowsPowerShellAllHostsProfileState = Get-ProfileInstallationState -ProfilePath $state.WindowsPowerShellAllHostsProfilePath
            $windowsPowerShellAllHostsProfileState.HasManagedBlocks | Should Be $true
            $windowsPowerShellProfileState = Get-ProfileInstallationState -ProfilePath $state.WindowsPowerShellProfilePath
            $windowsPowerShellProfileState.HasManagedBlocks | Should Be $true
            $stateBag.DidChange | Should Be $true

            foreach ($fileName in Get-ManagedProfileSupportFileNameList) {
                (Test-Path -LiteralPath (Join-Path $state.SupportRoot $fileName) -PathType Leaf) | Should Be $true
            }
        }
    }

}
