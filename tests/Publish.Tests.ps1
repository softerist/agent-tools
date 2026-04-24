$repoRoot = Split-Path $PSScriptRoot -Parent
$publishPath = Join-Path $repoRoot 'publish.ps1'
$manifestPath = Join-Path $repoRoot 'Enable-UnixTools.psd1'
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-ScriptFunction -ScriptPath $publishPath -Names @(
    'Get-ManifestVersionDefault',
    'Assert-RequestedModuleVersionMatchesManifest',
    'Get-DefaultReadmeContent',
    'Get-DefaultAboutHelpContent',
    'Initialize-ModulePackage'
)

Describe 'Publish packaging' {
    It 'uses the committed manifest version as the default version source' {
        $manifest = Import-PowerShellDataFile -Path $manifestPath

        (Get-ManifestVersionDefault -Path $manifestPath) | Should Be ([string]$manifest.ModuleVersion)
    }

    It 'rejects an explicit module version that diverges from the committed manifest' {
        $threw = $false

        try {
            Assert-RequestedModuleVersionMatchesManifest -RequestedVersion '0.0.0' -ManifestPath $manifestPath
        }
        catch {
            $threw = $true
            $_.Exception.Message | Should Match 'Requested ModuleVersion'
        }

        $threw | Should Be $true
    }

    It 'stages the committed module files and source tree without regenerating metadata' {
        $manifest = Import-PowerShellDataFile -Path $manifestPath
        $package = Initialize-ModulePackage `
            -SourceScript (Join-Path $repoRoot 'Enable-UnixTools.ps1') `
            -Name 'Enable-UnixTools' `
            -Version ([string]$manifest.ModuleVersion) `
            -ModuleDescription 'test package'

        try {
            $stagedPsm1 = Join-Path $package.ModulePath 'Enable-UnixTools.psm1'
            $stagedPsd1 = Join-Path $package.ModulePath 'Enable-UnixTools.psd1'
            $stagedBootstrap = Join-Path $package.ModulePath 'src\Private\Bootstrap.ps1'
            $stagedCatalog = Join-Path $package.ModulePath 'catalogs\optional-tools.json'

            (Test-Path -LiteralPath $stagedPsm1 -PathType Leaf) | Should Be $true
            (Test-Path -LiteralPath $stagedPsd1 -PathType Leaf) | Should Be $true
            (Test-Path -LiteralPath $stagedBootstrap -PathType Leaf) | Should Be $true
            (Test-Path -LiteralPath $stagedCatalog -PathType Leaf) | Should Be $true

            (Get-Content -Raw -Path $stagedPsm1) | Should Be (Get-Content -Raw -Path (Join-Path $repoRoot 'Enable-UnixTools.psm1'))
            (Get-Content -Raw -Path $stagedPsd1) | Should Be (Get-Content -Raw -Path $manifestPath)

            $stagedManifest = Import-PowerShellDataFile -Path $stagedPsd1
            $stagedManifest.GUID | Should Be $manifest.GUID

            $resolvedManifest = Test-ModuleManifest -Path $stagedPsd1
            $resolvedManifest.Name | Should Be 'Enable-UnixTools'
        }
        finally {
            Remove-Item -LiteralPath $package.StagingRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'tracks staged source files in the committed manifest file list' {
        $manifest = Import-PowerShellDataFile -Path $manifestPath
        $expectedFiles = @(
            'catalogs\optional-modules.json',
            'catalogs\optional-tools.json',
            'src\Private\Bootstrap.ps1',
            'src\Private\CommandResolution.ps1',
            'src\Private\FileIO.ps1',
            'src\Private\MainExecutionBody.ps1',
            'src\Private\MainOrchestration.ps1',
            'src\Private\OptionalTools.ps1',
            'src\Private\ProfileSupportInstall.ps1',
            'src\Private\RuntimeContext.ps1',
            'src\ProfileSupport\UnixTools.ProfileLoader.ps1',
            'src\ProfileSupport\UnixTools.ProfileShared.ps1',
            'src\Public\Invoke-EnableUnixTools.ps1'
        )

        foreach ($file in $expectedFiles) {
            ($manifest.FileList -contains $file) | Should Be $true
        }

        foreach ($file in $manifest.FileList) {
            (Test-Path -LiteralPath (Join-Path $repoRoot $file) -PathType Leaf) | Should Be $true
        }
    }
}
