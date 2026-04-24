function Invoke-UnixToolSetup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'ShouldProcess is dispatched through the per-flow functions in MainOrchestration.ps1.')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', PositionalBinding = $false)]
    param(
        [switch]$AddMingw,
        [switch]$AddGitCmd,
        [switch]$NormalizePath,
        [switch]$InstallOptionalTools,
        [switch]$InstallTerminalSetup,
        [switch]$InstallFull,
        [switch]$UserScope,
        [switch]$Uninstall,
        [switch]$UninstallOptionalTools,
        [switch]$UninstallFont,
        [string]$Theme = 'lightgreen',
        [string]$ThemesDir,
        [ValidateSet('Fast', 'Legacy')][string]$ProfileStartupMode = 'Fast',
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Lazy',
        [string]$LogPath,
        [Alias('h')]
        [switch]$Help,
        [switch]$DryRun
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $repoRoot = $script:EnableUnixToolsRepoRoot
    $sourceRoot = $script:EnableUnixToolsSourceRoot
    $manifestPath = $script:EnableUnixToolsManifestPath
    $helpPath = Join-Path $repoRoot 'Enable-UnixTools.ps1'
    $version = $script:EnableUnixToolsVersion

    $ui = Get-EnableUnixToolsScriptValue -Name UI -Default (Get-DefaultEnableUnixToolsUi)
    $pathScope = if ($UserScope) { 'User' } else { 'Machine' }
    $runtimeContext = New-EnableUnixToolsRuntimeContext `
        -RepoRoot $repoRoot `
        -SourceRoot $sourceRoot `
        -ManifestPath $manifestPath `
        -HelpPath $helpPath `
        -Version $version `
        -PathScope $pathScope `
        -DryRun:$DryRun.IsPresent `
        -Ui $ui

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13
    }
    catch {
        Write-Verbose "TLS 1.3 is unavailable in this host: $($_.Exception.Message)"
    }

    if (-not $PSBoundParameters.ContainsKey('Confirm')) {
        $ConfirmPreference = 'None'
    }

    $mainExecutionPath = Join-Path $sourceRoot 'Private\MainExecutionBody.ps1'
    if (-not (Test-Path -LiteralPath $mainExecutionPath -PathType Leaf)) {
        throw "Main execution body not found: $mainExecutionPath"
    }

    . $mainExecutionPath -runtimeContext $runtimeContext
}
