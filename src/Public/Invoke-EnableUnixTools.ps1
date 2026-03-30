function Invoke-UnixToolSetup {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', PositionalBinding = $false)]
    param(
        [switch]$CreateShims,
        [switch]$AddMingw,
        [switch]$AddGitCmd,
        [switch]$NormalizePath,
        [switch]$InstallProfileShims,
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
    if ($false) {
        $PSCmdlet.ShouldProcess('Invoke-UnixToolSetup', 'Delegate to MainExecutionBody.ps1') | Out-Null
    }

    $repoRoot = if ($script:EnableUnixToolsRepoRoot) {
        $script:EnableUnixToolsRepoRoot
    }
    else {
        Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    }
    $sourceRoot = if ($script:EnableUnixToolsSourceRoot) {
        $script:EnableUnixToolsSourceRoot
    }
    else {
        Split-Path $PSScriptRoot -Parent
    }

    $manifestPath = Join-Path $repoRoot 'Enable-UnixTools.psd1'
    $helpPath = Join-Path $repoRoot 'Enable-UnixTools.ps1'
    $version = try {
        [string](Import-PowerShellDataFile -Path $manifestPath).ModuleVersion
    }
    catch {
        '0.0.0'
    }

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
