<#
.SYNOPSIS
    Adds Unix-compatible tools to Windows PATH with optional shims and profile support.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Default')]
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
    [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Eager',
    [string]$LogPath,
    [Alias('h')]
    [switch]$Help,
    [switch]$DryRun
)

$bootstrapPath = Join-Path $PSScriptRoot 'src\Private\Bootstrap.ps1'
if (-not (Test-Path -LiteralPath $bootstrapPath -PathType Leaf)) {
    throw "Bootstrap script not found: $bootstrapPath"
}

. $bootstrapPath

Invoke-UnixToolSetup @PSBoundParameters
