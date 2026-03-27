#Requires -Version 5.1

<#
.SYNOPSIS
    Adds Unix-compatible tools to Windows PATH with optional shims and profile support.
#>
function Enable-UnixTools {
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
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Eager',
        [string]$LogPath,
        [Alias('h')]
        [switch]$Help,
        [switch]$DryRun,
        [Parameter(ValueFromRemainingArguments = $true)]
        [object[]]$ArgumentList
    )

    $bootstrapPath = Join-Path -Path $PSScriptRoot -ChildPath 'src\Private\Bootstrap.ps1'
    if (-not (Test-Path -LiteralPath $bootstrapPath -PathType Leaf)) {
        throw "Bootstrap script not found: $bootstrapPath"
    }
    . $bootstrapPath

    $wrapperHandlesShouldProcess = $PSBoundParameters.ContainsKey('WhatIf') -or $PSBoundParameters.ContainsKey('Confirm')
    if ($wrapperHandlesShouldProcess) {
        $scopeTarget = if ($UserScope) { 'User scope' } else { 'Machine scope' }
        $operation = if ($Uninstall) { 'Invoke unix-tools uninstall' } else { 'Invoke unix-tools installer' }
        if (-not $PSCmdlet.ShouldProcess($scopeTarget, $operation)) {
            return
        }
    }

    $invokeParams = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -eq 'ArgumentList') {
            continue
        }
        if ($wrapperHandlesShouldProcess -and ($entry.Key -eq 'Confirm' -or $entry.Key -eq 'WhatIf')) {
            continue
        }
        $invokeParams[$entry.Key] = $entry.Value
    }

    Invoke-EnableUnixTools @invokeParams @ArgumentList
}

Export-ModuleMember -Function 'Enable-UnixTools'
