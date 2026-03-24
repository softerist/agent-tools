#Requires -Version 5.1

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
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Lazy',
        [string]$LogPath,
        [Alias('h')]
        [switch]$Help,
        [switch]$DryRun,
        [Parameter(ValueFromRemainingArguments = $true)]
        [object[]]$ArgumentList
    )

    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Enable-UnixTools.ps1'
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Installer script not found: $scriptPath"
    }

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

    & $scriptPath @invokeParams @ArgumentList
}

Export-ModuleMember -Function 'Enable-UnixTools'
