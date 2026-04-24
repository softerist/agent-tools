<#
.SYNOPSIS
    Adds Unix-compatible tools to Windows PATH using real app executables.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Default')]
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

if (-not $env:ENABLE_UNIXTOOLS_CHILD) {
    $hostExe = if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Join-Path $PSHOME 'powershell.exe'
    }
    else {
        Join-Path $PSHOME 'pwsh.exe'
    }

    if (-not (Test-Path -LiteralPath $hostExe -PathType Leaf)) {
        $hostExe = (Get-Process -Id $PID).Path
    }

    $relayArgs = New-Object System.Collections.Generic.List[string]
    $relayArgs.Add('-NoProfile') | Out-Null
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $relayArgs.Add('-ExecutionPolicy') | Out-Null
        $relayArgs.Add('Bypass') | Out-Null
    }
    $relayArgs.Add('-File') | Out-Null
    $relayArgs.Add($PSCommandPath) | Out-Null

    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $value = $entry.Value
        if ($value -is [switch]) {
            if ($value.IsPresent) {
                $relayArgs.Add("-$($entry.Key)") | Out-Null
            }
            continue
        }

        if ($null -eq $value) {
            continue
        }

        $relayArgs.Add("-$($entry.Key)") | Out-Null
        $relayArgs.Add([string]$value) | Out-Null
    }

    $originalRelayFlag = $env:ENABLE_UNIXTOOLS_CHILD
    try {
        $env:ENABLE_UNIXTOOLS_CHILD = '1'
        & $hostExe $relayArgs.ToArray()
        $relayExitCode = $LASTEXITCODE
    }
    finally {
        if ($null -eq $originalRelayFlag) {
            Remove-Item Env:ENABLE_UNIXTOOLS_CHILD -ErrorAction SilentlyContinue
        }
        else {
            $env:ENABLE_UNIXTOOLS_CHILD = $originalRelayFlag
        }
    }
    if ($relayExitCode -ne 0) {
        throw "Enable-UnixTools child PowerShell process exited with code $relayExitCode."
    }
    return
}

$bootstrapPath = Join-Path $PSScriptRoot 'src\Private\Bootstrap.ps1'
if (-not (Test-Path -LiteralPath $bootstrapPath -PathType Leaf)) {
    throw "Bootstrap script not found: $bootstrapPath"
}

foreach ($functionName in @(
        'Invoke-UnixToolSetup',
        'Get-DefaultEnableUnixToolsUi',
        'New-EnableUnixToolsRuntimeContext',
        'Resolve-EnableUnixToolsRuntimeContext'
    )) {
    Remove-Item -Path ("Function:{0}" -f $functionName) -ErrorAction SilentlyContinue
}

. $bootstrapPath

if (-not (Get-Command Invoke-UnixToolSetup -CommandType Function -ErrorAction SilentlyContinue)) {
    throw 'Bootstrap completed without loading Invoke-UnixToolSetup.'
}

Invoke-UnixToolSetup @PSBoundParameters
