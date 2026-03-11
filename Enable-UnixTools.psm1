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
        [switch]$InstallFull,
        [switch]$UserScope,
        [switch]$Uninstall,
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

    $invokeParams = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -eq 'ArgumentList') {
            continue
        }
        $invokeParams[$entry.Key] = $entry.Value
    }

    & $scriptPath @invokeParams @ArgumentList
}

Export-ModuleMember -Function 'Enable-UnixTools'
