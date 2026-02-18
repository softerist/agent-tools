[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [object[]]$Args
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$newScript = Join-Path $scriptDir 'Enable-UnixToolsSystemWide.ps1'

if (-not (Test-Path $newScript)) {
    throw "Missing target script: $newScript"
}

Write-Host "[Deprecated] Enable-GitToolsSystemWide.ps1 -> Enable-UnixToolsSystemWide.ps1" -ForegroundColor Yellow
& $newScript @Args
