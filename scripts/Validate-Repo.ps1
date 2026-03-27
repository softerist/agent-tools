[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-RequiredCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$InstallHint
    )

    if (Get-Command $Name -ErrorAction SilentlyContinue) {
        return
    }

    throw "Required command '$Name' is not available. $InstallHint"
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$manifestPath = Join-Path $repoRoot 'Enable-UnixTools.psd1'
$testsPath = Join-Path $repoRoot 'tests'

Push-Location $repoRoot
try {
    Assert-RequiredCommand -Name 'Invoke-ScriptAnalyzer' -InstallHint "Install the PSScriptAnalyzer module and retry."
    Assert-RequiredCommand -Name 'Invoke-Pester' -InstallHint "Install the Pester module and retry."

    Write-Output 'Running ScriptAnalyzer...'
    $analysisResults = @(Invoke-ScriptAnalyzer -Path $repoRoot -Recurse)
    if ($analysisResults.Count -gt 0) {
        $analysisResults |
            Select-Object RuleName, Severity, ScriptName, Line, Message |
            Format-Table -AutoSize |
            Out-String |
            Write-Output
        throw "ScriptAnalyzer reported $($analysisResults.Count) finding(s)."
    }

    Write-Output 'Running Pester...'
    $pesterResult = Invoke-Pester -Script $testsPath -PassThru
    if (-not $pesterResult) {
        throw 'Invoke-Pester returned no result object.'
    }
    if ($pesterResult.FailedCount -gt 0) {
        throw "Pester reported $($pesterResult.FailedCount) failed test(s)."
    }

    Write-Output 'Validating module manifest...'
    Test-ModuleManifest -Path $manifestPath | Out-Null

    Write-Output 'Running module import smoke test...'
    Remove-Module Enable-UnixTools -Force -ErrorAction SilentlyContinue
    Import-Module $manifestPath -Force

    $functionCommand = Get-Command Enable-UnixTool -ErrorAction Stop
    $aliasCommand = Get-Command Enable-UnixTools -ErrorAction Stop

    if ($functionCommand.CommandType -ne 'Function') {
        throw "Enable-UnixTool should resolve to a function, got '$($functionCommand.CommandType)'."
    }
    if ($aliasCommand.CommandType -ne 'Alias') {
        throw "Enable-UnixTools should resolve to an alias, got '$($aliasCommand.CommandType)'."
    }
    if ($aliasCommand.ResolvedCommandName -ne 'Enable-UnixTool') {
        throw "Enable-UnixTools should resolve to Enable-UnixTool, got '$($aliasCommand.ResolvedCommandName)'."
    }

    Write-Output 'Repository validation completed successfully.'
}
finally {
    Remove-Module Enable-UnixTools -Force -ErrorAction SilentlyContinue
    Pop-Location
}
