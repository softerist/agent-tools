$supportRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $supportRoot 'UnixTools.ProfileConfig.psd1'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    return
}

try {
    Set-Variable -Scope Global -Name UnixToolsProfileConfig -Value (Import-PowerShellDataFile -Path $configPath)
}
catch {
    Write-Warning "unix-tools: failed to load profile config: $($_.Exception.Message)"
    return
}

foreach ($supportFile in @(
        'UnixTools.ProfileShared.ps1',
        'UnixTools.SmartShell.ps1'
    )) {
    $supportPath = Join-Path $supportRoot $supportFile
    if (Test-Path -LiteralPath $supportPath -PathType Leaf) {
        . $supportPath
    }
}

$profileConfig = Get-Variable -Scope Global -Name UnixToolsProfileConfig -ValueOnly -ErrorAction SilentlyContinue
if ($profileConfig -and $profileConfig.PromptInitMode -ne 'Off') {
    $promptPath = Join-Path $supportRoot 'UnixTools.Prompt.ps1'
    if (Test-Path -LiteralPath $promptPath -PathType Leaf) {
        . $promptPath
    }
}
