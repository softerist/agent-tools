$supportRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $supportRoot 'UnixTools.ProfileConfig.psd1'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    return
}

try {
    $script:UnixToolsProfileConfig = Import-PowerShellDataFile -Path $configPath
}
catch {
    Write-Warning "unix-tools: failed to load profile config: $($_.Exception.Message)"
    return
}

foreach ($supportFile in @(
        'UnixTools.ProfileShared.ps1',
        'UnixTools.MissingShims.ps1',
        'UnixTools.AliasCompat.ps1',
        'UnixTools.SmartShell.ps1'
    )) {
    $supportPath = Join-Path $supportRoot $supportFile
    if (Test-Path -LiteralPath $supportPath -PathType Leaf) {
        . $supportPath
    }
}

if ($script:UnixToolsProfileConfig.PromptInitMode -ne 'Off') {
    $promptPath = Join-Path $supportRoot 'UnixTools.Prompt.ps1'
    if (Test-Path -LiteralPath $promptPath -PathType Leaf) {
        . $promptPath
    }
}
