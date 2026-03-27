$bootstrapLoaded = Get-Variable -Scope Script -Name EnableUnixToolsBootstrapLoaded -ValueOnly -ErrorAction SilentlyContinue
if ($bootstrapLoaded) {
    return
}

$privateRoot = $PSScriptRoot
$publicRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public'
$script:EnableUnixToolsSourceRoot = Split-Path $PSScriptRoot -Parent
$script:EnableUnixToolsRepoRoot = Split-Path $script:EnableUnixToolsSourceRoot -Parent
$script:EnableUnixToolsManifestPath = Join-Path $script:EnableUnixToolsRepoRoot 'Enable-UnixTools.psd1'
$script:EnableUnixToolsVersion = try {
    [string](Import-PowerShellDataFile -Path $script:EnableUnixToolsManifestPath).ModuleVersion
}
catch {
    '0.0.0'
}
$currentUi = Get-Variable -Scope Script -Name UI -ValueOnly -ErrorAction SilentlyContinue
if (-not $currentUi) {
    $script:UI = [pscustomobject]@{
        TL     = [char]0x250C # ┌
        TR     = [char]0x2510 # ┐
        BL     = [char]0x2514 # └
        BR     = [char]0x2518 # ┘
        HLine  = [char]0x2500 # ─
        VLine  = [char]0x2502 # │
        Ok     = [char]0x2714 # ✔
        Fail   = [char]0x2716 # ✖
        Info   = [char]0x2139 # ℹ
        Detail = [char]0x203A # ›
        Warn   = [char]0x26A0 # ⚠
        Skip   = [char]0x21B7 # ↷
        Arrow  = [char]0x2192 # →
    }
}

foreach ($path in @(
        (Join-Path $privateRoot 'Output.ps1'),
        (Join-Path $privateRoot 'FileIO.ps1'),
        (Join-Path $privateRoot 'PathManagement.ps1'),
        (Join-Path $privateRoot 'CommandResolution.ps1'),
        (Join-Path $privateRoot 'OptionalTools.ps1'),
        (Join-Path $privateRoot 'TerminalSetup.ps1'),
        (Join-Path $privateRoot 'ProfileMigration.ps1'),
        (Join-Path $privateRoot 'ProfileSupportInstall.ps1'),
        (Join-Path $privateRoot 'MainOrchestration.ps1'),
        (Join-Path $publicRoot 'Invoke-EnableUnixTools.ps1')
    )) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Bootstrap source not found: $path"
    }

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        throw ($errors | ForEach-Object Message | Out-String)
    }

    $functions = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $false))

    foreach ($functionAst in $functions) {
        . ([scriptblock]::Create($functionAst.Extent.Text))
    }
}

$script:EnableUnixToolsBootstrapLoaded = $true
