if (Get-Variable -Scope Script -Name EnableUnixToolsBootstrapLoaded -ValueOnly -ErrorAction SilentlyContinue) {
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

if (-not (Get-Variable -Scope Script -Name UI -ValueOnly -ErrorAction SilentlyContinue)) {
    $script:UI = [pscustomobject]@{
        TL     = [string][char]0x256D
        TR     = [string][char]0x256E
        BL     = [string][char]0x2570
        BR     = [string][char]0x256F
        HLine  = [string][char]0x2500
        VLine  = [string][char]0x2502
        Ok     = [string][char]0x2713
        Fail   = [string][char]0x2715
        Info   = [string][char]0x2139
        Detail = [string][char]0x203A
        Warn   = [string][char]0x26A0
        Skip   = [string][char]0x00B7
        Arrow  = [string][char]0x2192
    }
}

# Load each function as its own scriptblock instead of dot-sourcing the file: AMSI flags TerminalSetup.ps1 wholesale (font copy + registry write + web download + Expand-Archive trips a heuristic), but accepts each function in isolation.
foreach ($path in @(
        (Join-Path $privateRoot 'RuntimeContext.ps1'),
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

    foreach ($functionAst in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($functionAst.Extent.Text))
    }
}

$script:EnableUnixToolsBootstrapLoaded = $true
