if ($script:EnableUnixToolsBootstrapLoaded) {
    return
}

$privateRoot = $PSScriptRoot
$publicRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public'
$script:EnableUnixToolsSourceRoot = Split-Path $PSScriptRoot -Parent
$script:EnableUnixToolsRepoRoot = Split-Path $script:EnableUnixToolsSourceRoot -Parent

foreach ($path in @(
        (Join-Path $privateRoot 'Output.ps1'),
        (Join-Path $privateRoot 'PathManagement.ps1'),
        (Join-Path $privateRoot 'CommandResolution.ps1'),
        (Join-Path $privateRoot 'OptionalTools.ps1'),
        (Join-Path $privateRoot 'TerminalSetup.ps1'),
        (Join-Path $privateRoot 'FileIO.ps1'),
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
        Invoke-Expression $functionAst.Extent.Text
    }
}

$script:EnableUnixToolsBootstrapLoaded = $true
