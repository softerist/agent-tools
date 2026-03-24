function Get-ScriptAst {
    param([Parameter(Mandatory = $true)][string]$ScriptPath)

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        throw ($errors | ForEach-Object { $_.Message } | Out-String)
    }

    return $ast
}

function Import-ScriptFunctions {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    $ast = Get-ScriptAst -ScriptPath $ScriptPath
    foreach ($name in $Names) {
        $functionAst = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
            }, $true) | Select-Object -First 1

        if (-not $functionAst) {
            throw "Function '$name' was not found in $ScriptPath"
        }

        $definition = $functionAst.Extent.Text -replace ("^function\s+{0}\b" -f [regex]::Escape($name)), ("function global:{0}" -f $name)
        Invoke-Expression $definition
    }
}

function Get-ScriptParamNames {
    param([Parameter(Mandatory = $true)][string]$ScriptPath)

    $ast = Get-ScriptAst -ScriptPath $ScriptPath
    return @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
}

function New-TestTempPath {
    param([string]$Extension = '.tmp')

    return Join-Path ([System.IO.Path]::GetTempPath()) ("agent-tools-{0}{1}" -f ([guid]::NewGuid()), $Extension)
}
