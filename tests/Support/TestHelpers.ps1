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

        if ($functionAst) {
            $definition = $functionAst.Extent.Text -replace ("^function\s+{0}\b" -f [regex]::Escape($name)), ("function global:{0}" -f $name)
            Invoke-Expression $definition
            continue
        }

        $repoRoot = Split-Path -Parent $ScriptPath
        $bootstrapPath = Join-Path $repoRoot 'src\Private\Bootstrap.ps1'
        if (-not (Test-Path -LiteralPath $bootstrapPath -PathType Leaf)) {
            throw "Function '$name' was not found in $ScriptPath"
        }

        . $bootstrapPath
        $sourceFiles = @(
            Get-ChildItem -Path (Join-Path $repoRoot 'src\Private') -Filter *.ps1 -File -ErrorAction SilentlyContinue
            Get-ChildItem -Path (Join-Path $repoRoot 'src\Public') -Filter *.ps1 -File -ErrorAction SilentlyContinue
        ) | Select-Object -ExpandProperty FullName -Unique

        foreach ($sourceFile in $sourceFiles) {
            $sourceAst = Get-ScriptAst -ScriptPath $sourceFile
            $sourceAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
                }, $false) | ForEach-Object {
                $loaded = Get-Command $_.Name -CommandType Function -ErrorAction SilentlyContinue
                if ($loaded) {
                    Set-Item -Path ("Function:global:{0}" -f $_.Name) -Value $loaded.ScriptBlock
                }
            }
        }

        if (-not (Get-Command $name -CommandType Function -ErrorAction SilentlyContinue)) {
            throw "Function '$name' was not found in $ScriptPath or bootstrap sources"
        }
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
