$repoRoot = Split-Path $PSScriptRoot -Parent
$scriptPath = Join-Path $repoRoot 'Enable-UnixTools.ps1'
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-ScriptFunction -ScriptPath $scriptPath -Names @(
    'Set-TerminalFontConfig',
    'Update-EditorAndTerminalFontConfig'
)

function global:Write-Status {
    param(
        [string]$Type,
        [string]$Label,
        [string]$Detail,
        [switch]$Indent
    )

    $null = $Type, $Label, $Detail, $Indent
}

Describe 'Terminal setup' {
    It 'adds the Nerd Font to editor and terminal settings for VS Code and Antigravity' {
        $originalAppData = $env:APPDATA
        $originalLocalAppData = $env:LOCALAPPDATA
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-appdata-' + [guid]::NewGuid())
        $tempLocalRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-localappdata-' + [guid]::NewGuid())

        try {
            $codeSettingsDir = Join-Path $tempRoot 'Code\User'
            $antigravitySettingsDir = Join-Path $tempRoot 'Antigravity\User'
            New-Item -ItemType Directory -Path $codeSettingsDir -Force | Out-Null
            New-Item -ItemType Directory -Path $antigravitySettingsDir -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $tempLocalRoot 'Packages') -Force | Out-Null

            @'
{
    "editor.fontFamily": "Consolas",
    "terminal.integrated.fontFamily": "Fira Code",
    "window.zoomLevel": 1
}
'@ | Set-Content -Path (Join-Path $codeSettingsDir 'settings.json') -Encoding UTF8

            @'
{
    "workbench.colorTheme": "Default Dark Modern"
}
'@ | Set-Content -Path (Join-Path $antigravitySettingsDir 'settings.json') -Encoding UTF8

            $env:APPDATA = $tempRoot
            $env:LOCALAPPDATA = $tempLocalRoot

            Set-TerminalFontConfig

            $codeSettings = Get-Content -Path (Join-Path $codeSettingsDir 'settings.json') -Raw
            ($codeSettings -match '"editor\.fontFamily"\s*:') | Should Be $true
            ([regex]::Matches($codeSettings, 'CaskaydiaCove NF').Count -ge 2) | Should Be $true
            ($codeSettings -match '"editor\.fontFamily"\s*:\s*"CaskaydiaCove NF, Consolas"') | Should Be $true
            ($codeSettings -match '"terminal\.integrated\.fontFamily"\s*:\s*"CaskaydiaCove NF, Fira Code"') | Should Be $true
            ($codeSettings -match '`Consolas') | Should Be $false
            ($codeSettings -match '`Fira Code') | Should Be $false
            ($codeSettings -match '"terminal\.integrated\.fontFamily"\s*:') | Should Be $true

            $antigravitySettings = Get-Content -Path (Join-Path $antigravitySettingsDir 'settings.json') -Raw
            ($antigravitySettings -match '"editor\.fontFamily"\s*:') | Should Be $true
            ([regex]::Matches($antigravitySettings, 'CaskaydiaCove NF').Count -ge 2) | Should Be $true
            ($antigravitySettings -match '"terminal\.integrated\.fontFamily"\s*:\s*"CaskaydiaCove NF"') | Should Be $true
        }
        finally {
            $env:APPDATA = $originalAppData
            $env:LOCALAPPDATA = $originalLocalAppData
            Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $tempLocalRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
