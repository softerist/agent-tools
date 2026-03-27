$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-SourceFunction -SourcePath (Join-Path $repoRoot 'src\Private\Output.ps1') -Names @(
    'Write-DryRun'
)
Import-SourceFunction -SourcePath (Join-Path $repoRoot 'src\Private\FileIO.ps1') -Names @(
    'Initialize-Directory',
    'Write-AtomicTextFile',
    'Write-AtomicUtf8File',
    'Write-AtomicAsciiFile'
)
Import-SourceFunction -SourcePath (Join-Path $repoRoot 'src\Private\PathManagement.ps1') -Names @(
    'Write-ShimCmd'
)
Import-SourceFunction -SourcePath (Join-Path $repoRoot 'src\Private\TerminalSetup.ps1') -Names @(
    'Update-EditorAndTerminalFontConfig',
    'Update-WindowsTerminalFontConfig',
    'Set-TerminalFontConfig'
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

Describe 'Runtime mutation helpers' {
    It 'does not write atomic UTF-8 files during dry run' {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-dryrun-' + [guid]::NewGuid())
        $filePath = Join-Path $tempRoot 'nested\sample.txt'
        $script:DryRun = $true

        try {
            Write-AtomicUtf8File -Path $filePath -Content 'sample'

            (Test-Path -LiteralPath $tempRoot) | Should Be $false
            (Test-Path -LiteralPath $filePath) | Should Be $false
        }
        finally {
            $script:DryRun = $false
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'creates shim cmd files through the shared atomic write helper' {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-shim-' + [guid]::NewGuid())
        $targetPath = Join-Path $env:WINDIR 'System32\cmd.exe'
        $script:DryRun = $false

        try {
            New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

            (Write-ShimCmd -shimDir $tempRoot -name 'sample' -targetExePath $targetPath) | Should Be $true

            $shimPath = Join-Path $tempRoot 'sample.cmd'
            (Test-Path -LiteralPath $shimPath -PathType Leaf) | Should Be $true

            $content = Get-Content -Path $shimPath -Raw
            ($content -match '@echo off') | Should Be $true
            ($content -match [regex]::Escape('set "_unix_tool=' + $targetPath + '"')) | Should Be $true
            ($content -match [regex]::Escape('"%_unix_tool%" %*')) | Should Be $true
        }
        finally {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'updates Windows Terminal settings through the shared settings writer' {
        $originalAppData = $env:APPDATA
        $originalLocalAppData = $env:LOCALAPPDATA
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-terminal-' + [guid]::NewGuid())
        $tempAppData = Join-Path $tempRoot 'AppData'
        $tempLocalAppData = Join-Path $tempRoot 'LocalAppData'
        $wtSettingsDir = Join-Path $tempLocalAppData 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState'
        $wtSettingsPath = Join-Path $wtSettingsDir 'settings.json'
        $script:DryRun = $false

        try {
            New-Item -ItemType Directory -Path $wtSettingsDir -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $tempAppData 'Code\User') -Force | Out-Null
            @'
{
  "profiles": {
    "defaults": {}
  }
}
'@ | Set-Content -Path $wtSettingsPath -Encoding UTF8

            $env:APPDATA = $tempAppData
            $env:LOCALAPPDATA = $tempLocalAppData

            Set-TerminalFontConfig

            $wtSettings = Get-Content -Path $wtSettingsPath -Raw
            ($wtSettings -match '"face"\s*:\s*"CaskaydiaCove NF"') | Should Be $true
            ($wtSettings -match '"defaults"\s*:\s*\{\s*"font"\s*:\s*\{') | Should Be $true
        }
        finally {
            $env:APPDATA = $originalAppData
            $env:LOCALAPPDATA = $originalLocalAppData
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
