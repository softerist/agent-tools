$repoRoot = Split-Path $PSScriptRoot -Parent
$scriptPath = Join-Path $repoRoot 'Enable-UnixTools.ps1'
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-ScriptFunctions -ScriptPath $scriptPath -Names @(
    'Get-OptionalToolCatalog',
    'Test-GitPreferredCoreCommand',
    'Get-ApplicationSourcePriority',
    'Get-PreferredApplicationCommand',
    'Get-OptionalToolCommandName',
    'Get-OptionalToolDisplayName'
)

Describe 'Optional tool catalog' {
    It 'puts coreutils in the optional tool catalog as the base Unix layer' {
        $catalog = @(Get-OptionalToolCatalog)
        $coreutils = $catalog | Where-Object { $_.Kind -eq 'Package' -and $_.WingetId -eq 'uutils.coreutils' } | Select-Object -First 1

        ($catalog[0].Kind -eq 'Package') | Should Be $true
        ($catalog[0].WingetId -eq 'uutils.coreutils') | Should Be $true
        ($coreutils -ne $null) | Should Be $true
        ($coreutils.ProbeCommands -ne $null) | Should Be $true
        ($coreutils.ProbeCommands -contains 'ls') | Should Be $true
        ([string]::IsNullOrWhiteSpace((Get-OptionalToolCommandName -Tool $coreutils))) | Should Be $true
        ((Get-OptionalToolDisplayName -Tool $coreutils) -eq 'coreutils') | Should Be $true
    }

    It 'prefers coreutils application sources over Git paths for non-sensitive commands' {
        $coreutilsPath = 'C:\Users\demo\AppData\Local\Microsoft\WinGet\Packages\uutils.coreutils_123\head.exe'
        $gitPath = 'C:\Program Files\Git\usr\bin\head.exe'

        ((Get-ApplicationSourcePriority -Source $coreutilsPath -Name 'head') -lt (Get-ApplicationSourcePriority -Source $gitPath -Name 'head')) | Should Be $true
    }

    It 'prefers Git application sources over coreutils for GNU-sensitive core commands' {
        $coreutilsPath = 'C:\Users\demo\AppData\Local\Microsoft\WinGet\Packages\uutils.coreutils_123\ls.exe'
        $gitPath = 'C:\Program Files\Git\usr\bin\ls.exe'

        ((Get-ApplicationSourcePriority -Source $gitPath -Name 'ls') -lt (Get-ApplicationSourcePriority -Source $coreutilsPath -Name 'ls')) | Should Be $true
    }

    It 'prefers a real exe over a same-named cmd wrapper' {
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-cmd-pref-' + [guid]::NewGuid())
        try {
            New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
            Copy-Item -Path "$env:WINDIR\System32\cmd.exe" -Destination (Join-Path $tempDir 'sample.exe') -Force
            @'
@echo off
echo sample
'@ | Set-Content -Path (Join-Path $tempDir 'sample.cmd') -Encoding ASCII

            $originalPath = $env:PATH
            try {
                $env:PATH = "$tempDir;$env:PATH"
                $cmd = Get-PreferredApplicationCommand -Name 'sample'

                ($cmd -ne $null) | Should Be $true
                ($cmd.Source.EndsWith('.exe')) | Should Be $true
                ($cmd.Source -like '*.exe') | Should Be $true
            }
            finally {
                $env:PATH = $originalPath
            }
        }
        finally {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
