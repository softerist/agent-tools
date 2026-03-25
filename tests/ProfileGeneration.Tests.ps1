$repoRoot = Split-Path $PSScriptRoot -Parent
$scriptPath = Join-Path $repoRoot 'Enable-UnixTools.ps1'
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-ScriptFunctions -ScriptPath $scriptPath -Names @(
    'Get-OptionalPowerShellModuleCatalog',
    'Get-SmartShellOptionalModuleNames',
    'Get-ProfileSmartShellBlockBody',
    'Resolve-ProfilePromptTheme',
    'Get-ProfilePromptBlockBody',
    'Update-ManagedOhMyPoshThemes'
)

Describe 'Generated profile blocks' {
    It 'prefers real executables over Git shim cmd wrappers in generated profile shims' {
        $scriptText = Get-Content -Raw -Path $scriptPath

        ([regex]::Matches($scriptText, [regex]::Escape("Get-Command `$Name -CommandType Application -All -ErrorAction SilentlyContinue")).Count -ge 2) | Should Be $true
        ([regex]::Matches($scriptText, [regex]::Escape("Where-Object { `$_.Source -match '\.exe$' -and `$_.Source -notmatch '\\Git\\shims\\' }")).Count -ge 2) | Should Be $true
    }

    It 'suppresses optional module import noise in the smart-shell block' {
        $block = Get-ProfileSmartShellBlockBody -StartupMode Fast

        ($block -match 'Import-Module \$module -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>\$null 3>\$null \| Out-Null') | Should Be $true
    }

    It 'skips Terminal-Icons in Codex and Antigravity shells' {
        $block = Get-ProfileSmartShellBlockBody -StartupMode Fast

        ($block -match '\$isAgentShell = \$env:CODEX_THREAD_ID -or \$env:CODEX_INTERNAL_ORIGINATOR_OVERRIDE -or \$env:ANTIGRAVITY_CLI_ALIAS') | Should Be $true
        ($block -match [regex]::Escape("if (`$isAgentShell -and `$module -eq 'Terminal-Icons')")) | Should Be $true
    }

    It 'builds a fast smart-shell block with deferred interactive features' {
        $block = Get-ProfileSmartShellBlockBody -StartupMode Fast

        ($block -match 'function global:Enable-UnixInteractiveFeatures') | Should Be $true
        ($block -match '(?m)^\s*Enable-UnixInteractiveFeatures\s*$') | Should Be $false
        ($block -match 'PSScriptAnalyzer') | Should Be $false
        ($block -match 'Set-PSReadLineOption -PredictionSource History') | Should Be $true
        ($block -match 'if \(-not \(Get-Module PSReadLine -ErrorAction SilentlyContinue\)\) \{\s*Import-Module PSReadLine -ErrorAction SilentlyContinue\s*\}') | Should Be $true
    }

    It 'builds a legacy smart-shell block that eagerly enables interactive features' {
        $block = Get-ProfileSmartShellBlockBody -StartupMode Legacy

        ($block -match '(?m)^\s*Enable-UnixInteractiveFeatures\s*$') | Should Be $true
        ($block -match '# Startup mode: Legacy') | Should Be $true
    }

    It 'builds a lazy prompt block with warmup state' {
        $block = Get-ProfilePromptBlockBody -ThemesDir 'C:\Themes' -Theme 'lightgreen' -PromptInitMode Lazy

        ($block -match '# Prompt init mode: Lazy') | Should Be $true
        ($block -match 'CODEX_THREAD_ID') | Should Be $true
        ($block -match 'ANTIGRAVITY_CLI_ALIAS') | Should Be $true
        ($block -match "UnixToolsPromptState = 'Pending'") | Should Be $true
        ($block -match 'function global:prompt') | Should Be $true
        ($block -match 'Enable-UnixInteractiveFeatures') | Should Be $true
    }

    It 'builds an eager prompt block without warmup state' {
        $block = Get-ProfilePromptBlockBody -ThemesDir 'C:\Themes' -Theme 'lightgreen' -PromptInitMode Eager

        ($block -match '# Prompt init mode: Eager') | Should Be $true
        ($block -match 'CODEX_INTERNAL_ORIGINATOR_OVERRIDE') | Should Be $true
        ($block -match 'ANTIGRAVITY_CLI_ALIAS') | Should Be $true
        ($block -match "UnixToolsPromptState = 'Pending'") | Should Be $false
    }

    It 'returns no prompt block when prompt mode is off' {
        $block = Get-ProfilePromptBlockBody -ThemesDir 'C:\Themes' -Theme 'lightgreen' -PromptInitMode Off
        $block | Should Be $null
    }

    It 'falls back to the default prompt theme when the requested theme is blank' {
        $themeInfo = Resolve-ProfilePromptTheme -ThemesDir 'C:\Themes' -Theme ''

        $themeInfo.Theme | Should Be 'lightgreen'
        $themeInfo.ConfigPath | Should Be 'C:\Themes\lightgreen.omp.json'
    }

    It 'applies the managed lightgreen theme customizations after install' {
        $themesDir = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-themes-' + [guid]::NewGuid())
        try {
            New-Item -ItemType Directory -Path $themesDir -Force | Out-Null
            $themePath = Join-Path $themesDir 'lightgreen.omp.json'
            @'
{
  "blocks": [
    {
      "type": "prompt",
      "segments": [
        {
          "type": "path",
          "foreground": "#3EC669",
          "options": {
            "style": "folder"
          },
          "template": " {{ .Path }}"
        }
      ]
    },
    {
      "type": "rprompt",
      "segments": [
        { "type": "executiontime" },
        { "type": "sysinfo" },
        { "type": "battery" },
        { "type": "time" }
      ]
    }
  ]
}
'@ | Set-Content -Path $themePath -Encoding UTF8

            Update-ManagedOhMyPoshThemes -ThemesDir $themesDir

            $theme = Get-Content -Raw -Path $themePath | ConvertFrom-Json
            $pathSegment = $theme.blocks[0].segments[0]
            $pathSegment.options.style | Should Be 'agnoster_short'
            ([int][char]$pathSegment.options.home_icon) | Should Be 0xF015
            $pathSegment.template | Should Be ' {{ .Path }} '
            ((@($theme.blocks[1].segments | Select-Object -ExpandProperty type)) -join ',') | Should Be 'battery'
        }
        finally {
            Remove-Item -Path $themesDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
