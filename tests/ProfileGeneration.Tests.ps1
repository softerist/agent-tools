$repoRoot = Split-Path $PSScriptRoot -Parent
$scriptPath = Join-Path $repoRoot 'Enable-UnixTools.ps1'
. (Join-Path $PSScriptRoot 'Support\TestHelpers.ps1')

Import-ScriptFunction -ScriptPath $scriptPath -Names @(
    'Get-OptionalPowerShellModuleCatalog',
    'Get-SmartShellOptionalModuleNameSet',
    'Get-ProfileSmartShellBlockBody',
    'Resolve-ProfilePromptTheme',
    'Get-ProfilePromptBlockBody',
    'Update-ManagedOhMyPoshTheme'
)

Describe 'Generated profile blocks' {
    It 'uses shared command-resolution helpers in managed profile support scripts' {
        $shared = Get-Content -Raw -Path (Join-Path $repoRoot 'src\ProfileSupport\UnixTools.ProfileShared.ps1')
        $loader = Get-Content -Raw -Path (Join-Path $repoRoot 'src\ProfileSupport\UnixTools.ProfileLoader.ps1')
        $smartShell = Get-Content -Raw -Path (Join-Path $repoRoot 'src\ProfileSupport\UnixTools.SmartShell.ps1')

        ($shared -match 'function Get-UnixToolsProfileConfig') | Should Be $true
        ($shared -match 'function Get-PreferredApplicationCommand') | Should Be $true
        ($shared -match 'function Get-UnixShimExecutable') | Should Be $true
        ($loader -match 'UnixTools\.MissingShims\.ps1') | Should Be $false
        ($loader -match 'UnixTools\.AliasCompat\.ps1') | Should Be $false
        ($smartShell -match 'Get-PreferredApplicationCommand -Name \$candidate') | Should Be $true
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

        ($block -match 'function Enable-UnixInteractiveFeatureSet') | Should Be $true
        ($block -match "StartupMode -eq 'Legacy'") | Should Be $true
        ($block -match 'function Initialize-UnixToolsPsReadLineState') | Should Be $true
        ($block -match 'function Invoke-UnixToolsDeferredZoxideCommand') | Should Be $true
        ($block -match [regex]::Escape("foreach (`$name in @('ls', 'cp', 'mv', 'rm', 'cat', 'sort'))")) | Should Be $true
        ($block -match "Get-PreferredApplicationCommand -Name 'eza'") | Should Be $true
        ($block -match 'Import-Module \$module -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>\$null 3>\$null \| Out-Null') | Should Be $true
    }

    It 'builds a legacy smart-shell block that eagerly enables interactive features' {
        $block = Get-ProfileSmartShellBlockBody -StartupMode Legacy

        ($block -match '(?m)^\s*Enable-UnixInteractiveFeatureSet\s*$') | Should Be $true
        ($block -match '# Startup mode: Legacy') | Should Be $true
    }

    It 'builds a lazy prompt block with warmup state' {
        $block = Get-ProfilePromptBlockBody -ThemesDir 'C:\Themes' -Theme 'lightgreen' -PromptInitMode Lazy

        ($block -match '# Prompt init mode: Lazy') | Should Be $true
        ($block -match 'CODEX_THREAD_ID') | Should Be $true
        ($block -match 'ANTIGRAVITY_CLI_ALIAS') | Should Be $true
        ($block -match "UnixToolsPromptState = 'Pending'") | Should Be $true
        ($block -match 'function global:prompt') | Should Be $true
        ($block -match 'Invoke-UnixToolsDeferredInteractivePrompt') | Should Be $true
        ($block -match 'Enable-UnixInteractiveFeatureSet') | Should Be $true
    }

    It 'builds an eager prompt block without warmup state' {
        $block = Get-ProfilePromptBlockBody -ThemesDir 'C:\Themes' -Theme 'lightgreen' -PromptInitMode Eager

        ($block -match '# Prompt init mode: Eager') | Should Be $true
        ($block -match 'CODEX_INTERNAL_ORIGINATOR_OVERRIDE') | Should Be $true
        ($block -match 'ANTIGRAVITY_CLI_ALIAS') | Should Be $true
        ($block -match 'Get-UnixToolsProfileConfig') | Should Be $true
        ($block -match 'Invoke-UnixToolsCachedOhMyPoshInit') | Should Be $true
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
          "template": "î—¿ {{ .Path }}"
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

            Update-ManagedOhMyPoshTheme -ThemesDir $themesDir

            $theme = Get-Content -Raw -Path $themePath | ConvertFrom-Json
            $pathSegment = $theme.blocks[0].segments[0]
            $pathSegment.options.style | Should Be 'agnoster_short'
            ([int][char]$pathSegment.options.home_icon) | Should Be 0xF015
            $pathSegment.template | Should Be ' {{ .Path }} '
            ($pathSegment.options.folder_separator_icon -match '#F4F1DE') | Should Be $true
            ($pathSegment.options.folder_separator_icon -match '#7DD3FC') | Should Be $false
            (@($theme.blocks | Select-Object -ExpandProperty type) -contains 'rprompt') | Should Be $false
        }
        finally {
            Remove-Item -Path $themesDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'shares loader config with the prompt support script and initializes oh-my-posh' {
        $supportRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-support-' + [guid]::NewGuid())
        $themesDir = Join-Path $supportRoot 'themes'
        try {
            New-Item -ItemType Directory -Path $supportRoot -Force | Out-Null
            New-Item -ItemType Directory -Path $themesDir -Force | Out-Null

            foreach ($fileName in @(
                    'UnixTools.ProfileShared.ps1',
                    'UnixTools.ProfileLoader.ps1',
                    'UnixTools.Prompt.ps1'
                )) {
                Copy-Item -LiteralPath (Join-Path $repoRoot ('src\ProfileSupport\' + $fileName)) -Destination (Join-Path $supportRoot $fileName) -Force
            }

            @'
function Enable-UnixInteractiveFeatureSet {}
'@ | Set-Content -LiteralPath (Join-Path $supportRoot 'UnixTools.SmartShell.ps1') -Encoding UTF8

            @"
@{
    Version        = '2.5.0'
    StartupMode    = 'Fast'
    PromptInitMode = 'Lazy'
    Theme          = 'lightgreen'
    ThemesDir      = '$($themesDir.Replace("'", "''"))'
    PathScope      = 'User'
    SupportRoot    = '$($supportRoot.Replace("'", "''"))'
}
"@ | Set-Content -LiteralPath (Join-Path $supportRoot 'UnixTools.ProfileConfig.psd1') -Encoding UTF8

            '{}' | Set-Content -LiteralPath (Join-Path $themesDir 'lightgreen.omp.json') -Encoding UTF8

            function Invoke-OhMyPoshStub {
                param([Parameter(ValueFromRemainingArguments = $true)]$RemainingArgs)
                $null = $RemainingArgs
                @'
function global:prompt { "OMP TEST" }
'@
            }
            Set-Alias -Name oh-my-posh -Value Invoke-OhMyPoshStub -Scope Global

            . (Join-Path $supportRoot 'UnixTools.ProfileLoader.ps1')

            (Get-Variable -Scope Global -Name UnixToolsProfileConfig -ValueOnly).ThemesDir | Should Be $themesDir
        }
        finally {
            Remove-Item Function:\Global:prompt -ErrorAction SilentlyContinue
            Remove-Item Function:\Invoke-OhMyPoshStub -ErrorAction SilentlyContinue
            Remove-Item Alias:\Global:oh-my-posh -ErrorAction SilentlyContinue
            Remove-Item Function:\Enable-UnixInteractiveFeatureSet -ErrorAction SilentlyContinue
            Remove-Variable -Name UnixToolsProfileConfig -Scope Global -ErrorAction SilentlyContinue
            Remove-Item -Path $supportRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'uses the real ls executable instead of the PowerShell alias when a real app is available' {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-ls-pass-' + [guid]::NewGuid())
        try {
            New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

            @'
@echo off
echo LS_PASSTHROUGH %*
'@ | Set-Content -Path (Join-Path $tempRoot 'ls.cmd') -Encoding ASCII

            Set-Variable -Name UnixToolsProfileConfig -Scope Global -Value ([pscustomobject]@{
                    StartupMode    = 'Fast'
                    PromptInitMode = 'Off'
                    Theme          = 'lightgreen'
                    ThemesDir      = ''
                })

            . (Join-Path $repoRoot 'src\ProfileSupport\UnixTools.ProfileShared.ps1')
            . (Join-Path $repoRoot 'src\ProfileSupport\UnixTools.SmartShell.ps1')

            $lsPath = Join-Path $tempRoot 'ls.cmd'
            function global:Get-PreferredApplicationCommand {
                param([Parameter(Mandatory = $true)][string]$Name)
                if ($Name -eq 'ls') {
                    return [pscustomobject]@{ Source = $lsPath }
                }
                return $null
            }

            $lsCommand = Get-Command -Name ls -CommandType Function
            $lsCommand.CommandType | Should Be 'Function'
            $output = (& $lsCommand -lf | Out-String)
            $output | Should Match 'LS_PASSTHROUGH -lf'
        }
        finally {
            Remove-Item Function:\Global:Get-PreferredApplicationCommand -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:ls -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:cp -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:mv -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:rm -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:cat -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:sort -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:j -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:ji -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:y -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:lg -ErrorAction SilentlyContinue
            Remove-Item Alias:\Global:Enable-UnixInteractiveFeatures -ErrorAction SilentlyContinue
            Remove-Variable UnixToolsProfileConfig -Scope Global -ErrorAction SilentlyContinue
            Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'prefers eza for ls and translates classic -f semantics when eza is available' {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('agent-tools-eza-pass-' + [guid]::NewGuid())
        try {
            New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

            @'
@echo off
echo LS_PASSTHROUGH %*
'@ | Set-Content -Path (Join-Path $tempRoot 'ls.cmd') -Encoding ASCII

            @'
@echo off
echo EZA_PASSTHROUGH %*
'@ | Set-Content -Path (Join-Path $tempRoot 'eza.cmd') -Encoding ASCII

            Set-Variable -Name UnixToolsProfileConfig -Scope Global -Value ([pscustomobject]@{
                    StartupMode    = 'Fast'
                    PromptInitMode = 'Off'
                    Theme          = 'lightgreen'
                    ThemesDir      = ''
                })

            . (Join-Path $repoRoot 'src\ProfileSupport\UnixTools.ProfileShared.ps1')
            . (Join-Path $repoRoot 'src\ProfileSupport\UnixTools.SmartShell.ps1')

            $lsPath = Join-Path $tempRoot 'ls.cmd'
            $ezaPath = Join-Path $tempRoot 'eza.cmd'
            function global:Get-PreferredApplicationCommand {
                param([Parameter(Mandatory = $true)][string]$Name)
                switch ($Name) {
                    'ls' { return [pscustomobject]@{ Source = $lsPath } }
                    'eza' { return [pscustomobject]@{ Source = $ezaPath } }
                    default { return $null }
                }
            }

            $lsCommand = Get-Command -Name ls -CommandType Function
            $output = (& $lsCommand -lf | Out-String)
            $output | Should Not Match 'LS_PASSTHROUGH'
            $output | Should Match 'EZA_PASSTHROUGH -l -a -s none'
        }
        finally {
            Remove-Item Function:\Global:Get-PreferredApplicationCommand -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:ls -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:cp -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:mv -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:rm -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:cat -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:sort -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:j -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:ji -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:y -ErrorAction SilentlyContinue
            Remove-Item Function:\Global:lg -ErrorAction SilentlyContinue
            Remove-Item Alias:\Global:Enable-UnixInteractiveFeatures -ErrorAction SilentlyContinue
            Remove-Variable UnixToolsProfileConfig -Scope Global -ErrorAction SilentlyContinue
            Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}


