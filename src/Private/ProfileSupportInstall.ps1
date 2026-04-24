function Get-ProfileSupportTemplateRoot {
    param([psobject]$RuntimeContext)

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    $srcRoot = if (-not [string]::IsNullOrWhiteSpace($RuntimeContext.SourceRoot)) {
        $RuntimeContext.SourceRoot
    }
    elseif ($PSScriptRoot) {
        Split-Path $PSScriptRoot -Parent
    }
    else {
        Join-Path (Get-Location).Path 'src'
    }

    return Join-Path $srcRoot 'ProfileSupport'
}

function Get-ManagedProfileSupportRoot {
    param([psobject]$RuntimeContext)

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    $base = if ($RuntimeContext.PathScope -eq 'User') {
        if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
    }
    else {
        $env:ProgramData
    }

    return Join-Path $base 'UnixToolsSystemWide\profile'
}

function Get-ManagedProfileSupportFileNameList {
    return @(
        'UnixTools.ProfileLoader.ps1',
        'UnixTools.ProfileShared.ps1',
        'UnixTools.SmartShell.ps1',
        'UnixTools.Prompt.ps1',
        'UnixTools.ProfileConfig.psd1'
    )
}

function Get-ManagedLegacyProfileSupportFileNameList {
    return @(
        'UnixTools.MissingShims.ps1',
        'UnixTools.AliasCompat.ps1'
    )
}

function Get-ManagedProfileRuntimeCacheFileNameList {
    return @(
        'UnixTools.OhMyPosh.Init.ps1'
    )
}

function Read-ProfileSupportTemplate {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [psobject]$RuntimeContext
    )

    $templatePath = Join-Path (Get-ProfileSupportTemplateRoot -RuntimeContext $RuntimeContext) $Name
    if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
        throw "Profile support template not found: $templatePath"
    }

    return Get-Content -Path $templatePath -Raw
}

function New-ProfileSupportConfigText {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'This helper only generates text content despite the New verb.')]
    param(
        [Parameter(Mandatory = $true)][string]$SupportRoot,
        [Parameter(Mandatory = $true)][string]$StartupMode,
        [Parameter(Mandatory = $true)][string]$PromptMode,
        [string]$Theme = 'lightgreen',
        [string]$ThemesDir = '',
        [psobject]$RuntimeContext
    )

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext

    $escapedSupportRoot = $SupportRoot.Replace("'", "''")
    $escapedTheme = ([string]$Theme).Replace("'", "''")
    $escapedThemesDir = ([string]$ThemesDir).Replace("'", "''")

    return @"
@{
    Version        = '$($RuntimeContext.Version)'
    StartupMode    = '$StartupMode'
    PromptInitMode = '$PromptMode'
    Theme          = '$escapedTheme'
    ThemesDir      = '$escapedThemesDir'
    PathScope      = '$($RuntimeContext.PathScope)'
    SupportRoot    = '$escapedSupportRoot'
}
"@
}

function Get-ProfileSupportCacheStamp {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ''
    }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) {
        return ''
    }

    return '{0}:{1}' -f $item.Length, $item.LastWriteTimeUtc.Ticks
}

function Initialize-ManagedProfileStartupCacheSet {
    param(
        [Parameter(Mandatory = $true)][string]$SupportRoot,
        [Parameter(Mandatory = $true)][string]$PromptMode,
        [string]$Theme = 'lightgreen',
        [string]$ThemesDir = '',
        [psobject]$RuntimeContext
    )

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    if ($RuntimeContext.DryRun) {
        return
    }

    if ($PromptMode -ne 'Off' -and -not [string]::IsNullOrWhiteSpace($ThemesDir)) {
        $themeInfo = Resolve-ProfilePromptTheme -ThemesDir $ThemesDir -Theme $Theme
        $configPath = [string]$themeInfo.ConfigPath
        $ohMyPoshCommand = Get-Command oh-my-posh -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ohMyPoshCommand -and -not [string]::IsNullOrWhiteSpace($configPath) -and (Test-Path -LiteralPath $configPath -PathType Leaf)) {
            $generated = oh-my-posh init pwsh --config "$configPath" | Out-String
            $match = [regex]::Match($generated, "&\s+'([^']+)'")
            if ($match.Success) {
                $initPath = $match.Groups[1].Value
                if (Test-Path -LiteralPath $initPath -PathType Leaf) {
                    $exePath = [string]$ohMyPoshCommand.Source
                    $escapedExePath = $exePath.Replace("'", "''")
                    $escapedConfigPath = $configPath.Replace("'", "''")
                    $escapedInitPath = $initPath.Replace("'", "''")
                    $cacheContent = @(
                        '# Kind: OhMyPosh'
                        "# ExePath: $escapedExePath"
                        "# ExeStamp: $(Get-ProfileSupportCacheStamp -Path $exePath)"
                        "# ConfigPath: $escapedConfigPath"
                        "# ConfigStamp: $(Get-ProfileSupportCacheStamp -Path $configPath)"
                        "# InitPath: $escapedInitPath"
                        '$env:POSH_SESSION_ID = [guid]::NewGuid().Guid'
                        "& '$escapedInitPath'"
                        ''
                    ) -join "`n"
                    Write-AtomicUtf8File -Path (Join-Path $SupportRoot 'UnixTools.OhMyPosh.Init.ps1') -Content $cacheContent -RuntimeContext $RuntimeContext
                }
            }
        }
    }
}

function Write-ManagedProfileSupportPayload {
    param(
        [Parameter(Mandatory = $true)][string]$StartupMode,
        [Parameter(Mandatory = $true)][string]$PromptMode,
        [string]$Theme = 'lightgreen',
        [string]$ThemesDir = '',
        [psobject]$RuntimeContext
    )

    $supportRoot = Get-ManagedProfileSupportRoot -RuntimeContext $RuntimeContext
    foreach ($fileName in @(
            'UnixTools.ProfileLoader.ps1',
            'UnixTools.ProfileShared.ps1',
            'UnixTools.SmartShell.ps1',
            'UnixTools.Prompt.ps1'
        )) {
        $content = Read-ProfileSupportTemplate -Name $fileName -RuntimeContext $RuntimeContext
        Write-AtomicUtf8File -Path (Join-Path $supportRoot $fileName) -Content $content -RuntimeContext $RuntimeContext
    }

    $configText = New-ProfileSupportConfigText -SupportRoot $supportRoot -StartupMode $StartupMode -PromptMode $PromptMode -Theme $Theme -ThemesDir $ThemesDir -RuntimeContext $RuntimeContext
    Write-AtomicUtf8File -Path (Join-Path $supportRoot 'UnixTools.ProfileConfig.psd1') -Content $configText -RuntimeContext $RuntimeContext
    Initialize-ManagedProfileStartupCacheSet -SupportRoot $supportRoot -PromptMode $PromptMode -Theme $Theme -ThemesDir $ThemesDir -RuntimeContext $RuntimeContext

    return $supportRoot
}

function Remove-ManagedProfileSupportPayload {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([psobject]$RuntimeContext)

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    $supportRoot = Get-ManagedProfileSupportRoot -RuntimeContext $RuntimeContext
    if (-not (Test-Path -LiteralPath $supportRoot -PathType Container)) {
        return $supportRoot
    }

    foreach ($fileName in (@(Get-ManagedProfileSupportFileNameList) + @(Get-ManagedLegacyProfileSupportFileNameList))) {
        $path = Join-Path $supportRoot $fileName
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            continue
        }

        if ($RuntimeContext.DryRun) {
            Write-DryRun "Remove-Item '$path' -Force"
        }
        else {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($fileName in Get-ManagedProfileRuntimeCacheFileNameList) {
        $path = Join-Path $supportRoot $fileName
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            continue
        }

        if ($RuntimeContext.DryRun) {
            Write-DryRun "Remove-Item '$path' -Force"
        }
        else {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $RuntimeContext.DryRun) {
        $remaining = Get-ChildItem -LiteralPath $supportRoot -Force -ErrorAction SilentlyContinue
        if (-not $remaining) {
            Remove-Item -LiteralPath $supportRoot -Force -ErrorAction SilentlyContinue
        }
    }

    return $supportRoot
}

function Get-ProfileLoaderBlockBody {
    param(
        [Parameter(Mandatory = $true)][string]$SupportRoot,
        [Parameter(Mandatory = $true)][string]$StartupMode,
        [Parameter(Mandatory = $true)][string]$PromptMode
    )

    $loaderPath = Join-Path $SupportRoot 'UnixTools.ProfileLoader.ps1'
    return @(
        "# Startup mode: $StartupMode"
        "# Prompt init mode: $PromptMode"
        "# Support root: $SupportRoot"
        ". '$loaderPath'"
    ) -join "`r`n"
}

function Get-ProfileSmartShellBlockBody {
    param(
        [ValidateSet('Fast', 'Legacy')][string]$StartupMode = 'Fast',
        [psobject]$RuntimeContext
    )

    return @(
        "# Startup mode: $StartupMode"
        (Read-ProfileSupportTemplate -Name 'UnixTools.SmartShell.ps1' -RuntimeContext $RuntimeContext)
    ) -join "`r`n"
}

function Resolve-ProfilePromptTheme {
    param(
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [string]$Theme = 'lightgreen'
    )

    $effectiveTheme = if ([string]::IsNullOrWhiteSpace($Theme)) {
        'lightgreen'
    }
    else {
        [System.IO.Path]::GetFileNameWithoutExtension($Theme.Trim())
    }

    if ([string]::IsNullOrWhiteSpace($effectiveTheme)) {
        $effectiveTheme = 'lightgreen'
    }

    $configPath = Join-Path $ThemesDir ("{0}.omp.json" -f $effectiveTheme)
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        return [pscustomobject]@{
            Theme      = $effectiveTheme
            ConfigPath = $configPath
        }
    }

    foreach ($fallbackTheme in @('lightgreen', 'pure', 'jandedobbeleer')) {
        $fallbackPath = Join-Path $ThemesDir ("{0}.omp.json" -f $fallbackTheme)
        if (Test-Path -LiteralPath $fallbackPath -PathType Leaf) {
            return [pscustomobject]@{
                Theme      = $fallbackTheme
                ConfigPath = $fallbackPath
            }
        }
    }

    return [pscustomobject]@{
        Theme      = $effectiveTheme
        ConfigPath = $configPath
    }
}

function Get-ProfilePromptBlockBody {
    param(
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [string]$Theme = 'lightgreen',
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Lazy',
        [psobject]$RuntimeContext
    )

    if ($PromptInitMode -eq 'Off') {
        return $null
    }

    $null = Resolve-ProfilePromptTheme -ThemesDir $ThemesDir -Theme $Theme

    return @(
        "# Prompt init mode: $PromptInitMode"
        (Read-ProfileSupportTemplate -Name 'UnixTools.Prompt.ps1' -RuntimeContext $RuntimeContext)
    ) -join "`r`n"
}

function Install-ProfileInlineSupport {
    param(
        [string]$ThemesDir,
        [string]$Theme = 'lightgreen',
        [ValidateSet('Fast', 'Legacy')][string]$StartupMode = 'Fast',
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptMode = 'Lazy',
        [psobject]$RuntimeContext
    )

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    $profilePaths = @(Get-ManagedUserProfilePathList)
    foreach ($profilePath in $profilePaths) {
        $backup = Backup-ProfileFile -ProfilePath $profilePath -RuntimeContext $RuntimeContext
        if ($backup) { Write-Status -Type detail -Label 'Profile backup' -Detail (Split-Path $backup -Leaf) -RuntimeContext $RuntimeContext }
    }

    Remove-InstalledProfileSupport -RuntimeContext $RuntimeContext | Out-Null
    $supportRoot = Write-ManagedProfileSupportPayload -StartupMode $StartupMode -PromptMode $PromptMode -Theme $Theme -ThemesDir $ThemesDir -RuntimeContext $RuntimeContext

    $startMarker = '# >>> unix-tools-profile >>>'
    $endMarker = '# <<< unix-tools-profile <<<'
    $blockBody = Get-ProfileLoaderBlockBody -SupportRoot $supportRoot -StartupMode $StartupMode -PromptMode $PromptMode
    foreach ($profilePath in $profilePaths) {
        Set-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker -BlockBody $blockBody -RuntimeContext $RuntimeContext
    }

    Write-Status -Type ok -Label 'Profile blocks' -Detail "loader (startup=$StartupMode, prompt=$PromptMode) -> $($profilePaths -join ', ')" -RuntimeContext $RuntimeContext
    return 'profile-loader'
}

function Install-ProfileOhMyPosh {
    param(
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [string]$Theme = 'lightgreen',
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Lazy',
        [psobject]$RuntimeContext
    )

    Install-ProfileInlineSupport -ThemesDir $ThemesDir -Theme $Theme -StartupMode 'Fast' -PromptMode $PromptInitMode -RuntimeContext $RuntimeContext
}

function Install-ProfileSmartShell {
    param(
        [ValidateSet('Fast', 'Legacy')][string]$StartupMode = 'Fast',
        [psobject]$RuntimeContext
    )

    Install-ProfileInlineSupport -StartupMode $StartupMode -PromptMode 'Off' -RuntimeContext $RuntimeContext
}
