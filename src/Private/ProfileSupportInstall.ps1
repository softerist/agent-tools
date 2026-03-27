function Get-ProfileSupportTemplateRoot {
    $srcRoot = if ($script:EnableUnixToolsSourceRoot) {
        $script:EnableUnixToolsSourceRoot
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
    $base = if ($script:PathScope -eq 'User') {
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
        'UnixTools.MissingShims.ps1',
        'UnixTools.AliasCompat.ps1',
        'UnixTools.SmartShell.ps1',
        'UnixTools.Prompt.ps1',
        'UnixTools.ProfileConfig.psd1'
    )
}

function Read-ProfileSupportTemplate {
    param([Parameter(Mandatory = $true)][string]$Name)

    $templatePath = Join-Path (Get-ProfileSupportTemplateRoot) $Name
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
        [string]$ThemesDir = ''
    )

    $escapedSupportRoot = $SupportRoot.Replace("'", "''")
    $escapedTheme = ([string]$Theme).Replace("'", "''")
    $escapedThemesDir = ([string]$ThemesDir).Replace("'", "''")

    return @"
@{
    Version        = '$($script:EnableUnixToolsVersion)'
    StartupMode    = '$StartupMode'
    PromptInitMode = '$PromptMode'
    Theme          = '$escapedTheme'
    ThemesDir      = '$escapedThemesDir'
    PathScope      = '$($script:PathScope)'
    SupportRoot    = '$escapedSupportRoot'
}
"@
}

function Write-ManagedProfileSupportPayload {
    param(
        [Parameter(Mandatory = $true)][string]$StartupMode,
        [Parameter(Mandatory = $true)][string]$PromptMode,
        [string]$Theme = 'lightgreen',
        [string]$ThemesDir = ''
    )

    $supportRoot = Get-ManagedProfileSupportRoot
    foreach ($fileName in @(
            'UnixTools.ProfileLoader.ps1',
            'UnixTools.ProfileShared.ps1',
            'UnixTools.MissingShims.ps1',
            'UnixTools.AliasCompat.ps1',
            'UnixTools.SmartShell.ps1',
            'UnixTools.Prompt.ps1'
        )) {
        $content = Read-ProfileSupportTemplate -Name $fileName
        Write-AtomicUtf8File -Path (Join-Path $supportRoot $fileName) -Content $content
    }

    $configText = New-ProfileSupportConfigText -SupportRoot $supportRoot -StartupMode $StartupMode -PromptMode $PromptMode -Theme $Theme -ThemesDir $ThemesDir
    Write-AtomicUtf8File -Path (Join-Path $supportRoot 'UnixTools.ProfileConfig.psd1') -Content $configText

    return $supportRoot
}

function Remove-ManagedProfileSupportPayload {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $supportRoot = Get-ManagedProfileSupportRoot
    if (-not (Test-Path -LiteralPath $supportRoot -PathType Container)) {
        return $supportRoot
    }

    foreach ($fileName in Get-ManagedProfileSupportFileNameList) {
        $path = Join-Path $supportRoot $fileName
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            continue
        }

        if ($script:DryRun) {
            Write-DryRun "Remove-Item '$path' -Force"
        }
        else {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $script:DryRun) {
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
        [ValidateSet('Fast', 'Legacy')][string]$StartupMode = 'Fast'
    )

    return @(
        "# Startup mode: $StartupMode"
        (Read-ProfileSupportTemplate -Name 'UnixTools.SmartShell.ps1')
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
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Eager'
    )

    if ($PromptInitMode -eq 'Off') {
        return $null
    }

    $null = Resolve-ProfilePromptTheme -ThemesDir $ThemesDir -Theme $Theme

    return @(
        "# Prompt init mode: $PromptInitMode"
        (Read-ProfileSupportTemplate -Name 'UnixTools.Prompt.ps1')
    ) -join "`r`n"
}

function Install-ProfileInlineSupport {
    param(
        [string]$ThemesDir,
        [string]$Theme = 'lightgreen',
        [ValidateSet('Fast', 'Legacy')][string]$StartupMode = 'Fast',
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptMode = 'Lazy'
    )

    $profilePath = $PROFILE.CurrentUserCurrentHost
    $backup = Backup-ProfileFile -ProfilePath $profilePath
    if ($backup) { Write-Status -Type detail -Label 'Profile backup' -Detail (Split-Path $backup -Leaf) }

    Remove-InstalledProfileSupport | Out-Null
    $supportRoot = Write-ManagedProfileSupportPayload -StartupMode $StartupMode -PromptMode $PromptMode -Theme $Theme -ThemesDir $ThemesDir

    $startMarker = '# >>> unix-tools-profile >>>'
    $endMarker = '# <<< unix-tools-profile <<<'
    $blockBody = Get-ProfileLoaderBlockBody -SupportRoot $supportRoot -StartupMode $StartupMode -PromptMode $PromptMode
    Set-ProfileBlock -ProfilePath $profilePath -StartMarker $startMarker -EndMarker $endMarker -BlockBody $blockBody

    Write-Status -Type ok -Label 'Profile blocks' -Detail "loader (startup=$StartupMode, prompt=$PromptMode) -> $profilePath"
    return 'profile-loader'
}

function Install-ProfileMissingSupport {
    Install-ProfileInlineSupport -StartupMode 'Fast' -PromptMode 'Off'
}

function Install-ProfileAliasCompat {
    Install-ProfileInlineSupport -StartupMode 'Fast' -PromptMode 'Off'
}

function Install-ProfileOhMyPosh {
    param(
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [string]$Theme = 'lightgreen',
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Eager'
    )

    Install-ProfileInlineSupport -ThemesDir $ThemesDir -Theme $Theme -StartupMode 'Fast' -PromptMode $PromptInitMode
}

function Install-ProfileSmartShell {
    param(
        [ValidateSet('Fast', 'Legacy')][string]$StartupMode = 'Fast'
    )

    Install-ProfileInlineSupport -StartupMode $StartupMode -PromptMode 'Off'
}
