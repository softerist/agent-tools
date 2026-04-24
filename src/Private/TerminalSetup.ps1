function Save-TerminalThemeBundle {
    param(
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [string]$Theme = 'lightgreen',
        [psobject]$RuntimeContext
    )

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    if ($RuntimeContext.DryRun) {
        Write-DryRun "Download and extract Oh My Posh themes to '$ThemesDir'"
        return
    }

    if (Test-Path $ThemesDir) {
        Write-Status -Type info -Label "Themes directory" -Detail "already exists, skipping download" -Indent -RuntimeContext $RuntimeContext
        Update-ManagedOhMyPoshTheme -ThemesDir $ThemesDir -Theme $Theme -RuntimeContext $RuntimeContext
        return
    }

    $zip = Join-Path $env:TEMP "omp-themes-$([guid]::NewGuid().ToString().Split('-')[0]).zip"
    try {
        Write-Status -Type detail -Label "Downloading themes" -Detail "oh-my-posh/releases/latest" -Indent -RuntimeContext $RuntimeContext
        Invoke-WebRequest -Uri "https://github.com/JanDeDobbeleer/oh-my-posh/releases/latest/download/themes.zip" -OutFile $zip -ErrorAction Stop
        New-DirectoryIfMissing -dir $ThemesDir -RuntimeContext $RuntimeContext
        Write-Status -Type detail -Label "Extracting themes" -Detail $ThemesDir -Indent -RuntimeContext $RuntimeContext
        Expand-Archive -Path $zip -DestinationPath $ThemesDir -Force -ErrorAction Stop
        Update-ManagedOhMyPoshTheme -ThemesDir $ThemesDir -Theme $Theme -RuntimeContext $RuntimeContext
    }
    catch {
        Write-Status -Type warn -Label "Themes failed" -Detail $_.Exception.Message -Indent -RuntimeContext $RuntimeContext
    }
    finally {
        if (Test-Path $zip) { Remove-Item -Path $zip -Force -ErrorAction SilentlyContinue }
    }
}

function Update-ManagedOhMyPoshTheme {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Theme file writes are gated by higher-level install flows and tested separately.')]
    param(
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [string]$Theme = 'lightgreen',
        [psobject]$RuntimeContext
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

    $themeNames = @($effectiveTheme, 'lightgreen') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    foreach ($themeName in $themeNames) {
        $themePath = Join-Path $ThemesDir ("{0}.omp.json" -f $themeName)
        if (-not (Test-Path -LiteralPath $themePath -PathType Leaf)) {
            Write-Verbose "Managed theme patch skipped: $themePath not found"
            continue
        }

        $themeJson = Get-Content -Raw -Path $themePath | ConvertFrom-Json
        $promptBlock = $themeJson.blocks | Where-Object { $_.type -eq 'prompt' } | Select-Object -First 1
        $rpromptBlock = $themeJson.blocks | Where-Object { $_.type -eq 'rprompt' } | Select-Object -First 1

        if ($themeName -eq 'lightgreen' -and $promptBlock) {
            $pathSegment = $promptBlock.segments | Where-Object { $_.type -eq 'path' } | Select-Object -First 1
            if ($pathSegment) {
                $folderIcon = '<#A7F3D0>{0} </>' -f ([char]0xF07B)
                $folderSeparatorIcon = ' <#F4F1DE>{0}</> ' -f ([char]0xE0B1)
                $homeIcon = [string]([char]0xF015)
                $pathSegment.foreground = '#F4F1DE'
                $pathSegment.options = [pscustomobject]@{
                    style                 = 'agnoster_short'
                    max_depth             = 4
                    folder_icon           = $folderIcon
                    folder_separator_icon = $folderSeparatorIcon
                    home_icon             = $homeIcon
                }
                $pathSegment.template = ' {{ .Path }} '
            }
        }

        if ($rpromptBlock) {
            $rpromptBlock.segments = @($rpromptBlock.segments | Where-Object { $_.type -notin @('executiontime', 'sysinfo', 'battery', 'shell', 'time') })
            if (@($rpromptBlock.segments).Count -eq 0) {
                $themeJson.blocks = @($themeJson.blocks | Where-Object { $_.type -ne 'rprompt' })
            }
        }

        $themeContent = $themeJson | ConvertTo-Json -Depth 100
        Write-AtomicUtf8File -Path $themePath -Content $themeContent -RuntimeContext $RuntimeContext
    }
}

function Install-NerdFont {
    param([psobject]$RuntimeContext)

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    if ($RuntimeContext.DryRun) {
        Write-DryRun "Download and install CaskaydiaCove Nerd Font"
        return
    }

    $fontDirs = @(
        (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"),
        (Join-Path $env:WINDIR "Fonts")
    )
    $fontFileFound = $fontDirs | Where-Object { Test-Path $_ } | ForEach-Object {
        (Get-ChildItem -Path $_ -Filter "CascadiaCode*" -ErrorAction SilentlyContinue),
        (Get-ChildItem -Path $_ -Filter "CaskaydiaCove*" -ErrorAction SilentlyContinue)
    } | Where-Object { $_ -ne $null } | Select-Object -First 1

    if ($fontFileFound) {
        Write-Status -Type ok -Label "Nerd Font" -Detail "CaskaydiaCove already installed, skipping" -Indent -RuntimeContext $RuntimeContext
        return
    }

    $zip = Join-Path $env:TEMP "CascadiaCode-$([guid]::NewGuid().ToString().Split('-')[0]).zip"
    $dir = Join-Path $env:TEMP "CascadiaCode-$([guid]::NewGuid().ToString().Split('-')[0])"
    try {
        Write-Status -Type detail -Label "Downloading font" -Detail "ryanoasis/nerd-fonts" -Indent -RuntimeContext $RuntimeContext
        Invoke-WebRequest -Uri "https://github.com/ryanoasis/nerd-fonts/releases/latest/download/CascadiaCode.zip" -OutFile $zip -ErrorAction Stop
        Initialize-Directory -Path $dir
        Expand-Archive -Path $zip -DestinationPath $dir -Force -ErrorAction Stop

        Write-Status -Type detail -Label "Installing font" -Detail "copying to User and System Fonts (silent)" -Indent -RuntimeContext $RuntimeContext

        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $installLocations = @(
            @{ Scope = "User"; Dir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"; Reg = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" }
        )
        if ($isAdmin) {
            $installLocations += @{ Scope = "System"; Dir = Join-Path $env:WINDIR "Fonts"; Reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" }
        }

        foreach ($loc in $installLocations) {
            Initialize-Directory -Path $loc.Dir
        }

        Get-ChildItem -Path $dir -Include "*.ttf", "*.otf" -Recurse | ForEach-Object {
            $fontKeyName = $_.BaseName
            if ($_.Extension -eq ".ttf") { $fontKeyName += " (TrueType)" }
            if ($_.Extension -eq ".otf") { $fontKeyName += " (OpenType)" }

            foreach ($loc in $installLocations) {
                $targetPath = Join-Path $loc.Dir $_.Name
                Copy-Item -Path $_.FullName -Destination $targetPath -Force
                Set-ItemProperty -Path $loc.Reg -Name $fontKeyName -Value $targetPath -Force
            }
        }
    }
    catch {
        Write-Status -Type warn -Label "Font install failed" -Detail $_.Exception.Message -Indent -RuntimeContext $RuntimeContext
    }
    finally {
        if (Test-Path $zip) { Remove-Item -Path $zip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $dir) { Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Uninstall-NerdFont {
    param([psobject]$RuntimeContext)

    Write-Status -Type detail -Label "Uninstalling font" -Detail "removing CaskaydiaCove from User and System Fonts" -Indent -RuntimeContext $RuntimeContext
    $removedCount = 0

    $fontLocations = @(
        @{ Dir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"; Reg = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" },
        @{ Dir = Join-Path $env:WINDIR "Fonts"; Reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" }
    )

    foreach ($loc in $fontLocations) {
        if (Test-Path $loc.Reg) {
            $regProps = Get-ItemProperty -Path $loc.Reg -ErrorAction SilentlyContinue
            if ($regProps) {
                $matchingKeys = $regProps.PSObject.Properties | Where-Object { $_.Name -match "Cascadia|Caskaydia" } | ForEach-Object { $_.Name }
                foreach ($key in $matchingKeys) {
                    Remove-ItemProperty -Path $loc.Reg -Name $key -Force -ErrorAction SilentlyContinue
                    $removedCount++
                }
            }
        }

        if (Test-Path $loc.Dir) {
            $filesPath = Join-Path $loc.Dir "*Cas*.ttf"
            $otfPath = Join-Path $loc.Dir "*Cas*.otf"
            $fontFiles = @(Get-ChildItem -Path $filesPath -ErrorAction SilentlyContinue) + @(Get-ChildItem -Path $otfPath -ErrorAction SilentlyContinue)
            foreach ($f in $fontFiles) {
                if ($f.Name -match "CascadiaCode|CaskaydiaCove") {
                    Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
                    $removedCount++
                }
            }
        }
    }

    if ($removedCount -gt 0) {
        Write-Status -Type ok -Label "Nerd Font" -Detail "removed $removedCount font files/registry keys" -Indent -RuntimeContext $RuntimeContext
        return $true
    }
    else {
        Write-Status -Type info -Label "Nerd Font" -Detail "not found in User or System Fonts" -Indent -RuntimeContext $RuntimeContext
        return $false
    }
}

function Update-EditorAndTerminalFontConfig {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$SettingsPath,
        [psobject]$RuntimeContext
    )

    if (-not (Test-Path $SettingsPath)) {
        return $false
    }

    $fontFamily = "CaskaydiaCove NF"
    $editorDefault = "CaskaydiaCove NF, Consolas, 'Courier New', monospace"
    $content = Get-Content $SettingsPath -Raw
    $updated = $false
    $missingSettings = @()

    $editorPattern = '("editor\.fontFamily"\s*:\s*)"([^"]+)"'
    if ($content -match $editorPattern) {
        if ($Matches[2] -notmatch [regex]::Escape($fontFamily)) {
            $content = [regex]::Replace($content, $editorPattern, {
                    param($match)
                    return ('{0}"{1}, {2}"' -f $match.Groups[1].Value, $fontFamily, $match.Groups[2].Value)
                })
            $updated = $true
        }
    }
    else {
        $missingSettings += [pscustomobject]@{
            Key   = 'editor.fontFamily'
            Value = $editorDefault
        }
    }

    $terminalPattern = '("terminal\.integrated\.fontFamily"\s*:\s*)"([^"]+)"'
    if ($content -match $terminalPattern) {
        if ($Matches[2] -notmatch [regex]::Escape($fontFamily)) {
            $content = [regex]::Replace($content, $terminalPattern, {
                    param($match)
                    return ('{0}"{1}, {2}"' -f $match.Groups[1].Value, $fontFamily, $match.Groups[2].Value)
                })
            $updated = $true
        }
    }
    else {
        $missingSettings += [pscustomobject]@{
            Key   = 'terminal.integrated.fontFamily'
            Value = $fontFamily
        }
    }

    if ($missingSettings.Count -gt 0) {
        $insertionLines = @(
            $missingSettings | ForEach-Object {
                '    "{0}": "{1}",' -f $_.Key, $_.Value
            }
        )
        if ($content -match '^\{\s*') {
            $content = $content -replace '^\{\s*', "{`n$($insertionLines -join "`n")`n"
        }
        else {
            $content = ($insertionLines -join "`n") + "`n" + $content
        }
        $updated = $true
    }

    if ($updated) {
        Write-AtomicUtf8File -Path $SettingsPath -Content $content -RuntimeContext $RuntimeContext
    }

    return $updated
}

function Update-WindowsTerminalFontConfig {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Settings file writes are gated by higher-level install flows and tested separately.')]
    param(
        [Parameter(Mandatory = $true)][string]$SettingsPath,
        [psobject]$RuntimeContext
    )

    if (-not (Test-Path -LiteralPath $SettingsPath -PathType Leaf)) {
        return $false
    }

    $content = Get-Content -Path $SettingsPath -Raw
    if ($content -match '"face"\s*:\s*"CaskaydiaCove[^"]*"' -or $content -match '"fontFace"\s*:\s*"CaskaydiaCove[^"]*"') {
        return $false
    }

    if ($content -match '"defaults"\s*:\s*\{\s*\}') {
        $content = $content -replace '"defaults"\s*:\s*\{\s*\}', '"defaults": { "font": { "face": "CaskaydiaCove NF" } }'
    }
    elseif ($content -match '"defaults"\s*:\s*\{') {
        $content = $content -replace '("defaults"\s*:\s*\{)(\s*"[^"]+")', ('$1' + "`n            `"font`": { `"face`": `"CaskaydiaCove NF`" }," + '$2')
    }
    else {
        return $false
    }

    Write-AtomicUtf8File -Path $SettingsPath -Content $content -RuntimeContext $RuntimeContext
    return $true
}

function Set-TerminalFontConfig {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([psobject]$RuntimeContext)

    Write-Status -Type detail -Label "Configuring Editors" -Detail "injecting CaskaydiaCove NF into WT, VSCode, and Antigravity" -Indent -RuntimeContext $RuntimeContext

    $wtPaths = Get-ChildItem -Path "$env:LOCALAPPDATA\Packages" -Filter "Microsoft.WindowsTerminal*" -Directory -ErrorAction SilentlyContinue
    foreach ($wtDir in $wtPaths) {
        $wtSettings = Join-Path $wtDir.FullName "LocalState\settings.json"
        Update-WindowsTerminalFontConfig -SettingsPath $wtSettings -RuntimeContext $RuntimeContext | Out-Null
    }

    $vscodeSettingsDirs = @(
        (Join-Path $env:APPDATA "Code\User"),
        (Join-Path $env:APPDATA "Code - Insiders\User"),
        (Join-Path $env:APPDATA "Antigravity\User")
    )
    foreach ($dir in $vscodeSettingsDirs) {
        $vscodePath = Join-Path $dir "settings.json"
        Update-EditorAndTerminalFontConfig -SettingsPath $vscodePath -RuntimeContext $RuntimeContext | Out-Null
    }

    Write-Status -Type ok -Label "Configuration" -Detail "WT, VSCode, and Antigravity updated to use Nerd Font" -Indent -RuntimeContext $RuntimeContext
}

function Install-TerminalSetup {
    param(
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [string]$Theme = 'lightgreen',
        [psobject]$RuntimeContext
    )

    Write-Section "Terminal Setup" -RuntimeContext $RuntimeContext

    Save-TerminalThemeBundle -ThemesDir $ThemesDir -Theme $Theme -RuntimeContext $RuntimeContext
    Install-NerdFont -RuntimeContext $RuntimeContext
    Set-TerminalFontConfig -RuntimeContext $RuntimeContext
}

