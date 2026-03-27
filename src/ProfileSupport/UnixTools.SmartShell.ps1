if ($Host.Name -eq 'ConsoleHost' -or $Host.Name -eq 'Visual Studio Code Host') {
    $script:SmartShellExeCache = @{}
    $script:UnixInteractiveFeaturesEnabled = $false
    $winGetLinks = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links'
    $winGetPackages = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
    if ((Test-Path -LiteralPath $winGetLinks) -and -not (($env:PATH -split ';') -contains $winGetLinks)) {
        $env:PATH = "$winGetLinks;$env:PATH"
    }

    function Resolve-SmartShellExecutable {
        param(
            [Parameter(Mandatory = $true)]
            [string[]]$Candidates,
            [switch]$AllowPackageScan
        )

        foreach ($candidate in $Candidates) {
            $cacheKey = "{0}:{1}" -f $candidate.ToLowerInvariant(), $AllowPackageScan.ToString().ToLowerInvariant()
            if ($script:SmartShellExeCache.ContainsKey($cacheKey)) {
                $cached = $script:SmartShellExeCache[$cacheKey]
                if ($cached) { return $cached }
                continue
            }

            $cmd = Get-PreferredApplicationCommand -Name $candidate
            if ($cmd) {
                $script:SmartShellExeCache[$cacheKey] = $cmd.Source
                return $cmd.Source
            }

            foreach ($dir in @($winGetLinks, 'C:\Program Files\Git\shims')) {
                if (-not [string]::IsNullOrWhiteSpace($dir)) {
                    $path = Join-Path $dir $candidate
                    if (Test-Path -LiteralPath $path -PathType Leaf) {
                        $script:SmartShellExeCache[$cacheKey] = $path
                        return $path
                    }
                }
            }

            if ($AllowPackageScan -and (Test-Path -LiteralPath $winGetPackages)) {
                $pkgPath = Get-ChildItem -Path $winGetPackages -Recurse -Filter $candidate -File -ErrorAction SilentlyContinue |
                Select-Object -First 1 -ExpandProperty FullName
                if ($pkgPath) {
                    $script:SmartShellExeCache[$cacheKey] = $pkgPath
                    return $pkgPath
                }
            }

            $script:SmartShellExeCache[$cacheKey] = $null
        }
    }

    function Enable-UnixInteractiveFeatureSet {
        if ($script:UnixInteractiveFeaturesEnabled) {
            return
        }

        $isAgentShell = $env:CODEX_THREAD_ID -or $env:CODEX_INTERNAL_ORIGINATOR_OVERRIDE -or $env:ANTIGRAVITY_CLI_ALIAS
        foreach ($module in @(
                'CompletionPredictor',
                'Microsoft.WinGet.CommandNotFound',
                'PSFzf',
                'ZLocation',
                'posh-git',
                'Terminal-Icons',
                'powershell-yaml'
            )) {
            if ($isAgentShell -and $module -eq 'Terminal-Icons') {
                continue
            }
            if (Get-Module -ListAvailable $module) {
                Import-Module $module -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null 3>$null | Out-Null
            }
        }

        if (Get-Module PSReadLine -ErrorAction SilentlyContinue) {
            if (-not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) {
                try {
                    $predictionSource = if (Get-Module CompletionPredictor -ErrorAction SilentlyContinue) { 'HistoryAndPlugin' } else { 'History' }
                    Set-PSReadLineOption -PredictionSource $predictionSource
                    Set-PSReadLineOption -PredictionViewStyle InlineView
                }
                catch {
                    Write-Verbose "PSReadLine interactive features unavailable: $($_.Exception.Message)"
                }
            }
        }

        if (Get-Command Set-PsFzfOption -ErrorAction SilentlyContinue) {
            Set-PsFzfOption -EnableAliasFuzzyZLocation:$true -AltCCommand { Invoke-FuzzyZLocation }
        }

        $script:UnixInteractiveFeaturesEnabled = $true
    }

    if (Get-Module -ListAvailable PSReadLine) {
        if (-not (Get-Module PSReadLine -ErrorAction SilentlyContinue)) {
            Import-Module PSReadLine -ErrorAction SilentlyContinue
        }
        if (-not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) {
            try {
                Set-PSReadLineOption -PredictionSource History
                Set-PSReadLineOption -PredictionViewStyle InlineView
            }
            catch {
                Write-Verbose "PSReadLine prediction setup unavailable: $($_.Exception.Message)"
            }
        }
    }

    if ($script:UnixToolsProfileConfig.StartupMode -eq 'Legacy') {
        Enable-UnixInteractiveFeatureSet
    }

    Set-Alias -Name Enable-UnixInteractiveFeatures -Value Enable-UnixInteractiveFeatureSet -Scope Global -ErrorAction SilentlyContinue

    $zoxideExe = Resolve-SmartShellExecutable -Candidates @('zoxide.exe', 'zoxide.cmd')
    if ($zoxideExe) {
        & ([scriptblock]::Create((& $zoxideExe init powershell --cmd j | Out-String)))
    }

    function global:y {
        $yaziExe = Resolve-SmartShellExecutable -Candidates @('yazi.exe', 'ya.exe', 'yazi.cmd', 'ya.cmd') -AllowPackageScan
        if (-not $yaziExe) {
            throw 'yazi is not available on PATH. Re-run setup with -InstallOptionalTools or restart PowerShell.'
        }

        $tmp = (New-TemporaryFile).FullName
        try {
            & $yaziExe @args --cwd-file="$tmp"
            if (Test-Path -LiteralPath $tmp) {
                $cwd = Get-Content -Path $tmp -Encoding UTF8 -ErrorAction SilentlyContinue
                if ($cwd -and $cwd -ne $PWD.Path -and (Test-Path -LiteralPath $cwd -PathType Container)) {
                    Set-Location -LiteralPath (Resolve-Path -LiteralPath $cwd).Path
                }
            }
        }
        finally {
            Remove-Item -Path $tmp -ErrorAction SilentlyContinue
        }
    }

    function global:lg {
        $lazygitExe = Resolve-SmartShellExecutable -Candidates @('lazygit.exe', 'lazygit.cmd') -AllowPackageScan
        if (-not $lazygitExe) {
            throw 'lazygit is not available on PATH. Re-run setup with -InstallOptionalTools.'
        }

        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("lazygit-cwd-{0}.txt" -f [guid]::NewGuid())
        try {
            $env:LAZYGIT_NEW_DIR_FILE = $tmp
            & $lazygitExe @args
            if (Test-Path -LiteralPath $tmp) {
                $cwd = (Get-Content -Path $tmp -Encoding UTF8 -ErrorAction SilentlyContinue | Select-Object -First 1)
                if ($cwd -and $cwd -ne $PWD.Path -and (Test-Path -LiteralPath $cwd -PathType Container)) {
                    Set-Location -LiteralPath (Resolve-Path -LiteralPath $cwd).Path
                }
            }
        }
        finally {
            Remove-Item env:LAZYGIT_NEW_DIR_FILE -ErrorAction SilentlyContinue
            Remove-Item -Path $tmp -ErrorAction SilentlyContinue
        }
    }
}
