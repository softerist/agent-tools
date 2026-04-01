if ($Host.Name -eq 'ConsoleHost' -or $Host.Name -eq 'Visual Studio Code Host') {
    $profileConfig = Get-UnixToolsProfileConfig
    $script:SmartShellExeCache = @{}
    $script:UnixInteractiveFeaturesEnabled = $false
    $script:UnixToolsZoxideInitialized = $false
    $allowAntigravityFullPrompt = $false
    if (-not [string]::IsNullOrWhiteSpace($env:UNIXTOOLS_ALLOW_ANTIGRAVITY_FULL_PROMPT)) {
        $allowAntigravityFullPrompt = $env:UNIXTOOLS_ALLOW_ANTIGRAVITY_FULL_PROMPT -match '^(1|true|yes|on)$'
    }
    $isAntigravityAgentShell = $env:ANTIGRAVITY_CLI_ALIAS -and -not $allowAntigravityFullPrompt
    $winGetLinks = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links'
    $winGetPackages = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
    if ((Test-Path -LiteralPath $winGetLinks) -and -not (($env:PATH -split ';') -contains $winGetLinks)) {
        $env:PATH = "$winGetLinks;$env:PATH"
    }

    foreach ($name in @('ls', 'cp', 'mv', 'rm', 'cat', 'sort')) {
        Reset-UnixShimName -Name $name

        $commandName = $name
        $wrapper = {
            $app = $null
            $invocationArgs = @($args)

            if ($commandName -eq 'ls') {
                $ezaCommand = Get-PreferredApplicationCommand -Name 'eza'
                if ($ezaCommand) {
                    $app = $ezaCommand
                    $translatedArgs = New-Object System.Collections.Generic.List[object]
                    $parseOptions = $true
                    foreach ($argument in $invocationArgs) {
                        if ($parseOptions -and $argument -eq '--') {
                            $parseOptions = $false
                            $translatedArgs.Add($argument) | Out-Null
                            continue
                        }

                        if ($parseOptions -and $argument -is [string] -and $argument -match '^-[A-Za-z]+$') {
                            foreach ($flag in $argument.Substring(1).ToCharArray()) {
                                if ($flag -eq 'f') {
                                    $translatedArgs.Add('-a') | Out-Null
                                    $translatedArgs.Add('-s') | Out-Null
                                    $translatedArgs.Add('none') | Out-Null
                                }
                                else {
                                    $translatedArgs.Add('-' + $flag) | Out-Null
                                }
                            }
                            continue
                        }

                        $translatedArgs.Add($argument) | Out-Null
                    }

                    $invocationArgs = $translatedArgs.ToArray()
                }
            }

            if (-not $app) {
                $app = Get-PreferredApplicationCommand -Name $commandName
            }

            if (-not $app) {
                throw "unix-tools: '$commandName' executable not found on PATH. Install the real tool and open a new terminal."
            }

            if ($MyInvocation.ExpectingInput) {
                $input | & $app.Source @invocationArgs
            }
            else {
                & $app.Source @invocationArgs
            }
        }.GetNewClosure()

        Set-Item -Path ("Function:\Global:" + $name) -Value $wrapper
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

    function Invoke-UnixToolsCachedZoxideInit {
        param([Parameter(Mandatory = $true)][string]$ExecutablePath)

        if (-not $profileConfig -or [string]::IsNullOrWhiteSpace($profileConfig.SupportRoot)) {
            & ([scriptblock]::Create((& $ExecutablePath init powershell --cmd j | Out-String)))
            return
        }

        $cachePath = Join-Path $profileConfig.SupportRoot 'UnixTools.Zoxide.Init.ps1'
        $exeStamp = Get-UnixToolsFileStamp -Path $ExecutablePath
        $metadata = Get-UnixToolsCacheHeader -Path $cachePath
        $canUseCache = $metadata -and
            $metadata['Kind'] -eq 'Zoxide' -and
            $metadata['ExePath'] -eq $ExecutablePath -and
            $metadata['ExeStamp'] -eq $exeStamp

        if ($canUseCache) {
            . $cachePath
            return
        }

        $generated = & $ExecutablePath init powershell --cmd j | Out-String
        $escapedExecutablePath = $ExecutablePath.Replace("'", "''")
        $cacheContent = @(
            '# Kind: Zoxide'
            "# ExePath: $escapedExecutablePath"
            "# ExeStamp: $exeStamp"
            $generated
            ''
        ) -join "`n"

        if (Write-UnixToolsCacheFile -Path $cachePath -Content $cacheContent) {
            . $cachePath
            return
        }

        & ([scriptblock]::Create($generated))
    }

    function Initialize-UnixToolsPsReadLineState {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param()

        if (-not $PSCmdlet.ShouldProcess('PSReadLine session', 'Initialize unix-tools defaults')) {
            return
        }

        if (-not (Get-Module -ListAvailable PSReadLine)) {
            return
        }

        if (-not (Get-Module PSReadLine -ErrorAction SilentlyContinue)) {
            Import-Module PSReadLine -ErrorAction SilentlyContinue
        }

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

    function Initialize-UnixToolsZoxideSupport {
        if ($script:UnixToolsZoxideInitialized) {
            return $true
        }

        $zoxideExe = Resolve-SmartShellExecutable -Candidates @('zoxide.exe', 'zoxide.cmd')
        if (-not $zoxideExe) {
            return $false
        }

        Remove-Item -Path Function:\Global:j -ErrorAction SilentlyContinue
        Remove-Item -Path Function:\Global:ji -ErrorAction SilentlyContinue

        Invoke-UnixToolsCachedZoxideInit -ExecutablePath $zoxideExe
        $script:UnixToolsZoxideInitialized = $true
        return $true
    }

    function Invoke-UnixToolsDeferredZoxideCommand {
        param(
            [Parameter(Mandatory = $true)][ValidateSet('j', 'ji')][string]$Name,
            [Parameter(ValueFromRemainingArguments = $true)][object[]]$RemainingArgs
        )

        if (-not (Initialize-UnixToolsZoxideSupport)) {
            throw 'zoxide is not available on PATH. Re-run setup with -InstallOptionalTools or restart PowerShell.'
        }

        & $Name @RemainingArgs
    }

    function Enable-UnixInteractiveFeatureSet {
        if ($script:UnixInteractiveFeaturesEnabled) {
            return
        }

        $isAgentShell = $env:CODEX_THREAD_ID -or $env:CODEX_INTERNAL_ORIGINATOR_OVERRIDE -or $isAntigravityAgentShell
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

        Initialize-UnixToolsPsReadLineState

        if (Get-Command Set-PsFzfOption -ErrorAction SilentlyContinue) {
            Set-PsFzfOption -EnableAliasFuzzyZLocation:$true -AltCCommand { Invoke-FuzzyZLocation }
        }

        $script:UnixInteractiveFeaturesEnabled = $true
    }

    if ($profileConfig -and $profileConfig.StartupMode -eq 'Legacy') {
        Enable-UnixInteractiveFeatureSet
        Initialize-UnixToolsZoxideSupport | Out-Null
    }
    else {
        function global:j {
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$RemainingArgs)
            Invoke-UnixToolsDeferredZoxideCommand -Name 'j' @RemainingArgs
        }

        function global:ji {
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$RemainingArgs)
            Invoke-UnixToolsDeferredZoxideCommand -Name 'ji' @RemainingArgs
        }
    }

    Set-Alias -Name Enable-UnixInteractiveFeatures -Value Enable-UnixInteractiveFeatureSet -Scope Global -ErrorAction SilentlyContinue

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
