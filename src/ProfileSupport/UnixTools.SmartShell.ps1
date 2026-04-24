if ($Host.Name -eq 'ConsoleHost' -or $Host.Name -eq 'Visual Studio Code Host') {
    $profileConfig = Get-UnixToolsProfileConfig
    $script:UnixInteractiveFeaturesEnabled = $false
    $allowAntigravityFullPrompt = $false
    if (-not [string]::IsNullOrWhiteSpace($env:UNIXTOOLS_ALLOW_ANTIGRAVITY_FULL_PROMPT)) {
        $allowAntigravityFullPrompt = $env:UNIXTOOLS_ALLOW_ANTIGRAVITY_FULL_PROMPT -match '^(1|true|yes|on)$'
    }
    $isAntigravityAgentShell = $env:ANTIGRAVITY_CLI_ALIAS -and -not $allowAntigravityFullPrompt
    $winGetLinks = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links'
    if ((Test-Path -LiteralPath $winGetLinks) -and -not (($env:PATH -split ';') -contains $winGetLinks)) {
        $env:PATH = "$winGetLinks;$env:PATH"
    }

    foreach ($name in @('ls', 'cp', 'mv', 'rm', 'cat', 'sort', 'ssh')) {
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

    function Enable-UnixInteractiveFeatureSet {
        if ($script:UnixInteractiveFeaturesEnabled) {
            return
        }

        $isAgentShell = $env:CODEX_THREAD_ID -or $env:CODEX_INTERNAL_ORIGINATOR_OVERRIDE -or $isAntigravityAgentShell
        foreach ($module in @(
                'CompletionPredictor',
                'Microsoft.WinGet.CommandNotFound',
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

        $script:UnixInteractiveFeaturesEnabled = $true
    }

    if ($profileConfig -and $profileConfig.StartupMode -eq 'Legacy') {
        Enable-UnixInteractiveFeatureSet
    }

    Set-Alias -Name Enable-UnixInteractiveFeatures -Value Enable-UnixInteractiveFeatureSet -Scope Global -ErrorAction SilentlyContinue
}
