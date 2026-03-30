$profileConfig = Get-UnixToolsProfileConfig

function Invoke-UnixToolsCachedOhMyPoshInit {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    $profileConfig = Get-UnixToolsProfileConfig
    if (-not $profileConfig -or [string]::IsNullOrWhiteSpace($profileConfig.SupportRoot)) {
        & ([scriptblock]::Create((oh-my-posh init pwsh --config "$ConfigPath" | Out-String)))
        return
    }

    $ohMyPoshCommand = Get-Command oh-my-posh -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ohMyPoshCommand) {
        return
    }

    $cachePath = Join-Path $profileConfig.SupportRoot 'UnixTools.OhMyPosh.Init.ps1'
    $exePath = [string]$ohMyPoshCommand.Source
    $exeStamp = Get-UnixToolsFileStamp -Path $exePath
    $configStamp = Get-UnixToolsFileStamp -Path $ConfigPath
    $metadata = Get-UnixToolsCacheHeader -Path $cachePath
    $cachedInitPath = if ($metadata) { [string]$metadata['InitPath'] } else { '' }

    $canUseCache = $metadata -and
        $metadata['Kind'] -eq 'OhMyPosh' -and
        $metadata['ExePath'] -eq $exePath -and
        $metadata['ExeStamp'] -eq $exeStamp -and
        $metadata['ConfigPath'] -eq $ConfigPath -and
        $metadata['ConfigStamp'] -eq $configStamp -and
        -not [string]::IsNullOrWhiteSpace($cachedInitPath) -and
        (Test-Path -LiteralPath $cachedInitPath -PathType Leaf)

    if ($canUseCache) {
        . $cachePath
        return
    }

    $generated = oh-my-posh init pwsh --config "$ConfigPath" | Out-String
    $match = [regex]::Match($generated, "&\s+'([^']+)'")
    if ($match.Success) {
        $initPath = $match.Groups[1].Value
        if (Test-Path -LiteralPath $initPath -PathType Leaf) {
            $escapedExePath = $exePath.Replace("'", "''")
            $escapedConfigPath = $ConfigPath.Replace("'", "''")
            $escapedInitPath = $initPath.Replace("'", "''")
            $cacheContent = @(
                '# Kind: OhMyPosh'
                "# ExePath: $escapedExePath"
                "# ExeStamp: $exeStamp"
                "# ConfigPath: $escapedConfigPath"
                "# ConfigStamp: $configStamp"
                "# InitPath: $escapedInitPath"
                '$env:POSH_SESSION_ID = [guid]::NewGuid().Guid'
                "& '$escapedInitPath'"
                ''
            ) -join "`n"

            if (Write-UnixToolsCacheFile -Path $cachePath -Content $cacheContent) {
                . $cachePath
                return
            }
        }
    }

    & ([scriptblock]::Create($generated))
}

function Invoke-UnixToolsDeferredInteractivePrompt {
    if (-not (Get-Command Enable-UnixInteractiveFeatureSet -ErrorAction SilentlyContinue)) {
        return
    }

    $currentPrompt = Get-Command prompt -CommandType Function -ErrorAction SilentlyContinue
    if (-not $currentPrompt) {
        return
    }

    $basePrompt = $currentPrompt.ScriptBlock
    $script:UnixToolsDeferredInteractiveState = 'Pending'

    $wrapper = {
        if ($script:UnixToolsDeferredInteractiveState -eq 'Pending') {
            $script:UnixToolsDeferredInteractiveState = 'Warmup'
            return & $basePrompt
        }

        if ($script:UnixToolsDeferredInteractiveState -eq 'Warmup') {
            $script:UnixToolsDeferredInteractiveState = 'Loaded'
            try {
                Enable-UnixInteractiveFeatureSet
            }
            catch {
                Write-Verbose "Deferred interactive feature setup failed: $($_.Exception.Message)"
            }

            $activePrompt = Get-Command prompt -CommandType Function -ErrorAction SilentlyContinue
            if ($activePrompt -and $activePrompt.ScriptBlock -ne $MyInvocation.MyCommand.ScriptBlock) {
                return & $activePrompt.ScriptBlock
            }
        }

        return & $basePrompt
    }.GetNewClosure()

    Set-Item -Path Function:\Global:prompt -Value $wrapper
}

if ($profileConfig -and -not $env:CODEX_THREAD_ID -and -not $env:CODEX_INTERNAL_ORIGINATOR_OVERRIDE -and -not $env:ANTIGRAVITY_CLI_ALIAS -and (Get-Command oh-my-posh -ErrorAction SilentlyContinue)) {
    $theme = if ([string]::IsNullOrWhiteSpace($profileConfig.Theme)) { 'lightgreen' } else { $profileConfig.Theme }
    $themesDir = $profileConfig.ThemesDir

    $configPath = $null
    if (-not [string]::IsNullOrWhiteSpace($themesDir)) {
        $requestedPath = Join-Path $themesDir ("{0}.omp.json" -f $theme)
        if (Test-Path -LiteralPath $requestedPath -PathType Leaf) {
            $configPath = $requestedPath
        }
        else {
            foreach ($fallbackTheme in @('lightgreen', 'pure', 'jandedobbeleer')) {
                $fallbackPath = Join-Path $themesDir ("{0}.omp.json" -f $fallbackTheme)
                if (Test-Path -LiteralPath $fallbackPath -PathType Leaf) {
                    $configPath = $fallbackPath
                    break
                }
            }
        }
    }

    if ($configPath) {
        switch ($profileConfig.PromptInitMode) {
            'Eager' {
                $loadInteractiveFeaturesNow = $profileConfig.StartupMode -eq 'Legacy'
                if ($loadInteractiveFeaturesNow -and (Get-Command Enable-UnixInteractiveFeatureSet -ErrorAction SilentlyContinue)) {
                    Enable-UnixInteractiveFeatureSet
                }
                Invoke-UnixToolsCachedOhMyPoshInit -ConfigPath $configPath
                if (-not $loadInteractiveFeaturesNow) {
                    Invoke-UnixToolsDeferredInteractivePrompt
                }
            }
            'Lazy' {
                $script:UnixToolsPromptState = 'Pending'
                $script:UnixToolsPromptWarningShown = $false

                function global:Get-UnixToolsMinimalPrompt {
                    return "PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) "
                }

                function global:Initialize-UnixToolsPrompt {
                    if ($script:UnixToolsPromptState -eq 'Loaded') { return $true }
                    if ($script:UnixToolsPromptState -eq 'Failed') { return $false }

                    try {
                        $loadInteractiveFeaturesNow = $profileConfig.StartupMode -eq 'Legacy'
                        if ($loadInteractiveFeaturesNow -and (Get-Command Enable-UnixInteractiveFeatureSet -ErrorAction SilentlyContinue)) {
                            Enable-UnixInteractiveFeatureSet
                        }
                        Invoke-UnixToolsCachedOhMyPoshInit -ConfigPath $configPath
                        if (-not $loadInteractiveFeaturesNow) {
                            Invoke-UnixToolsDeferredInteractivePrompt
                        }
                        $script:UnixToolsPromptState = 'Loaded'
                        return $true
                    }
                    catch {
                        $script:UnixToolsPromptState = 'Failed'
                        if (-not $script:UnixToolsPromptWarningShown) {
                            Write-Warning "oh-my-posh init failed: $($_.Exception.Message)"
                            $script:UnixToolsPromptWarningShown = $true
                        }
                        return $false
                    }
                }

                function global:prompt {
                    if ($script:UnixToolsPromptState -eq 'Pending') {
                        $script:UnixToolsPromptState = 'Warmup'
                        return Get-UnixToolsMinimalPrompt
                    }

                    if ($script:UnixToolsPromptState -eq 'Warmup') {
                        if (Initialize-UnixToolsPrompt) {
                            $currentPrompt = Get-Command prompt -CommandType Function -ErrorAction SilentlyContinue
                            if ($currentPrompt -and $currentPrompt.ScriptBlock -ne $MyInvocation.MyCommand.ScriptBlock) {
                                return & $currentPrompt.ScriptBlock
                            }
                        }
                    }

                    return Get-UnixToolsMinimalPrompt
                }
            }
        }
    }
}
