if (-not $env:CODEX_THREAD_ID -and -not $env:CODEX_INTERNAL_ORIGINATOR_OVERRIDE -and -not $env:ANTIGRAVITY_CLI_ALIAS -and (Get-Command oh-my-posh -ErrorAction SilentlyContinue)) {
    $theme = if ([string]::IsNullOrWhiteSpace($script:UnixToolsProfileConfig.Theme)) { 'lightgreen' } else { $script:UnixToolsProfileConfig.Theme }
    $themesDir = $script:UnixToolsProfileConfig.ThemesDir

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
        switch ($script:UnixToolsProfileConfig.PromptInitMode) {
            'Eager' {
                if (Get-Command Enable-UnixInteractiveFeatureSet -ErrorAction SilentlyContinue) {
                    Enable-UnixInteractiveFeatureSet
                }
                & ([scriptblock]::Create((oh-my-posh init pwsh --config "$configPath" | Out-String)))
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
                        if (Get-Command Enable-UnixInteractiveFeatureSet -ErrorAction SilentlyContinue) {
                            Enable-UnixInteractiveFeatureSet
                        }
                        & ([scriptblock]::Create((oh-my-posh init pwsh --config "$configPath" | Out-String)))
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
