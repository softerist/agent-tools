param([psobject]$runtimeContext)

if ($Help) {
    Get-Help $runtimeContext.HelpPath -Detailed
    return
}

if ($InstallFull -and $Uninstall) {
    throw "Cannot combine -InstallFull with -Uninstall. Choose one mode."
}
if ($Uninstall -and ($AddMingw -or $AddGitCmd -or $InstallOptionalTools -or $InstallTerminalSetup -or $InstallFull -or $UninstallFont)) {
    throw "Cannot combine -Uninstall with install switches. Use -Uninstall alone."
}
if ($UninstallOptionalTools -and -not $Uninstall) {
    throw "-UninstallOptionalTools requires -Uninstall."
}

if ($InstallFull) {
    $AddMingw = $true
    $AddGitCmd = $true
    $NormalizePath = $true
    $InstallOptionalTools = $true
    $InstallTerminalSetup = $true
}

$transcriptStarted = Start-ScriptTranscript -Path $LogPath -RuntimeContext $runtimeContext
try {
    if (-not $ThemesDir) {
        $base = if ($runtimeContext.PathScope -eq 'User') {
            if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
        }
        else {
            $env:ProgramData
        }
        $ThemesDir = Join-Path $base 'oh-my-posh-themes\themes'
    }

    $installMode = if ($InstallFull) { 'Full install' } elseif ($Uninstall -or $UninstallFont) { 'Uninstall' } else { 'Custom' }
    Write-Header -Mode $installMode -RuntimeContext $runtimeContext

    if (-not (Assert-Admin -RuntimeContext $runtimeContext)) {
        return
    }

    if (-not $runtimeContext.DryRun) {
        Backup-PathVariable -RuntimeContext $runtimeContext
    }

    $executionState = [pscustomobject]@{
        DidChange = $false
    }
    $hasAdditionalActions = $Uninstall -or $InstallFull -or $AddMingw -or $AddGitCmd -or $NormalizePath -or $InstallOptionalTools -or $InstallTerminalSetup
    $context = Get-ExecutionContext -AllowMissingGit:($Uninstall -or $UninstallFont) -RuntimeContext $runtimeContext

    if ($UninstallFont) {
        $fontOnlyHandled = Invoke-FontUninstallFlow -State $executionState -HasAdditionalActions:$hasAdditionalActions -RuntimeContext $runtimeContext
        if ($fontOnlyHandled) {
            return
        }
    }

    if ($Uninstall) {
        Invoke-UninstallFlow -Cmdlet $PSCmdlet -State $executionState -Context $context -UninstallOptionalTools:$UninstallOptionalTools -RuntimeContext $runtimeContext
        return
    }

    Invoke-PathConfigurationFlow -Cmdlet $PSCmdlet -State $executionState -Context $context -AddMingw:$AddMingw -AddGitCmd:$AddGitCmd -NormalizePath:$NormalizePath -InstallTerminalSetup:$InstallTerminalSetup -ThemesDir $ThemesDir -Theme $Theme -RuntimeContext $runtimeContext
    Invoke-ProfileSetupFlow -Cmdlet $PSCmdlet -State $executionState -InstallFull:$InstallFull -ThemesDir $ThemesDir -Theme $Theme -ProfileStartupMode $ProfileStartupMode -PromptInitMode $PromptInitMode -RuntimeContext $runtimeContext
    Invoke-ShimCleanupFlow -Cmdlet $PSCmdlet -State $executionState -Context $context -RuntimeContext $runtimeContext
    Invoke-OptionalToolFlow -Cmdlet $PSCmdlet -State $executionState -Context $context -InstallOptionalTools:$InstallOptionalTools -RuntimeContext $runtimeContext
    Invoke-VerificationFlow -State $executionState -InstallOptionalTools:$InstallOptionalTools -RuntimeContext $runtimeContext
}
finally {
    if ($transcriptStarted) {
        Stop-ScriptTranscript
    }
}
