
if ($Help) {
    Get-Help $script:EnableUnixToolsHelpPath -Detailed
    return
}

if ($InstallFull -and $Uninstall) {
    throw "Cannot combine -InstallFull with -Uninstall. Choose one mode."
}
if ($Uninstall -and ($CreateShims -or $AddMingw -or $AddGitCmd -or $InstallProfileShims -or $InstallOptionalTools -or $InstallTerminalSetup -or $InstallFull -or $UninstallFont)) {
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
    $CreateShims = $true
    $InstallProfileShims = $true
}

$transcriptStarted = Start-ScriptTranscript -Path $LogPath
try {
    if (-not $ThemesDir) {
        $base = if ($script:PathScope -eq "User") {
            if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
        }
        else {
            $env:ProgramData
        }
        $ThemesDir = Join-Path $base "oh-my-posh-themes\themes"
    }

    $installMode = if ($InstallFull) { "Full install" } elseif ($Uninstall -or $UninstallFont) { "Uninstall" } else { "Custom" }
    Write-Header -Mode $installMode

    if (-not (Assert-Admin)) {
        return
    }

    if (-not $script:DryRun) {
        Backup-PathVariable -Scope $script:PathScope
    }

    $executionState = [pscustomobject]@{
        DidChange = $false
    }
    $hasAdditionalActions = $Uninstall -or $InstallFull -or $CreateShims -or $AddMingw -or $AddGitCmd -or $NormalizePath -or $InstallProfileShims -or $InstallOptionalTools -or $InstallTerminalSetup
    $context = Get-ExecutionContext -AllowMissingGit:($Uninstall -or $UninstallFont)

    if ($UninstallFont) {
        $fontOnlyHandled = Invoke-FontUninstallFlow -State $executionState -HasAdditionalActions:$hasAdditionalActions
        if ($fontOnlyHandled) {
            return
        }
    }

    if ($Uninstall) {
        Invoke-UninstallFlow -Cmdlet $PSCmdlet -State $executionState -Context $context -UninstallOptionalTools:$UninstallOptionalTools
        return
    }

    Invoke-PathConfigurationFlow -Cmdlet $PSCmdlet -State $executionState -Context $context -AddMingw:$AddMingw -AddGitCmd:$AddGitCmd -NormalizePath:$NormalizePath -InstallTerminalSetup:$InstallTerminalSetup -ThemesDir $ThemesDir
    Invoke-OptionalToolFlow -Cmdlet $PSCmdlet -State $executionState -Context $context -InstallOptionalTools:$InstallOptionalTools
    Invoke-ShimFlow -Cmdlet $PSCmdlet -State $executionState -Context $context -CreateShims:$CreateShims -AddMingw:$AddMingw
    Invoke-ProfileSetupFlow -Cmdlet $PSCmdlet -State $executionState -InstallProfileShims:$InstallProfileShims -ThemesDir $ThemesDir -Theme $Theme -ProfileStartupMode $ProfileStartupMode -PromptInitMode $PromptInitMode
    Invoke-VerificationFlow -State $executionState -CreateShims:$CreateShims -InstallProfileShims:$InstallProfileShims -InstallOptionalTools:$InstallOptionalTools
}
finally {
    if ($transcriptStarted) {
        Stop-ScriptTranscript
    }
}
