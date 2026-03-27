
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

    $gitRoot = $null
    try {
        $gitRoot = Get-GitRoot
        Write-Status -Type detail -Label "Git discovered" -Detail $gitRoot
    }
    catch {
        if (-not $Uninstall -and -not $UninstallFont) { throw }
        Write-Status -Type info -Label "Git not found" -Detail "uninstall will clean known paths"
    }

    $gitUsrBin = $null
    $gitMingwBin = $null
    $gitCmd = $null
    $shimDir = $null
    $userShimRoot = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
    $userShimDir = Join-Path $userShimRoot "UnixTools\shims"
    if ($gitRoot) {
        $gitUsrBin = Join-Path $gitRoot "usr\bin"
        $gitMingwBin = Join-Path $gitRoot "mingw64\bin"
        $gitCmd = Join-Path $gitRoot "cmd"
        if ($script:PathScope -eq "User") {
            $shimDir = $userShimDir
        }
        else {
            $shimDir = Join-Path $gitRoot "shims"
        }
    }

    $didChange = $false

    if ($UninstallFont) {
        Write-Section "Uninstall Font"
        if (Uninstall-NerdFont) {
            $didChange = $true
            Send-EnvironmentChange
            Update-SessionPath
        }

        if (-not $Uninstall -and -not $InstallFull -and -not $CreateShims -and -not $AddMingw -and -not $AddGitCmd -and -not $NormalizePath -and -not $InstallProfileShims -and -not $InstallOptionalTools -and -not $InstallTerminalSetup) {
            Write-Footer -Message "Font uninstall complete" -Type ok
            return
        }
    }

    if ($Uninstall) {
        Write-Section "Uninstall"

        if ($script:PathScope -eq "User") {
            $candidateShimDirs = @($userShimDir)
            if ($shimDir) { $candidateShimDirs += $shimDir }
        }
        else {
            $candidateShimDirs = @(
                "C:\Program Files\Git\shims",
                "C:\Program Files (x86)\Git\shims"
            )
            if ($shimDir) { $candidateShimDirs += $shimDir }
        }
        $candidateShimDirs = $candidateShimDirs | Select-Object -Unique

        if ($PSCmdlet.ShouldProcess($PROFILE.CurrentUserCurrentHost, "Remove unix-tools profile shim blocks")) {
            $removalResult = Remove-InstalledProfileShims
            $didChange = $true
            $removalDetail = if ($removalResult.Status -eq 'Removed') { "unix-tools markers cleaned + legacy inline block removed" } else { "unix-tools markers cleaned" }
            Write-Status -Type ok -Label "Profile blocks removed" -Detail $removalDetail
        }

        $legacyFastScriptCandidates = @()
        if ($script:PathScope -eq "User") {
            if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
                $legacyFastScriptCandidates += (Join-Path $env:LOCALAPPDATA "UnixTools\Enable-UnixToolsFast.ps1")
            }
            if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
                $legacyFastScriptCandidates += (Join-Path $env:USERPROFILE "UnixTools\Enable-UnixToolsFast.ps1")
            }
        }
        else {
            if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
                $legacyFastScriptCandidates += (Join-Path $env:ProgramData "UnixToolsSystemWide\Enable-UnixToolsFast.ps1")
            }
        }
        foreach ($legacyFastPath in ($legacyFastScriptCandidates | Select-Object -Unique)) {
            if (-not (Test-Path -LiteralPath $legacyFastPath -PathType Leaf)) { continue }
            if ($PSCmdlet.ShouldProcess($legacyFastPath, "Remove legacy Enable-UnixToolsFast.ps1 copy")) {
                if ($script:DryRun) {
                    Write-DryRun "Remove-Item '$legacyFastPath' -Force"
                }
                else {
                    Remove-Item -LiteralPath $legacyFastPath -Force -ErrorAction SilentlyContinue
                    $legacyFastDir = Split-Path -Parent $legacyFastPath
                    if ($legacyFastDir -and (Test-Path -LiteralPath $legacyFastDir -PathType Container)) {
                        $remaining = Get-ChildItem -Path $legacyFastDir -Force -ErrorAction SilentlyContinue
                        if (-not $remaining) {
                            Remove-Item -LiteralPath $legacyFastDir -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                $didChange = $true
                Write-Status -Type ok -Label "Legacy script removed" -Detail (Split-Path $legacyFastPath -Leaf)
            }
        }

        foreach ($sd in $candidateShimDirs) {
            if ($PSCmdlet.ShouldProcess($script:PathDisplay, "Remove shim directory entry $sd")) {
                if (Remove-MachinePathEntries -pathsToRemove @($sd)) {
                    $didChange = $true
                    Write-Status -Type ok -Label "PATH entry removed" -Detail $sd
                }
            }
            if (Test-Path $sd -PathType Container) {
                if ($PSCmdlet.ShouldProcess($sd, "Delete generated .cmd shims")) {
                    if ($script:DryRun) {
                        Write-DryRun "Remove shim files from '$sd'"
                    }
                    else {
                        Get-ChildItem $sd -Filter *.cmd -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                        try {
                            Remove-Item $sd -Force -ErrorAction Stop
                        }
                        catch {
                            Write-Verbose "Shim directory not removed cleanly '$sd': $($_.Exception.Message)"
                        }
                    }
                    $didChange = $true
                    Write-Status -Type ok -Label "Shim files removed" -Detail $sd
                }
            }
        }

        if ($UninstallOptionalTools) {
            if ($PSCmdlet.ShouldProcess("Optional tools", "Uninstall optional tools previously installed by this script")) {
                $removedOptional = Uninstall-TrackedOptionalToolSet
                if ($removedOptional -gt 0) {
                    $didChange = $true
                    Write-Status -Type ok -Label "Optional items removed" -Detail "$removedOptional item(s)"
                }
                else {
                    Write-Status -Type info -Label "Optional tools" -Detail "none tracked"
                }
            }
        }
        else {
            Write-Status -Type info -Label "Optional tools" -Detail "preserved (use -UninstallOptionalTools to remove tracked items)"
        }

        if ($didChange) {
            Send-EnvironmentChange
            Update-SessionPath
            Write-Status -Type ok -Label "Environment refreshed" -Detail "WM_SETTINGCHANGE broadcasted"
        }
        else {
            Write-Status -Type info -Label "Nothing to uninstall"
        }

        Write-Footer -Message "Uninstall complete" -Type ok
        return
    }

    Write-Section "Path Configuration"

    $pathsToAdd = @($gitUsrBin)

    if ($AddMingw) {
        if (Test-Path $gitMingwBin) { $pathsToAdd += $gitMingwBin }
        else { Write-Status -Type info -Label "mingw64\bin" -Detail "not found, skipping" }
    }

    if ($AddGitCmd) {
        if (Test-Path $gitCmd) { $pathsToAdd += $gitCmd }
        else { Write-Status -Type info -Label "cmd" -Detail "not found, skipping" }
    }

    $changed = $false
    if ($PSCmdlet.ShouldProcess($script:PathDisplay, "Add tool directories")) {
        $changed = Add-MachinePathEntries $pathsToAdd
    }

    if ($changed) {
        $didChange = $true
        Write-Status -Type ok -Label "Tool directories added" -Detail "to $($script:PathDisplay)"
    }
    else {
        Write-Status -Type ok -Label "Tool directories" -Detail "already in $($script:PathDisplay)"
    }

    if ($NormalizePath) {
        if ($PSCmdlet.ShouldProcess($script:PathDisplay, "Normalize PATH entries")) {
            Update-MachinePathEntries
            $didChange = $true
            Write-Status -Type ok -Label "PATH normalized" -Detail "removed duplicates/trailing slashes"
        }
    }

    if ($InstallTerminalSetup) {
        if ($PSCmdlet.ShouldProcess("Terminal Setup", "Install Oh My Posh themes and Nerd Fonts")) {
            Install-TerminalSetup -ThemesDir $ThemesDir
            $didChange = $true
        }
    }

    $optionalToolCatalog = Get-OptionalToolCatalog
    $optionalModuleCatalog = Get-OptionalPowerShellModuleCatalog
    if ($InstallOptionalTools) {
        Write-Section "Optional Tools"
        if ($PSCmdlet.ShouldProcess("Optional tools", "Install missing optional tools via package managers")) {
            $presentBefore = @($optionalToolCatalog | Where-Object {
                    Test-OptionalToolAvailable -Tool $_
                } | ForEach-Object { Get-OptionalToolDisplayName -Tool $_ })
            $presentModulesBefore = @($optionalModuleCatalog | Where-Object {
                    $_.ModuleName -and (Get-Module -ListAvailable ([string]$_.ModuleName))
                } | ForEach-Object { [string]$_.ModuleName })

            $installedOptional = @(Install-MissingOptionalToolSet -Catalog $optionalToolCatalog)
            $installedOptionalModules = @(Install-MissingOptionalPowerShellModuleSet -Catalog $optionalModuleCatalog)
            Update-SessionPath

            $presentAfter = @($optionalToolCatalog | Where-Object {
                    Test-OptionalToolAvailable -Tool $_
                } | ForEach-Object { Get-OptionalToolDisplayName -Tool $_ })
            $missingAfter = @($optionalToolCatalog | Where-Object {
                    -not (Test-OptionalToolAvailable -Tool $_)
                } | ForEach-Object { Get-OptionalToolDisplayName -Tool $_ })
            $newlyDetected = @($presentAfter | Where-Object { $_ -notin $presentBefore })
            $alreadyPresent = @($presentBefore | Sort-Object -Unique)
            $presentAfter = @($presentAfter | Sort-Object -Unique)
            $missingAfter = @($missingAfter | Sort-Object -Unique)
            $presentModulesAfter = @($optionalModuleCatalog | Where-Object {
                    $_.ModuleName -and (Get-Module -ListAvailable ([string]$_.ModuleName))
                } | ForEach-Object { [string]$_.ModuleName })
            $missingModulesAfter = @($optionalModuleCatalog | Where-Object {
                    $_.ModuleName -and -not (Get-Module -ListAvailable ([string]$_.ModuleName))
                } | ForEach-Object { [string]$_.ModuleName })
            $newModulesDetected = @($presentModulesAfter | Where-Object { $_ -notin $presentModulesBefore })
            $alreadyPresentModules = @($presentModulesBefore | Sort-Object -Unique)
            $presentModulesAfter = @($presentModulesAfter | Sort-Object -Unique)
            $missingModulesAfter = @($missingModulesAfter | Sort-Object -Unique)

            if ($alreadyPresent.Count -gt 0) {
                Write-Status -Type ok -Label "$($alreadyPresent.Count) present before run" -Detail ($alreadyPresent -join ' ')
            }

            if ($newlyDetected.Count -gt 0) {
                Write-Status -Type ok -Label "$($newlyDetected.Count) present after install attempt" -Detail ($newlyDetected -join ' ')
            }

            if ($installedOptional.Count -gt 0) {
                $didChange = $true
                Write-Status -Type ok -Label "$($installedOptional.Count) newly installed"
            }

            if ($alreadyPresentModules.Count -gt 0) {
                Write-Status -Type ok -Label "$($alreadyPresentModules.Count) modules present" -Detail ($alreadyPresentModules -join ', ')
            }

            if ($newModulesDetected.Count -gt 0) {
                Write-Status -Type ok -Label "$($newModulesDetected.Count) modules present after install" -Detail ($newModulesDetected -join ', ')
            }

            if ($installedOptionalModules.Count -gt 0) {
                $didChange = $true
                Write-Status -Type ok -Label "$($installedOptionalModules.Count) modules newly installed"
            }

            if ($missingAfter.Count -gt 0) {
                Write-Status -Type warn -Label "$($missingAfter.Count) still missing" -Detail ($missingAfter -join ', ')
            }
            else {
                Write-Status -Type ok -Label "All optional tools available after run" -Detail ($presentAfter -join ' ')
            }

            if ($missingModulesAfter.Count -gt 0) {
                Write-Status -Type warn -Label "$($missingModulesAfter.Count) modules still missing" -Detail ($missingModulesAfter -join ', ')
            }
            else {
                Write-Status -Type ok -Label "All optional modules available after run" -Detail ($presentModulesAfter -join ', ')
            }
        }
        else {
            Write-Status -Type skip -Label "Optional tools" -Detail "skipped by -WhatIf/-Confirm"
        }
    }

    if ($CreateShims) {
        Write-Section "Shims"

        if ($PSCmdlet.ShouldProcess($shimDir, "Create/refresh shim .cmd files and prepend shim dir to $($script:PathDisplay)")) {
            New-DirectoryIfMissing $shimDir

            if ($script:DryRun) {
                Write-DryRun "Clear stale shims in '$shimDir'"
            }
            else {
                Get-ChildItem $shimDir -Filter *.cmd -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }

            $toolsToShim = Get-CoreShimToolCatalog
            $externalTools = @(
                $optionalToolCatalog |
                ForEach-Object { Get-OptionalToolCommandName -Tool $_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
            $searchDirs = @($gitUsrBin)
            if ($AddMingw -and (Test-Path $gitMingwBin)) { $searchDirs += $gitMingwBin }
            $appIndex = Get-ApplicationCommandIndex -excludeDir $shimDir

            $shimmed = 0
            $notFound = 0
            $notFoundTools = New-Object System.Collections.Generic.List[string]
            $externalFound = New-Object System.Collections.Generic.List[string]

            foreach ($tool in $toolsToShim) {
                $toolPath = Find-Tool -toolName $tool -searchDirs $searchDirs
                if (-not $toolPath) {
                    $toolPath = Find-ToolInPath -toolName $tool -excludeDir $shimDir -AppIndex $appIndex
                    if (-not $toolPath -and $tool -eq "nc") {
                        $toolPath = Find-ToolInPath -toolName "ncat" -excludeDir $shimDir -AppIndex $appIndex
                    }
                }
                if ($toolPath) {
                    if (Write-ShimCmd -shimDir $shimDir -name $tool -targetExePath $toolPath) { $shimmed++ }
                }
                else {
                    $notFound++
                    $notFoundTools.Add($tool) | Out-Null
                }
            }

            foreach ($tool in $externalTools) {
                $toolPath = Find-ToolInPath -toolName $tool -excludeDir $shimDir -AppIndex $appIndex
                if ($toolPath) {
                    if (Write-ShimCmd -shimDir $shimDir -name $tool -targetExePath $toolPath) {
                        $shimmed++
                        $externalFound.Add($tool) | Out-Null
                    }
                }
            }

            Add-MachinePathPrepend $shimDir

            if (-not $script:DryRun) {
                try {
                    if ($script:PathScope -eq "User") {
                        & icacls $shimDir /inheritance:r /grant "${env:USERNAME}:(OI)(CI)F" 2>&1 | Out-Null
                    }
                    else {
                        & icacls $shimDir /inheritance:r /grant "BUILTIN\Administrators:(OI)(CI)F" /grant "BUILTIN\Users:(OI)(CI)RX" 2>&1 | Out-Null
                    }
                    Write-Status -Type ok -Label "ACLs secured" -Detail "read-only for non-admins"
                }
                catch {
                    Write-Status -Type warn -Label "ACL warning" -Detail $_.Exception.Message
                }
            }
            else {
                Write-DryRun "icacls '$shimDir' /inheritance:r /grant ..."
            }

            $didChange = $true
            Write-Status -Type ok -Label "$shimmed shims created" -Detail $shimDir
            Write-Status -Type ok -Label "Shim dir prepended" -Detail "to $($script:PathDisplay) (priority)"

            if ($externalFound.Count -gt 0) {
                Write-Status -Type ok -Label "$($externalFound.Count) external tools" -Detail ($externalFound -join ' ')
            }

            if ($notFound -gt 0) {
                Write-Status -Type info -Label "$notFound tools not found" -Detail "(normal)"
                $missing = @($notFoundTools | Sort-Object -Unique)
                Write-CompactList -Items $missing
            }
        }
        else {
            Write-Status -Type skip -Label "Shims" -Detail "skipped by -WhatIf/-Confirm"
        }
    }

    if ($InstallProfileShims) {
        Write-Section "Profile"
        if ($PSCmdlet.ShouldProcess($PROFILE.CurrentUserCurrentHost, "Install/update unix-tools profile shim blocks")) {
            Install-ProfileInlineShims -ThemesDir $ThemesDir -Theme $Theme -StartupMode $ProfileStartupMode -PromptMode $PromptInitMode
            $profilePath = $PROFILE.CurrentUserCurrentHost
            $expectedHash = $null
            if (Test-Path $profilePath) {
                $expectedHash = (Get-FileHash -Path $profilePath -Algorithm SHA256).Hash
            }
            $isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            try {
                if (Test-Path $profilePath) {
                    if ($isElevated) {
                        Write-Status -Type warn -Label "Elevated session" -Detail "reload skipped (open new terminal)"
                    }
                    else {
                        $currentHash = (Get-FileHash -Path $profilePath -Algorithm SHA256).Hash
                        if ($expectedHash -and $currentHash -ne $expectedHash) {
                            Write-Status -Type warn -Label "Profile modified" -Detail "reload skipped for safety"
                        }
                        else {
                            . $profilePath
                            Write-Status -Type ok -Label "Profile reloaded" -Detail ". `$PROFILE"
                        }
                    }
                }
            }
            catch {
                Write-Status -Type warn -Label "Profile reload failed" -Detail $_.Exception.Message
            }
            Write-Status -Type ok -Label "Profile shims written" -Detail "managed loader + support files ($ProfileStartupMode / $PromptInitMode)"
            $didChange = $true
        }
        else {
            Write-Status -Type skip -Label "Profile shims" -Detail "skipped by -WhatIf/-Confirm"
        }
    }

    Write-Section "Environment"
    if ($didChange) {
        Send-EnvironmentChange
        Write-Status -Type ok -Label "WM_SETTINGCHANGE" -Detail "broadcasted"
    }
    else {
        Write-Status -Type info -Label "No changes" -Detail "nothing to broadcast"
    }

    Write-Section "Verification"
    Update-SessionPath

    $verifyTools = @("grep", "sed", "awk", "find", "bash")
    $verifyCommandCache = @{}
    foreach ($tool in $verifyTools) {
        $verifyCommandCache[$tool] = @(Get-Command $tool -All -ErrorAction SilentlyContinue)
    }

    foreach ($tool in $verifyTools) {
        $cmds = @($verifyCommandCache[$tool])
        if (-not $cmds) {
            Write-Status -Type fail -Label $tool -Detail "not found (open a NEW terminal)"
            continue
        }

        $ui = $script:UI
        $top = $cmds | Select-Object -First 3
        $lines = @()
        foreach ($c in $top) {
            $src = $c.Source
            if ($CreateShims -and $src -like "*\shims\*") {
                $shimContent = Get-Content $src -Raw -ErrorAction SilentlyContinue
                $target = $null
                if ($shimContent -match '"([^"]+\.exe)"') { $target = $matches[1] }
                if ($target) { $lines += "shim $($ui.Arrow) $(Split-Path $target -Leaf)" }
                else { $lines += "shim" }
            }
            elseif ($src -like "*\Git\*") {
                $lines += "Git $($ui.Arrow) $(Split-Path $src -Leaf)"
            }
            else {
                $lines += "$(Split-Path $src -Leaf)"
            }
        }

        Write-Status -Type ok -Label $tool -Detail ($lines -join " | ")
    }

    if ($InstallProfileShims) {
        $profilePath = $PROFILE.CurrentUserCurrentHost
        if ($script:DryRun) {
            Write-Status -Type info -Label "Profile blocks" -Detail "skipped in DryRun"
        }
        else {
            $profileState = Get-ProfileInstallationState -ProfilePath $profilePath

            if ($profileState.HasManagedBlocks) {
                Write-Status -Type ok -Label "Profile blocks" -Detail "present in `$PROFILE"
            }
            elseif ($profileState.HasMissingBlock -or $profileState.HasAliasBlock -or $profileState.HasSmartShellBlock) {
                Write-Status -Type warn -Label "Profile blocks" -Detail "partial install detected"
            }
            elseif ($profileState.HasLegacyFastBlock) {
                Write-Status -Type warn -Label "Profile blocks" -Detail "legacy fast-shim detected (re-run -InstallProfileShims)"
            }
            else {
                Write-Status -Type fail -Label "Profile blocks" -Detail "not found in `$PROFILE"
            }

            $legacyDetail = switch ($profileState.LegacyInlineStatus) {
                'Found' { 'present (cleanup still needed)' }
                'Ambiguous' { 'ambiguous signature detected (manual review needed)' }
                default { 'not detected' }
            }
            $startupModeDetail = if ([string]::IsNullOrWhiteSpace($profileState.StartupMode)) { 'Unknown' } else { $profileState.StartupMode }
            $promptModeDetail = if ([string]::IsNullOrWhiteSpace($profileState.PromptInitMode)) { 'Unknown' } else { $profileState.PromptInitMode }

            Write-Status -Type info -Label "Legacy inline shims" -Detail $legacyDetail
            Write-Status -Type info -Label "Startup mode" -Detail $startupModeDetail
            Write-Status -Type info -Label "Prompt init mode" -Detail $promptModeDetail
        }
    }

    Write-Footer -Message "Done $($ui.Arrow) open a new terminal to use tools" -Type ok

    $tryCommands = @("grep --version")
    if ($InstallProfileShims) { $tryCommands += @("ls -la", "'stressed' | rev") }
    if ($InstallOptionalTools) { $tryCommands += @("rg --version", "fd --version") }
    $tryLine = "  Try:  " + ($tryCommands -join " $([char]0x00B7) ")
    Write-Host $tryLine -ForegroundColor DarkCyan
    Write-Host ""

}
finally {
    if ($transcriptStarted) {
        Stop-ScriptTranscript
    }
}
