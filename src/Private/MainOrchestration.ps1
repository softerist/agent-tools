function Get-ExecutionContext {
    param(
        [switch]$AllowMissingGit,
        [psobject]$RuntimeContext
    )

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext

    $gitRoot = $null
    try {
        $gitRoot = Get-GitRoot
        Write-Status -Type detail -Label "Git discovered" -Detail $gitRoot -RuntimeContext $RuntimeContext
    }
    catch {
        if (-not $AllowMissingGit) {
            throw
        }

        Write-Status -Type info -Label "Git not found" -Detail "uninstall will clean known paths" -RuntimeContext $RuntimeContext
    }

    $gitUsrBin = $null
    $gitMingwBin = $null
    $gitCmd = $null
    $shimDir = $null
    $userShimRoot = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
    $userShimDir = Join-Path $userShimRoot 'UnixTools\shims'

    if ($gitRoot) {
        $gitUsrBin = Join-Path $gitRoot 'usr\bin'
        $gitMingwBin = Join-Path $gitRoot 'mingw64\bin'
        $gitCmd = Join-Path $gitRoot 'cmd'
        if ($RuntimeContext.PathScope -eq 'User') {
            $shimDir = $userShimDir
        }
        else {
            $shimDir = Join-Path $gitRoot 'shims'
        }
    }

    return [pscustomobject]@{
        GitRoot             = $gitRoot
        GitUsrBin           = $gitUsrBin
        GitMingwBin         = $gitMingwBin
        GitCmd              = $gitCmd
        ShimDir             = $shimDir
        UserShimDir         = $userShimDir
        OptionalToolCatalog = @(Get-OptionalToolCatalog -RuntimeContext $RuntimeContext)
        OptionalModuleCatalog = @(Get-OptionalPowerShellModuleCatalog -RuntimeContext $RuntimeContext)
    }
}

function Invoke-FontUninstallFlow {
    param(
        [Parameter(Mandatory = $true)][psobject]$State,
        [switch]$HasAdditionalActions,
        [psobject]$RuntimeContext
    )

    Write-Section 'Uninstall Font' -RuntimeContext $RuntimeContext
    if (Uninstall-NerdFont -RuntimeContext $RuntimeContext) {
        $State.DidChange = $true
        Send-EnvironmentChange
        Update-SessionPath
    }

    if (-not $HasAdditionalActions) {
        Write-Footer -Message 'Font uninstall complete' -Type ok -RuntimeContext $RuntimeContext
        return $true
    }

    return $false
}

function Invoke-UninstallFlow {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Cmdlet,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][psobject]$Context,
        [switch]$UninstallOptionalTools,
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

    Write-Section 'Uninstall' -RuntimeContext $RuntimeContext

    if ($RuntimeContext.PathScope -eq 'User') {
        $candidateShimDirs = @($Context.UserShimDir)
        if ($Context.ShimDir) { $candidateShimDirs += $Context.ShimDir }
    }
    else {
        $candidateShimDirs = @(
            'C:\Program Files\Git\shims',
            'C:\Program Files (x86)\Git\shims'
        )
        if ($Context.ShimDir) { $candidateShimDirs += $Context.ShimDir }
    }
    $candidateShimDirs = @($candidateShimDirs | Select-Object -Unique)

    if ($Cmdlet.ShouldProcess($PROFILE.CurrentUserCurrentHost, 'Remove unix-tools profile shim blocks')) {
        $removalResult = Remove-InstalledProfileSupport -RuntimeContext $RuntimeContext
        $State.DidChange = $true
        $removalDetail = if ($removalResult.Status -eq 'Removed') { 'unix-tools markers cleaned + legacy inline block removed' } else { 'unix-tools markers cleaned' }
        Write-Status -Type ok -Label 'Profile blocks removed' -Detail $removalDetail -RuntimeContext $RuntimeContext
    }

    $legacyFastScriptCandidates = @()
    if ($RuntimeContext.PathScope -eq 'User') {
        if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            $legacyFastScriptCandidates += (Join-Path $env:LOCALAPPDATA 'UnixTools\Enable-UnixToolsFast.ps1')
        }
        if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
            $legacyFastScriptCandidates += (Join-Path $env:USERPROFILE 'UnixTools\Enable-UnixToolsFast.ps1')
        }
    }
    else {
        if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
            $legacyFastScriptCandidates += (Join-Path $env:ProgramData 'UnixToolsSystemWide\Enable-UnixToolsFast.ps1')
        }
    }

    foreach ($legacyFastPath in ($legacyFastScriptCandidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $legacyFastPath -PathType Leaf)) { continue }
        if ($Cmdlet.ShouldProcess($legacyFastPath, 'Remove legacy Enable-UnixToolsFast.ps1 copy')) {
            if ($RuntimeContext.DryRun) {
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
            $State.DidChange = $true
            Write-Status -Type ok -Label 'Legacy script removed' -Detail (Split-Path $legacyFastPath -Leaf) -RuntimeContext $RuntimeContext
        }
    }

    foreach ($shimDirPath in $candidateShimDirs) {
        if ($Cmdlet.ShouldProcess($RuntimeContext.PathDisplay, "Remove shim directory entry $shimDirPath")) {
            if (Remove-MachinePathEntry -pathsToRemove @($shimDirPath) -RuntimeContext $RuntimeContext) {
                $State.DidChange = $true
                Write-Status -Type ok -Label 'PATH entry removed' -Detail $shimDirPath -RuntimeContext $RuntimeContext
            }
        }

        if (Test-Path $shimDirPath -PathType Container) {
            if ($Cmdlet.ShouldProcess($shimDirPath, 'Delete generated .cmd shims')) {
                if ($RuntimeContext.DryRun) {
                    Write-DryRun "Remove shim files from '$shimDirPath'"
                }
                else {
                    Get-ChildItem $shimDirPath -Filter *.cmd -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                    try {
                        Remove-Item $shimDirPath -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "Shim directory not removed cleanly '$shimDirPath': $($_.Exception.Message)"
                    }
                }
                $State.DidChange = $true
                Write-Status -Type ok -Label 'Shim files removed' -Detail $shimDirPath -RuntimeContext $RuntimeContext
            }
        }
    }

    if ($UninstallOptionalTools) {
        if ($Cmdlet.ShouldProcess('Optional tools', 'Uninstall optional tools previously installed by this script')) {
            $removedOptional = Uninstall-TrackedOptionalToolSet -RuntimeContext $RuntimeContext
            if ($removedOptional -gt 0) {
                $State.DidChange = $true
                Write-Status -Type ok -Label 'Optional items removed' -Detail "$removedOptional item(s)" -RuntimeContext $RuntimeContext
            }
            else {
                Write-Status -Type info -Label 'Optional tools' -Detail 'none tracked' -RuntimeContext $RuntimeContext
            }
        }
    }
    else {
        Write-Status -Type info -Label 'Optional tools' -Detail 'preserved (use -UninstallOptionalTools to remove tracked items)' -RuntimeContext $RuntimeContext
    }

    if ($State.DidChange) {
        Send-EnvironmentChange
        Update-SessionPath
        Write-Status -Type ok -Label 'Environment refreshed' -Detail 'WM_SETTINGCHANGE broadcasted' -RuntimeContext $RuntimeContext
    }
    else {
        Write-Status -Type info -Label 'Nothing to uninstall' -RuntimeContext $RuntimeContext
    }

    Write-Footer -Message 'Uninstall complete' -Type ok -RuntimeContext $RuntimeContext
}

function Invoke-PathConfigurationFlow {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Cmdlet,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][psobject]$Context,
        [switch]$AddMingw,
        [switch]$AddGitCmd,
        [switch]$NormalizePath,
        [switch]$InstallTerminalSetup,
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

    Write-Section 'Path Configuration' -RuntimeContext $RuntimeContext

    $pathsToAdd = @($Context.GitUsrBin)

    if ($AddMingw) {
        if (Test-Path $Context.GitMingwBin) { $pathsToAdd += $Context.GitMingwBin }
        else { Write-Status -Type info -Label 'mingw64\bin' -Detail 'not found, skipping' -RuntimeContext $RuntimeContext }
    }

    if ($AddGitCmd) {
        if (Test-Path $Context.GitCmd) { $pathsToAdd += $Context.GitCmd }
        else { Write-Status -Type info -Label 'cmd' -Detail 'not found, skipping' -RuntimeContext $RuntimeContext }
    }

    $changed = $false
    if ($Cmdlet.ShouldProcess($RuntimeContext.PathDisplay, 'Add tool directories')) {
        $changed = Add-MachinePathEntry -pathsToAdd $pathsToAdd -RuntimeContext $RuntimeContext
    }

    if ($changed) {
        $State.DidChange = $true
        Write-Status -Type ok -Label 'Tool directories added' -Detail "to $($RuntimeContext.PathDisplay)" -RuntimeContext $RuntimeContext
    }
    else {
        Write-Status -Type ok -Label 'Tool directories' -Detail "already in $($RuntimeContext.PathDisplay)" -RuntimeContext $RuntimeContext
    }

    if ($NormalizePath) {
        if ($Cmdlet.ShouldProcess($RuntimeContext.PathDisplay, 'Normalize PATH entries')) {
            Update-MachinePathEntry -RuntimeContext $RuntimeContext
            $State.DidChange = $true
            Write-Status -Type ok -Label 'PATH normalized' -Detail 'removed duplicates/trailing slashes' -RuntimeContext $RuntimeContext
        }
    }

    if ($InstallTerminalSetup) {
        if ($Cmdlet.ShouldProcess('Terminal Setup', 'Install Oh My Posh themes and Nerd Fonts')) {
            Install-TerminalSetup -ThemesDir $ThemesDir -RuntimeContext $RuntimeContext
            $State.DidChange = $true
        }
    }
}

function Invoke-OptionalToolFlow {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Cmdlet,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][psobject]$Context,
        [switch]$InstallOptionalTools,
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

    if (-not $InstallOptionalTools) {
        return
    }

    $optionalToolCatalog = @($Context.OptionalToolCatalog)
    $optionalModuleCatalog = @($Context.OptionalModuleCatalog)

    Write-Section 'Optional Tools' -RuntimeContext $RuntimeContext
    if ($Cmdlet.ShouldProcess('Optional tools', 'Install missing optional tools via package managers')) {
        $presentBefore = @($optionalToolCatalog | Where-Object {
                Test-OptionalToolAvailable -Tool $_
            } | ForEach-Object { Get-OptionalToolDisplayName -Tool $_ })
        $presentModulesBefore = @($optionalModuleCatalog | Where-Object {
                $_.ModuleName -and (Get-Module -ListAvailable ([string]$_.ModuleName))
            } | ForEach-Object { [string]$_.ModuleName })

        $installedOptional = @(Install-MissingOptionalToolSet -Catalog $optionalToolCatalog -RuntimeContext $RuntimeContext)
        $installedOptionalModules = @(Install-MissingOptionalPowerShellModuleSet -Catalog $optionalModuleCatalog -RuntimeContext $RuntimeContext)
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
            Write-Status -Type ok -Label "$($alreadyPresent.Count) present before run" -Detail ($alreadyPresent -join ' ') -RuntimeContext $RuntimeContext
        }

        if ($newlyDetected.Count -gt 0) {
            Write-Status -Type ok -Label "$($newlyDetected.Count) present after install attempt" -Detail ($newlyDetected -join ' ') -RuntimeContext $RuntimeContext
        }

        if ($installedOptional.Count -gt 0) {
            $State.DidChange = $true
            Write-Status -Type ok -Label "$($installedOptional.Count) newly installed" -RuntimeContext $RuntimeContext
        }

        if ($alreadyPresentModules.Count -gt 0) {
            Write-Status -Type ok -Label "$($alreadyPresentModules.Count) modules present" -Detail ($alreadyPresentModules -join ', ') -RuntimeContext $RuntimeContext
        }

        if ($newModulesDetected.Count -gt 0) {
            Write-Status -Type ok -Label "$($newModulesDetected.Count) modules present after install" -Detail ($newModulesDetected -join ', ') -RuntimeContext $RuntimeContext
        }

        if ($installedOptionalModules.Count -gt 0) {
            $State.DidChange = $true
            Write-Status -Type ok -Label "$($installedOptionalModules.Count) modules newly installed" -RuntimeContext $RuntimeContext
        }

        if ($missingAfter.Count -gt 0) {
            Write-Status -Type warn -Label "$($missingAfter.Count) still missing" -Detail ($missingAfter -join ', ') -RuntimeContext $RuntimeContext
        }
        else {
            Write-Status -Type ok -Label 'All optional tools available after run' -Detail ($presentAfter -join ' ') -RuntimeContext $RuntimeContext
        }

        if ($missingModulesAfter.Count -gt 0) {
            Write-Status -Type warn -Label "$($missingModulesAfter.Count) modules still missing" -Detail ($missingModulesAfter -join ', ') -RuntimeContext $RuntimeContext
        }
        else {
            Write-Status -Type ok -Label 'All optional modules available after run' -Detail ($presentModulesAfter -join ', ') -RuntimeContext $RuntimeContext
        }
    }
    else {
        Write-Status -Type skip -Label 'Optional tools' -Detail 'skipped by -WhatIf/-Confirm' -RuntimeContext $RuntimeContext
    }
}

function Invoke-ShimFlow {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Cmdlet,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][psobject]$Context,
        [switch]$CreateShims,
        [switch]$AddMingw,
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

    if (-not $CreateShims) {
        return
    }

    $optionalToolCatalog = @($Context.OptionalToolCatalog)

    Write-Section 'Shims' -RuntimeContext $RuntimeContext
    if ($Cmdlet.ShouldProcess($Context.ShimDir, "Create/refresh shim .cmd files and prepend shim dir to $($RuntimeContext.PathDisplay)")) {
        New-DirectoryIfMissing -dir $Context.ShimDir -RuntimeContext $RuntimeContext

        if ($RuntimeContext.DryRun) {
            Write-DryRun "Clear stale shims in '$($Context.ShimDir)'"
        }
        else {
            Get-ChildItem $Context.ShimDir -Filter *.cmd -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }

        $toolsToShim = Get-CoreShimToolCatalog -RuntimeContext $RuntimeContext
        $externalTools = @(
            $optionalToolCatalog |
            ForEach-Object { Get-OptionalToolCommandName -Tool $_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        $searchDirs = @($Context.GitUsrBin)
        if ($AddMingw -and (Test-Path $Context.GitMingwBin)) { $searchDirs += $Context.GitMingwBin }
        $appIndex = Get-ApplicationCommandIndex -excludeDir $Context.ShimDir

        $shimmed = 0
        $notFound = 0
        $notFoundTools = New-Object System.Collections.Generic.List[string]
        $externalFound = New-Object System.Collections.Generic.List[string]

        foreach ($tool in $toolsToShim) {
            $toolPath = Find-Tool -toolName $tool -searchDirs $searchDirs
            if (-not $toolPath) {
                $toolPath = Find-ToolInPath -toolName $tool -excludeDir $Context.ShimDir -AppIndex $appIndex
                if (-not $toolPath -and $tool -eq 'nc') {
                    $toolPath = Find-ToolInPath -toolName 'ncat' -excludeDir $Context.ShimDir -AppIndex $appIndex
                }
            }
            if ($toolPath) {
                if (Write-ShimCmd -shimDir $Context.ShimDir -name $tool -targetExePath $toolPath -RuntimeContext $RuntimeContext) { $shimmed++ }
            }
            else {
                $notFound++
                $notFoundTools.Add($tool) | Out-Null
            }
        }

        foreach ($tool in $externalTools) {
            $toolPath = Find-ToolInPath -toolName $tool -excludeDir $Context.ShimDir -AppIndex $appIndex
            if ($toolPath) {
                if (Write-ShimCmd -shimDir $Context.ShimDir -name $tool -targetExePath $toolPath -RuntimeContext $RuntimeContext) {
                    $shimmed++
                    $externalFound.Add($tool) | Out-Null
                }
            }
        }

        Add-MachinePathPrepend -pathToPrepend $Context.ShimDir -RuntimeContext $RuntimeContext

        if (-not $RuntimeContext.DryRun) {
            try {
                if ($RuntimeContext.PathScope -eq 'User') {
                    & icacls $Context.ShimDir /inheritance:r /grant "${env:USERNAME}:(OI)(CI)F" 2>&1 | Out-Null
                }
                else {
                    & icacls $Context.ShimDir /inheritance:r /grant 'BUILTIN\Administrators:(OI)(CI)F' /grant 'BUILTIN\Users:(OI)(CI)RX' 2>&1 | Out-Null
                }
                Write-Status -Type ok -Label 'ACLs secured' -Detail 'read-only for non-admins' -RuntimeContext $RuntimeContext
            }
            catch {
                Write-Status -Type warn -Label 'ACL warning' -Detail $_.Exception.Message -RuntimeContext $RuntimeContext
            }
        }
        else {
            Write-DryRun "icacls '$($Context.ShimDir)' /inheritance:r /grant ..."
        }

        $State.DidChange = $true
        Write-Status -Type ok -Label "$shimmed shims created" -Detail $Context.ShimDir -RuntimeContext $RuntimeContext
        Write-Status -Type ok -Label 'Shim dir prepended' -Detail "to $($RuntimeContext.PathDisplay) (priority)" -RuntimeContext $RuntimeContext

        if ($externalFound.Count -gt 0) {
            Write-Status -Type ok -Label "$($externalFound.Count) external tools" -Detail ($externalFound -join ' ') -RuntimeContext $RuntimeContext
        }

        if ($notFound -gt 0) {
            Write-Status -Type info -Label "$notFound tools not found" -Detail '(normal)' -RuntimeContext $RuntimeContext
            $missing = @($notFoundTools | Sort-Object -Unique)
            Write-CompactList -Items $missing
        }
    }
    else {
        Write-Status -Type skip -Label 'Shims' -Detail 'skipped by -WhatIf/-Confirm' -RuntimeContext $RuntimeContext
    }
}

function Invoke-ProfileSetupFlow {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Cmdlet,
        [Parameter(Mandatory = $true)][psobject]$State,
        [switch]$InstallProfileShims,
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [Parameter(Mandatory = $true)][string]$Theme,
        [Parameter(Mandatory = $true)][string]$ProfileStartupMode,
        [Parameter(Mandatory = $true)][string]$PromptInitMode,
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

    if (-not $InstallProfileShims) {
        return
    }

    Write-Section 'Profile' -RuntimeContext $RuntimeContext
    if ($Cmdlet.ShouldProcess($PROFILE.CurrentUserCurrentHost, 'Install/update unix-tools profile shim blocks')) {
        Install-ProfileInlineSupport -ThemesDir $ThemesDir -Theme $Theme -StartupMode $ProfileStartupMode -PromptMode $PromptInitMode -RuntimeContext $RuntimeContext
        $profilePath = $PROFILE.CurrentUserCurrentHost
        $expectedHash = $null
        if (Test-Path $profilePath) {
            $expectedHash = (Get-FileHash -Path $profilePath -Algorithm SHA256).Hash
        }

        $isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        try {
            if (Test-Path $profilePath) {
                if ($isElevated) {
                    Write-Status -Type warn -Label 'Elevated session' -Detail 'reload skipped (open new terminal)' -RuntimeContext $RuntimeContext
                }
                else {
                    $currentHash = (Get-FileHash -Path $profilePath -Algorithm SHA256).Hash
                    if ($expectedHash -and $currentHash -ne $expectedHash) {
                        Write-Status -Type warn -Label 'Profile modified' -Detail 'reload skipped for safety' -RuntimeContext $RuntimeContext
                    }
                    else {
                        . $profilePath
                        Write-Status -Type ok -Label 'Profile reloaded' -Detail '. `$PROFILE' -RuntimeContext $RuntimeContext
                    }
                }
            }
        }
        catch {
            Write-Status -Type warn -Label 'Profile reload failed' -Detail $_.Exception.Message -RuntimeContext $RuntimeContext
        }

        Write-Status -Type ok -Label 'Profile shims written' -Detail "managed loader + support files ($ProfileStartupMode / $PromptInitMode)" -RuntimeContext $RuntimeContext
        $State.DidChange = $true
    }
    else {
        Write-Status -Type skip -Label 'Profile shims' -Detail 'skipped by -WhatIf/-Confirm' -RuntimeContext $RuntimeContext
    }
}

function Invoke-VerificationFlow {
    param(
        [Parameter(Mandatory = $true)][psobject]$State,
        [switch]$CreateShims,
        [switch]$InstallProfileShims,
        [switch]$InstallOptionalTools,
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

    Write-Section 'Environment' -RuntimeContext $RuntimeContext
    if ($State.DidChange) {
        Send-EnvironmentChange
        Write-Status -Type ok -Label 'WM_SETTINGCHANGE' -Detail 'broadcasted' -RuntimeContext $RuntimeContext
    }
    else {
        Write-Status -Type info -Label 'No changes' -Detail 'nothing to broadcast' -RuntimeContext $RuntimeContext
    }

    Write-Section 'Verification' -RuntimeContext $RuntimeContext
    Update-SessionPath

    $verifyTools = @('grep', 'sed', 'awk', 'find', 'bash')
    $verifyCommandCache = @{}
    foreach ($tool in $verifyTools) {
        $verifyCommandCache[$tool] = @(Get-Command $tool -All -ErrorAction SilentlyContinue)
    }

    foreach ($tool in $verifyTools) {
        $cmds = @($verifyCommandCache[$tool])
        if (-not $cmds) {
            Write-Status -Type fail -Label $tool -Detail 'not found (open a NEW terminal)' -RuntimeContext $RuntimeContext
            continue
        }

        $ui = $RuntimeContext.Ui
        $top = $cmds | Select-Object -First 3
        $lines = @()
        foreach ($commandInfo in $top) {
            $src = $commandInfo.Source
            if ($CreateShims -and $src -like '*\shims\*') {
                $shimContent = Get-Content $src -Raw -ErrorAction SilentlyContinue
                $target = $null
                if ($shimContent -match '"([^"]+\.exe)"') { $target = $matches[1] }
                if ($target) { $lines += "shim $($ui.Arrow) $(Split-Path $target -Leaf)" }
                else { $lines += 'shim' }
            }
            elseif ($src -like '*\Git\*') {
                $lines += "Git $($ui.Arrow) $(Split-Path $src -Leaf)"
            }
            else {
                $lines += (Split-Path $src -Leaf)
            }
        }

        Write-Status -Type ok -Label $tool -Detail ($lines -join ' | ') -RuntimeContext $RuntimeContext
    }

    if ($InstallProfileShims) {
        $profilePath = $PROFILE.CurrentUserCurrentHost
        if ($RuntimeContext.DryRun) {
            Write-Status -Type info -Label 'Profile blocks' -Detail 'skipped in DryRun' -RuntimeContext $RuntimeContext
        }
        else {
            $profileState = Get-ProfileInstallationState -ProfilePath $profilePath

            if ($profileState.HasManagedBlocks) {
                Write-Status -Type ok -Label 'Profile blocks' -Detail 'present in `$PROFILE' -RuntimeContext $RuntimeContext
            }
            elseif ($profileState.HasMissingBlock -or $profileState.HasAliasBlock -or $profileState.HasSmartShellBlock) {
                Write-Status -Type warn -Label 'Profile blocks' -Detail 'partial install detected' -RuntimeContext $RuntimeContext
            }
            elseif ($profileState.HasLegacyFastBlock) {
                Write-Status -Type warn -Label 'Profile blocks' -Detail 'legacy fast-shim detected (re-run -InstallProfileShims)' -RuntimeContext $RuntimeContext
            }
            else {
                Write-Status -Type fail -Label 'Profile blocks' -Detail 'not found in `$PROFILE' -RuntimeContext $RuntimeContext
            }

            $legacyDetail = switch ($profileState.LegacyInlineStatus) {
                'Found' { 'present (cleanup still needed)' }
                'Ambiguous' { 'ambiguous signature detected (manual review needed)' }
                default { 'not detected' }
            }
            $startupModeDetail = if ([string]::IsNullOrWhiteSpace($profileState.StartupMode)) { 'Unknown' } else { $profileState.StartupMode }
            $promptModeDetail = if ([string]::IsNullOrWhiteSpace($profileState.PromptInitMode)) { 'Unknown' } else { $profileState.PromptInitMode }

            Write-Status -Type info -Label 'Legacy inline shims' -Detail $legacyDetail -RuntimeContext $RuntimeContext
            Write-Status -Type info -Label 'Startup mode' -Detail $startupModeDetail -RuntimeContext $RuntimeContext
            Write-Status -Type info -Label 'Prompt init mode' -Detail $promptModeDetail -RuntimeContext $RuntimeContext
        }
    }

    $ui = $RuntimeContext.Ui
    Write-Footer -Message "Done $($ui.Arrow) open a new terminal to use tools" -Type ok -RuntimeContext $RuntimeContext

    $tryCommands = @('grep --version')
    if ($InstallProfileShims) { $tryCommands += @('ls -la', "'stressed' | rev") }
    if ($InstallOptionalTools) { $tryCommands += @('rg --version', 'fd --version') }
    $tryLine = '  Try:  ' + ($tryCommands -join " $([char]0x00B7) ")
    Write-AccentLine -Text $tryLine
    Write-BlankLine
}
