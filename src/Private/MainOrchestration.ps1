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

function Get-ShimCandidateDirectoryList {
    param(
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

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

    return @($candidateShimDirs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Remove-LegacyShimDirectorySet {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Cmdlet,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][string[]]$ShimDirectories,
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

    foreach ($shimDirPath in @($ShimDirectories)) {
        if ($Cmdlet.ShouldProcess($RuntimeContext.PathDisplay, "Remove shim directory entry $shimDirPath")) {
            if (Remove-MachinePathEntry -pathsToRemove @($shimDirPath) -RuntimeContext $RuntimeContext) {
                $State.DidChange = $true
                Write-Status -Type ok -Label 'PATH entry removed' -Detail $shimDirPath -RuntimeContext $RuntimeContext
            }
        }

        if (-not (Test-Path -LiteralPath $shimDirPath -PathType Container)) {
            continue
        }

        if ($Cmdlet.ShouldProcess($shimDirPath, 'Delete generated .cmd shims')) {
            if ($RuntimeContext.DryRun) {
                Write-DryRun "Remove shim files from '$shimDirPath'"
            }
            else {
                Get-ChildItem -LiteralPath $shimDirPath -Filter *.cmd -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                try {
                    Remove-Item -LiteralPath $shimDirPath -Force -ErrorAction Stop
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

function Remove-LegacyProfileShimSupport {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Cmdlet,
        [Parameter(Mandatory = $true)][psobject]$State,
        [switch]$IncludeManagedProfileSupport,
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

    $profilePaths = @(Get-ManagedUserProfilePathList)
    $profileStates = @(
        foreach ($profilePath in $profilePaths) {
            [pscustomobject]@{
                Path = $profilePath
                State = Get-ProfileInstallationState -ProfilePath $profilePath
            }
        }
    )
    $hasProfileShimSupport = @($profileStates | Where-Object {
            ($IncludeManagedProfileSupport -and ($_.State.HasManagedBlocks -or $_.State.HasLoaderBlock)) -or
            $_.State.HasMissingBlock -or
            $_.State.HasAliasBlock -or
            $_.State.HasSmartShellBlock -or
            $_.State.HasLegacyFastBlock -or
            $_.State.HasLegacyInlineBlock -or
            $_.State.LegacyInlineStatus -eq 'Ambiguous'
        }).Count -gt 0

    $profileTarget = $profilePaths -join ', '
    if ($hasProfileShimSupport -and $Cmdlet.ShouldProcess($profileTarget, 'Remove unix-tools profile shim blocks')) {
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
                    $remaining = Get-ChildItem -LiteralPath $legacyFastDir -Force -ErrorAction SilentlyContinue
                    if (-not $remaining) {
                        Remove-Item -LiteralPath $legacyFastDir -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            $State.DidChange = $true
            Write-Status -Type ok -Label 'Legacy script removed' -Detail (Split-Path $legacyFastPath -Leaf) -RuntimeContext $RuntimeContext
        }
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

    Remove-LegacyProfileShimSupport -Cmdlet $Cmdlet -State $State -IncludeManagedProfileSupport -RuntimeContext $RuntimeContext
    Remove-LegacyShimDirectorySet -Cmdlet $Cmdlet -State $State -ShimDirectories (Get-ShimCandidateDirectoryList -Context $Context -RuntimeContext $RuntimeContext) -RuntimeContext $RuntimeContext

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
        [string]$Theme = 'lightgreen',
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
            Install-TerminalSetup -ThemesDir $ThemesDir -Theme $Theme -RuntimeContext $RuntimeContext
            $State.DidChange = $true
        }
    }
}

function Invoke-ProfileSetupFlow {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Cmdlet,
        [Parameter(Mandatory = $true)][psobject]$State,
        [switch]$InstallFull,
        [Parameter(Mandatory = $true)][string]$ThemesDir,
        [string]$Theme = 'lightgreen',
        [ValidateSet('Fast', 'Legacy')][string]$ProfileStartupMode = 'Fast',
        [ValidateSet('Lazy', 'Eager', 'Off')][string]$PromptInitMode = 'Lazy',
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

    if (-not $InstallFull) {
        return
    }

    Write-Section 'Profile Setup' -RuntimeContext $RuntimeContext
    $profilePaths = @(Get-ManagedUserProfilePathList)
    $profileTarget = if ($profilePaths.Count -gt 0) { $profilePaths -join ', ' } else { [string]$PROFILE.CurrentUserCurrentHost }
    if ($Cmdlet.ShouldProcess($profileTarget, 'Install unix-tools profile loader and prompt support')) {
        Install-ProfileInlineSupport -ThemesDir $ThemesDir -Theme $Theme -StartupMode $ProfileStartupMode -PromptMode $PromptInitMode -RuntimeContext $RuntimeContext | Out-Null
        $State.DidChange = $true
        Write-Status -Type ok -Label 'Profile support installed' -Detail "startup=$ProfileStartupMode, prompt=$PromptInitMode" -RuntimeContext $RuntimeContext
    }
    else {
        Write-Status -Type skip -Label 'Profile setup' -Detail 'skipped by -WhatIf/-Confirm' -RuntimeContext $RuntimeContext
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

function Invoke-ShimCleanupFlow {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Cmdlet,
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][psobject]$RuntimeContext
    )

    Write-Section 'Command Resolution' -RuntimeContext $RuntimeContext

    if ($Cmdlet.ShouldProcess($RuntimeContext.PathDisplay, 'Remove legacy shim directories and profile shim blocks')) {
        Remove-LegacyProfileShimSupport -Cmdlet $Cmdlet -State $State -RuntimeContext $RuntimeContext
        Remove-LegacyShimDirectorySet -Cmdlet $Cmdlet -State $State -ShimDirectories (Get-ShimCandidateDirectoryList -Context $Context -RuntimeContext $RuntimeContext) -RuntimeContext $RuntimeContext
        if (-not $State.DidChange) {
            Write-Status -Type info -Label 'Legacy shims' -Detail 'not detected' -RuntimeContext $RuntimeContext
        }
    }
    else {
        Write-Status -Type skip -Label 'Shim cleanup' -Detail 'skipped by -WhatIf/-Confirm' -RuntimeContext $RuntimeContext
    }
}

function Invoke-VerificationFlow {
    param(
        [Parameter(Mandatory = $true)][psobject]$State,
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
            if ($src -like '*\Git\*') {
                $lines += "Git $($ui.Arrow) $(Split-Path $src -Leaf)"
            }
            else {
                $lines += (Split-Path $src -Leaf)
            }
        }

        Write-Status -Type ok -Label $tool -Detail ($lines -join ' | ') -RuntimeContext $RuntimeContext
    }

    $ui = $RuntimeContext.Ui
    Write-Footer -Message "Done $($ui.Arrow) open a new terminal to use tools" -Type ok -RuntimeContext $RuntimeContext

    $tryCommands = @('grep --version')
    if ($InstallOptionalTools) { $tryCommands += @('rg --version', 'fd --version') }
    $tryLine = '  Try:  ' + ($tryCommands -join " $([char]0x00B7) ")
    Write-AccentLine -Text $tryLine
    Write-BlankLine
}
