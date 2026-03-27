function Get-OptionalToolCommandName {
    param([Parameter(Mandatory = $true)][object]$Tool)

    if ($Tool.PSObject.Properties['Command']) {
        return [string]$Tool.Command
    }

    return $null
}

function Get-OptionalToolDisplayName {
    param([Parameter(Mandatory = $true)][object]$Tool)

    $commandName = Get-OptionalToolCommandName -Tool $Tool
    if (-not [string]::IsNullOrWhiteSpace($commandName)) {
        return $commandName
    }

    if ($Tool.PSObject.Properties['PackageName'] -and -not [string]::IsNullOrWhiteSpace([string]$Tool.PackageName)) {
        return [string]$Tool.PackageName
    }

    if ($Tool.PSObject.Properties['ModuleName'] -and -not [string]::IsNullOrWhiteSpace([string]$Tool.ModuleName)) {
        return [string]$Tool.ModuleName
    }

    if ($Tool.PSObject.Properties['PackageId'] -and -not [string]::IsNullOrWhiteSpace([string]$Tool.PackageId)) {
        return [string]$Tool.PackageId
    }

    return ''
}

function Test-OptionalToolAvailable {
    param([Parameter(Mandatory = $true)][object]$Tool)

    if ($Tool.PSObject.Properties['Kind'] -and [string]$Tool.Kind -eq 'Package') {
        if ($Tool.PSObject.Properties['ProbeCommands'] -and $Tool.ProbeCommands) {
            return Test-CoreUtilsLayerAvailable -ProbeCommands @($Tool.ProbeCommands)
        }

        return $false
    }

    $commandName = Get-OptionalToolCommandName -Tool $Tool
    if ([string]::IsNullOrWhiteSpace($commandName)) {
        return $false
    }

    return [bool](Get-PreferredApplicationCommand -Name $commandName)
}

function Get-CatalogPath {
    param([Parameter(Mandatory = $true)][string]$Name)

    $repoRoot = if ($script:EnableUnixToolsRepoRoot) {
        $script:EnableUnixToolsRepoRoot
    }
    elseif ($PSScriptRoot) {
        Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    }
    else {
        (Get-Location).Path
    }

    return Join-Path $repoRoot ("catalogs\{0}" -f $Name)
}

function Read-CatalogJson {
    param([Parameter(Mandatory = $true)][string]$Name)

    $path = Get-CatalogPath -Name $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Catalog not found: $path"
    }

    $raw = Get-Content -Path $path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @()
    }

    return @((ConvertFrom-Json -InputObject $raw -ErrorAction Stop))
}

function Get-OptionalToolCatalog {
    return @(Read-CatalogJson -Name 'optional-tools.json')
}

function Get-OptionalPowerShellModuleCatalog {
    return @(Read-CatalogJson -Name 'optional-modules.json')
}

function Get-SmartShellOptionalModuleNameSet {
    return @(Get-OptionalPowerShellModuleCatalog | Select-Object -ExpandProperty ModuleName)
}

function Get-CoreShimToolCatalog {
    return @(Read-CatalogJson -Name 'core-shim-tools.json')
}

function Get-OptionalToolsStatePath {
    $base = if ($script:PathScope -eq "User") {
        if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
    }
    else {
        $env:ProgramData
    }
    $stateDir = Join-Path $base "UnixToolsSystemWide"
    return Join-Path $stateDir "optional-tools-installed.json"
}

function Read-OptionalToolState {
    $statePath = Get-OptionalToolsStatePath
    if (-not (Test-Path $statePath)) { return @() }

    try {
        $raw = Get-Content -Path $statePath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $data = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
        return @($data)
    }
    catch {
        return @()
    }
}

function Write-OptionalToolState([object[]]$Records) {
    $statePath = Get-OptionalToolsStatePath
    $stateDir = Split-Path -Parent $statePath
    if ($stateDir -and -not (Test-Path $stateDir)) {
        if ($script:DryRun) {
            Write-DryRun "New-Item -ItemType Directory -Path '$stateDir'"
        }
        else {
            New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
        }
    }

    if (-not $Records -or $Records.Count -eq 0) {
        if (Test-Path $statePath) {
            if ($script:DryRun) {
                Write-DryRun "Remove-Item -Path '$statePath'"
            }
            else {
                Remove-Item -Path $statePath -Force -ErrorAction SilentlyContinue
            }
        }
        return
    }

    $json = $Records | ConvertTo-Json -Depth 6
    Write-AtomicUtf8File -Path $statePath -Content $json
}

function Install-MissingOptionalPowerShellModuleSet([object[]]$Catalog) {
    if (-not $Catalog -or $Catalog.Count -eq 0) { return @() }

    $psResource = Get-Command Install-PSResource -ErrorAction SilentlyContinue
    $powerShellGet = Get-Command Install-Module -ErrorAction SilentlyContinue
    if (-not $psResource -and -not $powerShellGet) {
        Write-Status -Type warn -Label "No module installer" -Detail "PowerShell modules cannot be auto-installed"
        return @()
    }

    $newlyInstalled = @()
    foreach ($module in $Catalog) {
        $moduleName = [string]$module.ModuleName
        $repository = if ($module.Repository) { [string]$module.Repository } else { "PSGallery" }
        if ([string]::IsNullOrWhiteSpace($moduleName)) { continue }

        if (Get-Module -ListAvailable $moduleName) {
            continue
        }

        $installed = $false
        $managerUsed = $null

        try {
            if ($script:DryRun) {
                if ($psResource) {
                    Write-DryRun "Install-PSResource $moduleName -Repository $repository -Scope CurrentUser -TrustRepository -Quiet"
                    $managerUsed = "psresourceget"
                }
                else {
                    Write-DryRun "Install-Module $moduleName -Repository $repository -Scope CurrentUser -Force -AllowClobber"
                    $managerUsed = "powershellget"
                }
                $installed = $true
            }
            elseif ($psResource) {
                Install-PSResource -Name $moduleName -Repository $repository -Scope CurrentUser -TrustRepository -Quiet -ErrorAction Stop
                $managerUsed = "psresourceget"
                $installed = $true
            }
            else {
                Install-Module -Name $moduleName -Repository $repository -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                $managerUsed = "powershellget"
                $installed = $true
            }
        }
        catch {
            Write-Status -Type warn -Label "Module install failed" -Detail "${moduleName}: $($_.Exception.Message)" -Indent
        }

        if (-not $script:DryRun -and $installed -and -not (Get-Module -ListAvailable $moduleName)) {
            $installed = $false
            Write-Status -Type warn -Label "Module missing" -Detail "$moduleName not detected after install" -Indent
        }

        if ($installed) {
            $newlyInstalled += [pscustomobject]@{
                Kind          = "PowerShellModule"
                Command       = $null
                ModuleName    = $moduleName
                Manager       = $managerUsed
                PackageId     = $moduleName
                InstalledAt   = (Get-Date).ToString("o")
                ScriptVersion = $script:EnableUnixToolsVersion
            }
            Write-Status -Type ok -Label "Module installed" -Detail "$moduleName via $managerUsed" -Indent
        }
    }

    if ($newlyInstalled.Count -gt 0) {
        $existing = @(Read-OptionalToolState)
        $records = New-Object System.Collections.Generic.List[object]
        $moduleMap = @{}

        foreach ($item in $existing) {
            $kind = if ($item.PSObject.Properties["Kind"]) { [string]$item.Kind } else { "" }
            $name = if ($item.PSObject.Properties["ModuleName"]) { [string]$item.ModuleName } else { "" }
            if ($kind -eq "PowerShellModule" -and -not [string]::IsNullOrWhiteSpace($name)) {
                $moduleMap[$name] = $item
            }
            else {
                $records.Add($item) | Out-Null
            }
        }

        foreach ($item in $newlyInstalled) {
            $moduleMap[[string]$item.ModuleName] = $item
        }

        foreach ($item in ($moduleMap.Values | Sort-Object ModuleName)) {
            $records.Add($item) | Out-Null
        }

        Write-OptionalToolState -Records @($records)
    }

    return $newlyInstalled
}

function Install-MissingOptionalToolSet([object[]]$Catalog) {
    if (-not $Catalog -or $Catalog.Count -eq 0) { return @() }

    $pmProbe = @(Initialize-OptionalPackageManagers)
    $pm = @(
        $pmProbe | Where-Object {
            $_ -and
            $_.PSObject -and
            $_.PSObject.Properties["Winget"] -and
            $_.PSObject.Properties["Choco"]
        }
    ) | Select-Object -Last 1

    if (-not $pm) {
        Write-Status -Type warn -Label "No package manager" -Detail "missing tools cannot be auto-installed"
        Write-PackageManagerInstallGuidance
        return @()
    }

    $wingetAvailable = [bool]$pm.PSObject.Properties["Winget"].Value
    $chocoAvailable = [bool]$pm.PSObject.Properties["Choco"].Value
    $hasAnyPackageManager = $wingetAvailable -or $chocoAvailable
    $newlyInstalled = @()

    if (-not $hasAnyPackageManager) {
        $missingCommands = @(
            $Catalog |
            Where-Object { -not (Test-OptionalToolAvailable -Tool $_) } |
            ForEach-Object { Get-OptionalToolDisplayName -Tool $_ }
        )

        if ($missingCommands.Count -gt 0) {
            Write-Status -Type warn -Label "No package manager" -Detail "cannot auto-install missing tools"
            Write-Dim "Missing: $($missingCommands -join ', ')"
            Write-PackageManagerInstallGuidance
        }
        return @()
    }

    foreach ($tool in $Catalog) {
        $commandName = Get-OptionalToolCommandName -Tool $tool
        $toolLabel = Get-OptionalToolDisplayName -Tool $tool
        if ($tool.PSObject.Properties['Kind'] -and [string]$tool.Kind -eq 'Package') {
            if (Test-OptionalToolAvailable -Tool $tool) {
                continue
            }
        }
        elseif ([string]::IsNullOrWhiteSpace($commandName)) {
            continue
        }
        elseif (Test-OptionalToolAvailable -Tool $tool) {
            continue
        }

        $installed = $false
        $attempted = @()
        $attemptedExit = @{}
        $managerUsed = $null
        $packageIdUsed = $null

        if ($wingetAvailable -and $tool.WingetId) {
            $attempted += "winget"
            Write-Dim "Installing $toolLabel via winget ($($tool.WingetId))..."
            if ($script:DryRun) {
                Write-DryRun "winget install --id $($tool.WingetId) ..."
                $exitCode = 0
            }
            else {
                $exitCode = Invoke-NativeCommand winget install --id $tool.WingetId --exact --source winget --accept-package-agreements --accept-source-agreements
            }
            $attemptedExit['winget'] = $exitCode
            if ($exitCode -eq 0) {
                $installed = $true
                $managerUsed = "winget"
                $packageIdUsed = [string]$tool.WingetId
            }
        }

        if (-not $installed -and $chocoAvailable -and $tool.ChocoId) {
            $attempted += "choco"
            Write-Dim "Installing $toolLabel via choco ($($tool.ChocoId))..."
            if ($script:DryRun) {
                Write-DryRun "choco install $($tool.ChocoId) -y"
                $exitCode = 0
            }
            else {
                $exitCode = Invoke-NativeCommand choco install $tool.ChocoId -y
            }
            $attemptedExit['choco'] = $exitCode
            if ($exitCode -eq 0) {
                $installed = $true
                $managerUsed = "choco"
                $packageIdUsed = [string]$tool.ChocoId
            }
        }

        if (-not $installed) {
            Update-SessionPath
            if (Test-OptionalToolAvailable -Tool $tool) {
                $installed = $true
                if (-not $managerUsed) { $managerUsed = "detected" }
                if (-not $packageIdUsed) { $packageIdUsed = "n/a" }
            }
        }

        if ($installed) {
            $newlyInstalled += [pscustomobject]@{
                Kind          = if ($tool.PSObject.Properties['Kind']) { [string]$tool.Kind } else { 'Command' }
                Command       = $commandName
                PackageName   = if ($tool.PSObject.Properties['PackageName']) { [string]$tool.PackageName } else { $null }
                Manager       = $managerUsed
                PackageId     = $packageIdUsed
                InstalledAt   = (Get-Date).ToString("o")
                ScriptVersion = $script:EnableUnixToolsVersion
            }
            Write-Status -Type ok -Label "Installed" -Detail "$toolLabel via $managerUsed" -Indent
        }
        else {
            Write-Status -Type info -Label "Not installed" -Detail $toolLabel -Indent
            if ($attempted.Count -gt 0) {
                Write-Dim "Attempted via: $($attempted -join ', ')" -Indent
                $exitDetails = @()
                foreach ($m in $attempted) {
                    if ($attemptedExit.ContainsKey($m)) {
                        $exitDetails += ("{0}={1}" -f $m, $attemptedExit[$m])
                    }
                }
                if ($exitDetails.Count -gt 0) {
                    Write-Dim "Exit codes: $($exitDetails -join ', ')" -Indent
                }
            }
        }
    }

    if ($newlyInstalled.Count -gt 0) {
        $existing = @(Read-OptionalToolState)
        $byKey = @{}
        foreach ($item in $existing) {
            $key = if ($item.PSObject.Properties['Kind'] -and [string]$item.Kind -eq 'Package') {
                "package::{0}" -f (Get-OptionalToolDisplayName -Tool $item)
            }
            else {
                $cmd = Get-OptionalToolCommandName -Tool $item
                if ([string]::IsNullOrWhiteSpace($cmd)) { $null } else { "command::{0}" -f $cmd }
            }
            if (-not [string]::IsNullOrWhiteSpace($key)) { $byKey[$key] = $item }
        }
        foreach ($item in $newlyInstalled) {
            $key = if ($item.PSObject.Properties['Kind'] -and [string]$item.Kind -eq 'Package') {
                "package::{0}" -f (Get-OptionalToolDisplayName -Tool $item)
            }
            else {
                $cmd = Get-OptionalToolCommandName -Tool $item
                if ([string]::IsNullOrWhiteSpace($cmd)) { $null } else { "command::{0}" -f $cmd }
            }
            if (-not [string]::IsNullOrWhiteSpace($key)) { $byKey[$key] = $item }
        }
        $merged = @($byKey.Values | Sort-Object @{ Expression = { Get-OptionalToolDisplayName -Tool $_ } })
        Write-OptionalToolState -Records $merged
        Update-SessionPath
    }
    return $newlyInstalled
}

function Uninstall-TrackedOptionalToolSet {
    $tracked = @(Read-OptionalToolState)
    if ($tracked.Count -eq 0) { return 0 }

    $removedCount = 0
    $remaining = @()
    foreach ($item in $tracked) {
        $kind = if ($item.PSObject.Properties["Kind"]) { [string]$item.Kind } else { "" }
        $toolLabel = Get-OptionalToolDisplayName -Tool $item
        $moduleName = if ($item.PSObject.Properties["ModuleName"]) { [string]$item.ModuleName } else { "" }
        $manager = [string]$item.Manager
        $packageId = [string]$item.PackageId

        if ($kind -eq "PowerShellModule" -or -not [string]::IsNullOrWhiteSpace($moduleName)) {
            if ([string]::IsNullOrWhiteSpace($moduleName)) {
                $remaining += $item
                continue
            }

            $ok = $false
            try {
                if ($script:DryRun) {
                    if ($manager -eq "psresourceget") {
                        Write-DryRun "Uninstall-PSResource $moduleName"
                    }
                    else {
                        Write-DryRun "Uninstall-Module $moduleName -AllVersions -Force"
                    }
                    $ok = $true
                }
                elseif ($manager -eq "psresourceget" -and (Get-Command Uninstall-PSResource -ErrorAction SilentlyContinue)) {
                    Uninstall-PSResource -Name $moduleName -Scope CurrentUser -Quiet -ErrorAction Stop
                    $ok = $true
                }
                elseif (Get-Command Uninstall-Module -ErrorAction SilentlyContinue) {
                    Uninstall-Module -Name $moduleName -AllVersions -Force -ErrorAction Stop
                    $ok = $true
                }
            }
            catch {
                Write-Status -Type warn -Label "Module uninstall failed" -Detail "${moduleName}: $($_.Exception.Message)"
            }

            if ($ok) {
                $removedCount++
                Write-Status -Type ok -Label "Module removed" -Detail $moduleName
            }
            else {
                $remaining += $item
            }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($manager) -or [string]::IsNullOrWhiteSpace($packageId)) {
            $remaining += $item
            continue
        }

        $ok = $false
        switch ($manager.ToLowerInvariant()) {
            "winget" {
                if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                    break
                }
                Write-Dim "Uninstalling optional tool: $toolLabel via winget ($packageId)..."
                if ($script:DryRun) {
                    Write-DryRun "winget uninstall --id $packageId ..."
                    $exitCode = 0
                }
                else {
                    $exitCode = Invoke-NativeCommand winget uninstall --id $packageId --exact --source winget --accept-source-agreements
                }
                $ok = ($exitCode -eq 0)
                break
            }
            "choco" {
                if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                    break
                }
                Write-Dim "Uninstalling optional tool: $toolLabel via choco ($packageId)..."
                if ($script:DryRun) {
                    Write-DryRun "choco uninstall $packageId -y"
                    $exitCode = 0
                }
                else {
                    $exitCode = Invoke-NativeCommand choco uninstall $packageId -y
                }
                $ok = ($exitCode -eq 0)
                break
            }
            default {
                break
            }
        }

        if ($ok) {
            $removedCount++
            Write-Status -Type ok -Label "Optional tool removed" -Detail $toolLabel
        }
        else {
            $remaining += $item
        }
    }

    Write-OptionalToolState -Records $remaining
    if ($removedCount -gt 0) {
        Update-SessionPath
    }
    return $removedCount
}

