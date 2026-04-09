function Test-GitPreferredCoreCommand {
    param([Parameter(Mandatory = $true)][string]$Name)

    return $Name -in @('ls', 'cp', 'mv', 'rm', 'cat', 'sort')
}

function Get-ApplicationSourcePriority {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [string]$Name = ''
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        return 100
    }

    if ($Name -eq 'ssh' -and $Source -match '(?i)\\Windows\\System32\\OpenSSH\\ssh\.exe$') {
        return 0
    }

    $preferGit = -not [string]::IsNullOrWhiteSpace($Name) -and (Test-GitPreferredCoreCommand -Name $Name)

    if ($Source -match '(?i)uutils[.\-_]?coreutils') {
        if ($preferGit) { return 10 }
        return 0
    }

    if ($Source -match '\\Git\\usr\\bin\\') {
        if ($preferGit) { return 0 }
        return 10
    }

    if ($Source -match '\\Git\\shims\\') {
        return 30
    }

    return 5
}

function Get-PreferredApplicationCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$ExcludeDir = $null
    )

    try {
        $apps = @(Get-Command $Name -CommandType Application -All -ErrorAction SilentlyContinue)
        if (-not $apps) { return $null }

        $bestApp = $apps |
        Where-Object {
            $_.Source -and
            [System.IO.Path]::GetExtension($_.Source) -eq '.exe' -and
            (-not $ExcludeDir -or -not $_.Source.StartsWith($ExcludeDir.Trim().TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase))
        } |
        Sort-Object @{ Expression = { Get-ApplicationSourcePriority -Source $_.Source -Name $Name } }, @{ Expression = { $_.Source } } |
        Select-Object -First 1

        return $bestApp
    }
    catch {
        Write-Verbose "Ignored error in Get-PreferredApplicationCommand: $($_.Exception.Message)"
        return $null
    }
}

function Test-CoreUtilsLayerAvailable {
    param([string[]]$ProbeCommands)

    foreach ($command in @($ProbeCommands)) {
        if ([string]::IsNullOrWhiteSpace($command)) { continue }
        $apps = @(Get-Command $command -CommandType Application -All -ErrorAction SilentlyContinue)
        foreach ($app in $apps) {
            if ((Get-ApplicationSourcePriority -Source $app.Source -Name $command) -eq 0) {
                return $true
            }
        }
    }

    return $false
}
