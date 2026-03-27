if (-not $script:__UnixExeCache) {
    $script:__UnixExeCache = @{}
}

if (-not $script:__UnixExeMissing) {
    $script:__UnixExeMissing = New-Object object
}

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

function Get-UnixShimExecutable {
    param([Parameter(Mandatory = $true)][string]$Name)

    $key = $Name.ToLowerInvariant()
    if ($script:__UnixExeCache.ContainsKey($key)) {
        $cached = $script:__UnixExeCache[$key]
        if ($cached -eq $script:__UnixExeMissing) { return $null }
        return $cached
    }

    $candidates = @(Get-Command $Name -CommandType Application -All -ErrorAction SilentlyContinue)
    $app = $candidates |
        Where-Object { $_.Source -and [System.IO.Path]::GetExtension($_.Source) -eq '.exe' } |
        Sort-Object @{ Expression = { Get-ApplicationSourcePriority -Source $_.Source -Name $Name } }, @{ Expression = { $_.Source } } |
        Select-Object -First 1
    if (-not $app) {
        $app = $candidates |
            Sort-Object @{ Expression = { Get-ApplicationSourcePriority -Source $_.Source -Name $Name } }, @{ Expression = { $_.Source } } |
            Select-Object -First 1
    }

    if ($app) {
        $script:__UnixExeCache[$key] = $app
        return $app
    }

    $script:__UnixExeCache[$key] = $script:__UnixExeMissing
    return $null
}

function Clear-UnixShimCache {
    if ($script:__UnixExeCache) {
        $script:__UnixExeCache.Clear()
    }
}

function Reset-UnixShimName {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Name)

    Remove-Item ("Alias:" + $Name) -Force -ErrorAction SilentlyContinue
    Remove-Item ("Alias:Global:" + $Name) -Force -ErrorAction SilentlyContinue
    Remove-Item ("Function:" + $Name) -Force -ErrorAction SilentlyContinue
    Remove-Item ("Function:Global:" + $Name) -Force -ErrorAction SilentlyContinue
}
