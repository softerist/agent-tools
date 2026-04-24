if (-not (Get-Variable -Scope Script -Name __UnixExeCache -ErrorAction SilentlyContinue)) {
    $script:__UnixExeCache = @{}
}

if (-not (Get-Variable -Scope Script -Name __UnixExeMissing -ErrorAction SilentlyContinue)) {
    $script:__UnixExeMissing = New-Object object
}

function Test-GitPreferredCoreCommand {
    param([Parameter(Mandatory = $true)][string]$Name)

    return $Name -in @('ls', 'cp', 'mv', 'rm', 'cat', 'sort')
}

function Get-UnixToolsProfileConfig {
    return Get-Variable -Scope Global -Name UnixToolsProfileConfig -ValueOnly -ErrorAction SilentlyContinue
}

function Get-UnixToolsFileStamp {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ''
    }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) {
        return ''
    }

    return '{0}:{1}' -f $item.Length, $item.LastWriteTimeUtc.Ticks
}

function Get-UnixToolsCacheHeader {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $metadata = @{}
    foreach ($line in @(Get-Content -LiteralPath $Path -TotalCount 8 -ErrorAction SilentlyContinue)) {
        if ($line -match '^#\s*(?<key>[A-Za-z0-9]+):\s*(?<value>.*)$') {
            $metadata[$matches['key']] = $matches['value']
        }
    }

    return $metadata
}

function Write-UnixToolsCacheFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )

    try {
        $directory = Split-Path -Parent $Path
        if ($directory) {
            [System.IO.Directory]::CreateDirectory($directory) | Out-Null
        }

        $encoding = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($Path, $Content, $encoding)
        return $true
    }
    catch {
        Write-Verbose "Failed to write cache file '$Path': $($_.Exception.Message)"
        return $false
    }
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
