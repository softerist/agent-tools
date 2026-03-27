function Set-UnixCommand {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Fallback
    )

    Reset-UnixShimName -Name $Name
    $fb = $Fallback
    $wrapper = {
        $commandName = $MyInvocation.MyCommand.Name
        $app = Get-UnixShimExecutable -Name $commandName
        if ($app) {
            if ($MyInvocation.ExpectingInput) {
                $input | & $app.Source @args
            }
            else {
                & $app.Source @args
            }
            return
        }

        if ($MyInvocation.ExpectingInput) {
            $input | & $fb @args
        }
        else {
            & $fb @args
        }
    }.GetNewClosure()

    Set-Item -Path ("Function:\Global:" + $Name) -Value $wrapper
}

function Show-UnsupportedFlag {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$Flag,
        [Parameter(Mandatory = $true)][string]$SupportedFlags,
        [Parameter(Mandatory = $true)][string]$Usage
    )

    $message = @(
        "$($Command): unsupported option '$Flag'",
        "Supported flags in fallback: $SupportedFlags",
        "",
        "Tip: run Show-UnixCoverageReport -IncludeMissing to see command/flag coverage.",
        "",
        "How to add support for this flag:",
        "1) Open `$PROFILE and find marker: # >>> unix-tools-alias-compat >>>",
        "2) Find: Set-UnixCommand -Name '$Command' -Fallback { ... }",
        "3) Extend that parser switch/if to handle '$Flag'",
        "4) Or update installer block and re-run: Enable-UnixToolsSystemWide.ps1 -InstallProfileShims",
        "",
        "Usage: $Usage"
    ) -join [Environment]::NewLine

    throw $message
}

$script:UnixFallbackCoverage = [ordered]@{
    rm    = [ordered]@{ CoveredFlags = "-r, -R, -f, --"; UnsupportedFlags = "Any other short/long option" }
    cp    = [ordered]@{ CoveredFlags = "-r, -R, -f, -n, --"; UnsupportedFlags = "Any other short/long option" }
    mv    = [ordered]@{ CoveredFlags = "-f, -n, --"; UnsupportedFlags = "Any other short/long option" }
    mkdir = [ordered]@{ CoveredFlags = "-p, -v, --"; UnsupportedFlags = "Any other short/long option" }
    ls    = [ordered]@{ CoveredFlags = "-a, -l, -t, -r, -h, --"; UnsupportedFlags = "Any other short/long option" }
    cat   = [ordered]@{ CoveredFlags = "-n, -s, --"; UnsupportedFlags = "Any other short/long option" }
    sort  = [ordered]@{ CoveredFlags = "-u, -r, -n, -f, --"; UnsupportedFlags = "Any other short/long option" }
    diff  = [ordered]@{ CoveredFlags = "-u, -q, --"; UnsupportedFlags = "Any other short/long option" }
    tee   = [ordered]@{ CoveredFlags = "-a, -i, --"; UnsupportedFlags = "Any other short/long option" }
    sleep = [ordered]@{ CoveredFlags = "NUMBER[s|m|h|d]"; UnsupportedFlags = "Invalid value or unsupported suffix" }
}

$script:UnixMissingShimCoverage = [ordered]@{
    export       = [ordered]@{ CoveredFlags = "NAME=VALUE [NAME2=VALUE2 ...]"; UnsupportedFlags = "N/A (assignment syntax fallback)" }
    rev          = [ordered]@{ CoveredFlags = "[file ...] or stdin"; UnsupportedFlags = "N/A (line reverse fallback)" }
    unset        = [ordered]@{ CoveredFlags = "NAME [NAME2 ...]"; UnsupportedFlags = "N/A (name list fallback)" }
    mkdirp       = [ordered]@{ CoveredFlags = "<dir ...>"; UnsupportedFlags = "N/A (compat wrapper)" }
    ll           = [ordered]@{ CoveredFlags = "[path ...]"; UnsupportedFlags = "N/A (compat wrapper)" }
    'clear-hist' = [ordered]@{ CoveredFlags = "(no flags)"; UnsupportedFlags = "All flags unsupported" }
    clear        = [ordered]@{ CoveredFlags = "(no flags)"; UnsupportedFlags = "All flags unsupported" }
    pwd          = [ordered]@{ CoveredFlags = "(no flags)"; UnsupportedFlags = "All flags unsupported" }
    history      = [ordered]@{ CoveredFlags = "[count]"; UnsupportedFlags = "Any flag option" }
    touch        = [ordered]@{ CoveredFlags = "<file ...>"; UnsupportedFlags = "Any flag option" }
    head         = [ordered]@{ CoveredFlags = "-n, -nCOUNT"; UnsupportedFlags = "Any other short/long option" }
    tail         = [ordered]@{ CoveredFlags = "-n, -nCOUNT, -f"; UnsupportedFlags = "Any other short/long option" }
    wc           = [ordered]@{ CoveredFlags = "-l, -w"; UnsupportedFlags = "Any other short/long option" }
    grep         = [ordered]@{ CoveredFlags = "-i, -n, -v, -r, -R"; UnsupportedFlags = "Any other short/long option" }
    egrep        = [ordered]@{ CoveredFlags = "-i, -n, -v, -r, -R"; UnsupportedFlags = "Any other short/long option" }
    fgrep        = [ordered]@{ CoveredFlags = "-i, -n, -v, -r, -R"; UnsupportedFlags = "Any other short/long option" }
    rgf          = [ordered]@{ CoveredFlags = "<pattern> [path ...] (fixed string, line numbers)"; UnsupportedFlags = "Delegated to rg executable" }
    rgl          = [ordered]@{ CoveredFlags = "Alias to rgf"; UnsupportedFlags = "Same as rgf" }
    rgs          = [ordered]@{ CoveredFlags = "[rg args...] passthrough to rg executable with Select-String fallback"; UnsupportedFlags = "Fallback mode supports -e, -n, -i, -S, -F, -v, -r, -R only" }
    rg           = [ordered]@{ CoveredFlags = "Uses rg executable when present; fallback supports -e, -n, -i, -S, -F, -v, -r, -R"; UnsupportedFlags = "Fallback mode supports a subset of rg flags" }
    nc           = [ordered]@{ CoveredFlags = "[ncat-compatible args...]"; UnsupportedFlags = "Delegated to ncat when installed" }
    which        = [ordered]@{ CoveredFlags = "<command ...>"; UnsupportedFlags = "Any flag option" }
    man          = [ordered]@{ CoveredFlags = "<command>"; UnsupportedFlags = "Any flag option" }
    source       = [ordered]@{ CoveredFlags = "<script> [args...]"; UnsupportedFlags = "Any flag option" }
    apropos      = [ordered]@{ CoveredFlags = "<keyword>"; UnsupportedFlags = "Any flag option" }
    make         = [ordered]@{ CoveredFlags = "[make args...]"; UnsupportedFlags = "Delegated to mingw32-make/nmake when available" }
    open         = [ordered]@{ CoveredFlags = "[path|url ...]"; UnsupportedFlags = "Any flag option" }
    'xdg-open'   = [ordered]@{ CoveredFlags = "[path|url ...]"; UnsupportedFlags = "Any flag option" }
    rename       = [ordered]@{ CoveredFlags = "<old-path> <new-name|new-path>"; UnsupportedFlags = "Any flag option" }
    dos2unix     = [ordered]@{ CoveredFlags = "<file ...>"; UnsupportedFlags = "Any flag option" }
    unix2dos     = [ordered]@{ CoveredFlags = "<file ...>"; UnsupportedFlags = "Any flag option" }
    vdir         = [ordered]@{ CoveredFlags = "[path ...]"; UnsupportedFlags = "Any flag option" }
    link         = [ordered]@{ CoveredFlags = "<target> <linkpath>"; UnsupportedFlags = "Any flag option" }
    tput         = [ordered]@{ CoveredFlags = "clear|reset|cols|lines"; UnsupportedFlags = "Any other capability token" }
    sync         = [ordered]@{ CoveredFlags = "(no flags)"; UnsupportedFlags = "All flags unsupported" }
    at           = [ordered]@{ CoveredFlags = "HH:mm <command...>"; UnsupportedFlags = "Any other syntax" }
    aspell       = [ordered]@{ CoveredFlags = "(none in fallback)"; UnsupportedFlags = "Fallback unavailable (install executable)" }
    bc           = [ordered]@{ CoveredFlags = "<expression>"; UnsupportedFlags = "Any flag option" }
    base64       = [ordered]@{ CoveredFlags = "-d, --decode, -w N, [file]"; UnsupportedFlags = "Any other short/long option" }
    base32       = [ordered]@{ CoveredFlags = "(none in fallback)"; UnsupportedFlags = "Fallback unavailable (install executable)" }
    cksum        = [ordered]@{ CoveredFlags = "[file ...] or stdin"; UnsupportedFlags = "Any flag option" }
    sum          = [ordered]@{ CoveredFlags = "[file ...] or stdin"; UnsupportedFlags = "Any flag option" }
    pv           = [ordered]@{ CoveredFlags = "stdin passthrough"; UnsupportedFlags = "Any flag option" }
    pr           = [ordered]@{ CoveredFlags = "[file ...] or stdin"; UnsupportedFlags = "Any flag option" }
    cpio         = [ordered]@{ CoveredFlags = "(none in fallback)"; UnsupportedFlags = "Fallback unavailable (install executable)" }
    cal          = [ordered]@{ CoveredFlags = "[month] [year]"; UnsupportedFlags = "Any flag option" }
}

function Convert-UnixCoverageEntry {
    param([Parameter(Mandatory = $true)]$Entry)

    if ($Entry -is [string]) {
        return [pscustomobject]@{
            CoveredFlags     = $Entry
            UnsupportedFlags = "Any unsupported option gets friendly guidance"
        }
    }

    $covered = ""
    $unsupported = "Any unsupported option gets friendly guidance"
    if ($Entry.PSObject.Properties['CoveredFlags']) { $covered = [string]$Entry.CoveredFlags }
    if ($Entry.PSObject.Properties['UnsupportedFlags']) { $unsupported = [string]$Entry.UnsupportedFlags }

    [pscustomobject]@{
        CoveredFlags     = $covered
        UnsupportedFlags = $unsupported
    }
}

function Get-UnixFallbackCoverage {
    $script:UnixFallbackCoverage.GetEnumerator() | ForEach-Object {
        $normalized = Convert-UnixCoverageEntry -Entry $_.Value
        [pscustomobject]@{
            Command          = $_.Key
            CoveredFlags     = $normalized.CoveredFlags
            UnsupportedFlags = $normalized.UnsupportedFlags
        }
    }
}

function Get-UnixCoverageReport {
    param([switch]$IncludeMissing)

    $catalog = New-Object System.Collections.Generic.List[object]
    foreach ($e in $script:UnixFallbackCoverage.GetEnumerator()) {
        $normalized = Convert-UnixCoverageEntry -Entry $e.Value
        $catalog.Add([pscustomobject]@{
                Command          = $e.Key
                Group            = "alias-compat"
                CoveredFlags     = $normalized.CoveredFlags
                UnsupportedFlags = $normalized.UnsupportedFlags
            }) | Out-Null
    }

    if ($IncludeMissing) {
        foreach ($e in $script:UnixMissingShimCoverage.GetEnumerator()) {
            $normalized = Convert-UnixCoverageEntry -Entry $e.Value
            $catalog.Add([pscustomobject]@{
                    Command          = $e.Key
                    Group            = "missing-shim"
                    CoveredFlags     = $normalized.CoveredFlags
                    UnsupportedFlags = $normalized.UnsupportedFlags
                }) | Out-Null
        }
    }

    $commandCache = @{}
    $uniqueNames = $catalog | Select-Object -ExpandProperty Command -Unique
    foreach ($n in $uniqueNames) {
        $commandCache[$n] = @(Get-Command $n -All -ErrorAction SilentlyContinue)
    }

    foreach ($item in $catalog) {
        $name = $item.Command
        $all = @()
        if ($commandCache.ContainsKey($name)) { $all = @($commandCache[$name]) }
        $resolution = "missing"
        $source = ""

        if ($all.Count -gt 0) {
            $app = $all | Where-Object { $_.CommandType -eq "Application" } | Select-Object -First 1
            if ($app) {
                $resolution = "pass-through"
                $source = $app.Source
            }
            else {
                $fn = $all | Where-Object { $_.CommandType -eq "Function" } | Select-Object -First 1
                if ($fn) {
                    $resolution = "fallback"
                    $source = "Function:$($fn.Name)"
                }
                else {
                    $alias = $all | Where-Object { $_.CommandType -eq "Alias" } | Select-Object -First 1
                    if ($alias) {
                        $resolution = "alias"
                        $source = "Alias->$($alias.Definition)"
                    }
                    else {
                        $first = $all | Select-Object -First 1
                        $resolution = $first.CommandType.ToString().ToLowerInvariant()
                        if ($first.Source) { $source = $first.Source }
                        elseif ($first.Definition) { $source = $first.Definition }
                    }
                }
            }
        }

        $passThroughFlags = switch ($resolution) {
            "pass-through" { "All executable flags pass through" }
            "alias" { "Alias target decides" }
            default { "-" }
        }

        $effectiveUnsupportedFlags = switch ($resolution) {
            "pass-through" { "-" }
            "alias" { "Depends on alias target implementation" }
            "fallback" { $item.UnsupportedFlags }
            default { "Command not currently available" }
        }

        $unsupportedBehavior = switch ($resolution) {
            "pass-through" { "Delegated to executable behavior" }
            "fallback" { "Friendly message + add-support guidance" }
            "alias" { "Depends on alias target implementation" }
            default { "Command not currently available" }
        }

        [pscustomobject]@{
            Command             = $name
            Group               = $item.Group
            Resolution          = $resolution
            CoveredFlags        = $item.CoveredFlags
            PassThroughFlags    = $passThroughFlags
            UnsupportedFlags    = $effectiveUnsupportedFlags
            UnsupportedBehavior = $unsupportedBehavior
            Source              = $source
        }
    }
}

function Show-UnixCoverageReport {
    param([switch]$IncludeMissing)
    Get-UnixCoverageReport -IncludeMissing:$IncludeMissing |
    Sort-Object Group, Command |
    Format-Table Command, Group, Resolution, CoveredFlags, PassThroughFlags, UnsupportedFlags -AutoSize
}

Set-UnixCommand -Name "rm" -Fallback {
    $ArgList = @($args)
    $recurse = $false
    $force = $false
    $paths = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "rm" -Flag $a -SupportedFlags "-r, -R, -f, --" -Usage "rm [-rf] [--] <path...>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'r' { $recurse = $true; break }
                    'R' { $recurse = $true; break }
                    'f' { $force = $true; break }
                    default { Show-UnsupportedFlag -Command "rm" -Flag ("-" + $ch) -SupportedFlags "-r, -R, -f, --" -Usage "rm [-rf] [--] <path...>" }
                }
            }
        }
        else {
            $paths += $a
        }
    }
    if ($paths.Count -eq 0) { throw "usage: rm [-rf] [--] <path...>" }
    Write-Verbose "rm: removing $($paths.Count) path(s): $($paths -join ', ') (recurse=$recurse, force=$force)"
    Remove-Item -Path $paths -Recurse:$recurse -Force:$force
}

Set-UnixCommand -Name "cp" -Fallback {
    $ArgList = @($args)
    $recurse = $false
    $force = $false
    $noClobber = $false
    $items = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "cp" -Flag $a -SupportedFlags "-r, -R, -f, -n, --" -Usage "cp [-rfn] [--] <src...> <dest>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'r' { $recurse = $true; break }
                    'R' { $recurse = $true; break }
                    'f' { $force = $true; break }
                    'n' { $noClobber = $true; break }
                    default { Show-UnsupportedFlag -Command "cp" -Flag ("-" + $ch) -SupportedFlags "-r, -R, -f, -n, --" -Usage "cp [-rfn] [--] <src...> <dest>" }
                }
            }
        }
        else {
            $items += $a
        }
    }
    if ($items.Count -lt 2) { throw "usage: cp [-rfn] [--] <src...> <dest>" }
    $dest = $items[-1]
    $src = $items[0..($items.Count - 2)]

    if (-not $noClobber) {
        Copy-Item -Path $src -Destination $dest -Recurse:$recurse -Force:$force
        return
    }

    foreach ($s in $src) {
        $target = $dest
        if (Test-Path -Path $dest -PathType Container) {
            $target = Join-Path $dest (Split-Path -Leaf $s)
        }
        if (Test-Path -Path $target) { continue }
        Copy-Item -Path $s -Destination $dest -Recurse:$recurse -Force:$force
    }
}

Set-UnixCommand -Name "mv" -Fallback {
    $ArgList = @($args)
    $force = $false
    $noClobber = $false
    $items = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "mv" -Flag $a -SupportedFlags "-f, -n, --" -Usage "mv [-fn] [--] <src...> <dest>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'f' { $force = $true; break }
                    'n' { $noClobber = $true; break }
                    default { Show-UnsupportedFlag -Command "mv" -Flag ("-" + $ch) -SupportedFlags "-f, -n, --" -Usage "mv [-fn] [--] <src...> <dest>" }
                }
            }
        }
        else {
            $items += $a
        }
    }
    if ($items.Count -lt 2) { throw "usage: mv [-fn] [--] <src...> <dest>" }
    $dest = $items[-1]
    $src = $items[0..($items.Count - 2)]
    if (-not $noClobber) {
        Move-Item -Path $src -Destination $dest -Force:$force
        return
    }

    foreach ($s in $src) {
        $target = $dest
        if (Test-Path -Path $dest -PathType Container) {
            $target = Join-Path $dest (Split-Path -Leaf $s)
        }
        if (Test-Path -Path $target) { continue }
        Move-Item -Path $s -Destination $dest -Force:$force
    }
}

Set-UnixCommand -Name "mkdir" -Fallback {
    $ArgList = @($args)
    $p = $false
    $verbose = $false
    $paths = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "mkdir" -Flag $a -SupportedFlags "-p, -v, --" -Usage "mkdir [-pv] [--] <dir...>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'p' { $p = $true; break }
                    'v' { $verbose = $true; break }
                    default { Show-UnsupportedFlag -Command "mkdir" -Flag ("-" + $ch) -SupportedFlags "-p, -v, --" -Usage "mkdir [-pv] [--] <dir...>" }
                }
            }
        }
        else {
            $paths += $a
        }
    }
    if ($paths.Count -eq 0) { throw "usage: mkdir [-pv] [--] <dir...>" }
    foreach ($path in $paths) {
        New-Item -ItemType Directory -Path $path -Force:$p | Out-Null
        if ($verbose) { "mkdir: created directory '$path'" }
    }
}

Set-UnixCommand -Name "ls" -Fallback {
    $ArgList = @($args)
    $all = $false
    $long = $false
    $sortTime = $false
    $reverse = $false
    $paths = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "ls" -Flag $a -SupportedFlags "-a, -l, -t, -r, -h, --" -Usage "ls [-lathr] [--] [path...]"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'a' { $all = $true; break }
                    'l' { $long = $true; break }
                    't' { $sortTime = $true; break }
                    'r' { $reverse = $true; break }
                    'h' { break }
                    default { Show-UnsupportedFlag -Command "ls" -Flag ("-" + $ch) -SupportedFlags "-a, -l, -t, -r, -h, --" -Usage "ls [-lathr] [--] [path...]" }
                }
            }
        }
        else {
            $paths += $a
        }
    }
    if ($paths.Count -eq 0) { $paths = @(".") }
    $items = Get-ChildItem -Path $paths -Force:$all
    if ($sortTime) { $items = $items | Sort-Object LastWriteTime -Descending }
    if ($reverse) {
        $arr = @($items)
        if ($arr.Count -gt 1) { [array]::Reverse($arr) }
        $items = $arr
    }
    if ($long) {
        $rows = $items | ForEach-Object {
            $displayName = $_.Name
            $target = $null
            if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                if ($_.PSObject.Properties.Match('LinkTarget').Count -gt 0) { $target = $_.LinkTarget }
                if (-not $target -and $_.PSObject.Properties.Match('Target').Count -gt 0) { $target = $_.Target }
                if ($target -is [array]) { $target = $target -join ", " }
                if ($target) { $displayName = "$displayName -> $target" }
            }
            [pscustomobject]@{
                Mode          = $_.Mode
                LastWriteTime = $_.LastWriteTime
                Length        = if ($_.PSIsContainer) { '' } else { $_.Length }
                Name          = $displayName
            }
        }
        $rows | Format-Table Mode, LastWriteTime, Length, Name -AutoSize
    }
    else {
        $items
    }
}

Set-UnixCommand -Name "cat" -Fallback {
    $ArgList = @($args)
    $number = $false
    $squeezeBlank = $false
    $paths = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "cat" -Flag $a -SupportedFlags "-n, -s, --" -Usage "cat [-ns] [--] [file...]"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'n' { $number = $true; break }
                    's' { $squeezeBlank = $true; break }
                    default { Show-UnsupportedFlag -Command "cat" -Flag ("-" + $ch) -SupportedFlags "-n, -s, --" -Usage "cat [-ns] [--] [file...]" }
                }
            }
            continue
        }
        $paths += $a
    }

    $lines = if ($paths.Count -gt 0) { Get-Content -Path $paths } else { @($input) }
    if ($squeezeBlank) {
        $out = New-Object System.Collections.Generic.List[string]
        $prevBlank = $false
        foreach ($line in $lines) {
            $isBlank = [string]::IsNullOrWhiteSpace($line)
            if ($isBlank -and $prevBlank) { continue }
            $out.Add($line)
            $prevBlank = $isBlank
        }
        $lines = $out
    }
    if ($number) {
        $i = 0
        $lines | ForEach-Object { $i++; "{0,6}  {1}" -f $i, $_ }
    }
    else {
        $lines
    }
}

Set-UnixCommand -Name "sort" -Fallback {
    $ArgList = @($args)
    $unique = $false
    $descending = $false
    $numeric = $false
    $ignoreCase = $false
    $paths = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "sort" -Flag $a -SupportedFlags "-u, -r, -n, -f, --" -Usage "sort [-urnf] [--] [file...]"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'u' { $unique = $true; break }
                    'r' { $descending = $true; break }
                    'n' { $numeric = $true; break }
                    'f' { $ignoreCase = $true; break }
                    default { Show-UnsupportedFlag -Command "sort" -Flag ("-" + $ch) -SupportedFlags "-u, -r, -n, -f, --" -Usage "sort [-urnf] [--] [file...]" }
                }
            }
            continue
        }
        $paths += $a
    }

    $lines = if ($paths.Count -gt 0) { Get-Content -Path $paths } else { @($input) }
    $opts = @{}
    if ($unique) { $opts.Unique = $true }
    if ($descending) { $opts.Descending = $true }
    $opts.CaseSensitive = -not $ignoreCase

    if ($numeric) {
        $sorted = $lines | Sort-Object { [double]($_ -as [double]) } @opts
    }
    else {
        $sorted = $lines | Sort-Object @opts
    }
    $sorted
}

Set-UnixCommand -Name "diff" -Fallback {
    $ArgList = @($args)
    $files = @()
    $brief = $false
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "diff" -Flag $a -SupportedFlags "-u, -q, --" -Usage "diff [-uq] [--] <file1> <file2>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'u' { break }
                    'q' { $brief = $true; break }
                    default { Show-UnsupportedFlag -Command "diff" -Flag ("-" + $ch) -SupportedFlags "-u, -q, --" -Usage "diff [-uq] [--] <file1> <file2>" }
                }
            }
            continue
        }
        $files += $a
    }
    if ($files.Count -lt 2) { throw "usage: diff [-uq] [--] <file1> <file2>" }
    $result = Compare-Object -ReferenceObject (Get-Content -Path $files[0]) -DifferenceObject (Get-Content -Path $files[1])
    if ($brief) {
        if ($result) { "Files $($files[0]) and $($files[1]) differ" }
        return
    }
    $result
}

Set-UnixCommand -Name "tee" -Fallback {
    $ArgList = @($args)
    $append = $false
    $files = @()
    $parseOptions = $true
    foreach ($a in $ArgList) {
        if ($parseOptions -and $a -eq "--") {
            $parseOptions = $false
            continue
        }
        if ($parseOptions -and $a.StartsWith("--")) {
            Show-UnsupportedFlag -Command "tee" -Flag $a -SupportedFlags "-a, -i, --" -Usage "tee [-ai] [--] <file...>"
            continue
        }
        if ($parseOptions -and $a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'a' { $append = $true; break }
                    'i' { break }
                    default { Show-UnsupportedFlag -Command "tee" -Flag ("-" + $ch) -SupportedFlags "-a, -i, --" -Usage "tee [-ai] [--] <file...>" }
                }
            }
            continue
        }
        $files += $a
    }

    $lines = @($input)
    if ($files.Count -eq 0) { return $lines }
    foreach ($file in $files) {
        if ($append) { $lines | Add-Content -Path $file }
        else { $lines | Set-Content -Path $file }
    }
    $lines
}

Set-UnixCommand -Name "sleep" -Fallback {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: sleep <seconds>" }
    if ($ArgList[0].StartsWith("-")) {
        Show-UnsupportedFlag -Command "sleep" -Flag $ArgList[0] -SupportedFlags "NUMBER[s|m|h|d]" -Usage "sleep <seconds>|<number>[s|m|h|d]"
        return
    }
    $spec = $ArgList[0]
    $m = [regex]::Match($spec, '^\s*(?<n>\d+(?:\.\d+)?)(?<u>[smhd]?)\s*$')
    if (-not $m.Success) {
        Show-UnsupportedFlag -Command "sleep" -Flag $spec -SupportedFlags "NUMBER[s|m|h|d]" -Usage "sleep <seconds>|<number>[s|m|h|d]"
        return
    }
    $seconds = [double]$m.Groups['n'].Value
    switch ($m.Groups['u'].Value) {
        'm' { $seconds *= 60; break }
        'h' { $seconds *= 3600; break }
        'd' { $seconds *= 86400; break }
        default { }
    }
    Start-Sleep -Seconds $seconds
}

