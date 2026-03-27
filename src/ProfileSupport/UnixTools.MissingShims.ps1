function Add-UnixShimIfMissing {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Body
    )

    Reset-UnixShimName -Name $Name

    $fb = $Body
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

Add-UnixShimIfMissing -Name "export" -Body {
    $Assignments = @($args)
    foreach ($item in $Assignments) {
        $parts = $item -split "=", 2
        if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0])) {
            throw "usage: export NAME=VALUE [NAME2=VALUE2 ...]"
        }
        [System.Environment]::SetEnvironmentVariable($parts[0], $parts[1], "Process")
    }
}

Add-UnixShimIfMissing -Name "rev" -Body {
    param([string[]]$Path)

    $reverseLine = {
        param([string]$line)
        if ([string]::IsNullOrEmpty($line)) { return "" }
        $chars = $line.ToCharArray()
        [array]::Reverse($chars)
        return (-join $chars)
    }

    if ($Path -and $Path.Count -gt 0) {
        Get-Content -Path $Path | ForEach-Object { & $reverseLine $_ }
    }
    else {
        $input | ForEach-Object { & $reverseLine $_ }
    }
}

Add-UnixShimIfMissing -Name "unset" -Body {
    $Names = @($args)
    foreach ($name in $Names) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            Remove-Item -Path ("Env:" + $name) -ErrorAction SilentlyContinue
        }
    }
}

Add-UnixShimIfMissing -Name "mkdirp" -Body {
    $Paths = @($args)
    foreach ($path in $Paths) {
        if (-not [string]::IsNullOrWhiteSpace($path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

Add-UnixShimIfMissing -Name "ll" -Body {
    $ArgList = @($args)
    Get-ChildItem -Force @ArgList
}

Add-UnixShimIfMissing -Name "clear-hist" -Body {
    Clear-History
    if ([type]::GetType("Microsoft.PowerShell.PSConsoleReadLine, Microsoft.PowerShell.PSReadLine")) {
        [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
    }
}

Add-UnixShimIfMissing -Name "clear" -Body {
    Clear-Host
}

Add-UnixShimIfMissing -Name "pwd" -Body {
    (Get-Location).Path
}

Add-UnixShimIfMissing -Name "history" -Body {
    $ArgList = @($args)
    $items = Get-History
    if ($ArgList.Count -gt 0) {
        $count = 0
        if ([int]::TryParse($ArgList[0], [ref]$count) -and $count -gt 0) {
            $items | Select-Object -Last $count
            return
        }
    }
    $items
}

Add-UnixShimIfMissing -Name "touch" -Body {
    $Paths = @($args)
    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if (Test-Path -Path $path) {
            (Get-Item -Path $path).LastWriteTime = Get-Date
        }
        else {
            New-Item -ItemType File -Path $path -Force | Out-Null
        }
    }
}

Add-UnixShimIfMissing -Name "head" -Body {
    $ArgList = @($args)
    $count = 10
    $paths = @()
    $i = 0
    while ($i -lt $ArgList.Count) {
        $a = $ArgList[$i]
        if ($a -eq "-n" -and $i + 1 -lt $ArgList.Count) {
            $count = [int]$ArgList[$i + 1]
            $i += 2
            continue
        }
        if ($a -match "^-n\d+$") {
            $count = [int]($a.Substring(2))
            $i++
            continue
        }
        if ($a.StartsWith("-") -and $a -ne "--") { throw "head: unsupported option $a (fallback supports -n)" }
        if ($a -ne "--") { $paths += $a }
        $i++
    }
    if ($paths.Count -gt 0) { Get-Content -Path $paths -TotalCount $count } else { @($input) | Select-Object -First $count }
}

Add-UnixShimIfMissing -Name "tail" -Body {
    $ArgList = @($args)
    $count = 10
    $follow = $false
    $paths = @()
    $i = 0
    while ($i -lt $ArgList.Count) {
        $a = $ArgList[$i]
        if ($a -eq "-n" -and $i + 1 -lt $ArgList.Count) {
            $count = [int]$ArgList[$i + 1]
            $i += 2
            continue
        }
        if ($a -match "^-n\d+$") {
            $count = [int]($a.Substring(2))
            $i++
            continue
        }
        if ($a -eq "-f") { $follow = $true; $i++; continue }
        if ($a.StartsWith("-") -and $a -ne "--") { throw "tail: unsupported option $a (fallback supports -n, -f)" }
        if ($a -ne "--") { $paths += $a }
        $i++
    }
    if ($paths.Count -eq 0) { throw "usage: tail [-n COUNT] [-f] [file...]" }
    if ($follow) { Get-Content -Path $paths -Tail $count -Wait } else { Get-Content -Path $paths -Tail $count }
}

Add-UnixShimIfMissing -Name "wc" -Body {
    $ArgList = @($args)
    $linesOnly = $false
    $wordsOnly = $false
    $files = @()
    foreach ($a in $ArgList) {
        if ($a -eq "-l") { $linesOnly = $true; continue }
        if ($a -eq "-w") { $wordsOnly = $true; continue }
        if ($a.StartsWith("-")) { throw "wc: unsupported option $a (fallback supports -l, -w)" }
        $files += $a
    }
    if ($files.Count -eq 0) { throw "usage: wc [-l] [-w] [file...]" }
    foreach ($file in $files) {
        $content = Get-Content -Path $file
        $lineCount = $content.Count
        $wordCount = ($content | Measure-Object -Word).Words
        if ($linesOnly) { "$lineCount $file" }
        elseif ($wordsOnly) { "$wordCount $file" }
        else { "$lineCount $wordCount $file" }
    }
}

function Invoke-GrepShim {
    param(
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList,
        [object[]]$InputItems,
        [switch]$SimpleMatch
    )

    $ignoreCase = $false
    $lineNumber = $false
    $invert = $false
    $recursive = $false
    $pattern = $null
    $paths = @()

    foreach ($a in $ArgList) {
        if ($a -eq "--") { continue }
        if ($a.StartsWith("--")) { throw "grep: unsupported option $a (fallback supports -i, -n, -v, -r, -R)" }
        if ($a -match '^-[A-Za-z]+$') {
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'i' { $ignoreCase = $true; break }
                    'n' { $lineNumber = $true; break }
                    'v' { $invert = $true; break }
                    'r' { $recursive = $true; break }
                    'R' { $recursive = $true; break }
                    default { throw "grep: unsupported option -$ch (fallback supports -i, -n, -v, -r, -R)" }
                }
            }
            continue
        }

        if ($null -eq $pattern) {
            $pattern = $a
        }
        else {
            $paths += $a
        }
    }

    if ([string]::IsNullOrWhiteSpace($pattern)) {
        throw "usage: grep [-i] [-n] [-v] [-r] <pattern> [file|dir ...]"
    }

    $result = $null
    $caseSensitive = -not $ignoreCase
    if ($paths.Count -gt 0) {
        if ($recursive) {
            $targets = @()
            foreach ($p in $paths) {
                if (Test-Path -Path $p -PathType Container) { $targets += (Join-Path $p "*") }
                else { $targets += $p }
            }
            $result = Select-String -Pattern $pattern -Path $targets -Recurse -SimpleMatch:$SimpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
        }
        else {
            $result = Select-String -Pattern $pattern -Path $paths -SimpleMatch:$SimpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
        }
    }
    else {
        if ($InputItems -and $InputItems.Count -gt 0) {
            $result = $InputItems | Select-String -Pattern $pattern -SimpleMatch:$SimpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert
        }
        else {
            $defaultPath = if ($recursive) { @(".\*") } else { @(".") }
            $result = Select-String -Pattern $pattern -Path $defaultPath -Recurse:$recursive -SimpleMatch:$SimpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
        }
    }

    if ($lineNumber) {
        $result | ForEach-Object { "{0}:{1}:{2}" -f $_.Path, $_.LineNumber, $_.Line }
    }
    else {
        $result
    }
}

Add-UnixShimIfMissing -Name "grep" -Body {
    $ArgList = @($args)
    Invoke-GrepShim -ArgList $ArgList -InputItems @($input)
}

Add-UnixShimIfMissing -Name "egrep" -Body {
    $ArgList = @($args)
    Invoke-GrepShim -ArgList $ArgList -InputItems @($input)
}

Add-UnixShimIfMissing -Name "fgrep" -Body {
    $ArgList = @($args)
    Invoke-GrepShim -ArgList $ArgList -InputItems @($input) -SimpleMatch
}

Add-UnixShimIfMissing -Name "rgf" -Body {
    $Pattern = $args[0]
    if (-not $Pattern) { throw "rgf: pattern required. Usage: rgf <pattern> [path ...]" }
    $Rest = @()
    if ($args.Count -gt 1) { $Rest = $args[1..($args.Count - 1)] }
    $rg = Get-PreferredApplicationCommand -Name rg
    if (-not $rg) {
        throw "rgf: ripgrep 'rg' not found. Install with -InstallOptionalTools or winget install --id BurntSushi.ripgrep.MSVC --exact."
    }
    & $rg.Source -n -F -- $Pattern @Rest
}
function Invoke-RgFallback {
    param(
        [object[]]$ArgList,
        [object[]]$InputItems
    )

    $patterns = New-Object System.Collections.Generic.List[string]
    $paths = New-Object System.Collections.Generic.List[string]
    $ignoreCase = $false
    $lineNumber = $false
    $invert = $false
    $simpleMatch = $false
    $recursive = $true

    $i = 0
    while ($i -lt $ArgList.Count) {
        $a = [string]$ArgList[$i]

        if ($a -eq "--") {
            if ($i + 1 -lt $ArgList.Count) {
                for ($j = $i + 1; $j -lt $ArgList.Count; $j++) {
                    $paths.Add([string]$ArgList[$j]) | Out-Null
                }
            }
            break
        }

        if ($a -eq "-e") {
            if ($i + 1 -ge $ArgList.Count) { throw "rg fallback: -e requires a pattern value" }
            $patterns.Add([string]$ArgList[$i + 1]) | Out-Null
            $i += 2
            continue
        }

        if ($a.StartsWith("-e") -and $a.Length -gt 2) {
            $patterns.Add($a.Substring(2)) | Out-Null
            $i++
            continue
        }

        switch ($a) {
            "-n" { $lineNumber = $true; $i++; continue }
            "--line-number" { $lineNumber = $true; $i++; continue }
            "-i" { $ignoreCase = $true; $i++; continue }
            "--ignore-case" { $ignoreCase = $true; $i++; continue }
            "-S" { $i++; continue }
            "--smart-case" { $i++; continue }
            "-F" { $simpleMatch = $true; $i++; continue }
            "--fixed-strings" { $simpleMatch = $true; $i++; continue }
            "-v" { $invert = $true; $i++; continue }
            "--invert-match" { $invert = $true; $i++; continue }
            "-r" { $recursive = $true; $i++; continue }
            "-R" { $recursive = $true; $i++; continue }
        }

        if ($a.StartsWith("--")) {
            throw "rg fallback: unsupported option $a (supports -e, -n, -i, -S, -F, -v, -r, -R). Install ripgrep for full support."
        }

        if ($a -match '^-[A-Za-z]+$') {
            $unsupported = @()
            foreach ($ch in $a.Substring(1).ToCharArray()) {
                switch ($ch) {
                    'n' { $lineNumber = $true; break }
                    'i' { $ignoreCase = $true; break }
                    'S' { break }
                    'F' { $simpleMatch = $true; break }
                    'v' { $invert = $true; break }
                    'r' { $recursive = $true; break }
                    'R' { $recursive = $true; break }
                    default { $unsupported += "-$ch"; break }
                }
            }
            if ($unsupported.Count -gt 0) {
                throw "rg fallback: unsupported option(s) $($unsupported -join ', ') (supports -e, -n, -i, -S, -F, -v, -r, -R). Install ripgrep for full support."
            }
            $i++
            continue
        }

        if ($patterns.Count -eq 0) {
            $patterns.Add($a) | Out-Null
        }
        else {
            $paths.Add($a) | Out-Null
        }
        $i++
    }

    if ($patterns.Count -eq 0) {
        throw "usage: rg [-n] [-S] [-i] [-F] [-v] [-e PATTERN ...] [PATTERN] [path ...]"
    }

    $caseSensitive = -not $ignoreCase
    $result = $null

    if ($paths.Count -gt 0) {
        $targets = @()
        foreach ($p in $paths) {
            if (Test-Path -Path $p -PathType Container) {
                $targets += (Join-Path $p "*")
            }
            else {
                $targets += $p
            }
        }
        $result = Select-String -Pattern @($patterns) -Path $targets -Recurse:$recursive -SimpleMatch:$simpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
    }
    elseif ($InputItems -and $InputItems.Count -gt 0) {
        $result = $InputItems | Select-String -Pattern @($patterns) -SimpleMatch:$simpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert
    }
    else {
        $result = Select-String -Pattern @($patterns) -Path @(".\*") -Recurse:$true -SimpleMatch:$simpleMatch -CaseSensitive:$caseSensitive -NotMatch:$invert -ErrorAction SilentlyContinue
    }

    if ($lineNumber) {
        $result | ForEach-Object { "{0}:{1}:{2}" -f $_.Path, $_.LineNumber, $_.Line }
    }
    else {
        $result
    }
}
Add-UnixShimIfMissing -Name "rgs" -Body {
    $ArgList = @($args)
    $stdinItems = @($input)
    $rg = Get-PreferredApplicationCommand -Name rg
    if (-not $rg) {
        Invoke-RgFallback -ArgList $ArgList -InputItems $stdinItems
        return
    }

    if ($stdinItems.Count -gt 0) {
        $output = $stdinItems | & $rg.Source @ArgList 2>&1
    }
    else {
        $output = & $rg.Source @ArgList 2>&1
    }
    $exit = $LASTEXITCODE
    if ($exit -eq 0) {
        $output
        return
    }

    if (-not ($ArgList -contains "--")) {
        $flagToken = $null
        foreach ($line in @($output)) {
            if ([string]$line -match "unrecognized flag (.+)$") {
                $flagToken = $matches[1].Trim()
                break
            }
        }
        if ($flagToken) {
            $idx = [Array]::IndexOf($ArgList, $flagToken)
            if ($idx -ge 0) {
                $fixedArgs = @()
                if ($idx -gt 0) { $fixedArgs += $ArgList[0..($idx - 1)] }
                $fixedArgs += "--"
                $fixedArgs += $ArgList[$idx..($ArgList.Count - 1)]
                $retry = & $rg.Source @fixedArgs 2>&1
                $retryExit = $LASTEXITCODE
                if ($retryExit -eq 0) {
                    $retry
                    return
                }
                $output = $retry
                $exit = $retryExit
            }
        }
    }

    foreach ($line in @($output)) {
        [Console]::Error.WriteLine([string]$line)
    }
    $global:LASTEXITCODE = $exit
}
if (-not (Get-Command rgl -ErrorAction SilentlyContinue)) {
    Set-Alias -Name rgl -Value rgf -Scope Global
}
Add-UnixShimIfMissing -Name "rg" -Body {
    $ArgList = @($args)
    $stdinItems = @($input)
    $rgExe = Get-PreferredApplicationCommand -Name rg
    if ($rgExe) {
        if ($stdinItems.Count -gt 0) {
            $stdinItems | & $rgExe.Source @ArgList
        }
        else {
            & $rgExe.Source @ArgList
        }
        return
    }
    Invoke-RgFallback -ArgList $ArgList -InputItems $stdinItems
}

Add-UnixShimIfMissing -Name "nc" -Body {
    $ArgList = @($args)
    $ncat = Get-PreferredApplicationCommand -Name ncat
    if (-not $ncat) {
        throw "nc: command not found. Install ncat (winget install --id Insecure.Nmap --exact)."
    }
    & $ncat.Source @ArgList
}

Add-UnixShimIfMissing -Name "which" -Body {
    $Names = @($args)
    foreach ($name in $Names) {
        $cmd = Get-PreferredApplicationCommand -Name $name
        if (-not $cmd) {
            $cmd = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        if ($cmd) {
            if ($cmd.Source) { $cmd.Source }
            elseif ($cmd.Definition) { $cmd.Definition }
            else { $cmd.Name }
        }
    }
}

Add-UnixShimIfMissing -Name "man" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: man <command>" }
    Get-Help $ArgList[0] -Full
}

Add-UnixShimIfMissing -Name "source" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: source <script> [args...]" }
    $path = $ArgList[0]
    if (-not (Test-Path $path)) { throw "source: file not found: $path" }
    $path = (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path
    if (-not $path.EndsWith('.ps1') -and -not $path.EndsWith('.psm1')) {
        Write-Warning "source: dot-sourcing non-PowerShell file: $path"
    }
    $rest = @()
    if ($ArgList.Count -gt 1) { $rest = $ArgList[1..($ArgList.Count - 1)] }
    . $path @rest
}

Add-UnixShimIfMissing -Name "apropos" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: apropos <keyword>" }
    $pattern = "*" + (($ArgList -join " ").Trim()) + "*"
    Get-Help $pattern -ErrorAction SilentlyContinue |
    Select-Object Name, Synopsis |
    Sort-Object Name
}

Add-UnixShimIfMissing -Name "make" -Body {
    $ArgList = @($args)
    $alt = @("mingw32-make", "nmake")
    foreach ($name in $alt) {
        $cmd = Get-PreferredApplicationCommand -Name $name
        if ($cmd) {
            & $cmd.Source @ArgList
            return
        }
    }
    throw "make: command not found. Install make or run with -AddMingw so mingw32-make can be discovered."
}

Add-UnixShimIfMissing -Name "open" -Body {
    $ArgList = @($args)
    $dangerousSchemes = @('javascript', 'vbscript', 'data', 'shell')
    if ($ArgList.Count -eq 0) {
        Write-Verbose "open: launching current directory"
        Start-Process -FilePath "."
        return
    }
    foreach ($target in $ArgList) {
        foreach ($scheme in $dangerousSchemes) {
            if ($target -match "^${scheme}:") {
                throw "open: blocked potentially dangerous URI scheme '${scheme}:'"
            }
        }
        Write-Verbose "open: launching '$target'"
        Start-Process -FilePath $target
    }
}

Add-UnixShimIfMissing -Name "xdg-open" -Body {
    $ArgList = @($args)
    open @ArgList
}

Add-UnixShimIfMissing -Name "rename" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -ne 2) { throw "usage: rename <old-path> <new-name|new-path>" }
    $oldPath = $ArgList[0]
    $newSpec = $ArgList[1]
    if ($newSpec -match '[\\/]' -or [System.IO.Path]::IsPathRooted($newSpec)) {
        Move-Item -Path $oldPath -Destination $newSpec -Force
    }
    else {
        Rename-Item -Path $oldPath -NewName $newSpec -Force
    }
}

Add-UnixShimIfMissing -Name "dos2unix" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: dos2unix <file...>" }
    foreach ($path in $ArgList) {
        $text = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        $out = ($text -replace "`r`n", "`n") -replace "`r", "`n"
        Set-Content -LiteralPath $path -Value $out -NoNewline -Encoding utf8NoBOM
    }
}

Add-UnixShimIfMissing -Name "unix2dos" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: unix2dos <file...>" }
    foreach ($path in $ArgList) {
        $text = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        $normalized = ($text -replace "`r`n", "`n") -replace "`r", "`n"
        $out = $normalized -replace "`n", "`r`n"
        Set-Content -LiteralPath $path -Value $out -NoNewline -Encoding utf8NoBOM
    }
}

Add-UnixShimIfMissing -Name "vdir" -Body {
    $ArgList = @($args)
    Get-ChildItem -Force @ArgList | Format-Table Mode, LastWriteTime, Length, Name -AutoSize
}

Add-UnixShimIfMissing -Name "link" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -ne 2) { throw "usage: link <target> <linkpath>" }
    New-Item -ItemType HardLink -Path $ArgList[1] -Target $ArgList[0] -Force | Out-Null
}

Add-UnixShimIfMissing -Name "tput" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) { throw "usage: tput <clear|reset|cols|lines>" }
    switch ($ArgList[0]) {
        "clear" { Clear-Host; return }
        "reset" { Clear-Host; return }
        "cols" { [Console]::WindowWidth; return }
        "lines" { [Console]::WindowHeight; return }
        default { throw "tput: fallback supports clear, reset, cols, lines" }
    }
}

Add-UnixShimIfMissing -Name "sync" -Body {
    [GC]::Collect()
}

Add-UnixShimIfMissing -Name "at" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -lt 2) { throw "usage: at HH:mm <command...>" }
    $time = $ArgList[0]
    if ($time -notmatch '^([01]\d|2[0-3]):[0-5]\d$') { throw "at: time format must be HH:mm (24-hour, e.g. 09:30 or 14:00)" }
    $commandText = ($ArgList[1..($ArgList.Count - 1)] -join " ")
    $taskName = "unix-at-" + ([guid]::NewGuid().ToString("N").Substring(0, 8))
    $escapedCmd = $commandText -replace '"', '\"'
    $wrappedCommand = "cmd /c `"$escapedCmd`" & schtasks /Delete /TN $taskName /F"
    & schtasks /Create /SC ONCE /TN $taskName /TR "`"$wrappedCommand`"" /ST $time /F | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "at: failed to create scheduled task." }
    Write-Output $taskName
}

Add-UnixShimIfMissing -Name "aspell" -Body {
    throw "aspell: fallback unavailable. Install aspell and re-run setup to get executable pass-through."
}

Add-UnixShimIfMissing -Name "bc" -Body {
    $ArgList = @($args)
    $expr = if ($ArgList.Count -gt 0) { $ArgList -join " " } else { ($input | Out-String).Trim() }
    if ([string]::IsNullOrWhiteSpace($expr)) { throw "usage: bc <expression>" }
    if ($expr -notmatch '^[\d\s\+\-\*/\(\)\.,]+$') {
        throw "bc: expression contains disallowed characters (only digits, operators, parens, decimal allowed)"
    }
    $table = New-Object System.Data.DataTable
    $result = $table.Compute($expr, $null)
    Write-Output $result
}

Add-UnixShimIfMissing -Name "base64" -Body {
    $ArgList = @($args)
    $decode = $false
    $wrap = 76
    $files = @()
    $i = 0
    while ($i -lt $ArgList.Count) {
        $a = $ArgList[$i]
        if ($a -eq "--") { $i++; continue }
        if ($a -eq "-d" -or $a -eq "--decode") { $decode = $true; $i++; continue }
        if ($a -eq "-w" -and $i + 1 -lt $ArgList.Count) { $wrap = [int]$ArgList[$i + 1]; $i += 2; continue }
        if ($a.StartsWith("-")) { throw "base64: unsupported option $a (fallback supports -d/--decode, -w N)" }
        $files += $a
        $i++
    }

    if ($decode) {
        $encoded = if ($files.Count -gt 0) {
            Get-Content -LiteralPath $files[0] -Raw -ErrorAction Stop
        }
        else {
            (@($input) -join "`n")
        }
        $clean = ($encoded -replace '\s+', '')
        if ([string]::IsNullOrWhiteSpace($clean)) { return }
        [byte[]]$decodedBytes = [Convert]::FromBase64String($clean)
        $stdout = [Console]::OpenStandardOutput()
        $stdout.Write($decodedBytes, 0, $decodedBytes.Length)
        return
    }

    [byte[]]$bytes = if ($files.Count -gt 0) {
        [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $files[0]).Path)
    }
    else {
        [System.Text.Encoding]::UTF8.GetBytes((@($input) -join "`n"))
    }

    $encodedOut = [Convert]::ToBase64String($bytes)
    if ($wrap -gt 0) {
        for ($pos = 0; $pos -lt $encodedOut.Length; $pos += $wrap) {
            $len = [Math]::Min($wrap, $encodedOut.Length - $pos)
            $encodedOut.Substring($pos, $len)
        }
    }
    else {
        $encodedOut
    }
}

Add-UnixShimIfMissing -Name "base32" -Body {
    throw "base32: fallback unavailable. Install a real base32 tool (Git coreutils/busybox) for full support."
}

Add-UnixShimIfMissing -Name "cksum" -Body {
    $ArgList = @($args)

    function Get-Crc32Value {
        param([byte[]]$Bytes)
        $crc = [uint32]0xFFFFFFFF
        foreach ($b in $Bytes) {
            $crc = $crc -bxor [uint32]$b
            for ($j = 0; $j -lt 8; $j++) {
                if (($crc -band 1) -ne 0) {
                    $crc = ($crc -shr 1) -bxor [uint32]0xEDB88320
                }
                else {
                    $crc = $crc -shr 1
                }
            }
        }
        return (-bnot $crc) -band [uint32]0xFFFFFFFF
    }

    $targets = if ($ArgList.Count -gt 0) { $ArgList } else { @() }
    if ($targets.Count -eq 0) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes((@($input) -join "`n"))
        $crc = Get-Crc32Value -Bytes $bytes
        "{0} {1}" -f $crc, $bytes.Length
        return
    }

    foreach ($path in $targets) {
        $resolved = (Resolve-Path -LiteralPath $path).Path
        $bytes = [System.IO.File]::ReadAllBytes($resolved)
        $crc = Get-Crc32Value -Bytes $bytes
        "{0} {1} {2}" -f $crc, $bytes.Length, $path
    }
}

Add-UnixShimIfMissing -Name "sum" -Body {
    $ArgList = @($args)
    cksum @ArgList
}

Add-UnixShimIfMissing -Name "pv" -Body {
    $ArgList = @($args)
    $count = 0L
    $start = Get-Date
    foreach ($item in $input) {
        $line = [string]$item
        $count += [System.Text.Encoding]::UTF8.GetByteCount($line + [Environment]::NewLine)
        $item
    }
    $elapsed = (Get-Date) - $start
    Write-Host ("[pv fallback] transferred {0} bytes in {1:n2}s" -f $count, $elapsed.TotalSeconds) -ForegroundColor DarkGray
}

Add-UnixShimIfMissing -Name "pr" -Body {
    $ArgList = @($args)
    if ($ArgList.Count -eq 0) {
        $i = 1
        foreach ($line in $input) {
            "{0,6}  {1}" -f $i, $line
            $i++
        }
        return
    }
    foreach ($path in $ArgList) {
        "==== {0} ====" -f $path
        $i = 1
        Get-Content -LiteralPath $path | ForEach-Object {
            "{0,6}  {1}" -f $i, $_
            $i++
        }
    }
}

Add-UnixShimIfMissing -Name "cpio" -Body {
    throw "cpio: fallback unavailable. Install cpio executable to use this command."
}

Add-UnixShimIfMissing -Name "cal" -Body {
    $ArgList = @($args)
    $now = Get-Date
    $month = $now.Month
    $year = $now.Year
    if ($ArgList.Count -eq 1) { $month = [int]$ArgList[0] }
    if ($ArgList.Count -ge 2) { $year = [int]$ArgList[1] }
    $first = [datetime]::new($year, $month, 1)
    $days = [datetime]::DaysInMonth($year, $month)
    "{0} {1}" -f $first.ToString("MMMM"), $year
    "Su Mo Tu We Th Fr Sa"
    $offset = [int]$first.DayOfWeek
    $line = ("   " * $offset)
    for ($d = 1; $d -le $days; $d++) {
        $line += ("{0,2} " -f $d)
        if ((($offset + $d) % 7) -eq 0) {
            $line.TrimEnd()
            $line = ""
        }
    }
    if ($line.Trim().Length -gt 0) { $line.TrimEnd() }
}

