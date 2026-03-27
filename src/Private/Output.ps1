function Write-Header {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console output is intentionally centralized in this file.')]
    param(
        [psobject]$RuntimeContext,
        [string]$Title = 'Unix Tools for Windows',
        [string]$Version,
        [string]$Scope,
        [string]$Mode = ''
    )

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    if (-not $PSBoundParameters.ContainsKey('Version')) {
        $Version = $RuntimeContext.Version
    }
    if (-not $PSBoundParameters.ContainsKey('Scope')) {
        $Scope = $RuntimeContext.PathScope
    }

    $ui = $RuntimeContext.Ui
    $inner = "$Title"
    $right = "v$Version"
    $modeText = if ($Mode) { "$Scope scope $($ui.Detail) $Mode" } else { "$Scope scope" }

    $contentWidth = [Math]::Max($inner.Length + $right.Length + 6, $modeText.Length + 4)
    $boxWidth = [Math]::Max($contentWidth, 48)

    $topBorder = "  $($ui.TL)$($ui.HLine * $boxWidth)$($ui.TR)"
    $bottomBorder = "  $($ui.BL)$($ui.HLine * $boxWidth)$($ui.BR)"

    $pad1 = $boxWidth - $inner.Length - $right.Length - 2
    $line1Content = " $inner$(' ' * [Math]::Max($pad1, 0))$right "

    $pad2 = $boxWidth - $modeText.Length - 1
    $line2Content = " $modeText$(' ' * [Math]::Max($pad2, 0))"

    Write-Host ''
    Write-Host $topBorder -ForegroundColor DarkCyan
    Write-Host -NoNewline "  $($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host -NoNewline $line1Content -ForegroundColor White
    Write-Host "$($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host -NoNewline "  $($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host -NoNewline $line2Content -ForegroundColor DarkGray
    Write-Host "$($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host $bottomBorder -ForegroundColor DarkCyan
    Write-Host ''
}

function Write-Section {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console output is intentionally centralized in this file.')]
    param(
        [Parameter(Mandatory)][string]$Title,
        [psobject]$RuntimeContext
    )

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    $ui = $RuntimeContext.Ui
    $lineLen = [Math]::Max(50 - $Title.Length - 2, 6)
    $section = "  $($ui.HLine * 3) $Title $($ui.HLine * $lineLen)"
    Write-Host ''
    Write-Host $section -ForegroundColor DarkCyan
    Write-Host ''
}

function Write-Status {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console output is intentionally centralized in this file.')]
    param(
        [Parameter(Mandatory)][ValidateSet('ok', 'fail', 'info', 'detail', 'warn', 'skip')][string]$Type,
        [Parameter(Mandatory)][string]$Label,
        [string]$Detail = '',
        [switch]$Indent,
        [psobject]$RuntimeContext
    )

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    $ui = $RuntimeContext.Ui
    $prefix = if ($Indent) { '    ' } else { '  ' }

    $icon = switch ($Type) {
        'ok' { $ui.Ok }
        'fail' { $ui.Fail }
        'info' { $ui.Info }
        'detail' { $ui.Detail }
        'warn' { $ui.Warn }
        'skip' { $ui.Skip }
    }
    $color = switch ($Type) {
        'ok' { 'Green' }
        'fail' { 'Red' }
        'info' { 'DarkGray' }
        'detail' { 'DarkCyan' }
        'warn' { 'Yellow' }
        'skip' { 'DarkGray' }
    }

    $labelWidth = 24
    $paddedLabel = if ($Label.Length -ge $labelWidth) { $Label } else { $Label + (' ' * ($labelWidth - $Label.Length)) }

    Write-Host -NoNewline "$prefix" -ForegroundColor White
    Write-Host -NoNewline "$icon " -ForegroundColor $color
    Write-Host -NoNewline "$paddedLabel" -ForegroundColor White
    if ($Detail) {
        Write-Host " $Detail" -ForegroundColor DarkGray
    }
    else {
        Write-Host ''
    }
}

function Write-Dim {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console output is intentionally centralized in this file.')]
    param([Parameter(Mandatory)][string]$Text, [switch]$Indent)

    $prefix = if ($Indent) { '      ' } else { '  ' }
    Write-Host "$prefix$Text" -ForegroundColor DarkGray
}

function Write-CompactList {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console output is intentionally centralized in this file.')]
    param(
        [Parameter(Mandatory)][string[]]$Items,
        [int]$MaxWidth = 70,
        [string]$Prefix = '      '
    )

    if ($Items.Count -eq 0) { return }

    $line = $Prefix
    foreach ($item in $Items) {
        if (($line.Length + $item.Length + 1) -gt $MaxWidth -and $line.Length -gt $Prefix.Length) {
            Write-Host $line -ForegroundColor DarkGray
            $line = $Prefix
        }
        $line += "$item "
    }

    if ($line.Length -gt $Prefix.Length) {
        Write-Host $line -ForegroundColor DarkGray
    }
}

function Write-Footer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console output is intentionally centralized in this file.')]
    param(
        [string]$Message = 'Done',
        [ValidateSet('ok', 'fail', 'warn')][string]$Type = 'ok',
        [psobject]$RuntimeContext
    )

    $RuntimeContext = Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext
    $ui = $RuntimeContext.Ui
    $icon = switch ($Type) {
        'ok' { $ui.Ok }
        'fail' { $ui.Fail }
        'warn' { $ui.Warn }
    }
    $color = switch ($Type) {
        'ok' { 'Green' }
        'fail' { 'Red' }
        'warn' { 'Yellow' }
    }

    $inner = " $icon $Message"
    $boxWidth = [Math]::Max($inner.Length + 2, 48)
    $pad = $boxWidth - $inner.Length

    $contentInner = "$inner$(' ' * [Math]::Max($pad, 0))"

    $topBorder = "  $($ui.TL)$($ui.HLine * $boxWidth)$($ui.TR)"
    $bottomBorder = "  $($ui.BL)$($ui.HLine * $boxWidth)$($ui.BR)"

    Write-Host ''
    Write-Host $topBorder -ForegroundColor DarkCyan
    Write-Host -NoNewline "  $($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host -NoNewline $contentInner -ForegroundColor $color
    Write-Host "$($ui.VLine)" -ForegroundColor DarkCyan
    Write-Host $bottomBorder -ForegroundColor DarkCyan
    Write-Host ''
}

function Write-DryRun {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console output is intentionally centralized in this file.')]
    param([Parameter(Mandatory)][string]$Text)

    Write-Host "  [DRYRUN] $Text" -ForegroundColor DarkGray
}

function Write-BlankLine {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console output is intentionally centralized in this file.')]
    param()

    Write-Host ''
}

function Write-AccentLine {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console output is intentionally centralized in this file.')]
    param([Parameter(Mandatory)][string]$Text)

    Write-Host $Text -ForegroundColor DarkCyan
}
