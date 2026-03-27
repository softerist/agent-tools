function Get-EnableUnixToolsScriptValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )

    $value = Get-Variable -Scope Script -Name $Name -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $value) {
        return $Default
    }

    return $value
}

function Get-DefaultEnableUnixToolsUi {
    return [pscustomobject]@{
        TL     = '+'
        TR     = '+'
        BL     = '+'
        BR     = '+'
        HLine  = '-'
        VLine  = '|'
        Ok     = '+'
        Fail   = 'x'
        Info   = 'i'
        Detail = '>'
        Warn   = '!'
        Skip   = '-'
        Arrow  = '->'
    }
}

function New-EnableUnixToolsRuntimeContext {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'This constructor only builds an in-memory runtime context object.')]
    param(
        [string]$RepoRoot,
        [string]$SourceRoot,
        [string]$ManifestPath,
        [string]$HelpPath,
        [string]$Version = '0.0.0',
        [ValidateSet('User', 'Machine')][string]$PathScope = 'Machine',
        [string]$PathDisplay,
        [bool]$DryRun = $false,
        [psobject]$Ui,
        [AllowNull()][string]$ProfileBackupPath = $null
    )

    $effectiveUi = if ($Ui) { $Ui } else { Get-DefaultEnableUnixToolsUi }
    $effectiveDisplay = if ([string]::IsNullOrWhiteSpace($PathDisplay)) { "$PathScope PATH" } else { $PathDisplay }

    return [pscustomobject]@{
        RepoRoot          = $RepoRoot
        SourceRoot        = $SourceRoot
        ManifestPath      = $ManifestPath
        HelpPath          = $HelpPath
        Version           = $Version
        PathScope         = $PathScope
        PathDisplay       = $effectiveDisplay
        DryRun            = [bool]$DryRun
        Ui                = $effectiveUi
        ProfileBackupPath = $ProfileBackupPath
    }
}

function Resolve-EnableUnixToolsRuntimeContext {
    param([psobject]$RuntimeContext)

    if ($RuntimeContext) {
        if (-not $RuntimeContext.PSObject.Properties['Ui']) {
            Add-Member -InputObject $RuntimeContext -MemberType NoteProperty -Name Ui -Value (Get-DefaultEnableUnixToolsUi) -Force
        }
        if (-not $RuntimeContext.PSObject.Properties['PathDisplay']) {
            $pathScope = if ($RuntimeContext.PSObject.Properties['PathScope']) { [string]$RuntimeContext.PathScope } else { 'Machine' }
            Add-Member -InputObject $RuntimeContext -MemberType NoteProperty -Name PathDisplay -Value "$pathScope PATH" -Force
        }
        if (-not $RuntimeContext.PSObject.Properties['DryRun']) {
            Add-Member -InputObject $RuntimeContext -MemberType NoteProperty -Name DryRun -Value $false -Force
        }
        if (-not $RuntimeContext.PSObject.Properties['ProfileBackupPath']) {
            Add-Member -InputObject $RuntimeContext -MemberType NoteProperty -Name ProfileBackupPath -Value $null -Force
        }
        return $RuntimeContext
    }

    $sourceRoot = Get-EnableUnixToolsScriptValue -Name EnableUnixToolsSourceRoot
    if ([string]::IsNullOrWhiteSpace($sourceRoot)) {
        $sourceRoot = if ($PSScriptRoot) {
            Split-Path $PSScriptRoot -Parent
        }
        else {
            Join-Path (Get-Location).Path 'src'
        }
    }

    $repoRoot = Get-EnableUnixToolsScriptValue -Name EnableUnixToolsRepoRoot
    if ([string]::IsNullOrWhiteSpace($repoRoot)) {
        $repoRoot = if ($sourceRoot) {
            Split-Path $sourceRoot -Parent
        }
        else {
            (Get-Location).Path
        }
    }

    $manifestPath = Get-EnableUnixToolsScriptValue -Name EnableUnixToolsManifestPath -Default (Join-Path $repoRoot 'Enable-UnixTools.psd1')
    $helpPath = Get-EnableUnixToolsScriptValue -Name EnableUnixToolsHelpPath -Default (Join-Path $repoRoot 'Enable-UnixTools.ps1')
    $version = Get-EnableUnixToolsScriptValue -Name EnableUnixToolsVersion -Default '0.0.0'
    $pathScope = Get-EnableUnixToolsScriptValue -Name PathScope -Default 'Machine'
    $pathDisplay = Get-EnableUnixToolsScriptValue -Name PathDisplay -Default "$pathScope PATH"
    $dryRun = [bool](Get-EnableUnixToolsScriptValue -Name DryRun -Default $false)
    $ui = Get-EnableUnixToolsScriptValue -Name UI -Default (Get-DefaultEnableUnixToolsUi)
    $profileBackupPath = Get-EnableUnixToolsScriptValue -Name ProfileBackupPath

    return New-EnableUnixToolsRuntimeContext `
        -RepoRoot $repoRoot `
        -SourceRoot $sourceRoot `
        -ManifestPath $manifestPath `
        -HelpPath $helpPath `
        -Version $version `
        -PathScope $pathScope `
        -PathDisplay $pathDisplay `
        -DryRun:$dryRun `
        -Ui $ui `
        -ProfileBackupPath $profileBackupPath
}

function Test-EnableUnixToolsDryRun {
    param([psobject]$RuntimeContext)

    return [bool](Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext).DryRun
}
