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
        TL     = [string][char]0x256D
        TR     = [string][char]0x256E
        BL     = [string][char]0x2570
        BR     = [string][char]0x256F
        HLine  = [string][char]0x2500
        VLine  = [string][char]0x2502
        Ok     = [string][char]0x2713
        Fail   = [string][char]0x2715
        Info   = [string][char]0x2139
        Detail = [string][char]0x203A
        Warn   = [string][char]0x26A0
        Skip   = [string][char]0x00B7
        Arrow  = [string][char]0x2192
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
        [AllowNull()][string]$ProfileBackupPath = $null,
        [hashtable]$ProfileBackupPathMap = $null
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
        ProfileBackupPathMap = if ($ProfileBackupPathMap) { $ProfileBackupPathMap } else { @{} }
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
        if (-not $RuntimeContext.PSObject.Properties['ProfileBackupPathMap']) {
            Add-Member -InputObject $RuntimeContext -MemberType NoteProperty -Name ProfileBackupPathMap -Value @{} -Force
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
    $profileBackupPathMap = Get-EnableUnixToolsScriptValue -Name ProfileBackupPathMap -Default @{}

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
        -ProfileBackupPath $profileBackupPath `
        -ProfileBackupPathMap $profileBackupPathMap
}

function Test-EnableUnixToolsDryRun {
    param([psobject]$RuntimeContext)

    return [bool](Resolve-EnableUnixToolsRuntimeContext -RuntimeContext $RuntimeContext).DryRun
}
