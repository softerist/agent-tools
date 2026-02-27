#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive publisher for PowerShell Gallery.

.DESCRIPTION
    Builds a module package from a single installer script and publishes it to
    PowerShell Gallery using Publish-Module.

    This script also handles legacy Windows PowerShell environments by ensuring
    compatible PackageManagement and PowerShellGet versions are available.
#>

[CmdletBinding()]
param(
    [string]$SourceScriptPath,
    [string]$ModuleName,
    [string]$ModuleVersion,
    [string]$Author,
    [string]$Description,
    [string]$Tags,
    [string]$ReleaseNotes,
    [string]$ProjectUri,
    [string]$LicenseUri,
    [string]$IconUri,
    [string]$ReadmePath,
    [string]$AboutPath,
    [string]$Repository = 'PSGallery',
    [string]$NuGetApiKey,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "[STEP] $Message" -ForegroundColor Cyan
}

function Write-Info([string]$Message) {
    Write-Host "[INFO] $Message" -ForegroundColor DarkGray
}

function Read-Default([string]$Prompt, [string]$Default) {
    if ([string]::IsNullOrWhiteSpace($Default)) {
        return (Read-Host $Prompt)
    }
    $value = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

function Read-YesNo([string]$Prompt, [bool]$Default = $true) {
    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $raw = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
    switch ($raw.Trim().ToLowerInvariant()) {
        'y' { return $true }
        'yes' { return $true }
        'n' { return $false }
        'no' { return $false }
        default { return $Default }
    }
}

function Convert-ToTagArray([string]$TagText) {
    if ([string]::IsNullOrWhiteSpace($TagText)) { return @() }
    $parts = $TagText -split '[,; ]+'
    $set = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($p in $parts) {
        $t = $p.Trim()
        if ($t.Length -eq 0) { continue }
        if ($set.Add($t)) { $out.Add($t) | Out-Null }
    }
    return @($out)
}

function Get-ScriptSynopsis([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $m = [regex]::Match($raw, '(?ms)\.SYNOPSIS\s*(?<body>.*?)\r?\n\s*\.')
        if ($m.Success) {
            return (($m.Groups['body'].Value -replace '\r?\n', ' ').Trim())
        }
    }
    catch {}
    return ''
}

function New-ReadmeContent {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$SourceScript
    )

    return @(
        "# $Name",
        "",
        $Description,
        "",
        "## Installation",
        "",
        "```powershell",
        "Install-Module $Name",
        "```",
        "",
        "## Usage",
        "",
        "```powershell",
        "$Name -InstallFull",
        "```",
        "",
        "## Included Script",
        "",
        "- $([System.IO.Path]::GetFileName($SourceScript))",
        "",
        "## Published Version",
        "",
        "- $Version"
    ) -join "`r`n"
}

function New-AboutHelpContent {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Description
    )

    return @(
        "TOPIC",
        "    about_$Name",
        "",
        "SHORT DESCRIPTION",
        "    $Description",
        "",
        "LONG DESCRIPTION",
        "    This module publishes the command '$Name', which wraps the bundled",
        "    installer script and forwards all arguments to it.",
        "",
        "    Example:",
        "        $Name -InstallFull",
        "",
        "SEE ALSO",
        "    Get-Help $Name -Detailed"
    ) -join "`r`n"
}

function Get-DefaultModuleRoot {
    if ($PSVersionTable.PSEdition -eq 'Core') {
        return Join-Path $HOME 'Documents\\PowerShell\\Modules'
    }
    return Join-Path $HOME 'Documents\\WindowsPowerShell\\Modules'
}

function Add-ModulePathIfMissing([string]$ModuleRoot) {
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) { return }
    $paths = @($env:PSModulePath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $exists = $false
    foreach ($p in $paths) {
        if ($p.Trim().TrimEnd('\').Equals($ModuleRoot.Trim().TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            $exists = $true
            break
        }
    }
    if (-not $exists) {
        $env:PSModulePath = "$ModuleRoot;$env:PSModulePath"
        Write-Info "Prepended module path for this session: $ModuleRoot"
    }
}

function Import-RequiredModuleVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$ModuleRoot
    )

    try {
        Import-Module $Name -RequiredVersion $Version -Force -ErrorAction Stop
        return
    }
    catch {
        $candidateManifest = Join-Path $ModuleRoot "$Name\\$Version\\$Name.psd1"
        if (Test-Path -LiteralPath $candidateManifest -PathType Leaf) {
            Write-Info "Import fallback via manifest path: $candidateManifest"
            Import-Module -Name $candidateManifest -Force -ErrorAction Stop
            return
        }
        throw
    }
}

function Install-ModuleNupkg {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$ModuleRoot
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $tmpRoot = Join-Path $env:TEMP ("publish-bootstrap-{0}" -f ([guid]::NewGuid().ToString('N')))
    $null = New-Item -ItemType Directory -Path $tmpRoot -Force

    $nupkgPath = Join-Path $tmpRoot ("{0}.{1}.nupkg" -f $Name, $Version)
    $extractPath = Join-Path $tmpRoot 'extract'
    $url = "https://www.powershellgallery.com/api/v2/package/$Name/$Version"

    Write-Info "Downloading $Name $Version from PSGallery..."
    Invoke-WebRequest -Uri $url -OutFile $nupkgPath -UseBasicParsing

    $null = New-Item -ItemType Directory -Path $extractPath -Force
    [System.IO.Compression.ZipFile]::ExtractToDirectory($nupkgPath, $extractPath)

    $manifestCandidates = @(Get-ChildItem -Path $extractPath -Recurse -Filter "$Name.psd1" -File -ErrorAction SilentlyContinue)
    if ($manifestCandidates.Count -eq 0) {
        throw "Could not locate $Name.psd1 inside downloaded package."
    }
    $manifestSource = $manifestCandidates | Select-Object -First 1
    $sourceDir = Split-Path -Parent $manifestSource.FullName

    $dest = Join-Path $ModuleRoot "$Name\\$Version"
    $null = New-Item -ItemType Directory -Path $dest -Force
    Copy-Item -Path (Join-Path $sourceDir '*') -Destination $dest -Recurse -Force

    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
    return (Join-Path $dest "$Name.psd1")
}

function Ensure-PublishToolchain {
    $moduleRoot = Get-DefaultModuleRoot
    $null = New-Item -ItemType Directory -Path $moduleRoot -Force
    Add-ModulePathIfMissing -ModuleRoot $moduleRoot

    try {
        Import-RequiredModuleVersion -Name 'PackageManagement' -Version '1.4.8.1' -ModuleRoot $moduleRoot
    }
    catch {
        Write-Info 'PackageManagement 1.4.8.1 not available. Bootstrapping from PSGallery...'
        $pmManifest = Install-ModuleNupkg -Name 'PackageManagement' -Version '1.4.8.1' -ModuleRoot $moduleRoot
        Write-Info "Installed PackageManagement manifest: $pmManifest"
        Import-RequiredModuleVersion -Name 'PackageManagement' -Version '1.4.8.1' -ModuleRoot $moduleRoot
    }

    try {
        Import-RequiredModuleVersion -Name 'PowerShellGet' -Version '2.2.5' -ModuleRoot $moduleRoot
    }
    catch {
        Write-Info 'PowerShellGet 2.2.5 not available. Bootstrapping from PSGallery...'
        $psgManifest = Install-ModuleNupkg -Name 'PowerShellGet' -Version '2.2.5' -ModuleRoot $moduleRoot
        Write-Info "Installed PowerShellGet manifest: $psgManifest"
        Import-RequiredModuleVersion -Name 'PowerShellGet' -Version '2.2.5' -ModuleRoot $moduleRoot
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Set-PSRepository -Name $Repository -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }
    catch {
        Write-Info "Could not set $Repository as Trusted automatically: $($_.Exception.Message)"
    }
}

function Get-ScriptVersionDefault([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '1.0.0' }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $m = [regex]::Match($raw, '\$ScriptVersion\s*=\s*"(?<v>[0-9]+\.[0-9]+\.[0-9]+)"')
        if ($m.Success) { return $m.Groups['v'].Value }
    }
    catch {}
    return '1.0.0'
}

function New-ModulePackage {
    param(
        [Parameter(Mandatory = $true)][string]$SourceScript,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$ModuleAuthor,
        [Parameter(Mandatory = $true)][string]$ModuleDescription,
        [string[]]$ModuleTags,
        [string]$ModuleReleaseNotes,
        [string]$Project,
        [string]$License,
        [string]$ModuleIconUri,
        [string]$ReadmeSourcePath,
        [string]$AboutSourcePath
    )

    $stagingRoot = Join-Path $env:TEMP ("psgallery-publish-{0}" -f ([guid]::NewGuid().ToString('N')))
    $moduleDir = Join-Path $stagingRoot $Name
    $null = New-Item -ItemType Directory -Path $moduleDir -Force

    $sourceLeaf = Split-Path -Leaf $SourceScript
    $sourceCopy = Join-Path $moduleDir $sourceLeaf
    Copy-Item -LiteralPath $SourceScript -Destination $sourceCopy -Force

    $readmeTarget = Join-Path $moduleDir 'README.md'
    if (-not [string]::IsNullOrWhiteSpace($ReadmeSourcePath) -and (Test-Path -LiteralPath $ReadmeSourcePath -PathType Leaf)) {
        Copy-Item -LiteralPath $ReadmeSourcePath -Destination $readmeTarget -Force
    }
    else {
        Set-Content -LiteralPath $readmeTarget -Value (New-ReadmeContent -Name $Name -Version $Version -Description $ModuleDescription -SourceScript $SourceScript) -Encoding UTF8
    }

    $aboutLeaf = "about_{0}.help.txt" -f $Name
    $aboutTarget = Join-Path $moduleDir $aboutLeaf
    if (-not [string]::IsNullOrWhiteSpace($AboutSourcePath) -and (Test-Path -LiteralPath $AboutSourcePath -PathType Leaf)) {
        Copy-Item -LiteralPath $AboutSourcePath -Destination $aboutTarget -Force
    }
    else {
        Set-Content -LiteralPath $aboutTarget -Value (New-AboutHelpContent -Name $Name -Description $ModuleDescription) -Encoding UTF8
    }

    $psm1Path = Join-Path $moduleDir ("{0}.psm1" -f $Name)
    $manifestPath = Join-Path $moduleDir ("{0}.psd1" -f $Name)

    $wrapper = @(
        '#Requires -Version 5.1'
        ''
        "function $Name {"
        '    [CmdletBinding(PositionalBinding = $false)]'
        '    param('
        '        [Parameter(ValueFromRemainingArguments = $true)]'
        '        [object[]]$ArgumentList'
        '    )'
        ''
        "    `$scriptPath = Join-Path -Path `$PSScriptRoot -ChildPath '$sourceLeaf'"
        '    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {'
        '        throw "Installer script not found: $scriptPath"'
        '    }'
        ''
        '    & $scriptPath @ArgumentList'
        '}'
        ''
        "Export-ModuleMember -Function '$Name'"
    ) -join "`r`n"

    Set-Content -LiteralPath $psm1Path -Value $wrapper -Encoding UTF8

    if (-not $ModuleTags -or $ModuleTags.Count -eq 0) {
        $ModuleTags = @('unix', 'windows', 'path', 'shims', 'cli')
    }
    if ([string]::IsNullOrWhiteSpace($ModuleReleaseNotes)) {
        $ModuleReleaseNotes = "Published $Name $Version via publish.ps1."
    }
    $manifestParams = @{
        Path              = $manifestPath
        RootModule        = ("{0}.psm1" -f $Name)
        ModuleVersion     = $Version
        Guid              = [guid]::NewGuid()
        Author            = $ModuleAuthor
        CompanyName       = $ModuleAuthor
        Copyright         = ("(c) {0}. All rights reserved." -f $ModuleAuthor)
        Description       = $ModuleDescription
        PowerShellVersion = '5.1'
        FunctionsToExport = @($Name)
        CmdletsToExport   = @()
        VariablesToExport = @()
        AliasesToExport   = @()
        FileList          = @(("{0}.psm1" -f $Name), ("{0}.psd1" -f $Name), $sourceLeaf, 'README.md', $aboutLeaf)
        Tags              = $ModuleTags
        ReleaseNotes      = $ModuleReleaseNotes
    }

    if (-not [string]::IsNullOrWhiteSpace($Project)) {
        $manifestParams.ProjectUri = $Project
    }
    if (-not [string]::IsNullOrWhiteSpace($License)) {
        $manifestParams.LicenseUri = $License
    }
    if (-not [string]::IsNullOrWhiteSpace($ModuleIconUri)) {
        $manifestParams.IconUri = $ModuleIconUri
    }

    New-ModuleManifest @manifestParams | Out-Null
    Test-ModuleManifest -Path $manifestPath | Out-Null

    return [pscustomobject]@{
        StagingRoot = $stagingRoot
        ModulePath  = $moduleDir
        Manifest    = $manifestPath
        SourceCopy  = $sourceCopy
    }
}

Write-Step 'PowerShell Gallery Interactive Publisher'

if ([string]::IsNullOrWhiteSpace($SourceScriptPath)) {
    $defaultScript = Join-Path $PSScriptRoot 'Enable-UnixTools.ps1'
    if (-not (Test-Path -LiteralPath $defaultScript -PathType Leaf)) {
        $alt = Join-Path $PSScriptRoot 'Enable-UnixToolsSystemWide.ps1'
        if (Test-Path -LiteralPath $alt -PathType Leaf) { $defaultScript = $alt }
    }
    $SourceScriptPath = Read-Default -Prompt 'Installer script path' -Default $defaultScript
}

if (-not (Test-Path -LiteralPath $SourceScriptPath -PathType Leaf)) {
    throw "Source script not found: $SourceScriptPath"
}

if ([string]::IsNullOrWhiteSpace($ModuleName)) {
    $defaultName = [System.IO.Path]::GetFileNameWithoutExtension($SourceScriptPath)
    $ModuleName = Read-Default -Prompt 'Module name' -Default $defaultName
}

if ([string]::IsNullOrWhiteSpace($ModuleVersion)) {
    $ModuleVersion = Read-Default -Prompt 'Module version (SemVer)' -Default (Get-ScriptVersionDefault -Path $SourceScriptPath)
}

if ([string]::IsNullOrWhiteSpace($Author)) {
    $gitAuthor = ''
    try {
        $gitAuthor = (git config user.name 2>$null)
    }
    catch {}
    if ([string]::IsNullOrWhiteSpace($gitAuthor)) { $gitAuthor = 'softerist' }
    $Author = Read-Default -Prompt 'Author' -Default $gitAuthor
}

if ([string]::IsNullOrWhiteSpace($Description)) {
    $defaultSynopsis = Get-ScriptSynopsis -Path $SourceScriptPath
    if ([string]::IsNullOrWhiteSpace($defaultSynopsis)) {
        $defaultSynopsis = 'Adds Unix-compatible tools to Windows PATH with optional shims and profile wrappers.'
    }
    $Description = Read-Default -Prompt 'Module description' -Default $defaultSynopsis
}

if ([string]::IsNullOrWhiteSpace($Tags)) {
    $Tags = Read-Default -Prompt 'Tags (comma-separated)' -Default 'unix,windows,path,shims,cli'
}

if ([string]::IsNullOrWhiteSpace($ReleaseNotes)) {
    $ReleaseNotes = Read-Default -Prompt 'Release notes' -Default ("Publish {0} {1}" -f $ModuleName, $ModuleVersion)
}

if ([string]::IsNullOrWhiteSpace($ProjectUri)) {
    $remoteUrl = ''
    try {
        $remoteUrl = (git config --get remote.origin.url 2>$null)
    }
    catch {}
    if ($remoteUrl -match '^https://') {
        $ProjectUri = Read-Default -Prompt 'Project URI' -Default $remoteUrl
    }
    else {
        $ProjectUri = Read-Default -Prompt 'Project URI' -Default ''
    }
}

if ([string]::IsNullOrWhiteSpace($LicenseUri) -and -not [string]::IsNullOrWhiteSpace($ProjectUri)) {
    $LicenseUri = Read-Default -Prompt 'License URI' -Default ($ProjectUri.TrimEnd('/') + '/blob/main/LICENSE')
}
elseif ([string]::IsNullOrWhiteSpace($LicenseUri)) {
    $LicenseUri = Read-Default -Prompt 'License URI' -Default ''
}

if ([string]::IsNullOrWhiteSpace($IconUri) -and -not [string]::IsNullOrWhiteSpace($ProjectUri)) {
    $IconUri = Read-Default -Prompt 'Icon URI' -Default ''
}
elseif ([string]::IsNullOrWhiteSpace($IconUri)) {
    $IconUri = Read-Default -Prompt 'Icon URI' -Default ''
}

if ([string]::IsNullOrWhiteSpace($ReadmePath)) {
    $defaultReadme = Join-Path $PSScriptRoot 'README.md'
    if (Test-Path -LiteralPath $defaultReadme -PathType Leaf) {
        $ReadmePath = Read-Default -Prompt 'README path (blank = auto-generate)' -Default $defaultReadme
    }
    else {
        $ReadmePath = Read-Default -Prompt 'README path (blank = auto-generate)' -Default ''
    }
}

if ([string]::IsNullOrWhiteSpace($AboutPath)) {
    $defaultAbout = Join-Path $PSScriptRoot ("about_{0}.help.txt" -f $ModuleName)
    if (Test-Path -LiteralPath $defaultAbout -PathType Leaf) {
        $AboutPath = Read-Default -Prompt 'about_*.help.txt path (blank = auto-generate)' -Default $defaultAbout
    }
    else {
        $AboutPath = Read-Default -Prompt 'about_*.help.txt path (blank = auto-generate)' -Default ''
    }
}

if (-not [string]::IsNullOrWhiteSpace($ReadmePath) -and -not (Test-Path -LiteralPath $ReadmePath -PathType Leaf)) {
    throw "README file not found: $ReadmePath"
}
if (-not [string]::IsNullOrWhiteSpace($AboutPath) -and -not (Test-Path -LiteralPath $AboutPath -PathType Leaf)) {
    throw "about help file not found: $AboutPath"
}

if ([string]::IsNullOrWhiteSpace($NuGetApiKey)) {
    $NuGetApiKey = Read-Host 'PowerShell Gallery NuGet API key'
}
if ([string]::IsNullOrWhiteSpace($NuGetApiKey)) {
    throw 'NuGet API key is required.'
}

Write-Host ''
Write-Host 'Publish Plan' -ForegroundColor Yellow
Write-Host "- Source script : $SourceScriptPath"
Write-Host "- Module name   : $ModuleName"
Write-Host "- Version       : $ModuleVersion"
Write-Host "- Author        : $Author"
Write-Host "- Tags          : $Tags"
Write-Host "- Repository    : $Repository"
if (-not [string]::IsNullOrWhiteSpace($ReadmePath)) {
    Write-Host "- README        : $ReadmePath"
}
else {
    Write-Host "- README        : auto-generate"
}
if (-not [string]::IsNullOrWhiteSpace($AboutPath)) {
    Write-Host "- About help    : $AboutPath"
}
else {
    Write-Host "- About help    : auto-generate"
}

if (-not $Force -and -not (Read-YesNo -Prompt 'Continue and publish?' -Default $true)) {
    Write-Host 'Cancelled.' -ForegroundColor Yellow
    return
}

Write-Step 'Ensuring publish toolchain (PackageManagement + PowerShellGet)'
Ensure-PublishToolchain

Write-Step 'Building module staging package'
$package = New-ModulePackage `
    -SourceScript $SourceScriptPath `
    -Name $ModuleName `
    -Version $ModuleVersion `
    -ModuleAuthor $Author `
    -ModuleDescription $Description `
    -ModuleTags (Convert-ToTagArray -TagText $Tags) `
    -ModuleReleaseNotes $ReleaseNotes `
    -Project $ProjectUri `
    -License $LicenseUri `
    -ModuleIconUri $IconUri `
    -ReadmeSourcePath $ReadmePath `
    -AboutSourcePath $AboutPath
Write-Info "Staging path: $($package.ModulePath)"

Write-Step 'Publishing to PowerShell Gallery'
$global:LASTEXITCODE = 0
try {
    Publish-Module -Path $package.ModulePath -Repository $Repository -NuGetApiKey $NuGetApiKey -Force -Verbose -ErrorAction Stop
}
catch {
    $msg = $_.Exception.Message
    if ($msg -match '403' -or $msg -match 'API key is invalid' -or $msg -match 'does not have permission') {
        throw @(
            "Publish failed with authentication/authorization error.",
            "Check these items:",
            "1) API key is active and not expired",
            "2) API key has push scope for package '$ModuleName'",
            "3) Package owner includes your account",
            "4) Key has not been revoked after being exposed",
            "Original error: $msg"
        ) -join [Environment]::NewLine
    }
    throw
}

Write-Step 'Verifying publish result'
$published = Find-Module -Name $ModuleName -Repository $Repository -ErrorAction SilentlyContinue | Select-Object -First 1 Name, Version, PublishedDate, Author
if ($published) {
    Write-Host "Published: $($published.Name) $($published.Version)" -ForegroundColor Green
    if ($published.PublishedDate) {
        Write-Info ("PublishedDate: {0}" -f $published.PublishedDate)
    }
}
else {
    Write-Warning "Module '$ModuleName' not visible yet. PSGallery indexing can take a few minutes."
}

if (Read-YesNo -Prompt 'Delete local staging folder?' -Default $true) {
    Remove-Item -LiteralPath $package.StagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Info 'Staging folder removed.'
}
else {
    Write-Info ("Staging folder kept: {0}" -f $package.StagingRoot)
}

Write-Host 'Done.' -ForegroundColor Green
