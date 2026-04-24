#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive publisher for PowerShell Gallery.

.DESCRIPTION
    Stages the committed module wrapper, manifest, and source tree into a temp
    folder and hands it to Publish-Module. Module metadata (Author, Tags,
    Description, ProjectUri, ReleaseNotes, etc.) is read straight from the
    committed .psd1; this script does not regenerate it.

    On legacy Windows PowerShell hosts, bootstraps PackageManagement 1.4.8.1
    and PowerShellGet 2.2.5 from PSGallery if missing, and auto-applies safe
    preflight fixes (e.g., adding/enabling the dotnet nuget.org source).
#>

[CmdletBinding()]
param(
    [string]$SourceScriptPath,
    [string]$ModuleName,
    [string]$ModuleVersion,
    [string]$ReadmePath,
    [string]$AboutPath,
    [string]$Repository = 'PSGallery',
    [string]$NuGetApiKey,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Step {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive publisher prints to the console.')]
    param([string]$Message)
    Write-Host "[STEP] $Message" -ForegroundColor Cyan
}

function Write-Info {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive publisher prints to the console.')]
    param([string]$Message)
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

function Get-DefaultReadmeContent {
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

function Get-DefaultAboutHelpContent {
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
        return Join-Path $HOME 'Documents\PowerShell\Modules'
    }
    return Join-Path $HOME 'Documents\WindowsPowerShell\Modules'
}

function Add-ModulePathIfMissing([string]$ModuleRoot) {
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) { return }
    $normalized = $ModuleRoot.Trim().TrimEnd('\')
    foreach ($p in ($env:PSModulePath -split ';')) {
        if (-not [string]::IsNullOrWhiteSpace($p) -and $p.Trim().TrimEnd('\').Equals($normalized, [StringComparison]::OrdinalIgnoreCase)) {
            return
        }
    }
    $env:PSModulePath = "$ModuleRoot;$env:PSModulePath"
    Write-Info "Prepended module path for this session: $ModuleRoot"
}

function Get-DotNetNuGetSource {
    $output = @(& dotnet nuget list source 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $joined = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        throw "dotnet nuget list source failed.`n$joined"
    }

    $sources = New-Object System.Collections.Generic.List[object]
    $currentName = $null
    $currentEnabled = $false
    foreach ($line in $output) {
        $text = ([string]$line).TrimEnd()
        if ($text -match '^\s*\d+\.\s+(.+?)\s+\[(Enabled|Disabled)\]\s*$') {
            $currentName = $matches[1].Trim()
            $currentEnabled = $matches[2].Equals('Enabled', [StringComparison]::OrdinalIgnoreCase)
            continue
        }
        if ($currentName -and $text -match '^\s*(https?://\S+)\s*$') {
            $sources.Add([pscustomobject]@{
                    Name    = $currentName
                    Enabled = $currentEnabled
                    Url     = $matches[1].Trim()
                }) | Out-Null
            $currentName = $null
        }
    }
    return $sources.ToArray()
}

function New-PrereqIssue {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory diagnostic record.')]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Detail,
        [string[]]$FixCommands = @()
    )
    return [pscustomobject]@{
        Title       = $Title
        Detail      = $Detail
        FixCommands = @($FixCommands | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
}

function Test-PublishEnvironment {
    $issues = New-Object System.Collections.Generic.List[object]

    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        $issues.Add((New-PrereqIssue `
                    -Title 'Missing .NET SDK (dotnet)' `
                    -Detail 'Publish-Module uses dotnet pack internally. dotnet was not found on PATH.' `
                    -FixCommands @(
                        'winget install --id Microsoft.DotNet.SDK.10 --exact --accept-package-agreements --accept-source-agreements',
                        'dotnet --info'
                    ))) | Out-Null
        return [pscustomobject]@{ Ready = $false; Issues = $issues.ToArray() }
    }

    $nugetUrl = 'https://api.nuget.org/v3/index.json'
    $normalizedNugetUrl = $nugetUrl.TrimEnd('/')
    try {
        $sources = @(Get-DotNetNuGetSource)
    }
    catch {
        $issues.Add((New-PrereqIssue `
                    -Title 'Unable to read dotnet NuGet sources' `
                    -Detail $_.Exception.Message `
                    -FixCommands @(
                        'dotnet nuget list source',
                        'dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org'
                    ))) | Out-Null
        return [pscustomobject]@{ Ready = $false; Issues = $issues.ToArray() }
    }

    $nugetEntry = $sources | Where-Object {
        $_.Url -and $_.Url.TrimEnd('/').Equals($normalizedNugetUrl, [StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1

    if (-not $nugetEntry) {
        Write-Info "Auto-fix: adding dotnet NuGet source '$nugetUrl' as 'nuget.org'..."
        & dotnet nuget add source $nugetUrl -n nuget.org | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $issues.Add((New-PrereqIssue `
                        -Title 'Missing dotnet NuGet source: nuget.org' `
                        -Detail "No source found for $nugetUrl, and automatic add failed." `
                        -FixCommands @(
                            'dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org',
                            'dotnet nuget list source'
                        ))) | Out-Null
        }
    }
    elseif (-not $nugetEntry.Enabled) {
        Write-Info "Auto-fix: enabling dotnet NuGet source '$($nugetEntry.Name)'..."
        & dotnet nuget enable source $nugetEntry.Name | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $issues.Add((New-PrereqIssue `
                        -Title "Disabled dotnet NuGet source: $($nugetEntry.Name)" `
                        -Detail "The source URL is present but disabled, and automatic enable failed: $($nugetEntry.Url)" `
                        -FixCommands @(
                            "dotnet nuget enable source `"$($nugetEntry.Name)`"",
                            'dotnet nuget list source'
                        ))) | Out-Null
        }
    }

    return [pscustomobject]@{ Ready = ($issues.Count -eq 0); Issues = $issues.ToArray() }
}

function Write-IssueReport {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive publisher prints to the console.')]
    param(
        [Parameter(Mandatory = $true)][string]$Heading,
        [Parameter(Mandatory = $true)][object[]]$Issues
    )
    Write-Host ''
    Write-Host $Heading -ForegroundColor Red
    foreach ($issue in $Issues) {
        Write-Host "- $($issue.Title)" -ForegroundColor Red
        Write-Host "  $($issue.Detail)" -ForegroundColor DarkGray
        if ($issue.FixCommands -and $issue.FixCommands.Count -gt 0) {
            Write-Host '  Fix:' -ForegroundColor Yellow
            foreach ($cmd in $issue.FixCommands) {
                Write-Host "    $cmd" -ForegroundColor Yellow
            }
        }
    }
    Write-Host ''
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
        $candidateManifest = Join-Path $ModuleRoot "$Name\$Version\$Name.psd1"
        if (Test-Path -LiteralPath $candidateManifest -PathType Leaf) {
            Write-Info "Import fallback via manifest path: $candidateManifest"
            Import-Module -Name $candidateManifest -Force -ErrorAction Stop
            return
        }
        throw
    }
}

function Install-ModuleNupkg {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Bootstrap helper installs to a known per-user module root.')]
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

    $manifestSource = Get-ChildItem -Path $extractPath -Recurse -Filter "$Name.psd1" -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $manifestSource) {
        throw "Could not locate $Name.psd1 inside downloaded package."
    }

    $dest = Join-Path $ModuleRoot "$Name\$Version"
    $null = New-Item -ItemType Directory -Path $dest -Force
    Copy-Item -Path (Join-Path (Split-Path -Parent $manifestSource.FullName) '*') -Destination $dest -Recurse -Force

    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
    return (Join-Path $dest "$Name.psd1")
}

function Initialize-PublishToolchain {
    $moduleRoot = Get-DefaultModuleRoot
    $null = New-Item -ItemType Directory -Path $moduleRoot -Force
    Add-ModulePathIfMissing -ModuleRoot $moduleRoot

    foreach ($pair in @(
            @{ Name = 'PackageManagement'; Version = '1.4.8.1' },
            @{ Name = 'PowerShellGet'; Version = '2.2.5' }
        )) {
        try {
            Import-RequiredModuleVersion -Name $pair.Name -Version $pair.Version -ModuleRoot $moduleRoot
        }
        catch {
            Write-Info "$($pair.Name) $($pair.Version) not available. Bootstrapping from PSGallery..."
            Install-ModuleNupkg -Name $pair.Name -Version $pair.Version -ModuleRoot $moduleRoot | Out-Null
            Import-RequiredModuleVersion -Name $pair.Name -Version $pair.Version -ModuleRoot $moduleRoot
        }
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Set-PSRepository -Name $Repository -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }
    catch {
        Write-Info "Could not set $Repository as Trusted automatically: $($_.Exception.Message)"
    }
}

function Get-ManifestVersionDefault([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '1.0.0' }
    try {
        $data = Import-PowerShellDataFile -Path $Path
        if ($data.ModuleVersion) {
            return [string]$data.ModuleVersion
        }
    }
    catch {
        Write-Verbose "Unable to read manifest version from '$Path': $($_.Exception.Message)"
    }
    return '1.0.0'
}

function Assert-RequestedModuleVersionMatchesManifest {
    param(
        [string]$RequestedVersion,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )

    if ([string]::IsNullOrWhiteSpace($RequestedVersion)) {
        return
    }

    $manifestVersion = Get-ManifestVersionDefault -Path $ManifestPath
    if ($RequestedVersion -ne $manifestVersion) {
        throw "Requested ModuleVersion '$RequestedVersion' does not match committed manifest version '$manifestVersion'. Update $ManifestPath first."
    }
}

function Initialize-ModulePackage {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Stages files into a per-invocation temp directory.')]
    param(
        [Parameter(Mandatory = $true)][string]$SourceScript,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$ModuleDescription,
        [string]$ReadmeSourcePath,
        [string]$AboutSourcePath
    )

    $stagingRoot = Join-Path $env:TEMP ("psgallery-publish-{0}" -f ([guid]::NewGuid().ToString('N')))
    $moduleDir = Join-Path $stagingRoot $Name
    $null = New-Item -ItemType Directory -Path $moduleDir -Force

    Copy-Item -LiteralPath $SourceScript -Destination (Join-Path $moduleDir (Split-Path -Leaf $SourceScript)) -Force

    $readmeTarget = Join-Path $moduleDir 'README.md'
    if (-not [string]::IsNullOrWhiteSpace($ReadmeSourcePath) -and (Test-Path -LiteralPath $ReadmeSourcePath -PathType Leaf)) {
        Copy-Item -LiteralPath $ReadmeSourcePath -Destination $readmeTarget -Force
    }
    else {
        Set-Content -LiteralPath $readmeTarget -Value (Get-DefaultReadmeContent -Name $Name -Version $Version -Description $ModuleDescription -SourceScript $SourceScript) -Encoding UTF8
    }

    $aboutTarget = Join-Path $moduleDir ("about_{0}.help.txt" -f $Name)
    if (-not [string]::IsNullOrWhiteSpace($AboutSourcePath) -and (Test-Path -LiteralPath $AboutSourcePath -PathType Leaf)) {
        Copy-Item -LiteralPath $AboutSourcePath -Destination $aboutTarget -Force
    }
    else {
        Set-Content -LiteralPath $aboutTarget -Value (Get-DefaultAboutHelpContent -Name $Name -Description $ModuleDescription) -Encoding UTF8
    }

    $sourceDir = Split-Path -Parent $SourceScript
    $sourceWrapperPath = Join-Path $sourceDir ("{0}.psm1" -f $Name)
    $sourceManifestPath = Join-Path $sourceDir ("{0}.psd1" -f $Name)

    if (-not (Test-Path -LiteralPath $sourceWrapperPath -PathType Leaf)) {
        throw "Committed module wrapper not found: $sourceWrapperPath"
    }
    if (-not (Test-Path -LiteralPath $sourceManifestPath -PathType Leaf)) {
        throw "Committed module manifest not found: $sourceManifestPath"
    }

    $manifestPath = Join-Path $moduleDir ("{0}.psd1" -f $Name)
    Copy-Item -LiteralPath $sourceWrapperPath -Destination (Join-Path $moduleDir ("{0}.psm1" -f $Name)) -Force
    Copy-Item -LiteralPath $sourceManifestPath -Destination $manifestPath -Force

    foreach ($extraDirName in @('src', 'catalogs')) {
        $extraDir = Join-Path $sourceDir $extraDirName
        if (Test-Path -LiteralPath $extraDir -PathType Container) {
            Copy-Item -LiteralPath $extraDir -Destination (Join-Path $moduleDir $extraDirName) -Recurse -Force
        }
    }

    Test-ModuleManifest -Path $manifestPath | Out-Null

    return [pscustomobject]@{
        StagingRoot = $stagingRoot
        ModulePath  = $moduleDir
        Manifest    = $manifestPath
        SourceCopy  = (Join-Path $moduleDir (Split-Path -Leaf $SourceScript))
    }
}

# ---- main ----------------------------------------------------------------

if ($MyInvocation.InvocationName -eq '.') {
    return
}

Write-Step 'PowerShell Gallery Interactive Publisher'

Write-Step 'Running preflight checks'
$preflight = Test-PublishEnvironment
if (-not $preflight.Ready) {
    Write-IssueReport -Heading 'Preflight failed. Publish was not started.' -Issues $preflight.Issues
    return
}
Write-Info 'Preflight checks passed.'

if ([string]::IsNullOrWhiteSpace($SourceScriptPath)) {
    $defaultScript = Join-Path $PSScriptRoot 'Enable-UnixTools.ps1'
    $SourceScriptPath = Read-Default -Prompt 'Installer script path' -Default $defaultScript
}

if (-not (Test-Path -LiteralPath $SourceScriptPath -PathType Leaf)) {
    throw "Source script not found: $SourceScriptPath"
}

if ([string]::IsNullOrWhiteSpace($ModuleName)) {
    $defaultName = [System.IO.Path]::GetFileNameWithoutExtension($SourceScriptPath)
    $ModuleName = Read-Default -Prompt 'Module name' -Default $defaultName
}

$manifestSourcePath = Join-Path (Split-Path -Parent $SourceScriptPath) ("{0}.psd1" -f $ModuleName)
if ([string]::IsNullOrWhiteSpace($ModuleVersion)) {
    $ModuleVersion = Read-Default -Prompt 'Module version (SemVer)' -Default (Get-ManifestVersionDefault -Path $manifestSourcePath)
}
else {
    Assert-RequestedModuleVersionMatchesManifest -RequestedVersion $ModuleVersion -ManifestPath $manifestSourcePath
}

$manifestData = Import-PowerShellDataFile -Path $manifestSourcePath
$packageDescription = if ($manifestData.Description) { [string]$manifestData.Description } else { $ModuleName }

if ([string]::IsNullOrWhiteSpace($ReadmePath)) {
    $defaultReadme = Join-Path $PSScriptRoot 'README.md'
    $ReadmePath = if (Test-Path -LiteralPath $defaultReadme -PathType Leaf) {
        Read-Default -Prompt 'README path (blank = auto-generate)' -Default $defaultReadme
    }
    else {
        Read-Default -Prompt 'README path (blank = auto-generate)' -Default ''
    }
}
if (-not [string]::IsNullOrWhiteSpace($ReadmePath) -and -not (Test-Path -LiteralPath $ReadmePath -PathType Leaf)) {
    throw "README file not found: $ReadmePath"
}

if ([string]::IsNullOrWhiteSpace($AboutPath)) {
    $defaultAbout = Join-Path $PSScriptRoot ("about_{0}.help.txt" -f $ModuleName)
    $AboutPath = if (Test-Path -LiteralPath $defaultAbout -PathType Leaf) {
        Read-Default -Prompt 'about_*.help.txt path (blank = auto-generate)' -Default $defaultAbout
    }
    else {
        Read-Default -Prompt 'about_*.help.txt path (blank = auto-generate)' -Default ''
    }
}
if (-not [string]::IsNullOrWhiteSpace($AboutPath) -and -not (Test-Path -LiteralPath $AboutPath -PathType Leaf)) {
    throw "about help file not found: $AboutPath"
}

if ([string]::IsNullOrWhiteSpace($NuGetApiKey)) {
    $NuGetApiKey = Read-Host 'PowerShell Gallery NuGet API key'
}
if ([string]::IsNullOrWhiteSpace($NuGetApiKey)) {
    Write-IssueReport -Heading 'Publish was not started.' -Issues @(
        New-PrereqIssue `
            -Title 'Missing required input: NuGet API key' `
            -Detail 'Enter a valid PowerShell Gallery API key when prompted.' `
            -FixCommands @('Get or rotate keys at: https://www.powershellgallery.com/account/apikeys')
    )
    return
}

Write-Host ''
Write-Host 'Publish Plan' -ForegroundColor Yellow
Write-Host "- Source script : $SourceScriptPath"
Write-Host "- Module name   : $ModuleName"
Write-Host "- Version       : $ModuleVersion"
Write-Host "- Repository    : $Repository"
Write-Host ("- README        : {0}" -f ($(if ($ReadmePath) { $ReadmePath } else { 'auto-generate' })))
Write-Host ("- About help    : {0}" -f ($(if ($AboutPath) { $AboutPath } else { 'auto-generate' })))

if (-not $Force -and -not (Read-YesNo -Prompt 'Continue and publish?' -Default $true)) {
    Write-Host 'Cancelled.' -ForegroundColor Yellow
    return
}

Write-Step 'Ensuring publish toolchain (PackageManagement + PowerShellGet)'
Initialize-PublishToolchain

Write-Step 'Building module staging package'
$package = Initialize-ModulePackage `
    -SourceScript $SourceScriptPath `
    -Name $ModuleName `
    -Version $ModuleVersion `
    -ModuleDescription $packageDescription `
    -ReadmeSourcePath $ReadmePath `
    -AboutSourcePath $AboutPath
Write-Info "Staging path: $($package.ModulePath)"

Write-Step 'Publishing to PowerShell Gallery'
$global:LASTEXITCODE = 0
try {
    $publishParams = @{
        Path        = $package.ModulePath
        Repository  = $Repository
        NuGetApiKey = $NuGetApiKey
        Force       = $true
        ErrorAction = 'Stop'
    }
    if ($VerbosePreference -ne 'SilentlyContinue') {
        $publishParams.Verbose = $true
    }
    Publish-Module @publishParams
}
catch {
    $msg = $_.Exception.Message
    if ($msg -match '403' -or $msg -match 'API key is invalid' -or $msg -match 'does not have permission') {
        Write-IssueReport -Heading 'Publish failed. Package was not uploaded.' -Issues @(
            New-PrereqIssue `
                -Title 'Authentication/authorization error' `
                -Detail "PowerShell Gallery rejected the API key for module '$ModuleName'." `
                -FixCommands @(
                    'Use a valid PSGallery API key (active, not expired, push scope).',
                    "Ensure your account is an owner of '$ModuleName'.",
                    'If key exposure is possible, revoke and rotate the key.',
                    'Re-run publish with the new key.'
                )
        )
        return
    }
    if ($msg -match 'Failed to generate the compressed file' -or $msg -match 'failed to pack' -or $msg -match 'NU1100') {
        Write-IssueReport -Heading 'Publish failed. Package was not uploaded.' -Issues @(
            New-PrereqIssue `
                -Title 'Packaging failed during dotnet restore/pack' `
                -Detail 'Publish-Module could not build the temporary NuGet package (commonly missing/disabled nuget.org source).' `
                -FixCommands @(
                    'dotnet nuget list source',
                    'dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org',
                    'dotnet nuget enable source nuget.org'
                )
        )
        return
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
