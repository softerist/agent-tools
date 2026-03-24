# Enable-UnixTools

Enable Unix-style CLI tooling on Windows by adding Git-for-Windows tool paths, optional shims, and profile compatibility helpers.

## Install From PowerShell Gallery

```powershell
Install-Module -Name Enable-UnixTools
Import-Module Enable-UnixTools
Enable-UnixTools -InstallFull -ProfileStartupMode Fast -PromptInitMode Lazy
```

## Basic Usage

```powershell
Import-Module Enable-UnixTools -Force
Enable-UnixTools -InstallFull -ProfileStartupMode Fast -PromptInitMode Lazy
```

Examples:

```powershell
Enable-UnixTools -InstallFull -UserScope
Enable-UnixTools -CreateShims -InstallProfileShims -InstallOptionalTools -InstallTerminalSetup -ProfileStartupMode Fast -PromptInitMode Lazy
Enable-UnixTools -Uninstall
Enable-UnixTools -Uninstall -UninstallOptionalTools
```

Defaults:

- `-ProfileStartupMode Fast` keeps startup imports minimal and exposes `Enable-UnixInteractiveFeatures` for on-demand shell extras.
- `-PromptInitMode Lazy` installs a minimal prompt first, then applies Oh My Posh on a later prompt.

## Uninstall Semantics

- Remove Unix tools configuration (PATH/shims/profile) and keep tracked optional tools:

```powershell
Enable-UnixTools -Uninstall
```

- Also remove tracked optional tools installed by this script:

```powershell
Enable-UnixTools -Uninstall -UninstallOptionalTools
```

- Remove the PowerShell module package itself:

```powershell
Uninstall-Module Enable-UnixTools -AllVersions -Force
```

## Troubleshooting

### `Install-Module` produced no output

That is usually normal on success. Verify:

```powershell
Get-InstalledModule Enable-UnixTools
Get-Command Enable-UnixTools -All
```

### `Enable-UnixTools -InstallFull` appears to skip steps

Check command resolution and defaults:

```powershell
Get-Command Enable-UnixTools -All | Format-List CommandType,Source,Version,Definition
$PSDefaultParameterValues.GetEnumerator() | Where-Object Key -match 'TrustedShimRoot|Enable-UnixTools'
```

If needed:

```powershell
$PSDefaultParameterValues.Remove('*:TrustedShimRoot')
Enable-UnixTools -UserScope -CreateShims -InstallProfileShims -InstallOptionalTools -InstallTerminalSetup -AddMingw -AddGitCmd -NormalizePath -ProfileStartupMode Fast -PromptInitMode Lazy
```

If an older profile install left unmarked inline shims behind, re-run:

```powershell
Enable-UnixTools -InstallProfileShims -ProfileStartupMode Fast -PromptInitMode Lazy
```

After install/uninstall, open a new terminal and verify:

```powershell
where.exe grep
Get-Command grep -All
grep --version
```

## Publishing

Use the interactive publisher script:

```powershell
powershell -ExecutionPolicy Bypass -File .\publish.ps1
```

If publish prerequisites are missing, `publish.ps1` now auto-applies safe preflight fixes first (for example, adding/enabling dotnet `nuget.org` source). If a prerequisite still cannot be fixed automatically, it stops early and prints exact manual fix commands.

`publish.ps1` supports and packages:

- tags
- release notes
- project/license/icon URIs
- `README.md` (existing or auto-generated)
- `about_<ModuleName>.help.txt` (existing or auto-generated)

If publish returns HTTP 403, your PSGallery API key is invalid/expired, not scoped for this package, or package ownership does not match the publishing account.
