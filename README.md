# Enable-UnixTools

Enable Unix-style CLI tooling on Windows by adding Git-for-Windows tool paths, optional shims, and profile compatibility helpers.

## Install From PowerShell Gallery

```powershell
Install-Module Enable-UnixTools
```

`Install-Module` only downloads the module. It does not apply PATH/shim changes until you run the command.

## Basic Usage

```powershell
Import-Module Enable-UnixTools -Force
Enable-UnixTools -InstallFull
```

Examples:

```powershell
Enable-UnixTools -InstallFull -UserScope
Enable-UnixTools -CreateShims -InstallProfileShims -InstallOptionalTools -RepairWinget
Enable-UnixTools -Uninstall
Enable-UnixTools -Uninstall -UninstallOptionalTools
```

## Uninstall Semantics

- Remove Unix tools configuration (PATH/shims/profile):

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
Enable-UnixTools -UserScope -CreateShims -InstallProfileShims -InstallOptionalTools -AddMingw -AddGitCmd -NormalizePath
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

`publish.ps1` supports and packages:

- tags
- release notes
- project/license/icon URIs
- `README.md` (existing or auto-generated)
- `about_<ModuleName>.help.txt` (existing or auto-generated)

If publish returns HTTP 403, your PSGallery API key is invalid/expired, not scoped for this package, or package ownership does not match the publishing account.
