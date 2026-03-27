# Enable-UnixTools

Enable Unix-style CLI tooling on Windows by adding Git-for-Windows tool paths, optional shims, and profile compatibility helpers.

## Install From PowerShell Gallery

```powershell
Install-Module -Name Enable-UnixTools
Import-Module Enable-UnixTools
Enable-UnixTools -InstallFull -ProfileStartupMode Fast -PromptInitMode Eager
```

## Basic Usage

```powershell
Import-Module Enable-UnixTools -Force
Enable-UnixTools -InstallFull -ProfileStartupMode Fast -PromptInitMode Eager
```

Examples:

```powershell
Enable-UnixTools -InstallFull -UserScope
Enable-UnixTools -CreateShims -InstallProfileShims -InstallOptionalTools -InstallTerminalSetup -ProfileStartupMode Fast -PromptInitMode Eager
Enable-UnixTools -Uninstall
Enable-UnixTools -Uninstall -UninstallOptionalTools
```

Defaults:

- `-ProfileStartupMode Fast` keeps startup imports minimal and exposes `Enable-UnixInteractiveFeatureSet` for on-demand shell extras.
- `-PromptInitMode Eager` initializes Oh My Posh during profile load so the theme is active on the first prompt.
- `uutils.coreutils` is installed as the base Unix command layer when optional tools are installed. For GNU-sensitive core commands like `ls`, `cp`, `mv`, `rm`, `cat`, and `sort`, resolution still prefers Git's binaries; for the rest, the shims prefer coreutils when both are present.
- `lightgreen.omp.json` is automatically patched after theme install to keep a cleaner right prompt and a more polished folder path. `Terminal-Icons` plus `CaskaydiaCove NF` provide the file/folder glyphs.

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
Enable-UnixTools -UserScope -CreateShims -InstallProfileShims -InstallOptionalTools -InstallTerminalSetup -AddMingw -AddGitCmd -NormalizePath -ProfileStartupMode Fast -PromptInitMode Eager
```

If an older profile install left unmarked inline shims behind, re-run:

```powershell
Enable-UnixTools -InstallProfileShims -ProfileStartupMode Fast -PromptInitMode Eager
```

### `rg` regex with `|` runs pieces as commands

If `rg -n "a|b|c"` prints messages like `'b' is not recognized as an internal or external command`, PowerShell is resolving `rg` through a Git `shims\rg.cmd` wrapper instead of a real `rg.exe`. Refresh the generated profile shims:

```powershell
Enable-UnixTools -InstallProfileShims -ProfileStartupMode Fast -PromptInitMode Eager
```

Then open a new PowerShell session and verify:

```powershell
Get-UnixShimExecutable -Name rg | Format-List Name,Source
```

### Codex shell shows `Terminal-Icons` or `oh-my-posh` startup warnings

Codex and Antigravity shells can run with sandboxed or proxied startup behavior, so profile code that writes caches under `%APPDATA%` can be noisy. Current generated profiles automatically skip `Terminal-Icons` and `oh-my-posh` when Codex or Antigravity environment variables are present. Re-run profile installation to refresh an older profile:

```powershell
Enable-UnixTools -InstallProfileShims -ProfileStartupMode Fast -PromptInitMode Eager
```

Git Bash and other `bash`-based agent shells do not read the PowerShell profile, so this specific fix does not apply there. If you initialize a prompt/theme in `.bashrc` or `.bash_profile`, gate it the same way:

```bash
if [[ -z "${CODEX_THREAD_ID:-}" && -z "${CODEX_INTERNAL_ORIGINATOR_OVERRIDE:-}" && -z "${ANTIGRAVITY_CLI_ALIAS:-}" ]]; then
  # example:
  # eval "$(oh-my-posh init bash --config /path/to/theme.omp.json)"
fi
```

Useful checks in `bash`:

```bash
type -a rg
env | grep -E 'CODEX|ANTIGRAVITY'
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
