# Enable-UnixTools

Enable Unix-style CLI tooling on Windows by adding Git-for-Windows tool paths and optional app installs, without large fallback shim layers.

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
Enable-UnixTools -InstallOptionalTools -InstallTerminalSetup
Enable-UnixTools -Uninstall
Enable-UnixTools -Uninstall -UninstallOptionalTools
```

Defaults:

- `-ProfileStartupMode Fast` keeps startup imports minimal and exposes `Enable-UnixInteractiveFeatureSet` for on-demand shell extras.
- `-PromptInitMode Lazy` keeps profile load low by warming the full Oh My Posh prompt after the first prompt. Use `-PromptInitMode Eager` if you prefer the fully themed first prompt and can accept slower startup.
- `uutils.coreutils` is installed as the base Unix command layer when optional tools are installed. For GNU-sensitive core commands like `ls`, `cp`, `mv`, `rm`, `cat`, and `sort`, resolution still prefers Git's binaries; for the rest, real executables on PATH are used directly.
- PowerShell fallback shims are not installed. A small passthrough wrapper is installed only for the PowerShell-colliding command names `ls`, `cp`, `mv`, `rm`, `cat`, and `sort` so those names resolve to the real Unix executable instead of the built-in alias/cmdlet.
- When `eza` is available, `ls` prefers `eza` over `ls.exe`. Classic `ls -lf` is translated to the closest `eza` equivalent.
- `lightgreen.omp.json` is automatically patched after theme install to keep a cleaner right prompt and a more polished folder path. `Terminal-Icons` plus `CaskaydiaCove NF` provide the file/folder glyphs.

## Uninstall Semantics

- Remove Unix tools configuration and keep tracked optional tools:

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
$PSDefaultParameterValues.GetEnumerator() | Where-Object Key -match 'Enable-UnixTools'
```

If needed:

```powershell
Enable-UnixTools -UserScope -InstallOptionalTools -InstallTerminalSetup -AddMingw -AddGitCmd -NormalizePath
```

If an older install left shim wrappers behind, re-run:

```powershell
Enable-UnixTools
```

### `rg` regex with `|` runs pieces as commands

If `rg -n "a|b|c"` prints messages like `'b' is not recognized as an internal or external command`, PowerShell is likely resolving `rg` through a stale Git `shims\rg.cmd` wrapper instead of a real `rg.exe`. Re-run the installer to clean shim paths and keep only real apps:

```powershell
Enable-UnixTools
```

Then open a new PowerShell session and verify:

```powershell
Get-Command rg -All | Format-List Name,Source
```

### Codex shell shows `Terminal-Icons` or `oh-my-posh` startup warnings

Codex and Antigravity shells can run with sandboxed or proxied startup behavior, so profile code that writes caches under `%APPDATA%` can be noisy. Current generated profiles automatically skip `Terminal-Icons` and `oh-my-posh` when Codex or Antigravity environment variables are present. Re-run profile installation to refresh an older profile:

```powershell
Enable-UnixTools
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
