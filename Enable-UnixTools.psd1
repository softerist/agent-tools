@{
    RootModule        = 'Enable-UnixTools.psm1'
    ModuleVersion     = '2.4.0'
    GUID              = 'd5e6e1eb-b2f4-43fe-8e6c-a1fc50d47313'
    Author            = 'softerist'
    CompanyName       = 'softerist'
    Copyright         = '(c) softerist. All rights reserved.'
    Description       = 'Adds Unix-compatible tools to Windows PATH with optional shims and profile wrappers.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Enable-UnixTool')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @('Enable-UnixTools')
    FileList          = @(
        'Enable-UnixTools.psm1'
        'Enable-UnixTools.psd1'
        'Enable-UnixTools.ps1'
        'README.md'
        'catalogs\core-shim-tools.json'
        'catalogs\optional-modules.json'
        'catalogs\optional-tools.json'
        'src\Private\Bootstrap.ps1'
        'src\Private\CommandResolution.ps1'
        'src\Private\FileIO.ps1'
        'src\Private\MainExecutionBody.ps1'
        'src\Private\MainOrchestration.ps1'
        'src\Private\OptionalTools.ps1'
        'src\Private\Output.ps1'
        'src\Private\PathManagement.ps1'
        'src\Private\ProfileMigration.ps1'
        'src\Private\ProfileSupportInstall.ps1'
        'src\Private\TerminalSetup.ps1'
        'src\ProfileSupport\UnixTools.AliasCompat.ps1'
        'src\ProfileSupport\UnixTools.MissingShims.ps1'
        'src\ProfileSupport\UnixTools.ProfileLoader.ps1'
        'src\ProfileSupport\UnixTools.ProfileShared.ps1'
        'src\ProfileSupport\UnixTools.Prompt.ps1'
        'src\ProfileSupport\UnixTools.SmartShell.ps1'
        'src\Public\Invoke-EnableUnixTools.ps1'
    )
    PrivateData       = @{
        PSData = @{
            Tags         = @('unix', 'windows', 'path', 'shims', 'cli')
            ReleaseNotes = 'Adds startup-mode and prompt-mode controls, legacy profile cleanup, wrapper parity, and safer uninstall semantics.'
        }
    }
}
