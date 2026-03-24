@{
    RootModule        = 'Enable-UnixTools.psm1'
    ModuleVersion     = '2.4.0'
    GUID              = 'd5e6e1eb-b2f4-43fe-8e6c-a1fc50d47313'
    Author            = 'softerist'
    CompanyName       = 'softerist'
    Copyright         = '(c) softerist. All rights reserved.'
    Description       = 'Adds Unix-compatible tools to Windows PATH with optional shims and profile wrappers.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Enable-UnixTools')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    FileList          = @('Enable-UnixTools.psm1', 'Enable-UnixTools.psd1', 'Enable-UnixTools.ps1', 'README.md')
    PrivateData       = @{
        PSData = @{
            Tags         = @('unix', 'windows', 'path', 'shims', 'cli')
            ReleaseNotes = 'Adds startup-mode and prompt-mode controls, legacy profile cleanup, wrapper parity, and safer uninstall semantics.'
        }
    }
}
