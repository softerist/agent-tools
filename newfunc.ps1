function CredFromEnv {
    [CmdletBinding()]
    param(
        [string]$LogPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EnvVar,

        [AllowNull()]
        $IgnoreMissing = $false
    )

    $ignoreMissingEnabled = $false
    if ($IgnoreMissing -is [bool]) {
        $ignoreMissingEnabled = $IgnoreMissing
    }
    elseif ($null -ne $IgnoreMissing) {
        $ignoreMissingEnabled = $IgnoreMissing.ToString().Trim().Equals('true', [System.StringComparison]::OrdinalIgnoreCase)
    }

    $value = [Environment]::GetEnvironmentVariable($EnvVar, [EnvironmentVariableTarget]::Process)

    if ([string]::IsNullOrEmpty($value)) {
        if ($ignoreMissingEnabled) {
            return $null
        }

        if ($LogPath) {
            Log-Write -LogPath $LogPath -LineValue ("Environment variable '{0}' must be provided" -f $EnvVar) -Severity 'E'
        }

        exit 2
    }

    try {
        return $value
    }
    finally {
        $value = $null
    }
}
