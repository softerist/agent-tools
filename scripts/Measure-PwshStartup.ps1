[CmdletBinding()]
param(
    [int]$Iterations = 7,
    [string]$PwshPath = 'pwsh'
)

$script:StartupIterations = $Iterations
$script:StartupPwshPath = $PwshPath

function Get-PercentileValue {
    param(
        [double[]]$Values,
        [double]$Percentile
    )

    if (-not $Values -or $Values.Count -eq 0) {
        return [double]::NaN
    }

    $sorted = @($Values | Sort-Object)
    $rank = [Math]::Ceiling(($Percentile / 100.0) * $sorted.Count) - 1
    $index = [Math]::Max(0, [Math]::Min($sorted.Count - 1, [int]$rank))
    return [double]$sorted[$index]
}

function Measure-StartupMode {
    param([switch]$NoProfile)

    $samples = New-Object System.Collections.Generic.List[double]
    for ($i = 0; $i -lt $script:StartupIterations; $i++) {
        $elapsed = Measure-Command {
            $pwshArgs = @('-NoLogo', '-NonInteractive')
            if ($NoProfile) {
                $pwshArgs += '-NoProfile'
            }
            $pwshArgs += @('-Command', 'exit')
            & $script:StartupPwshPath @pwshArgs
        }
        $samples.Add([math]::Round($elapsed.TotalMilliseconds, 2)) | Out-Null
    }

    $sampleArray = @($samples)
    [pscustomobject]@{
        Mode     = if ($NoProfile) { 'NoProfile' } else { 'WithProfile' }
        SamplesMs = $sampleArray
        MedianMs = [math]::Round((Get-PercentileValue -Values $sampleArray -Percentile 50), 2)
        P95Ms    = [math]::Round((Get-PercentileValue -Values $sampleArray -Percentile 95), 2)
    }
}

$results = @(
    Measure-StartupMode -NoProfile
    Measure-StartupMode
)

$results | Format-Table -AutoSize
