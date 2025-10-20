<#
.SYNOPSIS
Runs the standard formatting, linting, and test pipeline for the workspace.

.DESCRIPTION
Executes `cargo fmt --all`, `cargo clippy --all-targets --all-features`, and
`cargo test --all-features` from the repository root. You can skip individual
steps with the optional switches documented below.
#>

[CmdletBinding()]
param(
    [switch]$SkipFmt,
    [switch]$SkipClippy,
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$summary = [ordered]@{
    Fmt    = [ordered]@{ Status = if ($SkipFmt) { 'Skipped' } else { 'Pending' } }
    Clippy = [ordered]@{ Status = if ($SkipClippy) { 'Skipped' } else { 'Pending' } }
    Tests  = [ordered]@{
        Status = if ($SkipTests) { 'Skipped' } else { 'Pending' }
        Totals = $null
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$originalLocation = Get-Location
Push-Location -LiteralPath $repoRoot

try {

function Invoke-Step {
    param(
        [string]$Title,
        [scriptblock]$Action
    )

    Write-Host ("==> {0}" -f $Title) -ForegroundColor Green
    & $Action
    Write-Host ("    {0} completed." -f $Title) -ForegroundColor DarkGray
}

function Invoke-Cargo {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CommandArgs,
        [switch]$CaptureOutput
    )

    Write-Host ("cargo {0}" -f ($CommandArgs -join ' ')) -ForegroundColor Cyan

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        if ($CaptureOutput) {
            $captured = & cargo @CommandArgs 2>&1 | Tee-Object -Variable teeBuffer
            $global:__lastCapturedLines = $teeBuffer
        } else {
            $captured = & cargo @CommandArgs
            $global:__lastCapturedLines = @()
        }
    } finally {
        $ErrorActionPreference = $previousPreference
    }

    if ($LASTEXITCODE -ne 0) {
        throw "cargo $($CommandArgs -join ' ') failed with exit code $LASTEXITCODE"
    }

    return $captured
}

if (-not $SkipFmt) {
    Invoke-Step "cargo fmt --all" {
        Invoke-Cargo -CommandArgs @("fmt", "--all")
    }
    $summary.Fmt.Status = 'Success'
} else {
    Write-Host "Skipping cargo fmt" -ForegroundColor Yellow
}

if (-not $SkipClippy) {
    Invoke-Step "cargo clippy --all-targets --all-features" {
        Invoke-Cargo -CommandArgs @("clippy", "--all-targets", "--all-features")
    }
    $summary.Clippy.Status = 'Success'
} else {
    Write-Host "Skipping cargo clippy" -ForegroundColor Yellow
}

if (-not $SkipTests) {
    Invoke-Step "cargo test --workspace --all-targets --all-features" {
        $global:__lastCapturedLines = @()
        $previousTestThreads = $env:RUST_TEST_THREADS
        $env:RUST_TEST_THREADS = '1'
        try {
            Invoke-Cargo -CommandArgs @("test", "--workspace", "--all-targets", "--all-features") -CaptureOutput
        } finally {
            if ($null -eq $previousTestThreads) {
                Remove-Item Env:RUST_TEST_THREADS -ErrorAction SilentlyContinue
            } else {
                $env:RUST_TEST_THREADS = $previousTestThreads
            }

            $summaryPattern = 'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out'
            $totals = [ordered]@{
                Crates        = 0
                Passed        = 0
                Failed        = 0
                Ignored       = 0
                Measured      = 0
                FilteredOut   = 0
                FailuresExist = $false
            }

            foreach ($line in $global:__lastCapturedLines) {
                $cleanLine = $line -replace '\x1b\[[0-9;]*m', ''
                if ($cleanLine -match $summaryPattern) {
                    $totals.Crates++
                    $totals.Passed      += [int]$Matches[2]
                    $totals.Failed      += [int]$Matches[3]
                    $totals.Ignored     += [int]$Matches[4]
                    $totals.Measured    += [int]$Matches[5]
                    $totals.FilteredOut += [int]$Matches[6]
                    if ($Matches[1] -ne 'ok') {
                        $totals.FailuresExist = $true
                    }
                }
            }

            if ($totals.Crates -gt 0) {
                $summary.Tests.Status = if ($totals.FailuresExist -or $totals.Failed -gt 0) { 'Failed' } else { 'Success' }
                $summary.Tests.Totals = $totals
                $statusColor = if ($totals.FailuresExist -or $totals.Failed -gt 0) { 'Red' } else { 'Green' }
                Write-Host ("-- Test Summary: {0} crates | {1} passed | {2} failed | {3} ignored | {4} measured | {5} filtered out" -f `
                    $totals.Crates, $totals.Passed, $totals.Failed, $totals.Ignored, $totals.Measured, $totals.FilteredOut) -ForegroundColor $statusColor
            } else {
                Write-Host "-- Test Summary: No 'test result' markers found in cargo output." -ForegroundColor Yellow
            }
        }
    }
    if ($summary.Tests.Status -eq 'Pending') {
        $summary.Tests.Status = 'Success'
    }
} else {
    Write-Host "Skipping cargo test" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "== Pipeline Summary ==" -ForegroundColor Cyan
Write-Host ("  fmt    : {0}" -f $summary.Fmt.Status)
Write-Host ("  clippy : {0}" -f $summary.Clippy.Status)
if ($summary.Tests.Totals) {
    Write-Host ("  tests  : {0} ({1} passed / {2} failed / {3} ignored)" -f `
        $summary.Tests.Status, `
        $summary.Tests.Totals.Passed, `
        $summary.Tests.Totals.Failed, `
        $summary.Tests.Totals.Ignored)
} else {
    Write-Host ("  tests  : {0}" -f $summary.Tests.Status)
}

Write-Host "All requested checks completed successfully." -ForegroundColor Green

} finally {
    Pop-Location
}
