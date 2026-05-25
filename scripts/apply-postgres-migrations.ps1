<#
.SYNOPSIS
Applies PostgreSQL migrations in lexical order.

.DESCRIPTION
Runs every `*.sql` migration under `migrations/postgres` with `psql` and
`ON_ERROR_STOP=1`. The DSN is read from `-DatabaseUrl` or `DATABASE_URL`.
#>

[CmdletBinding()]
param(
    [string]$DatabaseUrl = $env:DATABASE_URL,
    [string]$MigrationsPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($MigrationsPath)) {
    $MigrationsPath = Join-Path $repoRoot 'migrations/postgres'
}

if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) {
    throw 'DATABASE_URL is required. Pass -DatabaseUrl or set the DATABASE_URL environment variable.'
}

$psql = Get-Command psql -ErrorAction SilentlyContinue
if ($null -eq $psql) {
    throw 'psql was not found on PATH.'
}

if (-not (Test-Path -LiteralPath $MigrationsPath -PathType Container)) {
    throw "Migration directory not found: $MigrationsPath"
}

$migrationFiles = Get-ChildItem -LiteralPath $MigrationsPath -Filter '*.sql' -File |
    Where-Object { $_.Name -notlike '*_down.sql' } |
    Sort-Object Name

if ($migrationFiles.Count -eq 0) {
    throw "No migration files found in $MigrationsPath"
}

foreach ($migration in $migrationFiles) {
    Write-Host ("==> Applying {0}" -f $migration.Name) -ForegroundColor Green
    & $psql.Source $DatabaseUrl -v ON_ERROR_STOP=1 -f $migration.FullName
    if ($LASTEXITCODE -ne 0) {
        throw "Migration failed: $($migration.FullName)"
    }
}

Write-Host 'PostgreSQL migrations completed.' -ForegroundColor Green

