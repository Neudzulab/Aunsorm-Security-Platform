# UTF-8 Encoding Fix for PowerShell
# Run this before starting aunsorm-server to fix Turkish character display
#
# Usage:
#   . .\scripts\set-utf8-encoding.ps1
#   cargo run --release -p aunsorm-server

Write-Host "Setting console encoding to UTF-8..." -ForegroundColor Green
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "✓ UTF-8 encoding enabled" -ForegroundColor Green
Write-Host "  OutputEncoding: $([Console]::OutputEncoding.EncodingName)" -ForegroundColor Cyan
Write-Host "  InputEncoding: $([Console]::InputEncoding.EncodingName)" -ForegroundColor Cyan

# Optionally set RUST_LOG if not already set
if (-not $env:RUST_LOG) {
    $env:RUST_LOG = "info"
    Write-Host "✓ RUST_LOG set to 'info'" -ForegroundColor Green
}
