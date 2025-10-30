param(
    [Parameter(Mandatory=$true)]
    [string]$Token
)

$parts = $Token.Split('.')
if ($parts.Count -ne 3) {
    Write-Error "Invalid JWT format"
    exit 1
}

# Decode header
Write-Host "`n=== JWT HEADER ===" -ForegroundColor Cyan
$headerPadded = $parts[0]
while ($headerPadded.Length % 4 -ne 0) { $headerPadded += "=" }
$headerJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($headerPadded))
$headerJson | ConvertFrom-Json | ConvertTo-Json -Depth 10

# Decode payload
Write-Host "`n=== JWT PAYLOAD ===" -ForegroundColor Green
$payloadPadded = $parts[1]
while ($payloadPadded.Length % 4 -ne 0) { $payloadPadded += "=" }
$payloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payloadPadded))
$payloadJson | ConvertFrom-Json | ConvertTo-Json -Depth 10

Write-Host "`n=== RAW PAYLOAD JSON ===" -ForegroundColor Yellow
Write-Host $payloadJson
