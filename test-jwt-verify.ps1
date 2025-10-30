# Test JWT Verify endpoint - check for duplicate fields

# First, generate a token
$generateBody = @{
    roomId = "test-room"
    identity = "user123"
    participantName = "TestUser"
    metadata = @{
        codec = "vp9"
        appData = @{
            role = "host"
        }
    }
} | ConvertTo-Json -Depth 10

Write-Host "=== Generating JWT Token ===" -ForegroundColor Cyan
$response = Invoke-RestMethod -Uri "http://localhost:50011/security/generate-media-token" -Method Post -Body $generateBody -ContentType "application/json"
$token = $response.token

Write-Host "Token generated: $($token.Substring(0, 50))..." -ForegroundColor Green
Write-Host ""

# Now verify it
Write-Host "=== Verifying JWT Token ===" -ForegroundColor Cyan
$verifyBody = @{
    token = $token
} | ConvertTo-Json

$verifyResponse = Invoke-RestMethod -Uri "http://localhost:50011/security/jwt-verify" -Method Post -Body $verifyBody -ContentType "application/json"

Write-Host "Valid: $($verifyResponse.valid)" -ForegroundColor Green
Write-Host ""
Write-Host "=== Payload Structure ===" -ForegroundColor Yellow
$verifyResponse.payload | ConvertTo-Json -Depth 10 | Write-Host

# Check for duplicate fields
Write-Host ""
Write-Host "=== Checking for Duplicate Fields ===" -ForegroundColor Magenta
$jsonText = $verifyResponse | ConvertTo-Json -Depth 10
if ($jsonText -match '"audience".*"audience"' -or $jsonText -match '"aud".*"audience"') {
    Write-Host "❌ DUPLICATE FIELD DETECTED!" -ForegroundColor Red
} else {
    Write-Host "✅ No duplicate fields - Response structure is clean!" -ForegroundColor Green
}

# Show extras separately
if ($verifyResponse.payload.extras) {
    Write-Host ""
    Write-Host "=== Extras Object ===" -ForegroundColor Yellow
    $verifyResponse.payload.extras | ConvertTo-Json -Depth 10 | Write-Host
}
