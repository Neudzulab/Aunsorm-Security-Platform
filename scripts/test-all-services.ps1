#!/usr/bin/env pwsh
#
# Aunsorm Microservices Test Script
# Tests all 14 microservices for health and functionality
#

# Service definitions
$Services = @(
    @{ Name = "Gateway"; Port = 50010; TestPath = "/health" }
    @{ Name = "Auth"; Port = 50011; TestPath = "/oauth/jwks.json" }
    @{ Name = "Crypto"; Port = 50012; TestPath = "/health" }
    @{ Name = "X509"; Port = 50013; TestPath = "/health" }
    @{ Name = "KMS"; Port = 50014; TestPath = "/health" }
    @{ Name = "MDM"; Port = 50015; TestPath = "/health" }
    @{ Name = "ID"; Port = 50016; TestPath = "/health" }
    @{ Name = "ACME"; Port = 50017; TestPath = "/acme/directory" }
    @{ Name = "PQC"; Port = 50018; TestPath = "/health" }
    @{ Name = "RNG"; Port = 50019; TestPath = "/health" }
    @{ Name = "Blockchain"; Port = 50020; TestPath = "/health" }
    @{ Name = "E2EE"; Port = 50021; TestPath = "/health" }
    @{ Name = "Metrics"; Port = 50022; TestPath = "/health" }
    @{ Name = "CLI Gateway"; Port = 50023; TestPath = "/cli/status" }
)

Write-Host "🧪 Testing Aunsorm Microservices" -ForegroundColor Blue
Write-Host "══════════════════════════════════" -ForegroundColor Blue
Write-Host ""

$SuccessCount = 0
$TotalCount = $Services.Count

$HostName = if ([string]::IsNullOrWhiteSpace($env:HOST)) { "localhost" } else { $env:HOST }

foreach ($Service in $Services) {
    $Url = "http://$HostName:$($Service.Port)$($Service.TestPath)"
    Write-Host "$($Service.Name.PadRight(12)) ($($Service.Port)): " -NoNewline
    
    try {
        $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
        if ($Response.StatusCode -eq 200) {
            Write-Host "✅ OK ($($Response.StatusCode))" -ForegroundColor Green
            $SuccessCount++
        } else {
            Write-Host "⚠️  HTTP $($Response.StatusCode)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "❌ FAILED" -ForegroundColor Red
        Write-Host "    └─ Error: $($_.Exception.Message)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "══════════════════════════════════" -ForegroundColor Blue
if ($SuccessCount -eq $TotalCount) {
    Write-Host "🎉 All $TotalCount services are working!" -ForegroundColor Green
} else {
    Write-Host "⚠️  $SuccessCount/$TotalCount services working" -ForegroundColor Yellow
}
Write-Host ""

# Extended functional tests
Write-Host "🔧 Extended Functional Tests" -ForegroundColor Blue
Write-Host "══════════════════════════════════" -ForegroundColor Blue

# Test CLI Gateway specific endpoints
Write-Host "CLI Gateway Status: " -NoNewline
try {
    $CLIResponse = Invoke-WebRequest -Uri "http://$HostName:50023/cli/status" -UseBasicParsing
    $CLIData = $CLIResponse.Content | ConvertFrom-Json
    Write-Host "✅ Available commands: $($CLIData.available_commands.Count)" -ForegroundColor Green
}
catch {
    Write-Host "❌ FAILED" -ForegroundColor Red
}

# Test Auth Service OAuth
Write-Host "Auth OAuth JWKS:   " -NoNewline
try {
    $OAuthResponse = Invoke-WebRequest -Uri "http://$HostName:50011/oauth/jwks.json" -UseBasicParsing
    Write-Host "✅ JWKS available" -ForegroundColor Green
}
catch {
    Write-Host "❌ FAILED" -ForegroundColor Red
}

Write-Host ""
Write-Host "🌟 Test completed!" -ForegroundColor Cyan
