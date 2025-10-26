# Build all services locally without pulling from registry
Write-Host "🏗️ Building all Aunsorm services locally..." -ForegroundColor Green

# Build each service individually
$services = @(
    "gateway", "auth-service", "crypto-service", "x509-service", 
    "kms-service", "mdm-service", "acme-service", "id-service",
    "pqc-service", "rng-service", "blockchain-service", "e2ee-service",
    "metrics-service", "cli-gateway"
)

foreach ($service in $services) {
    Write-Host "Building $service..." -ForegroundColor Yellow
    docker-compose --env-file .env build --no-cache $service
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to build $service" -ForegroundColor Red
    } else {
        Write-Host "✅ Successfully built $service" -ForegroundColor Green
    }
}

Write-Host "🎉 All services built!" -ForegroundColor Green
Write-Host "To start services: docker-compose --env-file .env up -d" -ForegroundColor Cyan