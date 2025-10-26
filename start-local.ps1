# Start services with local builds only
Write-Host "🚀 Starting Aunsorm microservices..." -ForegroundColor Green

# Use --build to ensure local images are used, not pulled from registry
docker-compose --env-file .env up --build -d

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ All services started successfully!" -ForegroundColor Green
    Write-Host "📊 Service status:" -ForegroundColor Cyan
    docker-compose ps
} else {
    Write-Host "❌ Failed to start some services" -ForegroundColor Red
}