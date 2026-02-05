#!/usr/bin/env pwsh
#
# Aunsorm Microservices Start Script
# Builds and starts all 14 microservices
#

param(
    [switch]$Force,      # Force rebuild even if images exist
    [switch]$Logs,       # Show logs after starting
    [switch]$Help        # Show help
)

# Colors for output (PowerShell compatible)
function Write-Success($message) { Write-Host $message -ForegroundColor Green }
function Write-Warning($message) { Write-Host $message -ForegroundColor Yellow }
function Write-Error($message) { Write-Host $message -ForegroundColor Red }
function Write-Info($message) { Write-Host $message -ForegroundColor Blue }

function Write-Status {
    param($Message, $Color = "Green")
    Write-Host "[INFO] $Message" -ForegroundColor $Color
}

function Write-ScriptWarning {
    param($Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ScriptError {
    param($Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Show-Help {
    Write-Host @"
${Blue}Aunsorm Microservices Start Script${Reset}

Usage: ./start-all.ps1 [OPTIONS]

Options:
  -Force    Force rebuild all images even if they exist
  -Logs     Show logs after starting services
  -Help     Show this help message

Services:
  Gateway:          :50010
  Auth Service:     :50011  
  Crypto Service:   :50012
  X509 Service:     :50013
  KMS Service:      :50014
  MDM Service:      :50015
  ID Service:       :50016
  ACME Service:     :50017
  PQC Service:      :50018
  RNG Service:      :50019
  Blockchain:       :50020
  E2EE Service:     :50021
  Metrics:          :50022
  CLI Gateway:      :50023

Examples:
  ./start-all.ps1           # Smart start (build if needed)
  ./start-all.ps1 -Force    # Force rebuild all
  ./start-all.ps1 -Logs     # Start and show logs
"@
}

function Test-ImageExists {
    param($ImageName)
    $result = docker images --format "{{.Repository}}:{{.Tag}}" | Select-String "^$ImageName$"
    return $result -ne $null
}

function Test-DockerRunning {
    try {
        docker info | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Build-Services {
    param($ServicesToBuild)
    
    if ($ServicesToBuild.Count -eq 0) {
        Write-Status "All images exist, skipping build phase"
        return $true
    }

    Write-Status "Building $($ServicesToBuild.Count) services: $($ServicesToBuild -join ', ')"
    
    try {
        foreach ($service in $ServicesToBuild) {
            Write-Status "Building $service..." "Blue"
            docker-compose build $service
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Failed to build $service"
                return $false
            }
        }
        Write-Status "Build completed successfully"
        return $true
    }
    catch {
        Write-Error "Build failed: $_"
        return $false
    }
}

function Start-AllServices {
    $HostName = if ([string]::IsNullOrWhiteSpace($env:HOST)) { "localhost" } else { $env:HOST }

    Write-Status "Starting all microservices..." "Blue"
    
    try {
        docker-compose up -d
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to start services"
            return $false
        }
        
        Write-Status "Services starting, waiting for health checks..."
        Start-Sleep -Seconds 5
        
        # Check service status
        $status = docker-compose ps --format "table {{.Name}}\t{{.Status}}"
        Write-Host "`n$status`n"
        
        Write-Status "All services started successfully!"
        Write-Status "Gateway available at: ${Blue}http://$HostName:50010${Reset}"
        
        return $true
    }
    catch {
        Write-Error "Failed to start services: $_"
        return $false
    }
}

function Stop-AllServices {
    Write-Status "Stopping services gracefully..." "Yellow"
    docker-compose down --remove-orphans
}

function Show-ServiceLogs {
    Write-Status "Showing service logs (Ctrl+C to exit)..." "Blue"
    docker-compose logs -f --tail=50
}

# Main execution
if ($Help) {
    Show-Help
    exit 0
}

Write-Host "🚀 Aunsorm Microservices Starter" -ForegroundColor Blue
Write-Host "═══════════════════════════════════════"

# Check Docker
if (-not (Test-DockerRunning)) {
    Write-Error "Docker is not running. Please start Docker Desktop first."
    exit 1
}

# Define all services and their images
$Services = @{
    "gateway" = "aunsorm-gateway:local"
    "auth-service" = "aunsorm-auth:local"
    "crypto-service" = "aunsorm-crypto:local"
    "x509-service" = "aunsorm-x509:local"
    "kms-service" = "aunsorm-kms:local"
    "mdm-service" = "aunsorm-mdm:local"
    "id-service" = "aunsorm-id:local"
    "acme-service" = "aunsorm-acme:local"
    "pqc-service" = "aunsorm-pqc:local"
    "rng-service" = "aunsorm-rng:local"
    "blockchain-service" = "aunsorm-blockchain:local"
    "e2ee-service" = "aunsorm-e2ee:local"
    "metrics-service" = "aunsorm-metrics:local"
    "cli-gateway" = "aunsorm-cli-gateway:local"
}

# Check which services need building
$ServicesToBuild = @()

if ($Force) {
    Write-Warning "Force rebuild requested - rebuilding all services"
    $ServicesToBuild = $Services.Keys
} else {
    Write-Status "Checking existing images..."
    
    foreach ($service in $Services.Keys) {
        $image = $Services[$service]
        if (-not (Test-ImageExists $image)) {
            Write-Status "Missing image: $image" "Yellow"
            $ServicesToBuild += $service
        } else {
            Write-Status "Found image: $image" "Green"
        }
    }
}

# Build phase
if (-not (Build-Services $ServicesToBuild)) {
    Write-Error "Build failed, aborting startup"
    exit 1
}

# Startup phase
if (-not (Start-AllServices)) {
    Write-Error "Startup failed"
    exit 1
}

# Show logs if requested
if ($Logs) {
    Start-Sleep -Seconds 2
    Show-ServiceLogs
}

Write-Host "`n✅ All services are running successfully!" -ForegroundColor Green
Write-Host "Use " -NoNewline; Write-Host "docker-compose logs -f" -ForegroundColor Blue -NoNewline; Write-Host " to view logs"
Write-Host "Use " -NoNewline; Write-Host "docker-compose down" -ForegroundColor Blue -NoNewline; Write-Host " to stop services"
Write-Host "Use " -NoNewline; Write-Host "./start-all.ps1 -Help" -ForegroundColor Blue -NoNewline; Write-Host " for more options"
