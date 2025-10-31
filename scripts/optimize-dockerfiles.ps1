# Docker Build Cache Optimization Script
# This script adds dependency caching to all Dockerfiles

$dockerfiles = @(
    "docker/Dockerfile.auth",
    "docker/Dockerfile.crypto", 
    "docker/Dockerfile.x509",
    "docker/Dockerfile.kms",
    "docker/Dockerfile.mdm",
    "docker/Dockerfile.acme",
    "docker/Dockerfile.id",
    "docker/Dockerfile.pqc",
    "docker/Dockerfile.rng",
    "docker/Dockerfile.blockchain",
    "docker/Dockerfile.e2ee",
    "docker/Dockerfile.metrics"
)

$optimizedBuilder = @"
FROM rustlang/rust:nightly AS builder

WORKDIR /build

# Copy only Cargo files first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml ./crates/*/

# Create dummy main.rs files to enable dependency pre-build
RUN find crates -name Cargo.toml -exec dirname {} \; | xargs -I {} mkdir -p {}/src
RUN find crates -name Cargo.toml -exec dirname {} \; | xargs -I {} touch {}/src/lib.rs
RUN echo "fn main() {}" > src/main.rs

# Build dependencies only (will be cached)
RUN cargo build --release --locked

# Remove dummy sources
RUN rm -rf src crates/*/src

# Copy real source code
COPY . .

# Build server binary
RUN cargo build --release --locked -p aunsorm-server
"@

foreach ($dockerfile in $dockerfiles) {
    if (Test-Path $dockerfile) {
        Write-Host "Optimizing $dockerfile..."
        $content = Get-Content $dockerfile -Raw
        
        # Replace the builder stage with optimized version
        $newContent = $content -replace 'FROM rustlang/rust:nightly AS builder\s*WORKDIR /build\s*COPY \. \.\s*(?:#[^\r\n]*[\r\n]*)?\s*RUN cargo build --release --locked -p aunsorm-server', $optimizedBuilder
        
        if ($newContent -ne $content) {
            Set-Content -Path $dockerfile -Value $newContent -NoNewline
            Write-Host "✅ Optimized $dockerfile"
        } else {
            Write-Host "⚠️  No optimization needed for $dockerfile"
        }
    }
}

Write-Host "🎉 Docker cache optimization complete!"
Write-Host ""
Write-Host "Benefits:"
Write-Host "- Dependencies cached separately from source code"
Write-Host "- Subsequent builds will be much faster"
Write-Host "- Only source changes trigger full rebuild"