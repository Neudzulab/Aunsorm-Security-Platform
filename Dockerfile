# syntax=docker/dockerfile:1

FROM rustlang/rust:nightly AS builder

# Build arguments (varsayılan değerler)
ARG ENABLE_OTEL=false
ARG ENABLE_HTTP3=true
ARG ENABLE_PQC=false

WORKDIR /build
COPY . .

# Feature flags ile build
RUN set -eux; \
    FEATURES=""; \
    if [ "$ENABLE_OTEL" = "true" ]; then FEATURES="$FEATURES,otel"; fi; \
    if [ "$ENABLE_HTTP3" = "true" ]; then FEATURES="$FEATURES,http3-experimental"; fi; \
    if [ "$ENABLE_PQC" = "false" ]; then \
        echo "PQC disabled - using --no-default-features"; \
        cargo build --release --locked --no-default-features -p aunsorm-server; \
    else \
        if [ -n "$FEATURES" ]; then \
            FEATURES=$(echo "$FEATURES" | sed 's/^,//'); \
            echo "Building with features: $FEATURES"; \
            cargo build --release --locked --features "$FEATURES" -p aunsorm-server; \
        else \
            cargo build --release --locked -p aunsorm-server; \
        fi; \
    fi; \
    strip target/release/aunsorm-server

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 aunsorm
WORKDIR /srv
COPY --from=builder /build/target/release/aunsorm-server /usr/local/bin/aunsorm-server
ENV AUNSORM_LISTEN=0.0.0.0:8080
ENV RUST_LOG=info
USER aunsorm
EXPOSE 8080
ENTRYPOINT ["aunsorm-server"]
