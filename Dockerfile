# syntax=docker/dockerfile:1

FROM rustlang/rust:nightly AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked -p aunsorm-server \
    && strip target/release/aunsorm-server

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
