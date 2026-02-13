# Deployment Quick Start

## Prerequisites
- Docker and Docker Compose
- `.env` populated with port overrides and calibration values (see `.env.example`)

## Steps
1. Build and start services:
   ```bash
   docker compose up --build
   ```
2. Verify health and calibration:
   ```bash
   curl http://${HOST:-localhost}:50010/health | jq
   ```
3. Run CLI verification against the gateway:
   ```bash
   cargo run -p aunsorm-cli -- jwt verify --token <token> --format json
   ```
4. Stop and clean up:
   ```bash
   docker compose down -v
   ```

## Configuration Notes
- Use `HOST`/`ZASIAN_HOST` to avoid hardcoded localhost values in production.
- Set `AUNSORM_CLOCK_REFRESH_URL` and `AUNSORM_CLOCK_REFRESH_INTERVAL_SECS` for automated attestation refresh.
- Disable debug helpers by keeping `DEV_MODE=false` and `DEBUG_ENDPOINTS=false` in production stacks.
