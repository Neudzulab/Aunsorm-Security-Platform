# Security Overview

## Guarantees
- **Calibrated Time:** All services enforce attested time windows and reject requests older than configured `AUNSORM_CLOCK_MAX_AGE_SECS` values.
- **Native RNG:** `AunsormNativeRng` is the only approved randomness source beyond initial OS entropy seeding.
- **Deterministic Error Surfaces:** HTTP responses include explicit `Content-Type` headers and structured JSON errors.
- **Zeroization:** Key material and secrets are cleared with zeroization-friendly APIs across KMS, PQC, and JWT stores.

## Threat Model Highlights
- **Replay Attacks:** Mitigated via clock attestation fingerprints, strict max-age enforcement, and per-request calibration checks.
- **Algorithm Downgrade:** PQC handlers require explicit algorithm names (`ml-kem-*`, `slh-dsa-*`, `ml-dsa-*`) and fail closed.
- **Token Abuse:** Auth service mandates JTI persistence; missing JTI stores trigger explicit validation errors.
- **Entropy Abuse:** Forbidden use of `rand::thread_rng`, `OsRng`, or HTTP RNG sources in crates; tests use controlled native RNG hooks.

## Operational Controls
- Rotate calibration fingerprints with change-managed deploys.
- Enforce read-only file systems for containers and disable debug endpoints in production (`DEBUG_ENDPOINTS=false`).
- Monitor `/health` for `clock.status`, RNG readiness, and dependency liveness.
- Maintain SOC2/DORA-aligned audit trails and ledger anchoring where required.
