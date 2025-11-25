# Release Draft — v0.5.0

## Highlights
- PQC ML-KEM key encapsulation support and SLH-DSA / ML-DSA signing paths.
- Calibration workflow with strict clock attestation enforcement and refresh worker guidance.
- Hardened `AunsormNativeRng` seeding and reuse model across crates and service examples.
- Clock attestation observability surfaced on `/health` endpoints.
- ACME partial implementation (account onboarding, nonce lifecycle, order scaffolding).

## Readiness Checklist
- [ ] All crates compile with MSRV 1.76 and deny warnings.
- [ ] Docker Compose stack starts with healthy status for every service.
- [ ] Regression tests cover PQC, RNG, and calibration flows.
- [ ] OpenAPI specs updated for gateway, auth, ACME, and PQC endpoints.
- [ ] `.env.example` sanitized with dummy values; production secrets managed externally.
- [ ] CHANGELOG updated with v0.5.0 highlights.
- [ ] Release artifacts tagged `v0.5.0` after verification.
