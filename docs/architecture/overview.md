# Architecture Overview

## System Topology
The Aunsorm platform is organized as a gateway-led microservice mesh. The gateway fronts authentication, cryptography, KMS, X.509, ACME, PQC, and observability services while enforcing strict transport and calibration policies. Each service consumes the shared `AunsormNativeRng` implementation and verifies the same clock attestation source to prevent replay or skew-based attacks.

## Service Responsibilities
- **Gateway (50010):** Routes all public traffic, normalizes errors, and enforces TLS plus calibration headers.
- **Auth (50011):** OAuth2/PKCE, JWT issuance with JTI persistence, and device binding with attested clocks.
- **Crypto (50012):** Core symmetric/asymmetric operations and entropy exposure for upstream services.
- **KMS (50014):** Key lifecycle (generate/rotate/destroy) with strict backend policies and zeroized material handling.
- **X509 (50013):** CSR validation, issuance, and certificate status verification.
- **ACME (50017):** Account onboarding, nonce/order management, and challenge orchestration.
- **PQC (50018):** ML-KEM encapsulation and SLH-DSA / ML-DSA signature pipelines.
- **Metrics (50022):** Health and calibration telemetry aggregation.

## Data & Control Flows
- All request paths share a **calibration middleware** that rejects stale attestations based on `AUNSORM_CLOCK_MAX_AGE_SECS`.
- The **Native RNG** service seeds once from approved entropy and is injected into every operation through crate-level constructors.
- **PQC** operations are isolated behind dedicated handlers to simplify algorithm agility and strict-mode enforcement.
- **Audit streams** (KMS, Auth, ACME) publish structured events that can be anchored to ledger integrations (see `blockchain-integration.md`).

## Deployment Notes
- Container images expose only their designated ports and must run with read-only root filesystems where possible.
- Configuration is driven by environment variables documented under `docs/deployment/` and `.env.example`.
- Health endpoints surface calibration age, RNG readiness, and dependency liveness for automated rollouts.
