# Aunsorm Production Deployment Plan

**Version:** 0.5.0 → 1.0.0  
**Target Date:** Q3 2026  
**Status:** In Progress (Blocked on External Dependencies)

This document tracks all remaining work required for production deployment.

---

## Critical Security Tasks

### SASRL Spectral Validation Revision (2026-10-07)
- [ ] Revize: Extract the SASRL paper's conditional, empirical, and conjectural ideas into an implementation/verification matrix referencing recent sessions, replay, QUIC audio, and observability commits.
- [ ] Revize: Add a bounded offline cardinal-Mellin/hard-cutoff research tool with explicit zero coverage/provenance, exact arithmetic reference values, cutoff sweeps, compensated sums, and quadrature convergence diagnostics. Never use spectral estimates for cryptographic prime generation or authorization.
- [ ] Revize: Extend Native RNG validation with full-band spectral energy/periodicity regressions, deterministic adversarial controls, DC/Nyquist checks, and real AunsormNativeRng sampling without editing its sealed implementation.
- [ ] Revize: Validate telemetry sampling cadence and missing-sample/cluster conditioning before proposing any spectral anomaly detector; reconstructed samples must never stand in for authenticated audit events. Offline decoded-gauge diagnostics and synthetic loss/jitter/drift/full-band FFT controls are implemented in `scripts/sasrl_telemetry.py`; collect real connection traces and review the sampling model before production.
- [ ] Revize: Evaluate sinc-Gaussian PCM resampling separately from QUIC transport, with anti-alias filtering, bounded gain, loss/jitter tests, and authenticated source frames before integration. Offline baseline/refined WAV conversion and 18-tone measurements are implemented in `scripts/sasrl_pcm.py`; bounded streaming history/lookahead and offset continuity are experimental in `scripts/sasrl_pcm_stream.py`. Authentication, live media loss/jitter, throughput and backpressure tests remain required.
- [ ] Revize: Implement a bounded-state experimental streaming sinc-Gaussian PCM engine with exact integer sample-clock phases, bounded history/kernel caches and per-call work, explicit lookahead/EOF reflection, continuity-failure handling and chunk-partition equivalence against the offline oracle. Authenticate source frames before calling it; add measurable real media/QUIC/backpressure validation before production integration.
- [ ] Revize: Measure bounded synthetic streaming PCM host throughput with cold/steady/EOF timing, exact repeatability hashes, fixed input and aggregate work preflight, and an explicitly modelled single-worker 10 ms arrival backlog. Record measured failures to meet cadence without claiming live QUIC, authentication, real-time scheduling or production backpressure validation.
- [ ] Revize: Optimize streaming PCM interior history access after measured per-tap overhead, preserving exact tap/multiplication/summation order, bounds, lookahead and EOF semantics. Compare unchanged output hashes and baseline/optimized host measurements; retain actual cadence failures and require live production validation.
- [ ] Revize: Enforce QUIC audio sampling/profile and fragment bounds across constructor/encode/decode, reject mismatched channels/nonfinite gauges/trailing bytes, and add bounded exact PCM frame split/reassembly with sequence/timestamp/stream isolation and parser fuzz coverage. Keep encrypted shard bytes opaque and reject missing frames instead of reconstructing security data.
- [ ] Revize: Account for caller envelope overhead when splitting complete PCM frames, retaining the existing default fragmentation and wire format. Validate real AES-GCM/Native RNG encrypted round trips within byte budgets, canonical metadata/session AAD tampering, wrong context/key and incomplete frames. Treat the test AAD convention as integration evidence, not an adopted production E2EE protocol.
- [ ] Revize: Replace deprecated AES-GCM nonce slice constructors with checked fixed-size arrays without changing native entropy, nonce size or wire envelopes; verify encryption round trips across both dependency graphs.
- [ ] Revize: Document the already-routed `/http3/capabilities` endpoint in the auth OpenAPI contract, including enabled/disabled profiles, conditional caching and PCM metadata validation guidance.
- [ ] Revize: Implement and independently validate a bounded two-mode Fourier conditioning diagnostic for public uniformly sampled signals, including exact aliasing and small-gap noise amplification; do not generalize it to arbitrary clusters.
- [ ] Revize: Reproduce actual two-mode coefficient perturbation amplification using bounded synthetic complex signals, a cancellation-aware QR solve independent of the Gram singular-value formula, explicit finite-precision controls and weakest-direction perturbations. Reject aliased/numerically unresolved cases; do not reconstruct missing authenticated data or claim a multi-mode/sub-Nyquist theorem.
- [ ] Revize: Extend offline conditioning evidence to bounded 2..8-mode uniform Fourier matrices with direct one-sided Jacobi diagnostics, explicit sweep/work/precision limits and nonconvergence reporting. Independently validate DFT orthogonality, two-mode references and three-mode Vandermonde/Cauchy-Binet determinants; do not inherit LAPACK accuracy guarantees or reconstruct authenticated events.
- [ ] Revize: Evaluate conditioning at actual bounded observed millisecond timestamps, retaining integer-origin subtraction, known-mode/work limits and explicit irregular-grid scope. Integrate optional geometry-only diagnostics into decoded gauge analysis without relaxing FFT continuity/authentication rules or filling gaps; demonstrate thinning-induced aliasing and independent irregular-matrix SVD controls.
- [ ] Revize: Exercise accepted decoded gauge mutations through observed-time conditioning with explicit per-input and aggregate matrix limits, retaining expected parser rejection and propagating post-parse numerical failures. Commit a reproducible deterministic corpus report; do not substitute it for sustained coverage-guided fuzzing.
- [ ] Revize: Reproduce weighted local Euler recovery with independently sourced complete zero tables and explicit gamma/pole corrections for each L-function; keep gap-adaptive and sub-Nyquist schemes experimental pending conditioning/error bounds.
- [ ] Revize: Enforce the existing zeta-only recovery model in zero-table metadata: reject contradictory function/normalization/conductor/pole/gamma/self-duality declarations and unknown fields, label legacy implicit zeta input explicitly, and verify CLI/parser-fuzz rejection before estimates or output. General primitive L-function recovery still requires its own complete spectrum and correction implementation.
- [ ] Revize: Add a bounded independent finite-field point-count/Frobenius oracle for public elliptic-curve local Euler coefficients; pin exact Weierstrass models and Cremona/LMFDB label mappings, reject singular/bad-reduction inputs, independently verify point counts and prime-power logarithmic coefficients, and record unitary normalization. Implemented `scripts/sasrl_euler.py`: nine independent controls and all eight paper exact coefficients pass. Keep spectral recovery pending complete curve-specific zero/gamma/pole data.
- [ ] Revize: Audit replay namespace and QUIC grace tuple encodings for delimiter/sentinel collisions; design a persistent-ledger migration that cannot reopen already-consumed tokens before changing encodings.
- [ ] Revize: Validate the proposed persistent replay schema fence against actual current SqliteJtiStore open/purge/insert statements on temporary WAL databases: already-open and reopened workers must not create a fresh accepting ledger, version-marker-only designs must be shown insufficient, aborted cutovers must preserve legacy consumption, and conservative rollback must retain canonical consumption. Keep fixtures outside activation paths pending security review and atomic JtiStore API design.
- [ ] Revize: Retain consumed JTI entries throughout verifier expiration leeway, including SQLite second precision and exact acceptance boundaries; add signed-token regressions for both in-memory and reopened SQLite stores. The original verifier wrote raw exp while accepting exp + leeway. New entries now retain through exp + leeway + a 1-second precision guard; three real-store/overflow controls are implemented. Legacy rows, coordinated maximum policy and production review remain required. Preserve existing key encodings until the persistent migration is reviewed.
- [ ] Revize: Recheck the authoritative active-token ledger before accepting QUIC reconnect grace; revocation/expiry and ledger errors must fail closed even after an earlier acceptance. Cover actual signed-token registration, exact retry, revocation and rejected retry without changing sealed JWT fields.
- [ ] Revize: Replace the volatile QUIC reconnect-grace delimiter key with a typed tuple bound to issuer, verified audience and the exact normalized signed token; distinguish absent/sentinel values and preserve exact nonblank JTI bytes. Fix the existing store-less grace signature recheck so it does not demand a second JTI store; keep nonblank JTI and active-ledger requirements on grace acceptance. Add collision/context/expiry regressions without rewriting the persistent consumed-JTI ledger or sealed JWT response.
- [ ] Revize: Bound the volatile QUIC grace tracker to fixed-size domain-separated identity fingerprints and 4096 entries, bind the actual verification-scope tuple separately from resolved claim purpose, record immutable per-acceptance deadlines, refuse admission when full without evicting live entries, prevent retry/duplicate-record duration extension and cross-entry pruning, and fail closed on zero grace, rollback or time overflow. Validate boundary/capacity/context behavior with actual tracker tests and retain the real signed-token ledger regression.
- [ ] Revize: Fix the pre-existing parallel PQC strict-mode test environment race discovered by the SASRL full-workspace validation; serialize environment mutations and restore the caller's original value.
- [ ] Revize: Remediate compatible dependency security patches found during the SASRL audit; track remaining cryptoki/XML/TLS-major migrations, RSA side-channel exposure and unmaintained PQC providers without adding advisory suppressions.
- [ ] Revize: Harden PKCS#11 Ed25519 CKA_EC_POINT decoding against empty/unexpected attribute lists, overflowing/noncanonical DER lengths and trailing/nested data. Preserve the existing canonical single/double OCTET STRING formats, use bounded allocation-free parsing, add actual-signature/parser regressions and a shared-source fuzz target. Do not claim remediation of Cryptoki RUSTSEC-2026-0286 without upgrading its vulnerable dependency under a resolved MSRV policy.
- [ ] Revize: Replace the invalid ignored PKCS#11 software-key fixture with real AES-GCM-wrapped seed signing/verification and wrong-key/key-id/nonce/ciphertext/tag controls, serializing/restoring test environment state. Bound fixed wrap-key/seed encodings before decoding/decryption, zeroize decoded/decrypted transient secrets, and explicitly enable Ed25519 signing-key zeroization in standalone KMS builds. Preserve separate live-HSM and strict hardware-public-key review requirements.
- [ ] Revize: Add dedicated fuzz coverage for the bounded PKCS#11 wrapped-seed decoder using the actual shared AES-GCM implementation and valid Native RNG-generated envelope seeds, without adding the vulnerable Cryptoki dependency to the separate fuzz graph. Retain key-id/error context at the KMS boundary; exercise malformed base64, length, nonce/ciphertext/tag and AAD changes before any live-HSM claim.
- [ ] Revize: Bind PKCS#11 declared public-key identity to actual cryptography: reject mismatched/malformed software public_key metadata, bound fixed public-key decoding, reject invalid/weak Ed25519 public keys and strictly verify each hardware signing response against the selected stored public key/message before returning it. Use actual signature/software-backend regressions and shared-source fuzz controls without claiming live HSM compatibility or changing sealed structures.
- [ ] Revize: Reject ambiguous PKCS#11 private-key label matches rather than selecting the first object, including duplicate returned handles. Validate the exact-one selection rule without emulating a hardware session; preserve contextual missing/ambiguous errors. Resolve the Cryptoki/MSRV provider migration before claiming bounded hardware enumeration or live HSM validation.
- [ ] Revize: Replace vulnerable sitemap quick-xml parsing with an audited MSRV-compatible bounded XML reader; cap decoded discovery HTTP bytes, XML nodes/attributes/nesting and URL counts, disable DTD/entity resolution, retain namespace/escaped URL semantics, follow bounded same-origin sitemap indexes without credential-bearing cross-origin requests, and add real HTTP/hostile-input regressions plus fuzz targets.
- [ ] Revize: Reject validator path prefixes that become absolute/cross-origin URLs after slash removal; preflight every seed/OpenAPI/HTML validation target and cover OPTIONS/GET authentication scope with real local HTTP regressions. Preserve existing base-path behavior for valid relative targets.
- [ ] Revize: Reconcile remaining dependency MSRV drift in cryptoki (patched line requires 1.77) and experimental QUIC (existing line requires 1.85); preserve the documented MSRV 1.76 contract or obtain an explicit version-policy revision. XML was replaced with roxmltree 0.21.1 (declared MSRV 1.60), avoiding quick-xml's patched-line requirement of 1.79. Current offline Windows/all-feature metadata now finds 29 above-1.76 packages and 136 with no declared MSRV, after the compatible base64ct pin, including time 0.3.47, IDNA/ICU, async-compression, selectors and dev/benchmark dependencies; see `docs/research/msrv-dependency-audit.json`. This is broader than the initially identified cryptoki/QUIC drift.

- [ ] Revize: Resolve the metadata-proven MSRV 1.76 dependency incompatibilities with security-clean compatible pins or reviewed provider replacements, without undoing advisory fixes; test production/default and all-feature graphs on a real Rust 1.76 toolchain and explicitly account for target/dev/build dependency kinds and packages missing MSRV metadata. Preserve the declared 1.76 contract unless the user approves a version-policy revision.
- [ ] Revize: Restore a compatible locked base64ct version for the shared Argon2/password-hash/PEM graph after reviewing upstream changes, repeat real crypto/serialization regressions and security audits, and recalculate the remaining MSRV incompatibility count. Do not claim whole-workspace Rust 1.76 support from one compatible transitive pin.
- [ ] Revize: Review Rayon benchmark/sysinfo MSRV remediation against upstream safety fixes before any downgrade. Apply the corrected Unicode surrogate-boundary range implementation through maintained dependency releases in both locked graphs, run real Native RNG/crypto and benchmark regressions, and document the still-open Rust 1.76 compatibility strategy without suppressing compiler requirements.

- [ ] Revize: Bound normal endpoint-validation and SSE response accumulation/backpressure separately from the new discovery/XML budgets; preserve explicit failure reporting instead of silently truncating responses and test decoded/compressed and stalled streams. Implemented 1 MiB decoded ordinary-body rejection, explicitly labelled 1 KiB SSE prefix samples and transport/timeout failures preserving endpoint context; real HTTP regressions cover the boundaries. Production review and sustained backpressure measurements remain open.

Tasks above remain unchecked until verification and the applicable approval gates are satisfied. Implementation evidence and remaining prerequisites are recorded in `docs/sasrl-aunsorm-integration.md`.

### Clock Attestation System
- [ ] Deploy NTP attestation server with real certificate signatures
 - [ ] Provision dual-node NTP cluster with hardware PPS/GPS modules and HAProxy failover
 - [ ] Issue attestation certificates from production CA and rotate signing keys quarterly
 - [ ] Replace development mock signatures with production cryptographic proofs
 - [ ] Set `AUNSORM_CLOCK_MAX_AGE_SECS=30` in production environment
- [x] Document firewall rules and secure management network for attestation hosts (docs/src/operations/clock-attestation-deployment.md)
- [x] Implement automatic clock refresh service (ClockRefreshService integration)
- [x] Configure health checks to monitor clock attestation freshness
- [x] Enforce HTTPS-only refresh endpoints and verifier gating before publishing snapshots
- [x] Document clock attestation server deployment procedures

### Native RNG Compliance
- [ ] Add reproducible SASRL arithmetic research tooling with exact sieve ground truth, pinned zero-data provenance, cutoff sensitivity bounds and a fixed spectral-edge scan; keep review and merge pending, with no RNG/entropy claims.
- [ ] Research Toeplitz universal-hash entropy extraction: exact finite validation, certified min-entropy output budgeting and synthetic bias experiment; physical-source assessment, independent-seed design, production integration and review remain pending.
- [ ] Revize: Harden native RNG state lifecycle (redacted Debug, fast key erasure, OS reseeding, PID changes and snapshot guidance); correct statistical p-values. Revises the completed implementation/audit tasks below.
- [x] Aunsorm Native RNG implemented across all crates
- [x] OsRng usage restricted to initial entropy seeding only
- [x] Security audit of HKDF + NEUDZ-PCS + AACM mixing algorithm
- [x] Formal entropy analysis report
- [x] NIST SP 800-90B compliance validation
- [x] Performance benchmarks vs. hardware RNG
- [x] Document external-only policy for HTTP `/random/*` fallback while enforcing native RNG usage internally

### Key Management
- [ ] Implement hardware security module (HSM) integration for KMS
 - [ ] Finalize vendor selection (AWS CloudHSM vs. on-prem Luna SA) and procurement checklist
 - [ ] Implement PKCS#11 abstraction layer with failover to standby HSM cluster
 - [ ] Update Terraform to provision dedicated VPC subnets and security groups for HSM links
- [ ] Key rotation automation with zero-downtime
 - [ ] Implement dual-publish strategy (old+new keys) with gradual traffic shift
 - [ ] Add integration tests covering rotation rollback and cutover monitoring hooks
- [ ] Encrypted backup/restore procedures
 - [ ] Design sealed secret export format with hardware-bound wrapping keys
 - [ ] Schedule quarterly restore drills and capture runbooks in docs/src/operations
- [ ] Multi-signature approval for sensitive key operations
 - [ ] Integrate change-approval workflow with Slack + PagerDuty and store approvals in tamper-proof log
- [ ] Key material never touches disk unencrypted
 - [ ] Audit all services for tmpfs usage and enforce in CI with static analysis rule
- [ ] Implement key expiration and automatic rotation policies
 - [ ] Define per-algorithm lifetime matrix (RSA, Ed25519, AES-GCM) and codify in config schemas
 - [ ] Expose rotation status metrics for alerting (expiring_soon, expired)

### Authentication & Authorization
- [x] Multi-factor authentication (MFA) for admin operations
- [x] Role-based access control (RBAC) enforcement
- [x] OAuth 2.0 refresh token rotation
- [x] Revize: Add dedicated `/security/password-hash` + `/security/password-verify` endpoints for first-party account flows and document the Argon2id contract in auth service docs/OpenAPI
- [x] Revize: Add first-party application session endpoints (`/sessions`, `/sessions/{sessionId}/keys`) and HMAC signing helpers for MyeOffice session-cookie integration
- [ ] Token revocation webhook notifications
 - [ ] Implement signed webhook payloads with timestamped nonce validation
 - [ ] Add replay protection storage (Redis) with TTL tuned to webhook retry window
 - [ ] Provide webhook delivery monitoring dashboard and SLA alerts
- [x] Session timeout configuration per client type
- [x] Audit logging for all authentication events

---

## Infrastructure Tasks

### Docker & Orchestration
- [ ] Migrate from Docker Compose to Kubernetes
- [x] Revize: Add purpose-based Docker Compose stack files so auth/identity/crypto users can deploy only required services with mandatory RNG dependency
- [x] Implement Horizontal Pod Autoscaling (HPA)
- [x] Configure resource limits (CPU/memory) per service
- [x] Set up liveness and readiness probes
- [x] Configure rolling updates with zero downtime
- [ ] Implement blue-green deployment strategy
- [ ] Set up Helm charts for deployment automation

### Networking & Load Balancing
- [x] Configure Ingress controller with TLS termination
- [x] Implement rate limiting at gateway level
- [x] Set up DDoS protection (Cloudflare / AWS Shield)
- [x] Configure internal service mesh (Istio / Linkerd)
- [x] Implement circuit breakers for service resilience
- [x] Set up mutual TLS between services

### Database & Persistence
- [ ] Migrate from SQLite to PostgreSQL for production
- [ ] Configure database replication (master-slave)
- [ ] Implement automated backups with point-in-time recovery
- [ ] Set up connection pooling
- [ ] Configure database encryption at rest
- [ ] Implement database migration versioning strategy

### Monitoring & Observability
- [ ] Deploy Prometheus + Grafana for metrics
- [ ] Configure alerting rules for critical errors
 - [x] Revize: Add baseline PrometheusRule alerts for gateway/auth/crypto scrape failures and OAuth metric anomalies under `config/kubernetes`
- [ ] Set up distributed tracing (Jaeger / OpenTelemetry)
 - [x] Revize: Add baseline OTLP collector deployment config and enable `otel` feature in gateway/auth/crypto Docker builds
- [ ] Implement structured logging with log aggregation (ELK / Loki)
 - [x] Revize: Add JSON log format switch for `aunsorm-server` and baseline Loki/Promtail scrape contract under `config/kubernetes`
- [ ] Create operational dashboards for each service
 - [x] Revize: Add baseline Grafana dashboard JSON for canonical Aunsorm Prometheus metrics under `config/grafana`
- [ ] Configure uptime monitoring and SLA tracking
 - [x] Revize: Add Prometheus Operator Probe manifests for gateway/auth/crypto health endpoint uptime tracking
 - [x] Revize: Add critical `probe_success` alert coverage for gateway/auth/crypto uptime probes

### Tooling & CLI
- [x] Harden CLI default server URL inference so HOST-provided port/path/query hints are preserved
- [x] Revize: Honor HOST overrides in dev scripts (start-all/test-all/deploy-gateway-cert)

---

## API & Integration Tasks

### REST API Hardening
- [ ] Implement API versioning strategy (v1, v2, etc.)
- [ ] Add comprehensive input validation
- [x] Revize: Add `/security/encrypt` + `/security/decrypt` AES-256-GCM helpers for HD audio datagram payloads while keeping session-driven key rotation external to the endpoint contract
- [x] Implement request/response compression (tower-http katmanları ile tüm HTTP servisleri otomatik müzakere kullanıyor)
- [ ] Add ETag support for caching
 - [x] Revize: Add conditional GET ETag handling for `/health` endpoint in `crates/server`
 - [x] Revize: Add conditional GET ETag handling for `/pqc/capabilities` and `/v1/pqc/capabilities` in `crates/server`
 - [x] Revize: Add conditional GET ETag handling for `/http3/capabilities` in `crates/server`
 - [x] Revize: Extend `/http3/capabilities` with HD audio datagram profile metadata and `AudioPcmDatagram` shard format in `crates/server`
 - [x] Revize: Enable `http3-experimental` in gateway/e2ee Docker builds and expose UDP QUIC ports in `compose.yaml`
 - [x] Revize: Add conditional GET ETag handling for `/oauth/transparency` and `/v1/oauth/transparency` in `crates/server`
 - [x] Revize: Add conditional GET ETag handling for `/transparency/tree` and `/v1/transparency/tree` in `crates/server`
- [x] Implement CORS policies
- [ ] Add OpenAPI/Swagger documentation generation
 - [x] Revize: Generate `docs/api/openapi-catalog.md` + `docs/api/openapi-catalog.json` from `openapi/*-service.yaml` and enforce freshness in CI

### PQC (Post-Quantum Cryptography)
- [ ] Complete ML-KEM-1024 implementation
- [ ] Add Falcon-512 signature support
- [ ] Implement hybrid classical+PQC modes by default
- [ ] Performance optimization for PQC operations
- [ ] Interoperability testing with other PQC libraries
- [ ] Security audit of PQC implementations

### ACME / Certificate Management
- [ ] Production Let's Encrypt integration testing
- [ ] Implement DNS-01 challenge automation
- [ ] Certificate renewal automation (30 days before expiry)
- [ ] Wildcard certificate support
- [ ] Certificate revocation handling
- [ ] Multi-domain SAN certificate support

### Blockchain Integration
- [ ] Complete Hyperledger Fabric DID registry implementation (user verification required for live Fabric validation)
- [x] Implement chaincode deployment automation
- [x] Add blockchain-based audit trail for sensitive operations
- [x] Implement DID resolution caching
- [x] Configure blockchain network High Availability
 - [x] Define Fabric network topology, org MSPs, and channel policy baselines
 - [x] Provision CA/peer/orderer certificates with rotation runbooks
 - [x] Implement DID registry chaincode CRUD, events, and access controls
 - [x] Add chaincode lifecycle automation (package, approve, commit, upgrade)
 - [x] Build audit trail pipeline (on-chain events → secure log sink)
 - [x] Implement DID resolution cache invalidation and TTL policy
 - [x] Add HA deployment plan for orderers/peers with failover testing
 - [x] Document operational runbooks for Fabric deployment and upgrades

---

## Testing & Quality Assurance

### Test Coverage
- [ ] Achieve >80% unit test coverage
- [ ] Complete integration test suite for all services
- [x] Revize: Replace stale PLAN.md references in ignored OAuth integration tests with PROD_PLAN.md for devam traceability
- [x] Revize: Add calibration `/calib/verify` invalid-input regression coverage for strict-mode error handling and audit-log guardrails
- [x] Revize: Add gateway e2e smoke regression for `/health` and `/pqc/capabilities` conditional GET behavior in `tests/tests/e2e_gateway_smoke.rs`
- [ ] Add end-to-end test scenarios
- [ ] Implement chaos engineering tests (fault injection)
- [ ] Add load testing (Locust / k6)
- [ ] Implement security regression tests

### Security Auditing
- [ ] Third-party security audit (penetration testing)
- [x] Dependency vulnerability scanning automation
- [x] Revize: Disable push/pull_request workflow triggers for CI/release pipelines and keep manual dispatch-only execution to control token usage
- [x] Revize: Remove GitHub Actions workflow files to stop repository-billed automation usage
- [x] Revize: Update time crate to address RUSTSEC-2026-0009
- [ ] Replace unmaintained or vulnerable crypto dependencies flagged by cargo-deny (atomic-polyfill, fxhash, pqcrypto-dilithium/kyber, ring 0.16.20) to restore advisory compliance
- [x] Configure `cargo-deny` to fetch the RustSec advisory database via the git CLI fallback so checks succeed in restricted network environments
- [x] Static code analysis (cargo clippy strict mode)
- [ ] Dynamic analysis (ASAN, MSAN, TSAN)
- [ ] Fuzz testing for all parsers and decoders
- [x] Align fuzz harness base64 dependency with workspace version to reduce version divergence
- [ ] Supply chain security (verify all dependencies)

### Performance Optimization
- [ ] Profile hot paths and optimize (flamegraph analysis)
- [ ] Reduce memory allocations in critical paths
- [ ] Implement connection pooling for all external services
- [ ] Optimize database queries (indexing strategy)
- [ ] Add caching layer (Redis) for frequently accessed data
- [ ] Benchmark against performance SLAs

---

## Documentation & Compliance

### Technical Documentation
- [x] PROJECT_SUMMARY.md - Architecture overview
- [x] README.md - Quick start guide
- [x] Add PROD_PLAN link in README documentation section
- [x] port-map.yaml - Service port mapping
- [x] Revize: Align agent charter references from PLAN.md to PROD_PLAN.md
- [x] Document `devam` command kickoff expectations in agent charter checklist
- [x] Revize: Clarify CLI environment override variables in README quick start (AUNSORM_SERVER_URL/HOST)
- [x] Document Redoc access links in OpenAPI README quick start and service table
- [x] Revize: Replace hardcoded localhost references in OpenAPI landing page and README with host placeholders
- [x] Revize: Remove remaining localhost references from OpenAPI specs and OpenAPI nginx configuration (ref: Revize hardcoded localhost replacements)
- [x] Revize: Update OpenAPI landing page footer link to JWT guide to use the GitHub source URL
- [x] Revize: Add explicit PROD_PLAN task reference guidance in CONTRIBUTING.md
- [x] Revize: Replace localhost examples in JWT_AUTHENTICATION_GUIDE.md with HOST placeholders
- [x] Revize: Add HOST override guidance to OpenAPI README quick start for docs links
- [x] Revize: Add ADR 0002 documenting the path-based API versioning strategy
- [x] Revize: Align CONTRIBUTING validation commands with strict clippy warning handling
- [x] Revize: Consolidate entropy mixing experiment documentation to remove stale TBD placeholders
- [x] Revize: Align CONTRIBUTING branch naming guidance with agent workflow
- [x] Revize: Clarify cargo-deny advisory database fetch expectations in README validation section
- [x] Revize: Add cargo audit command to README validation section
- [x] Revize: Add `.env` HOST and AUNSORM_SERVER_URL example in README quick start
- [x] Revize: Replace localhost defaults in port-map integration URLs with HOST placeholders
- [x] Revize: Expand README API reference section with OpenAPI source and hosted docs entry points
- [x] Revize: Add Swagger UI access link to README hosted API docs section
- [x] Revize: Emphasize HOST override to avoid hardcoded localhost in README quick start
- [x] Revize: Align CLI default server URL port with gateway port 50010
- [x] Revize: Add README note to reference PROD_PLAN tasks in PR descriptions
- [x] Revize: Require CONTRIBUTING workflow to document immediate PR creation after commit with PROD_PLAN task + validation summary
- [x] Revize: Add a reusable PR body template in CONTRIBUTING.md with explicit PROD_PLAN task and validation sections
- [x] Revize: Clarify `devam` continuation workflow in CONTRIBUTING.md so follow-up commits preserve task priority and PR traceability
- [x] Revize: Clarify `devam` workflow for clean-branch continuations so agents select the next pending PROD_PLAN task before editing
- [x] Revize: Extend PR template and CONTRIBUTING scaffold with a required `Continuation Context` section for `devam` handoffs
- [x] Revize: Add a GitHub pull request template file that mirrors CONTRIBUTING required sections (Summary, PROD_PLAN.md task, Validation)
- [x] Revize: Replace remaining PLAN.md references in contributor guidance (CONTRIBUTING.md)
- [x] Revize: Clarify continuation workflow so empty `devam` runs skip PR creation while commits still require immediate PR submission
- [x] Revize: Require `devam` continuation checklist to verify git working tree state before implementation
- [x] Revize: Replace remaining PLAN.md references in architecture and operations docs (docs/src/architecture/overview.md, docs/src/operations/market-intelligence.md)
- [x] Revize: Update AGENTS revision lock policy to reference PROD_PLAN.md instead of legacy PLAN.md
- [x] Revize: Normalize legacy CHANGELOG documentation bullets to reference PROD_PLAN.md instead of PLAN.md
- [x] Revize: Replace service crate README curl examples with HOST placeholders (JWT/PQC/ACME/KMS)
- [x] Revize: Replace remaining localhost examples in server/docs quick starts with HOST placeholders (crates/server/README.md, docs/api/overview.md, docs/deployment/quickstart.md)
- [x] Revize: Replace localhost examples in operations and calibration runbooks with HOST placeholders (docs/src/architecture/calibration.md, docs/src/operations/troubleshooting-guide.md, docs/src/operations/oauth-openapi.md)
- [x] Revize: Add HOST placeholder guidance to OpenAPI landing page quick start
- [x] Revize: Document API versioning transition guidance in README (unversioned compatibility paths + planned `/v1` migration)
- [x] Revize: Add `/v1` compatibility route aliases in `aunsorm-server` and validate `/v1/health` + `/v1/pqc/capabilities` coverage
- [x] Revize: Extend `/v1` compatibility coverage tests for random and OAuth transparency endpoints in `aunsorm-server`
- [x] Revize: Extend `/v1` compatibility coverage tests for HTTP/3 capabilities endpoint parity in `aunsorm-server`
- [x] API reference documentation (OpenAPI spec)
  - [x] Revize: Document bulk OpenAPI spec validation command in openapi/README.md
  - [x] Revize: Add PowerShell HOST override example to OpenAPI documentation quick start
- [x] Revize: Mark planned OpenAPI service cards as placeholder specs in the landing page
- [x] Revize: Align OpenAPI landing page quick-start examples with available service specs
- [x] Add placeholder OpenAPI specs for X509 and KMS services to document planned schemas
- [x] Revize: Link placeholder X509/KMS OpenAPI specs from the documentation landing page
- [x] Revize: Add placeholder OpenAPI specs for ID and MDM services and link them from the documentation landing page
- [x] Architecture decision records (ADRs)
  - [x] Create ADR template and index (docs/architecture/adr)
  - [x] Revize: Add ADR documenting the `devam` agent continuation workflow
  - [x] Revize: Add ADR documenting mandatory PROD_PLAN task references in PR descriptions
  - [x] Revize: Add ADR documenting AGENTS.md scope inheritance and instruction precedence
  - [x] Revize: Add ADR documenting placeholder OpenAPI specs for planned services
  - [x] Revize: Add ADR documenting completion criteria for API reference documentation milestone
- [x] Disaster recovery runbook — documented in docs/src/operations/disaster-recovery-runbook.md
- [x] Incident response playbook
- [x] Production deployment guide
- [x] Revize: Fix typos and formatting in production-fix-instructions.md

### Compliance & Certifications
- [x] SOC 2 Type II audit preparation
- [x] GDPR compliance review
- [x] HIPAA compliance assessment (if applicable)
- [x] ISO 27001 certification preparation
- [x] Document data retention policies
- [x] Privacy policy and terms of service

### Developer Experience
- [x] Contribution guidelines update
  - [x] Documented native RNG compliance, plan alignment, and endpoint/OpenAPI
    update expectations in `CONTRIBUTING.md`
- [x] Code review checklist
  - Documented reviewer gates in `CONTRIBUTING.md`, including RNG compliance,
    documentation updates, and validation suite requirements
- [x] Development environment setup automation (devcontainer)
- [x] Document validation suite (fmt/clippy/test/deny) in README quick start
- [x] CI/CD pipeline documentation (docs/src/operations/ci-cd-pipeline.md)
- [x] Troubleshooting guide for common issues
- [x] Revize: Extend `scripts/test-all.sh` validation pipeline to run `cargo deny check` and `cargo audit`
- [x] Revize: Add `devam` continuation checklist to CONTRIBUTING workflow guidance

---

## Operational Readiness

### Incident Management
- [x] Define SLA/SLO targets (docs/src/operations/sla-slo-targets.md)
- [x] Set up on-call rotation schedule
- [ ] Configure PagerDuty / Opsgenie alerts
 - [x] Document service mapping, escalation baselines, and verification runbook (docs/src/operations/pagerduty-opsgenie-alert-routing.md)
 - [ ] Provision production integrations and validate live paging across all critical services
- [x] Create incident postmortem template (docs/src/operations/incident-postmortem-template.md)
- [x] Establish change management process
 - [x] Publish CAB workflow, change categories, and release evidence checklist (docs/src/operations/change-management-process.md)

### Backup & Disaster Recovery
- [ ] Implement automated daily backups
 - [x] Revize: Add Kubernetes PostgreSQL daily backup CronJob with compressed dump and checksum upload to S3-compatible storage
 - [x] Revize: Add Prometheus alerts for PostgreSQL backup job failures and suspended backup CronJob state
- [ ] Test backup restoration procedures
 - [x] Revize: Document PostgreSQL backup checksum and `pg_restore --list` spot-check in the disaster recovery runbook
- [x] Define Recovery Time Objective (RTO) and Recovery Point Objective (RPO)
- [ ] Set up cross-region disaster recovery
- [x] Document backup retention policies

### Cost Optimization
- [ ] Right-size container resources
- [ ] Implement auto-scaling policies
- [ ] Set up cost monitoring and alerts
- [ ] Evaluate reserved instance pricing
- [ ] Implement data lifecycle management

---

## Version 0.5.0 Milestone Tasks

### Immediate Priorities
- [x] JWT duplicate field fix (serialize with RFC standard names)
- [x] Clock attestation auto-update on server startup
- [x] Native RNG implementation across all crates
- [x] Complete port-map.yaml and documentation restructure
  - README.md service endpoint tree mirrors the latest port-map statuses (gateway, metrics, CLI, RNG deprecation note)
  - PROJECT_SUMMARY.md microservices table verified against port-map allocations
- [x] Version bump to 0.5.0 in all Cargo.toml files
- [x] Archive legacy planning documents (see `docs/archive/README.md` for the historical index)

### Next Sprint (v0.5.1)
- [ ] Kubernetes deployment manifests
  - [x] Revize: Add baseline Kubernetes deployment/service manifests for gateway, auth, and crypto services under config/kubernetes
  - [x] Revize: Define zero-downtime rolling update parameters (`maxUnavailable: 0`, `maxSurge: 1`) for baseline gateway/auth/crypto deployments
  - [x] Revize: Add PodDisruptionBudget manifests for gateway/auth/crypto workloads to preserve quorum during voluntary node drains
- [ ] PostgreSQL migration scripts
  - [x] Revize: Add initial PostgreSQL schema migrations for JTI, token, refresh token, and transparency ledgers under `migrations/postgres`
  - [x] Revize: Add Bash and PowerShell migration runners that apply PostgreSQL scripts in lexical order via `psql`
  - [x] Revize: Add dedicated PostgreSQL backup container build that packages `pg_dump`, AWS CLI, and zstd for daily backup jobs
- [ ] Prometheus metrics standardization
  - [x] Revize: Add baseline Prometheus scrape annotations and ServiceMonitor manifests for gateway/auth/crypto Kubernetes services
  - [x] Revize: Centralize canonical `/metrics` Prometheus gauge names in `crates/server::telemetry` and assert type lines in regression coverage
- [ ] API versioning implementation
  - [x] Revize: Add `/v1/metrics` regression coverage to preserve versioned Prometheus endpoint compatibility

---

## Risk Assessment

### High Risk
- **Clock attestation production readiness**: Development mock mode unacceptable for production
- **Database scalability**: SQLite not suitable for multi-node deployment
- **Key management**: No HSM integration means keys vulnerable to container compromise

### Medium Risk
- **Monitoring gaps**: Limited observability for distributed system troubleshooting
- **API versioning**: Breaking changes require coordination with clients
- **Blockchain dependency**: Hyperledger Fabric adds operational complexity

### Low Risk
- **Documentation gaps**: Can be addressed incrementally
- **Test coverage**: Core crypto functions well-tested, integration coverage improving

---

## Approval Gates

Each section requires approval before marking complete:

- **Security Tasks**: Security Team + CTO
- **Infrastructure Tasks**: DevOps Lead + Platform Architect
- **API Tasks**: API Team Lead + Product Manager
- **Testing Tasks**: QA Lead + Engineering Manager
- **Documentation**: Technical Writer + Product Manager
- **Operational Readiness**: SRE Team + VP Engineering

---

## Progress Tracking

**Last Updated:** 2026-01-31  
**Overall Completion:** ~45%  
**Target v1.0.0 Release:** 2026-Q3  

**Completed Milestones:**
- ✅ Native RNG implementation (all crates)
- ✅ JWT/OAuth basic flow
- ✅ Blockchain chaincode automation
- ✅ Clock attestation refresh service
- ✅ 550+ tests passing

**Blocked Items (External Dependencies):**
- 🔴 HSM Integration - Awaiting vendor selection & procurement
- 🔴 Third-party Security Audit - Awaiting budget approval
- 🔴 PostgreSQL Migration - Awaiting DBA resource allocation
- 🔴 Kubernetes Migration - Depends on PostgreSQL completion

**Velocity:** ~8 tasks/week  
**Estimated Remaining:** ~80 tasks  
**Projected Completion:** ~10 weeks (after blockers resolved)
