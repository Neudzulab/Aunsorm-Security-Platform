# Aunsorm Cryptographic Security Platform

**Version:** 0.5.0  
**Architecture:** Post-Quantum Cryptography (PQC) Ready Microservices  
**Language:** Rust (MSRV 1.76+)  
**License:** MIT/Apache-2.0

---

## Technical Overview

The declared Rust 1.76 target remains unverified: the current Windows/all-feature
metadata has 29 higher-MSRV dependencies after the compatible base64ct lock pin.
An actual Cargo 1.76 core-library check is rejected by rayon 1.12.0
(requires Rust 1.80), before source compilation. Rayon is activated through
normal core/sysinfo multithread dependencies as well as benchmark statistics.

SASRL research is isolated in the offline `scripts/sasrl_recovery.py` tool and
test-only Native RNG spectral regressions. Conditional cardinal-Mellin recovery
and conjectural hard cutoffs carry explicit provenance, coverage and numerical
diagnostics; they do not participate in production cryptographic decisions.
The zero-table contract now enforces its zeta-only analytic model: conductor,
pole, gamma factor, self-duality and normalization cannot be changed by input
metadata. Legacy implicit inputs remain labelled; no general L-function
recovery or automatic spectrum verification is introduced.
See [implementation evidence](docs/sasrl-aunsorm-integration.md) and the SASRL
revision tasks in `PROD_PLAN.md` for telemetry/audio/local Euler prerequisites.
`scripts/sasrl_euler.py` independently counts public curve points and provides
exact Frobenius/prime-power references with pinned model/label provenance.
Curve-specific spectral estimates still require complete zero/correction data.
Offline PCM conversion now measures bounded sinc-Gaussian profiles, anti-alias
behavior and exact aligned samples. Decoded gauge capture diagnostics separate
nominal cadence from gaps/jitter/drift and refuse an exact-grid FFT on incomplete
or irregular samples; neither tool authenticates data or drives security decisions.
`scripts/sasrl_pcm_stream.py` adds an experimental bounded-state PCM engine:
global integer phases, retained history, explicit lookahead and checked EOF count
preserve the offline filter across chunk partitions. Discontinuous input fails
closed. Callers must authenticate and isolate source frames before use; synthetic
equivalence does not establish live QUIC throughput or backpressure behavior.
The synthetic streaming benchmark separates cold/steady/EOF service times and
models periodic-arrival backlog. Direct access to verified interior history
reduces Python overhead without changing filter values or boundary rules.
The refined profile still misses the 10 ms cadence on the measured host;
native throughput and live authenticated transport integration remain open.
An independent synthetic QR solve confirms two-mode clustered-frequency noise
amplification against the Gram prediction and reports clean-fit roundoff.
This complete-grid known-frequency model does not recover missing audit events
or establish stability for larger clusters.
An additional 2..8-mode one-sided Jacobi diagnostic evaluates small complete-grid
Fourier matrices, exposing sweep limits, numerical resolution and nonconvergence.
Independent analytical and host NumPy SVD controls validate fixed fixtures;
general recovery and LAPACK accuracy guarantees are not claimed.
Optional decoded-gauge conditioning now uses actual observed millisecond
positions, with integer epoch subtraction and explicit 512-position limits.
Synthetic thinning/jitter controls expose aliasing that a nominal grid hides;
the diagnostic leaves gaps unfilled and preserves FFT eligibility checks.

QUIC audio now validates its fixed sample lattice at codec boundaries and offers
exact complete-frame helpers after envelope authentication/decryption. The codec
keeps encrypted bytes opaque; session isolation and authenticated fragment
metadata remain caller responsibilities. No spectral reconstruction is applied
to lost frames, audit events or cryptographic values.
The PCM splitter also accepts an even 8..960-byte plaintext shard budget. Callers
reserve full nonce/tag/envelope overhead before encryption; a 28-byte envelope
uses three shards for the fixed frame. Real AES-GCM/Native RNG tests validate
canonical test metadata/context binding, while production AAD, key/nonce lifecycle,
replay state and authenticated live transport remain separate review requirements.

PKCS#11 Ed25519 point decoding now rejects malformed attribute lists and
noncanonical/overflowing/trailing DER encodings without untrusted length
arithmetic. Its shared-source parser passes Rust 1.76 and seeded corpus checks;
Cryptoki dependency remediation and live HSM verification remain open.
The PKCS#11 software-seed path additionally bounds nonce/seed/tag envelopes
and zeroizes temporary decoded/decrypted secrets. Explicit Ed25519 zeroization
works in standalone KMS builds; real software wrapping/signature regressions
replace the invalid ignored fixture without claiming hardware integration.
A fixed-buffer AES-GCM decoder is now shared with a bounded wrapped-seed fuzz
target and seeded stdin driver. Recorded mutations check expected authentication
outcomes; the separate fuzz graph does not require Cryptoki.
Configured software public keys must match derived seed identity; weak/invalid
Ed25519 keys fail closed. Hardware signing replies undergo strict verification
against the selected key/message before return. Shared-source response controls
validate cryptographic behavior without proving live hardware compatibility.

Endpoint discovery now uses bounded UTF-8/XML ingestion, same-origin sitemap
index traversal and validation-target preflight. Redirects and URI path escapes
cannot send configured authentication/custom headers outside the origin. XML
resource limits apply before DOM allocations, with DTD/entity resolution disabled.

Aunsorm is a **production-grade cryptographic security platform** designed for modern distributed systems requiring:

- **Calibration-Bound Cryptography**: Every cryptographic operation is tied to a secure clock attestation (NTP-style) to prevent replay attacks and ensure temporal consistency
- **Post-Quantum Cryptography (PQC)**: ML-KEM-768, ML-DSA-65, SLH-DSA-128s implementations alongside classical algorithms
- **Zero-Trust Architecture**: Microservices-based design with per-service isolation, mutual TLS, and strict policy enforcement
- **Native RNG System**: Custom entropy mixing (HKDF + NEUDZ-PCS + AACM) providing 4x performance vs HTTP-based RNG

---

## Core Architecture

### Cryptographic Foundation

**Classical Algorithms:**
- AES-256-GCM (AEAD encryption)
- ChaCha20-Poly1305 (streaming AEAD)
- Ed25519 (signing, JWT)
- RSA-2048/4096 (X.509, ACME)
- ECDSA P-256 (TLS, certificates)

**Post-Quantum Algorithms (FIPS 203/204/205):**
- ML-KEM-768 (Key Encapsulation)
- ML-DSA-65 (Digital Signatures)
- SLH-DSA-128s (Stateless Hash Signatures)

**Hybrid Modes:**
- X25519 + ML-KEM-768 (key exchange)
- Ed25519 + ML-DSA-65 (signing)

### Security Mechanisms

**1. Clock Attestation System**
- NTP-style secure clock snapshots with certificate-based validation
- Configurable max_age (default: 30s production, 300s dev)
- Prevents time-based replay attacks across all services
- Auto-refresh architecture for production environments

**2. Native RNG (Aunsorm Native Random Number Generator)**
- HKDF-based entropy derivation from OsRng seed
- NEUDZ-PCS noise injection for additional entropy mixing
- AACM (Adaptive Additive Chaotic Maps) for state evolution
- Constant-time rejection sampling (timing attack resistant)
- **Performance:** 1.5s RSA-2048 key generation (vs 6.4s HTTP-based)

**3. Session Ratcheting**
- Double-ratchet protocol for E2EE sessions
- Perfect forward secrecy per-message
- SFU (Selective Forwarding Unit) integration for media streams

**4. Key Transparency**
- Append-only Merkle tree for public key publication
- Cryptographic audit trails for all key operations
- Ledger-based token revocation tracking

**5. Mobile Device Management (MDM)**
- Certificate-based device enrollment
- Platform-specific policy enforcement (iOS, Android, macOS, Windows, Linux)
- SCEP/ACME integration for automated cert distribution

---

## Microservices Architecture

Aunsorm operates as **15 independent microservices** communicating over an internal Docker network:

| Service | Purpose | Key Features |
|---------|---------|--------------|
| **gateway** | API Gateway & routing | Load balancing, rate limiting, health aggregation |
| **auth-service** | JWT token issuance | OAuth 2.0 flows, JTI revocation, PKCE |
| **crypto-service** | Core cryptographic ops | AEAD encryption, key derivation, signing |
| **pqc-service** | Post-quantum algorithms | ML-KEM, ML-DSA, SLH-DSA operations |
| **x509-service** | Certificate management | X.509 generation, CSR handling, chain validation |
| **kms-service** | Key management | Encrypted key storage, rotation, audit logging |
| **acme-service** | ACME protocol (Let's Encrypt) | Automated TLS cert provisioning, DNS-01/HTTP-01 |
| **mdm-service** | Mobile device management | Policy enforcement, device enrollment, compliance |
| **id-service** | Unique ID generation | Collision-resistant IDs, timestamp-based UUIDs |
| **rng-service** | Random number generation | Native RNG exposure via HTTP (deprecated, use native) |
| **e2ee-service** | End-to-end encryption | Session establishment, ratchet management |
| **blockchain-service** | DID registry (Hyperledger) | Decentralized identity anchoring (future) |
| **metrics-service** | Observability | Prometheus metrics, health checks |
| **cli-gateway** | CLI tool backend | Command execution, batch operations |

---

## Deployment Model

**Container Orchestration:** Docker Compose (production Kubernetes-ready)  
**Network Isolation:** All services on `aunsorm-network` bridge  
**Health Checks:** Configurable intervals, automatic restart on failure  
**Data Persistence:** SQLite (development), PostgreSQL/MySQL-ready  

**Environment Variables:**
- `AUNSORM_CLOCK_MAX_AGE_SECS`: Clock attestation validation window (strict mode enforces ≤30s, dev default 300s when unset)
- `AUNSORM_CALIBRATION_FINGERPRINT`: Calibration context identifier
- `AUNSORM_CLOCK_ATTESTATION`: JSON-encoded secure clock snapshot
- `AUNSORM_STRICT`: Enable strict security mode
- `AUNSORM_JTI_DB`: SQLite path for token revocation ledger

---

## Security Guarantees

1. **No `unsafe` code** - Entire codebase is `#![forbid(unsafe_code)]`
2. **Memory safety** - Rust ownership model prevents use-after-free, double-free
3. **Timing attack resistance** - Constant-time operations for sensitive data
4. **Replay attack prevention** - Clock attestation binds operations to time windows
5. **Forward secrecy** - Session keys never reused, ratcheted per message
6. **Audit trails** - Transparency logs for all key material operations

---

## Performance Characteristics

**RNG Performance (RSA-2048 key generation):**
- Native Aunsorm RNG: **1.5 seconds**
- HTTP-based RNG: **6.4 seconds**
- **Improvement: 4.2x faster**

**Cryptographic Operations (avg):**
- AES-256-GCM encrypt (1MB): ~15ms
- ChaCha20-Poly1305 encrypt (1MB): ~12ms
- Ed25519 sign: ~50µs
- Ed25519 verify: ~150µs
- ML-KEM-768 encapsulate: ~200µs
- ML-KEM-768 decapsulate: ~250µs

---

## Compliance & Standards

- **FIPS 203/204/205**: Post-Quantum Cryptography Standards
- **RFC 8555**: ACME Protocol
- **RFC 7519**: JSON Web Tokens (JWT)
- **RFC 5280**: X.509 Public Key Infrastructure
- **RFC 7748**: Elliptic Curves (X25519, Ed25519)
- **NIST SP 800-90A/B/C**: Random Number Generation
- **OWASP ASVS**: Application Security Verification

---

## Development Status

**Current Version:** 0.5.0  
**Production Readiness:** Beta (security-audited, performance-tested)  
**API Stability:** Stable for core endpoints, experimental for PQC/blockchain

**Known Limitations:**
- Blockchain DID registry integration incomplete (POC stage)
- HTTP/3 QUIC datagram support experimental
- WASM bindings for browser crypto in development

---

## Use Cases

1. **Enterprise Identity Management**: JWT-based authentication with PQC signatures
2. **IoT Device Security**: MDM-enforced policies, SCEP enrollment
3. **Secure Messaging**: E2EE with double-ratchet, media encryption
4. **Certificate Authority**: Automated TLS cert issuance via ACME
5. **Blockchain Identity**: DID anchoring on Hyperledger Fabric (future)

---

## Technical Stack

**Core Dependencies:**
- `ed25519-dalek`: Ed25519 signatures
- `rsa`: RSA key operations
- `aes-gcm`, `chacha20poly1305`: AEAD ciphers
- `pqc_kyber`, `pqc_dilithium`: Post-quantum implementations
- `x509-cert`: X.509 certificate handling
- `axum`: HTTP server framework
- `tokio`: Async runtime
- `rusqlite`: Embedded database
- `serde`: Serialization

---

## License

Dual-licensed under MIT and Apache-2.0. See LICENSE files for details.

---

## Contact

For production deployment questions or security disclosures, see `SECURITY.md`.

Endpoint validation now retains at most 1 MiB per ordinary decoded response
and rejects larger Content-Length/chunked/gzip bodies explicitly. Transport
errors and request deadlines preserve method/path/status in failed results.
SSE validation reads only a labelled 1 KiB prefix; JSON `body_sample` metadata
and Markdown sample lines disclose that the full stream was not validated.
Neither decoded chunks nor spectral methods repair missing HTTP/SSE data.

Volatile QUIC reconnect-grace identities now use typed field boundaries and
explicit optional values, bound to issuer, verified audience and the digest of
the exact normalized signed token. Persistent JTI rows retain their existing
encoding. A separate migration design requires atomic alias/tombstone handling,
old-writer fencing, rollback preservation and retention through verifier leeway.

New consumed-JTI records now retain through exp+verifier-leeway+1 second to
preserve the inclusive acceptance boundary under SQLite second precision.
Overflow fails explicitly; JWT wire expiration and persistent key encoding stay
unchanged. Legacy raw-exp history still needs a reviewed retention transition.

The volatile grace tracker now stores at most 4096 fixed-size SHA-256 identity
fingerprints and immutable acceptance/deadline values. Actual verification
scope is bound separately from resolved token purpose. Retry parameters cannot
extend the recorded deadline or prune unrelated live entries. Full capacity
refuses new grace admission; rollback/overflow/zero grace fail closed. Hashing
variable-size identity text runs outside the global tracker mutex. Persistent
JTI encoding is unaffected; per-process retry availability needs load validation.

An offline all-feature Windows dependency metadata audit finds 30 packages
whose declared MSRV exceeds the workspace's 1.76 target (including core's
Argon2/base64ct and shared time paths), plus 136 without declared MSRV metadata.
Current verification uses Rust 1.90; 1.76 compatibility is not established.
`docs/research/msrv-dependency-audit.json` records exact reachability evidence.

PKCS#11 private-key label lookup now requires exactly one returned object,
rejecting duplicate handles and ambiguous labels before storing a source.
The current Cryptoki API still collects all search results; bounded enumeration
and live vendor validation remain part of the provider/MSRV migration.
