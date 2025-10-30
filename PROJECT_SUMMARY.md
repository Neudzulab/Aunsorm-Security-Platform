# Aunsorm Cryptographic Security Platform

**Version:** 0.5.0  
**Architecture:** Post-Quantum Cryptography (PQC) Ready Microservices  
**Language:** Rust (MSRV 1.76+)  
**License:** MIT/Apache-2.0

---

## Technical Overview

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
- `AUNSORM_CLOCK_MAX_AGE_SECS`: Clock attestation validation window
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
