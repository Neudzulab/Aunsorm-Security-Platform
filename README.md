# Aunsorm Cryptographic Security Platform

**Version:** 0.5.0 | **License:** MIT/Apache-2.0 | **Language:** Rust (MSRV 1.76+)

Post-Quantum ready microservices platform for modern cryptographic operations.

> 📘 **Technical Details:** See [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)  
> 🗺️ **Port Mapping:** See [port-map.yaml](port-map.yaml)  
> 🎯 **Production Roadmap:** See [PROD_PLAN.md](PROD_PLAN.md)

---

## Quick Start

### Docker Compose (Recommended)

```powershell
# Start all 15 microservices
.\scripts\docker\start-all.ps1

# Check service health
docker compose ps
curl http://localhost:50010/health  # Gateway

# View logs
docker compose logs -f gateway

# Stop services
docker compose down
```

### Manual Build

```bash
# Build all crates
cargo build --release --all-features

# Run server
./target/release/aunsorm-server

# Run CLI
./target/release/aunsorm-cli --help
```

---

## Service Endpoints

### Gateway (Port 50010)
```
GET  /health                                # System health check
GET  /metrics                               # Prometheus metrics
```

### Auth Service (Port 50011)
```
POST /security/generate-media-token         # JWT token generation
POST /security/jwt-verify                   # JWT validation
GET  /oauth/jwks.json                       # JWKS key publication
POST /oauth/begin-auth                      # OAuth 2.0 + PKCE flow
POST /oauth/token                           # Token exchange
POST /oauth/introspect                      # Token introspection
GET  /oauth/transparency                    # Transparency logs
```

### Crypto Service (Port 50012)
```
POST /encrypt                               # AES-256-GCM / ChaCha20-Poly1305
POST /decrypt                               # AEAD decryption
POST /sign                                  # Ed25519 / RSA signing
POST /verify                                # Signature verification
POST /derive-key                            # HKDF key derivation
```

### PQC Service (Port 50018)
```
GET  /pqc/capabilities                      # Algorithm availability
POST /pqc/ml-kem/encapsulate                # ML-KEM-768 encapsulation
POST /pqc/ml-kem/decapsulate                # ML-KEM-768 decapsulation
POST /pqc/ml-dsa/sign                       # ML-DSA-65 signing
POST /pqc/ml-dsa/verify                     # ML-DSA-65 verification
POST /pqc/slh-dsa/sign                      # SLH-DSA-128s signing
POST /pqc/slh-dsa/verify                    # SLH-DSA-128s verification
```

### X.509 Service (Port 50013)
```
POST /x509/generate-ca                      # Root CA generation
POST /x509/generate-cert                    # Certificate signing
POST /x509/verify-chain                     # Chain validation
POST /x509/csr/generate                     # CSR creation
POST /x509/csr/sign                         # CSR signing
```

### KMS Service (Port 50014)
```
POST /kms/keys/generate                     # Key generation
POST /kms/keys/encrypt                      # Key wrapping
POST /kms/keys/decrypt                      # Key unwrapping
POST /kms/keys/rotate                       # Key rotation
GET  /kms/keys/:id/metadata                 # Key metadata
DELETE /kms/keys/:id                        # Key deletion
```

### ACME Service (Port 50017)
```
GET  /acme/directory                        # ACME directory (RFC 8555)
GET  /acme/new-nonce                        # Replay-Nonce generation
POST /acme/new-account                      # Account registration
POST /acme/new-order                        # Certificate order
POST /acme/order/:id/finalize               # CSR finalization
POST /acme/revoke-cert                      # Certificate revocation
POST /acme/validation/http-01               # HTTP-01 challenge
POST /acme/validation/dns-01                # DNS-01 challenge
```

### MDM Service (Port 50015)
```
POST /mdm/register                          # Device enrollment
GET  /mdm/policy/:platform                  # Platform-specific policies
GET  /mdm/cert-plan/:device_id              # Certificate distribution plan
POST /mdm/compliance/check                  # Compliance validation
```

### ID Service (Port 50016)
```
POST /id/generate                           # Unique ID generation
POST /id/parse                              # ID parsing
POST /id/verify-head                        # Head-stamped validation
```

### E2EE Service (Port 50021)
```
POST /e2ee/context                          # Session initialization
POST /e2ee/context/step                     # Ratchet advancement
POST /sfu/context                           # SFU context creation
POST /sfu/context/step                      # SFU ratchet step
```

### Blockchain Service (Port 50020)
```
POST /blockchain/fabric/did/verify          # Hyperledger DID verification (POC)
POST /blockchain/media/record               # Audit trail recording [Planned v0.6.1]
```

### RNG Service (Port 50019)
```
POST /random/number                         # Random number generation (deprecated, use native)
POST /random/bytes                          # Random byte generation
```

### Metrics Service (Port 50022)
```
GET  /metrics                               # Aggregated Prometheus metrics
GET  /health/aggregate                      # System-wide health status
```

### CLI Gateway (Port 50023)
```
POST /cli/jwt/verify                        # CLI JWT verification
POST /cli/execute                           # Command execution
```

---

## Environment Configuration

Key environment variables (see `.env`):

```bash
# Clock Attestation (required for all services)
AUNSORM_CLOCK_MAX_AGE_SECS=30              # Production: 30s, Dev: 300s
AUNSORM_CALIBRATION_FINGERPRINT=...        # Calibration context ID
AUNSORM_CLOCK_ATTESTATION=...              # JSON clock snapshot

# Security
AUNSORM_STRICT=false                        # Strict security mode
AUNSORM_JTI_DB=./data/tokens.db             # Token revocation database

# Server
AUNSORM_LISTEN=0.0.0.0:8080                 # Listen address
AUNSORM_ISSUER=https://aunsorm.local        # JWT issuer
AUNSORM_AUDIENCE=aunsorm-clients            # JWT audience
```

> ⚠️ **Production:** Clock attestation timestamp auto-updates on startup. For production, deploy NTP attestation server with real signatures.

---

## Testing

```bash
# Unit tests
cargo test --all-features

# Integration tests
cargo test --test '*' --all-features

# Benchmarks
cargo bench

# Fuzz testing
cargo +nightly fuzz run <target>
```

---

## Documentation

- **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** - Technical architecture and design
- **[PROD_PLAN.md](PROD_PLAN.md)** - Production deployment checklist
- **[port-map.yaml](port-map.yaml)** - Complete port mapping
- **[SECURITY.md](SECURITY.md)** - Security policy and disclosures
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines
- **[CHANGELOG.md](CHANGELOG.md)** - Version history

---

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE).
