# Aunsorm Cryptographic Security Platform

**Version:** 0.5.0 | **License:** MIT/Apache-2.0 | **Language:** Rust (MSRV 1.76+)

Post-Quantum ready microservices platform for modern cryptographic operations.

> 📘 **Technical Details:** See [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)  
> 🗺️ **Port Mapping:** See [port-map.yaml](port-map.yaml)  
> 🎯 **Production Roadmap:** See [PROD_PLAN.md](PROD_PLAN.md)  
> 📖 **API Documentation:** [Interactive Swagger UI](http://localhost:50024) (OpenAPI 3.0)  
> 🎫 **JWT Guide:** See [JWT_AUTHENTICATION_GUIDE.md](JWT_AUTHENTICATION_GUIDE.md)

---

## Quick Start

### Docker Compose (Recommended)

```powershell
# Start all 15 microservices
.\scripts\docker\start-all.ps1

# Start API documentation server
cd openapi && docker compose up -d

# Check service health
docker compose ps
curl http://localhost:50010/health  # Gateway

# View logs
docker compose logs -f gateway

# Stop services
docker compose down
```

### API Documentation

```bash
# Start Swagger UI (OpenAPI 3.0)
cd openapi
docker compose up -d

# Access documentation
# Main Portal: http://localhost:50024
# Swagger UI: http://localhost:8080
# Auth Service: http://localhost:8080/?url=http://localhost:50024/auth-service.yaml
# Crypto Service: http://localhost:8080/?url=http://localhost:50024/crypto-service.yaml
# PQC Service: http://localhost:8080/?url=http://localhost:50024/pqc-service.yaml
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

### Native RNG Compliance Checklist

All production binaries must derive entropy exclusively through `AunsormNativeRng`.
This RNG seeds itself from the operating system only during instantiation and then
mixes state via HKDF + NEUDZ-PCS + AACM, aligning with the security architecture
documented in `certifications/audit/native_rng_entropy_analysis.md` and the
repository-wide agent directives. Before rolling out new features, verify:

1. **No direct `OsRng` usage** — search for `OsRng` in the touched crates and
   confirm that it appears only inside `AunsormNativeRng::new` implementations or
   initial seeding helpers.
2. **Consistent helper import** — ensure modules call `create_aunsorm_rng()` or
   instantiate `AunsormNativeRng::new()` from their crate-specific `rng` module
   instead of third-party RNGs.
3. **Entropy provenance logged** — extend service/CLI diagnostics to report that
   the native RNG path was used (without leaking secret material) when new
   commands or endpoints are added.
4. **Tests mirror production** — integration and fuzz tests should exercise the
   same RNG helper to prevent drift between test and release binaries.

### Calibration Workflow (CLI + API)

1. **Inspect calibration locally**

   ```bash
   aunsorm-cli calib inspect \
     --org-salt V2VBcmVLdXQuZXU= \
     --calib-text "Neudzulab | Prod | 2025-08" \
     --format json
   ```

   Çıktıdaki `fingerprint_hex` değeri (`671023bc1061591b72923f7f9f97abb04fe3ab3767bb8b21895912995d1a3298`)
   sunucu tarafında `AUNSORM_CALIBRATION_FINGERPRINT` ortam değişkeni olarak
   yapılandırılmalıdır.

2. **Beklentiyi kilitle**

   ```bash
   aunsorm-cli calib verify \
     --org-salt V2VBcmVLdXQuZXU= \
     --calib-text "Neudzulab | Prod | 2025-08" \
     --expect-fingerprint-hex 671023bc1061591b72923f7f9f97abb04fe3ab3767bb8b21895912995d1a3298
   ```

   Komut hata kodu 0 döndürdüğünde fingerprint eşleşmiştir; aksi durumda CLI
   ayrıntılı rapor üretir.

3. **Sunucu uçlarını çağır**

   ```bash
   curl -sS http://localhost:8080/calib/inspect \
     -H 'Content-Type: application/json' \
     -d '{
           "org_salt": "V2VBcmVLdXQuZXU=",
           "calib_text": "Neudzulab | Prod | 2025-08"
         }'

   curl -sS -w '\nHTTP %{http_code}\n' http://localhost:8080/calib/verify \
     -H 'Content-Type: application/json' \
     -d '{
           "org_salt": "V2VBcmVLdXQuZXU=",
           "calib_text": "Neudzulab | Prod | 2025-08"
         }'
   ```

   Strict kip aktifteyken fingerprint uyuşmazlığı `HTTP 422` ile döner ve
   telemetriye kalibrasyon başarısızlığı kaydedilir.

---

## Service Endpoints

Durum işaretleri:
- ✅ Aktif ve üretimde çalışıyor
- 🚧 Aktif geliştirme veya üretim hazırlığı devam ediyor
- 📋 Planlandı, entegrasyon bekleniyor
- 🔮 Tasarım aşamasında / gelecek sürüm

### Çekirdek Servisler
- ✅ **Gateway** (`50010`, `aun-gateway`)
  - `GET /health` — sistem sağlık kontrolü
  - `GET /metrics` — Prometheus metrikleri

- ✅ **Auth Service** (`50011`, `aun-auth-service`)
  - `POST /security/generate-media-token` — JWT üretimi
  - `POST /security/jwt-verify` — JWT doğrulama
  - `GET /oauth/jwks.json` — JWKS anahtar yayını
  - `POST /oauth/begin-auth` — OAuth 2.0 + PKCE başlangıcı
  - `POST /oauth/token` — Token değişimi
  - `POST /oauth/revoke` — Erişim ve refresh token iptali
  - `POST /oauth/introspect` — Token inceleme
  - `GET /oauth/transparency` — Şeffaflık logları

- ✅ **Crypto Service** (`50012`, `aun-crypto-service`)
  - `POST /encrypt` — AES-256-GCM / ChaCha20-Poly1305
  - `POST /decrypt` — AEAD çözme
  - `POST /sign` — Ed25519 / RSA imzalama
  - `POST /verify` — İmza doğrulama
  - `POST /derive-key` — HKDF türetme

- 🚧 **PQC Service** (`50018`, `aun-pqc-service`)
  - `GET /pqc/capabilities` — Algoritma kullanılabilirliği
  - `POST /pqc/ml-kem/encapsulate` — ML-KEM-768 kapsülleme
  - `POST /pqc/ml-kem/decapsulate` — ML-KEM-768 kapsül çözme
  - `POST /pqc/ml-dsa/sign` — ML-DSA-65 imzalama
  - `POST /pqc/ml-dsa/verify` — ML-DSA-65 doğrulama
  - `POST /pqc/slh-dsa/sign` — SLH-DSA-128s imzalama
  - `POST /pqc/slh-dsa/verify` — SLH-DSA-128s doğrulama

### Kimlik ve Sertifika Servisleri
- ✅ **X.509 Service** (`50013`, `aun-x509-service`)
  - `POST /x509/generate-ca` — Root CA üretimi
  - `POST /x509/generate-cert` — Sertifika imzalama
  - `POST /x509/verify-chain` — Zincir doğrulama
  - `POST /x509/csr/generate` — CSR oluşturma
  - `POST /x509/csr/sign` — CSR imzalama

- ✅ **KMS Service** (`50014`, `aun-kms-service`)
  - `POST /kms/keys/generate` — Anahtar üretimi
  - `POST /kms/keys/encrypt` — Anahtar sarma
  - `POST /kms/keys/decrypt` — Anahtar açma
  - `POST /kms/keys/rotate` — Anahtar rotasyonu
  - `GET /kms/keys/:id/metadata` — Anahtar metadatası
  - `DELETE /kms/keys/:id` — Anahtar silme

- ✅ **MDM Service** (`50015`, `aun-mdm-service`)
  - `POST /mdm/register` — Cihaz kaydı
  - `GET /mdm/policy/:platform` — Platform politikaları
  - `GET /mdm/cert-plan/:device_id` — Sertifika dağıtım planı
  - `POST /mdm/compliance/check` — Uyumluluk doğrulama

- ✅ **ID Service** (`50016`, `aun-id-service`)
  - `POST /id/generate` — Benzersiz ID üretimi
  - `POST /id/parse` — ID ayrıştırma
  - `POST /id/verify-head` — Head-stamped doğrulama

- 🚧 **ACME Service** (`50017`, `aun-acme-service`)
  - `GET /acme/directory` — ACME dizini (RFC 8555)
  - `GET /acme/new-nonce` — Replay-Nonce üretimi
  - `POST /acme/new-account` — Hesap kaydı
  - `POST /acme/new-order` — Sertifika siparişi
  - `POST /acme/order/:id/finalize` — CSR finalizasyonu
  - `POST /acme/revoke-cert` — Sertifika iptali
  - `POST /acme/validation/http-01` — HTTP-01 doğrulaması
  - `POST /acme/validation/dns-01` — DNS-01 doğrulaması

### İletişim ve Şifreleme Servisleri
- 🚧 **E2EE Service** (`50021`, `aun-e2ee-service`)
  - `POST /e2ee/context` — Oturum başlatma
  - `POST /e2ee/context/step` — Ratchet ilerletme
  - `POST /sfu/context` — SFU bağlamı oluşturma
  - `POST /sfu/context/step` — SFU ratchet adımı

- 🚧 **Blockchain Service** (`50020`, `aun-blockchain-service`)
  - `POST /blockchain/fabric/did/verify` — Hyperledger DID doğrulama (POC)
  - `POST /blockchain/media/record` — Audit trail kaydı `[Planlandı v0.6.1]`

- 🚧 **RNG Service** (`50019`, `aun-rng-service`, **external fallback**)
  - `GET /random/number` — Üçüncü taraf istemciler için entropy fallback'i (Aunsorm servisleri native RNG kullanır)

### Gözlemlenebilirlik ve CLI
- ✅ **Metrics Service** (`50022`, `aun-metrics-service`)
  - `GET /metrics` — Prometheus metrikleri
  - `GET /health/aggregate` — Sistem genelinde sağlık durumu

- ✅ **CLI Gateway** (`50023`, `aun-cli-gateway`)
  - `POST /cli/jwt/verify` — CLI JWT doğrulama
  - `POST /cli/execute` — Komut yürütme

### HTTP Middleware Garantileri
- `tower-http` `TraceLayer` entegrasyonu tüm servis uçlarında istek/yanıt
  gecikmesini milisaniye hassasiyetiyle loglar ve başarısız istekleri
  ayrı log seviyesinde işaretler.
- Yanıtlar otomatik olarak `br`, `gzip`, `deflate` veya `zstd`
  sıkıştırma algoritmalarıyla müzakere edilir ve gelen istekler aynı
  `Content-Encoding` değerleri için açılır; bu sayede bant genişliği
  tüketimi düşerken CLI ve otomasyon istemcileri ek konfigürasyon
  gerektirmeden sıkıştırma kullanabilir.

---

## Environment Configuration

Key environment variables (see `.env`):

```bash
# Clock Attestation (required for all services)
AUNSORM_CLOCK_MAX_AGE_SECS=30              # Strict mode requires ≤30s; dev default is 300s when unset
AUNSORM_CLOCK_REFRESH_URL=https://ntp.prod.aunsorm/attestation
AUNSORM_CLOCK_REFRESH_INTERVAL_SECS=15     # Must be ≤ max_age/2 in strict mode
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

> ⚠️ **Production:** Clock attestation timestamp auto-updates on startup. For production, deploy NTP attestation server with real signatures and expose it via `AUNSORM_CLOCK_REFRESH_URL`. `/health` will report `clock.status=ok` when the attestation is fresh.

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
- **[docs/archive/README.md](docs/archive/README.md)** - Index of preserved legacy planning documents

---

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE).
