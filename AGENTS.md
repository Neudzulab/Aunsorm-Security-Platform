# Aunsorm Agent Coordination# Aunsorm Repository Coordination

### Principles
All test errors must be fixed — even warnings are unacceptable.
No deprecated dependencies are allowed.
Issues must never be suppressed; instead, they should be resolved properly.
Mocking must not be used as a replacement for actual implementations.
Sealed classes, methods, or structures must remain intact and must not be modified.

**The production plan must be completed**

    In summary:

    The codebase must maintain full integrity, with strict quality enforcement.
    Every test should pass cleanly with zero warnings, no deprecated code, and no shortcuts that compromise design principles.

**Version:** 0.5.0  Bu depo tek bir ajan tarafından değil, alan uzmanı takımlar tarafından yönetilecek şekilde tasarlanmalıdır. PLAN.md içerisindeki gereksinimler her sprintte küçük parçalara ayrılacak ve her iş öğesi için sorumlu ajan tanımlanacaktır.

**Last Updated:** 2025-11-01

## Genel İlkeler

---- Tüm kod MSRV 1.76 üzerinde derlenebilir olmalıdır.

- Güvenlik odaklı gereksinimler (kalibrasyon bağlamı, strict kipleri, sıfırlama vb.) uygulanırken formal dokümantasyon tutulmalıdır.

## Primary Directive- Her dizin altındaki ajanlar, bu dosyada belirtilen standartlara uymalıdır.

- Yeni bir alan açıldığında, o dizine özel ek `AGENTS.md` oluşturulmalıdır.

**All development work must align with [PROD_PLAN.md](PROD_PLAN.md).**

## 🎲 AUNSORM NATIVE RNG ZORUNLU KULLANIMI (v0.4.5+)

This repository is coordinated by specialized domain agents. All new features, refactoring, and infrastructure changes must be tracked as tasks in `PROD_PLAN.md` with checkbox format for progress tracking.**KRITIK:** Tüm kriptografik rastgele sayı üretimleri artık Aunsorm'un kendi native RNG algoritmasını kullanmak zorundadır!



---### Yasak Kullanımlar:

- ❌ **OsRng direkt kullanımı** (sadece initial entropy seeding için izin verilir)

## Agent Responsibilities- ❌ **HTTP /random/number** endpoint çağrıları (6.4s overhead)  

- ❌ **rand::thread_rng()** veya benzeri stdlib RNG'leri

### Crypto Agent- ❌ **ChaCha8Rng** veya diğer harici RNG implementasyonları (test hariç)

- **Scope:** `crates/core`, `crates/pqc`, `crates/packet`, `crates/crypto-service`

- **Focus:** Cryptographic primitives, PQC implementations, Native RNG compliance### Zorunlu Kullanım:

- **Current Priority:** Complete PQC security audit and NIST compliance validation- ✅ **AunsormNativeRng** - Tüm crate'lerde aynı implementation

- ✅ **HKDF + NEUDZ-PCS + AACM mixing** - Server ile aynı algoritma

### Platform Agent- ✅ **4x Performance** - Native vs HTTP (1.5s vs 6.4s RSA-2048)

- **Scope:** `crates/server`, `crates/cli`, `crates/wasm`, Docker/Kubernetes manifests- ✅ **Cross-Crate Standardization** - Aynı entropi kalitesi her yerde

- **Focus:** Microservice orchestration, API gateway, deployment automation

- **Current Priority:** Kubernetes migration and production infrastructure setup### Implementation Pattern:

```rust

### Identity Agent// ✅ DOĞRU - Her crate'te aynı pattern

- **Scope:** `crates/jwt`, `crates/x509`, `crates/kms`, `crates/acme`, `crates/mdm`use crate::rng::AunsormNativeRng;

- **Focus:** Authentication, certificates, key management, device enrollment

- **Current Priority:** HSM integration for KMS and OAuth 2.0 complete implementationpub fn generate_key() -> Result<Key, Error> {

    let mut rng = AunsormNativeRng::new();

### Interop Agent    Key::generate_with_rng(&mut rng)

- **Scope:** `benches/`, `fuzz/`, `tests/`, `examples/`, CI/CD pipelines}

- **Focus:** Testing, benchmarking, security audits, documentation

- **Current Priority:** Achieve >80% test coverage and third-party security audit// ❌ YANLIŞ - Artık yasak

use rand_core::OsRng;

---pub fn generate_key() -> Result<Key, Error> {

    let mut rng = OsRng;  // YASAK!

## Critical Rules    Key::generate_with_rng(&mut rng)

}

### 1. Native RNG Mandatory (v0.4.5+)```

**All cryptographic random number generation MUST use `AunsormNativeRng`.**

### Crate-Specific Requirements:

❌ **Forbidden:**- **ACME**: Ed25519, P256, RSA account keys → `AunsormNativeRng`

- Direct `OsRng` usage (except initial entropy seeding)- **JWT**: Ed25519 signing keys, JTI generation → `AunsormNativeRng`  

- HTTP `/random/number` endpoint calls- **KMS**: AES-GCM nonce generation → `AunsormNativeRng`

- `rand::thread_rng()` or other stdlib RNGs- **X509**: RSA key generation for certificates → `AunsormNativeRng`

- External RNG implementations (except in tests)- **YENİ CRATE'LER**: Mutlaka kendi `src/rng.rs` modülü oluştur



✅ **Required:**### Implementation Checklist:

```rust1. **src/rng.rs oluştur** (mevcut crate'lerden kopyala)

use crate::rng::AunsormNativeRng;2. **Cargo.toml'a hkdf dependency ekle** 

3. **lib.rs'de mod rng; pub use rng::* ekle**

pub fn generate_key() -> Result<Key, Error> {4. **Tüm OsRng kullanımlarını AunsormNativeRng ile değiştir**

    let mut rng = AunsormNativeRng::new();5. **cargo test ile doğrula**

    Key::generate_with_rng(&mut rng)

}Bu kural ihlal edilirse PR reject edilecektir!

```

## İş Akışı

**Performance:** Native RNG is 4x faster than HTTP-based RNG (1.5s vs 6.4s for RSA-2048).1. README üzerindeki durum kutucuklarını (checklist) güncel tutun.

2. Her ajan kendi bölümünde çalışır; çakışma durumunda koordinasyon bu dosyada güncellenir.

### 2. Production Plan Compliance3. `cargo fmt --all`, `cargo clippy --all-targets --all-features`, `cargo test --all-features` komutları her değişiklikte çalıştırılmalıdır.

- All new work items must be added to `PROD_PLAN.md` with `[ ]` checkbox4. Güvenlik gerekçesiyle `unsafe` kod yasaktır.

- Mark tasks as `[x]` only when fully completed and tested5. README, PLAN.md, TODO.md veya diğer planlama dosyalarında **tamamlandı (`[x]` veya `done`)** olarak işaretlenmiş kalemler kilitlidir; ajanlar bu maddeleri tekrar açmak yerine yeni bir iş maddesi olarak revizyon talebi oluşturmalıdır.

- Do NOT modify completed tasks - create new revision tasks instead   - Revizyon ihtiyacı varsa, ilgili bölümde `Revize:` önekiyle yeni bir madde ekleyin ve eski maddeye referans verin.

- Each PR must reference its `PROD_PLAN.md` task   - Kilitli maddelerdeki dosyalara dokunmanız gerekiyorsa, PLAN.md içerisinde yeni teslimat maddesi olarak belgeleyin ve yetkilendirme gelmeden değişiklik yapmayın.

6. Ajanlar yalnızca yapılacak işleri, `README.md` ana planını ve kapsamlarındaki `AGENTS.md` yönergelerini esas almalıdır; tamamlanan maddeleri değiştirmek iş akışını bozduğundan kaçınılmalıdır.

### 3. Code Quality Gates

Every commit must pass:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
cargo test --all-features
cargo deny check
```

### 4. Security Requirements

- **No `unsafe` code** - `#![forbid(unsafe_code)]` enforced
- **MSRV 1.76+** - Minimum Supported Rust Version
- **Dependency audits** - `cargo audit` must be clean
- **Fuzz testing** - All parsers/decoders must have fuzz targets



### 5. Documentation Standards

- Update `README.md` for any new endpoints or services
- Update `port-map.yaml` for any port changes
- Add `CHANGELOG.md` entry for version changes
- Technical architecture changes require `PROJECT_SUMMARY.md` updates

### 6. JWT Response Structure - SEALED (v0.5.0+)

**⚠️ SEALED STRUCTURE - DO NOT MODIFY WITHOUT SECURITY REVIEW ⚠️**

The JWT verification response structure is **sealed** to prevent duplicate field serialization errors and maintain client compatibility.

**Canonical Structure (`crates/server/src/routes.rs`):**

```rust
#[derive(Serialize)]
pub struct JwtPayload {
    pub subject: String,
    pub audience: String,
    pub issuer: String,
    pub expiration: u64,
    #[serde(rename = "issuedAt", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
    #[serde(rename = "relatedId", skip_serializing_if = "Option::is_none")]
    pub related_id: Option<String>,
    #[serde(rename = "jwtId", skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extras: Option<serde_json::Map<String, serde_json::Value>>,
}
```

**Example Response:**
```json
{
  "valid": true,
  "payload": {
    "subject": "user123",
    "audience": "zasian-media",
    "issuer": "https://aunsorm.local",
    "expiration": 1761791358,
    "issuedAt": 1761787758,
    "jwtId": "9a05c8cb00b52a2e79403e58d7f27b4e",
    "extras": {
      "roomId": "test-room",
      "participantName": "TestUser",
      "metadata": {
        "codec": "vp9",
        "appData": {
          "role": "host"
        }
      }
    }
  },
  "error": null
}
```

**Critical Rules:**
1. ❌ DO NOT flatten `extras` - causes duplicate field errors
2. ❌ DO NOT add raw claims to top-level
3. ✅ Standard JWT claims use canonical names at top-level
4. ✅ Custom claims MUST be nested under `extras`
5. ✅ Use camelCase for JSON fields

**Modification requires:** Security review, client compatibility assessment, API version bump, CHANGELOG update.

---

## 🚨 Servis Ağacı Güncelleme Direktifi

**YENİ ÖZELLİK/ENDPOINT EKLENDİĞİNDE MUTLAKA YAPILACAKLAR:**

1. **README.md Server Endpoint Ağacını Güncelle**
   - Yeni endpoint eklendiğinde `README.md` içindeki endpoint ağacına ekle
   - Yarım/tamamlanmamış özellik bile olsa `[Planlandı v0.X.0]` veya `[Devam Ediyor]` işaretiyle ekle
   - Kaybolmasın! Ajan değişse bile sonraki ajan eksik olanı görebilmeli

2. **Servis Durumu İşaretleri**
   - ✅ Aktif/Çalışıyor: Endpoint tamamen çalışıyor ve test edilmiş
   - 🚧 Geliştirme: Kod var ama endpoint route'u henüz eklenmedi
   - 📋 Planlandı: Crate var, servis entegrasyonu bekliyor
   - 🔮 Gelecek: Henüz tasarım aşamasında

3. **Port Mapping Güncelleme (`port-map.yaml`)**
   - Yeni port ekleme/değiştirme durumunda `port-map.yaml` güncelle
   - **Zasian Media Platform portları: 50030-50037** (v0.6.0)
   - **Aunsorm portları: 50010-50023** (mevcut)
   - External service entegrasyonları için `integration` bölümünü güncelle

4. **Environment Değişkenleri (`.env`)**
   - `BRIDGE_URL=ws://localhost:50031/ws` (SFU Router)
   - `ZASIAN_WEBSOCKET_URL=wss://localhost:50036/zasian` (Signaling)
   - **Production Override**: `ZASIAN_HOST` ve `HOST` environment variable'larıyla localhost hardcode'ları aşılabilir
   - **OAuth Callbacks**: `OAUTH_PRODUCTION_CALLBACK` ile production callback URL'i belirlenebilir
   - ❌ **Yasak**: Kod içine localhost/127.0.0.1 hardcode yazmak
   - ✅ **Doğru**: Environment variable + fallback pattern kullanmak

5. **OpenAPI Dokümantasyon Güncelleme (`openapi/`)**
   - Yeni endpoint eklendiğinde ilgili `{service}-service.yaml` dosyasını güncelle
   - Request/response schema'ları, örnek payloadlar ve hata kodları ekle
   - `openapi/index.html` içindeki servis kartlarına yeni endpoint'i ekle
   - **Swagger UI**: http://localhost:8080 - İnteraktif API testi
   - **Redoc**: http://localhost:50025 - Temiz dokümantasyon görünümü
   - **Spec Server**: http://localhost:50024 - YAML dosyaları
   - OpenAPI 3.0 standartlarına uygunluk kontrol et

## Workflow

1. **Check `PROD_PLAN.md`** - Find unassigned tasks in your domain
2. **Create branch** - Use format: `agent/crypto/task-description` or `agent/platform/feature-name`

3. **Implement** - Follow code quality gates

4. **Test** - Unit, integration, and manual testing required

5. **Document** - Update all relevant documentation
   - README.md endpoint ağacı
   - port-map.yaml port tahsisleri
   - OpenAPI YAML spec'leri (`openapi/{service}-service.yaml`)
   - index.html servis kartları (Swagger UI + Redoc linkleri)

6. **PR Review** - Requires approval from domain agent lead

7. **Merge** - Update `PROD_PLAN.md` checkbox `[ ]` → `[x]`

### Sorumluluk Matrisi

- **Platform Agent**: Server endpoint ağacının sahibidir
- **Crypto Agent**: Core, PQC, Packet servislerini bildirmekle sorumludur
- **Identity Agent**: JWT, X509, KMS, ID servislerini bildirmekle sorumludur
- **Interop Agent**: Test/benchmark süreçlerinde eksik servisleri tespit etmekle sorumludur

---

## Planlama Ajanları

## Communication- **Crypto Agent**: `crates/core`, `crates/pqc`, `crates/packet`.

- **Platform Agent**: `crates/cli`, `crates/server`, `crates/wasm`.

- **Questions:** Open GitHub issue with `[Agent Question]` prefix- **Identity Agent**: `crates/jwt`, `crates/x509`, `crates/kms`.

- **Blockers:** Tag `@platform-lead` in issue- **Interop Agent**: `benches`, `fuzz`, `crates/pytests`, `examples`, `.github`.

- **Security:** See `SECURITY.md` for disclosure process

- **Urgent:** Tag `@all-agents` in issue (use sparingly)Bu ilk commit planlama ve altyapı başlangıcı içindir. Sonraki işler ilgili ajan tarafından üstlenilecek.


---

## Versioning

Current version: **0.5.0**

- **Patch (0.5.x):** Bug fixes, documentation updates
- **Minor (0.x.0):** New features, backward-compatible API changes
- **Major (x.0.0):** Breaking changes (target: 1.0.0 in Q2 2025)

All version bumps require:
1. Update all `Cargo.toml` files
2. Update `CHANGELOG.md`
3. Update version references in documentation
4. Tag release in git: `v0.5.0`

---

## Production Readiness

**See [PROD_PLAN.md](PROD_PLAN.md) for complete production deployment checklist.**

Current blockers for v1.0.0:
- Clock attestation production NTP server deployment
- PostgreSQL migration from SQLite
- Kubernetes manifests and Helm charts
- Third-party security audit completion
- HSM integration for key management

---

## Contact

For urgent production issues or security concerns, see `SECURITY.md`.
