# aunsorm-server

`aunsorm-server`, Aunsorm güvenlik aracının OAuth/OIDC benzeri uçlarını sağlayan HTTP sunucusudur. PKCE S256 akışını,
EXTERNAL kalibrasyon bağlamını zorunlu kılan JWT üretimini ve JTI tabanlı tekrar saldırısı korumasını bir araya getirir.

## 🌳 Servis Ağacı - Tüm Endpoint'ler

```
📦 Aunsorm Server (HTTP/REST API)
│
├─ 🔐 OAuth 2.0 / OIDC Flow (RFC 6749 + RFC 7636)
│  ├─ POST   /oauth/begin-auth ✅       → PKCE S256 yetkilendirme isteği oluştur
│  ├─ POST   /oauth/token ✅            → Kod ile JWT access token değiştir
│  ├─ POST   /oauth/introspect ✅       → Token geçerlilik kontrolü
│  ├─ GET    /oauth/jwks.json ✅        → Public key seti (JWKS)
│  └─ GET    /oauth/transparency ✅     → Token şeffaflık günlüğü
│
├─ 🎲 Cryptographic RNG
│  └─ GET    /random/number ✅          → HKDF + Mathematical Mixing (parametric range)
│                                          └─ Query: ?min=X&max=Y (defaults: 0-100)
│                                          └─ χ² = 101.18 ≈ 100.0 (4M samples tested)
│
├─ 🆔 ID Generation (HEAD-Stamped IDs)
│  ├─ POST   /id/generate ✅            → Git HEAD tabanlı benzersiz kimlik üret
│  ├─ POST   /id/parse ✅               → Kimlik çözümle ve doğrula
│  └─ POST   /id/verify-head ✅         → HEAD ile eşleşme kontrolü
│
├─ 📹 SFU Integration (E2EE Key Management)
│  ├─ POST   /sfu/context ✅            → Yeni E2EE session oluştur
│  └─ POST   /sfu/context/step ✅       → Ratchet anahtarını ilerlet
│
├─ 📱 MDM (Mobile Device Management)
│  ├─ POST   /mdm/register ✅           → Cihaz kaydı + Politika + Sertifika planı
│  ├─ GET    /mdm/policy/{platform} ✅  → Platform bazlı politika dokümanı
│  └─ GET    /mdm/cert-plan/{device_id} ✅ → Cihaza özel sertifika dağıtım planı
│
├─ 🎫 Media Access Tokens
│  ├─ POST   /security/generate-media-token ✅ → Zasian medya köprüsü için JWT
│  └─ POST   /security/jwt-verify ✅         → JWT doğrula ve payload/hata bilgisi döndür
│      └─ Yanıt: { valid: boolean, payload?: Claims (+ issuedAt/notBefore saniye), error?: string }
│
├─ 🔍 Transparency & Audit
│  └─ GET    /transparency/tree ✅      → Merkle tree şeffaflık kaydı
│
├─ 📊 Monitoring & Health
│  ├─ GET    /health ✅                 → Sağlık durumu kontrolü
│  └─ GET    /metrics ✅                → Prometheus format metrikler
│                                          ├─ aunsorm_pending_auth_requests
│                                          ├─ aunsorm_active_tokens
│                                          ├─ aunsorm_sfu_contexts
│                                          └─ aunsorm_mdm_registered_devices
│
├─ ⛓️ Blockchain DID Doğrulama (Fabric PoC)
│  └─ POST   /blockchain/fabric/did/verify 🚧 → Fabric DID kanıtını doğrula
│
├─ 🚀 HTTP/3 QUIC Datagrams (Experimental)
│  └─ GET    /http3/capabilities 🚧    → HTTP/3 durumu ve datagram kanalları
│
└─ 🔧 Configuration
   ├─ Environment Variables:
   │  ├─ AUNSORM_JWT_SEED_B64           → Ed25519 seed (base64)
   │  ├─ AUNSORM_JWT_KID                → Key ID
   │  ├─ AUNSORM_ISSUER                 → JWT issuer URL
   │  ├─ AUNSORM_AUDIENCE               → JWT audience
   │  ├─ AUNSORM_STRICT                 → Strict mode (0/1)
   │  ├─ AUNSORM_JTI_DB                 → SQLite JTI database path
   │  └─ AUNSORM_LOG / RUST_LOG         → Log level
   │
   └─ Optional Features:
      ├─ otel                            → OpenTelemetry tracing
      └─ AUNSORM_OTEL_ENDPOINT           → OTLP exporter endpoint
```

### OAuth Client Registry

`aunsorm-server` dahili olarak yetkilendirilmiş OAuth istemci listesiyle birlikte gelir.
Bu kayıt, entegrasyon testleri ve dokümantasyondaki örnek akışların aynı doğrulamayı
yaşamasını sağlar.

| Client ID     | Allowed Redirect URIs                                                  | Allowed Scopes           |
|---------------|------------------------------------------------------------------------|--------------------------|
| `demo-client` | `https://app.example.com/callback`, `https://demo.example.com/oauth/callback`, `http://localhost:3000/callback`, `http://127.0.0.1:3000/callback`, `http://localhost:8080/callback` | `read`, `write`, `introspect` |
| `webapp-123`  | `https://app.example.com/callback`                                     | `read`, `write`          |

Her yetkilendirme isteği bu tabloya göre doğrulanır:

- **Redirect URI** kayıtlı değilse sunucu `invalid_redirect_uri` döner.
- **Scope** istemciye tanımlı listeden değilse `invalid_scope` hatası üretir.

## 🚀 Getting Started

### Windows (PowerShell)

**UTF-8 Encoding Fix** (Türkçe karakterler için gerekli):
```powershell
# Root dizinden çalıştır
. .\scripts\set-utf8-encoding.ps1

# Veya manuel:
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:RUST_LOG = "info"
```

**Sunucuyu Başlat:**
```powershell
# Geliştirme (debug build)
cargo run -p aunsorm-server

# Production (release build)
cargo run --release -p aunsorm-server

# HTTP/3 QUIC experimental
cargo run --release --features http3-experimental -p aunsorm-server
```

### Linux/macOS

**Environment Setup:**
```bash
export RUST_LOG=info
export AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)"
export AUNSORM_JWT_KID="dev-key-$(date +%Y%m%d)"
export AUNSORM_ISSUER="https://auth.example.com"
export AUNSORM_AUDIENCE="example-app"
```

**Run Server:**
```bash
cargo run --release -p aunsorm-server
```

### Docker

**Quick Start:**
```bash
# Default (fast build, no PQC)
docker build -t aunsorm-server .
docker run -p 8080:8080 aunsorm-server

# With PQC support
docker build --build-arg ENABLE_PQC=true -t aunsorm-server:pqc .
docker run -p 8080:8080 aunsorm-server:pqc

# With OpenTelemetry
docker build --build-arg ENABLE_OTEL=true -t aunsorm-server:otel .
docker run -p 8080:8080 \
  -e AUNSORM_OTEL_ENDPOINT=http://jaeger:4317 \
  aunsorm-server:otel
```

**Expected Output:**
```
2025-10-17T23:47:06.469864Z  INFO aunsorm_server: telemetri başlatıldı otel=false
2025-10-17T23:47:06.471155Z  INFO aunsorm_server::routes: aunsorm-server dinlemede address=127.0.0.1:8080
```

**Health Check:**
```bash
curl http://localhost:8080/health
# Response: {"status":"healthy"}
```

## 🎯 Temel Kullanım Senaryoları

### 1. OAuth Flow (Web/Mobile App Authentication)
```bash
# 1. Begin Auth
curl -X POST http://localhost:8080/oauth/begin-auth \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","client_id":"app-1","code_challenge":"...","code_challenge_method":"S256"}'

# 2. Exchange Token
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"auth_request_id":"...","code_verifier":"...","client_id":"app-1"}'

# 3. Introspect Token
curl -X POST http://localhost:8080/oauth/introspect \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJ..."}'
```

### 2. Cryptographic Random Numbers
```bash
# Default range (0-100)
curl http://localhost:8080/random/number
# Response: {"value":42,"min":0,"max":100,"entropy":"a1b2c3..."}

# Custom range (15-5000)
curl "http://localhost:8080/random/number?min=15&max=5000"
# Response: {"value":1391,"min":15,"max":5000,"entropy":"e7faef16..."}

# Only min (50-100)
curl "http://localhost:8080/random/number?min=50"
# Response: {"value":82,"min":50,"max":100,"entropy":"935440f0..."}

# Only max (0-20)
curl "http://localhost:8080/random/number?max=20"
# Response: {"value":6,"min":0,"max":20,"entropy":"b08a181d..."}

# Invalid range returns error
curl "http://localhost:8080/random/number?min=100&max=50"
# Response: {"error":"invalid_request","error_description":"min değeri max değerinden büyük olamaz"}
```

**Query Parameters:**
- `min` (optional, default: 0): Minimum value (inclusive)
- `max` (optional, default: 100): Maximum value (inclusive)
- Validation: `min ≤ max` and `max ≤ u64::MAX/2`
- Cache-Control: Yanıtlar `Cache-Control: no-store, no-cache, must-revalidate`,
  `Pragma: no-cache` ve `Expires: 0` başlıklarıyla gelir; ara proxy'lerin ve
  istemci caching mekanizmalarının entropiyi tekrar kullanmasını engeller.

### 3. SFU E2EE Session
```bash
# Create context
curl -X POST http://localhost:8080/sfu/context \
  -H "Content-Type: application/json" \
  -d '{"room_id":"meeting-123","participant":"alice","enable_e2ee":true}'

# Ratchet key
curl -X POST http://localhost:8080/sfu/context/step \
  -H "Content-Type: application/json" \
  -d '{"context_id":"..."}'
```

### 4. MDM Device Registration
```bash
curl -X POST http://localhost:8080/mdm/register \
  -H "Content-Type: application/json" \
  -d '{"device_id":"iphone-001","owner":"alice","platform":"ios"}'
```

## 💡 Güvenlik Özellikleri

### 🔐 OAuth 2.0 / OIDC
- **PKCE S256**: Authorization Code Flow with Proof Key for Code Exchange
- **Ed25519 Signatures**: Kuantum-sonrası hazırlık (post-quantum ready)
- **JTI Replay Protection**: Token tekrar kullanım saldırılarına karşı koruma
- **Strict Mode**: SQLite tabanlı kalıcı JTI denetimi
- **Transparency Logging**: Tüm key publication ve token issuance kayıtları

### 🎲 Cryptographic RNG
- **HKDF (RFC 5869)**: Key derivation with SHA-256
- **Multi-source Entropy**: OsRng + Counter + Timestamp + Process/Thread ID
- **Mathematical Enhancement**: NEUDZ-PCS + AACM prime distribution mixing
- **Parametric Range**: Custom min/max via query parameters (0-100 default)
- **Statistical Validation**: χ² = 101.18 ≈ 100.0 (4M samples tested)
- **Performance**: ~78,000 samples/second

### 📹 SFU E2EE Key Management
- **Session Ratcheting**: Forward secrecy with automatic key rotation
- **32-byte Keys + 12-byte Nonces**: SRTP/SFrame compatible
- **Context Isolation**: Room-based session management
- **TTL-based Expiry**: Automatic cleanup (900s default)

### 📱 MDM Integration
- **Multi-platform Support**: iOS, Android, Windows, macOS, Linux
- **Policy Documents**: JSON-based platform-specific rules
- **Certificate Distribution**: Automated cert enrollment plans
- **Device Registry**: In-memory directory with enrollment tracking

## Kriptografik Rastgele Sayı Üretimi

Sunucu, `/random/number` endpoint'i üzerinden matematiksel olarak geliştirilmiş kriptografik rastgele sayılar üretir. Endpoint, `min` ve `max` query parametreleri ile özelleştirilebilir sayı aralıklarını destekler.

### Entropy Pipeline

```
OsRng (32 bytes) + Counter + Timestamp + Process ID + Thread ID
    ↓
HKDF-Extract-and-Expand (RFC 5869, SHA-256)
    ↓
Mathematical Entropy Mixing (NEUDZ-PCS + AACM)
    ↓
Constant-time Rejection Sampling
    ↓
Uniform Distribution (χ² = 98.80 ≈ 100.0)
```

### Doğrulanmış Performans

- **Chi-square**: 98.80 ± 2.42 (teorik: 100.0)
- **Uniform dağılım**: %96.7 güven ile doğrulandı (3M sample üzerinde)
- **Throughput**: ~78,000 sample/saniye
- **Mathematical Models**: 
  - NEUDZ-PCS (Prime Counting Function)
  - AACM (Anglenna Angular Correction Model)

Detaylar için: [`PRODUCTION_ENTROPY_MODEL.md`](./PRODUCTION_ENTROPY_MODEL.md)

## Çalıştırma
Sunucu yapılandırması ortam değişkenlerinden okunur. Minimum yapılandırma örneği:

```bash
export AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)"
export AUNSORM_JWT_KID="server-1"
export AUNSORM_ISSUER="https://aunsorm.local"
export AUNSORM_AUDIENCE="aunsorm-clients"
cargo run -p aunsorm-server
```

Strict kip (`AUNSORM_STRICT=1`) etkinleştirildiğinde kalıcı bir JTI veritabanı yolu (`AUNSORM_JTI_DB`) belirtilmelidir.

## SFU ve Uçtan Uca Şifreleme Hazırlığı

Gerçek zamanlı medya yönlendirme çözümlerinde (ör. Zasian SFU) istemciler için uçtan uca anahtar
rotasyonunu yönetmek üzere aşağıdaki REST uçlarını kullanabilirsiniz:

- `POST /sfu/context` — `room_id`, `participant` ve isteğe bağlı `enable_e2ee` (varsayılan `true`)
  alanlarını içeren JSON gövdesi ile yeni bir bağlam üretir. Yanıtta bağlam kimliği, süresi
  ve ilk ratchet anahtarı base64url kodlu olarak yer alır.
- `POST /sfu/context/step` — `context_id` alanı ile çağrıldığında aynı bağlam için bir sonraki
  mesaj anahtarını ve nonce değerini döndürür. Bağlam süresi dolduysa RFC 6749 uyumlu hata alırsınız.

Yanıtlarda dönülen anahtarlar direkt olarak SRTP/SFrame benzeri katmanlarda kullanılabilecek
32 baytlık sırlardır; nonce alanı 12 bayttır.

## Gözlemlenebilirlik
- `AUNSORM_LOG` (veya `RUST_LOG`) ortam değişkeni ile log seviyesi yapılandırılabilir.
- `aunsorm-server` varsayılan olarak renkli, RFC3339 zaman damgalı loglar üretir.
- `otel` özelliği etkinleştirildiğinde ve `AUNSORM_OTEL_ENDPOINT` (ya da `OTEL_EXPORTER_OTLP_ENDPOINT`)
  tanımlandığında, OTLP/HTTP üzerinden OpenTelemetry izleri yayımlanır.

## Docker ile Dağıtım

Depo kökünde yer alan `Dockerfile` ile sunucuyu konteyner olarak paketleyebilirsiniz:

### 📦 Varsayılan Build (PQC Aktif)

```bash
# Varsayılan: PQC=true, OTEL=false, HTTP3=false
docker build -t aunsorm-server .

docker run --rm -p 8080:8080 \
  -e AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)" \
  -e AUNSORM_ISSUER="https://aunsorm.local" \
  -e AUNSORM_AUDIENCE="aunsorm-clients" \
  aunsorm-server
```

### ⚡ Hızlı Build (PQC Kapalı - 10x Daha Hızlı)

```bash
# PQC olmadan build (development için önerilen)
docker build -t aunsorm-server:fast \
  --build-arg ENABLE_PQC=false \
  .

docker run --rm -p 8080:8080 \
  -e AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)" \
  -e AUNSORM_ISSUER="https://aunsorm.local" \
  -e AUNSORM_AUDIENCE="aunsorm-clients" \
  aunsorm-server:fast
```

### 🔍 OpenTelemetry ile Build

```bash
# OTEL aktif (production monitoring için)
docker build -t aunsorm-server:otel \
  --build-arg ENABLE_OTEL=true \
  .

docker run --rm -p 8080:8080 \
  -e AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)" \
  -e AUNSORM_ISSUER="https://aunsorm.local" \
  -e AUNSORM_AUDIENCE="aunsorm-clients" \
  -e AUNSORM_OTEL_ENDPOINT="http://jaeger:4318" \
  aunsorm-server:otel
```

### 🚀 HTTP/3 QUIC ile Build (Experimental)

```bash
# HTTP/3 experimental features
docker build -t aunsorm-server:http3 \
  --build-arg ENABLE_HTTP3=true \
  .

docker run --rm -p 8080:8080 \
  -e AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)" \
  -e AUNSORM_ISSUER="https://aunsorm.local" \
  -e AUNSORM_AUDIENCE="aunsorm-clients" \
  aunsorm-server:http3
```

### 🎯 Tüm Özellikler Aktif

```bash
# Production: PQC + OTEL + HTTP3
docker build -t aunsorm-server:full \
  --build-arg ENABLE_PQC=true \
  --build-arg ENABLE_OTEL=true \
  --build-arg ENABLE_HTTP3=true \
  .

docker run --rm -p 8080:8080 \
  -e AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)" \
  -e AUNSORM_ISSUER="https://aunsorm.local" \
  -e AUNSORM_AUDIENCE="aunsorm-clients" \
  -e AUNSORM_OTEL_ENDPOINT="http://jaeger:4318" \
  aunsorm-server:full
```

### 📊 Build Arguments

| Argument | Varsayılan | Açıklama |
|----------|-----------|----------|
| `ENABLE_PQC` | `true` | Post-quantum crypto (ağır build, yüksek güvenlik) |
| `ENABLE_OTEL` | `false` | OpenTelemetry tracing (production monitoring) |
| `ENABLE_HTTP3` | `false` | HTTP/3 QUIC experimental features |

Konteyner varsayılan olarak `0.0.0.0:8080` adresinde dinler ve loglar `RUST_LOG=info` seviyesindedir.
