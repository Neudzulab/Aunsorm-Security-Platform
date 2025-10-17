# aunsorm-server

`aunsorm-server`, Aunsorm güvenlik aracının OAuth/OIDC benzeri uçlarını sağlayan HTTP sunucusudur. PKCE S256 akışını,
EXTERNAL kalibrasyon bağlamını zorunlu kılan JWT üretimini ve JTI tabanlı tekrar saldırısı korumasını bir araya getirir.

## 🌳 Servis Ağacı - Tüm Endpoint'ler

```
📦 Aunsorm Server (HTTP/REST API)
│
├─ 🔐 OAuth 2.0 / OIDC Flow
│  ├─ POST   /oauth/begin-auth          → PKCE S256 yetkilendirme isteği oluştur
│  ├─ POST   /oauth/token               → Kod ile JWT access token değiştir
│  ├─ POST   /oauth/introspect          → Token geçerlilik kontrolü
│  ├─ GET    /oauth/jwks.json           → Public key seti (JWKS)
│  └─ GET    /oauth/transparency        → Token şeffaflık günlüğü
│
├─ 🎲 Cryptographic RNG
│  └─ GET    /random/number             → HKDF + Mathematical Mixing (parametric range)
│                                          └─ Query: ?min=X&max=Y (defaults: 0-100)
│                                          └─ χ² = 101.18 ≈ 100.0 (4M samples tested)
│
├─ 📹 SFU Integration (E2EE Key Management)
│  ├─ POST   /sfu/context               → Yeni E2EE session oluştur
│  │                                       └─ Input: room_id, participant, enable_e2ee
│  │                                       └─ Output: context_id, session_id, key, nonce
│  └─ POST   /sfu/context/step          → Ratchet anahtarını ilerlet
│                                          └─ Input: context_id
│                                          └─ Output: message_no, key, nonce (rotated)
│
├─ 📱 MDM (Mobile Device Management)
│  ├─ POST   /mdm/register              → Cihaz kaydı + Politika + Sertifika planı
│  │                                       └─ Input: device_id, owner, platform
│  │                                       └─ Output: DeviceRecord + Policy + CertPlan
│  ├─ GET    /mdm/policy/{platform}     → Platform bazlı politika dokümanı
│  │                                       └─ Platforms: ios, android, windows, macos, linux
│  └─ GET    /mdm/cert-plan/{device_id} → Cihaza özel sertifika dağıtım planı
│
├─ 🔍 Transparency & Audit
│  └─ GET    /transparency/tree         → Merkle tree şeffaflık kaydı
│                                          └─ Key publications, token issuance history
│
├─ 📊 Monitoring & Health
│  ├─ GET    /health                    → Sağlık durumu kontrolü
│  └─ GET    /metrics                   → Prometheus format metrikler
│                                          ├─ aunsorm_pending_auth_requests
│                                          ├─ aunsorm_active_tokens
│                                          ├─ aunsorm_sfu_contexts
│                                          └─ aunsorm_mdm_registered_devices
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

```bash
docker build -t aunsorm-server .
docker run --rm -p 8080:8080 \
  -e AUNSORM_JWT_SEED_B64="$(openssl rand -base64 32)" \
  -e AUNSORM_ISSUER="https://aunsorm.local" \
  -e AUNSORM_AUDIENCE="aunsorm-clients" \
  aunsorm-server
```

Konteyner varsayılan olarak `0.0.0.0:8080` adresinde dinler ve loglar `RUST_LOG=info` seviyesindedir.
