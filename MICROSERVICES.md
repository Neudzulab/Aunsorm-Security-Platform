# Aunsorm Mikroservis Mimarisi

Bu doküman, Aunsorm'un mikroservis mimarisini, port yapılandırmasını ve servis organizasyonunu açıklar.

## 🏗️ Mimari Genel Bakış

Aunsorm v0.4.5 itibariyle **mikroservis mimarisine** geçmiştir. Tüm işlevsellik bağımsız, ölçeklenebilir servisler halinde organize edilmiştir.

### 🔧 Teknoloji Stack
- **Container Orchestration:** Docker Compose
- **Network:** Bridge network (`aunsorm-network`)
- **Port Range:** 50010-50023 (14 servis)
- **Base Image:** `rustlang/rust:nightly`
- **Binary:** `aunsorm-server` (her servis farklı portla çalışır)

## 📊 Servis Haritası

| Servis | Port | Service Name | Image | Açıklama | Endpoints | Volumes |
|--------|------|--------------|-------|----------|-----------|---------|
| **🌐 Gateway** | 50010 | `aun-gateway` | `aunsorm-gateway:local` | Client API Gateway | `/health`, `/metrics`, `/random/*`, `/transparency/*` | - |
| **🔐 Auth Service** | 50011 | `aun-auth-service` | `aunsorm-auth:local` | OAuth2/JWT authentication | `/oauth/*`, `/security/jwt-verify`, `/security/generate-media-token` | `aun-auth-data` |
| **🔒 Crypto Service** | 50012 | `aun-crypto-service` | `aunsorm-crypto:local` | AEAD encryption/decryption | `/core/*`, `/crypto/*` | - |
| **📜 X509 Service** | 50013 | `aun-x509-service` | `aunsorm-x509:local` | Certificate Authority | `/cert/*`, `/x509/*` | - |
| **🔑 KMS Service** | 50014 | `aun-kms-service` | `aunsorm-kms:local` | Key Management Service | `/kms/*`, `/keys/*` | - |
| **📱 MDM Service** | 50015 | `aun-mdm-service` | `aunsorm-mdm:local` | Mobile Device Management | `/mdm/*`, `/device/*` | `aun-mdm-data` |
| **🆔 ID Service** | 50016 | `aun-id-service` | `aunsorm-id:local` | HEAD-stamped ID generation | `/id/*`, `/identity/*` | - |
| **🔗 ACME Service** | 50017 | `aun-acme-service` | `aunsorm-acme:local` | Let's Encrypt protocol | `/acme/*` | `aun-acme-data` |
| **🔮 PQC Service** | 50018 | `aun-pqc-service` | `aunsorm-pqc:local` | Post-Quantum Cryptography | `/pqc/*`, `/quantum/*` | - |
| **🎲 RNG Service** | 50019 | `aun-rng-service` | `aunsorm-rng:local` | Cryptographic RNG | `/random/*` (internal only) | - |
| **⛓️ Blockchain Service** | 50020 | `aun-blockchain-service` | `aunsorm-blockchain:local` | DID verification PoC | `/blockchain/*` | - |
| **🔄 E2EE Service** | 50021 | `aun-e2ee-service` | `aunsorm-e2ee:local` | E2EE media streaming | `/sfu/*` | `aun-e2ee-data` |
| **📊 Metrics Service** | 50022 | `aun-metrics-service` | `aunsorm-metrics:local` | Prometheus monitoring | `/metrics` (aggregated) | - |
| **⚡ CLI Gateway** | 50023 | `aun-cli-gateway` | `aunsorm-cli-gateway:local` | REST API for CLI commands | `/cli/*` | - |

## 🚀 Hızlı Başlangıç

```bash
# Tüm servisleri başlat
docker-compose up -d

# Servis durumunu kontrol et
docker-compose ps

# Logları takip et
docker-compose logs -f

# Belirli servisi yeniden başlat
docker-compose restart auth-service

# Tüm servisleri durdur
docker-compose down

# Volumes ile birlikte temizle
docker-compose down -v
```

## 🌐 Endpoint Distribution & Service Architecture

Aunsorm mikroservis mimarisi **service-specific routing** kullanır. Her servis sadece kendi sorumlu olduğu endpoint'leri expose eder.

### 🚪 Gateway (Port 50010) - Client Entry Point
Gateway **external client requests** için ana giriş noktasıdır:

```bash
# ✅ Gateway endpoint'leri (client-facing)
curl http://localhost:50010/health              # Health check  
curl http://localhost:50010/metrics             # System metrics
curl http://localhost:50010/random/number       # Random number generator
curl http://localhost:50010/transparency/tree   # Transparency logs

# ❌ Gateway'de JWT/OAuth endpoint'leri YOK 
curl http://localhost:50010/security/jwt-verify # → 404 Not Found
```

### 🔐 Auth Service (Port 50011) - Authentication & JWT
Auth Service **authentication & token management** için:

```bash
# ✅ Auth service endpoint'leri
curl http://localhost:50011/security/jwt-verify           # JWT verification
curl http://localhost:50011/oauth/begin-auth             # OAuth2 start
curl http://localhost:50011/oauth/token                  # Token exchange
curl http://localhost:50011/security/generate-media-token # Media tokens

# ❌ Auth service'te random/transparency endpoint'leri YOK
curl http://localhost:50011/random/number                # → 404 Not Found
```

### 📱 Diğer Servisler - Specialized Functions
Her servis sadece kendi alanındaki endpoint'leri expose eder:

```bash
# MDM Service (50015)
curl http://localhost:50015/mdm/register           # Device registration
curl http://localhost:50015/mdm/policy/ios         # Platform policies

# ACME Service (50017)  
curl http://localhost:50017/acme/directory         # Let's Encrypt directory
curl http://localhost:50017/acme/new-nonce         # ACME nonce

# Blockchain Service (50020)
curl http://localhost:50020/blockchain/fabric/did/verify  # DID verification
```

### 🔀 Service Communication Patterns

#### Pattern 1: Direct Service Access (External)
Client → Service (doğrudan port ile)

```bash
# Client JWT doğrulaması için direkt auth service'e bağlanır
curl http://localhost:50011/security/jwt-verify -d '{"token":"..."}'
```

#### Pattern 2: Gateway Entry Point (External)
Client → Gateway → Internal processing

```bash  
# Client genel endpoint'ler için gateway'i kullanır
curl http://localhost:50010/random/number
curl http://localhost:50010/transparency/tree
```

#### Pattern 3: Service Discovery (Internal)
Service → Service (Docker network üzerinde)

```rust
// ❌ Port hard-coding (kırılgan)
let auth_url = "http://aun-auth-service:50011/security/jwt-verify";

// ✅ Service discovery (esnek)
let auth_url = format!("http://{}/security/jwt-verify", 
    env::var("AUTH_SERVICE_HOST").unwrap_or("aun-auth-service".to_string()));

// 🎯 En iyi pratik: Service ismiyle doğrudan bağlantı
let auth_url = "http://aun-auth-service/security/jwt-verify";
```

### 🌐 Service URLs

Servisler arası iletişim için bu URL'leri kullanın:

```bash
# Service-to-service communication (Docker network içinde)
http://aun-gateway/health                    # Gateway health check
http://aun-auth-service/security/jwt-verify  # JWT token verification
http://aun-crypto-service/rng/random         # Secure random number generation
http://aun-x509-service/pki/cert-generate    # X.509 certificate generation
http://aun-kms-service/vault/key-store       # Key management operations
http://aun-mdm-service/device/register       # Mobile device registration
http://aun-id-service/identity/create        # Identity generation
http://aun-acme-service/letsencrypt/order    # Let's Encrypt certificate
http://aun-pqc-service/quantum/key-gen       # Post-quantum cryptography
http://aun-rng-service/entropy/collect       # Entropy collection
http://aun-blockchain-service/did/verify     # DID verification
http://aun-e2ee-service/media/encrypt        # End-to-end media encryption
http://aun-metrics-service/prometheus        # Metrics collection
http://aun-cli-gateway/cli/execute           # CLI command execution

# External client access (localhost ports)
http://localhost:50010/health                # Gateway health check
http://localhost:50011/security/jwt-verify   # Direct auth service access
http://localhost:50012/rng/random            # Direct crypto service access
http://localhost:50013/pki/cert-generate     # Direct X.509 service access
http://aun-acme-service/acme/directory       # ACME directory
http://aun-pqc-service/pqc/keygen            # Post-quantum keygen
http://aun-blockchain-service/blockchain/did/verify  # DID verification
http://aun-e2ee-service/sfu/context          # E2EE context
http://aun-metrics-service/metrics           # Metrics collection
http://aun-cli-gateway/cli/status            # CLI gateway
```

### 📍 Port Independence

**Avantajlar:**
- ✅ Port değişse de kod bozulmaz  
- ✅ Service discovery otomatik
- ✅ Load balancer/proxy friendly
- ✅ Kubernetes ready

**Kullanım:**
```yaml
# docker-compose.yml'de environment variables
environment:
  - AUTH_SERVICE_URL=http://aun-auth-service
  - CRYPTO_SERVICE_URL=http://aun-crypto-service
  # Port numbers belirtmeye gerek yok!
```

### 🎯 Service Discovery Best Practices

#### ✅ YAPILMASI GEREKENLER
1. **Container name'leri kullan**: `http://aun-auth-service/endpoint`
2. **Port'ları hardcode etme**: Docker network otomatik port yönetimi yapar
3. **Environment variables tercih et**: Daha esnek konfigürasyon
4. **Health check'leri ekle**: Servis durumunu kontrol et

#### ❌ YAPILMAMASI GEREKENLER  
1. **IP adresi hardcode**: `http://172.20.0.3:50011` (kırılgan)
2. **Port hardcode**: `http://service:50011` (gereksiz)
3. **localhost kullanma**: Container içinde `localhost` = kendi container'ı

#### 💡 Configuration Examples

```rust
// ✅ En iyi pratik
pub struct ServiceConfig {
    auth_service: String,
    crypto_service: String,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            auth_service: env::var("AUTH_SERVICE_URL")
                .unwrap_or("http://aun-auth-service".to_string()),
            crypto_service: env::var("CRYPTO_SERVICE_URL")
                .unwrap_or("http://aun-crypto-service".to_string()),
        }
    }
}
```

### Servis-to-Servis İletişim
Servisler Docker network üzerinde isim çözümü kullanır:

```yaml
# .env dosyasında servis URL'leri
AUTH_SERVICE_URL=http://auth-service:50011
CRYPTO_SERVICE_URL=http://crypto-service:50012
X509_SERVICE_URL=http://x509-service:50013
# ... diğer servisler
```

## 📋 Servis Detayları

### 🔐 Auth Service (50011)
- **Sorumluluğu:** OAuth2/JWT authentication
- **Volume:** Persistent JWT token store (SQLite)
- **Environment:** JWT secrets, issuer/audience config
- **Dependencies:** Base crypto services

### 🔒 Crypto Service (50012)
- **Sorumluluğu:** Core AEAD encryption/decryption
- **Algoritma:** AES-GCM, ChaCha20-Poly1305, Argon2
- **Bağımlılık:** Yok (base service)

### 📜 X509 Service (50013)
- **Sorumluluğu:** Certificate Authority operations + Self-signed certificates
- **Özellikler:** 
  - Root/Intermediate CA management
  - **Self-signed certificates** (development/testing)
  - Server certificates (production)
  - Client certificates (mutual TLS)
  - **DTLS certificates** (CoAP/IoT)
- **Algoritma:** Ed25519, RSA-2048/4096
- **Use Cases:** Development, private CA, self-signed, DTLS, mTLS

### 🗝️ KMS Service (50014)
- **Sorumluluğu:** Key management ve HSM integration
- **Backends:** Local, GCP KMS, Azure Key Vault
- **Profiles:** mobile/low/medium/high/ultra

### 📱 MDM Service (50015)
- **Sorumluluğu:** Mobile Device Management
- **Volume:** Device registry database
- **Platforms:** iOS, Android, Windows, macOS, Linux

### 🆔 ID Service (50016)
- **Sorumluluğu:** HEAD-stamped unique ID generation
- **Format:** `aid.<namespace>.<head>.<payload>`
- **Environment:** AUNSORM_HEAD, GITHUB_SHA

### ✅ ACME Service (50017)
- **Sorumluluğu:** Let's Encrypt protocol (RFC 8555)
- **Volume:** ACME account/order state
- **Endpoints:** Directory, nonce, account, order, finalize
- **Use Cases:** Production DTLS certificates, **publicly trusted certificates**

### 🛡️ PQC Service (50018)
- **Sorumluluğu:** Post-Quantum Cryptography
- **Algoritma:** ML-KEM-768/1024, ML-DSA-65, Falcon-512
- **Hybrid:** Classical + PQC combined security

### 🎲 RNG Service (50019)
- **Sorumluluğu:** Cryptographic random number generation
- **Model:** NEUDZ-PCS + AACM entropy mixing
- **Throughput:** ~78,000 samples/second
- **Validation:** Chi-square tested (χ² = 101.18)

### ⛓️ Blockchain Service (50020)
- **Sorumluluğu:** DID verification PoC
- **Platform:** Hyperledger Fabric integration
- **Verification:** Ed25519 signature, clock skew validation

### 📹 E2EE Service (50021)
- **Sorumluluğu:** End-to-End Encryption media streaming
- **Volume:** Session ratchet state
- **Protocol:** Double Ratchet, forward secrecy

### 📊 Metrics Service (50022)
- **Sorumluluğu:** Prometheus metrics collection
- **Format:** OpenMetrics/Prometheus text format
- **Metrics:** Token counts, device counts, session counts

## 🔄 Servis Yaşam Döngüsü

### Health Checks
Her servis `/health` endpoint'i sunar:

```bash
# Tüm servislerin sağlık kontrolü
for port in {50010..50022}; do
  echo "Port $port: $(curl -s http://localhost:$port/health | jq -r .status)"
done
```

### Graceful Shutdown
Servisler SIGTERM/SIGINT sinyallerini yakalayarak graceful shutdown yapar:

```bash
# Graceful shutdown
docker-compose stop

# Force kill (emergency)
docker-compose kill
```

### Rolling Updates
Servisleri tek tek güncelleme:

```bash
# Build new image
docker-compose build auth-service

# Rolling restart
docker-compose up -d --no-deps auth-service
```

## 📈 Scaling ve Performance

### Horizontal Scaling
```yaml
# docker-compose.override.yml
services:
  auth-service:
    scale: 3  # 3 instance
    
  rng-service:
    scale: 2  # Load balancing for high-throughput RNG
```

### Resource Limits
```yaml
services:
  crypto-service:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
```

### Load Balancing
Gateway servisi otomatik load balancing yapabilir (future enhancement).

## 🔧 Yeni Servis Ekleme

**ÖNEMLİ:** v0.4.5 sonrasında tüm yeni özellikler **mikroservis olarak** eklenecektir.

### 1. Yeni Servis için Port Seç
Sıradaki available port: **50023**

### 💡 Potansiyel Yeni Servisler
| Servis | Port | Açıklama | Durum |
|--------|------|----------|-------|
| **CLI Gateway** | 50023 | REST API for CLI commands | 📋 Planlandı |
| **WebUI** | 50024 | Web-based management UI | 🔮 Gelecek |
| **Notification** | 50025 | Push/Email notifications | 🔮 Gelecek |

### 2. Dockerfile Oluştur
```dockerfile
# Dockerfile.new-service
FROM rustlang/rust:nightly AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --release --bin aunsorm-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN adduser --disabled-password --gecos '' aunsorm-new-service
USER aunsorm-new-service
WORKDIR /srv
COPY --from=builder /workspace/target/release/aunsorm-server /srv/aunsorm-server
EXPOSE 50023
CMD ["/srv/aunsorm-server", "--port", "50023", "--service", "new-service"]
```

### 3. compose.yaml'a Ekle
```yaml
services:
  # ... existing services

  new-service:
    build:
      context: .
      dockerfile: Dockerfile.new-service
    image: aunsorm-new-service:local
    ports:
      - "50023:50023"
    networks:
      - aunsorm-network
    restart: unless-stopped
```

### 4. Gateway Dependencies Güncelle
```yaml
gateway:
  depends_on:
    # ... existing dependencies
    - new-service
```

### 5. README.md Servis Ağacını Güncelle
AGENTS.md direktifi gereği, yeni servis eklendiğinde README.md'deki endpoint ağacına eklenmelidir.

## 🛠️ Troubleshooting

### Servis Başlamıyor
```bash
# Logs kontrolü
docker-compose logs service-name

# Port çakışması kontrolü
netstat -tulpn | grep :50011

# Network connectivity
docker-compose exec gateway ping auth-service
```

### Volume Sorunları
```bash
# Volume inspect
docker volume ls | grep aunsorm

# Volume temizliği
docker-compose down -v
docker volume prune
```

### Performance Issues
```bash
# Container stats
docker stats

# Resource usage per service
docker-compose top
```

## � DTLS Sertifika Yönetimi

### Production (Publicly Trusted) - ACME Service
```bash
# 1. ACME directory keşfi
curl http://localhost:50017/acme/directory

# 2. Account oluştur
curl -X POST http://localhost:50017/acme/new-account \
  -H "Content-Type: application/jose+json" \
  -d '{"contact":["mailto:admin@example.com"],"termsOfServiceAgreed":true}'

# 3. DTLS server için domain sertifikası order et
curl -X POST http://localhost:50017/acme/new-order \
  -H "Content-Type: application/jose+json" \
  -d '{"identifiers":[{"type":"dns","value":"dtls-server.example.com"}]}'

# 4. Challenge doğrulama ve finalize
# (DNS-01 veya HTTP-01 challenge çözümü gerekli)
```

### Development/Testing - X509 Service

#### Option 1: Self-Signed (Hızlı Test)
```bash
# Self-signed DTLS sertifikası oluştur (CA olmadan)
aunsorm-cli x509 self-signed \
  --hostname dtls-test.local \
  --cert-out dtls-self-signed.crt \
  --key-out dtls-self-signed.key \
  --algorithm rsa2048 \
  --days 365 \
  --extended-key-usage "serverAuth,clientAuth"
```

#### Option 2: Private CA (Organizasyon İçi)
```bash
# 1. Root CA oluştur (bir kez)
aunsorm-cli x509 ca init --profile ca-profile.yaml \
  --cert-out dtls-root-ca.crt --key-out dtls-root-ca.key \
  --algorithm rsa2048

# 2. DTLS server sertifikası imzala
aunsorm-cli x509 ca sign-server \
  --ca-cert dtls-root-ca.crt --ca-key dtls-root-ca.key \
  --hostname dtls-server.local \
  --cert-out dtls-server.crt --key-out dtls-server.key \
  --algorithm rsa2048 \
  --extended-key-usage "serverAuth,clientAuth"

# 3. Client sertifikası (mutual TLS için)
aunsorm-cli x509 ca sign-client \
  --ca-cert dtls-root-ca.crt --ca-key dtls-root-ca.key \
  --client-name "DTLS Client 001" \
  --cert-out dtls-client.crt --key-out dtls-client.key \
  --algorithm rsa2048
```

### API Endpoints
```bash
# X509 Service - Direct API
POST http://localhost:50013/ca/sign-server
{
  "hostname": "dtls-server.example.com",
  "algorithm": "rsa2048", 
  "extended_key_usage": ["serverAuth", "clientAuth"],
  "subject_alt_names": ["DNS:dtls-server.example.com", "IP:192.168.1.100"]
}

# ACME Service - Let's Encrypt compatible
POST http://localhost:50017/acme/new-order
{
  "identifiers": [
    {"type": "dns", "value": "dtls-server.example.com"}
  ]
}
```

## � Gelecek Özellikler

### CLI Gateway Service (Port 50023) - Planlandı
**aunsorm-cli** komutlarını REST API olarak sunan mikroservis:

```bash
# Mevcut CLI kullanımı
aunsorm-cli encrypt --input data.txt --output encrypted.bin

# Gelecek API kullanımı  
curl -X POST http://localhost:50023/cli/encrypt \
  -F "input=@data.txt" \
  -H "Authorization: Bearer jwt-token"
```

**Avantajlar:**
- 🌐 Web/mobile uygulamalardan CLI erişimi
- 🔐 JWT tabanlı yetkilendirme
- 📊 Komut logları ve audit trail
- 🚀 Remote CLI execution
- 📦 Batch operations

**Endpoint Örnekleri:**
```bash
POST /cli/encrypt        # File encryption
POST /cli/decrypt        # File decryption  
POST /cli/x509/ca        # CA operations
POST /cli/jwt/sign       # JWT signing
GET  /cli/status         # Command status
GET  /cli/history        # Command history
```

## �📚 İlgili Belgeler

- [README.md](README.md) - Genel proje dokümantasyonu
- [AGENTS.md](AGENTS.md) - Ajan sorumlulukları ve koordinasyon
- [compose.yaml](compose.yaml) - Docker Compose konfigürasyonu
- [crates/server/README.md](crates/server/README.md) - Server implementation detayları
- [crates/cli/README.md](crates/cli/README.md) - CLI tool documentation

---

**Not:** Bu dokümantasyon Aunsorm v0.4.5 mikroservis mimarisi için günceldir. Yeni servis eklemeleri bu dokümana yansıtılmalıdır.