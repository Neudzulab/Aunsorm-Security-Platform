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

| Servis | Port | Dockerfile | Image | Açıklama | Volumes |
|--------|------|------------|-------|----------|---------|
| **Gateway** | 50010 | `Dockerfile.gateway` | `aunsorm-gateway:local` | API Gateway ve routing | - |
| **Auth** | 50011 | `Dockerfile.auth` | `aunsorm-auth:local` | OAuth2/JWT authentication | `aunsorm-auth-data` |
| **Crypto** | 50012 | `Dockerfile.crypto` | `aunsorm-crypto:local` | AEAD encryption/decryption | - |
| **X509** | 50013 | `Dockerfile.x509` | `aunsorm-x509:local` | Certificate Authority + Self-signed | - |
| **KMS** | 50014 | `Dockerfile.kms` | `aunsorm-kms:local` | Key Management Service | - |
| **MDM** | 50015 | `Dockerfile.mdm` | `aunsorm-mdm:local` | Mobile Device Management | `aunsorm-mdm-data` |
| **ID** | 50016 | `Dockerfile.id` | `aunsorm-id:local` | HEAD-stamped ID generation | - |
| **ACME** | 50017 | `Dockerfile.acme` | `aunsorm-acme:local` | Let's Encrypt protocol | `aunsorm-acme-data` |
| **PQC** | 50018 | `Dockerfile.pqc` | `aunsorm-pqc:local` | Post-Quantum Cryptography | - |
| **RNG** | 50019 | `Dockerfile.rng` | `aunsorm-rng:local` | Cryptographic RNG | - |
| **Blockchain** | 50020 | `Dockerfile.blockchain` | `aunsorm-blockchain:local` | DID verification PoC | - |
| **E2EE** | 50021 | `Dockerfile.e2ee` | `aunsorm-e2ee:local` | E2EE media streaming | `aunsorm-e2ee-data` |
| **Metrics** | 50022 | `Dockerfile.metrics` | `aunsorm-metrics:local` | Prometheus monitoring | - |
| **CLI Gateway** | 50023 | `Dockerfile.cli-gateway` | `aunsorm-cli-gateway:local` | REST API for CLI commands | - |

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

## 🌐 Servis Keşfi

### API Gateway (Port 50010)
Gateway servisi tüm diğer servislere reverse proxy görevi görür:

```bash
# Health check
curl http://localhost:50010/health

# Gateway üzerinden auth servisi
curl http://localhost:50010/oauth/jwks.json

# Direkt auth servisine erişim
curl http://localhost:50011/oauth/jwks.json
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