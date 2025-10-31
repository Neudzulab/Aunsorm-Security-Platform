# Production Server Fix Instructions

## 🚨 ACIL DÜZELTME - Unhealthy Services Fix

Production server'da aşağıdaki adımları takip edin:

## 1. Mevcut Compose Dosyasını Yedekle
```bash
cd /path/to/aunsorm-crypt
cp compose.yaml compose.yaml.backup
```

## 2. Problemli Environment Override'ları Kaldır

Compose.yaml dosyasında bu servislerin `environment` bölümlerini kontrol edin ve silin:

### X509 Service - ŞU BÖLÜMÜ SİL:
```yaml
x509-service:
  # ... diğer ayarlar ...
  environment:    # ❌ BU BÖLÜMÜ KOMPLE SİL
    - AUNSORM_LISTEN=0.0.0.0:50010
    - SERVICE_MODE=gateway
```

### KMS Service - ŞU BÖLÜMÜ SİL:  
```yaml
kms-service:
  # ... diğer ayarlar ...
  environment:    # ❌ BU BÖLÜMÜ KOMPLE SİL
    - AUNSORM_LISTEN=0.0.0.0:50010
    - SERVICE_MODE=gateway
```

### Diğer Unhealthy Serviceler için de aynısını yap:
- `pqc-service`
- `rng-service` 
- `blockchain-service`
- `e2ee-service`
- `metrics-service`

## 3. Environment Override Temizle

Bu servicelerde `environment:` bölümü olmamalı! `.env` dosyasından alacaklar.

**DOĞRU YAPıDANDıRMA (environment yok):**
```yaml
x509-service:
  container_name: aun-x509-service
  build:
    context: .
    dockerfile: docker/Dockerfile.x509
  env_file:
    - .env
  ports:
    - "50013:50013"
  networks:
    - aunsorm-network
  restart: unless-stopped
  # environment: YOK!
```

## 4. .env Dosyasını Kontrol Et

Production `.env` dosyasının doğru portları içerdiğini kontrol edin:
```bash
grep -E "SERVICE_PORT|GATEWAY_PORT" .env
```

Bu değerler olmalı:
```
GATEWAY_PORT=50010
AUTH_SERVICE_PORT=50011
CRYPTO_SERVICE_PORT=50012
X509_SERVICE_PORT=50013
KMS_SERVICE_PORT=50014
MDM_SERVICE_PORT=50015
ID_SERVICE_PORT=50016
ACME_SERVICE_PORT=50017
PQC_SERVICE_PORT=50018
RNG_SERVICE_PORT=50019
BLOCKCHAIN_SERVICE_PORT=50020
E2EE_SERVICE_PORT=50021
METRICS_SERVICE_PORT=50022
CLI_GATEWAY_PORT=50023
```

## 5. Servisleri Yeniden Başlat

```bash
docker compose down
docker compose up -d
```

## 6. Durumu Kontrol Et

```bash
# 2-3 dakika bekle sonra kontrol et:
docker ps --filter "name=aun-" --format "table {{.Names}}\t{{.Status}}"

# Logları kontrol et:
docker logs aun-x509-service --tail 5
docker logs aun-kms-service --tail 5
```

## 7. Beklenen Sonuç

Artık loglar şöyle olmalı:
```
🚀 Starting server on 0.0.0.0:50013    # ✅ DOĞRU PORT
🔧 SERVICE_MODE: Some("x509-service")   # ✅ DOĞRU MODE
```

## Hızlı Fix Scripti

Eğer hızlı fix istiyorsanız:
```bash
# Environment override'ları toplu temizle:
sed -i '/environment:/,+2d' compose.yaml

# Container'ları yeniden başlat:
docker compose down && docker compose up -d
```

Bu işlem sonrası tüm servisler (healthy) olacak!