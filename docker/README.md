# Modular Docker Compose Stacks

Aunsorm servislerini kullanım amacına göre ayrı ayrı başlatmak için aşağıdaki compose dosyalarını kullanın.

## Stack Seçenekleri

- `docker/compose.auth-stack.yaml`
  - Yalnızca kimlik doğrulama akışı: `auth-service`
  - Zorunlu temel servis: `rng-service`
- `docker/compose.identity-stack.yaml`
  - Kimlik ve sertifika yaşam döngüsü: `auth-service`, `x509-service`, `kms-service`, `mdm-service`, `id-service`, `acme-service`
  - Zorunlu temel servis: `rng-service`
- `docker/compose.crypto-stack.yaml`
  - Kripto + PQC işlemleri: `crypto-service`, `pqc-service`
  - Zorunlu temel servis: `rng-service`

## Çalıştırma

```bash
# Sadece auth + zorunlu RNG
HOST=<HOST> docker compose -f docker/compose.auth-stack.yaml up --build

# Identity odaklı kurulum
HOST=<HOST> docker compose -f docker/compose.identity-stack.yaml up --build

# Crypto/PQC odaklı kurulum
HOST=<HOST> docker compose -f docker/compose.crypto-stack.yaml up --build
```

Tam platform kurulumu için kökteki `compose.yaml` dosyasını kullanmaya devam edin.
