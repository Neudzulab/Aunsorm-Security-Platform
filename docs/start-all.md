# start-all.ps1 

Aunsorm Microservices için otomatik build ve başlatma scripti.

## Kullanım

```powershell
.\start-all.ps1 [SEÇENEKLER]
```

## Seçenekler

| Seçenek | Açıklama |
|---------|----------|
| `-Force` | Mevcut image'lar olsa bile zorla yeniden build et |
| `-Logs` | Servisleri başlattıktan sonra logları canlı göster |  
| `-Help` | Yardım menüsünü göster |

## Örnekler

```powershell
# Akıllı başlatma - sadece eksik image'ları build eder
.\start-all.ps1

# Zorla tüm servisleri yeniden build et ve başlat
.\start-all.ps1 -Force

# Başlat ve logları göster
.\start-all.ps1 -Logs

# Yardım menüsü
.\start-all.ps1 -Help
```

## İşlevler

### 🔍 Akıllı Build Kontrol
- Mevcut Docker image'leri kontrol eder
- Sadece eksik olanları build eder
- `-Force` ile tümünü yeniden build eder

### 🚀 Otomatik Başlatma
- 13 mikroservisi sırayla başlatır
- Health check'leri bekler
- Servis durumlarını raporlar

### 📊 Durum Raporlama
- Renkli terminal çıktısı
- Servis durumu tablosu
- Gateway endpoint bilgisi

## Servisler

Script aşağıdaki servisleri yönetir:

| Servis | Image | Port |
|--------|-------|------|
| Gateway | aunsorm-gateway:local | 50010 |
| Auth | aunsorm-auth:local | 50011 |
| Crypto | aunsorm-crypto:local | 50012 |
| X509 | aunsorm-x509:local | 50013 |
| KMS | aunsorm-kms:local | 50014 |
| MDM | aunsorm-mdm:local | 50015 |
| ID | aunsorm-id:local | 50016 |
| ACME | aunsorm-acme:local | 50017 |
| PQC | aunsorm-pqc:local | 50018 |
| RNG | aunsorm-rng:local | 50019 |
| Blockchain | aunsorm-blockchain:local | 50020 |
| E2EE | aunsorm-e2ee:local | 50021 |
| Metrics | aunsorm-metrics:local | 50022 |

## Gereksinimler

- Docker Desktop çalışır durumda
- PowerShell 5.1+ veya PowerShell Core 7+
- `docker-compose.yml` mevcut dizinde

## Sorun Giderme

**Docker çalışmıyor:**
```
[ERROR] Docker is not running. Please start Docker Desktop first.
```
➜ Docker Desktop'ı başlatın

**Build hatası:**
```
[ERROR] Failed to build service-name
```
➜ `docker-compose build service-name` ile manuel kontrol edin

**Port çakışması:**
```
ERROR: for gateway Cannot start service...bind: address already in use
```
➜ `docker-compose down` ile eski servisleri durdurun