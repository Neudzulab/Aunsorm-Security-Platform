# Operasyon Runbook'u: Felaket Kurtarma

*Revizyon: 2025-10-25*

Bu runbook, Aunsorm platformunun herhangi bir bölgede yaşanan kalıcı hizmet
kaybı veya veri bütünlüğü ihlali durumunda en fazla 45 dakikalık kurtarma
süresi (RTO) ve 5 dakikalık veri kaybı penceresi (RPO) hedefleriyle ayağa
kaldırılmasını tanımlar. Prosedür, Docker Compose tabanlı üretim kümeleri ile
aynı yapılandırmayı paylaşan Kubernetes dağıtımları için de referans
alınabilecek şekilde hazırlanmıştır.

## Kapsam ve Ön Koşullar

- Plan `prod-primary` (Frankfurt) ve `prod-dr` (Dublin) bölgeleri için geçerlidir;
  `port-map.yaml` içindeki port tahsisi ve Compose servis isimleri her iki
  bölgede de aynıdır.
- Günlük artımlı ve haftalık tam yedekler `s3://aunsorm-backups/<env>/`
  dizininde tutulur. Yedekler, `aunsorm-auth-data`, `aunsorm-mdm-data`,
  `aunsorm-acme-data` ve `aunsorm-e2ee-data` Docker volume'larını kapsar.
- `AUNSORM_JTI_DB` SQLite veritabanı `.env` dosyasında belirtilen yol ile
  `auth-service` konteynerine bind edilir; bu yolun da yedeklenmesi zorunludur.
- `SecureClockSnapshot` değerleri `config/clock/` altında saklanır ve her yayın
  sonrası `git` ile versiyonlanır. Restore sırasında aynı sürüm kullanılmalıdır.

## Roller ve Sorumluluklar

| Rol | Görev | Temas Kanalı |
| --- | ----- | ------------- |
| **Platform On-Call** | Kurtarma sürecini yürütür, Compose dağıtımını yönetir | `#ops-oncall` Slack, PagerDuty `P0` |
| **Security On-Call** | Anahtar materyali ve HSM erişim kontrollerini doğrular, `AUNSORM_STRICT` politika takibini yapar | `#sec-incident` Slack |
| **Compliance Liaison** | Veri kaybı raporlaması, SOC2/GDPR bildirim akışını başlatır | `compliance@aunsorm.dev` |
| **Database Specialist** | Yedek dosyalarının bütünlüğünü doğrular, `sqlite3` kontrol komutlarını çalıştırır | `#db-ops` Slack |

## Hazırlık Kontrolleri (Her Gün 08:00 UTC)

1. **Yedek doğrulama:**
   ```bash
   aws s3 ls s3://aunsorm-backups/prod-primary/daily/$(date -d 'yesterday' +%F)/
   aws s3 ls s3://aunsorm-backups/prod-primary/full/$(date -d 'last sunday' +%F)/
   ```
   Beklenen dosyalar:
   - `auth-service.sqlite.gz`
   - `mdm-ledger.tar.zst`
   - `acme-accounts.tar.zst`
   - `e2ee-sessions.tar.zst`
   - `tokens.db.zst`

2. **Restore spot-check (haftalık):** Yedeklerden rastgele bir set indirip
   `/tmp/dr-restore` dizinine açın. `sqlite3 tokens.db 'PRAGMA integrity_check;'`
   komutunun `ok` döndürdüğünü ve arşivlerin `tar -tzf`/`unzstd --test`
   komutlarıyla doğrulandığını kaydedin.

3. **Clock snapshot doğrulaması:** `config/clock/prod-primary.json` ile
   `config/clock/prod-dr.json` dosyalarının SHA-256 özetlerini `sha256sum`
   komutu ile karşılaştırın; sapma varsa Security ekibi bilgilendirilir.

4. **RTO tatbikatı (aylık):** `COMPOSE_PROJECT_NAME=aunsorm-drill docker compose up -d`
   komutu ile yedek bölgedeki servisleri test amaçlı ayağa kaldırın. `gateway`
   servisine `/healthz` isteği göndererek 45 dakikanın altında yanıt alındığını
   doğrulayın; süreyi `runbook-retention.md` altına kayıt edin.

## Tetikleyici Sinyaller

- **PagerDuty `Aunsorm-Prod-Down`** alarmı tetiklendiğinde plan devreye girer.
- `gateway` servisinden 5 dakikadan uzun süren 5xx fırtınası.
- `metrics-service` üzerinden alınan `clock_attestation_stale` metriği kritik
  seviyeye ulaştığında (>=30 saniye sapma).
- `blockchain-service` Fabric ağından ayrılmış ve yeniden bağlanamıyorsa.

## Kurtarma Adımları

### 1. Olayı Değerlendirme

1. PagerDuty çağrısını kabul edin, Zoom köprüsünü başlatın.
2. `docker compose -f compose.yaml -p aunsorm ps` komutuyla etkilenen
   konteynerleri doğrulayın.
3. Eğer Kubernetes üzerinde çalışılıyorsa, platform ekibi `kubectl get pods`
   çıktısını sağlar ve `CrashLoopBackOff` / `Terminating` durumlarını raporlar.
4. `ops` olayı için açılan Confluence şablonunda T+0 zamanını kaydedin.

### 2. Yedekleri Hazırlama

1. `aws s3 sync s3://aunsorm-backups/prod-primary/latest /srv/dr-restore`
   komutunu çalıştırın.
2. `sha256sum -c checksums.txt` ile yedek bütünlüğünü doğrulayın.
3. `sqlite3 /srv/dr-restore/tokens.db --cmd "PRAGMA integrity_check;"` çıktısının
   `ok` olduğunu teyit edin.
4. `tar --use-compress-program=unzstd -xf mdm-ledger.tar.zst -C /srv/dr-restore/mdm`
   gibi arşivleri açın; aynı işlemi diğer hizmet verileri için tekrarlayın.

### 3. DR Bölgesinde Servisleri Ayağa Kaldırma

1. `COMPOSE_PROJECT_NAME=aunsorm-dr` olarak ayarlayın ve DR ortamına özel `.env.dr`
   dosyasını (`cp .env .env.dr && vi .env.dr`) güncelleyin; `AUNSORM_HOST`,
   `AUNSORM_JTI_DB` ve DNS kayıtları yeni bölgeyi göstermelidir.
2. `docker compose --project-name aunsorm-dr down` ile varsa başarısız dağıtımı
   temizleyin.
3. Her volume için restore:
   ```bash
   docker run --rm -v aunsorm-auth-data:/data -v /srv/dr-restore/auth:/restore \
     alpine sh -c 'rm -rf /data/* && cp -a /restore/. /data/'
   ```
   Aynı işlemi `aunsorm-mdm-data`, `aunsorm-acme-data` ve `aunsorm-e2ee-data`
   için uygulayın.
4. `AUNSORM_JTI_DB` yolunu `.env.dr` içinde doğrulayın ve dosyayı hedef ortama
   kopyalayın (`scp .env.dr ops@dr-gateway:/opt/aunsorm/.env`).
5. `docker compose --project-name aunsorm-dr up -d gateway auth-service \
   crypto-service x509-service kms-service mdm-service id-service \
   acme-service pqc-service rng-service blockchain-service e2ee-service \
   metrics-service cli-gateway` komutunu çalıştırın.
6. Kubernetes dağıtımları için platform ekibi `production-debug.md` dokümanındaki
   konteyner ve ağ kontrollerini referans alarak iç Kubernetes failover SOP'sini
   yürütür ve StatefulSet pod'larının `Ready` durumuna döndüğünü onaylar.

### 4. Sistem Doğrulama

1. `scripts/interop-sanity.sh --profile dr` komutunu çalıştırın; tüm testlerin
   yeşil olduğundan emin olun.
2. `curl -f https://gateway.dr.aunsorm.dev/healthz` isteği 200 döndürmelidir.
3. `aunsorm-cli validate-endpoints --profile dr` komutu ile güvenlik uçları
   kontrol edilir; rapor `docs/src/operations/runbook-retention.md` dosyasına
   eklenir.
4. `POST /security/jwt-verify` ve `POST /acme/new-order` uçları manuel olarak
   test edilir, sonuçlar incident dokümanına eklenir.
5. `clock_attestation_stale` metriği `metrics-service` Prometheus endpoint'inde
   0 değerine dönmelidir.

### 5. İstemci Bildirimleri ve Failover Tamamlama

1. DNS `gateway.aunsorm.dev` kaydı `prod-dr` yük dengeleyicisine yönlendirilir.
2. `status.aunsorm.dev` üzerinde durum güncellemesi yapılır.
3. Compliance ekibi GDPR/SOC2 raporlama gereksinimlerini tetikler.
4. Olay tamamlandıktan sonra T+45 içinde postmortem için taslak başlatılır.

## Failback Prosedürü (Primary Restore Olduğunda)

1. Primary bölgedeki altyapı onarıldığında aynı yedekleme adımlarıyla veri
   geri yüklenir ve `prod-primary` tekrar çevrimiçi getirilir.
2. `gateway` DNS kaydı tekrar primary bölgeye alınır ve 15 dakikalık paralel
   sağlık kontrolleri yapılır.
3. `prod-dr` ortamında kalan iş yükleri `docker compose --project-name aunsorm-dr down`
   ile kapatılır, volume'lar `aws s3 sync /srv/dr-restore s3://aunsorm-backups/prod-dr/archive/$(date +%F)`
   komutu ile arşivlenir.
4. Postmortem toplantısı tamamlanana kadar DR ortamı `readiness` modunda
   tutulur, bekleyen işlemler `ops` ticket'ında kapanır.

## Kayıt ve Raporlama

- Her olay için `runbook-retention.md` dosyasında yeni bir kayıt açılır ve
  RTO/RPO gerçekleşme değerleri eklenir.
- `PROD_PLAN.md` içindeki `Backup & Disaster Recovery` maddeleri ilgili ilerleme
  ile güncellenir.
- Olay sonrası 72 saat içerisinde `certifications/` altındaki uygun rapor
  şablonu (`soc2/incident-report.md`) güncellenir.

## Referanslar

- [Clock Attestation Sunucu Runbook'u](clock-attestation-deployment.md)
- [Regülasyon Uyumluluk Kontrol Listesi](compliance-checklist.md)
- [Operasyon Runbook'u: Müşteri Saklama & Anahtar İmha](runbook-retention.md)
