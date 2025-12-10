# Production Deployment Guide

*Revizyon: 2025-11-05*

Bu rehber, Aunsorm platformunun üretim ortamında güvenli ve tekrar
üretilebilir şekilde devreye alınması için takip edilmesi gereken
zorunlu adımları tanımlar. Adımlar, `compose.yaml` tabanlı dağıtımlar ile
Kubernetes kümeleri için aynı doğrulama hatlarını paylaşacak şekilde
hazırlanmıştır.

## Kapsam ve Varsayımlar

- `main` dalındaki `Cargo.lock` ve `package-lock.json` sürümleri değişmeden
  kullanılmalıdır; farklı versiyon kullanımı yasaktır.
- Port tahsisi `port-map.yaml` dosyası ile uyumlu olmalı ve yeni portlar
  eklenecekse bu dosya güncellenmelidir.
- Tüm kriptografik rastgelelik `AunsormNativeRng` üzerinden sağlanır;
  komut veya kod tarafında `OsRng` veya HTTP tabanlı RNG çağrıları
  kesinlikle devre dışıdır.
- Yapılandırma değerleri dosyaya gömülmez; ortam değişkenleri kullanılır
  ve `HOST`, `ZASIAN_HOST`, `ZASIAN_WEBSOCKET_URL`, `BRIDGE_URL` gibi
  alanlar üretim domainlerine işaret eder.
- `AUNSORM_STRICT=1` ve `AUNSORM_CLOCK_MAX_AGE_SECS=30` değişkenleri
  devreye alınmadan önce ayarlanmalıdır.

## Ön Hazırlık Kontrol Listesi

1. **Kimlik ve gizli anahtarlar**
   - `config/clock/*.json` dosyalarının SHA-256 özetlerini üretim ve DR
     bölgeleri arasında karşılaştırın.
   - HSM erişim bilgileri ve JWT imzalama anahtarları yalnızca
     `age`/`sops` ile şifreli depolanmalı; düz metin dosyalar yasak.
2. **Görüntü ve artefakt seti**
   - `docker buildx bake --set *.platform=linux/amd64 --push` komutuyla
     imajları registry'ye gönderin.
   - `scripts/pkg-check.sh` çıktısında uyarı veya kullanım dışı
     bağımlılık olmadığından emin olun.
3. **Veri düzlemi**
   - PostgreSQL hedefleniyorsa migration betikleri (`scripts/migrate.sh`)
     production DSN ile çalıştırılmalı; SQLite yalnızca geliştirme için
     kullanılabilir.
   - `AUNSORM_JTI_DB` konumu tmpfs üzerinde olmalı ve yedeklemeye dahil
     edilmelidir.
4. **Ağ ve sertifika hazırlığı**
   - `compose.yaml` içindeki host adları için DNS kayıtları oluşturulmalı
     ve TLS sertifikaları `config/tls/` altında depolanmalıdır.
   - WAF/Rate limiting kuralları gateway önünde aktif olmalıdır.

## Dağıtım Yolları

### Docker Compose (Kontrol Listesi)

1. Üretim ortamına özel `.env.prod` dosyasını hazırlayın:
   ```bash
   cp .env .env.prod
   export $(grep -v '^#' .env.prod | xargs)
   ```
   `HOST`, `ZASIAN_HOST`, `AUNSORM_STRICT`, `AUNSORM_CLOCK_MAX_AGE_SECS`
   ve `AUNSORM_JTI_DB` değerlerini üretim hedeflerine göre güncelleyin.
2. `COMPOSE_PROJECT_NAME=aunsorm-prod docker compose pull` ile en güncel
   imajların çekildiğini doğrulayın.
3. İlk dağıtım için:
   ```bash
   COMPOSE_PROJECT_NAME=aunsorm-prod docker compose up -d \
     gateway auth-service kms-service x509-service id-service \
     acme-service pqc-service rng-service blockchain-service \
     mdm-service e2ee-service metrics-service cli-gateway
   ```
4. Sağlık kontrolleri:
   - `curl -f https://$HOST/healthz` 200 döndürmelidir.
   - `scripts/interop-sanity.sh --profile prod` tamamıyla yeşil olmalı.
5. Geri alma (rollback): `docker compose --project-name aunsorm-prod
   rollback` komutu ile son stabil etikete dönülür; rollback sonrası
   sağlık kontrolleri yeniden çalıştırılır.

### Kubernetes (Kontrol Listesi)

1. `config/kubernetes/` altındaki manifestleri inceleyin; `HOST` ve
   `ZASIAN_*` değerlerini `kustomize edit set image` ve `kubectl set env`
   komutları ile güncelleyin.
2. Sır yönetimi:
   - TLS sertifikaları ve JWT anahtarları `SealedSecrets` veya HSM entegr
     asyonu ile sağlanır.
   - `AUNSORM_JTI_DB` için `PersistentVolumeClaim` yerine `emptyDir`
     + `tmpfs` veya `Memory` sınıfı kullanılır; veri yedeklemesi
     `k8up`/`velero` ile yapılır.
3. Dağıtım:
   ```bash
   kubectl apply -k config/kubernetes/overlays/prod
   kubectl rollout status deploy/gateway
   kubectl rollout status statefulset/kms-service
   ```
4. Ağ ve güvenlik:
   - Ingress/Service nesnelerinin `podLabels` ile mTLS politika setlerini
     uyguladığını kontrol edin.
   - HPA ve PodDisruptionBudget tanımlarının etkin olduğunu doğrulayın.
5. Gözlemler:
   - `kubectl get --raw "/apis/custom.metrics.k8s.io/v1beta1" | jq` ile
     metrik servisinin kayıtlı olduğunu doğrulayın.
   - `prometheus` hedef listesinde `gateway`, `auth-service`,
     `pqc-service` ve `rng-service` entry'lerinin `UP` olduğunu kontrol
     edin.

## Sürüm Yükseltme Prosedürü

1. Yeni sürüm tag'i `vX.Y.Z` olarak oluşturulur ve imajlar yeniden
   üretilir.
2. `CHANGELOG.md` `[Unreleased]` kısmına değişiklikler işlenir, ardından
   ilgili bölüm `vX.Y.Z` altına taşınır.
3. `docker compose` veya `kubectl` ile `rolling update` uygulanır;
   aksilik halinde bir önceki etikete dönülür.
4. Yükseltme sonrası `scripts/interop-sanity.sh` ve `tests/blockchain`
   entegrasyon testleri çalıştırılır; başarısızlık durumunda yükseltme
   iptal edilip inceleme başlatılır.

## Runbook ve İzleme

- Olay müdahalesi için `operations/incident-response-playbook.md` ve
  `operations/disaster-recovery-runbook.md` dokümanları referans alınır.
- KPI takibi için minimum metrikler:
  - `clock_attestation_stale` < 30 sn
  - `rng_entropy_bits` hedef bandı içinde
  - HTTP hata oranı <%0.1 (5 dakikalık pencere)
- İzleme alarmları `#ops-oncall` kanalına, güvenlik anomalileri
  `#sec-incident` kanalına yönlendirilmelidir.

## Tamamlama Kriterleri

- Tüm sağlık kontrolleri ve entegrasyon testleri yeşil.
- `PROD_PLAN.md` ve `port-map.yaml` ile uyumlu port, ortam değişkeni ve
  servis listesi doğrulandı.
- Rollback prosedürü en az bir kez tatbik edildi ve süreler kayıt altına
  alındı.
