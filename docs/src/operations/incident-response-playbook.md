# Operasyon Runbook'u: Olay Müdahale

*Revizyon: 2025-11-03*

Bu runbook, Aunsorm üretim ortamında meydana gelen tüm müşteri etkili olayların
ilk 90 dakikalık müdahale penceresi içerisinde kontrol altına alınmasını,
en geç 24 saat içinde kök neden analizinin tamamlanarak paylaşılmasını ve
regülasyon bildirimlerinin gecikmeden yapılmasını garanti eder. Doküman,
`prod-primary` ve `prod-dr` bölgelerinde çalışan Kubernetes kümeleri ile
docker-compose tabanlı kalibrasyon ortamları için geçerlidir.

## Hedefler ve Kapsam

- RTO hedefi: P0/P1 olaylarında maksimum 45 dakika, P2 olaylarında 4 saat.
- RPO hedefi: Kritik veri hizmetleri için 5 dakika, diğer bileşenler için 30 dakika.
- Kapsam: Gateway, kimlik servisleri (JWT, KMS, X509), ACME, MDM, PQC ve
  blockchain mikroservisleri ile destekleyici altyapı (RNG, clock attestation,
  metrics, logging).
- Olay tipleri: Uptime ihlalleri, güvenlik olayları, veri bütünlüğü
  ihlalleri, düzenleyici uyumluluk ihlalleri ve müşteri verisi etkilenmeleri.

## Rol ve Sorumluluk Matrisi (RACI)

| Rol | Sorumluluk | R | A | C | I |
| --- | ----------- | --- | --- | --- | --- |
| **Platform On-Call** | Olay liderliği, mitigasyon komutlarının yürütülmesi | ✅ |  | ✅ | ✅ |
| **Security On-Call** | Güvenlik olaylarının doğrulanması, erişim kontrolleri | ✅ |  | ✅ | ✅ |
| **SRE Lead** | Kaynak koordinasyonu, harici iletişim onayı |  | ✅ | ✅ | ✅ |
| **Compliance Liaison** | Düzenleyici bildirimler, SOC2/GDPR kayıtları |  | ✅ | ✅ | ✅ |
| **Database Specialist** | Veri geri yükleme, RPO doğrulaması | ✅ |  | ✅ | ✅ |
| **Communications Manager** | Status sayfası, müşteri bildirimleri |  | ✅ | ✅ | ✅ |
| **Product Owner** | Müşteri etki analizi, önceliklendirme |  |  | ✅ | ✅ |

- `R`: Responsible — görevi icra eden.
- `A`: Accountable — nihai sorumluluk.
- `C`: Consulted — karar sürecine dahil.
- `I`: Informed — güncel gelişmelerden haberdar.

## Ciddiyet Sınıflandırması

| Seviye | Tanım | Örnek Tetikleyiciler | Zaman hedefi |
| --- | --- | --- | --- |
| **P0** | Tüm müşteriler etkileniyor, temel servisler erişilemez | `gateway` %100 hata, clock attestation süresi > 5 dk, kritik veri ihlali | <15 dk içinde müdahale lideri atanır, 45 dk içinde hizmet geri döner |
| **P1** | Çoğu müşteri etkileniyor veya güvenlik olayı doğrulandı | OAuth token sızıntısı, PQC anahtar yüklemesi başarısız | 30 dk içinde tampon çözüm, 2 saat içinde kalıcı fix |
| **P2** | Sınırlı müşteri etkisi, SLA sapması yok | Tek bölge kesintisi, ACME yenileme kuyruğu yavaş | 4 saat içinde çözüm |
| **P3** | Potansiyel risk, müşteri etkisi yok | Alert gürültüsü, konfigürasyon drift | Planlanan bakım döngüsünde |

Ciddiyet, Platform On-Call tarafından belirlenir ve gerektiğinde SRE Lead ile
revize edilir. Seviyeler Statuspage ve iç iletişimde tutarlı şekilde
kullanılmalıdır.

## Tetikleyici Kanallar

- **PagerDuty**: `Aunsorm-Prod-P0`, `Aunsorm-Prod-P1` servisleri.
- **Prometheus Alertmanager**: `gateway_http5xx_burst`, `clock_attestation_stale`,
  `rng_entropy_pool_low`, `postgres_replica_lag_high` (migration sonrası).
- **Security Event Stream**: `SIEM` kanalı üzerinden gelen `Critical` uyarılar.
- **Müşteri Bildirimi**: `support@aunsorm.dev` veya Tier-1 destek aramaları.

Tetikleyicilerden herhangi biri geldiğinde olay otomatik olarak oluşturulur ve
PagerDuty üzerinden Platform On-Call'a atanır.

## İlk 30 Dakika İçin Zaman Çizelgesi

| Zaman | Adım | Sorumlu |
| --- | --- | --- |
| **T+0** | PagerDuty çağrısını kabul et, Slack `#incident-war-room` kanalını aç | Platform On-Call |
| **T+5** | Ciddiyet belirle, olay kaydını `incidents/` Confluence alanında oluştur | Platform On-Call |
| **T+10** | Etki yüzeyini doğrula (`scripts/interop-sanity.sh`, sağlık kontrolleri) | Platform On-Call + SRE Lead |
| **T+15** | İlk durum güncellemesi (Slack pin + Statuspage taslağı) | Communications Manager |
| **T+20** | Mitigasyon planını onayla (`mitigation` başlığı altına yazılı) | Platform On-Call + Security |
| **T+25** | Kalıcı fix için görevleri atama (`Jira SEC-xxxx`, `OPS-xxxx`) | Product Owner |
| **T+30** | İkinci durum güncellemesi, dış paydaş maili (gerekirse) | Communications Manager |

## Müdahale Aşamaları

### 1. Tespit ve Doğrulama

1. `scripts/health/multi-region.sh --profile prod` çıktısını inceleyin.
2. `kubectl get pods -A | grep -E "Error|CrashLoop"` ile Kubernetes durumu kontrol edin.
3. Güvenlik olayı ise `siem fetch --incident <id>` komutuyla olay detaylarını alın.
4. `port-map.yaml` referans alınarak etkilenen servisin bağlı olduğu portlar
   doğrulanır.

### 2. Baskılama (Containment)

- Trafiği sağlıklı bölgeye yönlendirmek için `traffic-shift` betiği:
  ```bash
  ./scripts/traffic-shift.sh --from prod-primary --to prod-dr --reason incident-<id>
  ```
- Güvenlik ihlali durumunda ilgili API anahtarları `kms-service revoke-key` ile
  iptal edilir.
- `gateway` üzerinde hız sınırlaması gerekiyorsa `config/cloudflare/waf-rules.yaml`
  güncellenir; değişiklikler `cfctl apply` ile yayınlanır.

### 3. Kök Neden ve Düzeltme

1. Loglar `scripts/logs/pull.sh --service <name> --since 30m` ile toplanır.
2. Performans sorunları için `docs/src/operations/native-rng-performance-benchmarks.md`
   referans alınarak karşılaştırma yapılır.
3. Gerekiyorsa `git bisect` veya `kubectl rollout undo` ile bir önceki sürüme dönüş.
4. `CHANGELOG.md` güncellemesi ve hotfix dalı açma kararı Product Owner onayı ile
   verilir.

### 4. Kurtarma ve Doğrulama

- Hizmet geri yüklendikten sonra aşağıdaki kontroller zorunludur:
  - `curl -fsS https://gateway.aunsorm.dev/healthz`
  - `aunsorm-cli validate-endpoints --profile prod`
  - `scripts/interop-sanity.sh --profile prod`
  - `clock_attestation_stale` metriğinin Prometheus'ta 0'a dönmesi
  - PostgreSQL geçişi tamamlandıysa `pg_is_in_recovery()` kontrolü
- Kontroller tamamlandıktan sonra Platform On-Call `#incident-war-room`
  kanalında yeşil durum güncellemesi yapar.

### 5. Kapanış

1. Olay raporunu Confluence şablonunda tamamlayın (T+24 içinde).
2. `docs/src/operations/runbook-retention.md` dosyasına olay numarası,
   gerçekleşen RTO/RPO ve kalıcı düzeltme özetini ekleyin.
3. `PROD_PLAN.md` içinde ilgili görev kutucuklarını güncelleyin.
4. Gerekiyorsa `certifications/soc2/incident-report.md` dosyasında kayıt açın.
5. `lessons-learned` kısmında eksik runbook adımları varsa bu doküman
   güncellenmelidir.

## İletişim Protokolleri

- **Slack Kanalları**:
  - `#incident-war-room`: Operasyonel koordinasyon.
  - `#security-ops`: Güvenlik olaylarının triage'ı.
  - `#exec-brief`: Yönetici bilgilendirmesi (yalnızca özetler).
- **Statuspage**: P0/P1 olaylarında 15 dakikalık aralıklarla güncelleme.
- **Müşteri Bildirimi**: Communications Manager tarafından `status@aunsorm.dev`
  üzerinden gönderilir; SOC2 gereği 1 saat içinde ilk mail atılmalıdır.
- **Kamu Duyurusu**: Yalnızca CTO onayı ile blog veya sosyal medya.

## Ölçütler ve Denetim

- Haftalık on-call retrospektifinde aşağıdaki metrikler raporlanır:
  - Ortalama müdahale süresi (MTTA)
  - Ortalama çözüm süresi (MTTR)
  - P0/P1 olay sayısı, 30 günlük kayan pencere
  - Uyarı gürültüsü oranı (`false_positive / total_alerts`)
- Üç ayda bir tatbikat: `scripts/incident-game-day.sh` ile sahte olay senaryosu
  çalıştırılır, rapor `docs/src/operations/testing.md` dokümanına eklenir.

## Referans Dokümanlar

- [Operasyon Runbook'u: Felaket Kurtarma](disaster-recovery-runbook.md)
- [Operasyon Runbook'u: Müşteri Saklama & Anahtar İmha](runbook-retention.md)
- [Regülasyon Uyumluluk Kontrol Listesi](compliance-checklist.md)
- [Clock Attestation Sunucu Runbook'u](clock-attestation-deployment.md)
- [Ağ ve Yük Dengeleme Sertleştirmesi](networking-load-balancing.md)

