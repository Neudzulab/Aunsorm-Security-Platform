# Veri Saklama Politikası ve İmha Programı

*Revizyon: 2025-02-17*

Bu politika, GDPR Madde 5(1)(e), HIPAA Security Rule §164.310(d)(2)(i) ve
ISO/IEC 27001:2022 Ek A.8.10 gereksinimlerine uygun olarak Aunsorm
platformunda tutulan verilerin saklama sürelerini, imha yöntemlerini ve
sorumlu ekipleri tanımlar. Politika, `runbook-retention.md` altında
belirtilen operasyonel kontrollerle birlikte yürütülür.

## Saklama İlkeleri
1. **Veri Minimizasyonu:** Ürün modülleri yalnızca işleyiş için gerekli
   kişisel ve hassas verileri tutar. Her yeni veri kategorisi için
   `docs/src/operations/compliance-checklist.md` üzerinde sprint kapanış
   değerlendirmesi yapılır.
2. **Segmentasyon:** Müşteri verileri `org_scope` etiketiyle
   bölümlendirilir; Quorum taahhütleri yalnızca hash ve kalibrasyon
   referanslarını içerir.
3. **Denetim İzleri:** SOC 2 ve ISO 27001 gereksinimleri için tüm erişim,
   değişiklik ve imha olayları `certifications/audit/` raporlarıyla
   çapraz doğrulanır.

## Saklama Süreleri
| Veri Kategorisi | Saklama Süresi | Regülasyon Referansı | Saklama Ortamı | İmha Yöntemi |
|-----------------|----------------|----------------------|----------------|--------------|
| Kimlik doğrulama logları | 400 gün | GDPR Art. 32, ISO 27001 A.12.4 | SIEM + HSM audit log | `log_reaper` + HSM `kms_key_destroyed` |
| Müşteri sözleşmeleri | Sözleşme bitişinden +6 yıl | SOC 2 CC2.3, HIPAA §164.316(b)(2)(i) | Şifreli obje depolama | `retention_sync --archive` + hukuk onayı |
| PHI içerikli işlemler | İşlemden +30 gün (varsayılan), maksimum 180 gün | HIPAA §164.530(j), GDPR Art. 5(1)(e) | Segmente edilmiş Postgres | `kms::destroy` tetikleyici + veritabanı `shred_via_digest` |
| Telemetri metrikleri | 90 gün | GDPR Art. 25(2) | Prometheus TSDB | `promtool delete-series` otomasyonu |
| Destek bileti logları | 365 gün | ISO 27001 A.5.31 | Ticketing S3 bucket | S3 `LifecycleRule` + `audit-export` kaydı |

## Roller ve Sorumluluklar
- **Platform Operasyon Ekibi:** Runbook kontrollerini uygular, `retention_sync`
  çıktılarını değerlendirir ve `travel_rule_reconcile` iş akışını kapatır.
- **Güvenlik Ekibi:** Politika değişikliklerini SOC 2/ISO 27001 kontrolleri
  ile hizalar, denetimlerde kanıt toplar.
- **Hukuk ve Uyumluluk:** GDPR veri sahipleri taleplerini ve HIPAA BAA
  yükümlülüklerini takip eder, sözleşme saklama sürelerini günceller.

## İmha Süreçleri
1. **Planlama:** `retention_policy` güncellemesi `scripts/retention-plan`
   ile planlanır ve ilgili `org_scope` için onay alınır.
2. **İcra:** `retention_sync --execute` komutu çalıştırılır; komut çıktı
   logları `certifications/audit/hsm_retention_audit.md` ile kayıt altına
   alınır.
3. **Doğrulama:** `tests/blockchain/retention.rs` regresyonları ve
   `fuzz/retention/` senaryoları çalıştırılarak sapma kontrol edilir.
4. **Raporlama:** Operasyon kayıtları `runbook-retention.md` altında yeni
   bir giriş olarak eklenir; SOC 2 ve ISO 27001 denetimleri için kanıt
   paketine taşınır.

## İlgili Belgeler
- `certifications/compliance_status.md`
- `docs/src/operations/runbook-retention.md`
- `docs/src/operations/privacy-terms-blueprint.md`
