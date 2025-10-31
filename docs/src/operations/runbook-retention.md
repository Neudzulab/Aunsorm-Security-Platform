# Operasyon Runbook'u: Müşteri Bazlı Saklama ve Anahtar İmha

Bu dosya, müşteri bazlı saklama ve anahtar imha politikalarının Quorum
`AuditAsset` kayıtları ile eşleştirilmesine ilişkin haftalık operasyon
kontrollerinin kayıt altına alınması için kullanılır. Her kayıt aşağıdaki
başlıkları içermelidir:

- **Tarih Aralığı:** ISO 8601 formatında başlangıç/bitiş.
- **Sorumlu Operatör:** Ops On-Call mühendisi.
- **Retensiyon Versiyonları:** İncelenen `retention_policy` sürümleri ve
  kapsamındaki müşteri `org_scope` değerleri.
- **Anahtar İmha Olayları:** İlgili `kms_key_destroyed` Quorum/Fabric referans
  kimlikleri.
- **Kontrol Sonuçları:** Runbook kontrol listesindeki her madde için "Geçti",
  "Uyarı" veya "Hata" değerlendirmesi ve gerekirse destekleyici metrik
  değerleri.
- **Düzeltici Eylemler:** Açılan `retention_policy_mismatch`,
  `quorum_audit_mint_missing_policy`, `travel_rule_reconcile` vb. iş akışları
  için alınan aksiyonlar ve kapanış zamanları.
- **Notlar:** SOC 2/eIDAS raporlarına taşınması gereken bulgular veya takip
  edilmesi gereken açık maddeler.

> Runbook kayıtları Git versiyon kontrolünde tutulmalı ve haftalık güncellemeler
> PR incelemesinden geçmelidir. Geriye dönük düzeltmeler yeni bir kayıt olarak
> eklenmeli, var olan girişler değiştirilmemelidir.

## 2024-06-17 – Haftalık Kontrol (Uzlaştırma Sonrası)

- **Tarih Aralığı:** 2024-06-17T12:05:05Z – 2024-06-17T12:30:05Z
- **Sorumlu Operatör:** platform-oncall@aunsorm.dev
- **Retensiyon Versiyonları:**
  - `vasp:europe:de:001` → `ret-2024.06-r5`
  - `vasp:apac:sg:014` → `ret-2024.07-r2`
- **Anahtar İmha Olayları:** Quorum `kms_key_destroyed`
  (`0x71ae9c84d157bf28ea4df1a6c96f8f5ad01e5d2c17244b8be9ef5b57d3f6b8d2`) ve
  `AuditAssetRegistry::mint` işlemi (`0x8cc3d732f3b02652bc629b2312ab9da47cebb6ba1cc403c53afc7bf99a1dc77e`)
  `cal-2024-07-bridge-021` ile eşleşti.
- **Kontrol Sonuçları:**
  - `retention_sync_last_success_at` = `2024-06-17T12:25:05Z`
    (`tests/blockchain/retention.rs::retention_sync_alarm_clears_after_reconcile_run`).
  - `retention_policy_mismatch` alarmı temizlendi (`RetentionSync::retention_policy_alarm()`).
  - Travel Rule paketi `tr-2024-07-bridge-208` olarak düzeltildi; SLA ölçümü 300 saniye.
- **Düzeltici Eylemler:** `retention_sync --reconcile --org vasp:apac:sg:014`
  komutu çalıştırıldı, Travel Rule ekibi yeniden yayınlama yaptı ve Fabric
  anchor `bridge-relay` ile senkronize edildi (`tests/data/blockchain/retention_sync_reconcile.json`).
- **Notlar:** `certifications/audit/hsm_retention_audit.md` raporu uzlaştırma
  sonrası başarı durumunu belgelemek üzere güncellendi.
