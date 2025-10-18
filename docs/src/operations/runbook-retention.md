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
