# HSM Retention Audit Verification — 2024-06-17

Bu rapor, `RetentionSync` çalıştırmasının yayımladığı saklama politikası
metadatasını Quorum `AuditAssetRegistry` kayıtları ve HSM audit log'ları ile
karşılaştırmak için hazırlanmıştır. Çalışmanın amacı, `retention_policy`
verisinin zincirler arası eşlemesinin bozulduğu durumları hızlıca tanımlamak ve
`retention_policy_mismatch` alarmının ne zaman açıldığını belgelemektir.

## İncelenen Veri Setleri
- `tests/data/blockchain/retention_policy_audit.json`: Politika, Quorum mint ve
  Fabric anchor korelasyonları için referans kayıtları.
- `tests/data/blockchain/retention_sync_status.json`: `RetentionSync`
  çalıştırmalarının zaman damgaları ile beklenen/gerçekleşen politika versiyon
  bilgileri.
- `tests/data/blockchain/retention_sync_reconcile.json`: Uzlaştırma koşusunda
  alarmın kapanmasını belgeleyen veri seti.
- `tests/blockchain/retention.rs`: Son çalıştırma zamanını ve alarm durumunu
  doğrulayan regresyon testi.

## Doğrulama Adımları
1. HSM audit log'larında yer alan `kms_destroy_event` kayıtlarının zaman
   damgaları, ilgili Quorum mint işlemlerinden önce gerçekleşmelidir.
2. Aynı kayıt için `calibration_ref` değeri Fabric anchor, Quorum mint ve HSM
   audit log'u arasında bire bir eşleşmelidir.
3. `RetentionSync` çıktısında yer alan politika versiyonu ile Quorum mint
   metadatası aynı olmalı; farklılık tespit edilirse `retention_policy_mismatch`
   alarmı aktive olur.
4. Travel Rule paket referansları (`travel_rule_bundle`) tüm veri kaynakları
   arasında tutarlı olmalıdır.

## Bulgular
| Org Scope            | Politika (PolicyStore) | Quorum Mint | HSM Audit | Travel Rule | Not |
|----------------------|------------------------|-------------|-----------|-------------|-----|
| `vasp:europe:de:001` | `ret-2024.06-r5`       | Eşleşiyor   | Eşleşiyor | `tr-2024-06-bridge-104` | Başarılı |
| `vasp:apac:sg:014`   | `ret-2024.07-r2`       | Eşleşiyor   | Eşleşiyor | `tr-2024-07-bridge-208` | Uzlaştırma sonrası başarılı |

- `RetentionSync` drift koşusu `vasp:apac:sg:014` için alarm tetiklese de
  uzlaştırma çalışması (`2024-06-17T12:25:05Z`) politika versiyonunu ve Travel
  Rule paketini yeniden hizaladı.
- Fabric anchor yeniden yayımlandı ve Quorum/Fabric kalibrasyon referansları
  `cal-2024-07-bridge-021` ile eşleşti.
- `tests/blockchain/retention.rs::retention_sync_alarm_clears_after_reconcile_run`
  alarm kapandıktan sonraki başarı zaman damgasını doğruladı.

## Düzeltici Aksiyonlar
- PolicyStore, Quorum ve Fabric kayıtları `retention_sync --reconcile` komutu
  sonrasında yeniden hizalandı; alarm kapatıldı.
- Travel Rule ekibi `tr-2024-07-bridge-208` paketini yeniden yayımladı ve
  `travel_rule_reconcile` iş akışını kapattı.
- Fabric `bridge-relay` yeniden senkronizasyonu tamamlandı; anchor eksikliği
  giderildi.
