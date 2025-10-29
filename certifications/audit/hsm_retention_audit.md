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
| `vasp:apac:sg:014`   | `ret-2024.07-r2`       | `ret-2024.07-r3` | Eşleşiyor | `tr-2024-07-bridge-412` | Alarm tetiklendi |

- `vasp:apac:sg:014` kaydı için Quorum `AuditAssetRegistry` metadatası beklenen
  politika versiyonu ile uyuşmadı ve Travel Rule paketi `tr-2024-07-bridge-208`
  yerine `tr-2024-07-bridge-412` olarak yayımlandı.
- Aynı kayıt için Fabric anchor'da `calibration_ref` değeri bulunamadı.
- `RetentionSync` testi (`tests/blockchain/retention.rs`), son başarılı çalışma
  zamanını `2024-06-17T12:05:05Z` olarak doğruladı ve 10 dakika sonra alınan
  drift çalıştırmasında alarmın aktif olduğunu belgeledi.

## Düzeltici Aksiyonlar
- `retention_policy_mismatch` alarmı `vasp:apac:sg:014` için açık bırakıldı ve
  PolicyStore/Quorum uyumunun manuel olarak uzlaştırılması planlandı.
- Travel Rule ekibi, `tr-2024-07-bridge-412` paketinin doğrulanması için
  bilgilendirildi.
- Fabric entegrasyonu, eksik anchor için `bridge-relay` yeniden senkronizasyonu
  amacıyla planlandı.
