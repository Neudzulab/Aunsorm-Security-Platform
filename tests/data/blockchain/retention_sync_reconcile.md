# Retention Sync Reconcile Fixture

Bu veri kümesi, `RetentionSync` alarmının manuel uzlaştırma sonrasında nasıl
kapatıldığını gösteren üç aşamalı bir senaryoyu içerir.

## İçerik
- **baseline:** Drift oluşmadan önceki başarılı çalıştırmanın zaman damgası ve
  iki müşteri (`vasp:europe:de:001`, `vasp:apac:sg:014`) için beklenen/veri
  eşleşmeleri.
- **drift:** `vasp:apac:sg:014` kaydında politika versiyonu ve Travel Rule
  paketinin sapması ile Fabric anchor eksikliğini tetikleyen çalıştırma.
- **reconcile:** `retention_sync --reconcile --org vasp:apac:sg:014` komutunun
  ardından PolicyStore ile Quorum/Fabric verilerinin yeniden hizalandığı
  çalıştırma. Travel Rule ekibi `tr-2024-07-bridge-412` paketini
  `tr-2024-07-bridge-208` ile değiştirip Fabric anchor'ı yeniden yayımladı.

## Amaç
Bu fixture, regresyon testlerinde (`tests/blockchain/retention.rs`) alarmın
uzlaştırma sonrasında temizlendiğini ve `last_success_at` zaman damgasının
reconcile koşusuna güncellendiğini doğrulamak için kullanılır.
