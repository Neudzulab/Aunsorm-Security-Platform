# Retention Policy Audit Fixtures

Bu veri kümesi, müşteri bazlı saklama ve anahtar imha politikalarının
Quorum `AuditAssetRegistry` kayıtlarıyla nasıl ilişkilendirildiğini
belgeleyen deterministik örnekleri içerir.

## Amaç
- `retention_policy_version` ile `kms_destroy_event` ve `AuditAsset` logları
  arasındaki çapraz referansları doğrulamak.
- Travel Rule raporları ve kalibrasyon kayıtlarının aynı `calibration_ref`
  değeri üzerinden senkron tutulduğunu göstermek.
- Runbook kontrollerinin (`RetensionSync`, `retention_policy_mismatch`,
  `quorum_audit_mint_missing_policy`) gerçekçi örneklerle test edilebilmesini
  sağlamak.

## Yapı
Her kayıt aşağıdaki alanları içerir:
- `org_scope`: Müşteri organizasyon kapsamı.
- `retention_policy_version`: PolicyStore tarafından yayımlanan sürüm.
- `policy_hash`: `SHA-256(org_scope:retention_policy_version)` çıktısı.
- `calibration_ref`: Fabric ve Quorum log'ları için paylaşılan bağlama kimliği.
- `travel_rule_bundle`: Travel Rule raporu için kullanılan paket referansı.
- `kms_destroy_event`: Quorum üzerinde yayılan `kms_key_destroyed` olayı
  (network, tx, block, timestamp, reason).
- `audit_asset`: `AuditAssetRegistry::mint` çağrısından elde edilen kayıt
  (tx, block, timestamp, calibration_ref, retention_policy_version,
  travel_rule_bundle).
- `fabric_retention_anchor`: Fabric tarafındaki çapalama bilgisi
  (channel, tx, block).

## Üretim Notları
- `policy_hash` değerleri, `sha256(org_scope + ":" + retention_policy_version)`
  formülüyle hesaplandı.
- Transaction kimlikleri deterministik olarak örneklenmiş 256-bit hex
  dizileridir; gerçek ortam anahtarları içermezler.
- Zaman damgaları (millisaniye) `kms_destroy_event` → `AuditAsset` sıralamasını
  takip eder ve runbook'taki kronolojik gereklilikleri doğrular.

## Test Kapsamı
`tests/blockchain/retention_audit.rs` modülü ve
`tests/tests/blockchain_retention_audit.rs` entegrasyon testi bu veri kümesini
kullanarak aşağıdaki kontrolleri uygular:
- Policy hashlerinin deterministik olarak türetildiğinin doğrulanması.
- KMS imha olaylarının AuditAsset kayıtlarından önce geldiğinin
  ve aynı `calibration_ref`/`retention_policy_version` değerlerini taşıdığının
  ispatı.
- Travel Rule paketlerinin benzersiz ve kayıt sayısıyla tutarlı olduğunun
  doğrulanması.
