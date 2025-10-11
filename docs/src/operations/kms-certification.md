# KMS Conformance ve Sertifikasyon Raporları

Bu bölüm, harici KMS/HSM sağlayıcıları için üretilen deterministik
fixture setlerini ve bunlara ait sertifikasyon özetlerini içerir.
Fixture dosyaları `tests/data/kms/` dizininde JSON olarak saklanır ve
hem entegrasyon testlerinde hem de üçüncü taraf doğrulamalarında aynı
referans materyali sunar.

## Rapor Özeti

| Sağlayıcı | Rapor Kimliği | Kapsam | Geçerlilik |
| --- | --- | --- | --- |
| GCP Cloud KMS | `AUN-KMS-2025-001` | Ed25519 imzalama uçları, retry/backoff ve `kid` hesaplaması | 10 Şubat 2025 – 10 Şubat 2026 |
| Azure Key Vault | `AUN-KMS-2025-002` | Uzaktan Ed25519 imzalama, strict cache zorunlulukları | 11 Şubat 2025 – 11 Şubat 2026 |
| PKCS#11 (SoftHSM) | `AUN-KMS-2025-003` | Deterministik Ed25519 slot operasyonları, `kid` doğrulaması | 12 Şubat 2025 – 12 Şubat 2026 |

## Fixture İçeriği

Her JSON dosyası aşağıdaki alanları barındırır:

- `provider`: Hedef sağlayıcının kısa adı (`gcp`, `azure`, `pkcs11`).
- `key_material`: Base64 kodlu özel/genel anahtar ve `kid` özeti.
- `messages`: Deterministik mesaj ve beklenen imza çiftleri.
- `certificate`: İç kalite ekibinin hazırladığı rapor kimliği, süresi ve
açıklayıcı özeti.

Fixture dosyaları, entegrasyon testleri tarafından okunarak hem HTTP
tabanlı uçların (GCP, Azure) hem de yerel HSM senaryolarının (PKCS#11)
aynı deterministik veri ile sınanmasını sağlar. Bu sayede sertifikasyon
dosyaları yalnızca dokümantasyon amaçlı kalmaz; CI ortamında sürekli
doğrulama sağlanır.

## Kullanım

1. `tests/tests/kms_conformance.rs` testi fixture dosyalarını yükler ve
   ilgili backend için HTTP veya yerel çağrı simülasyonunu kurar.
2. Testler hem imza çıktısını hem de `kid` hesaplamasını fixture ile
   karşılaştırır.
3. Başarılı test çıktıları, raporların geçerliliğinin korunduğunu
   gösterir. Fixture dosyasında değişiklik gerektiğinde rapor özetini
   ve tarihlerini güncelleyin.

Sertifikasyon raporları, harici denetçilerle paylaşılmak üzere PDF/CSV
formatında ayrıca dışa aktarılabilir. Bu mdBook bölümü raporun özetini
ve fixture referanslarını canlı tutar.
