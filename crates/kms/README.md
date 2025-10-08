# aunsorm-kms

`aunsorm-kms`, Aunsorm güvenlik araçlarının ihtiyaç duyduğu anahtar
 yönetimi soyutlamasını sağlar. Yerel JSON tabanlı anahtar deposu ile
 Ed25519 imzalama ve AES-256-GCM anahtar sarma işlemleri
 gerçekleştirilebilir. Ayrıca aynı JSON formatını kullanan GCP, Azure
 ve PKCS#11 sağlayıcıları için dosya tabanlı konnektörler içerir. Bu
 konnektörler gerçek servis entegrasyonları için deterministik bir test
 yüzeyi sağlar ve strict kip/fallback politikalarına uyar.

## Özellikler

- `KmsClient` ile ortak imzalama/sarma API'si.
- JSON konfigürasyonundan yüklenebilen `Local`, `Gcp`, `Azure` ve
  `Pkcs11` backend'leri.
- Strict kip ve fallback politikaları için merkezi kontrol.
- Her backend için deterministik test JSON'ları üzerinden senaryolar.

## Örnek Kullanım

```rust
use aunsorm_kms::{BackendKind, BackendLocator, KeyDescriptor, KmsClient, KmsConfig};

# fn example() -> anyhow::Result<()> {
let config = KmsConfig::local_only("tests/data/local-kms.json")?;
let client = KmsClient::from_config(config)?;
let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Local, "jwt-sign"));
let signature = client.sign_ed25519(&descriptor, b"hello")?;
assert_eq!(signature.len(), 64);
# Ok(())
# }
```

### Ortam Değişkenleri

- `AUNSORM_KMS_LOCAL_STORE`: Yerel JSON anahtar deposu.
- `AUNSORM_KMS_GCP_STORE`: GCP backend'i için JSON dosyası (feature
  `kms-gcp`).
- `AUNSORM_KMS_AZURE_STORE`: Azure backend'i için JSON dosyası (feature
  `kms-azure`).
- `AUNSORM_KMS_PKCS11_STORE`: PKCS#11 backend'i için JSON dosyası
  (feature `kms-pkcs11`).

Dosya biçimi her backend için ortaktır:

```json
{
  "keys": [
    {
      "id": "projects/demo/locations/us/keyRings/main/cryptoKeys/jwt",
      "purpose": "ed25519-sign",
      "secret": "ZGV0ZXJtaW5pc3RpYy1zZWVkLWJhc2U2NA=="
    },
    {
      "id": "projects/demo/locations/us/keyRings/main/cryptoKeys/wrap",
      "purpose": "aes256-wrap",
      "secret": "d3JhcC1rZXktYmFzZTY0"
    }
  ]
}
```
