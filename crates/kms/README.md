# aunsorm-kms

`aunsorm-kms`, Aunsorm güvenlik araçlarının ihtiyaç duyduğu anahtar
 yönetimi soyutlamasını sağlar. Yerel JSON tabanlı anahtar deposu
 vasıtasıyla Ed25519 imzalama ve AES-256-GCM anahtar sarma işlemleri
 gerçekleştirilebilir; GCP, Azure ve PKCS#11 sağlayıcıları için
 genişletilebilir arayüzler sunulur.

## Özellikler

- `KmsClient` ile ortak imzalama/sarma API'si.
- JSON konfigürasyonundan yüklenebilen `Local` backend.
- Strict kip ve fallback politikaları için merkezi kontrol.

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
