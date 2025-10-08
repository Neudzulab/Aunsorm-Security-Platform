# aunsorm-kms

`aunsorm-kms`, Aunsorm güvenlik araçlarının ihtiyaç duyduğu anahtar
 yönetimi soyutlamasını sağlar. Yerel JSON tabanlı anahtar deposuna
 ek olarak GCP Cloud KMS, Azure Key Vault ve PKCS#11 uyumlu HSM
 entegrasyonları ile Ed25519 imza operasyonları güvenli biçimde
 gerçekleştirilebilir.

## Özellikler

- `KmsClient` ile ortak imzalama/sarma API'si.
- JSON konfigürasyonundan yüklenebilen `Local` backend.
- `kms-gcp` özelliği ile HTTP tabanlı GCP Cloud KMS imzası ve otomatik
  public key önbellekleme (retry/backoff dahil).
- `kms-azure` özelliği ile Azure Key Vault imzası; strict kipte public
  key zorunluluğu, non-strict kipte kontrollü yerel fallback.
- `kms-pkcs11` özelliği ile PKCS#11 uyumlu HSM/soft-HSM Ed25519 imzası.
- Strict kip ve fallback politikaları için merkezi kontrol.

## Örnek Kullanım

```rust
use aunsorm_kms::{
    BackendKind, BackendLocator, KeyDescriptor, KmsClient, KmsConfig,
    GcpBackendConfig, GcpKeyConfig,
};

# fn example() -> anyhow::Result<()> {
let mut config = KmsConfig::local_only("tests/data/local-kms.json")?;
config = config.with_gcp(GcpBackendConfig {
    base_url: "https://cloudkms.googleapis.com".into(),
    access_token: Some("ya29...".into()),
    max_retries: 3,
    retry_backoff_ms: 25,
    keys: vec![GcpKeyConfig {
        key_id: "prod-sign".into(),
        resource: Some("projects/acme/locations/eu/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1".into()),
        public_key: None,
        kid: None,
    }],
});
let client = KmsClient::from_config(config)?;
let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Gcp, "prod-sign"));
let signature = client.sign_ed25519(&descriptor, b"hello")?;
assert_eq!(signature.len(), 64);
# Ok(())
# }
```
