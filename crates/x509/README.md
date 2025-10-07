# aunsorm-x509

Aunsorm platformu için Ed25519 tabanlı X.509 sertifika yardımcı
kütüphanesi. EXTERNAL kalibrasyon bağlamını sertifika uzantılarına
dahil ederek Aunsorm koordinatlarını kimlik doğrulama katmanına
bağlamayı hedefler.

## Özellikler

- Ed25519 ile öz-imzalı sertifika üretimi.
- `AUNSORM_OID_BASE` ortam değişkenine bağlı özel kalibrasyon uzantısı.
- CPS URL'leri ve politika OID'leri için meta veri desteği.
- JSON tabanlı kalibrasyon uzantısı (kalibrasyon kimliği + fingerprint).

## Kullanım

```rust
use aunsorm_x509::{generate_self_signed, SelfSignedCertParams};

let params = SelfSignedCertParams {
    common_name: "Example", 
    org_salt: b"org-salt", 
    calibration_text: "Demo calibration", 
    cps_uris: &[],
    policy_oids: &[],
    validity_days: 365,
};
let cert = generate_self_signed(&params)?;
println!("calibration id: {}", cert.calibration_id);
```

## Testler

```
cargo test -p aunsorm-x509
```
