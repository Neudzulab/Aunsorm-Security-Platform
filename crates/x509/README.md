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
- Yerel HTTPS geliştirme sertifikaları için otomatik Subject Alternative Name (SAN)
  üretimi.

## Subject Alternative Name (SAN) nedir?

Modern tarayıcılar ve istemciler ortak ad (CN) alanını tek başına güvenilir
bulmaz; HTTPS sertifikasının hangi alan adları ve IP adresleri için geçerli
olduğunu Subject Alternative Name (SAN) uzantısından okurlar. `aunsorm-x509`
yerel geliştirme sertifikalarında `localhost`, `127.0.0.1`, `::1` gibi varsayılan
değerleri ve ihtiyaç duyulan ek DNS/IP girdilerini otomatik olarak ekleyerek
`mkcert` benzeri haricî araçlara ihtiyaç duymadan aynı güvenilirliği sağlar.

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
    subject_alt_names: Vec::new(),
};
let cert = generate_self_signed(&params)?;
println!("calibration id: {}", cert.calibration_id);
```

## Testler

```
cargo test -p aunsorm-x509
```
