# aunsorm-x509 Ajanı Rehberi

- Tüm sertifikalar Ed25519 (EdDSA) ile imzalanmalı ve deterministik
  seri numarası üretimi sağlanmalıdır.
- EXTERNAL kalibrasyon bağlamı sertifika uzantılarında JSON olarak
  raporlanmalı; verinin içerisinde kalibrasyon kimliği ve fingerprint'i
  bulunmalıdır.
- `AUNSORM_OID_BASE` ortam değişkeni ile gelen taban OID kullanılmalı,
  yoksa depo varsayılanı tercih edilmelidir.
- Testler sertifika uzantısında beklenen alanların yer aldığını doğrulamalıdır.
