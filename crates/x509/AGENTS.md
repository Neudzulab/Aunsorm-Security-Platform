# aunsorm-x509 Ajanı Rehberi

- Sertifikalar varsayılan olarak Ed25519 (EdDSA) ile üretilmeli; legacy
  uyumluluk için RSA 2048/4096 anahtarları desteklenmelidir. Her iki
  algoritma için deterministik seri numarası üretimi korunmalıdır.
- EXTERNAL kalibrasyon bağlamı sertifika uzantılarında JSON olarak
  raporlanmalı; verinin içerisinde kalibrasyon kimliği ve fingerprint'i
  bulunmalıdır.
- `AUNSORM_OID_BASE` ortam değişkeni ile gelen taban OID kullanılmalı,
  yoksa depo varsayılanı tercih edilmelidir.
- Testler sertifika uzantısında beklenen alanların yer aldığını doğrulamalıdır.
