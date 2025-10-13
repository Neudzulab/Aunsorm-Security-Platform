# aunsorm-core

`aunsorm-core`, Aunsorm güvenlik aracının temel kriptografik ilkel ve bağlama (calibration) işlemlerini sağlar. Parola tabanlı anahtar
türetimi, EXTERNAL kalibrasyon kimlikleri ve oturum ratchet akışı bu crate içerisinde sunulur.

## Sağlanan Bileşenler

- Deterministik `Calibration` türetimi, NFC/boşluk normalizasyonu ve kimlik üretimi.
- Argon2id tabanlı `derive_seed64_and_pdk` fonksiyonu ile tohum ve paket türetme anahtarı elde etme; `KdfProfile::auto()` donanım kaynaklarına göre uygun profili seçer.
- HKDF tabanlı `coord32_derive` ve oturum ratchet (`SessionRatchet`).
- `KeyTransparencyLog`, JWT/JWKS yayımlarını ve kanıtlarını zincir hâlinde
  kaydederek üretim ortamlarında şeffaflık sağlar; `TransparencyCheckpoint`
  ile son durumun imzalı özetini kolayca dışa aktarabilirsiniz.

Tüm API'lar tekrar çağrıldığında aynı girdilerle aynı çıktıyı verir ve güvenlik açısından hassas arabellekler temizlenir.
