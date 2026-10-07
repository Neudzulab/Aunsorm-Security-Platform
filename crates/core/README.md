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

Deterministik türetme API'ları aynı girdilerle aynı çıktıyı verir; rastgelelik API'ları OS entropisi kullanır.

## Native RNG

`AunsormNativeRng` ChaCha20 ile her 1 KiB tampon dolumunda anahtarı yeniler,
anahtar için ayrılan baytları çıktıya vermez ve tüketilen baytları temizler.
64 KiB çıktı üretiminden sonra ve PID değişiminde OS entropisiyle yeniden tohumlanır.
`try_new()` ve `try_fill_bytes()` OS hatalarını döndürür; `new()`/`fill_bytes()`
hata durumunda panic üretir. Başarısız bir reseed sonrası çıktı, reseed başarılı
olana kadar engellenir. Debug çıktısı gizli durumu içermez.

Aynı PID ile snapshot geri yükleme otomatik algılanamaz: ilk kullanımdan önce
`reseed()` çağrılmalıdır. Canlı belleği okuyabilen saldırgan, henüz tüketilmemiş
tamponu görebilir ve yeni gizli OS tohumu alınana kadar gelecek çıktıyı tahmin
edebilir. Bu uygulama bağımsız bir sertifikasyon iddiası taşımaz.
