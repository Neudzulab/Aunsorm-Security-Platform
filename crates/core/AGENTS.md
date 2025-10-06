# aunsorm-core Ajanı Rehberi

- `aunsorm-core` kriptografik temel fonksiyonları içerir; deterministik türetmeler `Aunsorm/1.01` domain ayracını kullanmalıdır.
- API'larda salt/parametre doğrulamaları yapılmalı, hatalar `thiserror` ile tiplenmelidir.
- `Calib` türetimleri ve koordinat üretimi tekrar çağrıldığında aynı girdilerle aynı çıktıyı vermelidir (idempotentlik).
- Testler deterministik örnekler ve negatif durumlar içermelidir.
- Tüm public fonksiyonlar rustdoc ile belgelenmeli, kullanım örneği verilmelidir.
