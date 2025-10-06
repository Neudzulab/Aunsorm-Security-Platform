# aunsorm-cli Ajanı Rehberi

- Komut satırı arayüzü, `clap` tabanlı ve kullanıcı dostu hata
  mesajları üretmelidir.
- Varsayılan olarak stdout'a minimal ama bilgilendirici loglar
  yazılmalı; gizli materyaller loglanmamalıdır.
- KDF profil, AEAD ve KEM seçimleri açıkça raporlanmalı ve
  deterministik salt türetimi kullanılmalıdır.
- CLI içindeki yardımcı fonksiyonlar ayrı modüllerde testlerle
  doğrulanmalıdır.
- Döndürülmeyen hatalarda çıkış kodu `1` olmalı ve `eprintln!`
  üzerinden bildirilmeli.
