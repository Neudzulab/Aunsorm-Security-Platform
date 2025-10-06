# aunsorm-cli Ajanı Rehberi

- Komut satırı arabirimi `clap` ile tanımlanmalı ve alt komutlar `encrypt`/`decrypt`/benzeri
  işlemleri kapsamalıdır.
- Tüm hassas girdiler (parola vb.) bellekte `Zeroizing` ile korunmalı ve gereksiz yere
  kopyalanmamalıdır.
- Kullanıcıya dönen hatalar belirgin ve aksiyon aldırıcı olmalı; `anyhow::Context` ile
  açıklayıcı mesajlar ekleyin.
- JSON çıktıları `serde_json` ile üretilmeli ve deterministik anahtar sırasını korumalıdır.
- Birim testleri örnek bir zarf (envelope) yapısını serileştirip geri açmalıdır.
