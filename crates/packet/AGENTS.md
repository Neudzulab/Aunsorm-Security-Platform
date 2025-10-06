# aunsorm-packet Ajanı Rehberi

- Paket başlıkları `serde_json` ile deterministik sırada serileştirilmelidir; HMAC girişi başlık
  alanlarının `hdrmac` hariç tutulmuş JSON çıktısı olmalıdır.
- `AeadAlgorithm` için string gösterimleri `aes-gcm` ve `chacha20poly1305` şeklinde sabitlenmiştir.
- EXTERNAL kalibrasyon bağlamı doğrulanmadan hiçbir deşifre işlemi başarıyla dönmemelidir.
- HMAC ve P-MAC karşılaştırmaları sabit zamanlı yapılmalıdır.
- `SessionStore` yeniden oynatmaları engellemek için `HashSet` tabanlı bir yapı kullanmalıdır.
