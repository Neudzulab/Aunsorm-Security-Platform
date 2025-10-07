# aunsorm-server Ajanı Rehberi

- Sunucu `axum` tabanlı olmalı ve tüm yanıtlar deterministik JSON
  veya metin formatlarında döndürülmelidir.
- OAuth uçları PKCE S256 gereksinimine uymalı; doğrulama hataları
  açık ve eylem yapılabilir mesajlar içermelidir.
- `AUNSORM_STRICT` etkinse daha sıkı doğrulamalar yapılmalı ve
  ihlal durumunda `400` yerine `422` döndürülmelidir.
- JTI kayıtları temizlenmeli ve metrikler `/metrics`
  uç noktasından Prometheus uyumlu formatta yayımlanmalıdır.
- Testler begin-auth → token → introspect zincirini ve katı kipte
  başarısız senaryoyu kapsamalıdır.
