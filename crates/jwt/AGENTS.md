# aunsorm-jwt Ajanı Rehberi

- JSON Web Token desteği yalnızca Ed25519 (EdDSA) algoritması
  ile sağlanacaktır; diğer algoritmalar açıkça reddedilmelidir.
- `jti` alanı tekrar saldırılarına karşı zorunlu tutulmalı, yoksa
  doğrulama başarısız olmalıdır (JTI store kullanılmıyorsa
  hata mesajı açıkça belirtmelidir).
- JWK/JWKS çıktıları RFC 8037 uyumlu (`OKP`/`Ed25519`)
  biçimde üretilmeli ve `kid` alanı her zaman doldurulmalıdır.
- SQLite destekli JTI store WAL kipinde açılmalı ve eşzamanlı
  erişimlerde tutarlı davranmalıdır.
- Testler hem bellek içi hem SQLite JTI store ile pozitif/negatif
  senaryoları kapsamalıdır.
