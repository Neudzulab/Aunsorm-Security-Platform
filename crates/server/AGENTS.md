# aunsorm-server Ajanı Rehberi

- HTTP uçları `axum` tabanlı olmalı ve tüm yanıtlar JSON veya `text/plain` olarak belirgin
  `Content-Type` başlığı ile döndürülmelidir.
- `/oauth/*` uçlarında hata durumları RFC 6749 uyumlu olacak şekilde `error` ve `error_description`
  alanları içermelidir.
- PKCE yalnızca `S256` yöntemiyle desteklenmeli; farklı yöntemler açık bir hata mesajıyla reddedilmelidir.
- Strict kipte kalıcı JTI deposu zorunludur; in-memory seçenekler hataya sebep olmalıdır.
- Testler başarılı bir tam PKCE akışını ve en az bir hata senaryosunu kapsamalıdır.
- Yeni HTTP endpoint'i eklediğinizde: `CHANGELOG.md` `[Unreleased]` bölümüne kayıt açın ve `README.md` sunucu endpoint ağacını güncelleyin (durum etiketi ve açıklama ekleyin).
