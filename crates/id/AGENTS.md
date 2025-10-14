# aunsorm-id Ajanı Rehberi

- `aunsorm-id` projeler arası paylaşılabilir benzersiz ID jeneratörünü içerir.
- API'lar `Result` döndürmeli ve hata tipleri `thiserror` ile tanımlanmalıdır.
- Üretilen ID biçimi ve doğrulama adımları rustdoc örnekleri ile belgelenmelidir.
- Testler hem mutlu yol hem de hata durumlarını kapsamalı, deterministik doğrulamalar içermelidir.
- Namespace/HEAD normalizasyonu açıkça test edilmelidir.
