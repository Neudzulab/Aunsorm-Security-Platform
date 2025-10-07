# aunsorm-kms Ajanı Rehberi

- KMS katmanı, `BackendKind` ile tanımlanan sağlayıcıların ortak
  arayüzünü sunmalıdır. `Local` sağlayıcı testlerde kullanılacak
  şekilde tam işlevli olmalı ve `strict` kipini dikkate almalıdır.
- Fallback yalnızca `AUNSORM_KMS_FALLBACK=1` ve `strict` kapalıyken
  denenmeli; aksi halde anlamlı bir hata döndürülmelidir.
- JSON yapılandırması, eksik alanlarda açıklayıcı hata mesajları
  üretmeli ve `Zeroizing` ile hafızayı temizlemelidir.
- Tüm public API'ler rustdoc örnekleri içermelidir.
- Testler deterministik dosya içerikleriyle yerel backend'i, fallback
  davranışını ve strict kipini kapsamalıdır.
