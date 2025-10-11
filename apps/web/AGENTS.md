# Web Uygulaması Ajanı

Bu dizin, web entegrasyon yardımcılarını ve deneysel araçları barındırır.

- TypeScript dosyaları ESM biçiminde yazılmalı ve `tsconfig.json` tarafından
  sağlanan sıkı kontrolü geçmelidir.
- Yeni yardımcılar saf (pure) fonksiyonlar olarak tasarlanmalı, `process.env`
  gibi global durumlara doğrudan bağımlı kalmamalıdır; bunun yerine
  test edilebilir girdi parametreleri kullanılmalıdır.
- Testler `vitest` ile yazılmalı ve `npm test` komutu ile çalıştırılmalıdır.
- Ortam değişkeni adları belgelenmeli ve regresyon testleriyle korunmalıdır.
- Dosya içi açıklamalar gerektiğinde JSDoc formatında tutulmalıdır.
