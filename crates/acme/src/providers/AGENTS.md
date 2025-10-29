# ACME Provider Katmanı Kuralları

- Provider adaptörleri `Send + Sync` olacak şekilde tasarlanmalıdır.
- Ağ çağrıları gelecekte ekleneceğinden her metot `async` planına uygun
  olarak tanımlanmalıdır.
- Skeleton implementasyonlarda bile ayrıntılı hata mesajları sağlayın;
  `todo!` yerine anlamlı `Error` varyantları döndürün.
