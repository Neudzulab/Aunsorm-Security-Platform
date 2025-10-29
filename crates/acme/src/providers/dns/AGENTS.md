# DNS Provider Adaptörleri

- Cloudflare ve Route53 adaptörleri yalnızca iskelet olsa bile yapılandırma
  alanlarını (`zone_id`, `credentials`) açıkça belirtmelidir.
- Bir adaptör henüz uygulanmadıysa `DnsProviderError::NotImplemented`
  döndürün ve sağlayıcı adını mesajda geçirin.
