# Cloudflare Konfigürasyon Rehberi

- Dosyalar Cloudflare API'si ile uyumlu YAML veya Terraform formatında olmalıdır.
- Hassas kimlik bilgileri (`account_id`, `api_token`) placeholder olarak bırakılmalı ve üst kısımda nasıl sağlanacağı
  açıklanmalıdır.
- Kurallar sıralaması önemlidir; her kuralın üzerinde etkinleşme mantığını özetleyen bir yorum bulunmalıdır.
