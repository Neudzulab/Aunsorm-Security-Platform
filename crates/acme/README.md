# aunsorm-acme

## Servisin Görevi
ACME servisi, RFC 8555 uyumlu hesap, nonce ve sipariş yönetimini sağlar. Domain doğrulama akışları modüler tutulur ve üst katman istemciler için deterministik testler üretir.

## Portlar
- **50017** — ACME HTTP API

## Örnek İstek/Response
```bash
curl -X POST http://localhost:50017/acme/new-account \
  -H "Content-Type: application/json" \
  -d '{"contact":["mailto:ops@example.com"],"termsOfServiceAgreed":true}'
```

```json
{
  "status": "valid",
  "kid": "https://ca.example.com/acme/acct/1",
  "orders": "https://ca.example.com/acme/acct/1/orders"
}
```

## Güvenlik Notları
- Nonce üretimi ve tüketimi tekrar üretilebilir şekilde test edilir; dış ağ çağrısı yapılmaz.
- JSON ayrıştırma hataları ayrıntılı ve kullanıcıya yardımcı olacak mesajlarla döner.
- Rastgelelik ve anahtar üretimi `AunsormNativeRng` üzerinden yapılır; harici RNG yasaktır.
- Strict kipte desteklenmeyen algoritmalar reddedilir, hata mesajları açıkça belirtilir.
