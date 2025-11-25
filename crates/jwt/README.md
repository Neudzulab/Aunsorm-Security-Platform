# aunsorm-jwt

## Servisin Görevi
JWT katmanı Ed25519 (EdDSA) imzalı token üretimi ve doğrulamasını sağlar. JTI kontrolü zorunlu olup eksik veya devre dışı bırakılmış depolarda doğrulama hatası üretir.

## Portlar
- **50011** — Auth servisindeki JWT uçları (gateway üzerinden erişilir)

## Örnek İstek/Response
```bash
curl -X POST http://localhost:50011/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"client_credentials","client_id":"cli","client_secret":"secret"}'
```

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "jti": "example-jti"
}
```

## Güvenlik Notları
- Sadece Ed25519 algoritması desteklenir; diğer algoritmalar açıkça reddedilir.
- JWK/JWKS çıktıları RFC 8037 uyumlu (`OKP`/`Ed25519`) olup `kid` alanı zorunludur.
- JTI store WAL kipinde açılır ve eşzamanlı erişimlere karşı test edilir.
- Rastgelelik ve JTI üretimi `AunsormNativeRng` ile yapılır.
