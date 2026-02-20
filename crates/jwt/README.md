# aunsorm-jwt

## Servisin Görevi
JWT katmanı Ed25519 (EdDSA) imzalı token üretimi ve doğrulamasını sağlar. JTI kontrolü zorunlu olup eksik veya devre dışı bırakılmış depolarda doğrulama hatası üretir.

## Portlar
- **50011** — Auth servisindeki JWT uçları (gateway üzerinden erişilir)

## Örnek İstek/Response

### Authorization Code (PKCE) akışı

```bash
# 1. Yetkilendirme başlat
curl -X POST http://${HOST:-localhost}:50011/oauth/begin-auth \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","subject":"alice","client_id":"demo-client","redirect_uri":"https://app.example.com/callback","code_challenge":"<S256_challenge>","code_challenge_method":"S256"}'

# 2. Token al
curl -X POST http://${HOST:-localhost}:50011/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"<code>","code_verifier":"<verifier>","client_id":"demo-client","redirect_uri":"https://app.example.com/callback"}'
```

### Client Credentials (M2M) akışı

```bash
curl -X POST http://${HOST:-localhost}:50011/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"client_credentials","client_id":"service-client","client_secret":"aunsorm-service-secret"}'
```

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 600,
  "refreshToken": "...",
  "refreshExpiresIn": 7200,
  "role": "service",
  "mfaVerified": false
}
```

> **Not:** `service-client` gizli anahtarını `AUNSORM_SERVICE_CLIENT_SECRET` ortam değişkeni ile geçersiz kılabilirsiniz.

## Güvenlik Notları
- Sadece Ed25519 algoritması desteklenir; diğer algoritmalar açıkça reddedilir.
- JWK/JWKS çıktıları RFC 8037 uyumlu (`OKP`/`Ed25519`) olup `kid` alanı zorunludur.
- JTI store WAL kipinde açılır ve eşzamanlı erişimlere karşı test edilir.
- Rastgelelik ve JTI üretimi `AunsormNativeRng` ile yapılır.
