# aunsorm-server

## Servisin Görevi
Aunsorm Server, gateway rolüyle OAuth2/PKCE, JWT üretimi, JTI doğrulaması, cihaz/ID işlemleri ve kalibrasyon kontrollü RNG uçlarını tek bir HTTP katmanında sunar. Tüm yanıtlar JSON veya `text/plain` olarak döner ve kalibrasyon başlıkları zorunlu kılınır.

## Portlar
- **50010** — Genel gateway ve HTTP API

## Örnek İstek/Response
```bash
curl -X POST http://localhost:50010/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"sample","code_verifier":"verifier","client_id":"cli","redirect_uri":"https://client/callback"}'
```

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile",
  "jti": "example-jti"
}
```

## Güvenlik Notları
- PKCE yalnızca `S256` ile desteklenir; diğer yöntemler reddedilir.
- JTI deposu zorunludur; yoksa doğrulama hatası döner.
- Tüm rastgelelik `AunsormNativeRng` ile üretilir, `OsRng` kullanımına izin verilmez.
- Clock attestation `AUNSORM_CLOCK_MAX_AGE_SECS` ve `AUNSORM_CALIBRATION_FINGERPRINT` ile doğrulanır.
