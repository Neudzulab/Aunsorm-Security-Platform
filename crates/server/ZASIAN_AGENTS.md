# Zasian × Aunsorm Agent Koordinasyonu

Bu dosya Zasian Media Platform ile Aunsorm güvenlik servislerini entegre eden
agent'lar için referans kılavuzudur.

---

## Servis Mimarisi

```
Zasian SFU (Docker)
  │
  ├─► aunsorm-network
  │     │
  │     ├─► aun-auth-service:50011      (JWT üretim/doğrulama)
  │     └─► aun-e2ee-service:50021      (JWE şifreleme + SFU E2EE oturum)
  │
  └─► host.docker.internal:50010 (nginx gateway → auth-service)

MyeOffice Next.js (nginx)
  └─► host.docker.internal:50010 → gateway → auth-service:50011
```

---

## Auth Service — JWT Endpoint'leri (port 50011)

### Token Üretimi
```
POST /security/generate-media-token
Content-Type: application/json

{
  "roomId": "oda1",
  "identity": "Kullanici_timestamp_random",
  "participantName": "Görünen Ad",
  "metadata": {
    "transportMode": "webrtc",
    "codec": "d",
    "qualityProfile": "balanced",
    "processId": "...",
    "tokenRequestTimestamp": 1773172785465,
    "tokenRequestNano": "...",
    "tokenRequestRandom": "..."
  }
}
```
**Yanıt:** `{ "token": "<JWT>", "expiresAt": "...", "ttlSeconds": 3600, "bridgeUrl": "wss://..." }`

Token `aud` claim'i: **`zasian-media`** — doğrulama sırasında bununla eşleşmesi zorunludur.

### Token Doğrulama
```
POST /security/jwt-verify
Content-Type: application/json

{ "token": "<JWT>" }
```
**Yanıt başarı:** `{ "valid": true, "payload": { "subject": "...", "audience": "zasian-media", ... } }`  
**Yanıt hata:** `{ "valid": false, "error": "Claim mismatch: aud" }`

> ⚠️ Bu endpoint `aud: zasian-media` olan token'ları doğrular.
> `aunsorm-clients` audience'ı için `/cli/jwt/verify` kullanın.

### JWE Şifreleme (auth-service'de de mevcut)
```
POST /security/jwe/encrypt
{ "plaintext": "<base64>", "kid": "mye-office-media-key" }

POST /security/jwe/decrypt
{ "ciphertext": "<JWE compact>", "kid": "mye-office-media-key" }
```

---

## E2EE Service — SFU Oturum Endpoint'leri (port 50021)

### E2EE Oturum Başlatma
```
POST /sfu/context
Content-Type: application/json

{
  "roomId": "oda1",
  "participant": "Kullanici",
  "enableE2ee": true
}
```
**Yanıt:** `{ "sessionId": "...", "e2ee": { "publicKey": "<ECDH pub>", "step": "init" } }`

Dönen `publicKey` Zasian SFU'nun kendi ECDH public key'iyle değiştirilir.

### ECDH Anahtar Değişimi Adımı
```
POST /sfu/context/step
Content-Type: application/json

{
  "sessionId": "...",
  "peerPublicKey": "<Zasian SFU ECDH pub key base64>"
}
```
**Yanıt:** `{ "sessionId": "...", "sharedSecretReady": true }`

Ortak sır türetildikten sonra medya paketleri `/security/jwe/encrypt` ile şifrelenir.

### JWE Şifreleme/Çözme (E2EE service'de de mevcut)
```
POST /security/jwe/encrypt
POST /security/jwe/decrypt
```
(Auth service ile aynı API — bkz. yukarıdaki bölüm)

---

## Zasian SFU Compose Entegrasyonu

Zasian SFU'nun `docker-compose.yml` dosyasına eklenecekler:

```yaml
services:
  sfu:
    # ...mevcut config...
    networks:
      - aunsorm-network
    environment:
      # Auth service — JWT üretim/doğrulama
      ZASIAN_WS_AUNSORM_URL: http://aun-auth-service:50011
      # E2EE service — JWE şifreleme + SFU oturum yönetimi
      ZASIAN_E2EE_URL: http://aun-e2ee-service:50021

networks:
  aunsorm-network:
    external: true
    name: aunsorm-network
```

> `host.docker.internal` Linux'ta container içinden çözümlenmiyor.
> Container DNS kullanın: `aun-auth-service:50011`, `aun-e2ee-service:50021`.

---

## Kritik Kurallar

### Audience Eşleşmesi
| Token türü        | Üretim endpoint               | Doğrulama endpoint     | `aud` değeri     |
|-------------------|-------------------------------|------------------------|------------------|
| Zasian medya JWT  | `/security/generate-media-token` | `/security/jwt-verify` | `zasian-media`   |
| OAuth access token | `/oauth/token`               | `/oauth/introspect`    | `aunsorm-clients` |

### RNG Zorunluluğu
Token üretiminde `AunsormNativeRng` kullanılır — `OsRng` doğrudan çağrılamaz.
(Bkz. `/AGENTS.md` → "Native RNG Mandatory" bölümü)

### Sealed Yapılar
`JwtPayload` struct'ı mühürlüdür (bkz. `/AGENTS.md` → "JWT Response Structure - SEALED").
`extras` alanına custom claim ekleyin; üst düzey alan eklemeyin.

---

## Hata Ayıklama

### jwt-verify 200 dönüyor ama SFU "aud mismatch" veriyor
- Token üretiminde `aud` kontrol edin: `zasian-media` olmalı
- `/security/jwt-verify` route'unun `verify_media_token`'a bağlı olduğunu doğrulayın
  (`verify_jwt_token` değil — bu `aunsorm-clients` audience bekler)

### E2EE service'e bağlanamıyor
- `aunsorm-network` ağına katılıp katılmadığını kontrol edin
- Container adı: `aun-e2ee-service`, port: `50021`
- `docker network inspect aunsorm-network` ile bağlı container'ları listeleyin

### host.docker.internal çözümlenmiyor (Linux)
- Zasian SFU `aunsorm-network` ağına bağlı olmalı
- Gateway container `host.docker.internal` alias'ına sahip (port 50010'da dinliyor)
- Doğrudan container DNS tercih edin: `aun-auth-service`, `aun-e2ee-service`
