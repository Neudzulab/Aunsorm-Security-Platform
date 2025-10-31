# JWT Authentication Guide

Aunsorm sisteminde JWT token almanın farklı yöntemleri:

## 🎫 JWT Token Nasıl Alınır?

### 1. **Media Token (Zasian Entegrasyonu için)**

**Endpoint:** `POST /security/generate-media-token`  
**Port:** 50011 (Auth Service)  
**Kullanım:** WebRTC, media session'ları, Zasian platform entegrasyonu

#### Request:
```bash
curl -X POST http://localhost:50011/security/generate-media-token \
  -H "Content-Type: application/json" \
  -d '{
    "roomId": "test-room",
    "identity": "user123", 
    "participantName": "TestUser",
    "metadata": {
      "codec": "vp9",
      "appData": {
        "role": "host"
      }
    }
  }'
```

#### Response:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...",
  "expiresIn": 3600
}
```

### 2. **OAuth 2.0 + PKCE Flow (Secure)**

**Başlangıç:** `POST /oauth/begin-auth`  
**Token Exchange:** `POST /oauth/token`  
**Port:** 50011 (Auth Service)

#### Step 1: Auth Flow Başlat
```bash
# PKCE parametreleri oluştur
code_verifier=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
code_challenge=$(echo -n "$code_verifier" | openssl dgst -sha256 -binary | base64url)

curl -X POST http://localhost:50011/oauth/begin-auth \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-app-id",
    "code_challenge": "'$code_challenge'",
    "code_challenge_method": "S256",
    "scope": "encrypt decrypt session:manage"
  }'
```

#### Step 2: Token Exchange  
```bash
curl -X POST http://localhost:50011/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "client_id": "your-app-id", 
    "code": "received_auth_code",
    "code_verifier": "'$code_verifier'"
  }'
```

### 3. **Programmatic Token (Development)**

**Code Example:**
```rust
use aunsorm_jwt::{Claims, Ed25519KeyPair, JwtSigner, Audience};
use std::time::Duration;

// Key generation
let key = Ed25519KeyPair::generate("demo-key")?;
let signer = JwtSigner::new(key);

// Claims setup
let mut claims = Claims::new();
claims.issuer = Some("https://aunsorm.local".to_string());
claims.subject = Some("user-123".to_string());
claims.audience = Some(Audience::Single("aunsorm-cli".to_string()));
claims.set_issued_now();
claims.set_expiration_from_now(Duration::from_secs(3600));

// Custom claims
claims.extra.insert("role".to_string(), json!("admin"));
claims.extra.insert("scopes".to_string(), json!(["encrypt", "decrypt"]));

// Sign token
let token = signer.sign(&mut claims)?;
```

## 🔐 JWT Token Verification

### Endpoint: `POST /security/jwt-verify`

```bash
curl -X POST http://localhost:50011/security/jwt-verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9..."
  }'
```

### Response:
```json
{
  "valid": true,
  "payload": {
    "subject": "user123",
    "audience": "zasian-media",
    "issuer": "https://aunsorm.local",
    "expiration": 1761791358,
    "issuedAt": 1761787758,
    "jwtId": "9a05c8cb00b52a2e79403e58d7f27b4e",
    "extras": {
      "roomId": "test-room",
      "participantName": "TestUser", 
      "metadata": {
        "codec": "vp9",
        "appData": {"role": "host"}
      }
    }
  },
  "error": null
}
```

## 📋 JWKS Public Keys

### Endpoint: `GET /oauth/jwks.json`

Public key'leri almak için:
```bash
curl http://localhost:50011/oauth/jwks.json
```

## ⚠️ Production Considerations

### Environment Variables:
```bash
# Production settings
JWT_SECRET_KEY=your-production-secret-key-here
JWT_EXPIRES_IN=3600  # 1 hour
OAUTH_PRODUCTION_CALLBACK=https://prod.example.com/oauth/callback

# Clock attestation (required)
AUNSORM_CALIBRATION_FINGERPRINT=f4c9b1a27e38d34d9c0f4f8a96b3e2f74d91856b6b87a29a7df11d8e2a30c3f5
AUNSORM_CLOCK_ATTESTATION={"authority_id":"production-ntp",...}
```

### Security Notes:
1. **JTI Replay Protection**: Her token bir kez kullanılabilir
2. **Clock Attestation**: Secure timestamp verification zorunlu
3. **PKCE**: OAuth flow'da code injection attacks prevention
4. **Key Rotation**: Ed25519 key'ler düzenli rotate edilmeli

## 🧪 Test Scripts

Mevcut test dosyası: `test-jwt-verify.ps1`
```bash
# PowerShell ile test
./test-jwt-verify.ps1

# Rust example ile test  
cargo run --example jwt_flow
```

## 🔗 Related Services

- **Auth Service**: JWT issuance ve verification
- **Gateway Service**: JWT middleware ve routing
- **Zasian Integration**: Media server authentication
- **CLI Gateway**: Command-line tool authentication

## Troubleshooting

### Common Errors:
1. **Invalid signature**: JWKS public key mismatch
2. **Expired token**: Check system clock synchronization
3. **JTI replay**: Token already used (security feature)
4. **Clock attestation**: `AUNSORM_CLOCK_ATTESTATION` configuration error

### Debug Commands:
```bash
# Service health check
curl http://localhost:50011/health

# JWKS validation
curl http://localhost:50011/oauth/jwks.json

# Service logs
docker logs aun-auth-service --tail 20
```