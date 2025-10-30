# aunsorm-jwt

`aunsorm-jwt`, Ed25519 tabanlı JSON Web Token (JWT) ve JSON Web Key
Set (JWKS) işlemlerini sağlayan kimlik bileşenidir. EXTERNAL
kalibrasyonlu Aunsorm paketlerinin üstünde çalışan uygulamalar için
kimlik doğrulama ve tekrar saldırısı engelleme (JTI store) yetenekleri
sunar.

## Özellikler

- RFC 8037 uyumlu Ed25519 (`EdDSA`) imza ve doğrulama.
- JWKS üretimi ve dış sistemlerden alınan JWK'ların doğrulanması.
- Bellek içi veya SQLite destekli JTI store ile tekrar koruması.
- Yaygın kayıtlı claim'ler (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`,
  `jti`) ve ekstra claim alanlarının yönetimi.
- Leeway/clock skew ayarı ile geçerlilik denetimleri.

## Hızlı Başlangıç

```rust
use std::sync::Arc;
use aunsorm_jwt::{
    Claims, Ed25519KeyPair, InMemoryJtiStore, JwtSigner, JwtVerifier,
    VerificationOptions,
};

let key = Ed25519KeyPair::generate("sig-2025").expect("key");
let signer = JwtSigner::new(key.clone());

let mut claims = Claims::new();
claims.issuer = Some("https://idp.aunsorm".into());
claims.subject = Some("user-123".into());
claims.set_expiration_from_now(std::time::Duration::from_secs(3600));

let token = signer.sign(&mut claims).expect("jwt");

let store = Arc::new(InMemoryJtiStore::default());
let verifier = JwtVerifier::new([key.public_key()]).with_store(store);
let verified = verifier
    .verify(&token, &VerificationOptions::default())
    .expect("verified");
assert_eq!(verified.subject.as_deref(), Some("user-123"));
```

> **Not:** `JwtSigner::sign` eksik `jti` alanını otomatik olarak üretir.
> `VerificationOptions::default()` JTI alanını zorunlu kılar ve
> yapılandırılmış bir `JtiStore` olmadan doğrulama hatası döner.

Detaylı API belgeleri için `cargo doc --open` komutunu kullanabilirsiniz.
