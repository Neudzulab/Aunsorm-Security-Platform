# aunsorm-server

`aunsorm-server`, Aunsorm platformu için OAuth/OIDC benzeri uçları
sağlayan Axum tabanlı servis katmanıdır. EXTERNAL kalibrasyon
zorunluluğu ve PKCE S256 desteği ile güvenli token akışlarını expose
eder.

## Özellikler
- `/oauth/begin-auth`, `/oauth/token`, `/oauth/introspect` uçları.
- Prometheus uyumlu `/metrics` ve sağlık için `/health`.
- `AUNSORM_STRICT` ve `AUNSORM_JTI_DB` ortam değişkenleriyle
  yapılandırma.

## Kullanım
```rust
use std::net::SocketAddr;

use aunsorm_jwt::Ed25519KeyPair;
use aunsorm_server::{router, ServerConfig, JtiStoreConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key = Ed25519KeyPair::generate("primary")?;
    let config = ServerConfig::new(
        "https://issuer.example".into(),
        "aunsorm-cli".into(),
        std::time::Duration::from_secs(3600),
        false,
        JtiStoreConfig::InMemory,
        key,
    );
    let app = router(config)?;
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    axum::Server::bind(&addr).serve(app.into_make_service()).await?;
    Ok(())
}
```
