#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use tracing::info;

use aunsorm_server::{init_tracing, serve, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let telemetry = init_tracing("aunsorm-server")?;
    info!(otel = telemetry.otel_enabled(), "telemetri başlatıldı");
    let config = ServerConfig::from_env()?;
    serve(config).await?;
    drop(telemetry);
    Ok(())
}
