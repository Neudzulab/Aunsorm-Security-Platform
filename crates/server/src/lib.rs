#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! Aunsorm OAuth benzeri sunucu bileşeni.

mod config;
mod error;
mod routes;
mod state;
mod telemetry;
mod transparency;

pub use config::{LedgerBackend, ServerConfig};
pub use error::{ApiError, ServerError};
pub use routes::{build_router, serve};
pub use state::ServerState;
pub use telemetry::{init_tracing, TelemetryError, TelemetryGuard};
pub use transparency::{TransparencyEvent, TransparencyLogEntry, TransparencySnapshot};

#[cfg(test)]
mod tests;
