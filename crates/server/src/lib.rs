#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! Aunsorm OAuth benzeri sunucu bileşeni.

mod config;
mod error;
mod routes;
mod state;

pub use config::{LedgerBackend, ServerConfig};
pub use error::{ApiError, ServerError};
pub use routes::{build_router, serve};
pub use state::ServerState;

#[cfg(test)]
mod tests;
