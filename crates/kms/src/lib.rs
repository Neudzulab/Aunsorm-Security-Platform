#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! Aunsorm için anahtar yönetim katmanı.
//!
//! Yerel JSON tabanlı store ve gelecekteki sağlayıcılar için ortak
//! API sağlar.

mod client;
mod config;
mod error;
mod local;

pub use client::KmsClient;
pub use config::{BackendKind, BackendLocator, KeyDescriptor, KmsConfig, LocalStoreConfig};
pub use error::{KmsError, Result};

#[cfg(test)]
mod tests;
