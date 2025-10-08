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
#[cfg(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11"))]
mod remote;

pub use client::KmsClient;
#[cfg(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11"))]
pub use config::RemoteStoreConfig;
pub use config::{BackendKind, BackendLocator, KeyDescriptor, KmsConfig, LocalStoreConfig};
pub use error::{KmsError, Result};

#[cfg(test)]
mod tests;
