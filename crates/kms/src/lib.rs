#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! Aunsorm için anahtar yönetim katmanı.
//!
//! Yerel JSON tabanlı store ve gelecekteki sağlayıcılar için ortak
//! API sağlar.

#[cfg(feature = "kms-azure")]
mod azure;
mod client;
mod config;
mod error;
#[cfg(feature = "kms-gcp")]
mod gcp;
mod local;
#[cfg(feature = "kms-pkcs11")]
mod pkcs11;
mod rng;
mod util;

pub use client::KmsClient;
#[cfg(feature = "kms-azure")]
pub use config::{AzureBackendConfig, AzureKeyConfig};
pub use config::{BackendKind, BackendLocator, KeyDescriptor, KmsConfig, LocalStoreConfig};
pub use rng::{AunsormNativeRng, create_aunsorm_rng};
#[cfg(feature = "kms-gcp")]
pub use config::{GcpBackendConfig, GcpKeyConfig};
#[cfg(feature = "kms-pkcs11")]
pub use config::{Pkcs11BackendConfig, Pkcs11KeyConfig};
pub use error::{KmsError, Result};

#[cfg(test)]
mod tests;
