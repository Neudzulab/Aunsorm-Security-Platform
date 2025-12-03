#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all)]
#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::unused_self)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_map)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::useless_conversion)]
#![allow(dead_code)]

//! Aunsorm için anahtar yönetim katmanı.
//!
//! Yerel JSON tabanlı store ve gelecekteki sağlayıcılar için ortak
//! API sağlar.

mod approval;
#[cfg(feature = "kms-azure")]
mod azure;
mod backup;
mod client;
mod config;
mod error;
#[cfg(feature = "kms-gcp")]
mod gcp;
mod local;
#[cfg(feature = "kms-pkcs11")]
mod pkcs11;
// mod rng; // DEPRECATED: Use aunsorm-core::AunsormNativeRng instead
mod rotation;
mod util;

// Re-export sealed RNG from aunsorm-core
pub use aunsorm_core::AunsormNativeRng;

/// Create a new Aunsorm native RNG instance
pub fn create_aunsorm_rng() -> AunsormNativeRng {
    AunsormNativeRng::new()
}

pub use approval::{ApprovalBundle, ApprovalPolicy, ApprovalSignature};
pub use backup::{BackupMetadata, EncryptedBackup};
pub use client::KmsClient;
#[cfg(feature = "kms-azure")]
pub use config::{AzureBackendConfig, AzureKeyConfig};
pub use config::{BackendKind, BackendLocator, KeyDescriptor, KmsConfig, LocalStoreConfig};
#[cfg(feature = "kms-gcp")]
pub use config::{GcpBackendConfig, GcpKeyConfig};
#[cfg(feature = "kms-pkcs11")]
pub use config::{Pkcs11BackendConfig, Pkcs11KeyConfig};
pub use error::{KmsError, Result};
// pub use rng::{create_aunsorm_rng, AunsormNativeRng}; // Now re-exported from aunsorm-core above
pub use rotation::{RotationEvent, RotationPolicy};

#[cfg(test)]
mod tests;
