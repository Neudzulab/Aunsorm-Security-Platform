#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! Aunsorm Ed25519 tabanlı JWT/JWKS ve JTI store bileşeni.

mod claims;
mod error;
mod jti;
mod jwe;
mod jwk;
// mod rng; // DEPRECATED: Use aunsorm-core::AunsormNativeRng instead
mod signer;
mod verifier;

// Re-export sealed RNG from aunsorm-core
pub use aunsorm_core::AunsormNativeRng;

/// Create a new Aunsorm native RNG instance
#[must_use]
pub fn create_aunsorm_rng() -> AunsormNativeRng {
    AunsormNativeRng::new()
}

pub use claims::{Audience, Claims};
pub use error::{JwtError, Result};
pub use jti::{InMemoryJtiStore, JtiStore};
pub use jwe::{CalibrationDescriptor, HybridJwe, JweProtectedHeader};
pub use jwk::{Ed25519KeyPair, Ed25519PublicKey, Jwk, Jwks};
// pub use rng::{create_aunsorm_rng, AunsormNativeRng}; // Now re-exported from aunsorm-core above
pub use signer::JwtSigner;
#[cfg(feature = "kms")]
pub use signer::KmsJwtSigner;
pub use verifier::{JwtVerifier, VerificationOptions};

#[cfg(feature = "sqlite")]
pub use jti::SqliteJtiStore;

#[cfg(test)]
mod tests;
