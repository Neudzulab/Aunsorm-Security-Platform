#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! Aunsorm Ed25519 tabanlı JWT/JWKS ve JTI store bileşeni.

mod claims;
mod error;
mod jti;
mod jwk;
mod signer;
mod verifier;

pub use claims::{Audience, Claims};
pub use error::{JwtError, Result};
pub use jti::{InMemoryJtiStore, JtiStore};
pub use jwk::{Ed25519KeyPair, Ed25519PublicKey, Jwk, Jwks};
pub use signer::JwtSigner;
#[cfg(feature = "kms")]
pub use signer::KmsJwtSigner;
pub use verifier::{JwtVerifier, VerificationOptions};

#[cfg(feature = "sqlite")]
pub use jti::SqliteJtiStore;

#[cfg(test)]
mod tests;
