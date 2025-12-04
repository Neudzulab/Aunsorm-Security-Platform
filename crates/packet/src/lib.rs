#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![doc = "Aunsorm paketleme katmanı; tek-atım ve oturum bazlı şifreleme/deşifreleme sağlar."]

mod crypto;
mod error;
mod header;
mod packet;
// mod rng; // DEPRECATED: Use aunsorm-core::AunsormNativeRng instead
mod session;
mod transcript;
mod util;

#[cfg(feature = "hpke")]
pub mod hpke;

pub use crate::error::PacketError;
pub use crate::header::{
    AeadAlgorithm, Header, HeaderAead, HeaderKem, HeaderProfile, HeaderSalts, HeaderSession,
    HeaderSizes,
};
pub use crate::packet::{
    decrypt_one_shot, encrypt_one_shot, DecryptOk, DecryptParams, EncryptParams, KemPayload,
    Packet, PacketId,
};
// Re-export sealed RNG from aunsorm-core
pub use aunsorm_core::AunsormNativeRng;

/// Create a new Aunsorm native RNG instance
#[must_use]
pub fn create_aunsorm_rng() -> AunsormNativeRng {
    AunsormNativeRng::new()
}

pub use crate::session::{
    decrypt_session, encrypt_session, SessionDecryptParams, SessionEncryptParams, SessionMetadata,
    SessionStepOutcome, SessionStore,
};
pub use crate::transcript::{compute_transcript, TranscriptHash};
pub use crate::util::peek_header;
