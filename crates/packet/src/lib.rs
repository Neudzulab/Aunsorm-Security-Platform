#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![doc = "Aunsorm paketleme katmanı; tek-atım ve oturum bazlı şifreleme/deşifreleme sağlar."]

mod crypto;
mod error;
mod header;
mod packet;
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
    decrypt_one_shot, encrypt_one_shot, DecryptOk, DecryptParams, EncryptParams, KemPayload, Packet,
};
pub use crate::session::{
    decrypt_session, encrypt_session, SessionDecryptParams, SessionEncryptParams, SessionMetadata,
    SessionStepOutcome, SessionStore,
};
pub use crate::transcript::{compute_transcript, TranscriptHash};
pub use crate::util::peek_header;
