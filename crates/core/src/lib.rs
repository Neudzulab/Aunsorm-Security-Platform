#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![doc = "Aunsorm çekirdek kütüphanesi; Argon2 tabanlı KDF, EXTERNAL kalibrasyon bağlamı ve\
oturum ratchet mekanizmalarını sağlar."]

pub mod calibration;
pub mod error;
pub mod kdf;
pub mod salts;
pub mod session;
pub mod transparency;

pub use calibration::{
    calib_from_text, coord32_derive, normalize_calibration_text, Calibration, CalibrationId,
    CalibrationRange,
};
pub use error::CoreError;
pub use kdf::{
    derive_seed64_and_pdk, KdfInfo, KdfPreset, KdfPresetParseError, KdfProfile, SensitiveVec,
};
pub use salts::Salts;
pub use session::{SessionRatchet, SessionRatchetState, StepSecret};
pub use transparency::{
    unix_timestamp, KeyTransparencyLog, TransparencyCheckpoint, TransparencyError,
    TransparencyEvent, TransparencyEventKind, TransparencyRecord,
};
