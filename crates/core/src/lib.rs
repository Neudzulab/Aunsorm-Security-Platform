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

pub use calibration::{
    calib_from_text, coord32_derive, Calibration, CalibrationId, CalibrationRange,
};
pub use error::CoreError;
pub use kdf::{derive_seed64_and_pdk, KdfInfo, KdfPreset, KdfProfile};
pub use salts::Salts;
pub use session::{SessionRatchet, SessionRatchetState, StepSecret};
