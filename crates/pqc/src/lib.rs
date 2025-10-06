#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![doc = "Aunsorm post-kuantum kriptografi köprüsü"]

pub mod error;
pub mod kem;
pub mod signature;
pub mod strict;

pub use error::{PqcError, Result};
