#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

//! Aunsorm entegrasyon testleri için yardımcı crate.

/// Crate'in boş derlenmesini doğrulamak için sembolik bir fonksiyon.
#[allow(clippy::missing_const_for_fn)]
pub fn ensure_ready() {}

#[cfg(test)]
mod acme;
