use argon2::{password_hash, Error as ArgonError};
use thiserror::Error;

/// Hata türü, çekirdek kriptografik operasyonlar sırasında oluşabilecek durumları temsil eder.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Parametre olarak verilen salt değeri çok kısadır.
    #[error("salt too short: {0}")]
    SaltTooShort(&'static str),
    /// KDF profilindeki parametreler geçersizdir.
    #[error("invalid KDF profile: {0}")]
    InvalidProfile(&'static str),
    /// Argon2 hesaplaması başarısız oldu.
    #[error("argon2 error: {0}")]
    Argon2(#[from] password_hash::Error),
    /// HKDF türetimi istenen uzunlukta çıktı üretemedi.
    #[error("hkdf error: invalid length")]
    HkdfInvalidLength,
    /// Argon2 yapılandırması başarısız oldu.
    #[error("argon2 configuration error: {0}")]
    Argon2Config(ArgonError),
    /// Beklenen formatta olmayan girdi verisi.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}

impl CoreError {
    pub(crate) const fn invalid_profile(msg: &'static str) -> Self {
        Self::InvalidProfile(msg)
    }

    pub(crate) const fn salt_too_short(msg: &'static str) -> Self {
        Self::SaltTooShort(msg)
    }

    pub(crate) const fn invalid_input(msg: &'static str) -> Self {
        Self::InvalidInput(msg)
    }

    pub(crate) const fn hkdf_length() -> Self {
        Self::HkdfInvalidLength
    }
}
