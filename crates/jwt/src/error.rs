#![allow(clippy::module_name_repetitions)]

use aunsorm_core::error::CoreError;
use thiserror::Error;

/// JWT işlemleri için sonuç türü.
pub type Result<T> = std::result::Result<T, JwtError>;

/// JWT hata türleri.
#[derive(Debug, Error)]
pub enum JwtError {
    /// Serde seri/de-serializasyon hatası.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    /// Base64 kod çözme hatası.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Şifreleme hatası.
    #[error("encryption error: {0}")]
    Encryption(&'static str),
    /// Şifre çözme hatası.
    #[error("decryption error: {0}")]
    Decryption(&'static str),
    /// İmza doğrulama hatası.
    #[error("signature verification failed")]
    Signature,
    /// Desteklenmeyen algoritma.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// `kid` alanı bilinmiyor.
    #[error("unknown key id: {0}")]
    UnknownKey(String),
    /// Birden fazla anahtar varken `kid` eksik.
    #[error("missing key id")]
    MissingKeyId,
    /// Token süresi dolmuş.
    #[error("token expired")]
    Expired,
    /// Token henüz geçerli değil.
    #[error("token not yet valid")]
    NotYetValid,
    /// `iat` gelecekte.
    #[error("token issued in the future")]
    IssuedInFuture,
    /// Zaman alanları hatalı.
    #[error("invalid claim {0}: {1}")]
    InvalidClaim(&'static str, &'static str),
    /// JWE alanı hatalı.
    #[error("invalid jwe field: {0}")]
    InvalidJwe(&'static str),
    /// Beklenen claim eşleşmedi.
    #[error("claim mismatch: {0}")]
    ClaimMismatch(&'static str),
    /// `jti` alanı zorunlu.
    #[error("jti claim missing")]
    MissingJti,
    /// Girdi/çıktı hatası.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// JTI store hatası.
    #[error("jti store error: {0}")]
    JtiStore(&'static str),
    /// JTI tekrar saldırısı.
    #[error("jti replay detected")]
    Replay,
    /// JWT biçimi hatalı.
    #[error("malformed jwt")]
    Malformed,
    /// Zaman hesaplaması yapılamadı.
    #[error("time conversion error")]
    TimeConversion,
    /// SQL hatası.
    #[cfg(feature = "sqlite")]
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// KMS katmanından dönen hata.
    #[cfg(feature = "kms")]
    #[error("kms error: {0}")]
    Kms(#[from] aunsorm_kms::KmsError),
    /// Kalibrasyon katmanından dönen hata.
    #[error("calibration error: {0}")]
    Calibration(#[from] CoreError),
}

impl From<std::time::SystemTimeError> for JwtError {
    fn from(_: std::time::SystemTimeError) -> Self {
        Self::TimeConversion
    }
}
