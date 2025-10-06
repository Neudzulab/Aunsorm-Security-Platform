use thiserror::Error;

/// Hata türleri.
#[derive(Debug, Error)]
pub enum PqcError {
    /// İstenen algoritma bu derlemede mevcut değil.
    #[error("algorithm {algorithm} is unavailable in this build")]
    Unavailable { algorithm: String },
    /// Girdi geçersiz olduğunda döner.
    #[error("invalid input for {algorithm}: {reason}")]
    InvalidInput { algorithm: String, reason: String },
    /// Kriptografik işlem başarısız olduğunda döner.
    #[error("cryptographic failure in {algorithm}: {reason}")]
    CryptoFailure { algorithm: String, reason: String },
    /// Strict kip uygun algoritma gerektirir.
    #[error("strict mode requires an available PQC algorithm")]
    StrictRequired,
}

impl PqcError {
    pub(crate) fn unavailable(algorithm: impl Into<String>) -> Self {
        Self::Unavailable {
            algorithm: algorithm.into(),
        }
    }

    pub(crate) fn invalid(algorithm: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            algorithm: algorithm.into(),
            reason: reason.into(),
        }
    }

    pub(crate) fn crypto(algorithm: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::CryptoFailure {
            algorithm: algorithm.into(),
            reason: reason.into(),
        }
    }
}

/// Yardımcı bir sonuç türü.
pub type Result<T> = std::result::Result<T, PqcError>;
