use base64::DecodeError;
use thiserror::Error;

use aunsorm_core::CoreError;

/// Paketleme katmanı hata türü.
#[derive(Debug, Error)]
pub enum PacketError {
    /// JSON serileştirme veya ayrıştırma hatası.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Base64 çözme hatası.
    #[error("base64 decode error: {0}")]
    Base64(#[from] DecodeError),
    /// Çekirdek katmandan gelen hata.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// AEAD işlemleri sırasında hata.
    #[error("aead error: {0}")]
    Aead(&'static str),
    /// Bütünlük kontrolü başarısız oldu.
    #[error("integrity error: {0}")]
    Integrity(&'static str),
    /// Strict kipi politikası ihlali.
    #[error("strict policy violation: {0}")]
    Strict(&'static str),
    /// Yeniden oynatma tespit edildi.
    #[error("replay detected for session")]
    Replay,
    /// Girdi doğrulaması başarısız oldu.
    #[error("invalid input: {0}")]
    Invalid(&'static str),
}
