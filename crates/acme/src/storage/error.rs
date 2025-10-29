use thiserror::Error;

use aunsorm_kms::KmsError;

/// Sertifika saklama katmanına ait hata türleri.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sertifika paketi boş")]
    EmptyCertificates,
    #[error("dosya yazılamadı: {0}")]
    Io(#[from] std::io::Error),
    #[error("KMS işlemi başarısız: {0}")]
    Kms(#[from] KmsError),
    #[error("sarılmış anahtar çıktısı serileştirilemedi: {0}")]
    Serde(#[from] serde_json::Error),
}
