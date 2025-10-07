use std::error::Error;

use crate::config::BackendKind;

/// KMS işlemleri sırasında oluşabilecek hatalar.
#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    /// Yapılandırma dosyasında eksik veya geçersiz alan.
    #[error("configuration error: {0}")]
    Config(String),
    /// İstenen backend etkin değil veya yapılandırılmamış.
    #[error("backend {backend:?} not configured")]
    BackendNotConfigured { backend: BackendKind },
    /// Anahtar bulunamadığında döner.
    #[error("key {key_id} not found in backend {backend:?}")]
    KeyNotFound {
        backend: BackendKind,
        key_id: String,
    },
    /// Backend bu operasyonu desteklemiyor.
    #[error("operation unsupported on backend {backend:?}")]
    Unsupported { backend: BackendKind },
    /// Backend geçici olarak kullanılamıyor.
    #[error("backend {backend:?} unavailable: {source}")]
    BackendUnavailable {
        backend: BackendKind,
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    /// Strict kip fallback kullanımını reddetti.
    #[error("strict mode forbids fallback from {from:?} to {to:?}")]
    StrictFallback { from: BackendKind, to: BackendKind },
    /// Kriptografik operasyon başarısız olduğunda kullanılır.
    #[error("cryptographic error: {0}")]
    Crypto(String),
}

/// Sonuç tipi kestirmesi.
pub type Result<T> = std::result::Result<T, KmsError>;

impl KmsError {
    /// Yardımcı: backend erişilemez hatasını üretir.
    pub fn unavailable<E>(backend: BackendKind, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::BackendUnavailable {
            backend,
            source: Box::new(source),
        }
    }
}
