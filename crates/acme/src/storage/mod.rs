use std::sync::Arc;

mod bundle;
mod error;
mod kms;
mod local;
mod outcome;

pub use bundle::CertificateBundle;
pub use error::StorageError;
pub use kms::KmsStorage;
pub use local::LocalStorage;
pub use outcome::StorageOutcome;

/// Sertifika saklama backend'lerinin ortak sözleşmesi.
pub trait CertificateStorageBackend: Send + Sync {
    /// Sertifika demetini kalıcı hale getirir.
    fn store(&self, bundle: &CertificateBundle) -> Result<StorageOutcome, StorageError>;
}

/// Sertifika saklama için tür-erased kolaylaştırıcı.
#[derive(Clone)]
pub struct CertificateStorage {
    backend: Arc<dyn CertificateStorageBackend>,
}

impl CertificateStorage {
    /// Yeni bir backend ile sarmalayıcı oluşturur.
    #[must_use]
    pub fn new<B>(backend: B) -> Self
    where
        B: CertificateStorageBackend + 'static,
    {
        Self {
            backend: Arc::new(backend),
        }
    }

    /// Yerel dosya sistemi backend'i kurar.
    #[must_use]
    pub fn local(
        certificate_path: impl Into<std::path::PathBuf>,
        chain_path: impl Into<std::path::PathBuf>,
        private_key_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self::new(LocalStorage::new(
            certificate_path.into(),
            chain_path.into(),
            private_key_path.into(),
        ))
    }

    /// KMS tabanlı backend'i kurar.
    #[must_use]
    pub fn kms(
        client: Arc<aunsorm_kms::KmsClient>,
        wrap_key: aunsorm_kms::BackendLocator,
        certificate_path: impl Into<std::path::PathBuf>,
        chain_path: impl Into<std::path::PathBuf>,
        wrapped_key_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self::new(KmsStorage::new(
            client,
            wrap_key,
            certificate_path.into(),
            chain_path.into(),
            wrapped_key_path.into(),
        ))
    }

    /// Backend'e saklama isteğini iletir.
    ///
    /// # Errors
    ///
    /// Altyapı sertifika demetini kalıcı hale getiremezse [`StorageError`] döner.
    pub fn store(&self, bundle: &CertificateBundle) -> Result<StorageOutcome, StorageError> {
        self.backend.store(bundle)
    }
}
