use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aunsorm_kms::{BackendKind, BackendLocator, KmsClient, KmsError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::certificates::CertificateDownload;

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

#[derive(Debug, Clone)]
pub struct CertificateBundle {
    certificates: Vec<String>,
    private_key_pem: String,
}

impl CertificateBundle {
    /// Constructs a certificate bundle from raw PEM components.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::EmptyCertificates`] when an empty certificate chain is provided.
    pub fn new(private_key_pem: String, certificates: Vec<String>) -> Result<Self, StorageError> {
        if certificates.is_empty() {
            return Err(StorageError::EmptyCertificates);
        }
        Ok(Self {
            certificates,
            private_key_pem,
        })
    }

    /// Creates a bundle using the certificates produced by [`CertificateDownload`].
    ///
    /// # Errors
    ///
    /// Propagates [`StorageError::EmptyCertificates`] when the download did not contain
    /// any certificate blocks.
    pub fn from_download(
        download: &CertificateDownload,
        private_key_pem: String,
    ) -> Result<Self, StorageError> {
        Self::new(private_key_pem, download.certificates().to_vec())
    }

    #[must_use]
    pub fn certificates(&self) -> &[String] {
        &self.certificates
    }

    #[must_use]
    pub fn leaf_certificate(&self) -> &str {
        &self.certificates[0]
    }

    #[must_use]
    pub fn intermediates(&self) -> &[String] {
        match self.certificates.len() {
            0..=2 => &self.certificates[0..0],
            len => &self.certificates[1..len - 1],
        }
    }

    #[must_use]
    pub fn root_certificate(&self) -> Option<&str> {
        self.certificates.last().map(String::as_str)
    }

    #[must_use]
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    #[must_use]
    pub fn full_chain_pem(&self) -> String {
        let mut output = String::new();
        for cert in &self.certificates {
            let mut normalized = cert.trim().to_owned();
            normalized.push('\n');
            output.push_str(&normalized);
        }
        output
    }
}

#[derive(Debug, Clone)]
pub struct StorageOutcome {
    pub certificate_path: PathBuf,
    pub chain_path: PathBuf,
    pub private_key_path: Option<PathBuf>,
    pub wrapped_key_path: Option<PathBuf>,
}

pub enum CertificateStorage {
    Local(LocalStorage),
    Kms(KmsStorage),
}

impl CertificateStorage {
    pub fn local(
        certificate_path: impl Into<PathBuf>,
        chain_path: impl Into<PathBuf>,
        private_key_path: impl Into<PathBuf>,
    ) -> Self {
        Self::Local(LocalStorage::new(
            certificate_path.into(),
            chain_path.into(),
            private_key_path.into(),
        ))
    }

    pub fn kms(
        client: Arc<KmsClient>,
        wrap_key: BackendLocator,
        certificate_path: impl Into<PathBuf>,
        chain_path: impl Into<PathBuf>,
        wrapped_key_path: impl Into<PathBuf>,
    ) -> Self {
        Self::Kms(KmsStorage::new(
            client,
            wrap_key,
            certificate_path.into(),
            chain_path.into(),
            wrapped_key_path.into(),
        ))
    }

    /// Dispatches the storage request to the configured backend.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the underlying backend fails to persist artifacts.
    pub fn store(&self, bundle: &CertificateBundle) -> Result<StorageOutcome, StorageError> {
        match self {
            Self::Local(storage) => storage.store(bundle),
            Self::Kms(storage) => storage.store(bundle),
        }
    }
}

#[allow(clippy::struct_field_names)]
pub struct LocalStorage {
    certificate_path: PathBuf,
    chain_path: PathBuf,
    private_key_path: PathBuf,
}

impl LocalStorage {
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(certificate_path: PathBuf, chain_path: PathBuf, private_key_path: PathBuf) -> Self {
        Self {
            certificate_path,
            chain_path,
            private_key_path,
        }
    }

    /// Persists the certificate artifacts to disk.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Io`] when writing to the filesystem fails.
    pub fn store(&self, bundle: &CertificateBundle) -> Result<StorageOutcome, StorageError> {
        let chain_pem = bundle.full_chain_pem();
        write_pem(&self.certificate_path, bundle.leaf_certificate())?;
        write_pem(&self.chain_path, &chain_pem)?;
        write_pem(&self.private_key_path, bundle.private_key_pem())?;

        Ok(StorageOutcome {
            certificate_path: self.certificate_path.clone(),
            chain_path: self.chain_path.clone(),
            private_key_path: Some(self.private_key_path.clone()),
            wrapped_key_path: None,
        })
    }
}

pub struct KmsStorage {
    client: Arc<KmsClient>,
    wrap_key: BackendLocator,
    certificate_path: PathBuf,
    chain_path: PathBuf,
    wrapped_key_path: PathBuf,
}

impl KmsStorage {
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(
        client: Arc<KmsClient>,
        wrap_key: BackendLocator,
        certificate_path: PathBuf,
        chain_path: PathBuf,
        wrapped_key_path: PathBuf,
    ) -> Self {
        Self {
            client,
            wrap_key,
            certificate_path,
            chain_path,
            wrapped_key_path,
        }
    }

    /// Wraps the private key using the configured KMS and writes encrypted material to disk.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Io`] when filesystem writes fail or [`StorageError::Kms`] when the
    /// wrap operation cannot be completed.
    pub fn store(&self, bundle: &CertificateBundle) -> Result<StorageOutcome, StorageError> {
        let chain_pem = bundle.full_chain_pem();
        write_pem(&self.certificate_path, bundle.leaf_certificate())?;
        write_pem(&self.chain_path, &chain_pem)?;

        let aad = Sha256::digest(bundle.leaf_certificate().as_bytes());
        let aad_bytes: &[u8] = aad.as_ref();
        let ciphertext = self.client.wrap_key(
            &self.wrap_key,
            bundle.private_key_pem().as_bytes(),
            aad_bytes,
        )?;
        let wrapped = WrappedKeyFile {
            backend: backend_kind_name(self.wrap_key.kind()),
            key_id: self.wrap_key.key_id().to_owned(),
            aad_b64: URL_SAFE_NO_PAD.encode(aad_bytes),
            ciphertext_b64: URL_SAFE_NO_PAD.encode(&ciphertext),
        };
        write_json(&self.wrapped_key_path, &wrapped)?;

        Ok(StorageOutcome {
            certificate_path: self.certificate_path.clone(),
            chain_path: self.chain_path.clone(),
            private_key_path: None,
            wrapped_key_path: Some(self.wrapped_key_path.clone()),
        })
    }
}

#[derive(Serialize)]
struct WrappedKeyFile {
    backend: &'static str,
    key_id: String,
    aad_b64: String,
    ciphertext_b64: String,
}

const fn backend_kind_name(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Local => "local",
        BackendKind::Gcp => "gcp",
        BackendKind::Azure => "azure",
        BackendKind::Pkcs11 => "pkcs11",
    }
}

fn write_pem(path: &Path, value: &str) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut normalized = value.trim().to_owned();
    normalized.push('\n');
    fs::write(path, normalized)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_vec_pretty(value)?;
    fs::write(path, json)?;
    Ok(())
}
