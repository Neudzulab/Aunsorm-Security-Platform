use std::fs;
use std::path::{Path, PathBuf};

use super::{CertificateBundle, CertificateStorageBackend, StorageError, StorageOutcome};

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

    fn write_pem(path: &Path, value: &str) -> Result<(), StorageError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut normalized = value.trim().to_owned();
        normalized.push('\n');
        fs::write(path, normalized)?;
        Ok(())
    }
}

impl CertificateStorageBackend for LocalStorage {
    fn store(&self, bundle: &CertificateBundle) -> Result<StorageOutcome, StorageError> {
        let chain_pem = bundle.full_chain_pem();
        Self::write_pem(&self.certificate_path, bundle.leaf_certificate())?;
        Self::write_pem(&self.chain_path, &chain_pem)?;
        Self::write_pem(&self.private_key_path, bundle.private_key_pem())?;

        Ok(StorageOutcome {
            certificate_path: self.certificate_path.clone(),
            chain_path: self.chain_path.clone(),
            private_key_path: Some(self.private_key_path.clone()),
            wrapped_key_path: None,
        })
    }
}
