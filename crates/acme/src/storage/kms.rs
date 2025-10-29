use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aunsorm_kms::{BackendKind, BackendLocator, KmsClient};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{CertificateBundle, CertificateStorageBackend, StorageError, StorageOutcome};

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
}

impl CertificateStorageBackend for KmsStorage {
    fn store(&self, bundle: &CertificateBundle) -> Result<StorageOutcome, StorageError> {
        let chain_pem = bundle.full_chain_pem();
        Self::write_pem(&self.certificate_path, bundle.leaf_certificate())?;
        Self::write_pem(&self.chain_path, &chain_pem)?;

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
        Self::write_json(&self.wrapped_key_path, &wrapped)?;

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
