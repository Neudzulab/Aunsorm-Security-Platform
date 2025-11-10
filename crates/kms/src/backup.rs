use aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::error::{KmsError, Result};
use crate::rng::create_aunsorm_rng;

/// Metadata describing an encrypted backup artifact.
#[derive(Debug, Clone)]
pub struct BackupMetadata {
    pub created_at: OffsetDateTime,
    pub key_ids: Vec<String>,
    pub store_version: u32,
}

impl BackupMetadata {
    /// Creates metadata for the given key identifiers.
    #[must_use]
    pub fn new(created_at: OffsetDateTime, key_ids: Vec<String>, store_version: u32) -> Self {
        Self {
            created_at,
            key_ids,
            store_version,
        }
    }
}

/// Encrypted backup document used for secure backup/restore.
#[derive(Debug, Clone)]
pub struct EncryptedBackup {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    metadata: BackupMetadata,
}

impl EncryptedBackup {
    /// Encrypts plaintext store bytes with AES-256-GCM using the provided key material.
    pub fn seal(plaintext: &[u8], key: &[u8; 32], metadata: BackupMetadata) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|err| KmsError::Backup(format!("invalid backup key: {err}")))?;
        let mut nonce_bytes = [0u8; 12];
        create_aunsorm_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let aad = metadata_aad(&metadata);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|err| KmsError::Backup(format!("failed to seal backup: {err}")))?;
        Ok(Self {
            nonce: nonce_bytes,
            ciphertext,
            metadata,
        })
    }

    /// Decrypts the backup using the provided key material.
    pub fn open(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|err| KmsError::Backup(format!("invalid backup key: {err}")))?;
        let nonce = Nonce::from(self.nonce);
        let aad = metadata_aad(&self.metadata);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: self.ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|err| KmsError::Backup(format!("failed to open backup: {err}")))
    }

    /// Serialises the backup into JSON bytes for persistence.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let document = BackupDocument {
            version: 1,
            nonce: STANDARD.encode(self.nonce),
            ciphertext: STANDARD.encode(self.ciphertext.as_slice()),
            metadata: BackupMetadataDocument::from_runtime(&self.metadata),
        };
        serde_json::to_vec_pretty(&document)
            .map_err(|err| KmsError::Backup(format!("failed to serialise backup: {err}")))
    }

    /// Reconstructs a backup from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let document: BackupDocument = serde_json::from_slice(bytes)
            .map_err(|err| KmsError::Backup(format!("invalid backup json: {err}")))?;
        if document.version != 1 {
            return Err(KmsError::Backup(format!(
                "unsupported backup version: {}",
                document.version
            )));
        }
        let nonce_vec = STANDARD
            .decode(document.nonce.as_bytes())
            .map_err(|err| KmsError::Backup(format!("invalid backup nonce: {err}")))?;
        let nonce: [u8; 12] = nonce_vec
            .as_slice()
            .try_into()
            .map_err(|_| KmsError::Backup("backup nonce must be 12 bytes".into()))?;
        let ciphertext = STANDARD
            .decode(document.ciphertext.as_bytes())
            .map_err(|err| KmsError::Backup(format!("invalid backup ciphertext: {err}")))?;
        let metadata = document.metadata.into_runtime()?;
        Ok(Self {
            nonce,
            ciphertext,
            metadata,
        })
    }

    /// Returns backup metadata.
    pub const fn metadata(&self) -> &BackupMetadata {
        &self.metadata
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct BackupDocument {
    version: u16,
    nonce: String,
    ciphertext: String,
    metadata: BackupMetadataDocument,
}

#[derive(Debug, Serialize, Deserialize)]
struct BackupMetadataDocument {
    created_at: String,
    key_ids: Vec<String>,
    store_version: u32,
}

impl BackupMetadataDocument {
    fn from_runtime(metadata: &BackupMetadata) -> Self {
        Self {
            created_at: metadata
                .created_at
                .format(&time::format_description::well_known::Rfc3339)
                .expect("rfc3339 formatting"),
            key_ids: metadata.key_ids.clone(),
            store_version: metadata.store_version,
        }
    }

    fn into_runtime(self) -> Result<BackupMetadata> {
        let created_at = OffsetDateTime::parse(
            &self.created_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|err| KmsError::Backup(format!("invalid backup timestamp: {err}")))?;
        Ok(BackupMetadata {
            created_at,
            key_ids: self.key_ids,
            store_version: self.store_version,
        })
    }
}

fn metadata_aad(metadata: &BackupMetadata) -> Zeroizing<Vec<u8>> {
    let mut aad = Zeroizing::new(Vec::new());
    aad.extend_from_slice(metadata.created_at.unix_timestamp().to_le_bytes().as_ref());
    aad.extend_from_slice(&metadata.store_version.to_le_bytes());
    for key in &metadata.key_ids {
        aad.extend_from_slice(&(key.len() as u32).to_le_bytes());
        aad.extend_from_slice(key.as_bytes());
    }
    aad
}
