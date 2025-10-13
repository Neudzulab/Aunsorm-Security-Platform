use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::config::BackendKind;
use crate::error::{KmsError, Result};
use crate::util::compute_kid;

/// Yerel JSON store tabanlı backend.
#[derive(Clone)]
pub struct LocalBackend {
    keys: BTreeMap<String, LocalKey>,
}

#[derive(Clone)]
enum LocalKey {
    Ed25519 {
        seed: Zeroizing<[u8; 32]>,
        public: Box<VerifyingKey>,
        kid: String,
    },
    AesWrap {
        key: Zeroizing<Vec<u8>>,
    },
}

impl LocalBackend {
    /// JSON dosyasından backend oluşturur.
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .map_err(|err| KmsError::Config(format!("failed to read local store: {err}")))?;
        Self::from_bytes(&bytes)
    }

    /// JSON verisinden backend oluşturur.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let store: LocalStore = serde_json::from_slice(bytes)
            .map_err(|err| KmsError::Config(format!("invalid local store json: {err}")))?;
        let mut keys = BTreeMap::new();
        for entry in store.keys {
            if keys.contains_key(&entry.id) {
                return Err(KmsError::Config(format!(
                    "duplicate key identifier detected: {}",
                    entry.id
                )));
            }
            let decoded =
                Zeroizing::new(STANDARD.decode(entry.secret.as_bytes()).map_err(|err| {
                    KmsError::Config(format!("failed to decode secret for {}: {err}", entry.id))
                })?);
            let key = match entry.purpose {
                KeyPurpose::Ed25519Sign => {
                    if decoded.len() != 32 {
                        return Err(KmsError::Config(format!(
                            "ed25519 secret for {} must be 32 bytes",
                            entry.id
                        )));
                    }
                    let mut seed = Zeroizing::new([0u8; 32]);
                    seed.copy_from_slice(decoded.as_ref());
                    let signing_key = SigningKey::from_bytes(&seed);
                    let public = Box::new(VerifyingKey::from(&signing_key));
                    let kid = entry
                        .kid
                        .unwrap_or_else(|| compute_kid(public.as_ref().as_bytes()));
                    LocalKey::Ed25519 { seed, public, kid }
                }
                KeyPurpose::Aes256Wrap => {
                    if decoded.len() != 32 {
                        return Err(KmsError::Config(format!(
                            "aes-256 key for {} must be 32 bytes",
                            entry.id
                        )));
                    }
                    LocalKey::AesWrap {
                        key: decoded.clone(),
                    }
                }
            };
            keys.insert(entry.id, key);
        }
        Ok(Self { keys })
    }

    /// Belirtilen anahtar kimliği için kid değerini döndürür.
    pub fn kid(&self, key_id: &str) -> Result<String> {
        match self.keys.get(key_id) {
            Some(LocalKey::Ed25519 { kid, .. }) => Ok(kid.clone()),
            _ => Err(KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            }),
        }
    }

    /// Ed25519 public anahtarını döndürür.
    pub fn public_ed25519(&self, key_id: &str) -> Result<VerifyingKey> {
        match self.keys.get(key_id) {
            Some(LocalKey::Ed25519 { public, .. }) => Ok(*public.as_ref()),
            Some(LocalKey::AesWrap { .. }) => Err(KmsError::Unsupported {
                backend: BackendKind::Local,
            }),
            None => Err(KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            }),
        }
    }

    /// Ed25519 imzası üretir.
    pub fn sign_ed25519(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        match self.keys.get(key_id) {
            Some(LocalKey::Ed25519 { seed, .. }) => {
                let signing_key = SigningKey::from_bytes(seed);
                Ok(signing_key.sign(message).to_vec())
            }
            Some(LocalKey::AesWrap { .. }) => Err(KmsError::Unsupported {
                backend: BackendKind::Local,
            }),
            None => Err(KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            }),
        }
    }

    /// AES-256-GCM ile anahtar sarma (wrap) gerçekleştirir.
    pub fn wrap_key(&self, key_id: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self.keys.get(key_id) {
            Some(LocalKey::AesWrap { key }) => {
                let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|err| {
                    KmsError::Crypto(format!("invalid aes key for {key_id}: {err}"))
                })?;
                let mut nonce_bytes = [0u8; 12];
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from(nonce_bytes);
                let ciphertext = cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|err| KmsError::Crypto(format!("wrap failed for {key_id}: {err}")))?;
                let mut output = Vec::with_capacity(nonce.len() + ciphertext.len());
                output.extend_from_slice(&nonce_bytes);
                output.extend_from_slice(&ciphertext);
                Ok(output)
            }
            Some(LocalKey::Ed25519 { .. }) => Err(KmsError::Unsupported {
                backend: BackendKind::Local,
            }),
            None => Err(KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            }),
        }
    }

    /// AES-256-GCM sarılmış anahtarı çözer.
    pub fn unwrap_key(&self, key_id: &str, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(KmsError::Crypto("ciphertext too short".into()));
        }
        match self.keys.get(key_id) {
            Some(LocalKey::AesWrap { key }) => {
                let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|err| {
                    KmsError::Crypto(format!("invalid aes key for {key_id}: {err}"))
                })?;
                let (nonce_bytes, payload) = ciphertext.split_at(12);
                let nonce_array: [u8; 12] = nonce_bytes
                    .try_into()
                    .map_err(|_| KmsError::Crypto("invalid nonce size".into()))?;
                let nonce = Nonce::from(nonce_array);
                cipher
                    .decrypt(&nonce, Payload { msg: payload, aad })
                    .map_err(|err| KmsError::Crypto(format!("unwrap failed for {key_id}: {err}")))
            }
            Some(LocalKey::Ed25519 { .. }) => Err(KmsError::Unsupported {
                backend: BackendKind::Local,
            }),
            None => Err(KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            }),
        }
    }
}

#[derive(Deserialize)]
struct LocalStore {
    keys: Vec<LocalKeyEntry>,
}

#[derive(Deserialize)]
struct LocalKeyEntry {
    id: String,
    purpose: KeyPurpose,
    secret: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum KeyPurpose {
    Ed25519Sign,
    Aes256Wrap,
}
