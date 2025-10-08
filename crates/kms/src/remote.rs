use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::config::BackendKind;
use crate::error::{KmsError, Result};

#[derive(Clone)]
pub struct RemoteBackend {
    kind: BackendKind,
    keys: BTreeMap<String, RemoteKey>,
}

#[derive(Clone)]
enum RemoteKey {
    Ed25519 {
        seed: Zeroizing<[u8; 32]>,
        public: Box<VerifyingKey>,
        kid: String,
    },
    AesWrap {
        key: Zeroizing<Vec<u8>>,
    },
}

impl RemoteBackend {
    pub(crate) fn from_file(kind: BackendKind, path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .map_err(|err| KmsError::Config(format!("failed to read {kind:?} store: {err}")))?;
        Self::from_bytes(kind, &bytes)
    }

    pub(crate) fn from_bytes(kind: BackendKind, bytes: &[u8]) -> Result<Self> {
        let store: RemoteStore = serde_json::from_slice(bytes)
            .map_err(|err| KmsError::Config(format!("invalid {kind:?} store json: {err}")))?;
        let mut keys = BTreeMap::new();
        for entry in store.keys {
            if keys.contains_key(&entry.id) {
                return Err(KmsError::Config(format!(
                    "duplicate key identifier detected in {kind:?} store: {}",
                    entry.id
                )));
            }
            let decoded_secret =
                Zeroizing::new(STANDARD.decode(entry.secret.as_bytes()).map_err(|err| {
                    KmsError::Config(format!(
                        "failed to decode secret for {} in {kind:?}: {err}",
                        entry.id
                    ))
                })?);
            let key = match entry.purpose {
                RemoteKeyPurpose::Ed25519Sign => {
                    if decoded_secret.len() != 32 {
                        return Err(KmsError::Config(format!(
                            "ed25519 secret for {} must be 32 bytes",
                            entry.id
                        )));
                    }
                    let mut seed = Zeroizing::new([0u8; 32]);
                    seed.copy_from_slice(decoded_secret.as_ref());
                    let signing_key = SigningKey::from_bytes(&seed);
                    let public = match entry.public {
                        Some(ref explicit) => {
                            let mut public_bytes = [0u8; 32];
                            let decoded = STANDARD.decode(explicit.as_bytes()).map_err(|err| {
                                KmsError::Config(format!(
                                    "failed to decode public key for {}: {err}",
                                    entry.id
                                ))
                            })?;
                            if decoded.len() != 32 {
                                return Err(KmsError::Config(format!(
                                    "public key for {} must be 32 bytes",
                                    entry.id
                                )));
                            }
                            public_bytes.copy_from_slice(&decoded);
                            Box::new(VerifyingKey::from_bytes(&public_bytes).map_err(|err| {
                                KmsError::Config(format!(
                                    "invalid public key provided for {}: {err}",
                                    entry.id
                                ))
                            })?)
                        }
                        None => Box::new(VerifyingKey::from(&signing_key)),
                    };
                    let key_identifier = entry
                        .kid
                        .unwrap_or_else(|| compute_kid(public.as_ref().as_bytes()));
                    RemoteKey::Ed25519 {
                        seed,
                        public,
                        kid: key_identifier,
                    }
                }
                RemoteKeyPurpose::Aes256Wrap => {
                    if decoded_secret.len() != 32 {
                        return Err(KmsError::Config(format!(
                            "aes-256 key for {} must be 32 bytes",
                            entry.id
                        )));
                    }
                    RemoteKey::AesWrap {
                        key: decoded_secret.clone(),
                    }
                }
            };
            keys.insert(entry.id, key);
        }
        Ok(Self { kind, keys })
    }

    pub(crate) fn kid(&self, key_id: &str) -> Result<String> {
        match self.keys.get(key_id) {
            Some(RemoteKey::Ed25519 { kid, .. }) => Ok(kid.clone()),
            Some(RemoteKey::AesWrap { .. }) => Err(KmsError::Unsupported { backend: self.kind }),
            None => Err(KmsError::KeyNotFound {
                backend: self.kind,
                key_id: key_id.to_string(),
            }),
        }
    }

    pub(crate) fn public_ed25519(&self, key_id: &str) -> Result<VerifyingKey> {
        match self.keys.get(key_id) {
            Some(RemoteKey::Ed25519 { public, .. }) => Ok(*public.as_ref()),
            Some(RemoteKey::AesWrap { .. }) => Err(KmsError::Unsupported { backend: self.kind }),
            None => Err(KmsError::KeyNotFound {
                backend: self.kind,
                key_id: key_id.to_string(),
            }),
        }
    }

    pub(crate) fn sign_ed25519(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        match self.keys.get(key_id) {
            Some(RemoteKey::Ed25519 { seed, .. }) => {
                let signing_key = SigningKey::from_bytes(seed);
                Ok(signing_key.sign(message).to_vec())
            }
            Some(RemoteKey::AesWrap { .. }) => Err(KmsError::Unsupported { backend: self.kind }),
            None => Err(KmsError::KeyNotFound {
                backend: self.kind,
                key_id: key_id.to_string(),
            }),
        }
    }

    pub(crate) fn wrap_key(&self, key_id: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self.keys.get(key_id) {
            Some(RemoteKey::AesWrap { key }) => {
                let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|err| {
                    KmsError::Crypto(format!("invalid aes key for {key_id}: {err}"))
                })?;
                let mut nonce_bytes = [0u8; 12];
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let ciphertext = cipher
                    .encrypt(
                        nonce,
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|err| KmsError::Crypto(format!("wrap failed for {key_id}: {err}")))?;
                let mut output = Vec::with_capacity(12 + ciphertext.len());
                output.extend_from_slice(&nonce_bytes);
                output.extend_from_slice(&ciphertext);
                Ok(output)
            }
            Some(RemoteKey::Ed25519 { .. }) => Err(KmsError::Unsupported { backend: self.kind }),
            None => Err(KmsError::KeyNotFound {
                backend: self.kind,
                key_id: key_id.to_string(),
            }),
        }
    }

    pub(crate) fn unwrap_key(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(KmsError::Crypto("ciphertext too short".into()));
        }
        match self.keys.get(key_id) {
            Some(RemoteKey::AesWrap { key }) => {
                let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|err| {
                    KmsError::Crypto(format!("invalid aes key for {key_id}: {err}"))
                })?;
                let (nonce_bytes, payload) = ciphertext.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);
                cipher
                    .decrypt(nonce, Payload { msg: payload, aad })
                    .map_err(|err| KmsError::Crypto(format!("unwrap failed for {key_id}: {err}")))
            }
            Some(RemoteKey::Ed25519 { .. }) => Err(KmsError::Unsupported { backend: self.kind }),
            None => Err(KmsError::KeyNotFound {
                backend: self.kind,
                key_id: key_id.to_string(),
            }),
        }
    }
}

#[derive(Deserialize)]
struct RemoteStore {
    keys: Vec<RemoteKeyEntry>,
}

#[derive(Deserialize)]
struct RemoteKeyEntry {
    id: String,
    purpose: RemoteKeyPurpose,
    secret: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    public: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RemoteKeyPurpose {
    Ed25519Sign,
    Aes256Wrap,
}

fn compute_kid(public: &[u8]) -> String {
    let digest = Sha256::digest(public);
    hex::encode(digest)
}
