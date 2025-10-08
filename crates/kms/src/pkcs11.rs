use std::collections::HashMap;

use crate::config::{BackendKind, Pkcs11BackendConfig, Pkcs11KeyConfig};
use crate::error::{KmsError, Result};
use crate::util::compute_kid;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

pub struct Pkcs11Backend {
    keys: HashMap<String, Pkcs11Entry>,
}

struct Pkcs11Entry {
    signing: SigningKey,
    public: [u8; 32],
    kid: String,
}

impl Pkcs11Backend {
    pub fn new(config: Pkcs11BackendConfig, strict: bool) -> Result<Self> {
        let mut keys = HashMap::new();
        for key in config.keys {
            let alias = key.key_id.trim();
            if alias.is_empty() {
                return Err(KmsError::Config("pkcs11 key_id cannot be empty".into()));
            }
            if keys.contains_key(alias) {
                return Err(KmsError::Config(format!(
                    "duplicate pkcs11 key identifier detected: {alias}"
                )));
            }
            let entry = build_entry(&key, strict)?;
            keys.insert(alias.to_string(), entry);
        }
        Ok(Self { keys })
    }

    pub fn sign_ed25519(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let entry = self.entry_for(key_id)?;
        Ok(entry.signing.sign(message).to_vec())
    }

    pub fn public_ed25519(&self, key_id: &str) -> Result<Vec<u8>> {
        let entry = self.entry_for(key_id)?;
        Ok(entry.public.to_vec())
    }

    pub fn key_kid(&self, key_id: &str) -> Result<String> {
        let entry = self.entry_for(key_id)?;
        Ok(entry.kid.clone())
    }

    fn entry_for(&self, key_id: &str) -> Result<&Pkcs11Entry> {
        self.keys.get(key_id).ok_or_else(|| KmsError::KeyNotFound {
            backend: BackendKind::Pkcs11,
            key_id: key_id.to_string(),
        })
    }
}

fn build_entry(key: &Pkcs11KeyConfig, strict: bool) -> Result<Pkcs11Entry> {
    let decoded = STANDARD.decode(key.private_key.as_bytes()).map_err(|err| {
        KmsError::Config(format!(
            "failed to decode pkcs11 private key for {}: {err}",
            key.key_id
        ))
    })?;
    let seed: [u8; 32] = decoded.try_into().map_err(|_| {
        KmsError::Config(format!(
            "pkcs11 private key for {} must be 32 bytes",
            key.key_id
        ))
    })?;
    let signing = SigningKey::from_bytes(&seed);
    let mut public = if let Some(public_b64) = &key.public_key {
        let decoded = STANDARD.decode(public_b64.as_bytes()).map_err(|err| {
            KmsError::Config(format!(
                "failed to decode pkcs11 public key for {}: {err}",
                key.key_id
            ))
        })?;
        decoded.try_into().map_err(|_| {
            KmsError::Config(format!(
                "pkcs11 public key for {} must be 32 bytes",
                key.key_id
            ))
        })?
    } else {
        if strict {
            return Err(KmsError::Config(format!(
                "strict mode requires public_key for pkcs11 key {}",
                key.key_id
            )));
        }
        VerifyingKey::from(&signing).to_bytes()
    };

    let expected_public = VerifyingKey::from(&signing).to_bytes();
    if public != expected_public {
        public = expected_public;
    }
    let kid = key.kid.clone().unwrap_or_else(|| compute_kid(&public));
    Ok(Pkcs11Entry {
        signing,
        public,
        kid,
    })
}
