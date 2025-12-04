use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fs;

use aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::approval::{ApprovalPolicy, ApprovalPolicyConfig, ApprovalSignerConfig};
use crate::backup::{BackupMetadata, EncryptedBackup};
use crate::config::{BackendKind, LocalStoreConfig};
use crate::create_aunsorm_rng;
use crate::error::{KmsError, Result};
use crate::rotation::{RotationEvent, RotationPolicy, RotationPolicyConfig};
use crate::util::compute_kid;

const LOCAL_STORE_VERSION: u32 = 2;

/// Yerel JSON store tabanlı backend.
#[derive(Clone)]
pub struct LocalBackend {
    keys: BTreeMap<String, LocalKey>,
    store_version: u32,
}

#[derive(Clone)]
enum LocalKey {
    Ed25519 {
        active: KeyVersion,
        previous: Option<KeyVersion>,
        policy: Option<RotationPolicy>,
        policy_config: Option<RotationPolicyConfig>,
        approvals: Option<ApprovalPolicy>,
        approval_config: Option<ApprovalPolicyConfig>,
    },
    AesWrap {
        key: Zeroizing<Vec<u8>>,
    },
}

#[derive(Clone)]
struct KeyVersion {
    seed: Zeroizing<[u8; 32]>,
    public: [u8; 32],
    kid: String,
    created_at: OffsetDateTime,
    valid_until: Option<OffsetDateTime>,
}

impl LocalBackend {
    /// Şifreli JSON store'dan backend oluşturur.
    pub fn from_config(config: &LocalStoreConfig) -> Result<Self> {
        let bytes = fs::read(config.path())
            .map_err(|err| KmsError::Config(format!("failed to read local store: {err}")))?;
        Self::from_encrypted_bytes(&bytes, config.encryption_key())
    }

    /// Store sürümünü döndürür.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn store_version(&self) -> u32 {
        self.store_version
    }

    /// Store'daki anahtar kimliklerini döndürür.
    pub fn key_ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    /// Şifreli byte dizisinden backend oluşturur.
    pub fn from_encrypted_bytes(bytes: &[u8], key: &[u8; 32]) -> Result<Self> {
        let encrypted = EncryptedBackup::from_bytes(bytes)?;
        let plaintext = Zeroizing::new(encrypted.open(key)?);
        let document: LocalStoreDocument = serde_json::from_slice(plaintext.as_ref())
            .map_err(|err| KmsError::Config(format!("invalid local store json: {err}")))?;
        if encrypted.metadata().store_version != document.version {
            return Err(KmsError::Config(format!(
                "local store metadata version mismatch: metadata {} != document {}",
                encrypted.metadata().store_version,
                document.version
            )));
        }
        let backend = Self::from_document(document)?;
        Ok(backend)
    }

    fn from_document(document: LocalStoreDocument) -> Result<Self> {
        let mut keys = BTreeMap::new();
        for entry in document.keys {
            if keys.contains_key(&entry.id) {
                return Err(KmsError::Config(format!(
                    "duplicate key identifier detected: {}",
                    entry.id
                )));
            }
            let key = match entry.purpose {
                KeyPurpose::Ed25519Sign => Self::build_ed25519_key(&entry)?,
                KeyPurpose::Aes256Wrap => Self::build_aes_wrap_key(&entry)?,
            };
            keys.insert(entry.id, key);
        }
        Ok(Self {
            keys,
            store_version: document.version,
        })
    }

    fn build_ed25519_key(entry: &LocalKeyEntry) -> Result<LocalKey> {
        let decoded =
            Zeroizing::new(STANDARD.decode(entry.material.as_bytes()).map_err(|err| {
                KmsError::Config(format!("failed to decode secret for {}: {err}", entry.id))
            })?);
        if decoded.len() != 32 {
            return Err(KmsError::Config(format!(
                "ed25519 secret for {} must be 32 bytes",
                entry.id
            )));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(decoded.as_ref());
        let signing_key = SigningKey::from_bytes(&seed);
        let mut public = VerifyingKey::from(&signing_key).to_bytes();
        if let Some(explicit) = &entry.public_key {
            let decoded = STANDARD.decode(explicit.as_bytes()).map_err(|err| {
                KmsError::Config(format!(
                    "failed to decode public key for {}: {err}",
                    entry.id
                ))
            })?;
            let parsed: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
                KmsError::Config(format!("public key for {} must be 32 bytes", entry.id))
            })?;
            if parsed != public {
                public = parsed;
            }
        }
        let metadata = entry.metadata.clone().unwrap_or_default();
        let created_at = metadata
            .parsed_created_at(&entry.id)?
            .unwrap_or_else(OffsetDateTime::now_utc);
        let policy_config = metadata.rotation.clone();
        let policy = policy_config
            .as_ref()
            .map(RotationPolicy::from_config)
            .transpose()?;
        let approval_config = metadata.approvals.clone();
        let approvals = approval_config
            .as_ref()
            .map(ApprovalPolicy::from_config)
            .transpose()?;
        let valid_until = if let Some(explicit) = metadata.parsed_expires_at(&entry.id)? {
            Some(explicit)
        } else {
            policy
                .as_ref()
                .map(|policy| policy.compute_expiration(created_at))
        };
        let kid = entry.kid.clone().unwrap_or_else(|| compute_kid(&public));
        let active = KeyVersion {
            seed,
            public,
            kid,
            created_at,
            valid_until,
        };
        let previous = metadata
            .previous_versions
            .iter()
            .filter_map(|historical| historical.to_key_version(&entry.id).transpose())
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .next();
        Ok(LocalKey::Ed25519 {
            active,
            previous,
            policy,
            policy_config,
            approvals,
            approval_config,
        })
    }

    fn build_aes_wrap_key(entry: &LocalKeyEntry) -> Result<LocalKey> {
        let decoded =
            Zeroizing::new(STANDARD.decode(entry.material.as_bytes()).map_err(|err| {
                KmsError::Config(format!("failed to decode secret for {}: {err}", entry.id))
            })?);
        if decoded.len() != 32 {
            return Err(KmsError::Config(format!(
                "aes-256 key for {} must be 32 bytes",
                entry.id
            )));
        }
        Ok(LocalKey::AesWrap { key: decoded })
    }

    /// Belirtilen anahtar kimliği için aktif kid değerini döndürür.
    pub fn kid(&self, key_id: &str) -> Result<String> {
        match self.keys.get(key_id) {
            Some(LocalKey::Ed25519 { active, .. }) => Ok(active.kid.clone()),
            _ => Err(KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            }),
        }
    }

    /// Mevcut ve grace dönemindeki tüm kid değerlerini döndürür.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn key_kids(&self, key_id: &str) -> Result<Vec<String>> {
        match self.keys.get(key_id) {
            Some(LocalKey::Ed25519 {
                active, previous, ..
            }) => {
                let mut kids = vec![active.kid.clone()];
                if let Some(previous) = previous {
                    kids.push(previous.kid.clone());
                }
                Ok(kids)
            }
            _ => Err(KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            }),
        }
    }

    /// Ed25519 public anahtarını döndürür.
    pub fn public_ed25519(&self, key_id: &str) -> Result<VerifyingKey> {
        match self.keys.get(key_id) {
            Some(LocalKey::Ed25519 { active, .. }) => VerifyingKey::from_bytes(&active.public)
                .map_err(|err| KmsError::Crypto(format!("invalid public key: {err}"))),
            Some(LocalKey::AesWrap { .. }) => Err(KmsError::Unsupported {
                backend: BackendKind::Local,
            }),
            None => Err(KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            }),
        }
    }

    /// Grace dönemindeki eski public anahtarları da içerir.
    pub fn public_ed25519_versions(&self, key_id: &str) -> Result<Vec<(String, Vec<u8>)>> {
        match self.keys.get(key_id) {
            Some(LocalKey::Ed25519 {
                active, previous, ..
            }) => {
                let mut versions = vec![(active.kid.clone(), active.public.to_vec())];
                if let Some(previous) = previous {
                    versions.push((previous.kid.clone(), previous.public.to_vec()));
                }
                Ok(versions)
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

    /// Anahtar için onay politikasını döndürür.
    pub fn approvals(&self, key_id: &str) -> Result<Option<&ApprovalPolicy>> {
        match self.keys.get(key_id) {
            Some(LocalKey::Ed25519 { approvals, .. }) => Ok(approvals.as_ref()),
            _ => Err(KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            }),
        }
    }

    /// Anahtar rotasyon politikasını döndürür.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn rotation_policy(&self, key_id: &str) -> Result<Option<&RotationPolicy>> {
        match self.keys.get(key_id) {
            Some(LocalKey::Ed25519 { policy, .. }) => Ok(policy.as_ref()),
            _ => Err(KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            }),
        }
    }

    /// Ed25519 imzası üretir ve gerekiyorsa otomatik rotasyonu tetikler.
    pub fn sign_ed25519(&mut self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        self.auto_rotate_if_needed(key_id)?;
        match self.keys.get(key_id) {
            Some(LocalKey::Ed25519 { active, .. }) => {
                let signing_key = SigningKey::from_bytes(&active.seed);
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

    /// Anahtar rotasyonunu elle tetikler.
    pub fn rotate_ed25519(&mut self, key_id: &str) -> Result<RotationEvent> {
        let now = OffsetDateTime::now_utc();
        let key = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            })?;
        let LocalKey::Ed25519 {
            active,
            previous,
            policy,
            ..
        } = key
        else {
            return Err(KmsError::Unsupported {
                backend: BackendKind::Local,
            });
        };
        let mut new_seed = Zeroizing::new([0u8; 32]);
        create_aunsorm_rng().fill_bytes(new_seed.as_mut());
        let signing_key = SigningKey::from_bytes(&new_seed);
        let public = VerifyingKey::from(&signing_key).to_bytes();
        let new_kid = compute_kid(&public);
        let new_version = KeyVersion {
            seed: new_seed,
            public,
            kid: new_kid.clone(),
            created_at: now,
            valid_until: policy.as_ref().map(|policy| policy.compute_expiration(now)),
        };
        let grace_deadline = policy
            .as_ref()
            .map(|policy| policy.compute_grace_deadline(now));
        let old_kid = active.kid.clone();
        let mut old = active.clone();
        old.valid_until = grace_deadline;
        *previous = Some(old);
        *active = new_version;
        let _ = active;
        let _ = previous;
        Self::prune_previous_if_expired(key, OffsetDateTime::now_utc());
        Ok(RotationEvent::new(
            key_id,
            Some(old_kid),
            new_kid,
            now,
            grace_deadline,
        ))
    }

    /// AES-256-GCM ile anahtar sarma (wrap) gerçekleştirir.
    pub fn wrap_key(&self, key_id: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self.keys.get(key_id) {
            Some(LocalKey::AesWrap { key }) => {
                let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|err| {
                    KmsError::Crypto(format!("invalid aes key for {key_id}: {err}"))
                })?;
                let mut nonce_bytes = [0u8; 12];
                create_aunsorm_rng().fill_bytes(&mut nonce_bytes);
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
                Ok(cipher
                    .decrypt(&nonce, Payload { msg: payload, aad })
                    .map_err(|err| {
                        KmsError::Crypto(format!("unwrap failed for {key_id}: {err}"))
                    })?)
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

    /// Mevcut anahtar durumunu şifreli JSON formatında dışa aktarır.
    pub fn export_encrypted(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        let document = self.to_document();
        let plaintext =
            Zeroizing::new(serde_json::to_vec_pretty(&document).map_err(|err| {
                KmsError::Backup(format!("failed to serialise local store: {err}"))
            })?);
        let metadata = BackupMetadata::new(
            OffsetDateTime::now_utc(),
            self.keys.keys().cloned().collect(),
            self.store_version,
        );
        let encrypted = EncryptedBackup::seal(plaintext.as_ref(), key, metadata)?;
        encrypted.to_bytes()
    }

    /// Yedekleme nesnesi üretir.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn create_backup(&self, key: &[u8; 32]) -> Result<EncryptedBackup> {
        let document = self.to_document();
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&document).map_err(|err| {
                KmsError::Backup(format!("failed to serialise local store: {err}"))
            })?);
        let metadata = BackupMetadata::new(
            OffsetDateTime::now_utc(),
            self.keys.keys().cloned().collect(),
            self.store_version,
        );
        EncryptedBackup::seal(plaintext.as_ref(), key, metadata)
    }

    fn to_document(&self) -> LocalStoreDocument {
        let mut keys = Vec::with_capacity(self.keys.len());
        for (id, key) in &self.keys {
            match key {
                LocalKey::Ed25519 {
                    active,
                    previous,
                    policy,
                    policy_config,
                    approvals,
                    approval_config,
                } => {
                    let material = STANDARD.encode(active.seed.as_ref());
                    let mut metadata = KeyMetadataDocument::default();
                    metadata.created_at = Some(format_timestamp(active.created_at));
                    metadata.expires_at = active.valid_until.map(format_timestamp);
                    metadata.rotation = if let Some(config) = policy_config.clone() {
                        Some(config)
                    } else if let Some(policy) = policy {
                        Some(reconstruct_rotation_config(policy, active.created_at))
                    } else {
                        None
                    };
                    metadata.approvals = if let Some(config) = approval_config.clone() {
                        Some(config)
                    } else if let Some(policy) = approvals {
                        Some(reconstruct_approval_config(policy))
                    } else {
                        None
                    };
                    if let Some(previous) = previous {
                        metadata
                            .previous_versions
                            .push(HistoricalVersionDocument::from_version(previous));
                    }
                    keys.push(LocalKeyEntry {
                        id: id.clone(),
                        purpose: KeyPurpose::Ed25519Sign,
                        material,
                        kid: Some(active.kid.clone()),
                        public_key: Some(STANDARD.encode(active.public)),
                        metadata: Some(metadata),
                    });
                }
                LocalKey::AesWrap { key } => {
                    let wrap_bytes: &[u8] = key.as_ref();
                    keys.push(LocalKeyEntry {
                        id: id.clone(),
                        purpose: KeyPurpose::Aes256Wrap,
                        material: STANDARD.encode(wrap_bytes),
                        kid: None,
                        public_key: None,
                        metadata: None,
                    });
                }
            }
        }
        let version = if self.store_version == 0 {
            LOCAL_STORE_VERSION
        } else {
            self.store_version
        };
        LocalStoreDocument { version, keys }
    }

    fn auto_rotate_if_needed(&mut self, key_id: &str) -> Result<Option<RotationEvent>> {
        let now = OffsetDateTime::now_utc();
        let key = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| KmsError::KeyNotFound {
                backend: BackendKind::Local,
                key_id: key_id.to_string(),
            })?;
        if !matches!(key, LocalKey::Ed25519 { .. }) {
            return Ok(None);
        }
        Self::prune_previous_if_expired(key, now);
        let LocalKey::Ed25519 {
            active,
            previous,
            policy,
            ..
        } = key
        else {
            unreachable!("ed25519 branch checked above");
        };
        let Some(policy) = policy else {
            return Ok(None);
        };
        if !policy.auto_rotate() {
            return Ok(None);
        }
        if let Some(valid_until) = active.valid_until {
            if now < valid_until {
                return Ok(None);
            }
        } else if !policy.is_expired(active.created_at, now) {
            return Ok(None);
        }
        let mut new_seed = Zeroizing::new([0u8; 32]);
        create_aunsorm_rng().fill_bytes(new_seed.as_mut());
        let signing_key = SigningKey::from_bytes(&new_seed);
        let public = VerifyingKey::from(&signing_key).to_bytes();
        let new_kid = compute_kid(&public);
        let new_version = KeyVersion {
            seed: new_seed,
            public,
            kid: new_kid.clone(),
            created_at: now,
            valid_until: Some(policy.compute_expiration(now)),
        };
        let grace_deadline = Some(policy.compute_grace_deadline(now));
        let old_kid = active.kid.clone();
        let mut old = active.clone();
        old.valid_until = grace_deadline;
        *previous = Some(old);
        *active = new_version;
        let _ = active;
        let _ = previous;
        Self::prune_previous_if_expired(key, OffsetDateTime::now_utc());
        Ok(Some(RotationEvent::new(
            key_id,
            Some(old_kid),
            new_kid,
            now,
            grace_deadline,
        )))
    }

    fn prune_previous_if_expired(key: &mut LocalKey, now: OffsetDateTime) {
        if let LocalKey::Ed25519 { previous, .. } = key {
            if let Some(previous_version) = previous {
                if previous_version
                    .valid_until
                    .map(|deadline| now > deadline)
                    .unwrap_or(false)
                {
                    *previous = None;
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalStoreDocument {
    version: u32,
    keys: Vec<LocalKeyEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct LocalKeyEntry {
    id: String,
    purpose: KeyPurpose,
    material: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    metadata: Option<KeyMetadataDocument>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct KeyMetadataDocument {
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    rotation: Option<RotationPolicyConfig>,
    #[serde(default)]
    approvals: Option<ApprovalPolicyConfig>,
    #[serde(default)]
    previous_versions: Vec<HistoricalVersionDocument>,
}

impl KeyMetadataDocument {
    fn parsed_created_at(&self, key_id: &str) -> Result<Option<OffsetDateTime>> {
        parse_optional_timestamp(self.created_at.as_deref(), key_id, "created_at")
    }

    fn parsed_expires_at(&self, key_id: &str) -> Result<Option<OffsetDateTime>> {
        parse_optional_timestamp(self.expires_at.as_deref(), key_id, "expires_at")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct HistoricalVersionDocument {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    valid_until: Option<String>,
    #[serde(default)]
    seed: String,
}

impl HistoricalVersionDocument {
    fn to_key_version(&self, key_id: &str) -> Result<Option<KeyVersion>> {
        if self.kid.is_empty() || self.seed.is_empty() || self.public_key.is_empty() {
            return Ok(None);
        }
        let decoded_seed = STANDARD.decode(self.seed.as_bytes()).map_err(|err| {
            KmsError::Config(format!(
                "failed to decode historical seed for {}: {err}",
                key_id
            ))
        })?;
        if decoded_seed.len() != 32 {
            return Err(KmsError::Config(format!(
                "historical seed for {} must be 32 bytes",
                key_id
            )));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&decoded_seed);
        let decoded_public = STANDARD.decode(self.public_key.as_bytes()).map_err(|err| {
            KmsError::Config(format!(
                "failed to decode historical public key for {}: {err}",
                key_id
            ))
        })?;
        let public: [u8; 32] = decoded_public.as_slice().try_into().map_err(|_| {
            KmsError::Config(format!(
                "historical public key for {} must be 32 bytes",
                key_id
            ))
        })?;
        let valid_until =
            parse_optional_timestamp(self.valid_until.as_deref(), key_id, "valid_until")?;
        Ok(Some(KeyVersion {
            seed,
            public,
            kid: self.kid.clone(),
            created_at: OffsetDateTime::now_utc(),
            valid_until,
        }))
    }

    fn from_version(version: &KeyVersion) -> Self {
        Self {
            kid: version.kid.clone(),
            public_key: STANDARD.encode(version.public),
            valid_until: version.valid_until.map(format_timestamp),
            seed: STANDARD.encode(version.seed.as_ref()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
enum KeyPurpose {
    Ed25519Sign,
    Aes256Wrap,
}

fn parse_optional_timestamp(
    value: Option<&str>,
    key_id: &str,
    field: &str,
) -> Result<Option<OffsetDateTime>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map(Some)
        .map_err(|err| KmsError::Config(format!("invalid {field} timestamp for {key_id}: {err}")))
}

fn format_timestamp(ts: OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339 formatting")
}

fn saturating_seconds(start: OffsetDateTime, end: OffsetDateTime) -> u64 {
    let diff = end - start;
    if diff.is_negative() {
        0
    } else {
        diff.whole_seconds().try_into().unwrap_or(u64::MAX)
    }
}

fn reconstruct_rotation_config(
    policy: &RotationPolicy,
    reference: OffsetDateTime,
) -> RotationPolicyConfig {
    RotationPolicyConfig {
        auto_rotate: policy.auto_rotate(),
        expires_after_seconds: saturating_seconds(reference, policy.compute_expiration(reference)),
        grace_period_seconds: Some(saturating_seconds(
            reference,
            policy.compute_grace_deadline(reference),
        )),
    }
}

fn reconstruct_approval_config(policy: &ApprovalPolicy) -> ApprovalPolicyConfig {
    ApprovalPolicyConfig {
        required: policy.threshold() as u8,
        signers: policy
            .signer_ids()
            .map(|id| ApprovalSignerConfig {
                id: id.clone(),
                public_key: STANDARD
                    .encode(policy.verifying_key(id).expect("signer exists").as_bytes()),
            })
            .collect(),
    }
}
