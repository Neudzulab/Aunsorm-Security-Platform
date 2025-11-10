use std::collections::HashMap;
use std::env;
use std::io;
use std::sync::Mutex;

use aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cryptoki::context::Pkcs11;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::approval::{ApprovalPolicy, ApprovalPolicyConfig};
use crate::config::{BackendKind, Pkcs11BackendConfig, Pkcs11KeyConfig};
use crate::error::{KmsError, Result};
use crate::rng::create_aunsorm_rng;
use crate::rotation::{RotationEvent, RotationPolicy, RotationPolicyConfig};
use crate::util::compute_kid;
use rand_core::RngCore;

const PKCS11_WRAP_KEY_ENV: &str = "AUNSORM_KMS_PKCS11_WRAP_KEY";

pub struct Pkcs11Backend {
    hardware: Option<HardwareContext>,
    wrap_key: Option<Zeroizing<[u8; 32]>>,
    keys: Mutex<HashMap<String, Pkcs11Key>>,
}

struct HardwareContext {
    _context: Pkcs11,
    session: Mutex<Session>,
}

struct Pkcs11Key {
    active: KeyVersion,
    previous: Option<KeyVersion>,
    policy: Option<RotationPolicy>,
    policy_config: Option<RotationPolicyConfig>,
    approvals: Option<ApprovalPolicy>,
    approval_config: Option<ApprovalPolicyConfig>,
}

#[derive(Clone)]
struct KeyVersion {
    source: SigningSource,
    public: [u8; 32],
    kid: String,
    created_at: OffsetDateTime,
    valid_until: Option<OffsetDateTime>,
}

enum SigningSource {
    Software(Zeroizing<[u8; 32]>),
    Hardware(cryptoki::object::ObjectHandle),
}

impl Pkcs11Backend {
    pub fn new(config: Pkcs11BackendConfig, strict: bool) -> Result<Self> {
        let wrap_key = if config.keys.iter().any(|key| key.wrapped_seed.is_some()) {
            Some(load_wrap_key()?)
        } else {
            None
        };
        let hardware = if let Some(module) = config.module.as_deref() {
            Some(initialize_hardware(module, &config)?)
        } else {
            None
        };
        let mut entries = HashMap::new();
        for key_cfg in config.keys {
            let key_id = key_cfg.key_id.trim();
            if key_id.is_empty() {
                return Err(KmsError::Config("pkcs11 key_id cannot be empty".into()));
            }
            if entries.contains_key(key_id) {
                return Err(KmsError::Config(format!(
                    "duplicate pkcs11 key identifier detected: {key_id}"
                )));
            }
            let entry = build_key_entry(
                key_id,
                &key_cfg,
                strict,
                hardware.as_ref(),
                wrap_key.as_ref(),
            )?;
            entries.insert(key_id.to_string(), entry);
        }
        Ok(Self {
            hardware,
            wrap_key,
            keys: Mutex::new(entries),
        })
    }

    pub fn sign_ed25519(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let mut keys = self.keys.lock().map_err(|err| {
            let io_err = io::Error::new(io::ErrorKind::Other, err.to_string());
            KmsError::unavailable(BackendKind::Pkcs11, io_err)
        })?;
        let entry = keys.get_mut(key_id).ok_or_else(|| KmsError::KeyNotFound {
            backend: BackendKind::Pkcs11,
            key_id: key_id.to_string(),
        })?;
        auto_rotate_if_needed(
            entry,
            key_id,
            self.hardware.as_ref(),
            self.wrap_key.as_ref(),
        )?;
        sign_with_source(&entry.active.source, message, self.hardware.as_ref())
    }

    pub fn public_ed25519(&self, key_id: &str) -> Result<Vec<u8>> {
        let keys = self.keys.lock().map_err(|err| {
            let io_err = io::Error::new(io::ErrorKind::Other, err.to_string());
            KmsError::unavailable(BackendKind::Pkcs11, io_err)
        })?;
        let entry = keys.get(key_id).ok_or_else(|| KmsError::KeyNotFound {
            backend: BackendKind::Pkcs11,
            key_id: key_id.to_string(),
        })?;
        Ok(entry.active.public.to_vec())
    }

    pub fn public_ed25519_versions(&self, key_id: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let keys = self.keys.lock().map_err(|err| {
            let io_err = io::Error::new(io::ErrorKind::Other, err.to_string());
            KmsError::unavailable(BackendKind::Pkcs11, io_err)
        })?;
        let entry = keys.get(key_id).ok_or_else(|| KmsError::KeyNotFound {
            backend: BackendKind::Pkcs11,
            key_id: key_id.to_string(),
        })?;
        let mut versions = vec![(entry.active.kid.clone(), entry.active.public.to_vec())];
        if let Some(previous) = &entry.previous {
            versions.push((previous.kid.clone(), previous.public.to_vec()));
        }
        Ok(versions)
    }

    pub fn key_kid(&self, key_id: &str) -> Result<String> {
        let keys = self
            .keys
            .lock()
            .map_err(|err| KmsError::unavailable(BackendKind::Pkcs11, err))?;
        let entry = keys.get(key_id).ok_or_else(|| KmsError::KeyNotFound {
            backend: BackendKind::Pkcs11,
            key_id: key_id.to_string(),
        })?;
        Ok(entry.active.kid.clone())
    }

    pub fn rotate_ed25519(
        &self,
        key_id: &str,
        approvals: &crate::approval::ApprovalBundle,
        strict: bool,
    ) -> Result<RotationEvent> {
        let mut keys = self.keys.lock().map_err(|err| {
            let io_err = io::Error::new(io::ErrorKind::Other, err.to_string());
            KmsError::unavailable(BackendKind::Pkcs11, io_err)
        })?;
        let entry = keys.get_mut(key_id).ok_or_else(|| KmsError::KeyNotFound {
            backend: BackendKind::Pkcs11,
            key_id: key_id.to_string(),
        })?;
        if let Some(policy) = entry.approvals.clone() {
            let message = format!("{}:{}", approvals.operation(), key_id).into_bytes();
            approvals.verify(&message, &policy)?;
        } else if strict {
            return Err(KmsError::Approval(format!(
                "approval policy required for pkcs11 key {key_id}"
            )));
        }
        rotate_entry(
            entry,
            key_id,
            self.hardware.as_ref(),
            self.wrap_key.as_ref(),
        )
    }
}

type KeyEntryResult = Result<Pkcs11Key>;

type SharedHardware<'a> = Option<&'a HardwareContext>;

type SharedWrap<'a> = Option<&'a Zeroizing<[u8; 32]>>;

fn build_key_entry(
    key_id: &str,
    config: &Pkcs11KeyConfig,
    strict: bool,
    hardware: SharedHardware,
    wrap_key: SharedWrap,
) -> KeyEntryResult {
    let metadata = config.rotation.clone();
    let policy_config = metadata.clone();
    let rotation_policy = config
        .rotation
        .as_ref()
        .map(RotationPolicy::from_config)
        .transpose()?;
    let approval_config = config.approvals.clone();
    let approvals = approval_config
        .as_ref()
        .map(ApprovalPolicy::from_config)
        .transpose()?;
    let created_at = OffsetDateTime::now_utc();
    let (source, public) = match (
        config.wrapped_seed.as_ref(),
        config.label.as_ref(),
        hardware,
    ) {
        (Some(seed), _, _) => {
            let wrap_key = wrap_key.ok_or_else(|| {
                KmsError::Config("AUNSORM_KMS_PKCS11_WRAP_KEY must be set for wrapped seeds".into())
            })?;
            let seed_bytes = unwrap_seed(wrap_key, seed, key_id)?;
            let signing = SigningKey::from_bytes(&seed_bytes);
            let public = VerifyingKey::from(&signing).to_bytes();
            (SigningSource::Software(seed_bytes), public)
        }
        (None, Some(label), Some(hw)) => {
            let handle = find_private_key(&hw.session, label).map_err(|err| {
                KmsError::Hsm(format!("failed to locate pkcs11 key {key_id}: {err}"))
            })?;
            let public = if let Some(public_b64) = &config.public_key {
                decode_public(public_b64, key_id)?
            } else if strict {
                return Err(KmsError::Config(format!(
                    "strict mode requires public_key for pkcs11 key {key_id}"
                )));
            } else {
                read_public_key(&hw.session, handle).map_err(|err| {
                    KmsError::Hsm(format!("failed to read public key for {key_id}: {err}"))
                })?
            };
            (SigningSource::Hardware(handle), public)
        }
        _ => {
            return Err(KmsError::Config(format!(
                "pkcs11 key {key_id} requires wrapped_seed or label"
            )))
        }
    };
    let kid = config.kid.clone().unwrap_or_else(|| compute_kid(&public));
    let active = KeyVersion {
        source,
        public,
        kid,
        created_at,
        valid_until: rotation_policy
            .as_ref()
            .map(|policy| policy.compute_expiration(created_at)),
    };
    Ok(Pkcs11Key {
        active,
        previous: None,
        policy: rotation_policy,
        policy_config,
        approvals,
        approval_config,
    })
}

fn auto_rotate_if_needed(
    entry: &mut Pkcs11Key,
    key_id: &str,
    hardware: SharedHardware,
    wrap_key: SharedWrap,
) -> Result<()> {
    let Some(policy) = entry.policy.clone() else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    if entry
        .active
        .valid_until
        .map(|deadline| now < deadline)
        .unwrap_or_else(|| !policy.is_expired(entry.active.created_at, now))
    {
        return Ok(());
    }
    if matches!(entry.active.source, SigningSource::Hardware(_)) {
        return Err(KmsError::Rotation(format!(
            "automatic rotation is not supported for hardware-bound key {key_id}"
        )));
    }
    rotate_entry(entry, key_id, hardware, wrap_key).map(|_| ())
}

fn rotate_entry(
    entry: &mut Pkcs11Key,
    key_id: &str,
    hardware: SharedHardware,
    wrap_key: SharedWrap,
) -> Result<RotationEvent> {
    let now = OffsetDateTime::now_utc();
    match entry.active.source {
        SigningSource::Hardware(_) => {
            return Err(KmsError::Rotation(format!(
                "hardware key {key_id} requires external rotation workflow"
            )))
        }
        SigningSource::Software(_) => {}
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    crate::rng::create_aunsorm_rng().fill_bytes(seed.as_mut());
    let signing = SigningKey::from_bytes(&seed);
    let public = VerifyingKey::from(&signing).to_bytes();
    let kid = compute_kid(&public);
    let new_version = KeyVersion {
        source: SigningSource::Software(seed.clone()),
        public,
        kid: kid.clone(),
        created_at: now,
        valid_until: entry
            .policy
            .as_ref()
            .map(|policy| policy.compute_expiration(now)),
    };
    let grace_deadline = entry
        .policy
        .as_ref()
        .map(|policy| policy.compute_grace_deadline(now));
    let mut previous = entry.active.clone();
    previous.valid_until = grace_deadline;
    entry.previous = Some(previous);
    entry.active = new_version;
    Ok(RotationEvent::new(
        key_id,
        entry.previous.as_ref().map(|prev| prev.kid.clone()),
        kid,
        now,
        grace_deadline,
    ))
}

fn sign_with_source(
    source: &SigningSource,
    message: &[u8],
    hardware: SharedHardware,
) -> Result<Vec<u8>> {
    match source {
        SigningSource::Software(seed) => {
            let signing = SigningKey::from_bytes(seed);
            Ok(signing.sign(message).to_vec())
        }
        SigningSource::Hardware(handle) => {
            let hw =
                hardware.ok_or_else(|| KmsError::Hsm("hardware session not configured".into()))?;
            let session = hw.session.lock().map_err(|err| {
                let io_err = io::Error::new(io::ErrorKind::Other, err.to_string());
                KmsError::unavailable(BackendKind::Pkcs11, io_err)
            })?;
            session
                .sign(&Mechanism::Eddsa, *handle, message)
                .map_err(|err| KmsError::Hsm(format!("pkcs11 sign failed: {err}")))
        }
    }
}

fn initialize_hardware(module: &str, config: &Pkcs11BackendConfig) -> Result<HardwareContext> {
    let pkcs11 = Pkcs11::new(module)
        .map_err(|err| KmsError::Hsm(format!("failed to load pkcs11 module {module}: {err}")))?;
    pkcs11
        .initialize(Default::default())
        .map_err(|err| KmsError::Hsm(format!("pkcs11 initialize failed: {err}")))?;
    let slots = pkcs11
        .get_slot_list(true)
        .map_err(|err| KmsError::Hsm(format!("pkcs11 get_slot_list failed: {err}")))?;
    let slot = select_slot(&pkcs11, &slots, config)?;
    let session = pkcs11
        .open_rw_session(slot)
        .map_err(|err| KmsError::Hsm(format!("pkcs11 open session failed: {err}")))?;
    if let Some(pin_env) = config.user_pin_env.as_deref() {
        let pin = env::var(pin_env).map_err(|_| {
            KmsError::Config(format!("missing pkcs11 pin environment variable {pin_env}"))
        })?;
        session
            .login(UserType::User, Some(&AuthPin::new(pin.into())))
            .map_err(|err| KmsError::Hsm(format!("pkcs11 login failed: {err}")))?;
    }
    Ok(HardwareContext {
        _context: pkcs11,
        session: Mutex::new(session),
    })
}

fn select_slot(pkcs11: &Pkcs11, slots: &[Slot], config: &Pkcs11BackendConfig) -> Result<Slot> {
    if let Some(index) = config.slot {
        slots
            .get(index as usize)
            .copied()
            .ok_or_else(|| KmsError::Hsm(format!("pkcs11 slot index {index} not available")))
    } else if let Some(label) = &config.token_label {
        for slot in slots {
            let info = pkcs11
                .get_token_info(*slot)
                .map_err(|err| KmsError::Hsm(format!("pkcs11 token info failed: {err}")))?;
            if info.label().trim() == label.trim() {
                return Ok(*slot);
            }
        }
        Err(KmsError::Hsm(format!(
            "pkcs11 token with label {} not found",
            label
        )))
    } else {
        slots
            .first()
            .copied()
            .ok_or_else(|| KmsError::Hsm("pkcs11 module exposes no slots".into()))
    }
}

fn find_private_key(
    session: &Mutex<Session>,
    label: &str,
) -> Result<cryptoki::object::ObjectHandle> {
    let mut session = session.lock().map_err(|err| {
        let io_err = io::Error::new(io::ErrorKind::Other, err.to_string());
        KmsError::unavailable(BackendKind::Pkcs11, io_err)
    })?;
    let template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    session
        .find_objects_init(&template)
        .map_err(|err| KmsError::Hsm(format!("pkcs11 find_objects_init failed: {err}")))?;
    let objects = session
        .find_objects(1)
        .map_err(|err| KmsError::Hsm(format!("pkcs11 find_objects failed: {err}")))?;
    session
        .find_objects_final()
        .map_err(|err| KmsError::Hsm(format!("pkcs11 find_objects_final failed: {err}")))?;
    objects
        .into_iter()
        .next()
        .ok_or_else(|| KmsError::Hsm(format!("pkcs11 key with label {label} not found")))
}

fn read_public_key(
    session: &Mutex<Session>,
    handle: cryptoki::object::ObjectHandle,
) -> Result<[u8; 32]> {
    let session = session.lock().map_err(|err| {
        let io_err = io::Error::new(io::ErrorKind::Other, err.to_string());
        KmsError::unavailable(BackendKind::Pkcs11, io_err)
    })?;
    let attributes = session
        .get_attributes(handle, &[AttributeType::EcPoint])
        .map_err(|err| KmsError::Hsm(format!("pkcs11 get_attributes failed: {err}")))?;
    let Attribute::EcPoint(point) = &attributes[0] else {
        return Err(KmsError::Hsm("pkcs11 ec point missing".into()));
    };
    extract_ed25519_public(point, |msg| KmsError::Hsm(msg.into()))
}

fn extract_ed25519_public<F>(data: &[u8], err: F) -> Result<[u8; 32]>
where
    F: Fn(String) -> KmsError,
{
    fn decode_length(bytes: &[u8]) -> Option<(usize, usize)> {
        let first = *bytes.first()?;
        if first & 0x80 == 0 {
            Some((first as usize, 1))
        } else {
            let count = (first & 0x7F) as usize;
            if count == 0 || bytes.len() < 1 + count {
                return None;
            }
            let mut length = 0usize;
            for &byte in &bytes[1..=count] {
                length = (length << 8) | usize::from(byte);
            }
            Some((length, 1 + count))
        }
    }

    fn parse_octet<'a, F>(input: &'a [u8], err: &F) -> Result<&'a [u8]>
    where
        F: Fn(String) -> KmsError,
    {
        if input.is_empty() {
            return Err(err("ec point encoding missing tag".into()));
        }
        if input[0] != 0x04 {
            return Err(err("ec point must be DER OCTET STRING".into()));
        }
        let (len, header) =
            decode_length(&input[1..]).ok_or_else(|| err("invalid ec point length".into()))?;
        let start = 1 + header;
        let end = start + len;
        if end > input.len() {
            return Err(err("ec point length exceeds buffer".into()));
        }
        Ok(&input[start..end])
    }

    let mut current = parse_octet(data, &err)?;
    if current.len() != 32 && current.first() == Some(&0x04) {
        current = parse_octet(current, &err)?;
    }
    current
        .try_into()
        .map_err(|_| err("ed25519 public key must be 32 bytes".into()))
}

fn load_wrap_key() -> Result<Zeroizing<[u8; 32]>> {
    let raw = env::var(PKCS11_WRAP_KEY_ENV).map_err(|_| {
        KmsError::Config(format!(
            "{PKCS11_WRAP_KEY_ENV} must be set for pkcs11 wrapped seeds"
        ))
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(KmsError::Config(format!(
            "{PKCS11_WRAP_KEY_ENV} cannot be empty"
        )));
    }
    let decoded = STANDARD.decode(trimmed.as_bytes()).map_err(|err| {
        KmsError::Config(format!("failed to decode {PKCS11_WRAP_KEY_ENV}: {err}"))
    })?;
    if decoded.len() != 32 {
        return Err(KmsError::Config(format!(
            "{PKCS11_WRAP_KEY_ENV} must decode to 32 bytes"
        )));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn unwrap_seed(
    wrap_key: &Zeroizing<[u8; 32]>,
    wrapped: &str,
    key_id: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = STANDARD.decode(wrapped.as_bytes()).map_err(|err| {
        KmsError::Config(format!("failed to decode wrapped seed for {key_id}: {err}"))
    })?;
    if bytes.len() < 12 {
        return Err(KmsError::Config(format!(
            "wrapped seed for {key_id} must include 12-byte nonce"
        )));
    }
    let (nonce_bytes, ciphertext) = bytes.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(wrap_key.as_ref())
        .map_err(|err| KmsError::Config(format!("invalid pkcs11 wrap key: {err}")))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: key_id.as_bytes(),
            },
        )
        .map_err(|err| KmsError::Config(format!("failed to unwrap seed for {key_id}: {err}")))?;
    if plaintext.len() != 32 {
        return Err(KmsError::Config(format!(
            "unwrapped seed for {key_id} must be 32 bytes"
        )));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

fn decode_public(value: &str, key_id: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD.decode(value.as_bytes()).map_err(|err| {
        KmsError::Config(format!(
            "failed to decode pkcs11 public key for {key_id}: {err}"
        ))
    })?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| KmsError::Config(format!("pkcs11 public key for {key_id} must be 32 bytes")))
}
