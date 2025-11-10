use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{KmsError, Result};

/// Runtime representation of a multi-signature approval policy.
#[derive(Debug, Clone)]
pub struct ApprovalPolicy {
    threshold: usize,
    signers: HashMap<String, VerifyingKey>,
}

impl ApprovalPolicy {
    /// Constructs a policy from configuration.
    pub fn from_config(config: &ApprovalPolicyConfig) -> Result<Self> {
        if config.required == 0 {
            return Err(KmsError::Approval(
                "approval policy must require at least one signature".into(),
            ));
        }
        if config.signers.is_empty() {
            return Err(KmsError::Approval(
                "approval policy requires at least one signer".into(),
            ));
        }
        if usize::from(config.required) > config.signers.len() {
            return Err(KmsError::Approval(
                "approval threshold cannot exceed signer list".into(),
            ));
        }
        let mut signers = HashMap::with_capacity(config.signers.len());
        for signer in &config.signers {
            if signer.id.trim().is_empty() {
                return Err(KmsError::Approval(
                    "approval signer id cannot be empty".into(),
                ));
            }
            if signers.contains_key(&signer.id) {
                return Err(KmsError::Approval(format!(
                    "duplicate approval signer id detected: {}",
                    signer.id
                )));
            }
            let decoded = STANDARD
                .decode(signer.public_key.as_bytes())
                .map_err(|err| {
                    KmsError::Approval(format!(
                        "invalid approval signer public key for {}: {err}",
                        signer.id
                    ))
                })?;
            let verifying_key =
                VerifyingKey::from_bytes(decoded.as_slice().try_into().map_err(|_| {
                    KmsError::Approval(format!(
                        "approval signer public key for {} must be 32 bytes",
                        signer.id
                    ))
                })?)
                .map_err(|err| {
                    KmsError::Approval(format!(
                        "invalid approval signer key for {}: {err}",
                        signer.id
                    ))
                })?;
            signers.insert(signer.id.clone(), verifying_key);
        }
        Ok(Self {
            threshold: usize::from(config.required),
            signers,
        })
    }

    /// Returns approval threshold.
    pub const fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns the list of signer identifiers.
    pub fn signer_ids(&self) -> impl Iterator<Item = &String> {
        self.signers.keys()
    }

    /// Resolves a verifying key for a signer.
    pub fn verifying_key(&self, signer_id: &str) -> Option<&VerifyingKey> {
        self.signers.get(signer_id)
    }
}

/// Declarative configuration for an approval policy.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApprovalPolicyConfig {
    pub required: u8,
    #[serde(default)]
    pub signers: Vec<ApprovalSignerConfig>,
}

/// Individual signer configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApprovalSignerConfig {
    pub id: String,
    pub public_key: String,
}

/// Signature bundle presented when performing a privileged operation.
#[derive(Debug, Clone)]
pub struct ApprovalBundle {
    operation: String,
    signatures: Vec<ApprovalSignature>,
    expires_at: Option<i64>,
}

impl ApprovalBundle {
    /// Creates a new bundle.
    #[must_use]
    pub fn new(
        operation: impl Into<String>,
        signatures: Vec<ApprovalSignature>,
        expires_at: Option<i64>,
    ) -> Self {
        Self {
            operation: operation.into(),
            signatures,
            expires_at,
        }
    }

    /// Operation name associated with bundle.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Verifies bundle against policy and message to be signed.
    pub fn verify(&self, message: &[u8], policy: &ApprovalPolicy) -> Result<()> {
        if let Some(expiration) = self.expires_at {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            if now > expiration {
                return Err(KmsError::Approval("approval bundle expired".into()));
            }
        }
        if self.signatures.is_empty() {
            return Err(KmsError::Approval(
                "approval bundle contains no signatures".into(),
            ));
        }
        let mut verified: HashSet<String> = HashSet::new();
        for signature in &self.signatures {
            if verified.contains(signature.signer_id()) {
                continue;
            }
            let signer_id = signature.signer_id();
            let Some(verifying_key) = policy.verifying_key(signer_id) else {
                return Err(KmsError::Approval(format!(
                    "unknown approval signer: {}",
                    signer_id
                )));
            };
            let signature_bytes: [u8; 64] = signature
                .signature()
                .try_into()
                .map_err(|_| KmsError::Approval("invalid approval signature length".into()))?;
            let signature = Signature::from(signature_bytes);
            verifying_key
                .verify(message, &signature)
                .map_err(|_| KmsError::Approval("approval signature verification failed".into()))?;
            verified.insert(signer_id.to_string());
            if verified.len() >= policy.threshold() {
                return Ok(());
            }
        }
        Err(KmsError::Approval("insufficient approvals provided".into()))
    }
}

/// Individual approval signature entry.
#[derive(Debug, Clone)]
pub struct ApprovalSignature {
    signer_id: String,
    signature: Vec<u8>,
}

impl ApprovalSignature {
    /// Constructs a new approval signature entry.
    #[must_use]
    pub fn new(signer_id: impl Into<String>, signature: Vec<u8>) -> Self {
        Self {
            signer_id: signer_id.into(),
            signature,
        }
    }

    /// Returns signer identifier.
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// Returns raw signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}
