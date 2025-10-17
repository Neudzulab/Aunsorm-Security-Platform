#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_jwt::{Ed25519KeyPair, Ed25519PublicKey, JwtError};
use ed25519_dalek::{Signature, Verifier};
use sha2::{Digest, Sha256};

const DEFAULT_CLOCK_SKEW_MS: u64 = 30_000;
const ANCHOR_CONTEXT: &[u8] = b"aunsorm-fabric-anchor:v1";

pub const FABRIC_POC_DID: &str = "did:fabric:testnet:aunsorm:device-root";
pub const FABRIC_POC_CONTROLLER: &str = "did:fabric:testnet:aunsorm:controller";
pub const FABRIC_POC_CHANNEL: &str = "aunsorm-channel";
pub const FABRIC_POC_METHOD_ID: &str = "did:fabric:testnet:aunsorm:device-root#key-1";
pub const FABRIC_POC_TRANSACTION_ID: &str = "b9f8a6d97f4c41b89f0dfcc0aunsorm";
pub const FABRIC_POC_MSP_ID: &str = "AUNSORMMSP";
pub const FABRIC_POC_SERVICE_ID: &str = "#ledger-audit";
pub const FABRIC_POC_SERVICE_ENDPOINT: &str = "https://api.aunsorm.local/blockchain/did";
pub const FABRIC_POC_KEY_SEED: [u8; 32] = [0x37; 32];
pub const FABRIC_POC_BLOCK_INDEX: u64 = 42;
pub const FABRIC_POC_ANCHOR_TIMESTAMP_MS: u64 = 1_728_000_200_000;

#[derive(Debug, Clone)]
pub struct FabricDidRegistry {
    documents: Arc<HashMap<String, FabricDidDocument>>,
    allowed_clock_skew_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FabricDidStatus {
    Active,
}

impl FabricDidStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FabricDidDocument {
    pub(crate) did: String,
    pub(crate) controller: String,
    pub(crate) channel: String,
    pub(crate) msp_id: String,
    pub(crate) status: FabricDidStatus,
    pub(crate) verification_method: FabricDidVerificationMethod,
    pub(crate) service: Option<FabricDidService>,
    pub(crate) anchor: FabricLedgerAnchor,
}

#[derive(Debug, Clone)]
pub struct FabricDidVerificationMethod {
    pub(crate) id: String,
    pub(crate) controller: String,
    pub(crate) r#type: &'static str,
    pub(crate) public_key: Ed25519PublicKey,
}

impl FabricDidVerificationMethod {
    pub const fn algorithm(&self) -> &'static str {
        self.r#type
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key.verifying_key().as_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct FabricDidService {
    pub(crate) id: String,
    pub(crate) r#type: &'static str,
    pub(crate) endpoint: String,
}

#[derive(Debug, Clone)]
pub struct FabricLedgerAnchor {
    pub(crate) block_index: u64,
    pub(crate) block_hash: [u8; 32],
    pub(crate) transaction_id: String,
    pub(crate) timestamp_ms: u64,
}

impl FabricLedgerAnchor {
    pub fn block_hash_hex(&self) -> String {
        hex::encode(self.block_hash)
    }
}

#[derive(Debug)]
pub struct FabricDidVerification<'a> {
    pub(crate) document: &'a FabricDidDocument,
    pub(crate) challenge: Vec<u8>,
    pub(crate) checked_at_ms: u64,
    pub(crate) clock_skew_ms: u64,
}

#[derive(Debug)]
pub enum FabricDidError {
    UnknownDid(String),
    ChannelMismatch { expected: String, found: String },
    BlockHashMismatch { expected: [u8; 32], found: [u8; 32] },
    TransactionMismatch { expected: String, found: String },
    ChallengeMismatch,
    SignatureInvalid,
    Clock(std::time::SystemTimeError),
    ClockOverflow,
    ClockSkew { delta_ms: u64, allowed_ms: u64 },
}

impl From<std::time::SystemTimeError> for FabricDidError {
    fn from(value: std::time::SystemTimeError) -> Self {
        Self::Clock(value)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FabricDidVerificationRequest<'a> {
    pub did: &'a str,
    pub channel: &'a str,
    pub block_hash: [u8; 32],
    pub transaction_id: &'a str,
    pub timestamp_ms: u64,
    pub challenge: &'a [u8],
    pub signature: [u8; 64],
}

impl FabricDidRegistry {
    pub fn poc() -> Result<Self, JwtError> {
        let mut documents = HashMap::new();
        let key_pair = Ed25519KeyPair::from_seed(FABRIC_POC_METHOD_ID, FABRIC_POC_KEY_SEED)?;
        let mut hasher = Sha256::new();
        hasher.update(ANCHOR_CONTEXT);
        hasher.update(FABRIC_POC_TRANSACTION_ID.as_bytes());
        hasher.update(FABRIC_POC_KEY_SEED);
        let block_hash: [u8; 32] = hasher.finalize().into();
        let document = FabricDidDocument {
            did: FABRIC_POC_DID.to_owned(),
            controller: FABRIC_POC_CONTROLLER.to_owned(),
            channel: FABRIC_POC_CHANNEL.to_owned(),
            msp_id: FABRIC_POC_MSP_ID.to_owned(),
            status: FabricDidStatus::Active,
            verification_method: FabricDidVerificationMethod {
                id: FABRIC_POC_METHOD_ID.to_owned(),
                controller: FABRIC_POC_CONTROLLER.to_owned(),
                r#type: "Ed25519VerificationKey2018",
                public_key: key_pair.public_key(),
            },
            service: Some(FabricDidService {
                id: FABRIC_POC_SERVICE_ID.to_owned(),
                r#type: "LedgerAuditChannel",
                endpoint: FABRIC_POC_SERVICE_ENDPOINT.to_owned(),
            }),
            anchor: FabricLedgerAnchor {
                block_index: FABRIC_POC_BLOCK_INDEX,
                block_hash,
                transaction_id: FABRIC_POC_TRANSACTION_ID.to_owned(),
                timestamp_ms: FABRIC_POC_ANCHOR_TIMESTAMP_MS,
            },
        };
        documents.insert(document.did.clone(), document);
        Ok(Self {
            documents: Arc::new(documents),
            allowed_clock_skew_ms: DEFAULT_CLOCK_SKEW_MS,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn document(&self, did: &str) -> Option<&FabricDidDocument> {
        self.documents.get(did)
    }

    pub fn verify<'a>(
        &'a self,
        request: FabricDidVerificationRequest<'_>,
    ) -> Result<FabricDidVerification<'a>, FabricDidError> {
        let document = self
            .documents
            .get(request.did)
            .ok_or_else(|| FabricDidError::UnknownDid(request.did.to_owned()))?;
        if document.channel != request.channel {
            return Err(FabricDidError::ChannelMismatch {
                expected: document.channel.clone(),
                found: request.channel.to_owned(),
            });
        }
        if document.anchor.block_hash != request.block_hash {
            return Err(FabricDidError::BlockHashMismatch {
                expected: document.anchor.block_hash,
                found: request.block_hash,
            });
        }
        if document.anchor.transaction_id != request.transaction_id {
            return Err(FabricDidError::TransactionMismatch {
                expected: document.anchor.transaction_id.clone(),
                found: request.transaction_id.to_owned(),
            });
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let now_ms = checked_millis(now).ok_or(FabricDidError::ClockOverflow)?;
        let delta = now_ms.abs_diff(request.timestamp_ms);
        if delta > self.allowed_clock_skew_ms {
            return Err(FabricDidError::ClockSkew {
                delta_ms: delta,
                allowed_ms: self.allowed_clock_skew_ms,
            });
        }
        let block_hash_hex = document.anchor.block_hash_hex();
        let canonical = canonical_challenge(request.did, &block_hash_hex, request.timestamp_ms);
        if request.challenge != canonical.as_slice() {
            return Err(FabricDidError::ChallengeMismatch);
        }
        let signature = Signature::from_bytes(&request.signature);
        document
            .verification_method
            .public_key
            .verifying_key()
            .verify(&canonical, &signature)
            .map_err(|_| FabricDidError::SignatureInvalid)?;
        Ok(FabricDidVerification {
            document,
            challenge: canonical,
            checked_at_ms: now_ms,
            clock_skew_ms: delta,
        })
    }
}

pub fn canonical_challenge(did: &str, block_hash_hex: &str, timestamp_ms: u64) -> Vec<u8> {
    format!("{did}|{block_hash_hex}|{timestamp_ms}").into_bytes()
}

fn checked_millis(duration: Duration) -> Option<u64> {
    duration
        .as_secs()
        .checked_mul(1_000)?
        .checked_add(u64::from(duration.subsec_millis()))
}
