use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Metadata emitted when a customer-specific key destroy operation is recorded on-chain.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct KmsDestroyEvent {
    pub network: String,
    pub tx: String,
    pub block: u64,
    pub timestamp_ms: u64,
    pub reason: String,
}

/// Quorum `AuditAssetRegistry::mint` metadata associated with a retention policy.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AuditAssetRecord {
    pub tx: String,
    pub block: u64,
    pub timestamp_ms: u64,
    pub calibration_ref: String,
    pub retention_policy_version: String,
    pub travel_rule_bundle: String,
}

/// Fabric anchor that mirrors the retention policy update for auditability.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct FabricRetentionAnchor {
    pub channel: String,
    pub tx: String,
    pub block: u64,
}

/// Deterministic record tying retention policies to blockchain artefacts.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RetentionAuditRecord {
    pub org_scope: String,
    pub retention_policy_version: String,
    pub policy_hash: String,
    pub calibration_ref: String,
    pub travel_rule_bundle: String,
    pub kms_destroy_event: KmsDestroyEvent,
    pub audit_asset: AuditAssetRecord,
    pub fabric_retention_anchor: FabricRetentionAnchor,
}

impl RetentionAuditRecord {
    /// Returns the deterministic hash derived from the organisation scope and policy version.
    #[must_use]
    pub fn derived_policy_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.org_scope.as_bytes());
        hasher.update(b":");
        hasher.update(self.retention_policy_version.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Loads the retention audit dataset from disk.
///
/// # Panics
/// Panics if the fixture file cannot be read or parsed as valid JSON.
#[must_use]
pub fn load_retention_audit_records() -> Vec<RetentionAuditRecord> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("data/blockchain/retention_policy_audit.json");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read retention fixture {path:?}: {err}"));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("failed to parse retention fixture {path:?}: {err}"))
}
