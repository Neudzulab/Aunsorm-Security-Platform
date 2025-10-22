#[path = "../blockchain/retention_audit.rs"]
mod retention_audit;

use std::collections::HashSet;

use retention_audit::load_retention_audit_records;

#[test]
fn policy_hashes_and_metadata_align() {
    let records = load_retention_audit_records();
    for record in &records {
        assert_eq!(
            record.policy_hash,
            record.derived_policy_hash(),
            "policy hash mismatch for {}",
            record.org_scope
        );
        assert_eq!(
            record.audit_asset.retention_policy_version,
            record.retention_policy_version
        );
        assert_eq!(record.audit_asset.calibration_ref, record.calibration_ref);
        assert_eq!(
            record.audit_asset.travel_rule_bundle,
            record.travel_rule_bundle
        );
        assert!(!record.kms_destroy_event.reason.is_empty());
    }
}

#[test]
fn kms_destroy_events_precede_audit_asset_mints() {
    let records = load_retention_audit_records();
    for record in &records {
        assert!(
            record.kms_destroy_event.timestamp_ms <= record.audit_asset.timestamp_ms,
            "KMS destroy event must occur before audit asset mint"
        );
        assert!(
            record.kms_destroy_event.block <= record.audit_asset.block,
            "KMS destroy block height must not exceed audit asset block"
        );
        assert_eq!(record.kms_destroy_event.network, "quorum-istanbul");
        assert!(record.kms_destroy_event.tx.starts_with("0x"));
        assert!(record.audit_asset.tx.starts_with("0x"));
        assert_eq!(
            record.audit_asset.retention_policy_version,
            record.retention_policy_version
        );
        assert_eq!(record.fabric_retention_anchor.channel, "ops.retention");
        assert!(
            record.fabric_retention_anchor.block < record.audit_asset.block,
            "Fabric anchor should land before Quorum mint"
        );
    }
}

#[test]
fn travel_rule_bundles_and_calibration_refs_are_unique() {
    let records = load_retention_audit_records();
    let mut bundles = HashSet::new();
    let mut calibrations = HashSet::new();
    for record in &records {
        assert!(
            bundles.insert(record.travel_rule_bundle.clone()),
            "duplicate travel rule bundle: {}",
            record.travel_rule_bundle
        );
        assert!(
            calibrations.insert(record.calibration_ref.clone()),
            "duplicate calibration ref: {}",
            record.calibration_ref
        );
        assert_eq!(record.policy_hash.len(), 64);
        assert!(record.policy_hash.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(record.kms_destroy_event.tx.len(), 66);
        assert!(record
            .kms_destroy_event
            .tx
            .chars()
            .skip(2)
            .all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(record.audit_asset.tx.len(), 66);
        assert!(record
            .audit_asset
            .tx
            .chars()
            .skip(2)
            .all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(record.fabric_retention_anchor.tx.len(), 64);
        assert!(record
            .fabric_retention_anchor
            .tx
            .chars()
            .all(|ch| ch.is_ascii_hexdigit()));
    }
    assert_eq!(bundles.len(), records.len());
    assert_eq!(calibrations.len(), records.len());
}
