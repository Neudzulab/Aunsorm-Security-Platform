use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_mdm::retention::{
    MismatchKind, RetentionPolicyEvaluation, RetentionPolicySnapshot, RetentionSync,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RetentionSyncFixture {
    baseline: RunFixture,
    drift: RunFixture,
}

#[derive(Debug, Deserialize)]
struct RunFixture {
    evaluated_at_ms: u64,
    snapshots: Vec<SnapshotFixture>,
}

#[derive(Debug, Deserialize)]
struct SnapshotFixture {
    org_scope: String,
    expected_policy_version: String,
    expected_calibration_ref: String,
    expected_travel_rule_bundle: String,
    #[serde(default)]
    quorum_policy_version: Option<String>,
    #[serde(default)]
    quorum_calibration_ref: Option<String>,
    #[serde(default)]
    quorum_travel_rule_bundle: Option<String>,
    #[serde(default)]
    fabric_calibration_ref: Option<String>,
}

impl From<SnapshotFixture> for RetentionPolicySnapshot {
    fn from(value: SnapshotFixture) -> Self {
        Self {
            org_scope: value.org_scope,
            expected_policy_version: value.expected_policy_version,
            expected_calibration_ref: value.expected_calibration_ref,
            expected_travel_rule_bundle: value.expected_travel_rule_bundle,
            quorum_policy_version: value.quorum_policy_version,
            quorum_calibration_ref: value.quorum_calibration_ref,
            quorum_travel_rule_bundle: value.quorum_travel_rule_bundle,
            fabric_calibration_ref: value.fabric_calibration_ref,
        }
    }
}

fn load_fixture() -> RetentionSyncFixture {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("data/blockchain/retention_sync_status.json");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read retention sync fixture {path:?}: {err}"));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("failed to parse retention sync fixture {path:?}: {err}"))
}

fn ms_to_system_time(value: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(value)
}

#[test]
fn retention_sync_last_run_timestamp_and_alarm_state() {
    let fixture = load_fixture();
    let mut sync = RetentionSync::new();

    let baseline_time = ms_to_system_time(fixture.baseline.evaluated_at_ms);
    let baseline_eval = RetentionPolicyEvaluation::from_snapshots(
        baseline_time,
        fixture
            .baseline
            .snapshots
            .into_iter()
            .map(RetentionPolicySnapshot::from),
    );
    sync.record_run(baseline_eval);
    assert_eq!(sync.last_success_at(), Some(baseline_time));
    assert_eq!(sync.last_run_at(), Some(baseline_time));
    assert!(!sync.alarm_is_active());
    let metric_reference = baseline_time + Duration::from_secs(120);
    assert_eq!(sync.seconds_since_last_success(metric_reference), Some(120));

    let drift_time = ms_to_system_time(fixture.drift.evaluated_at_ms);
    let drift_eval = RetentionPolicyEvaluation::from_snapshots(
        drift_time,
        fixture
            .drift
            .snapshots
            .into_iter()
            .map(RetentionPolicySnapshot::from),
    );
    sync.record_run(drift_eval);

    assert_eq!(sync.last_run_at(), Some(drift_time));
    assert_eq!(sync.last_success_at(), Some(baseline_time));
    assert!(sync.alarm_is_active());

    let alarm_snapshot = sync.retention_policy_alarm();
    assert!(alarm_snapshot.active);
    assert_eq!(alarm_snapshot.last_triggered_at, Some(drift_time));
    assert_eq!(alarm_snapshot.mismatches.len(), 3);
    assert!(alarm_snapshot
        .mismatches
        .iter()
        .any(
            |mismatch| mismatch.kind == MismatchKind::PolicyVersionMismatch
                && mismatch.org_scope == "vasp:apac:sg:014"
        ));
    assert!(alarm_snapshot
        .mismatches
        .iter()
        .any(|mismatch| mismatch.kind == MismatchKind::TravelRuleBundleMismatch));
    assert!(alarm_snapshot
        .mismatches
        .iter()
        .any(|mismatch| mismatch.kind == MismatchKind::MissingFabricAnchor));

    let minutes_after_alarm = drift_time + Duration::from_secs(60);
    assert_eq!(
        sync.seconds_since_last_success(minutes_after_alarm),
        Some(660)
    );
}
