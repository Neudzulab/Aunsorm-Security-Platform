use std::time::SystemTime;

/// Snapshot of expected and observed retention policy signals for an organisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicySnapshot {
    pub org_scope: String,
    pub expected_policy_version: String,
    pub expected_calibration_ref: String,
    pub expected_travel_rule_bundle: String,
    pub quorum_policy_version: Option<String>,
    pub quorum_calibration_ref: Option<String>,
    pub quorum_travel_rule_bundle: Option<String>,
    pub fabric_calibration_ref: Option<String>,
}

impl RetentionPolicySnapshot {
    #[must_use]
    pub fn with_quorum_policy_version(mut self, value: Option<String>) -> Self {
        self.quorum_policy_version = value;
        self
    }

    #[must_use]
    pub fn with_quorum_calibration_ref(mut self, value: Option<String>) -> Self {
        self.quorum_calibration_ref = value;
        self
    }

    #[must_use]
    pub fn with_quorum_travel_rule_bundle(mut self, value: Option<String>) -> Self {
        self.quorum_travel_rule_bundle = value;
        self
    }

    #[must_use]
    pub fn with_fabric_calibration_ref(mut self, value: Option<String>) -> Self {
        self.fabric_calibration_ref = value;
        self
    }
}

/// Specific failure modes observed while reconciling retention policy state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MismatchKind {
    MissingLedgerPolicy,
    PolicyVersionMismatch,
    CalibrationRefMismatch,
    TravelRuleBundleMismatch,
    MissingFabricAnchor,
}

/// Structured description of a detected mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMismatch {
    pub org_scope: String,
    pub kind: MismatchKind,
    pub expected: String,
    pub observed: Option<String>,
    pub evidence_source: String,
}

impl PolicyMismatch {
    #[must_use]
    pub fn new(
        org_scope: impl Into<String>,
        kind: MismatchKind,
        expected: impl Into<String>,
        observed: Option<impl Into<String>>,
        evidence_source: impl Into<String>,
    ) -> Self {
        Self {
            org_scope: org_scope.into(),
            kind,
            expected: expected.into(),
            observed: observed.map(Into::into),
            evidence_source: evidence_source.into(),
        }
    }
}

/// Result of evaluating a batch of retention policy snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicyEvaluation {
    evaluated_at: SystemTime,
    mismatches: Vec<PolicyMismatch>,
}

impl RetentionPolicyEvaluation {
    #[must_use]
    pub fn from_snapshots(
        evaluated_at: SystemTime,
        snapshots: impl IntoIterator<Item = RetentionPolicySnapshot>,
    ) -> Self {
        let mut mismatches = Vec::new();
        for snapshot in snapshots {
            match snapshot.quorum_policy_version {
                Some(ref observed) if observed == &snapshot.expected_policy_version => {}
                Some(observed) => mismatches.push(PolicyMismatch::new(
                    &snapshot.org_scope,
                    MismatchKind::PolicyVersionMismatch,
                    &snapshot.expected_policy_version,
                    Some(observed),
                    "quorum_audit_asset",
                )),
                None => mismatches.push(PolicyMismatch::new(
                    &snapshot.org_scope,
                    MismatchKind::MissingLedgerPolicy,
                    &snapshot.expected_policy_version,
                    None::<String>,
                    "quorum_audit_asset",
                )),
            }

            match snapshot.quorum_calibration_ref {
                Some(ref observed) if observed == &snapshot.expected_calibration_ref => {}
                Some(observed) => mismatches.push(PolicyMismatch::new(
                    &snapshot.org_scope,
                    MismatchKind::CalibrationRefMismatch,
                    &snapshot.expected_calibration_ref,
                    Some(observed),
                    "quorum_audit_asset",
                )),
                None => mismatches.push(PolicyMismatch::new(
                    &snapshot.org_scope,
                    MismatchKind::CalibrationRefMismatch,
                    &snapshot.expected_calibration_ref,
                    None::<String>,
                    "quorum_audit_asset",
                )),
            }

            match snapshot.quorum_travel_rule_bundle {
                Some(ref observed) if observed == &snapshot.expected_travel_rule_bundle => {}
                Some(observed) => mismatches.push(PolicyMismatch::new(
                    &snapshot.org_scope,
                    MismatchKind::TravelRuleBundleMismatch,
                    &snapshot.expected_travel_rule_bundle,
                    Some(observed),
                    "travel_rule_export",
                )),
                None => mismatches.push(PolicyMismatch::new(
                    &snapshot.org_scope,
                    MismatchKind::TravelRuleBundleMismatch,
                    &snapshot.expected_travel_rule_bundle,
                    None::<String>,
                    "travel_rule_export",
                )),
            }

            match snapshot.fabric_calibration_ref {
                Some(ref observed) if observed == &snapshot.expected_calibration_ref => {}
                Some(observed) => mismatches.push(PolicyMismatch::new(
                    &snapshot.org_scope,
                    MismatchKind::CalibrationRefMismatch,
                    &snapshot.expected_calibration_ref,
                    Some(observed),
                    "fabric_anchor",
                )),
                None => mismatches.push(PolicyMismatch::new(
                    &snapshot.org_scope,
                    MismatchKind::MissingFabricAnchor,
                    &snapshot.expected_calibration_ref,
                    None::<String>,
                    "fabric_anchor",
                )),
            }
        }

        Self {
            evaluated_at,
            mismatches,
        }
    }

    #[must_use]
    pub const fn evaluated_at(&self) -> SystemTime {
        self.evaluated_at
    }

    #[must_use]
    pub fn mismatches(&self) -> &[PolicyMismatch] {
        &self.mismatches
    }

    #[must_use]
    pub fn is_alarm_active(&self) -> bool {
        !self.mismatches.is_empty()
    }
}

/// Snapshot of the `retention_policy_mismatch` alarm state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionAlarmSnapshot {
    pub code: &'static str,
    pub active: bool,
    pub last_triggered_at: Option<SystemTime>,
    pub mismatches: Vec<PolicyMismatch>,
}

/// Tracks `RetentionSync` runs and propagates the alarm state.
#[derive(Debug, Clone, Default)]
pub struct RetentionSync {
    last_run_at: Option<SystemTime>,
    last_success_at: Option<SystemTime>,
    alarm_last_triggered: Option<SystemTime>,
    active_mismatches: Vec<PolicyMismatch>,
}

impl RetentionSync {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_run(&mut self, evaluation: RetentionPolicyEvaluation) {
        let evaluated_at = evaluation.evaluated_at;
        self.last_run_at = Some(evaluated_at);
        if evaluation.mismatches.is_empty() {
            self.last_success_at = Some(evaluated_at);
            self.active_mismatches.clear();
        } else {
            self.alarm_last_triggered = Some(evaluated_at);
            self.active_mismatches = evaluation.mismatches;
        }
    }

    #[must_use]
    pub const fn last_run_at(&self) -> Option<SystemTime> {
        self.last_run_at
    }

    #[must_use]
    pub const fn last_success_at(&self) -> Option<SystemTime> {
        self.last_success_at
    }

    #[must_use]
    pub fn alarm_is_active(&self) -> bool {
        !self.active_mismatches.is_empty()
    }

    #[must_use]
    pub fn retention_policy_alarm(&self) -> RetentionAlarmSnapshot {
        RetentionAlarmSnapshot {
            code: "retention_policy_mismatch",
            active: self.alarm_is_active(),
            last_triggered_at: self.alarm_last_triggered,
            mismatches: self.active_mismatches.clone(),
        }
    }

    #[must_use]
    pub fn seconds_since_last_success(&self, reference: SystemTime) -> Option<u64> {
        self.last_success_at.and_then(|success| {
            reference
                .duration_since(success)
                .ok()
                .map(|duration| duration.as_secs())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn baseline_snapshot() -> RetentionPolicySnapshot {
        RetentionPolicySnapshot {
            org_scope: "vasp:europe:de:001".to_owned(),
            expected_policy_version: "ret-2024.06-r5".to_owned(),
            expected_calibration_ref: "cal-2024-06-bridge-015".to_owned(),
            expected_travel_rule_bundle: "tr-2024-06-bridge-104".to_owned(),
            quorum_policy_version: Some("ret-2024.06-r5".to_owned()),
            quorum_calibration_ref: Some("cal-2024-06-bridge-015".to_owned()),
            quorum_travel_rule_bundle: Some("tr-2024-06-bridge-104".to_owned()),
            fabric_calibration_ref: Some("cal-2024-06-bridge-015".to_owned()),
        }
    }

    #[test]
    fn evaluation_without_mismatches_is_clean() {
        let evaluation = RetentionPolicyEvaluation::from_snapshots(
            UNIX_EPOCH + Duration::from_secs(1_718_625_905),
            [baseline_snapshot()],
        );
        assert!(!evaluation.is_alarm_active());
        assert!(evaluation.mismatches().is_empty());
    }

    #[test]
    fn evaluation_detects_policy_drift() {
        let mut snapshot = baseline_snapshot();
        snapshot.quorum_policy_version = Some("ret-2024.07-r1".to_owned());
        let evaluation = RetentionPolicyEvaluation::from_snapshots(
            UNIX_EPOCH + Duration::from_secs(1_718_626_505),
            [snapshot],
        );
        assert!(evaluation.is_alarm_active());
        assert_eq!(evaluation.mismatches().len(), 1);
        assert!(matches!(
            evaluation.mismatches().first().map(|m| &m.kind),
            Some(MismatchKind::PolicyVersionMismatch)
        ));
    }

    #[test]
    fn retention_sync_tracks_alarm_state() {
        let success_eval = RetentionPolicyEvaluation::from_snapshots(
            UNIX_EPOCH + Duration::from_secs(1_718_625_905),
            [baseline_snapshot()],
        );
        let mut sync = RetentionSync::new();
        sync.record_run(success_eval);
        assert_eq!(
            sync.last_success_at(),
            Some(UNIX_EPOCH + Duration::from_secs(1_718_625_905))
        );
        assert!(!sync.alarm_is_active());

        let mut snapshot = baseline_snapshot();
        snapshot.quorum_travel_rule_bundle = Some("tr-2024-06-bridge-999".to_owned());
        let drift_eval = RetentionPolicyEvaluation::from_snapshots(
            UNIX_EPOCH + Duration::from_secs(1_718_626_505),
            [snapshot],
        );
        sync.record_run(drift_eval);
        assert_eq!(
            sync.last_run_at(),
            Some(UNIX_EPOCH + Duration::from_secs(1_718_626_505))
        );
        assert_eq!(
            sync.last_success_at(),
            Some(UNIX_EPOCH + Duration::from_secs(1_718_625_905))
        );
        assert!(sync.alarm_is_active());
        let alarm = sync.retention_policy_alarm();
        assert_eq!(alarm.code, "retention_policy_mismatch");
        assert!(alarm.active);
        assert_eq!(alarm.mismatches.len(), 1);
    }
}
