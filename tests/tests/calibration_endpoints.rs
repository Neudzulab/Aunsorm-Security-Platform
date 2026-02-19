use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_core::{calibration::calib_from_text, clock::SecureClockSnapshot};
use aunsorm_jwt::Ed25519KeyPair;
use aunsorm_server::{build_router, AuditOutcome, LedgerBackend, ServerConfig, ServerState};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

const ROLE_BINDINGS_JSON: &str = r#"{"alice":["user","admin"],"client:demo-client":["service","user"],"client:webapp-123":["user"]}"#;
const MFA_SECRETS_JSON: &str =
    r#"{"alice":{"secret":"YWRtaW4tc2hhcmVkLXNlY3JldC1vdHA=","digits":6}}"#;

#[derive(Debug, Deserialize)]
struct CalibrationVerifyExpectations {
    fingerprint_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CalibrationVerifyResults {
    fingerprint_hex: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct CalibrationVerifyResponseBody {
    calibration_id: String,
    fingerprint_hex: String,
    expectations: CalibrationVerifyExpectations,
    results: CalibrationVerifyResults,
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

fn strict_state() -> (Arc<ServerState>, TempDir) {
    const SEED: [u8; 32] = [0x11; 32];
    let key = Ed25519KeyPair::from_seed("calibration-tests", SEED).expect("seed");
    let now_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    let clock_snapshot = SecureClockSnapshot {
        authority_id: "ntp.test.aunsorm".to_owned(),
        authority_fingerprint_hex:
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        unix_time_ms: now_ms,
        stratum: 2,
        round_trip_ms: 8,
        dispersion_ms: 12,
        estimated_offset_ms: 4,
        signature_b64: "dGVzdC1jbG9jay1zaWc".to_owned(),
    };
    let (calibration, _) =
        calib_from_text(b"test-salt", "Test calibration for audit proof").expect("calibration");
    let calibration_fingerprint = calibration.fingerprint_hex();
    let temp_dir = TempDir::new().expect("temp dir");
    let ledger_path = temp_dir.path().join("jti-ledger.sqlite");
    let _role_guard = EnvVarGuard::set("AUNSORM_ROLE_BINDINGS", ROLE_BINDINGS_JSON);
    let _mfa_guard = EnvVarGuard::set("AUNSORM_MFA_SECRETS", MFA_SECRETS_JSON);
    let config = ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().expect("socket"),
        "https://calibration-tests",
        "aunsorm-calibration",
        Duration::from_secs(600),
        true,
        key,
        LedgerBackend::Sqlite(ledger_path),
        None,
        None,
        calibration_fingerprint,
        Duration::from_secs(30),
        clock_snapshot,
        None,
        None, // revocation_webhook
        None, // cors
    )
    .expect("config");
    let state = Arc::new(ServerState::try_new(config).expect("state"));
    (state, temp_dir)
}

async fn post_calibration_verify(
    state: &Arc<ServerState>,
    body: serde_json::Value,
) -> (StatusCode, CalibrationVerifyResponseBody) {
    let app = build_router(state);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/calib/verify")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");

    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let parsed: CalibrationVerifyResponseBody = serde_json::from_slice(&body).expect("verify json");
    (status, parsed)
}

async fn post_calibration_verify_raw(
    state: &Arc<ServerState>,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let app = build_router(state);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/calib/verify")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");

    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn strict_calibration_verify_rejects_mismatch_and_records_audit_event() {
    let (state, _ledger_dir) = strict_state();
    assert!(state.audit_events().await.is_empty());

    let payload = json!({
        "org_salt": STANDARD.encode(b"test-salt"),
        "calib_text": "Different calibration payload",
    });

    let (status, body) = post_calibration_verify(&state, payload).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body.results.fingerprint_hex, Some(false));

    let events = state.audit_events().await;
    assert_eq!(events.len(), 1, "expected a single audit event");
    let event = &events[0];
    assert_eq!(event.outcome, AuditOutcome::Failure);
    assert!(
        event.resource.contains(&body.calibration_id),
        "resource should reference calibration id"
    );
    if let Some(expected) = body.expectations.fingerprint_hex.as_ref() {
        assert!(
            event.resource.contains(expected),
            "resource should include expected fingerprint"
        );
    }
    assert!(
        event.resource.contains(&body.fingerprint_hex),
        "resource should include actual fingerprint"
    );
}

#[tokio::test]
async fn strict_calibration_verify_accepts_match_without_audit_failure() {
    let (state, _ledger_dir) = strict_state();
    let payload = json!({
        "org_salt": STANDARD.encode(b"test-salt"),
        "calib_text": "Test calibration for audit proof",
    });

    let (status, body) = post_calibration_verify(&state, payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.results.fingerprint_hex, Some(true));
    assert!(state.audit_events().await.is_empty());
}

#[tokio::test]
async fn strict_calibration_verify_rejects_invalid_inputs_before_audit_logging() {
    let (state, _ledger_dir) = strict_state();
    let invalid_salt_payload = json!({
        "org_salt": "@@not-base64@@",
        "calib_text": "Test calibration for audit proof",
    });

    let (status, body) = post_calibration_verify_raw(&state, invalid_salt_payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("org_salt base64 decode failed"),
        "response should explain decode failure"
    );
    assert!(state.audit_events().await.is_empty());

    let empty_text_payload = json!({
        "org_salt": STANDARD.encode(b"test-salt"),
        "calib_text": " \n\t",
    });
    let (status, body) = post_calibration_verify_raw(&state, empty_text_payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("calibration text cannot be empty"),
        "response should explain empty calibration text"
    );
    assert!(state.audit_events().await.is_empty());
}
