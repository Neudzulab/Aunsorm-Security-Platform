use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;

use aunsorm_jwt::{Ed25519KeyPair, Jwk};
use aunsorm_mdm::{DeviceCertificatePlan, DeviceRecord, PolicyDocument};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::{LedgerBackend, ServerConfig};
use crate::fabric::{
    canonical_challenge, FABRIC_POC_CHANNEL, FABRIC_POC_DID, FABRIC_POC_KEY_SEED,
    FABRIC_POC_METHOD_ID, FABRIC_POC_TRANSACTION_ID,
};
use crate::routes::build_router;
use crate::state::ServerState;
use ed25519_dalek::Signer;

#[derive(Debug, Deserialize)]
struct TransparencyTree {
    domain: String,
    tree_head: String,
    latest_sequence: u64,
    #[serde(default)]
    transcript_hash: Option<String>,
    records: Vec<TransparencyTreeRecord>,
}

#[derive(Debug, Deserialize)]
struct TransparencyTreeRecord {
    sequence: u64,
    timestamp: u64,
    key_id: String,
    action: String,
}

#[derive(Debug, Deserialize)]
struct RandomNumberPayload {
    value: u64,
    min: u64,
    max: u64,
    entropy: String,
}

#[derive(Debug, Deserialize)]
struct FabricVerificationResponse {
    did: String,
    verified: bool,
    controller: String,
    status: String,
    channel: String,
    #[serde(rename = "mspId")]
    msp_id: String,
    #[serde(rename = "ledger_anchor")]
    ledger_anchor: FabricLedgerAnchorResponse,
    #[serde(rename = "verification_method")]
    verification_method: FabricVerificationMethodResponse,
    service: Option<FabricVerificationServiceResponse>,
    audit: FabricVerificationAuditResponse,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct FabricLedgerAnchorResponse {
    #[serde(rename = "blockIndex")]
    block_index: u64,
    #[serde(rename = "blockHash")]
    block_hash: String,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    #[serde(rename = "timestampMs")]
    timestamp_ms: u64,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct FabricVerificationMethodResponse {
    id: String,
    #[serde(rename = "type")]
    ty: String,
    controller: String,
    #[serde(rename = "publicKeyBase64")]
    public_key_base64: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct FabricVerificationServiceResponse {
    id: String,
    #[serde(rename = "type")]
    ty: String,
    endpoint: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct FabricVerificationAuditResponse {
    challenge: String,
    #[serde(rename = "checkedAtMs")]
    checked_at_ms: u64,
    #[serde(rename = "clockSkewMs")]
    clock_skew_ms: u64,
}

fn test_seed() -> [u8; 32] {
    [7_u8; 32]
}

fn setup_state() -> Arc<ServerState> {
    let key = Ed25519KeyPair::from_seed("test", test_seed()).expect("seed");
    let config = ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
        "https://issuer",
        "aunsorm-audience",
        Duration::from_secs(600),
        false,
        key,
        LedgerBackend::Memory,
    )
    .expect("config");
    Arc::new(ServerState::try_new(config).expect("state"))
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn pkce_flow_succeeds() {
    let state = setup_state();
    let app = build_router(Arc::clone(&state));
    let code_verifier = "correcthorsebatterystaplepkce-verifier-000000000000000000000";
    let digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);
    let begin_payload = json!({
        "subject": "alice",
        "client_id": "  demo-client  ",
        "redirect_uri": "https://app.example.com/callback",
        "state": "random-csrf-token-123",
        "scope": "read write",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/begin-auth")
                .header("content-type", "application/json")
                .body(Body::from(begin_payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let begin: BeginAuthResponse = serde_json::from_slice(&body).expect("json");
    assert_eq!(begin.state.as_deref(), Some("random-csrf-token-123"));

    let token_payload = json!({
        "grant_type": "authorization_code",
        "code": begin.code,
        "code_verifier": code_verifier,
        "client_id": "demo-client",
        "redirect_uri": "https://app.example.com/callback"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/json")
                .body(Body::from(token_payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let token: TokenResponse = serde_json::from_slice(&body).expect("token");
    assert_eq!(token.token_type, "Bearer");

    let introspect_payload = json!({ "token": token.access_token });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/introspect")
                .header("content-type", "application/json")
                .body(Body::from(introspect_payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let introspect: IntrospectResponse = serde_json::from_slice(&body).expect("introspect");
    assert!(introspect.active);
    assert_eq!(introspect.sub.as_deref(), Some("alice"));
    assert_eq!(introspect.client_id.as_deref(), Some("demo-client"));
    assert_eq!(introspect.scope.as_deref(), Some("read write"));

    let metrics_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("metrics");
    assert_eq!(metrics_response.status(), StatusCode::OK);
    let metrics_body = to_bytes(metrics_response.into_body(), usize::MAX)
        .await
        .expect("metrics body");
    let metrics_text = String::from_utf8(metrics_body.to_vec()).expect("metrics str");
    assert!(metrics_text.contains("aunsorm_active_tokens"));
    assert!(metrics_text.contains("aunsorm_sfu_contexts"));
    assert!(metrics_text.contains("aunsorm_mdm_registered_devices"));

    let transparency_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/transparency")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("transparency");
    assert_eq!(transparency_response.status(), StatusCode::OK);
    let transparency_body = to_bytes(transparency_response.into_body(), usize::MAX)
        .await
        .expect("transparency body");
    let transparency: TransparencySnapshotResponse =
        serde_json::from_slice(&transparency_body).expect("transparency json");
    assert!(transparency.transcript_hash.is_some());
    assert!(transparency.entries.len() >= 2);
    assert!(matches!(
        transparency.entries.first().map(|entry| &entry.event),
        Some(TransparencyEventResponse::KeyPublished { .. })
    ));
    let last_hash = transparency.entries.last().map(|entry| entry.hash.clone());
    assert_eq!(last_hash, transparency.transcript_hash);
    let token_entry = transparency
        .entries
        .iter()
        .find(|entry| matches!(entry.event, TransparencyEventResponse::TokenIssued { .. }))
        .expect("token entry");
    let expected_subject_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(b"alice"));
    match &token_entry.event {
        TransparencyEventResponse::TokenIssued {
            jti,
            subject_hash,
            audience,
            expires_at,
        } => {
            assert_eq!(jti, introspect.jti.as_ref().expect("jti"));
            assert_eq!(
                subject_hash.as_deref(),
                Some(expected_subject_hash.as_str())
            );
            assert_eq!(audience.as_deref(), Some("\"aunsorm-audience\""));
            assert_eq!(*expires_at, introspect.exp.expect("exp"));
        }
        TransparencyEventResponse::KeyPublished { .. } => panic!("unexpected event kind"),
    }
}

#[derive(Debug, Deserialize)]
struct DeviceEnrollmentEnvelope {
    device: DeviceRecord,
    policy: PolicyDocument,
    certificate: DeviceCertificatePlan,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
}

#[tokio::test]
async fn mdm_registration_flow() {
    let state = setup_state();
    let app = build_router(Arc::clone(&state));
    let payload = json!({
        "device_id": "mdm-device-1",
        "owner": "alice",
        "platform": "ios",
        "display_name": "Alice's iPhone"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mdm/register")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let envelope: DeviceEnrollmentEnvelope = serde_json::from_slice(&body).expect("json");
    assert_eq!(envelope.device.device_id, "mdm-device-1");
    assert_eq!(envelope.device.owner, "alice");
    assert_eq!(envelope.policy.version, "2025.10-ios");
    assert_eq!(envelope.certificate.profile_name, "aunsorm-mdm-default");

    let conflict = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mdm/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "device_id": "mdm-device-1",
                        "owner": "alice",
                        "platform": "ios"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(conflict.status(), StatusCode::BAD_REQUEST);

    let policy = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mdm/policy/ios")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("policy");
    assert_eq!(policy.status(), StatusCode::OK);
    let policy_body = to_bytes(policy.into_body(), usize::MAX)
        .await
        .expect("policy body");
    let policy_doc: PolicyDocument = serde_json::from_slice(&policy_body).expect("policy json");
    assert_eq!(policy_doc.rules.len(), 3);

    let plan = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mdm/cert-plan/mdm-device-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("plan");
    assert_eq!(plan.status(), StatusCode::OK);
    let plan_body = to_bytes(plan.into_body(), usize::MAX)
        .await
        .expect("plan body");
    let plan_doc: DeviceCertificatePlan = serde_json::from_slice(&plan_body).expect("plan json");
    assert_eq!(plan_doc.device_id, "mdm-device-1");

    let missing_plan = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mdm/cert-plan/unknown-device")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("missing");
    assert_eq!(missing_plan.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mdm_rejects_empty_identifiers() {
    let state = setup_state();
    let app = build_router(Arc::clone(&state));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mdm/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "device_id": "   ",
                        "owner": "alice",
                        "platform": "ios"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let error: ErrorResponse = serde_json::from_slice(&body).expect("json");
    assert_eq!(error.error, "invalid_request");
    assert!(
        error.error_description.contains("device_id")
            && (error.error_description.contains("geçersiz")
                || error.error_description.contains("boş olamaz")),
        "unexpected error message: {}",
        error.error_description
    );

    let count = state.mdm_directory().device_count().expect("device count");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn mdm_rejects_control_characters_in_platform() {
    let state = setup_state();
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mdm/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "device_id": "valid-device",
                        "owner": "alice",
                        "platform": "ios\u{0007}",
                        "display_name": "Alice test"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let error: ErrorResponse = serde_json::from_slice(&body).expect("json");
    assert_eq!(error.error, "invalid_request");
    assert!(
        error.error_description.contains("platform değeri geçersiz"),
        "unexpected error message: {}",
        error.error_description
    );
}

#[tokio::test]
async fn mdm_policy_returns_not_found_for_unknown_platform() {
    let state = setup_state();
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mdm/policy/unknown-os")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let error: ErrorResponse = serde_json::from_slice(&body).expect("json");
    assert_eq!(error.error, "not_found");
    assert!(
        error.error_description.contains("Politika bulunamadı"),
        "unexpected error message: {}",
        error.error_description
    );
}

#[tokio::test]
async fn mdm_certificate_plan_rejects_blank_identifier() {
    let state = setup_state();
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mdm/cert-plan/%20%20")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let error: ErrorResponse = serde_json::from_slice(&body).expect("json");
    assert_eq!(error.error, "invalid_request");
    assert!(
        error.error_description.contains("device_id boş olamaz"),
        "unexpected error message: {}",
        error.error_description
    );
}

#[tokio::test]
async fn transparency_endpoint_returns_snapshot() {
    let state = setup_state();
    let app = build_router(Arc::clone(&state));
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/transparency/tree")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let tree: TransparencyTree = serde_json::from_slice(&body).expect("json");
    assert_eq!(tree.domain, "aunsorm-server");
    let first = tree.records.first().expect("records");
    assert!(tree.latest_sequence >= first.sequence);
    assert!(!tree.tree_head.is_empty());
    assert_eq!(first.key_id, "test");
    assert_eq!(first.action, "publish");
    assert!(first.timestamp > 0);
    let snapshot = state.transparency_tree_snapshot().await;
    let expected_hash = snapshot
        .transcript_hash()
        .expect("transcript hash")
        .map(hex::encode);
    assert_eq!(tree.transcript_hash, expected_hash);
}

#[tokio::test]
async fn reject_non_s256_method() {
    let state = setup_state();
    let app = build_router(state);
    let begin_payload = json!({
        "client_id": "demo-client",
        "redirect_uri": "https://app.example.com/callback",
        "code_challenge": "abcd",
        "code_challenge_method": "plain"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/begin-auth")
                .header("content-type", "application/json")
                .body(Body::from(begin_payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reject_blank_identity_fields() {
    let state = setup_state();
    let app = build_router(state);
    let verifier = "identity-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let digest = Sha256::digest(verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);
    let payloads = vec![
        (
            "blank subject",
            json!({
                "subject": "   ",
                "client_id": "demo-client",
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": code_challenge.clone(),
                "code_challenge_method": "S256"
            }),
            "invalid_request",
        ),
        (
            "client_id with control characters",
            json!({
                "subject": "alice",
                "client_id": "\n\tdemo",
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": code_challenge.clone(),
                "code_challenge_method": "S256"
            }),
            "invalid_request",
        ),
        (
            "subject with control characters",
            json!({
                "subject": "alice\u{0007}",
                "client_id": "demo-client",
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": code_challenge.clone(),
                "code_challenge_method": "S256"
            }),
            "invalid_request",
        ),
        (
            "blank client_id",
            json!({
                "subject": "alice",
                "client_id": "   ",
                "redirect_uri": "https://app.example.com/callback",
                "code_challenge": code_challenge.clone(),
                "code_challenge_method": "S256"
            }),
            "invalid_request",
        ),
        (
            "blank redirect",
            json!({
                "client_id": "demo-client",
                "redirect_uri": "   ",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256"
            }),
            "invalid_redirect_uri",
        ),
    ];

    for (case, payload, expected_error) in payloads {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/begin-auth")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let error: ApiErrorBody = serde_json::from_slice(&body).expect("error json");
        assert_eq!(error.error, expected_error, "case: {case}");
    }
}

#[tokio::test]
async fn reject_unregistered_redirect_uri() {
    let state = setup_state();
    let app = build_router(state);
    let verifier = "identity-verifier-redirect-check-aaaaaaaaaaaaaaaaaaaa";
    let digest = Sha256::digest(verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);
    let payload = json!({
        "subject": "alice",
        "client_id": "demo-client",
        "redirect_uri": "https://malicious.example.com/callback",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/begin-auth")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let error: ApiErrorBody = serde_json::from_slice(&body).expect("error json");
    assert_eq!(error.error, "invalid_redirect_uri");
    assert!(error.error_description.contains("yetkili değil"));
}

#[tokio::test]
async fn reject_scope_outside_registration() {
    let state = setup_state();
    let app = build_router(state);
    let verifier = "identity-verifier-scope-check-aaaaaaaaaaaaaaaaaaaaaa";
    let digest = Sha256::digest(verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);
    let payload = json!({
        "subject": "alice",
        "client_id": "demo-client",
        "redirect_uri": "https://app.example.com/callback",
        "scope": "read delete",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/begin-auth")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let error: ApiErrorBody = serde_json::from_slice(&body).expect("error json");
    assert_eq!(error.error, "invalid_scope");
    assert!(error.error_description.contains("delete"));
}

#[tokio::test]
async fn sfu_context_flow() {
    let state = setup_state();
    let app = build_router(Arc::clone(&state));
    let create_payload = json!({
        "room_id": "zasian-room",
        "participant": "bob",
        "enable_e2ee": true
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sfu/context")
                .header("content-type", "application/json")
                .body(Body::from(create_payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let context: CreateSfuContextResponse = serde_json::from_slice(&body).expect("context json");
    assert!(context.expires_in > 0);
    assert_eq!(context.room_id, "zasian-room");
    assert_eq!(context.participant, "bob");
    let e2ee = context.e2ee.expect("e2ee");
    let key_bytes = URL_SAFE_NO_PAD.decode(&e2ee.key).expect("decode key");
    assert_eq!(key_bytes.len(), 32);
    let nonce_bytes = URL_SAFE_NO_PAD.decode(&e2ee.nonce).expect("decode nonce");
    assert_eq!(nonce_bytes.len(), 12);

    let step_payload = json!({ "context_id": context.context_id });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sfu/context/step")
                .header("content-type", "application/json")
                .body(Body::from(step_payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("step response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("step body");
    let step: NextSfuStepResponse = serde_json::from_slice(&body).expect("step json");
    assert_eq!(step.context_id, context.context_id);
    assert_eq!(step.room_id, context.room_id);
    assert_eq!(step.participant, context.participant);
    assert_eq!(step.session_id, e2ee.session_id);
    assert!(step.message_no > e2ee.message_no);
    assert!(step.expires_in <= context.expires_in);
    let step_key = URL_SAFE_NO_PAD.decode(&step.key).expect("decode step key");
    assert_eq!(step_key.len(), 32);
    let step_nonce = URL_SAFE_NO_PAD
        .decode(&step.nonce)
        .expect("decode step nonce");
    assert_eq!(step_nonce.len(), 12);
}

#[tokio::test]
async fn sfu_context_step_rejects_unknown() {
    let state = setup_state();
    let app = build_router(state);
    let payload = json!({ "context_id": "does-not-exist" });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sfu/context/step")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn random_number_endpoint_returns_entropy() {
    let state = setup_state();
    let app = build_router(Arc::clone(&state));

    // Test 1: Default range (0-100)
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/random/number")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload: RandomNumberPayload = serde_json::from_slice(&body).expect("random json");
    assert!((0..=100).contains(&payload.value));
    assert_eq!(payload.min, 0);
    assert_eq!(payload.max, 100);
    assert_eq!(payload.entropy.len(), 64);
    assert!(payload.entropy.chars().all(|ch| ch.is_ascii_hexdigit()));

    // Test 2: Custom range (15-5000)
    let app2 = build_router(Arc::clone(&state));
    let response2 = app2
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/random/number?min=15&max=5000")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response2.status(), StatusCode::OK);
    let body2 = to_bytes(response2.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload2: RandomNumberPayload = serde_json::from_slice(&body2).expect("random json");
    assert!((15..=5000).contains(&payload2.value));
    assert_eq!(payload2.min, 15);
    assert_eq!(payload2.max, 5000);

    // Test 3: Invalid range (min > max)
    let app3 = build_router(state);
    let response3 = app3
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/random/number?min=100&max=50")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response3.status(), StatusCode::BAD_REQUEST);

    // Test 4: Range near u64::MAX
    let app4 = build_router(setup_state());
    let high_min = u64::MAX - 10;
    let high_max = u64::MAX;
    let high_uri = format!("/random/number?min={high_min}&max={high_max}");
    let response4 = app4
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&high_uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response4.status(), StatusCode::OK);
    let body4 = to_bytes(response4.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload4: RandomNumberPayload = serde_json::from_slice(&body4).expect("random json");
    assert!((high_min..=high_max).contains(&payload4.value));
    assert_eq!(payload4.min, high_min);
    assert_eq!(payload4.max, high_max);
}

/// Smoke test: Random number distribution check (quick validation)
#[test]
fn random_distribution_smoke_test() {
    let state = setup_state();
    let samples: u64 = 1_000; // Smoke test - sadece 1K örnek
    let mut sum: u64 = 0;
    let mut min_value: u64 = u64::MAX;
    let mut max_value: u64 = 0;

    for _ in 0..samples {
        let draw = state.random_inclusive(1, 100);
        assert!((1..=100).contains(&draw), "Value out of range: {}", draw);
        sum += draw;
        min_value = min_value.min(draw);
        max_value = max_value.max(draw);
    }

    let sum_u32 = u32::try_from(sum).expect("sum within bounds");
    let samples_u32 = u32::try_from(samples).expect("samples within bounds");
    let mean = f64::from(sum_u32) / f64::from(samples_u32);
    let expected = 50.5_f64;
    let deviation = (mean - expected).abs();

    // Smoke test - sadece genel sınırları kontrol et
    assert!(
        min_value >= 1 && max_value <= 100,
        "Range check failed: min={min_value}, max={max_value}"
    );
    assert!(
        deviation < 5.0, // Gevşek tolerans - smoke test
        "Mean deviation too high: mean={mean}, expected={expected}, deviation={deviation}"
    );
}

#[tokio::test]
async fn fabric_did_verification_succeeds() {
    let state = setup_state();
    let app = build_router(Arc::clone(&state));
    let document = state
        .fabric_registry()
        .document(FABRIC_POC_DID)
        .expect("fabric did");
    let anchor_hash_hex = document.anchor.block_hash_hex();
    let expected_controller = document.controller.clone();
    let expected_msp = document.msp_id.clone();
    let expected_tx = document.anchor.transaction_id.clone();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("time");
    let timestamp_ms = now
        .as_secs()
        .saturating_mul(1_000)
        .saturating_add(u64::from(now.subsec_millis()));
    let challenge = canonical_challenge(FABRIC_POC_DID, &anchor_hash_hex, timestamp_ms);
    let key_pair =
        Ed25519KeyPair::from_seed(FABRIC_POC_METHOD_ID, FABRIC_POC_KEY_SEED).expect("seed");
    let signature = key_pair.signing_key().sign(&challenge);
    let payload = json!({
        "did": FABRIC_POC_DID,
        "channel": FABRIC_POC_CHANNEL,
        "proof": {
            "challenge": URL_SAFE_NO_PAD.encode(&challenge),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            "block_hash": anchor_hash_hex,
            "transaction_id": FABRIC_POC_TRANSACTION_ID,
            "timestamp_ms": timestamp_ms,
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/blockchain/fabric/did/verify")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let verification: FabricVerificationResponse =
        serde_json::from_slice(&body).expect("verification json");
    assert!(verification.verified);
    assert_eq!(verification.did, FABRIC_POC_DID);
    assert_eq!(verification.controller, expected_controller);
    assert_eq!(verification.channel, FABRIC_POC_CHANNEL);
    assert_eq!(verification.msp_id, expected_msp);
    assert_eq!(verification.ledger_anchor.block_hash, anchor_hash_hex);
    assert_eq!(verification.ledger_anchor.transaction_id, expected_tx);
    assert!(verification.audit.clock_skew_ms <= 30_000);
    assert_eq!(
        verification.audit.challenge,
        URL_SAFE_NO_PAD.encode(&challenge)
    );
    assert_eq!(verification.status, "active");
    assert!(verification.service.is_some());
    assert!(verification.verification_method.public_key_base64.len() >= 40);
}

#[tokio::test]
async fn fabric_did_verification_rejects_tampered_anchor() {
    let state = setup_state();
    let document = state
        .fabric_registry()
        .document(FABRIC_POC_DID)
        .expect("fabric did");
    let anchor_hash_hex = document.anchor.block_hash_hex();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("time");
    let timestamp_ms = now
        .as_secs()
        .saturating_mul(1_000)
        .saturating_add(u64::from(now.subsec_millis()));
    let challenge = canonical_challenge(FABRIC_POC_DID, &anchor_hash_hex, timestamp_ms);
    let key_pair =
        Ed25519KeyPair::from_seed(FABRIC_POC_METHOD_ID, FABRIC_POC_KEY_SEED).expect("seed");
    let signature = key_pair.signing_key().sign(&challenge);
    let mut tampered_hash = anchor_hash_hex.clone();
    if let Some(last) = tampered_hash.pop() {
        let replacement = if last == '0' { '1' } else { '0' };
        tampered_hash.push(replacement);
    }
    let payload = json!({
        "did": FABRIC_POC_DID,
        "channel": FABRIC_POC_CHANNEL,
        "proof": {
            "challenge": URL_SAFE_NO_PAD.encode(&challenge),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            "block_hash": tampered_hash,
            "transaction_id": FABRIC_POC_TRANSACTION_ID,
            "timestamp_ms": timestamp_ms,
        }
    });
    let app = build_router(Arc::clone(&state));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/blockchain/fabric/did/verify")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let error: ApiErrorBody = serde_json::from_slice(&body).expect("error json");
    assert_eq!(error.error, "invalid_request");
    assert!(error
        .error_description
        .contains("block_hash ledger kaydıyla eşleşmiyor"));
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BeginAuthResponse {
    code: String,
    #[serde(default)]
    state: Option<String>,
    expires_in: u64,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    error: String,
    #[serde(rename = "error_description")]
    error_description: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct IntrospectResponse {
    active: bool,
    scope: Option<String>,
    client_id: Option<String>,
    username: Option<String>,
    token_type: Option<String>,
    exp: Option<u64>,
    iat: Option<u64>,
    iss: Option<String>,
    aud: Option<String>,
    sub: Option<String>,
    jti: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TransparencySnapshotResponse {
    transcript_hash: Option<String>,
    entries: Vec<TransparencyEntryResponse>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TransparencyEntryResponse {
    index: u64,
    timestamp: u64,
    event: TransparencyEventResponse,
    hash: String,
    #[serde(default)]
    previous_hash: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TransparencyEventResponse {
    KeyPublished {
        jwk: Jwk,
    },
    TokenIssued {
        jti: String,
        #[serde(default)]
        subject_hash: Option<String>,
        #[serde(default)]
        audience: Option<String>,
        expires_at: u64,
    },
}

#[derive(Debug, Deserialize)]
struct CreateSfuContextResponse {
    context_id: String,
    room_id: String,
    participant: String,
    expires_in: u64,
    #[serde(default)]
    e2ee: Option<SfuE2eeEnvelope>,
}

#[derive(Debug, Deserialize)]
struct SfuE2eeEnvelope {
    session_id: String,
    message_no: u64,
    key: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct NextSfuStepResponse {
    context_id: String,
    room_id: String,
    participant: String,
    session_id: String,
    message_no: u64,
    key: String,
    nonce: String,
    expires_in: u64,
}
