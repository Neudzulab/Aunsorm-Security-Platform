use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;

use aunsorm_jwt::Ed25519KeyPair;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::{LedgerBackend, ServerConfig};
use crate::routes::build_router;
use crate::state::ServerState;

#[derive(Debug, Deserialize)]
struct TransparencyTree {
    domain: String,
    tree_head: String,
    latest_sequence: u64,
    records: Vec<TransparencyTreeRecord>,
}

#[derive(Debug, Deserialize)]
struct TransparencyTreeRecord {
    sequence: u64,
    timestamp: u64,
    key_id: String,
    action: String,
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

#[tokio::test]
async fn pkce_flow_succeeds() {
    let state = setup_state();
    let app = build_router(Arc::clone(&state));
    let code_verifier = "correcthorsebatterystaplepkce-verifier-000000000000000000000";
    let digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);
    let begin_payload = json!({
        "username": "alice",
        "client_id": "demo-client",
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

    let token_payload = json!({
        "auth_request_id": begin.auth_request_id,
        "code_verifier": code_verifier,
        "client_id": "demo-client"
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
    assert_eq!(introspect.username.as_deref(), Some("alice"));

    let metrics_response = app
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
}

#[tokio::test]
async fn transparency_endpoint_returns_snapshot() {
    let state = setup_state();
    let app = build_router(state);
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
}

#[tokio::test]
async fn reject_non_s256_method() {
    let state = setup_state();
    let app = build_router(state);
    let begin_payload = json!({
        "username": "alice",
        "client_id": "demo-client",
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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BeginAuthResponse {
    auth_request_id: String,
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
struct IntrospectResponse {
    active: bool,
    username: Option<String>,
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
