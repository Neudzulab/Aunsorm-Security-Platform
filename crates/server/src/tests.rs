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
