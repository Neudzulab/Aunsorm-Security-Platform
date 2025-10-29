#![allow(clippy::too_many_lines)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_core::{calibration::calib_from_text, clock::SecureClockSnapshot};
use aunsorm_jwt::Ed25519KeyPair;
use aunsorm_server::{build_router, LedgerBackend, ServerConfig, ServerState};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BeginAuthResponse {
    code: String,
    state: Option<String>,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct IntrospectResponse {
    active: bool,
    sub: Option<String>,
    client_id: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    error: String,
    error_description: String,
}

fn demo_state() -> Arc<ServerState> {
    const SEED: [u8; 32] = [7_u8; 32];
    let key = Ed25519KeyPair::from_seed("oauth-test", SEED).expect("seed");
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
    let config = ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().expect("socket address"),
        "https://issuer",
        "aunsorm-audience",
        Duration::from_secs(600),
        false,
        key,
        LedgerBackend::Memory,
        None,
        calibration_fingerprint,
        clock_snapshot,
    )
    .expect("config");
    Arc::new(ServerState::try_new(config).expect("state"))
}

async fn post_json(app: &mut Router, uri: &str, body: Value) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response")
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

async fn begin_flow(
    app: &mut Router,
    subject: &str,
    state: Option<&str>,
    scope: Option<&str>,
    method: &str,
    redirect_uri: &str,
) -> (BeginAuthResponse, String) {
    let verifier = "correcthorsebatterystaplepkce-verifier-000000000000000000000";
    let mut payload = json!({
        "subject": subject,
        "client_id": "demo-client",
        "redirect_uri": redirect_uri,
        "code_challenge": pkce_challenge(verifier),
        "code_challenge_method": method
    });
    if let Some(value) = state {
        payload["state"] = json!(value);
    }
    if let Some(value) = scope {
        payload["scope"] = json!(value);
    }

    let response = post_json(app, "/oauth/begin-auth", payload).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let begin: BeginAuthResponse = serde_json::from_slice(&body).expect("begin auth response");
    (begin, verifier.to_owned())
}

async fn begin_flow_error(app: &mut Router, mut payload: Value, expected: StatusCode) -> ErrorBody {
    if payload.get("client_id").is_none() {
        payload["client_id"] = json!("demo-client");
    }
    if payload.get("redirect_uri").is_none() {
        payload["redirect_uri"] = json!("https://app.example.com/callback");
    }
    let response = post_json(app, "/oauth/begin-auth", payload).await;
    assert_eq!(response.status(), expected);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).unwrap_or_else(|_| ErrorBody {
        error: "invalid_request".to_string(),
        error_description: String::from_utf8_lossy(&body).to_string(),
    })
}

async fn exchange_code(app: &mut Router, code: &str, verifier: &str) -> Response {
    let payload = json!({
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "client_id": "demo-client",
        "redirect_uri": "https://app.example.com/callback"
    });
    post_json(app, "/oauth/token", payload).await
}

async fn exchange_code_error(app: &mut Router, payload: Value, expected: StatusCode) -> ErrorBody {
    let response = post_json(app, "/oauth/token", payload).await;
    assert_eq!(response.status(), expected);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).unwrap_or_else(|_| ErrorBody {
        error: "invalid_request".to_string(),
        error_description: String::from_utf8_lossy(&body).to_string(),
    })
}

async fn introspect_token(app: &mut Router, token: &str) -> IntrospectResponse {
    let payload = json!({ "token": token });
    let response = post_json(app, "/oauth/introspect", payload).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("introspect response")
}

#[tokio::test]
async fn authorization_code_flow_roundtrip() {
    let state = demo_state();
    let mut app = build_router(&state);
    let (begin, verifier) = begin_flow(
        &mut app,
        "alice",
        Some("csrf-123"),
        Some("read write"),
        "S256",
        "https://app.example.com/callback",
    )
    .await;
    assert_eq!(begin.state.as_deref(), Some("csrf-123"));

    let response = exchange_code(&mut app, &begin.code, &verifier).await;
    assert_eq!(response.status(), StatusCode::OK);
    let token: TokenResponse = serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("token response");
    assert_eq!(token.token_type, "Bearer");

    let introspect = introspect_token(&mut app, &token.access_token).await;
    assert!(introspect.active, "token should be active");
    assert_eq!(introspect.sub.as_deref(), Some("alice"));
    assert_eq!(introspect.client_id.as_deref(), Some("demo-client"));
    assert_eq!(introspect.scope.as_deref(), Some("read write"));
}

#[tokio::test]
async fn pkce_must_use_s256_method() {
    let state = demo_state();
    let mut app = build_router(&state);
    let payload = json!({
        "subject": "alice",
        "code_challenge": pkce_challenge("verifier"),
        "code_challenge_method": "plain"
    });
    let error = begin_flow_error(&mut app, payload, StatusCode::BAD_REQUEST).await;
    assert_eq!(error.error, "invalid_request");
    assert!(error
        .error_description
        .contains("PKCE yöntemi yalnızca S256"));
}

#[tokio::test]
async fn redirect_uri_must_be_registered_and_https() {
    let state = demo_state();
    let mut app = build_router(&state);
    let payload = json!({
        "subject": "mallory",
        "redirect_uri": "https://evil.example.com/callback",
        "code_challenge": pkce_challenge("verifier"),
        "code_challenge_method": "S256"
    });
    let error = begin_flow_error(&mut app, payload, StatusCode::BAD_REQUEST).await;
    assert_eq!(error.error, "invalid_redirect_uri");
    assert!(error
        .error_description
        .contains("redirect_uri kayıtlı istemci için yetkili değil"));
}

#[tokio::test]
async fn authorization_code_is_single_use() {
    let state = demo_state();
    let mut app = build_router(&state);
    let (begin, verifier) = begin_flow(
        &mut app,
        "carol",
        None,
        Some("read"),
        "S256",
        "https://app.example.com/callback",
    )
    .await;

    let first = exchange_code(&mut app, &begin.code, &verifier).await;
    assert_eq!(first.status(), StatusCode::OK);
    let _token: TokenResponse =
        serde_json::from_slice(&to_bytes(first.into_body(), usize::MAX).await.expect("body"))
            .expect("token response");

    let second = exchange_code(&mut app, &begin.code, &verifier).await;
    let error = ErrorBody::from_response(second, StatusCode::BAD_REQUEST).await;
    assert_eq!(error.error, "invalid_grant");
    assert!(error
        .error_description
        .contains("Yetkilendirme kodu bulunamadı"));
}

#[tokio::test]
async fn state_is_bound_to_authorization_code() {
    let state = demo_state();
    let mut app = build_router(&state.clone());
    let (begin, verifier) = begin_flow(
        &mut app,
        "ivy",
        Some("csrf-456"),
        Some("read"),
        "S256",
        "https://app.example.com/callback",
    )
    .await;

    let stored = state
        .consume_auth_request(&begin.code)
        .await
        .expect("auth request stored");
    assert_eq!(stored.state.as_deref(), Some("csrf-456"));
    assert_eq!(stored.client_id, "demo-client");
    assert_eq!(stored.redirect_uri, "https://app.example.com/callback");

    let payload = json!({
        "grant_type": "authorization_code",
        "code": begin.code,
        "code_verifier": verifier,
        "client_id": "demo-client",
        "redirect_uri": "https://app.example.com/callback"
    });
    let error = exchange_code_error(&mut app, payload, StatusCode::BAD_REQUEST).await;
    assert_eq!(error.error, "invalid_grant");
    assert!(error
        .error_description
        .contains("Yetkilendirme kodu bulunamadı"));
}

#[tokio::test]
async fn invalid_scope_rejected_during_authorization() {
    let state = demo_state();
    let mut app = build_router(&state);
    let payload = json!({
        "subject": "dave",
        "scope": "admin",
        "code_challenge": pkce_challenge("verifier"),
        "code_challenge_method": "S256"
    });
    let error = begin_flow_error(&mut app, payload, StatusCode::BAD_REQUEST).await;
    assert_eq!(error.error, "invalid_scope");
    assert!(error
        .error_description
        .contains("scope değeri izinli değil"));
}

#[tokio::test]
async fn pkce_challenge_must_be_valid_base64url() {
    let state = demo_state();
    let mut app = build_router(&state);
    let payload = json!({
        "subject": "frank",
        "code_challenge": "not-base64!!!",
        "code_challenge_method": "S256"
    });
    let error = begin_flow_error(&mut app, payload, StatusCode::BAD_REQUEST).await;
    assert_eq!(error.error, "invalid_request");
    assert!(error
        .error_description
        .contains("code_challenge değeri base64url"));
}

#[tokio::test]
async fn token_exchange_rejects_mismatched_client_id() {
    let state = demo_state();
    let mut app = build_router(&state);
    let (begin, verifier) = begin_flow(
        &mut app,
        "grace",
        None,
        Some("read"),
        "S256",
        "https://app.example.com/callback",
    )
    .await;

    let payload = json!({
        "grant_type": "authorization_code",
        "code": begin.code,
        "code_verifier": verifier,
        "client_id": "evil-client",
        "redirect_uri": "https://app.example.com/callback"
    });
    let error = exchange_code_error(&mut app, payload, StatusCode::UNAUTHORIZED).await;
    assert_eq!(error.error, "invalid_client");
    assert!(error.error_description.contains("client_id eşleşmiyor"));
}

#[tokio::test]
async fn token_exchange_rejects_pkce_mismatch() {
    let state = demo_state();
    let mut app = build_router(&state);
    let (begin, _) = begin_flow(
        &mut app,
        "heidi",
        None,
        Some("read"),
        "S256",
        "https://app.example.com/callback",
    )
    .await;

    let payload = json!({
        "grant_type": "authorization_code",
        "code": begin.code,
        "code_verifier": "wrong-verifier-value-that-is-long-enough-to-pass-length-check-1234567",
        "client_id": "demo-client",
        "redirect_uri": "https://app.example.com/callback"
    });
    let error = exchange_code_error(&mut app, payload, StatusCode::BAD_REQUEST).await;
    assert_eq!(error.error, "invalid_grant");
    assert!(error
        .error_description
        .contains("PKCE doğrulaması başarısız"));
}

#[tokio::test]
async fn missing_required_parameters_return_invalid_request() {
    let state = demo_state();
    let mut app = build_router(&state);

    let payload = json!({
        "subject": "erin",
        "code_challenge_method": "S256"
    });
    let error = begin_flow_error(&mut app, payload, StatusCode::UNPROCESSABLE_ENTITY).await;
    assert_eq!(error.error, "invalid_request");

    let (begin, _) = begin_flow(
        &mut app,
        "erin",
        None,
        None,
        "S256",
        "https://app.example.com/callback",
    )
    .await;
    let payload = json!({
        "grant_type": "authorization_code",
        "code": begin.code,
        "client_id": "demo-client",
        "redirect_uri": "https://app.example.com/callback"
    });
    let error = exchange_code_error(&mut app, payload, StatusCode::UNPROCESSABLE_ENTITY).await;
    assert_eq!(error.error, "invalid_request");
    assert!(error.error_description.contains("code_verifier"));
}

impl ErrorBody {
    async fn from_response(response: Response, expected: StatusCode) -> Self {
        assert_eq!(response.status(), expected);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&body).expect("error body")
    }
}
