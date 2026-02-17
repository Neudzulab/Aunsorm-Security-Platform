#![allow(clippy::too_many_lines)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_core::{calibration::calib_from_text, clock::SecureClockSnapshot};
use aunsorm_jwt::Ed25519KeyPair;
use aunsorm_server::{
    build_router, LedgerBackend, RevocationWebhookConfig, ServerConfig, ServerState,
};
use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::{serve, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::time::timeout;
use tower::ServiceExt;
use url::Url;

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
    demo_state_with_webhook(None)
}

fn demo_state_with_webhook(webhook: Option<RevocationWebhookConfig>) -> Arc<ServerState> {
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
        None,
        calibration_fingerprint,
        Duration::from_secs(300),
        clock_snapshot,
        None,
        webhook,
        None,
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

type WebhookSinkSender = Arc<AsyncMutex<Option<oneshot::Sender<(HeaderMap, Vec<u8>)>>>>;

async fn webhook_sink_handler(
    State(sender): State<WebhookSinkSender>,
    req: Request<Body>,
) -> StatusCode {
    let headers = req.headers().clone();
    let body = to_bytes(req.into_body(), usize::MAX)
        .await
        .map(|bytes| bytes.to_vec())
        .unwrap_or_default();
    if let Some(channel) = sender.lock().await.take() {
        let _ = channel.send((headers, body));
    }
    StatusCode::OK
}

async fn spawn_test_webhook_sink() -> (
    Url,
    oneshot::Receiver<(HeaderMap, Vec<u8>)>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("webhook sink");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = oneshot::channel();
    let sender: WebhookSinkSender = Arc::new(AsyncMutex::new(Some(tx)));
    let router = Router::new()
        .route("/", any(webhook_sink_handler))
        .with_state(sender);
    let handle = tokio::spawn(async move {
        if let Err(err) = serve(listener, router).await {
            eprintln!("webhook sink error: {err}");
        }
    });
    let endpoint = Url::parse(&format!("http://{}", addr)).expect("url");
    (endpoint, rx, handle)
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
#[ignore = "Webhook implementation in progress - see PROD_PLAN.md"]
async fn refresh_token_revocation_emits_signed_webhook() {
    let (endpoint, receiver, handle) = spawn_test_webhook_sink().await;
    let secret = "test-webhook-secret-0123456789abcdef".repeat(2);
    let webhook =
        RevocationWebhookConfig::new(endpoint, secret.clone(), Duration::from_millis(750))
            .expect("webhook config");
    let state = demo_state_with_webhook(Some(webhook));
    let mut app = build_router(&state);
    let (begin, verifier) = begin_flow(
        &mut app,
        "alice",
        None,
        Some("read"),
        "S256",
        "https://app.example.com/callback",
    )
    .await;

    let token_response = exchange_code(&mut app, &begin.code, &verifier).await;
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_body = to_bytes(token_response.into_body(), usize::MAX)
        .await
        .expect("token body");
    let token_json: Value = serde_json::from_slice(&token_body).expect("token json");
    let refresh_token = token_json["refreshToken"]
        .as_str()
        .expect("refresh token")
        .to_owned();

    let revoke_payload = json!({
        "token": refresh_token,
        "token_type_hint": "refresh_token"
    });
    let revoke_response = post_json(&mut app, "/oauth/revoke", revoke_payload).await;
    assert_eq!(revoke_response.status(), StatusCode::OK);

    let (headers, body) = timeout(Duration::from_secs(5), receiver)
        .await
        .expect("webhook timeout")
        .expect("webhook payload");
    handle.abort();

    let payload: Value = serde_json::from_slice(&body).expect("webhook body");
    assert_eq!(payload["event"], "token.revoked");
    assert_eq!(payload["revocation"]["tokenType"], "refresh_token");
    assert_eq!(payload["revocation"]["revoked"], true);
    assert_eq!(payload["revocation"]["clientId"], "demo-client");

    let signature_header = headers
        .get("Aunsorm-Signature")
        .and_then(|value| value.to_str().ok())
        .expect("signature header");
    let mut timestamp = None;
    let mut nonce = None;
    let mut signature = None;
    for part in signature_header.split(';') {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "t" => timestamp = Some(value.to_owned()),
                "nonce" => nonce = Some(value.to_owned()),
                "v1" => signature = Some(value.to_owned()),
                _ => {}
            }
        }
    }
    let timestamp = timestamp.expect("timestamp");
    let nonce = nonce.expect("nonce");
    let signature = signature.expect("signature");
    assert_eq!(
        timestamp.parse::<u64>().expect("timestamp number"),
        payload["timestampMs"].as_u64().expect("payload timestamp"),
    );
    type WebhookHmac = Hmac<Sha256>;
    let mut mac = WebhookHmac::new_from_slice(secret.as_bytes()).expect("mac");
    let mut canonical = Vec::new();
    canonical.extend_from_slice(timestamp.as_bytes());
    canonical.push(b'.');
    canonical.extend_from_slice(nonce.as_bytes());
    canonical.push(b'.');
    canonical.extend_from_slice(&body);
    mac.update(&canonical);
    let expected_signature = hex::encode(mac.finalize().into_bytes());
    assert_eq!(signature, expected_signature);
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
#[ignore = "OAuth implementation in progress - see PROD_PLAN.md"]
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
#[ignore = "OAuth implementation in progress - see PROD_PLAN.md"]
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
#[ignore = "OAuth implementation in progress - see PROD_PLAN.md"]
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
#[ignore = "OAuth implementation in progress - see PROD_PLAN.md"]
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
#[ignore = "OAuth implementation in progress - see PROD_PLAN.md"]
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
#[ignore = "OAuth implementation in progress - see PROD_PLAN.md"]
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
#[ignore = "OAuth implementation in progress - see PROD_PLAN.md"]
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
