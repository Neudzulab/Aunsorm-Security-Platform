use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aunsorm_acme::{AcmeDirectory, ReplayNonce, REPLAY_NONCE_HEADER};
use aunsorm_jwt::Ed25519KeyPair;
use aunsorm_server::{build_router, LedgerBackend, ServerConfig, ServerState};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn demo_state() -> Arc<ServerState> {
    const SEED: [u8; 32] = [0x42; 32];
    let key = Ed25519KeyPair::from_seed("acme-tests", SEED).expect("seed");
    let config = ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().expect("socket"),
        "https://acme-tests.local/",
        "aunsorm-clients",
        Duration::from_secs(600),
        false,
        key,
        LedgerBackend::Memory,
    )
    .expect("config");
    Arc::new(ServerState::try_new(config).expect("state"))
}

#[tokio::test]
async fn acme_directory_and_nonce_flow() {
    let state = demo_state();
    let app = build_router(&state);

    let directory_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/acme/directory")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(directory_response.status(), StatusCode::OK);
    let (parts, body) = directory_response.into_parts();
    let first_nonce = parts
        .headers
        .get(REPLAY_NONCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("nonce header")
        .to_owned();
    ReplayNonce::parse(&first_nonce).expect("valid nonce");

    let body = to_bytes(body, usize::MAX).await.expect("body");
    let directory: AcmeDirectory = serde_json::from_slice(&body).expect("directory json");
    assert_eq!(
        directory.new_nonce.as_str(),
        "https://acme-tests.local/acme/new-nonce"
    );
    assert_eq!(
        directory.new_account.as_str(),
        "https://acme-tests.local/acme/new-account"
    );
    assert!(directory
        .meta
        .as_ref()
        .is_some_and(|meta| !meta.caa_identities.is_empty()));

    let nonce_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/acme/new-nonce")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(nonce_response.status(), StatusCode::OK);
    let second_nonce = nonce_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("nonce header")
        .to_owned();
    ReplayNonce::parse(&second_nonce).expect("valid nonce");
    assert_ne!(first_nonce, second_nonce, "nonces must rotate");
}
