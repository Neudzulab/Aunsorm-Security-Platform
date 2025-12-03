use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_acme::{AcmeDirectory, ReplayNonce, REPLAY_NONCE_HEADER};
use aunsorm_core::{calibration::calib_from_text, clock::SecureClockSnapshot};
use aunsorm_jwt::Ed25519KeyPair;
use aunsorm_server::{build_router, LedgerBackend, ServerConfig, ServerState};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde::Deserialize;
use serde_json::{from_slice, json};
use tower::ServiceExt;

fn demo_state() -> Arc<ServerState> {
    const SEED: [u8; 32] = [0x42; 32];
    let key = Ed25519KeyPair::from_seed("acme-tests", SEED).expect("seed");
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
        "127.0.0.1:0".parse::<SocketAddr>().expect("socket"),
        "https://acme-tests.local/",
        "aunsorm-clients",
        Duration::from_secs(600),
        false,
        key,
        LedgerBackend::Memory,
        None,
        calibration_fingerprint,
        Duration::from_secs(300),
        clock_snapshot,
        None,
        None, // revocation_webhook
    )
    .expect("config");
    Arc::new(ServerState::try_new(config).expect("state"))
}

#[derive(Debug, Deserialize)]
struct HttpFixture {
    #[allow(dead_code)]
    description: String,
    token: String,
    thumbprint: String,
    expected_path: String,
    expected_body: String,
}

#[derive(Debug, Deserialize)]
struct DnsFixture {
    #[allow(dead_code)]
    description: String,
    token: String,
    identifier: String,
    thumbprint: String,
    expected_name: String,
    expected_value: String,
}

fn load_http_fixture() -> HttpFixture {
    let path = fixture_base_path().join("http01_fixture.json");
    let data = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("http fixture okunamadı: {path:?}: {err}");
    });
    serde_json::from_str(&data).expect("http fixture json")
}

fn load_dns_fixture() -> DnsFixture {
    let path = fixture_base_path().join("dns01_fixture.json");
    let data = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("dns fixture okunamadı: {path:?}: {err}");
    });
    serde_json::from_str(&data).expect("dns fixture json")
}

fn fixture_base_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("acme")
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

#[derive(Debug, Deserialize)]
struct HttpPublishResponse {
    state: String,
    resource_path: String,
    body: String,
}

#[derive(Debug, Deserialize)]
struct DnsPublishResponse {
    state: String,
    record_name: String,
    record_value: String,
}

#[derive(Debug, Deserialize)]
struct ChallengeStateResponse {
    state: String,
}

#[tokio::test]
async fn acme_validation_publication_and_revocation() {
    let state = demo_state();
    let app = build_router(&state);
    let http_fixture = load_http_fixture();
    let dns_fixture = load_dns_fixture();

    let http_token = http_fixture.token.clone();
    let http_thumbprint = http_fixture.thumbprint.clone();
    let http_request_body = json!({
        "token": http_token,
        "account_thumbprint": http_thumbprint,
    });
    let http_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/acme/validation/http-01")
                .header("content-type", "application/json")
                .body(Body::from(http_request_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(http_response.status(), StatusCode::CREATED);
    let body = to_bytes(http_response.into_body(), usize::MAX)
        .await
        .expect("body");
    let http_publish: HttpPublishResponse = from_slice(&body).expect("publish response");
    assert_eq!(http_publish.state, "published");
    assert_eq!(http_publish.resource_path, http_fixture.expected_path);
    assert_eq!(http_publish.body, http_fixture.expected_body);

    let revoke_http = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/acme/validation/http-01/{}", http_token))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(revoke_http.status(), StatusCode::OK);
    let body = to_bytes(revoke_http.into_body(), usize::MAX)
        .await
        .expect("body");
    let state_response: ChallengeStateResponse = from_slice(&body).expect("revoke response");
    assert_eq!(state_response.state, "revoked");

    let dns_token = dns_fixture.token.clone();
    let dns_identifier = dns_fixture.identifier.clone();
    let dns_thumbprint = dns_fixture.thumbprint.clone();
    let dns_request_body = json!({
        "token": dns_token.clone(),
        "identifier": dns_identifier,
        "account_thumbprint": dns_thumbprint,
    });
    let dns_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/acme/validation/dns-01")
                .header("content-type", "application/json")
                .body(Body::from(dns_request_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(dns_response.status(), StatusCode::CREATED);
    let body = to_bytes(dns_response.into_body(), usize::MAX)
        .await
        .expect("body");
    let dns_publish: DnsPublishResponse = from_slice(&body).expect("dns publish response");
    assert_eq!(dns_publish.state, "published");
    assert_eq!(dns_publish.record_name, dns_fixture.expected_name);
    assert_eq!(dns_publish.record_value, dns_fixture.expected_value);

    let revoke_dns = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/acme/validation/dns-01/{}", dns_token))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(revoke_dns.status(), StatusCode::OK);
    let body = to_bytes(revoke_dns.into_body(), usize::MAX)
        .await
        .expect("body");
    let dns_state: ChallengeStateResponse = from_slice(&body).expect("dns revoke response");
    assert_eq!(dns_state.state, "revoked");
}
