use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_core::clock::SecureClockSnapshot;
use aunsorm_jwt::Ed25519KeyPair;
use aunsorm_server::{build_router, LedgerBackend, ServerConfig, ServerState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

fn smoke_state() -> (Arc<ServerState>, TempDir) {
    const SEED: [u8; 32] = [0x22; 32];
    let key = Ed25519KeyPair::from_seed("gateway-smoke-tests", SEED).expect("seed");
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
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        unix_time_ms: now_ms,
        stratum: 2,
        round_trip_ms: 8,
        dispersion_ms: 12,
        estimated_offset_ms: 4,
        signature_b64: "Z2F0ZXdheS1zbW9rZS1zaWc".to_owned(),
    };

    let temp_dir = TempDir::new().expect("temp dir");
    let ledger_path = temp_dir.path().join("jti-ledger.sqlite");

    let config = ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().expect("socket"),
        "https://gateway-smoke-tests",
        "aunsorm-gateway-smoke",
        Duration::from_secs(600),
        false,
        key,
        LedgerBackend::Sqlite(ledger_path),
        None,
        None,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
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

#[tokio::test]
async fn e2e_gateway_health_and_pqc_capabilities_conditional_get() {
    let (state, _ledger_dir) = smoke_state();
    let app = build_router(&state);

    let health_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .expect("health request"),
        )
        .await
        .expect("health response");
    assert_eq!(health_response.status(), StatusCode::OK);
    let health_etag = health_response
        .headers()
        .get(header::ETAG)
        .cloned()
        .expect("health etag");

    let conditional_health = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header(header::IF_NONE_MATCH, health_etag)
                .body(Body::empty())
                .expect("health conditional request"),
        )
        .await
        .expect("health conditional response");
    assert_eq!(conditional_health.status(), StatusCode::NOT_MODIFIED);

    let pqc_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/pqc/capabilities")
                .body(Body::empty())
                .expect("pqc request"),
        )
        .await
        .expect("pqc response");
    assert_eq!(pqc_response.status(), StatusCode::OK);
    let pqc_etag = pqc_response
        .headers()
        .get(header::ETAG)
        .cloned()
        .expect("pqc etag");

    let conditional_pqc = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/pqc/capabilities")
                .header(header::IF_NONE_MATCH, pqc_etag)
                .body(Body::empty())
                .expect("pqc conditional request"),
        )
        .await
        .expect("pqc conditional response");
    assert_eq!(conditional_pqc.status(), StatusCode::NOT_MODIFIED);
}
