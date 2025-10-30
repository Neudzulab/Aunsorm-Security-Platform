use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::util::ServiceExt;

use aunsorm_acme::{
    AccountContact, Ed25519AccountKey, KeyBinding, NewAccountRequest, NewOrderRequest,
    OrderIdentifier, ReplayNonce, REPLAY_NONCE_HEADER,
};
use aunsorm_core::{calibration::calib_from_text, clock::SecureClockSnapshot};
use aunsorm_jwt::{Audience, Claims, Ed25519KeyPair, Jwk};
use aunsorm_mdm::{DeviceCertificatePlan, DeviceRecord, PolicyDocument};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use url::Url;
use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, pem::parse_x509_pem, prelude::FromDer,
};

use tempfile::tempdir;

use crate::build_router;
use crate::config::{LedgerBackend, ServerConfig};
use crate::fabric::{
    canonical_challenge, FABRIC_POC_CHANNEL, FABRIC_POC_DID, FABRIC_POC_KEY_SEED,
    FABRIC_POC_METHOD_ID, FABRIC_POC_TRANSACTION_ID,
};
use crate::state::ServerState;
use ed25519_dalek::Signer;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType};

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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct CalibrationRangeBody {
    start: u16,
    end: u16,
    step: u16,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct CalibrationInspectBody {
    calibration_id: String,
    note_text: String,
    alpha_long: u16,
    alpha_short: u16,
    beta_long: u16,
    beta_short: u16,
    tau: u16,
    fingerprint: String,
    fingerprint_hex: String,
    ranges: Vec<CalibrationRangeBody>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct CalibrationVerifyExpectationsBody {
    id: Option<String>,
    fingerprint_b64: Option<String>,
    fingerprint_hex: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct CalibrationVerifyResultsBody {
    id: Option<bool>,
    fingerprint_b64: Option<bool>,
    fingerprint_hex: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct CalibrationVerifyBody {
    calibration_id: String,
    fingerprint_b64: String,
    fingerprint_hex: String,
    expectations: CalibrationVerifyExpectationsBody,
    results: CalibrationVerifyResultsBody,
}

#[derive(Debug, Deserialize)]
struct MediaTokenResponseBody {
    token: String,
    #[serde(rename = "roomId")]
    room_id: String,
    identity: String,
}

#[derive(Debug, Deserialize)]
struct JwtVerifyResponseBody {
    valid: bool,
    #[serde(default)]
    payload: Option<Value>,
    #[serde(default)]
    error: Option<String>,
}

#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize)]
struct AcmeDirectoryPayload {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

#[derive(Debug, Deserialize)]
struct TestAccountResponseBody {
    status: String,
    contact: Vec<String>,
    #[serde(rename = "orders")]
    _orders: String,
    #[serde(rename = "termsOfServiceAgreed")]
    terms_of_service_agreed: bool,
    kid: String,
}

#[derive(Debug, Deserialize)]
struct TestOrderResponseBody {
    status: String,
    identifiers: Vec<TestOrderIdentifierBody>,
    authorizations: Vec<String>,
    finalize: String,
    #[serde(rename = "expires")]
    _expires: String,
    #[serde(rename = "notBefore")]
    _not_before: Option<String>,
    #[serde(rename = "notAfter")]
    _not_after: Option<String>,
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TestOrderIdentifierBody {
    #[serde(rename = "type")]
    ty: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct AcmeProblemResponse {
    #[serde(rename = "type")]
    problem_type: String,
    detail: String,
    status: u16,
}

#[derive(Debug, Deserialize)]
struct RevokeCertResponseBody {
    status: String,
    #[serde(rename = "revokedAt", with = "time::serde::rfc3339")]
    revoked_at: OffsetDateTime,
    #[serde(default)]
    reason: Option<u8>,
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
    setup_state_with_profile(false, None)
}

fn setup_state_with_profile(
    strict: bool,
    calibration_override: Option<String>,
) -> Arc<ServerState> {
    let key = Ed25519KeyPair::from_seed("test", test_seed()).expect("seed");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_millis() as u64;
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
    let calibration_fingerprint =
        calibration_override.unwrap_or_else(|| calibration.fingerprint_hex());
    let ledger = if strict {
        let dir = tempdir().expect("tempdir");
        #[allow(deprecated)]
        let path = dir.into_path().join("jti.sqlite");
        LedgerBackend::Sqlite(path)
    } else {
        LedgerBackend::Memory
    };
    let config = ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
        "https://issuer",
        "aunsorm-audience",
        Duration::from_secs(600),
        strict,
        key,
        ledger,
        None,
        calibration_fingerprint,
        clock_snapshot,
    )
    .expect("config");
    Arc::new(ServerState::try_new(config).expect("state"))
}

#[tokio::test]
async fn acme_directory_and_order_flow() {
    let state = setup_state();

    // Debug: test simple route first
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
    eprintln!(
        "DEBUG: Health endpoint status: {}",
        health_response.status()
    );

    let app = build_router(&state);

    // Debug: test ACME directory specifically
    eprintln!("DEBUG: Attempting ACME directory...");

    // Directory discovery returns fully qualified endpoints.
    let response = app
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
    eprintln!(
        "DEBUG: ACME directory response status: {}",
        response.status()
    );
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "ACME directory endpoint returned: {}",
        response.status()
    );
    let replay = response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("nonce header present")
        .to_str()
        .expect("nonce str");
    assert!(!replay.is_empty(), "nonce must not be empty");
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let directory: AcmeDirectoryPayload = serde_json::from_slice(&body).expect("directory json");
    assert_eq!(directory.new_nonce, state.acme().new_nonce_url().as_str());
    assert_eq!(
        directory.new_account,
        state.acme().new_account_url().as_str()
    );
    assert_eq!(directory.new_order, state.acme().new_order_url().as_str());

    // Fetch a nonce for new-account.
    let nonce_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/acme/new-nonce")
                .body(Body::empty())
                .expect("nonce request"),
        )
        .await
        .expect("nonce response");
    assert_eq!(nonce_response.status(), StatusCode::OK);
    let account_nonce = nonce_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("nonce header")
        .to_str()
        .expect("nonce str");
    let account_nonce = ReplayNonce::parse(account_nonce).expect("valid nonce value");

    // Create a new account with Ed25519 key.
    let key = Ed25519AccountKey::from_seed([7_u8; 32]);
    let account_payload = NewAccountRequest::builder()
        .contact(AccountContact::email("security@example.com").expect("contact"))
        .terms_of_service_agreed(true)
        .build();
    let account_jws = key
        .sign_json(
            &account_payload,
            &account_nonce,
            state.acme().new_account_url(),
            KeyBinding::Jwk,
        )
        .expect("jws");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/acme/new-account")
                .header(header::CONTENT_TYPE, "application/jose+json")
                .body(Body::from(
                    serde_json::to_vec(&account_jws).expect("serialize"),
                ))
                .expect("account request"),
        )
        .await
        .expect("account response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let account_nonce = response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("account nonce header")
        .to_str()
        .expect("nonce str")
        .to_owned();
    assert!(!account_nonce.is_empty());
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header")
        .to_str()
        .expect("location str")
        .to_owned();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("account body");
    let account: TestAccountResponseBody = serde_json::from_slice(&body).expect("account json");
    assert_eq!(account.status, "valid");
    assert!(account.terms_of_service_agreed);
    assert_eq!(
        account.contact,
        vec!["mailto:security@example.com".to_string()]
    );
    assert_eq!(account.kid, location);

    let account_nonce_value = ReplayNonce::parse(account_nonce).expect("account nonce parse");
    let account_url = Url::parse(&location).expect("account url");
    let account_status_jws = key
        .sign_payload(
            &[],
            &account_nonce_value,
            &account_url,
            KeyBinding::Kid(&account.kid),
        )
        .expect("account status jws");
    let account_status_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(account_url.path())
                .header(header::CONTENT_TYPE, "application/jose+json")
                .body(Body::from(
                    serde_json::to_vec(&account_status_jws).expect("serialize"),
                ))
                .expect("account status request"),
        )
        .await
        .expect("account status response");
    assert_eq!(account_status_response.status(), StatusCode::OK);
    let account_status_nonce = account_status_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("account status nonce header")
        .to_str()
        .expect("nonce str");
    assert!(!account_status_nonce.is_empty());
    let account_status_body = to_bytes(account_status_response.into_body(), usize::MAX)
        .await
        .expect("account status body");
    let account_status: TestAccountResponseBody =
        serde_json::from_slice(&account_status_body).expect("account status json");
    assert_eq!(account_status.kid, location);
    assert_eq!(account_status.contact, account.contact);

    // Fetch another nonce for new-order.
    let nonce_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/acme/new-nonce")
                .body(Body::empty())
                .expect("nonce request"),
        )
        .await
        .expect("nonce response");
    let order_nonce = nonce_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("order nonce header")
        .to_str()
        .expect("nonce str");
    let order_nonce = ReplayNonce::parse(order_nonce).expect("valid nonce value");

    let order_request = NewOrderRequest::builder()
        .identifier(OrderIdentifier::dns("example.com").expect("dns"))
        .build()
        .expect("order build");
    let order_jws = key
        .sign_json(
            &order_request,
            &order_nonce,
            state.acme().new_order_url(),
            KeyBinding::Kid(&account.kid),
        )
        .expect("order jws");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/acme/new-order")
                .header(header::CONTENT_TYPE, "application/jose+json")
                .body(Body::from(
                    serde_json::to_vec(&order_jws).expect("serialize"),
                ))
                .expect("order request"),
        )
        .await
        .expect("order response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let order_nonce_header = response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("order nonce header")
        .to_str()
        .expect("nonce str")
        .to_owned();
    assert!(!order_nonce_header.is_empty());
    let order_location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header")
        .to_str()
        .expect("location str")
        .to_owned();
    let order_url = Url::parse(&order_location).expect("order url");
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("order body");
    let order: TestOrderResponseBody = serde_json::from_slice(&body).expect("order json");
    assert_eq!(order.status, "pending");
    assert_eq!(order.identifiers.len(), 1);
    assert_eq!(order.identifiers[0].ty, "dns");
    assert_eq!(order.identifiers[0].value, "example.com");
    assert_eq!(order.authorizations.len(), 1);
    assert!(order_location.contains("/acme/order/"));
    let finalize_endpoint = order.finalize.clone();
    assert!(order.certificate.is_none());

    let order_status_nonce = ReplayNonce::parse(order_nonce_header).expect("order nonce parse");
    let order_status_jws = key
        .sign_payload(
            &[],
            &order_status_nonce,
            &order_url,
            KeyBinding::Kid(&account.kid),
        )
        .expect("order status jws");
    let order_status_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(order_url.path())
                .header(header::CONTENT_TYPE, "application/jose+json")
                .body(Body::from(
                    serde_json::to_vec(&order_status_jws).expect("serialize"),
                ))
                .expect("order status request"),
        )
        .await
        .expect("order status response");
    assert_eq!(order_status_response.status(), StatusCode::OK);
    let order_status_nonce_header = order_status_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("order status nonce header")
        .to_str()
        .expect("nonce str");
    assert!(!order_status_nonce_header.is_empty());
    let order_status_body = to_bytes(order_status_response.into_body(), usize::MAX)
        .await
        .expect("order status body");
    let order_status: TestOrderResponseBody =
        serde_json::from_slice(&order_status_body).expect("order status json");
    assert_eq!(order_status.status, "pending");
    assert_eq!(order_status.identifiers.len(), 1);
    assert_eq!(order_status.finalize, finalize_endpoint);

    // Fetch nonce for finalize request.
    let nonce_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/acme/new-nonce")
                .body(Body::empty())
                .expect("nonce request"),
        )
        .await
        .expect("nonce response");
    let finalize_nonce = nonce_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("finalize nonce header")
        .to_str()
        .expect("nonce str");
    let finalize_nonce = ReplayNonce::parse(finalize_nonce).expect("valid finalize nonce");

    // Build CSR covering the identifier.
    let mut params = CertificateParams::new(vec!["example.com".to_string()]);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "example.com");
    params.distinguished_name = dn;
    let certificate = Certificate::from_params(params).expect("certificate params");
    let csr_der = certificate.serialize_request_der().expect("csr der");
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);

    let finalize_url = Url::parse(&finalize_endpoint).expect("finalize url");
    let finalize_payload = json!({ "csr": csr_b64 });
    let finalize_jws = key
        .sign_json(
            &finalize_payload,
            &finalize_nonce,
            &finalize_url,
            KeyBinding::Kid(&account.kid),
        )
        .expect("finalize jws");

    let finalize_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(finalize_url.path())
                .header(header::CONTENT_TYPE, "application/jose+json")
                .body(Body::from(
                    serde_json::to_vec(&finalize_jws).expect("serialize"),
                ))
                .expect("finalize request"),
        )
        .await
        .expect("finalize response");
    assert_eq!(finalize_response.status(), StatusCode::OK);
    let finalize_nonce_header = finalize_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("nonce header")
        .to_str()
        .expect("nonce str")
        .to_owned();
    assert!(!finalize_nonce_header.is_empty());
    let finalize_location = finalize_response
        .headers()
        .get(header::LOCATION)
        .expect("location header")
        .to_str()
        .expect("location str");
    assert_eq!(finalize_location, order_location);
    let body = to_bytes(finalize_response.into_body(), usize::MAX)
        .await
        .expect("finalize body");
    let finalized: TestOrderResponseBody = serde_json::from_slice(&body).expect("finalized json");
    assert_eq!(finalized.status, "valid");
    assert_eq!(finalized.finalize, finalize_endpoint);
    let order_id = order_location
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .expect("order id");
    let expected_certificate = format!("https://issuer/acme/cert/{order_id}");
    assert_eq!(
        finalized.certificate.as_deref(),
        Some(expected_certificate.as_str())
    );

    let finalize_nonce_value = ReplayNonce::parse(finalize_nonce_header).expect("finalize nonce");
    let order_refresh_jws = key
        .sign_payload(
            &[],
            &finalize_nonce_value,
            &order_url,
            KeyBinding::Kid(&account.kid),
        )
        .expect("order refresh jws");
    let order_refresh_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(order_url.path())
                .header(header::CONTENT_TYPE, "application/jose+json")
                .body(Body::from(
                    serde_json::to_vec(&order_refresh_jws).expect("serialize"),
                ))
                .expect("order refresh request"),
        )
        .await
        .expect("order refresh response");
    assert_eq!(order_refresh_response.status(), StatusCode::OK);
    let order_refresh_body = to_bytes(order_refresh_response.into_body(), usize::MAX)
        .await
        .expect("order refresh body");
    let refreshed: TestOrderResponseBody =
        serde_json::from_slice(&order_refresh_body).expect("order refresh json");
    assert_eq!(refreshed.status, "valid");
    assert_eq!(refreshed.certificate, finalized.certificate);

    let certificate_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/acme/cert/{order_id}"))
                .body(Body::empty())
                .expect("certificate request"),
        )
        .await
        .expect("certificate response");
    assert_eq!(certificate_response.status(), StatusCode::OK);
    let certificate_nonce = certificate_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("certificate nonce header")
        .to_str()
        .expect("nonce str");
    assert!(!certificate_nonce.is_empty());
    let content_type = certificate_response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("content-type header")
        .to_str()
        .expect("content-type str");
    assert_eq!(content_type, "text/plain; charset=utf-8");
    let certificate_body = to_bytes(certificate_response.into_body(), usize::MAX)
        .await
        .expect("certificate body");
    let certificate_text = String::from_utf8(certificate_body.to_vec()).expect("pem text");
    let begin_markers = certificate_text
        .matches("-----BEGIN CERTIFICATE-----")
        .count();
    assert_eq!(
        begin_markers, 2,
        "chain should contain leaf and issuer certificates"
    );
    let (_, pem) = parse_x509_pem(certificate_text.as_bytes()).expect("leaf pem");
    let (_, leaf) = X509Certificate::from_der(&pem.contents).expect("leaf certificate");
    let san_extension = leaf
        .subject_alternative_name()
        .expect("subjectAltName lookup should succeed")
        .expect("san extension should exist");
    let names = &san_extension.value.general_names;
    assert!(names
        .iter()
        .any(|name| { matches!(name, GeneralName::DNSName(value) if *value == "example.com") }));

    let nonce_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/acme/new-nonce")
                .body(Body::empty())
                .expect("nonce request"),
        )
        .await
        .expect("nonce response");
    let revoke_nonce = nonce_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("revoke nonce header")
        .to_str()
        .expect("nonce str");
    let revoke_nonce = ReplayNonce::parse(revoke_nonce).expect("revoke nonce parse");

    let certificate_b64 = URL_SAFE_NO_PAD.encode(&pem.contents);
    let revoke_payload = json!({
        "certificate": certificate_b64,
        "reason": 1u8,
    });
    let revoke_jws = key
        .sign_json(
            &revoke_payload,
            &revoke_nonce,
            state.acme().revoke_cert_url(),
            KeyBinding::Kid(&account.kid),
        )
        .expect("revoke jws");
    let revoke_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/acme/revoke-cert")
                .header(header::CONTENT_TYPE, "application/jose+json")
                .body(Body::from(
                    serde_json::to_vec(&revoke_jws).expect("serialize"),
                ))
                .expect("revoke request"),
        )
        .await
        .expect("revoke response");
    assert_eq!(revoke_response.status(), StatusCode::OK);
    let revoke_nonce_header = revoke_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("revoke nonce header")
        .to_str()
        .expect("nonce str");
    assert!(!revoke_nonce_header.is_empty());
    let revoke_body = to_bytes(revoke_response.into_body(), usize::MAX)
        .await
        .expect("revoke body");
    let revoke: RevokeCertResponseBody = serde_json::from_slice(&revoke_body).expect("revoke json");
    assert_eq!(revoke.status, "revoked");
    assert_eq!(revoke.reason, Some(1));
    assert!(revoke.revoked_at >= OffsetDateTime::now_utc() - TimeDuration::minutes(5));

    let revoked_fetch = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/acme/cert/{order_id}"))
                .body(Body::empty())
                .expect("revoked certificate request"),
        )
        .await
        .expect("revoked certificate response");
    assert_eq!(revoked_fetch.status(), StatusCode::UNAUTHORIZED);
    let revoked_problem = to_bytes(revoked_fetch.into_body(), usize::MAX)
        .await
        .expect("revoked problem body");
    let revoked_error: AcmeProblemResponse =
        serde_json::from_slice(&revoked_problem).expect("revoked problem json");
    assert_eq!(
        revoked_error.problem_type,
        "urn:ietf:params:acme:error:unauthorized"
    );
    assert_eq!(revoked_error.status, StatusCode::UNAUTHORIZED.as_u16());
    assert!(!revoked_error.detail.is_empty());

    let nonce_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/acme/new-nonce")
                .body(Body::empty())
                .expect("nonce request"),
        )
        .await
        .expect("nonce response");
    let retry_nonce = nonce_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .expect("retry nonce header")
        .to_str()
        .expect("nonce str");
    let retry_nonce = ReplayNonce::parse(retry_nonce).expect("retry nonce parse");

    let second_revoke_jws = key
        .sign_json(
            &revoke_payload,
            &retry_nonce,
            state.acme().revoke_cert_url(),
            KeyBinding::Kid(&account.kid),
        )
        .expect("second revoke jws");
    let second_revoke = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/acme/revoke-cert")
                .header(header::CONTENT_TYPE, "application/jose+json")
                .body(Body::from(
                    serde_json::to_vec(&second_revoke_jws).expect("serialize"),
                ))
                .expect("second revoke request"),
        )
        .await
        .expect("second revoke response");
    assert_eq!(second_revoke.status(), StatusCode::OK);
    let second_body = to_bytes(second_revoke.into_body(), usize::MAX)
        .await
        .expect("second revoke body");
    let second_problem: AcmeProblemResponse =
        serde_json::from_slice(&second_body).expect("second revoke json");
    assert_eq!(
        second_problem.problem_type,
        "urn:ietf:params:acme:error:alreadyRevoked"
    );
    assert_eq!(second_problem.status, StatusCode::OK.as_u16());
    assert!(!second_problem.detail.is_empty());
}

#[tokio::test]
async fn calibration_inspect_reports_cli_equivalent_payload() {
    let state = setup_state();
    let app = build_router(&state);
    let org_salt_b64 = STANDARD.encode(b"test-salt");
    let payload = json!({
        "org_salt": org_salt_b64,
        "calib_text": "Test calibration for audit proof",
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/calib/inspect")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("inspect request"),
        )
        .await
        .expect("inspect response");

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let report: CalibrationInspectBody = serde_json::from_slice(&body).expect("inspect json");

    let (calibration, _) =
        calib_from_text(b"test-salt", "Test calibration for audit proof").expect("calibration");

    assert_eq!(report.calibration_id, calibration.id.as_str());
    assert_eq!(report.fingerprint_hex, calibration.fingerprint_hex());
    assert_eq!(report.fingerprint, calibration.fingerprint_b64());
    assert_eq!(report.ranges.len(), 5);
}

#[tokio::test]
async fn calibration_verify_accepts_matching_calibration() {
    let state = setup_state();
    let app = build_router(&state);
    let org_salt_b64 = STANDARD.encode(b"test-salt");
    let payload = json!({
        "org_salt": org_salt_b64,
        "calib_text": "Test calibration for audit proof",
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/calib/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("verify request"),
        )
        .await
        .expect("verify response");

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let report: CalibrationVerifyBody = serde_json::from_slice(&body).expect("verify json");

    let expected_hex = state.audit_proof_document().calibration_fingerprint;
    assert_eq!(
        report.expectations.fingerprint_hex.as_deref(),
        Some(expected_hex.as_str())
    );
    assert_eq!(report.results.fingerprint_hex, Some(true));
    assert_eq!(report.results.fingerprint_b64, Some(true));
}

#[tokio::test]
async fn calibration_verify_rejects_mismatch_in_strict_mode() {
    let state = setup_state_with_profile(true, None);
    let app = build_router(&state);
    let org_salt_b64 = STANDARD.encode(b"test-salt");
    let payload = json!({
        "org_salt": org_salt_b64,
        "calib_text": "Different calibration payload",
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/calib/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("verify request"),
        )
        .await
        .expect("verify response");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let report: CalibrationVerifyBody = serde_json::from_slice(&body).expect("verify json");

    assert_eq!(report.results.fingerprint_hex, Some(false));
    assert_eq!(report.results.fingerprint_b64, Some(false));
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn pkce_flow_succeeds() {
    let state = setup_state();
    let app = build_router(&state);
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
    assert!(metrics_text.contains("aunsorm_pending_auth_requests"));
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
        TransparencyEventResponse::MediaRecord { .. } => {
            panic!("media records are not expected in this smoke test")
        }
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
    let app = build_router(&state);
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
    let app = build_router(&state);

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
        error
            .error_description
            .contains("device_id cannot be empty"),
        "unexpected error message: {}",
        error.error_description
    );

    let count = state.mdm_directory().device_count().expect("device count");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn mdm_rejects_control_characters_in_platform() {
    let state = setup_state();
    let app = build_router(&state);

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
        error
            .error_description
            .contains("Platform contains control characters"),
        "unexpected error message: {}",
        error.error_description
    );
}

#[tokio::test]
async fn mdm_policy_returns_not_found_for_unknown_platform() {
    let state = setup_state();
    let app = build_router(&state);

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
        error.error_description.contains("Platform not supported"),
        "unexpected error message: {}",
        error.error_description
    );
}

#[tokio::test]
async fn mdm_certificate_plan_rejects_blank_identifier() {
    let state = setup_state();
    let app = build_router(&state);

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
        error
            .error_description
            .contains("device_id cannot be empty"),
        "unexpected error message: {}",
        error.error_description
    );
}

#[tokio::test]
async fn transparency_endpoint_returns_snapshot() {
    let state = setup_state();
    let app = build_router(&state);
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
    let app = build_router(&state);
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
    let app = build_router(&state);
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
    let app = build_router(&state);
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
    let app = build_router(&state);
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
    let app = build_router(&state);
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
    let app = build_router(&state);
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
    let app = build_router(&state);

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
    let (parts, body) = response.into_parts();
    let cache_control = parts
        .headers
        .get(header::CACHE_CONTROL)
        .expect("cache-control header");
    assert_eq!(cache_control, "no-store, no-cache, must-revalidate");
    let pragma = parts.headers.get(header::PRAGMA).expect("pragma header");
    assert_eq!(pragma, "no-cache");
    let expires = parts.headers.get(header::EXPIRES).expect("expires header");
    assert_eq!(expires, "0");
    let body = to_bytes(body, usize::MAX).await.expect("body");
    let payload: RandomNumberPayload = serde_json::from_slice(&body).expect("random json");
    assert!((0..=100).contains(&payload.value));
    assert_eq!(payload.min, 0);
    assert_eq!(payload.max, 100);
    assert_eq!(payload.entropy.len(), 64);
    assert!(payload.entropy.chars().all(|ch| ch.is_ascii_hexdigit()));

    // Test 2: Custom range (15-5000)
    let app2 = build_router(&state);
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
    let (parts2, body2) = response2.into_parts();
    let cache_control2 = parts2
        .headers
        .get(header::CACHE_CONTROL)
        .expect("cache-control header");
    assert_eq!(cache_control2, "no-store, no-cache, must-revalidate");
    let pragma2 = parts2.headers.get(header::PRAGMA).expect("pragma header");
    assert_eq!(pragma2, "no-cache");
    let expires2 = parts2.headers.get(header::EXPIRES).expect("expires header");
    assert_eq!(expires2, "0");
    let body2 = to_bytes(body2, usize::MAX).await.expect("body");
    let payload2: RandomNumberPayload = serde_json::from_slice(&body2).expect("random json");
    assert!((15..=5000).contains(&payload2.value));
    assert_eq!(payload2.min, 15);
    assert_eq!(payload2.max, 5000);

    // Test 3: Invalid range (min > max)
    let app3 = build_router(&state);
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
    let app4 = build_router(&setup_state());
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
    let (parts4, body4) = response4.into_parts();
    let cache_control4 = parts4
        .headers
        .get(header::CACHE_CONTROL)
        .expect("cache-control header");
    assert_eq!(cache_control4, "no-store, no-cache, must-revalidate");
    let pragma4 = parts4.headers.get(header::PRAGMA).expect("pragma header");
    assert_eq!(pragma4, "no-cache");
    let expires4 = parts4.headers.get(header::EXPIRES).expect("expires header");
    assert_eq!(expires4, "0");
    let body4 = to_bytes(body4, usize::MAX).await.expect("body");
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
    let app = build_router(&state);
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
    let app = build_router(&state);
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

#[tokio::test]
async fn jwt_verify_endpoint_accepts_valid_token() {
    let state = setup_state();
    let app = build_router(&state);

    let token_payload = json!({
        "roomId": "room-hall-1",
        "identity": "participant-42",
        "participantName": "Test User",
        "metadata": { "role": "speaker" }
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/security/generate-media-token")
                .header("content-type", "application/json")
                .body(Body::from(token_payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("token response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("token body");
    let token_body: MediaTokenResponseBody = serde_json::from_slice(&body).expect("token json");
    assert_eq!(token_body.room_id, "room-hall-1");
    assert_eq!(token_body.identity, "participant-42");

    let verify_payload = json!({ "token": token_body.token });
    let verify_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/security/jwt-verify")
                .header("content-type", "application/json")
                .body(Body::from(verify_payload.to_string()))
                .expect("verify request"),
        )
        .await
        .expect("verify response");
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .expect("verify body");
    let verify: JwtVerifyResponseBody = serde_json::from_slice(&verify_body).expect("verify json");
    assert!(verify.valid);
    assert!(verify.error.is_none());
    let payload = verify.payload.expect("payload");
    let issued_at = payload
        .get("issuedAt")
        .and_then(serde_json::Value::as_u64)
        .expect("issuedAt claim");
    assert!(issued_at > 0);
    assert_eq!(
        payload.get("issuer").and_then(|value| value.as_str()),
        Some(state.issuer())
    );
    assert_eq!(
        payload.get("audience").and_then(|value| value.as_str()),
        Some("zasian-media")
    );
    assert_eq!(
        payload.get("subject").and_then(|value| value.as_str()),
        Some("participant-42")
    );
    // extras are now nested under "extras" object
    let extras = payload.get("extras").and_then(|v| v.as_object()).expect("extras");
    assert_eq!(
        extras.get("roomId").and_then(|value| value.as_str()),
        Some("room-hall-1")
    );
    assert_eq!(
        extras.get("participantName").and_then(|value| value.as_str()),
        Some("Test User")
    );
    assert!(payload
        .get("jwtId")
        .and_then(|value| value.as_str())
        .is_some());
}

#[tokio::test]
async fn jwt_verify_endpoint_accepts_bearer_prefix() {
    let state = setup_state();
    let app = build_router(&state);

    let token_payload = json!({
        "roomId": "room-bearer",
        "identity": "participant-99"
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/security/generate-media-token")
                .header("content-type", "application/json")
                .body(Body::from(token_payload.to_string()))
                .expect("token request"),
        )
        .await
        .expect("token response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("token body");
    let token_body: MediaTokenResponseBody = serde_json::from_slice(&body).expect("token json");

    let verify_payload = json!({
        "token": format!(" BEARER  {}", token_body.token)
    });

    let verify_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/security/jwt-verify")
                .header("content-type", "application/json")
                .body(Body::from(verify_payload.to_string()))
                .expect("verify request"),
        )
        .await
        .expect("verify response");

    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .expect("verify body");
    let verify: JwtVerifyResponseBody = serde_json::from_slice(&verify_body).expect("verify json");
    assert!(verify.valid);
    assert!(verify.error.is_none());
    let payload = verify.payload.expect("payload");
    assert_eq!(
        payload.get("audience").and_then(|value| value.as_str()),
        Some("zasian-media"),
    );
    assert_eq!(
        payload.get("subject").and_then(|value| value.as_str()),
        Some("participant-99"),
    );
}

#[tokio::test]
async fn jwt_verify_endpoint_rejects_tampered_token() {
    let state = setup_state();
    let app = build_router(&state);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/security/generate-media-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "roomId": "room-compromised",
                        "identity": "intruder"
                    })
                    .to_string(),
                ))
                .expect("token request"),
        )
        .await
        .expect("token response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("token body");
    let token_body: MediaTokenResponseBody = serde_json::from_slice(&body).expect("token json");

    let mut tampered = token_body.token;
    let last = tampered.pop().expect("token char");
    let replacement = if last == 'A' { 'B' } else { 'A' };
    tampered.push(replacement);

    let verify_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/security/jwt-verify")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "token": tampered }).to_string()))
                .expect("verify request"),
        )
        .await
        .expect("verify response");
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .expect("verify body");
    let verify: JwtVerifyResponseBody = serde_json::from_slice(&verify_body).expect("verify json");
    assert!(!verify.valid);
    assert!(verify.payload.is_none());
    let error = verify.error.expect("error");
    assert!(error.contains("Invalid token"));
}

#[tokio::test]
async fn jwt_verify_endpoint_rejects_missing_token() {
    let state = setup_state();
    let app = build_router(&state);

    let verify_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/security/jwt-verify")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "token": "   " }).to_string()))
                .expect("verify request"),
        )
        .await
        .expect("verify response");

    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .expect("verify body");
    let verify: JwtVerifyResponseBody = serde_json::from_slice(&verify_body).expect("verify json");
    assert!(!verify.valid);
    assert!(verify.payload.is_none());
    assert_eq!(verify.error.as_deref(), Some("Token is required"));
}

#[tokio::test]
async fn jwt_verify_endpoint_rejects_tokens_missing_jti() {
    let state = setup_state();
    let app = build_router(&state);

    let mut claims = Claims::new();
    claims.subject = Some("participant-007".to_string());
    claims.issuer = Some(state.issuer().to_owned());
    claims.audience = Some(Audience::Single("zasian-media".to_owned()));
    claims.set_issued_now();
    claims.set_expiration_from_now(state.token_ttl());
    claims.extra.insert(
        "roomId".to_string(),
        Value::String("room-missing-jti".to_string()),
    );

    let signer = state.signer().clone();
    let token = signer
        .sign(&claims)
        .expect("token without jti should still sign");

    let verify_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/security/jwt-verify")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "token": token }).to_string()))
                .expect("verify request"),
        )
        .await
        .expect("verify response");

    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .expect("verify body");
    let verify: JwtVerifyResponseBody = serde_json::from_slice(&verify_body).expect("verify json");
    assert!(!verify.valid);
    assert!(verify.payload.is_none());
    assert_eq!(verify.error.as_deref(), Some("Token missing jti claim"));
}

#[tokio::test]
async fn jwt_verify_endpoint_reports_temporal_claims() {
    let state = setup_state();
    let app = build_router(&state);

    let mut claims = Claims::new();
    claims.subject = Some("participant-temporal".to_string());
    claims.issuer = Some(state.issuer().to_owned());
    claims.audience = Some(Audience::Single("zasian-media".to_owned()));
    claims.ensure_jwt_id();
    claims.set_issued_now();
    let not_before = SystemTime::now()
        .checked_sub(Duration::from_secs(15))
        .unwrap_or_else(SystemTime::now);
    claims.not_before = Some(not_before);
    claims.set_expiration_from_now(state.token_ttl());
    claims.extra.insert(
        "roomId".to_string(),
        Value::String("room-temporal".to_string()),
    );

    let signer = state.signer().clone();
    let token = signer.sign(&claims).expect("token");

    let jti = claims.jwt_id.clone().expect("jti");
    let expiration = claims.expiration.expect("exp");
    state
        .record_token(
            &jti,
            expiration,
            claims.subject.as_deref(),
            Some("zasian-media"),
        )
        .await
        .expect("record token");

    let verify_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/security/jwt-verify")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "token": token }).to_string()))
                .expect("verify request"),
        )
        .await
        .expect("verify response");

    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .expect("verify body");
    let verify: JwtVerifyResponseBody = serde_json::from_slice(&verify_body).expect("verify json");
    assert!(verify.valid);
    let payload = verify.payload.expect("payload");

    let issued_at_value = payload
        .get("issuedAt")
        .and_then(serde_json::Value::as_u64)
        .expect("issuedAt field");
    let expected_issued_at = claims
        .issued_at
        .expect("issued_at")
        .duration_since(UNIX_EPOCH)
        .expect("iat epoch")
        .as_secs();
    assert_eq!(issued_at_value, expected_issued_at);

    let not_before_value = payload
        .get("notBefore")
        .and_then(serde_json::Value::as_u64)
        .expect("notBefore field");
    let expected_not_before = claims
        .not_before
        .expect("nbf")
        .duration_since(UNIX_EPOCH)
        .expect("nbf epoch")
        .as_secs();
    assert_eq!(not_before_value, expected_not_before);
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
    MediaRecord {
        calibration_id: String,
        media_commitment_sha256: String,
        blockchain_tx_hash: String,
        #[serde(default)]
        blockchain_height: Option<u64>,
        #[serde(default)]
        media_profile: Option<String>,
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

#[tokio::test]
async fn test_acme_service_debug() {
    let state = setup_state();
    println!("✓ State created successfully");

    let acme_service = state.acme();
    println!("✓ ACME service accessed successfully");

    let nonce_url = acme_service.new_nonce_url();
    println!("✓ Nonce URL: {}", nonce_url);
}

#[tokio::test]
#[ignore = "pending /security/jwe/encrypt implementation"]
async fn security_jwe_encrypt_contract() {
    // Request: POST /security/jwe/encrypt with a media envelope payload containing
    //          audience, ttlSeconds, and plaintext media session metadata for hybrid encryption.
    // Response: 201 Created with a JSON body exposing compact JWE (field `token`) and
    //           derived key metadata required by the consuming WebRTC bridge.
    todo!("Finalize once the /security/jwe/encrypt endpoint is wired to crypto services");
}

#[tokio::test]
#[ignore = "pending /blockchain/media/record implementation"]
async fn blockchain_media_record_contract() {
    // Request: POST /blockchain/media/record with signed media session identifiers,
    //          ledger anchor hints, and transparency checksum fields generated by the
    //          Zasian bridge.
    // Response: 202 Accepted acknowledging ledger persistence, returning a JSON envelope
    //           with `recordId`, `ledgerAnchor`, and `nextPollAfter` fields for follow-up polling.
    todo!("Enable once blockchain media recording ledger is implemented");
}
