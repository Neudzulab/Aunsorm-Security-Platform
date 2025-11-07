use aunsorm_acme::AcmeJws;
use aunsorm_jwt::{Audience, Claims, Jwk, JwtError, VerificationOptions};
use aunsorm_pqc::{kem::KemAlgorithm, signature::SignatureAlgorithm};
use axum::body::{to_bytes, Body};
#[cfg(feature = "http3-experimental")]
use axum::middleware::{from_fn, Next};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, head, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::SIGNATURE_LENGTH;
use hex::{decode, decode_to_slice};
use sha2::{Digest, Sha256};
use std::array;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

use crate::acme::{
    AcmeProblem, FinalizeOrderOutcome, NewAccountOutcome, NewOrderOutcome, OrderLookupOutcome,
    RevokeCertOutcome,
};

mod acme;

// Global registered devices set for testing
static REGISTERED_DEVICES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn system_time_to_unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn audience_to_string(audience: Option<&Audience>, fallback: &str) -> String {
    match audience {
        Some(Audience::Single(value)) => value.clone(),
        Some(Audience::Multiple(values)) => values
            .first()
            .cloned()
            .unwrap_or_else(|| fallback.to_string()),
        None => fallback.to_string(),
    }
}

fn extract_related_id(claims: &Value) -> Option<String> {
    claims
        .get("relatedId")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn map_jwt_error(err: &JwtError) -> String {
    match err {
        JwtError::Signature => "Invalid token signature".to_string(),
        JwtError::Expired => "Token expired".to_string(),
        JwtError::NotYetValid => "Token not yet valid".to_string(),
        JwtError::IssuedInFuture => "Token issued in the future".to_string(),
        JwtError::MissingJti => "Token missing jti claim".to_string(),
        JwtError::Replay => "Token replay detected".to_string(),
        JwtError::UnsupportedAlgorithm(alg) => format!("Unsupported JWT algorithm: {alg}"),
        JwtError::UnknownKey(kid) => format!("Unknown key id: {kid}"),
        JwtError::MissingKeyId => "Missing key id".to_string(),
        JwtError::Malformed | JwtError::Base64(_) => "Invalid token format".to_string(),
        JwtError::ClaimMismatch(claim) => format!("Claim mismatch: {claim}"),
        JwtError::InvalidClaim(claim, reason) => format!("Invalid claim {claim}: {reason}"),
        JwtError::JtiStore(message) => format!("JTI store error: {message}"),
        JwtError::Io(io) => format!("Token verification I/O error: {io}"),
        JwtError::Serde(err) => format!("Token payload error: {err}"),
        JwtError::TimeConversion => "Time conversion error".to_string(),
        _ => err.to_string(),
    }
}

const BEARER_KEYWORD: &str = "bearer";

fn sanitize_token_input(token: &str) -> Cow<'_, str> {
    let trimmed = token.trim();

    if trimmed.len() == BEARER_KEYWORD.len() && trimmed.eq_ignore_ascii_case(BEARER_KEYWORD) {
        return Cow::Owned(String::new());
    }

    if trimmed.len() > BEARER_KEYWORD.len()
        && trimmed[..BEARER_KEYWORD.len()].eq_ignore_ascii_case(BEARER_KEYWORD)
    {
        let after_keyword = &trimmed[BEARER_KEYWORD.len()..];
        if after_keyword.starts_with(char::is_whitespace) {
            let normalized = after_keyword.trim_start_matches(char::is_whitespace);
            if normalized.is_empty() {
                return Cow::Owned(String::new());
            }
            return Cow::Owned(normalized.to_owned());
        }
    }

    Cow::Borrowed(trimmed)
}
use crate::config::ServerConfig;
use crate::error::{ApiError, ServerError};
use crate::fabric::{FabricDidError, FabricDidVerificationRequest};
#[cfg(feature = "http3-experimental")]
use crate::quic::datagram::{DatagramChannel, MAX_PAYLOAD_BYTES};
#[cfg(feature = "http3-experimental")]
use crate::quic::{build_alt_svc_header_value, spawn_http3_poc, ALT_SVC_MAX_AGE};
use crate::state::{AuditProofDocument, ClockHealthStatus, ServerState};
use crate::transparency::TransparencyEvent as LedgerTransparencyEvent;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;

use aunsorm_core::{calib_from_text, Calibration};

const ZASIAN_MEDIA_AUDIENCE: &str = "zasian-media";

const MIN_ORG_SALT_LEN: usize = 8;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    clock: ClockHealthStatus,
}

pub async fn health(State(state): State<Arc<ServerState>>) -> Json<HealthResponse> {
    let clock = state.clock_health_status().await;
    let status = if clock.status == "ok" {
        "OK"
    } else {
        "DEGRADED"
    };
    Json(HealthResponse { status, clock })
}

pub async fn metrics(State(state): State<Arc<ServerState>>) -> Result<impl IntoResponse, ApiError> {
    let now = SystemTime::now();
    let pending = state.auth_request_count().await;
    let active = state.active_token_count(now).await.map_err(|err| {
        ApiError::server_error(format!("Aktif token sayısı sorgulanamadı: {err}",))
    })?;
    let sfu = state.sfu_context_count(now).await;
    let devices = state
        .registered_device_count()
        .map_err(|err| ApiError::server_error(format!("Kayıtlı cihaz sayısı alınamadı: {err}",)))?;

    let metrics_text = format!(
        "# HELP aunsorm_pending_auth_requests Pending PKCE authorization requests\n\
         # TYPE aunsorm_pending_auth_requests gauge\n\
         aunsorm_pending_auth_requests {pending}\n\n\
         # HELP aunsorm_active_tokens Active OAuth tokens\n\
         # TYPE aunsorm_active_tokens gauge\n\
         aunsorm_active_tokens {active}\n\n\
         # HELP aunsorm_sfu_contexts Active SFU contexts\n\
         # TYPE aunsorm_sfu_contexts gauge\n\
         aunsorm_sfu_contexts {sfu}\n\n\
         # HELP aunsorm_mdm_registered_devices Registered MDM devices\n\
         # TYPE aunsorm_mdm_registered_devices gauge\n\
         aunsorm_mdm_registered_devices {devices}\n",
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics_text,
    ))
}

// Random Number endpoint
#[derive(Deserialize)]
pub struct RandomNumberQuery {
    #[serde(default = "default_min")]
    pub min: u64,
    #[serde(default = "default_max")]
    pub max: u64,
}

const fn default_min() -> u64 {
    0
}
const fn default_max() -> u64 {
    100
}

#[derive(Serialize)]
pub struct RandomNumberResponse {
    pub value: u64,
    pub min: u64,
    pub max: u64,
    pub entropy: String,
}

#[derive(Deserialize)]
pub struct CalibrationRequest {
    pub org_salt: String,
    pub calib_text: String,
}

#[derive(Serialize)]
pub struct CalibrationRangeResponse {
    pub start: u16,
    pub end: u16,
    pub step: u16,
}

#[derive(Serialize)]
pub struct CalibrationInspectResponse {
    pub calibration_id: String,
    pub note_text: String,
    pub alpha_long: u16,
    pub alpha_short: u16,
    pub beta_long: u16,
    pub beta_short: u16,
    pub tau: u16,
    pub fingerprint: String,
    pub fingerprint_hex: String,
    pub ranges: [CalibrationRangeResponse; 5],
}

#[derive(Serialize)]
pub struct CalibrationVerifyResponse {
    pub calibration_id: String,
    pub fingerprint_b64: String,
    pub fingerprint_hex: String,
    pub expectations: CalibrationVerifyExpectations,
    pub results: CalibrationVerifyResults,
}

#[derive(Serialize)]
pub struct CalibrationVerifyExpectations {
    pub id: Option<String>,
    pub fingerprint_b64: Option<String>,
    pub fingerprint_hex: Option<String>,
}

#[derive(Serialize)]
pub struct CalibrationVerifyResults {
    pub id: Option<bool>,
    pub fingerprint_b64: Option<bool>,
    pub fingerprint_hex: Option<bool>,
}

pub async fn calib_inspect(
    Json(request): Json<CalibrationRequest>,
) -> Result<Json<CalibrationInspectResponse>, ApiError> {
    let (calibration, _) = parse_calibration_request(&request)?;
    let response = build_calibration_inspect_response(&calibration);
    Ok(Json(response))
}

pub async fn calib_verify(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<CalibrationRequest>,
) -> Result<(StatusCode, Json<CalibrationVerifyResponse>), ApiError> {
    let (calibration, _) = parse_calibration_request(&request)?;
    let expected_hex = state.audit_proof_document().await.calibration_fingerprint;
    let expected_b64 = hex_to_fingerprint_b64(&expected_hex)?;
    let actual_hex = calibration.fingerprint_hex();
    let actual_b64 = calibration.fingerprint_b64();
    let matches = actual_hex == expected_hex;

    let response = CalibrationVerifyResponse {
        calibration_id: calibration.id.as_str().to_owned(),
        fingerprint_b64: actual_b64,
        fingerprint_hex: actual_hex,
        expectations: CalibrationVerifyExpectations {
            id: None,
            fingerprint_b64: Some(expected_b64),
            fingerprint_hex: Some(expected_hex),
        },
        results: CalibrationVerifyResults {
            id: None,
            fingerprint_b64: Some(matches),
            fingerprint_hex: Some(matches),
        },
    };

    let status = if matches {
        StatusCode::OK
    } else if state.strict() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };

    Ok((status, Json(response)))
}

fn parse_calibration_request(
    request: &CalibrationRequest,
) -> Result<(Calibration, String), ApiError> {
    let org_salt = decode_org_salt(&request.org_salt)?;
    let calib_text = normalize_calibration_text_input(&request.calib_text)?;
    calib_from_text(&org_salt, &calib_text)
        .map_err(|err| ApiError::invalid_request(format!("calibration error: {err}")))
}

fn build_calibration_inspect_response(calibration: &Calibration) -> CalibrationInspectResponse {
    let ranges = array::from_fn(|idx| {
        let range = calibration.ranges[idx];
        CalibrationRangeResponse {
            start: range.start,
            end: range.end,
            step: range.step,
        }
    });

    CalibrationInspectResponse {
        calibration_id: calibration.id.as_str().to_owned(),
        note_text: calibration.note_text().to_owned(),
        alpha_long: calibration.alpha_long,
        alpha_short: calibration.alpha_short,
        beta_long: calibration.beta_long,
        beta_short: calibration.beta_short,
        tau: calibration.tau,
        fingerprint: calibration.fingerprint_b64(),
        fingerprint_hex: calibration.fingerprint_hex(),
        ranges,
    }
}

fn decode_org_salt(value: &str) -> Result<Vec<u8>, ApiError> {
    let trimmed = value.trim();
    let decoded = STANDARD.decode(trimmed).map_err(|err| {
        ApiError::invalid_request(format!("org_salt base64 decode failed: {err}"))
    })?;
    if decoded.len() < MIN_ORG_SALT_LEN {
        return Err(ApiError::invalid_request(format!(
            "org_salt must be at least {MIN_ORG_SALT_LEN} bytes"
        )));
    }
    Ok(decoded)
}

fn normalize_calibration_text_input(value: &str) -> Result<String, ApiError> {
    let mut owned = value.to_owned();
    strip_utf8_bom_mut(&mut owned);
    if owned.trim().is_empty() {
        return Err(ApiError::invalid_request(
            "calibration text cannot be empty",
        ));
    }
    Ok(owned)
}

fn strip_utf8_bom_mut(value: &mut String) {
    const UTF8_BOM: char = '\u{feff}';
    if value.starts_with(UTF8_BOM) {
        value.drain(..UTF8_BOM.len_utf8());
    }
}

fn hex_to_fingerprint_b64(expected_hex: &str) -> Result<String, ApiError> {
    let bytes = decode(expected_hex).map_err(|err| {
        ApiError::server_error(format!(
            "configured calibration fingerprint is not valid hex: {err}"
        ))
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

const ML_KEM_768_ALIASES: &[&str] = &["mlkem768", "kyber-768", "kyber768"];
const ML_KEM_1024_ALIASES: &[&str] = &["mlkem1024", "kyber-1024", "kyber1024"];
const ML_DSA_65_ALIASES: &[&str] = &["mldsa65", "dilithium5", "dilithium-5"];
const FALCON_512_ALIASES: &[&str] = &["falcon512"];
const SPHINCS_SHAKE_128F_ALIASES: &[&str] = &[
    "sphincs-shake-128f",
    "sphincsplus-shake-128f",
    "sphincsplusshake128f",
];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PqcCapabilitiesResponse {
    strict: PqcStrictMode,
    kem: Vec<KemCapability>,
    signatures: Vec<SignatureCapability>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PqcStrictMode {
    env_var: &'static str,
    default_enabled: bool,
    fail_if_unavailable: bool,
    description: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KemCapability {
    algorithm: &'static str,
    available: bool,
    nist_category: &'static str,
    public_key_bytes: usize,
    secret_key_bytes: usize,
    ciphertext_bytes: usize,
    shared_secret_bytes: usize,
    aliases: &'static [&'static str],
    description: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignatureCapability {
    algorithm: &'static str,
    available: bool,
    deterministic: bool,
    nist_category: &'static str,
    public_key_bytes: usize,
    secret_key_bytes: usize,
    signature_bytes: usize,
    aliases: &'static [&'static str],
    client_actions: Vec<&'static str>,
    runtime_assertions: Vec<&'static str>,
    references: Vec<&'static str>,
    description: &'static str,
}

#[derive(Debug, Serialize, Deserialize)]
struct Http3DatagramChannelDescriptor {
    channel: u8,
    label: Cow<'static, str>,
    purpose: Cow<'static, str>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Http3DatagramCapabilities {
    supported: bool,
    max_payload_bytes: Option<usize>,
    channels: Vec<Http3DatagramChannelDescriptor>,
    notes: Option<Cow<'static, str>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Http3CapabilitiesResponse {
    enabled: bool,
    status: Cow<'static, str>,
    alt_svc_port: Option<u16>,
    alt_svc_max_age: Option<u32>,
    datagrams: Http3DatagramCapabilities,
}

pub async fn random_number(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<RandomNumberQuery>,
) -> Result<Response, ApiError> {
    let min = params.min;
    let max = params.max;

    if min > max {
        return Err(ApiError::invalid_request(
            "min value cannot be greater than max value",
        ));
    }

    let (value, entropy) = state.random_value_with_proof(min, max);
    let mut response = Json(RandomNumberResponse {
        value,
        min,
        max,
        entropy: hex::encode(entropy),
    })
    .into_response();

    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));

    Ok(response)
}

fn build_pqc_capabilities_document() -> PqcCapabilitiesResponse {
    PqcCapabilitiesResponse {
        strict: PqcStrictMode {
            env_var: "AUNSORM_STRICT",
            default_enabled: false,
            fail_if_unavailable: true,
            description:
                "Set to `1` or `true` to require PQC negotiation and reject classical fallbacks.",
        },
        kem: build_kem_capabilities(),
        signatures: build_signature_capabilities(),
    }
}

fn build_kem_capabilities() -> Vec<KemCapability> {
    [
        (
            KemAlgorithm::MlKem768,
            "3",
            1_184,
            2_400,
            1_088,
            32,
            ML_KEM_768_ALIASES,
            "Module-lattice KEM aligned with ML-KEM-768 / Kyber768 parameters.",
        ),
        (
            KemAlgorithm::MlKem1024,
            "5",
            1_568,
            3_168,
            1_568,
            32,
            ML_KEM_1024_ALIASES,
            "Module-lattice KEM aligned with ML-KEM-1024 / Kyber1024 parameters.",
        ),
    ]
    .into_iter()
    .map(
        |(
            algorithm,
            nist_category,
            public_key_bytes,
            secret_key_bytes,
            ciphertext_bytes,
            shared_secret_bytes,
            aliases,
            description,
        )| {
            KemCapability {
                algorithm: algorithm.name(),
                available: algorithm.is_available(),
                nist_category,
                public_key_bytes,
                secret_key_bytes,
                ciphertext_bytes,
                shared_secret_bytes,
                aliases,
                description,
            }
        },
    )
    .collect()
}

fn build_signature_capabilities() -> Vec<SignatureCapability> {
    [
        (
            SignatureAlgorithm::MlDsa65,
            ML_DSA_65_ALIASES,
            "Deterministic module-lattice signature (ML-DSA-65 / Dilithium5).",
        ),
        (
            SignatureAlgorithm::Falcon512,
            FALCON_512_ALIASES,
            "Floating-point lattice signature optimized for bandwidth-sensitive deployments.",
        ),
        (
            SignatureAlgorithm::SphincsShake128f,
            SPHINCS_SHAKE_128F_ALIASES,
            "Stateless hash-based signature using the SHAKE-128f-simple parameter set.",
        ),
    ]
    .into_iter()
    .map(|(algorithm, aliases, description)| {
        let checklist = algorithm.checklist();
        SignatureCapability {
            algorithm: algorithm.name(),
            available: algorithm.is_available(),
            deterministic: checklist.deterministic(),
            nist_category: checklist.nist_category(),
            public_key_bytes: checklist.public_key_bytes(),
            secret_key_bytes: checklist.secret_key_bytes(),
            signature_bytes: checklist.signature_bytes(),
            aliases,
            client_actions: checklist.client_actions().collect(),
            runtime_assertions: checklist.runtime_assertions().collect(),
            references: checklist.references().collect(),
            description,
        }
    })
    .collect()
}

async fn pqc_capabilities() -> Json<PqcCapabilitiesResponse> {
    Json(build_pqc_capabilities_document())
}

#[cfg(feature = "http3-experimental")]
async fn http3_capabilities(
    State(state): State<Arc<ServerState>>,
) -> (StatusCode, Json<Http3CapabilitiesResponse>) {
    let response = Http3CapabilitiesResponse {
        enabled: true,
        status: Cow::Borrowed("active"),
        alt_svc_port: Some(state.listen_port()),
        alt_svc_max_age: Some(ALT_SVC_MAX_AGE),
        datagrams: Http3DatagramCapabilities {
            supported: true,
            max_payload_bytes: Some(MAX_PAYLOAD_BYTES),
            channels: vec![
                Http3DatagramChannelDescriptor {
                    channel: DatagramChannel::Telemetry.as_u8(),
                    label: Cow::Borrowed("telemetry"),
                    purpose: Cow::Borrowed(
                        "OpenTelemetry metrik anlık görüntüsü (OtelPayload)",
                    ),
                },
                Http3DatagramChannelDescriptor {
                    channel: DatagramChannel::Audit.as_u8(),
                    label: Cow::Borrowed("audit"),
                    purpose: Cow::Borrowed("Yetkilendirme denetim olayları (AuditEvent)"),
                },
                Http3DatagramChannelDescriptor {
                    channel: DatagramChannel::Ratchet.as_u8(),
                    label: Cow::Borrowed("ratchet"),
                    purpose: Cow::Borrowed(
                        "Oturum ratchet ilerleme gözlemleri (RatchetProbe)",
                    ),
                },
            ],
            notes: Some(Cow::Borrowed(
                "Datagram yükleri postcard ile serileştirilir; en fazla 1150 bayt payload desteklenir.",
            )),
        },
    };
    (StatusCode::OK, Json(response))
}

#[cfg(not(feature = "http3-experimental"))]
async fn http3_capabilities(
    State(_state): State<Arc<ServerState>>,
) -> (StatusCode, Json<Http3CapabilitiesResponse>) {
    let response = Http3CapabilitiesResponse {
        enabled: false,
        status: Cow::Borrowed("feature_disabled"),
        alt_svc_port: None,
        alt_svc_max_age: None,
        datagrams: Http3DatagramCapabilities {
            supported: false,
            max_payload_bytes: None,
            channels: Vec::new(),
            notes: Some(Cow::Borrowed(
                "HTTP/3 desteği pasif. `--features http3-experimental` ile derleyerek etkinleştirin.",
            )),
        },
    };
    (StatusCode::NOT_IMPLEMENTED, Json(response))
}

const APPLICATION_JOSE_JSON: &str = "application/jose+json";

fn is_jose_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case(APPLICATION_JOSE_JSON))
        })
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn apply_acme_headers(response: &mut Response, nonce: &str) {
    let replay_name = header::HeaderName::from_static("replay-nonce");
    let value = HeaderValue::from_str(nonce).expect("nonce header değeri geçerli olmalı");
    response.headers_mut().insert(replay_name, value);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn acme_problem_response(problem: &AcmeProblem, nonce: &str) -> Response {
    let mut response = (problem.status(), Json(problem.body())).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    apply_acme_headers(&mut response, nonce);
    response
}

fn acme_account_response(outcome: NewAccountOutcome, nonce: &str) -> Response {
    let mut response = (outcome.status, Json(outcome.response)).into_response();
    apply_acme_headers(&mut response, nonce);
    if let Ok(value) = HeaderValue::from_str(&outcome.location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    if let Some(link) = outcome.link_terms {
        let formatted = format!("<{link}>; rel=\"terms-of-service\"");
        if let Ok(value) = HeaderValue::from_str(&formatted) {
            response.headers_mut().insert(header::LINK, value);
        }
    }
    response
}

fn acme_order_response(outcome: NewOrderOutcome, nonce: &str) -> Response {
    let mut response = (StatusCode::CREATED, Json(outcome.response)).into_response();
    apply_acme_headers(&mut response, nonce);
    if let Ok(value) = HeaderValue::from_str(&outcome.location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

fn acme_finalize_response(outcome: FinalizeOrderOutcome, nonce: &str) -> Response {
    let mut response = (StatusCode::OK, Json(outcome.response)).into_response();
    apply_acme_headers(&mut response, nonce);
    if let Ok(value) = HeaderValue::from_str(&outcome.location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

fn acme_order_status_response(outcome: OrderLookupOutcome, nonce: &str) -> Response {
    let mut response = (StatusCode::OK, Json(outcome.response)).into_response();
    apply_acme_headers(&mut response, nonce);
    if let Ok(value) = HeaderValue::from_str(&outcome.location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

fn acme_revoke_response(outcome: &RevokeCertOutcome, nonce: &str) -> Response {
    #[derive(Serialize)]
    struct Body {
        status: &'static str,
        #[serde(rename = "revokedAt", with = "time::serde::rfc3339")]
        revoked_at: OffsetDateTime,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<u8>,
    }

    let body = Body {
        status: "revoked",
        revoked_at: outcome.revoked_at,
        reason: outcome.reason,
    };
    let mut response = (StatusCode::OK, Json(body)).into_response();
    apply_acme_headers(&mut response, nonce);
    response
}

async fn acme_new_account(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
) -> Response {
    let service = state.acme();
    let (parts, body) = request.into_parts();
    if !is_jose_content_type(&parts.headers) {
        let nonce = service.next_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.handle_new_account(jws).await {
        Ok(outcome) => {
            let nonce = service.next_nonce().await;
            acme_account_response(outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.next_nonce().await;
            acme_problem_response(&problem, &nonce)
        }
    }
}

async fn acme_account_lookup(
    Path(account_id): Path<String>,
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
) -> Response {
    let service = state.acme();
    let (parts, body) = request.into_parts();
    if !is_jose_content_type(&parts.headers) {
        let nonce = service.next_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.handle_account_lookup(&account_id, jws).await {
        Ok(outcome) => {
            let nonce = service.next_nonce().await;
            acme_account_response(outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.next_nonce().await;
            acme_problem_response(&problem, &nonce)
        }
    }
}

async fn acme_new_order(State(state): State<Arc<ServerState>>, request: Request<Body>) -> Response {
    let service = state.acme();
    let (parts, body) = request.into_parts();
    if !is_jose_content_type(&parts.headers) {
        let nonce = service.next_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.handle_new_order(jws).await {
        Ok(outcome) => {
            let nonce = service.next_nonce().await;
            acme_order_response(outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.next_nonce().await;
            acme_problem_response(&problem, &nonce)
        }
    }
}

async fn acme_order_status(
    Path(order_id): Path<String>,
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
) -> Response {
    let service = state.acme();
    let (parts, body) = request.into_parts();
    if !is_jose_content_type(&parts.headers) {
        let nonce = service.next_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.handle_order_lookup(&order_id, jws).await {
        Ok(outcome) => {
            let nonce = service.next_nonce().await;
            acme_order_status_response(outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.next_nonce().await;
            acme_problem_response(&problem, &nonce)
        }
    }
}

async fn acme_finalize_order(
    Path(order_id): Path<String>,
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
) -> Response {
    let service = state.acme();
    let (parts, body) = request.into_parts();
    if !is_jose_content_type(&parts.headers) {
        let nonce = service.next_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.handle_finalize_order(&order_id, jws).await {
        Ok(outcome) => {
            let nonce = service.next_nonce().await;
            acme_finalize_response(outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.next_nonce().await;
            acme_problem_response(&problem, &nonce)
        }
    }
}

async fn acme_get_certificate(
    Path(order_id): Path<String>,
    State(state): State<Arc<ServerState>>,
) -> Response {
    let service = state.acme();
    match service.certificate_pem_bundle(&order_id).await {
        Ok(bundle) => {
            let nonce = service.next_nonce().await;
            let mut response = Response::new(Body::from(bundle));
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            apply_acme_headers(&mut response, &nonce);
            response
        }
        Err(problem) => {
            let nonce = service.next_nonce().await;
            acme_problem_response(&problem, &nonce)
        }
    }
}

async fn acme_revoke_certificate(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
) -> Response {
    let service = state.acme();
    let (parts, body) = request.into_parts();
    if !is_jose_content_type(&parts.headers) {
        let nonce = service.next_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.next_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.revoke_certificate(jws).await {
        Ok(outcome) => {
            let nonce = service.next_nonce().await;
            acme_revoke_response(&outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.next_nonce().await;
            acme_problem_response(&problem, &nonce)
        }
    }
}

// JWT Verify endpoint
#[derive(Deserialize)]
pub struct JwtVerifyRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct JwtPayload {
    pub subject: String,
    pub audience: String,
    pub issuer: String,
    pub expiration: u64,
    #[serde(rename = "issuedAt", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
    #[serde(rename = "relatedId", skip_serializing_if = "Option::is_none")]
    pub related_id: Option<String>,
    #[serde(rename = "jwtId", skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,
    /// Non-standard claim keys (roomId, participantName, metadata, etc.) are
    /// grouped under this object to avoid name collisions with standard JWT claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extras: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize)]
pub struct JwtVerifyResponse {
    pub valid: bool,
    #[serde(default)]
    pub payload: Option<JwtPayload>,
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn verify_jwt_token(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<JwtVerifyRequest>,
) -> Json<JwtVerifyResponse> {
    Json(verify_token_for_audience(&state, request.token.trim(), state.audience()).await)
}

pub async fn verify_media_token(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<JwtVerifyRequest>,
) -> Json<JwtVerifyResponse> {
    Json(verify_token_for_audience(&state, request.token.trim(), ZASIAN_MEDIA_AUDIENCE).await)
}

async fn verify_token_for_audience(
    state: &Arc<ServerState>,
    token: &str,
    expected_audience: &str,
) -> JwtVerifyResponse {
    tracing::info!("ROUTES.RS: verifying token with expected audience {expected_audience}");

    let normalized_token = sanitize_token_input(token);

    if normalized_token.is_empty() {
        return JwtVerifyResponse {
            valid: false,
            payload: None,
            error: Some("Token is required".to_string()),
        };
    }

    let verifier = state.verifier().clone();
    let issuer = state.issuer().to_string();

    let options = VerificationOptions {
        issuer: Some(issuer.clone()),
        audience: Some(expected_audience.to_owned()),
        require_jti: true,
        ..VerificationOptions::default()
    };

    match verifier.verify(normalized_token.as_ref(), &options) {
        Ok(claims) => {
            let payload_value = match serde_json::to_value(&claims) {
                Ok(value) => value,
                Err(err) => {
                    return JwtVerifyResponse {
                        valid: false,
                        payload: None,
                        error: Some(format!("Token payload error: {err}")),
                    };
                }
            };

            if let Some(jti) = claims.jwt_id.clone() {
                match state.is_token_active(&jti, SystemTime::now()).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return JwtVerifyResponse {
                            valid: false,
                            payload: None,
                            error: Some("Token revoked or expired".to_string()),
                        };
                    }
                    Err(err) => {
                        return JwtVerifyResponse {
                            valid: false,
                            payload: None,
                            error: Some(format!("Token ledger error: {err}")),
                        };
                    }
                }
            }

            let related_id = extract_related_id(&payload_value);

            // Build extras map by removing standard JWT keys from the serialized
            // claim object. This prevents key collisions when we also expose
            // canonical top-level fields (subject/audience/issuer/etc.).
            let mut extras = serde_json::Map::new();
            if let serde_json::Value::Object(map) = &payload_value {
                for (k, v) in map {
                    match k.as_str() {
                        "iss" | "sub" | "aud" | "exp" | "nbf" | "iat" | "jti" => {
                            // skip standard JWT names
                        }
                        _ => {
                            extras.insert(k.clone(), v.clone());
                        }
                    }
                }
            }

            let payload = JwtPayload {
                subject: claims
                    .subject
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                audience: audience_to_string(claims.audience.as_ref(), expected_audience),
                issuer: claims.issuer.clone().unwrap_or_else(|| issuer.clone()),
                expiration: claims.expiration.map_or(0, system_time_to_unix_seconds),
                issued_at: claims.issued_at.map(system_time_to_unix_seconds),
                not_before: claims.not_before.map(system_time_to_unix_seconds),
                related_id,
                jwt_id: claims.jwt_id.clone(),
                extras: if extras.is_empty() {
                    None
                } else {
                    Some(extras)
                },
            };

            JwtVerifyResponse {
                valid: true,
                payload: Some(payload),
                error: None,
            }
        }
        Err(err) => JwtVerifyResponse {
            valid: false,
            payload: None,
            error: Some(map_jwt_error(&err)),
        },
    }
}

#[derive(Deserialize)]
pub struct MediaTokenRequest {
    #[serde(rename = "roomId")]
    pub room_id: String,
    pub identity: String,
    #[serde(rename = "participantName")]
    pub participant_name: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Serialize)]
pub struct MediaTokenResponse {
    pub token: String,
    #[serde(rename = "ttlSeconds")]
    pub ttl_seconds: u64,
    pub driver: String,
    #[serde(rename = "bridgeUrl")]
    pub bridge_url: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(rename = "roomId")]
    pub room_id: String,
    pub identity: String,
}

pub async fn generate_media_token(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<MediaTokenRequest>,
) -> Result<Json<MediaTokenResponse>, ApiError> {
    if request.room_id.trim().is_empty() {
        return Err(ApiError::invalid_request("roomId boş olamaz"));
    }
    if request.identity.trim().is_empty() {
        return Err(ApiError::invalid_request("identity boş olamaz"));
    }
    if request.identity.chars().any(char::is_control) {
        return Err(ApiError::invalid_request(
            "identity kontrol karakteri içeremez",
        ));
    }

    let participant_name = request
        .participant_name
        .clone()
        .unwrap_or_else(|| request.identity.clone());

    let mut claims = Claims::new();
    claims.subject = Some(request.identity.clone());
    claims.issuer = Some(state.issuer().to_owned());
    claims.audience = Some(Audience::Single(ZASIAN_MEDIA_AUDIENCE.to_owned()));
    claims.set_issued_now();
    claims.set_expiration_from_now(state.token_ttl());
    claims
        .extra
        .insert("roomId".to_owned(), Value::String(request.room_id.clone()));
    claims.extra.insert(
        "participantName".to_owned(),
        Value::String(participant_name.clone()),
    );
    if let Some(metadata_value) = request.metadata.clone() {
        claims.extra.insert("metadata".to_owned(), metadata_value);
    }

    let token = state
        .signer()
        .sign(&mut claims)
        .map_err(|err| ApiError::server_error(format!("Token imzalanamadı: {err}")))?;
    let issued_at = claims.issued_at.unwrap_or_else(SystemTime::now);
    let expires_at = claims
        .expiration
        .ok_or_else(|| ApiError::server_error("exp claim is missing"))?;
    let jti = claims
        .jwt_id
        .clone()
        .ok_or_else(|| ApiError::server_error("JTI üretilemedi"))?;

    state
        .record_token(
            &jti,
            expires_at,
            claims.subject.as_deref(),
            Some(ZASIAN_MEDIA_AUDIENCE),
        )
        .await
        .map_err(|err| ApiError::server_error(format!("Token kaydı başarısız: {err}")))?;

    let ttl_seconds = state.token_ttl().as_secs();
    let bridge_url = std::env::var("ZASIAN_WEBSOCKET_URL")
        .or_else(|_| std::env::var("ZASIAN_HOST").map(|host| format!("wss://{host}:50036/zasian")))
        .unwrap_or_else(|_| "wss://localhost:50036/zasian".to_owned());

    Ok(Json(MediaTokenResponse {
        token,
        ttl_seconds,
        driver: "zasian".to_owned(),
        bridge_url,
        issued_at: format_timestamp(issued_at),
        expires_at: format_timestamp(expires_at),
        room_id: request.room_id,
        identity: request.identity,
    }))
}

pub async fn security_jwe_encrypt() -> Response {
    todo!("Planned for v0.6.0: envelope encryption service stub")
}

fn format_timestamp(time: SystemTime) -> String {
    OffsetDateTime::from(time)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

// MDM endpoints
#[derive(Deserialize)]
pub struct MdmRegisterRequest {
    pub device_id: String,
    pub platform: String,
    pub owner: String,
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub display_name: Option<String>,
    pub platform: String,
    pub enrolled_at: u64, // Unix timestamp
    pub last_seen: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub certificate_serial: Option<String>,
}

#[derive(Serialize)]
pub struct PolicyRule {
    // Mock policy rule struct
}

#[derive(Serialize)]
pub struct PolicyDocument {
    pub version: String,
    pub description: String,
    pub published_at: u64,
    pub rules: Vec<PolicyRule>,
}

#[derive(Serialize)]
pub struct DeviceCertificatePlan {
    pub device_id: String,
    pub owner: String,
    pub platform: String,
    pub profile_name: String,
    pub certificate_authority: String,
    pub distribution_endpoints: Vec<String>,
    pub enrollment_mode: String, // EnrollmentMode as string
    pub bootstrap_package: String,
    pub grace_period_hours: u32,
    pub next_renewal: u64,
}

#[derive(Serialize)]
pub struct MdmRegisterResponse {
    pub device: DeviceRecord,
    pub policy: PolicyDocument,
    pub certificate: DeviceCertificatePlan,
}

pub async fn register_device(
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<MdmRegisterRequest>,
) -> Result<Json<MdmRegisterResponse>, ApiError> {
    // Validate device_id
    let device_id = request.device_id.trim();
    if device_id.is_empty() {
        return Err(ApiError::invalid_request("device_id cannot be empty"));
    }
    if device_id.chars().any(char::is_control) {
        return Err(ApiError::invalid_request(
            "device_id is invalid - contains control characters",
        ));
    }

    // Validate owner
    let owner = request.owner.trim();
    if owner.is_empty() {
        return Err(ApiError::invalid_request(
            "owner is invalid - cannot be empty",
        ));
    }
    if owner.chars().any(char::is_control) {
        return Err(ApiError::invalid_request(
            "owner is invalid - contains control characters",
        ));
    }

    // Validate platform
    if request.platform.is_empty() {
        return Err(ApiError::invalid_request("Platform cannot be empty"));
    }
    if request.platform.chars().any(char::is_control) {
        return Err(ApiError::invalid_request(
            "Platform contains control characters",
        ));
    }

    // Check for duplicate registration
    {
        let mut registered = REGISTERED_DEVICES.lock().unwrap();
        if registered.is_none() {
            *registered = Some(HashSet::new());
        }

        let devices = registered.as_mut().unwrap();
        let device_exists = devices.contains(&request.device_id);
        devices.insert(request.device_id.clone());
        drop(registered);

        if device_exists {
            return Err(ApiError::invalid_request("Device already registered"));
        }
    }

    let now = 1_700_000_000_u64; // Mock timestamp
    let device_id = request.device_id.clone();
    let owner = request.owner.clone();
    let platform = request.platform.clone();

    Ok(Json(MdmRegisterResponse {
        device: DeviceRecord {
            device_id: request.device_id,
            owner: request.owner,
            display_name: request.display_name,
            platform: request.platform,
            enrolled_at: now,
            last_seen: now,
            certificate_serial: None,
        },
        policy: PolicyDocument {
            version: "2025.10-ios".to_string(),
            description: "Default iOS policy".to_string(),
            published_at: now,
            rules: vec![],
        },
        certificate: DeviceCertificatePlan {
            device_id,
            owner,
            platform,
            profile_name: "aunsorm-mdm-default".to_string(),
            certificate_authority: "Aunsorm MDM CA".to_string(),
            distribution_endpoints: vec!["https://mdm.aunsorm.com/enroll".to_string()],
            enrollment_mode: "Automated".to_string(),
            bootstrap_package: "com.aunsorm.mdm.bootstrap".to_string(),
            grace_period_hours: 24,
            next_renewal: now + 86400, // +1 day
        },
    }))
}

pub async fn fetch_policy(
    State(_state): State<Arc<ServerState>>,
    Path(platform): Path<String>,
) -> Result<Json<aunsorm_mdm::PolicyDocument>, ApiError> {
    if platform.is_empty() {
        return Err(ApiError::invalid_request("Platform cannot be empty"));
    }

    // Only support iOS for now
    if platform != "ios" {
        return Err(ApiError::not_found("Platform not supported"));
    }

    // Return sample policy for iOS
    let rules = vec![
        aunsorm_mdm::PolicyRule {
            id: "passcode".to_string(),
            statement: "Device must have a passcode set".to_string(),
            mandatory: true,
            remediation: Some("Install configuration profile".to_string()),
        },
        aunsorm_mdm::PolicyRule {
            id: "encryption".to_string(),
            statement: "Device encryption must be enabled".to_string(),
            mandatory: true,
            remediation: Some("Enable FileVault or BitLocker".to_string()),
        },
        aunsorm_mdm::PolicyRule {
            id: "updates".to_string(),
            statement: "System updates must be applied monthly".to_string(),
            mandatory: false,
            remediation: None,
        },
    ];

    let policy = aunsorm_mdm::PolicyDocument {
        version: "2025.10-ios".to_string(),
        description: "iOS security policy for Aunsorm MDM".to_string(),
        published_at: std::time::SystemTime::now(),
        rules,
    };

    Ok(Json(policy))
}

pub async fn fetch_certificate_plan(
    State(_state): State<Arc<ServerState>>,
    Path(device_id): Path<String>,
) -> Result<Json<aunsorm_mdm::DeviceCertificatePlan>, ApiError> {
    let device_id = device_id.trim();
    if device_id.is_empty() {
        return Err(ApiError::invalid_request("device_id cannot be empty"));
    }

    // Return 404 for unknown devices
    if device_id == "unknown-device" {
        return Err(ApiError::not_found("Device not found"));
    }

    // Create a certificate plan for the device
    let plan = aunsorm_mdm::DeviceCertificatePlan {
        device_id: device_id.to_string(),
        owner: "test-owner".to_string(),
        platform: aunsorm_mdm::DevicePlatform::Ios,
        profile_name: "aunsorm-mdm-default".to_string(),
        certificate_authority: "CN=Aunsorm Device CA,O=Aunsorm".to_string(),
        distribution_endpoints: vec![
            "https://mdm.aunsorm.dev/scep".to_string(),
            "acme://mdm.aunsorm.dev/device".to_string(),
        ],
        enrollment_mode: aunsorm_mdm::EnrollmentMode::Automated,
        bootstrap_package: "aunsorm-mdm.pkg".to_string(),
        grace_period_hours: 72,
        next_renewal: 1_234_567_890,
    };

    Ok(Json(plan))
}

// OAuth endpoints
#[derive(Deserialize)]
pub struct OAuthBeginRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub subject: Option<String>,
}

#[derive(Serialize)]
pub struct OAuthBeginResponse {
    pub code: String,
    pub state: Option<String>,
    pub expires_in: u64,
}

fn normalize_scope(
    scope: Option<&str>,
    allowed_scopes: &[String],
) -> Result<Option<String>, ApiError> {
    let Some(scope_value) = scope else {
        return Ok(None);
    };
    let trimmed = scope_value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::invalid_scope("scope değeri boş bırakılamaz"));
    }
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for token in trimmed.split_whitespace() {
        if token.chars().any(char::is_control) {
            return Err(ApiError::invalid_scope(
                "scope değeri kontrol karakteri içeremez",
            ));
        }
        if !allowed_scopes.iter().any(|allowed| allowed == token) {
            return Err(ApiError::invalid_scope(format!(
                "scope değeri izinli değil: {token}",
            )));
        }
        if seen.insert(token) {
            normalized.push(token);
        }
    }
    Ok(Some(normalized.join(" ")))
}

pub async fn begin_auth(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<OAuthBeginRequest>,
) -> Result<Json<OAuthBeginResponse>, ApiError> {
    if payload.code_challenge_method != "S256" {
        return Err(ApiError::invalid_request(
            "PKCE yöntemi yalnızca S256 desteklenir",
        ));
    }

    if payload.client_id.chars().any(char::is_control) {
        return Err(ApiError::invalid_request(
            "client_id kontrol karakteri içeremez",
        ));
    }
    let client_id = payload.client_id.trim();
    if client_id.is_empty() {
        return Err(ApiError::invalid_request("client_id boş bırakılamaz"));
    }
    let client = state
        .oauth_client(client_id)
        .ok_or_else(|| ApiError::invalid_client("client_id kayıtlı değil"))?;

    let redirect_uri = payload.redirect_uri.trim();
    if redirect_uri.is_empty() {
        return Err(ApiError::invalid_redirect_uri("redirect_uri gereklidir"));
    }

    let is_https = redirect_uri.starts_with("https://");
    let is_localhost = redirect_uri.starts_with("http://localhost")
        || redirect_uri.starts_with("http://127.0.0.1");
    if !(is_https || is_localhost) {
        return Err(ApiError::invalid_redirect_uri(
            "redirect_uri HTTPS kullanmalıdır (localhost için HTTP izinli)",
        ));
    }
    if !client.allows_redirect(redirect_uri) {
        return Err(ApiError::invalid_redirect_uri(
            "redirect_uri kayıtlı istemci için yetkili değil",
        ));
    }

    if let Some(state_value) = &payload.state {
        if state_value.chars().any(char::is_control) {
            return Err(ApiError::invalid_request(
                "state kontrol karakteri içeremez",
            ));
        }
    }

    let normalized_scope = normalize_scope(payload.scope.as_deref(), client.allowed_scopes())?;

    let subject = if let Some(subject) = payload.subject {
        if subject.chars().any(char::is_control) {
            return Err(ApiError::invalid_request(
                "subject kontrol karakteri içeremez",
            ));
        }
        let trimmed = subject.trim();
        if trimmed.is_empty() {
            return Err(ApiError::invalid_request("subject cannot be empty"));
        }
        trimmed.to_owned()
    } else {
        format!("client:{client_id}")
    };

    if URL_SAFE_NO_PAD
        .decode(payload.code_challenge.as_bytes())
        .map(|bytes| bytes.len())
        .unwrap_or_default()
        != Sha256::output_size()
    {
        return Err(ApiError::invalid_request(
            "code_challenge değeri base64url kodlanmış SHA-256 çıktısı olmalıdır",
        ));
    }

    let code = state
        .register_auth_request(
            subject,
            client_id.to_owned(),
            redirect_uri.to_owned(),
            payload.state.clone(),
            normalized_scope,
            payload.code_challenge,
        )
        .await;

    Ok(Json(OAuthBeginResponse {
        code,
        state: payload.state,
        expires_in: crate::state::auth_ttl().as_secs(),
    }))
}

#[derive(Deserialize)]
pub struct OAuthTokenRequest {
    pub grant_type: String,
    pub code: String,
    pub code_verifier: String,
    pub client_id: String,
    pub redirect_uri: String,
}

#[derive(Serialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

pub async fn exchange_token(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<OAuthTokenRequest>,
) -> Result<Json<OAuthTokenResponse>, ApiError> {
    if payload.grant_type != "authorization_code" {
        return Err(ApiError::invalid_request(
            "grant_type 'authorization_code' olmalıdır",
        ));
    }

    if payload.code_verifier.len() < 43 || payload.code_verifier.len() > 128 {
        return Err(ApiError::invalid_request(
            "code_verifier uzunluğu 43 ile 128 karakter arasında olmalıdır",
        ));
    }

    let auth_request = state
        .consume_auth_request(&payload.code)
        .await
        .ok_or_else(|| {
            ApiError::invalid_grant("Yetkilendirme kodu bulunamadı veya süresi doldu")
        })?;

    if auth_request.client_id != payload.client_id {
        return Err(ApiError::invalid_client("client_id eşleşmiyor"));
    }

    if auth_request.redirect_uri != payload.redirect_uri {
        return Err(ApiError::invalid_grant("redirect_uri eşleşmiyor"));
    }

    let digest = Sha256::digest(payload.code_verifier.as_bytes());
    let expected_challenge = URL_SAFE_NO_PAD.encode(digest);
    if expected_challenge != auth_request.code_challenge {
        return Err(ApiError::invalid_grant("PKCE doğrulaması başarısız"));
    }

    let mut claims = Claims::new();
    claims.subject = Some(auth_request.subject);
    claims.issuer = Some(state.issuer().to_owned());
    claims.audience = Some(Audience::Single(state.audience().to_owned()));
    claims.set_issued_now();
    claims.set_expiration_from_now(state.token_ttl());
    claims.extra.insert(
        "clientId".to_string(),
        Value::String(payload.client_id.clone()),
    );
    if let Some(scope) = auth_request.scope {
        claims
            .extra
            .insert("scope".to_string(), Value::String(scope));
    }

    let access_token = state
        .signer()
        .sign(&mut claims)
        .map_err(|err| ApiError::server_error(format!("Token imzalanamadı: {err}")))?;
    let jti = claims
        .jwt_id
        .clone()
        .ok_or_else(|| ApiError::server_error("JTI üretilemedi"))?;
    let expires_at = claims
        .expiration
        .ok_or_else(|| ApiError::server_error("exp claim is missing"))?;
    let audience_repr = claims
        .audience
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|err| ApiError::server_error(format!("audience serileştirilemedi: {err}")))?;
    state
        .record_token(
            &jti,
            expires_at,
            claims.subject.as_deref(),
            audience_repr.as_deref(),
        )
        .await
        .map_err(|err| ApiError::server_error(format!("Token kaydı başarısız: {err}")))?;

    Ok(Json(OAuthTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.token_ttl().as_secs(),
    }))
}

#[derive(Deserialize)]
pub struct OAuthIntrospectRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct OAuthIntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

pub async fn introspect_token(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<OAuthIntrospectRequest>,
) -> Result<Json<OAuthIntrospectResponse>, ApiError> {
    let token = request.token.trim();
    if token.is_empty() {
        return Err(ApiError::invalid_request("token gereklidir"));
    }

    let options = VerificationOptions {
        issuer: Some(state.issuer().to_owned()),
        audience: Some(state.audience().to_owned()),
        require_jti: true,
        ..VerificationOptions::default()
    };

    match state.verifier().verify(token, &options) {
        Ok(claims) => {
            let now = SystemTime::now();
            let jti = claims.jwt_id.clone();
            let active = if let Some(ref jti_value) = jti {
                state.is_token_active(jti_value, now).await.map_err(|err| {
                    ApiError::server_error(format!("Token durumu sorgulanamadı: {err}"))
                })?
            } else {
                false
            };

            let exp = claims.expiration.map(system_time_to_unix_seconds);
            let iat = claims.issued_at.map(system_time_to_unix_seconds);
            let client_id = claims
                .extra
                .get("clientId")
                .or_else(|| claims.extra.get("client_id"))
                .and_then(|value| value.as_str())
                .map(str::to_owned);
            let scope = claims
                .extra
                .get("scope")
                .and_then(|value| value.as_str())
                .map(str::to_owned);
            let aud = claims.audience.as_ref().and_then(|aud| match aud {
                Audience::Single(value) => Some(value.clone()),
                Audience::Multiple(values) => values.first().cloned(),
            });

            Ok(Json(OAuthIntrospectResponse {
                active,
                scope,
                client_id,
                username: claims.subject.clone(),
                token_type: Some("Bearer".to_string()),
                exp,
                iat,
                iss: claims.issuer.clone(),
                aud,
                sub: claims.subject,
                jti,
            }))
        }
        Err(JwtError::Expired) => Ok(Json(OAuthIntrospectResponse {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: Some("Bearer".to_string()),
            exp: None,
            iat: None,
            iss: Some(state.issuer().to_owned()),
            aud: Some(state.audience().to_owned()),
            sub: None,
            jti: None,
        })),
        Err(err) => Err(ApiError::invalid_request(format!(
            "Token doğrulanamadı: {err}"
        ))),
    }
}

#[derive(Serialize)]
pub struct OAuthTransparencyResponse {
    pub transcript_hash: Option<String>,
    pub entries: Vec<OAuthTransparencyEntry>,
}

#[derive(Serialize)]
pub struct OAuthTransparencyEntry {
    pub index: u64,
    pub timestamp: u64,
    pub event: OAuthTransparencyEvent,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OAuthTransparencyEvent {
    #[allow(dead_code)]
    KeyPublished { jwk: Jwk },
    TokenIssued {
        jti: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        expires_at: u64,
    },
    MediaRecord {
        calibration_id: String,
        media_commitment_sha256: String,
        blockchain_tx_hash: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        blockchain_height: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        media_profile: Option<String>,
    },
}

pub async fn oauth_transparency(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<OAuthTransparencyResponse>, ApiError> {
    let snapshot = state
        .transparency_ledger_snapshot()
        .await
        .map_err(|err| ApiError::server_error(format!("Şeffaflık günlüğü alınamadı: {err}")))?;

    let entries = snapshot
        .entries
        .into_iter()
        .map(|entry| OAuthTransparencyEntry {
            index: entry.index,
            timestamp: entry.timestamp,
            event: match entry.event {
                LedgerTransparencyEvent::KeyPublished { jwk } => {
                    OAuthTransparencyEvent::KeyPublished { jwk }
                }
                LedgerTransparencyEvent::TokenIssued {
                    jti,
                    subject_hash,
                    audience,
                    expires_at,
                } => OAuthTransparencyEvent::TokenIssued {
                    jti,
                    subject_hash,
                    audience,
                    expires_at,
                },
                LedgerTransparencyEvent::MediaRecord {
                    calibration_id,
                    media_commitment_sha256,
                    blockchain_tx_hash,
                    blockchain_height,
                    media_profile,
                } => OAuthTransparencyEvent::MediaRecord {
                    calibration_id,
                    media_commitment_sha256,
                    blockchain_tx_hash,
                    blockchain_height,
                    media_profile,
                },
            },
            hash: entry.hash,
            previous_hash: entry.previous_hash,
        })
        .collect();

    Ok(Json(OAuthTransparencyResponse {
        transcript_hash: snapshot.transcript_hash,
        entries,
    }))
}

// ID service endpoints
#[derive(Deserialize)]
pub struct IdGenerateRequest {
    pub namespace: Option<String>,
}

#[derive(Serialize)]
pub struct IdGenerateResponse {
    pub id: String,
    pub namespace: String,
    #[serde(rename = "headPrefix")]
    pub head_prefix: String,
}

pub async fn generate_id(
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<IdGenerateRequest>,
) -> Result<Json<IdGenerateResponse>, ApiError> {
    use aunsorm_id::HeadIdGenerator;

    let generator = request
        .namespace
        .map_or_else(
            HeadIdGenerator::from_env,
            HeadIdGenerator::from_env_with_namespace,
        )
        .map_err(|e| ApiError::invalid_request(format!("ID generator error: {e}")))?;

    let id = generator
        .next_id()
        .map_err(|e| ApiError::server_error(format!("ID generation failed: {e}")))?;

    Ok(Json(IdGenerateResponse {
        id: id.as_str().to_string(),
        namespace: id.namespace().to_string(),
        head_prefix: id.head_prefix(),
    }))
}

// HEAD endpoint for SFU compatibility
pub async fn head_generate_id(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<IdGenerateResponse>, ApiError> {
    // Default HEAD request without body
    let request = IdGenerateRequest { namespace: None };
    generate_id(State(state), Json(request)).await
}

// Fabric DID endpoints
#[derive(Deserialize)]
pub struct FabricDidProofPayload {
    pub challenge: String,
    pub signature: String,
    pub block_hash: String,
    pub transaction_id: String,
    #[serde(rename = "timestamp_ms")]
    pub timestamp_ms: u64,
}

#[derive(Deserialize)]
pub struct FabricDidVerificationPayload {
    pub did: String,
    pub channel: String,
    pub proof: FabricDidProofPayload,
}

#[derive(Serialize)]
pub struct FabricLedgerAnchorResponse {
    #[serde(rename = "blockIndex")]
    pub block_index: u64,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "timestampMs")]
    pub timestamp_ms: u64,
}

#[derive(Serialize)]
pub struct FabricVerificationMethodResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub controller: String,
    #[serde(rename = "publicKeyBase64")]
    pub public_key_base64: String,
}

#[derive(Serialize)]
pub struct FabricVerificationServiceResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub endpoint: String,
}

#[derive(Serialize)]
pub struct FabricVerificationAuditResponse {
    pub challenge: String,
    #[serde(rename = "checkedAtMs")]
    pub checked_at_ms: u64,
    #[serde(rename = "clockSkewMs")]
    pub clock_skew_ms: u64,
}

#[derive(Serialize)]
pub struct FabricDidVerificationResponse {
    pub did: String,
    pub verified: bool,
    pub controller: String,
    pub status: String,
    pub channel: String,
    #[serde(rename = "mspId")]
    pub msp_id: String,
    #[serde(rename = "ledger_anchor")]
    pub ledger_anchor: FabricLedgerAnchorResponse,
    #[serde(rename = "verification_method")]
    pub verification_method: FabricVerificationMethodResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<FabricVerificationServiceResponse>,
    pub audit: FabricVerificationAuditResponse,
}

fn map_fabric_error(error: FabricDidError) -> ApiError {
    match error {
        FabricDidError::UnknownDid(did) => {
            ApiError::invalid_request(format!("bilinmeyen DID: {did}"))
        }
        FabricDidError::ChannelMismatch { expected, found } => ApiError::invalid_request(format!(
            "channel beklenen değeri karşılamıyor: beklenen {expected}, bulundu {found}"
        )),
        FabricDidError::BlockHashMismatch { expected, found } => {
            ApiError::invalid_request(format!(
                "block_hash ledger kaydıyla eşleşmiyor: beklenen {}, bulundu {}",
                hex::encode(expected),
                hex::encode(found)
            ))
        }
        FabricDidError::TransactionMismatch { expected, found } => {
            ApiError::invalid_request(format!(
                "transaction_id beklenen değeri karşılamıyor: beklenen {expected}, bulundu {found}"
            ))
        }
        FabricDidError::ChallengeMismatch => {
            ApiError::invalid_request("challenge canonical biçimle eşleşmiyor")
        }
        FabricDidError::SignatureInvalid => ApiError::invalid_request("imza doğrulanamadı"),
        FabricDidError::Clock(err) => {
            ApiError::server_error(format!("sistem saati okunamadı: {err}"))
        }
        FabricDidError::ClockOverflow => {
            ApiError::server_error("sistem saati hesaplaması taşma üretti")
        }
        FabricDidError::ClockSkew {
            delta_ms,
            allowed_ms,
        } => ApiError::invalid_request(format!(
            "clock skew çok yüksek: {delta_ms}ms (izin verilen {allowed_ms}ms)"
        )),
    }
}

pub async fn verify_fabric_did(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<FabricDidVerificationPayload>,
) -> Result<Json<FabricDidVerificationResponse>, ApiError> {
    let did = payload.did.trim();
    if did.is_empty() {
        return Err(ApiError::invalid_request("did boş olamaz"));
    }
    let channel = payload.channel.trim();
    if channel.is_empty() {
        return Err(ApiError::invalid_request("channel boş olamaz"));
    }
    let transaction_id = payload.proof.transaction_id.trim();
    if transaction_id.is_empty() {
        return Err(ApiError::invalid_request("transaction_id boş olamaz"));
    }

    let challenge = URL_SAFE_NO_PAD
        .decode(payload.proof.challenge.as_bytes())
        .map_err(|_| ApiError::invalid_request("challenge base64url çözülemedi"))?;
    if challenge.is_empty() {
        return Err(ApiError::invalid_request("challenge boş olamaz"));
    }

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(payload.proof.signature.as_bytes())
        .map_err(|_| ApiError::invalid_request("signature base64url çözülemedi"))?;
    if signature_bytes.len() != SIGNATURE_LENGTH {
        return Err(ApiError::invalid_request(
            "signature uzunluğu 64 bayt olmalıdır",
        ));
    }
    let mut signature = [0_u8; SIGNATURE_LENGTH];
    signature.copy_from_slice(&signature_bytes);

    let mut block_hash = [0_u8; 32];
    decode_to_slice(payload.proof.block_hash.as_bytes(), &mut block_hash)
        .map_err(|_| ApiError::invalid_request("block_hash hex formatında olmalıdır"))?;

    let request = FabricDidVerificationRequest {
        did,
        channel,
        block_hash,
        transaction_id,
        timestamp_ms: payload.proof.timestamp_ms,
        challenge: &challenge,
        signature,
    };

    let verification = state
        .fabric_registry()
        .verify(request)
        .map_err(map_fabric_error)?;

    let document = verification.document;
    let anchor = &document.anchor;
    let method = &document.verification_method;
    let service = document
        .service
        .as_ref()
        .map(|svc| FabricVerificationServiceResponse {
            id: svc.id.clone(),
            ty: svc.r#type.to_owned(),
            endpoint: svc.endpoint.clone(),
        });
    let challenge_b64 = URL_SAFE_NO_PAD.encode(&verification.challenge);
    let public_key_b64 = URL_SAFE_NO_PAD.encode(method.public_key_bytes());

    let response = FabricDidVerificationResponse {
        did: document.did.clone(),
        verified: true,
        controller: document.controller.clone(),
        status: document.status.as_str().to_owned(),
        channel: document.channel.clone(),
        msp_id: document.msp_id.clone(),
        ledger_anchor: FabricLedgerAnchorResponse {
            block_index: anchor.block_index,
            block_hash: anchor.block_hash_hex(),
            transaction_id: anchor.transaction_id.clone(),
            timestamp_ms: anchor.timestamp_ms,
        },
        verification_method: FabricVerificationMethodResponse {
            id: method.id.clone(),
            ty: method.algorithm().to_owned(),
            controller: method.controller.clone(),
            public_key_base64: public_key_b64,
        },
        service,
        audit: FabricVerificationAuditResponse {
            challenge: challenge_b64,
            checked_at_ms: verification.checked_at_ms,
            clock_skew_ms: verification.clock_skew_ms,
        },
    };

    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct BlockchainMediaRecordRequest {
    #[serde(rename = "mediaHash")]
    pub media_hash: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "auditProof")]
    pub audit_proof: AuditProofDocument,
}

#[derive(Serialize)]
pub struct BlockchainMediaRecordResponse {
    pub status: &'static str,
    pub queued: bool,
    #[serde(rename = "expectedAuditProof")]
    pub expected_audit_proof: AuditProofDocument,
}

pub async fn blockchain_media_record(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<BlockchainMediaRecordRequest>,
) -> Result<(StatusCode, Json<BlockchainMediaRecordResponse>), ApiError> {
    if request.media_hash.trim().is_empty() {
        return Err(ApiError::invalid_request("mediaHash boş olamaz"));
    }
    if request.session_id.trim().is_empty() {
        return Err(ApiError::invalid_request("sessionId boş olamaz"));
    }

    if let Err(err) = state.verify_audit_proof(&request.audit_proof).await {
        return Err(ApiError::unprocessable_entity(err.to_string()));
    }

    let response = BlockchainMediaRecordResponse {
        status: "not-implemented",
        queued: false,
        expected_audit_proof: state.audit_proof_document().await,
    };

    Ok((StatusCode::NOT_IMPLEMENTED, Json(response)))
}

// SFU Context endpoints
#[derive(Deserialize)]
pub struct CreateSfuContextRequest {
    pub room_id: String,
    pub participant: String,
    #[serde(default)]
    pub enable_e2ee: bool,
}

#[derive(Serialize)]
pub struct SfuE2eeEnvelope {
    pub session_id: String,
    pub message_no: u64,
    pub key: String,
    pub nonce: String,
}

#[derive(Serialize)]
pub struct CreateSfuContextResponse {
    pub context_id: String,
    pub room_id: String,
    pub participant: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e2ee: Option<SfuE2eeEnvelope>,
}

pub async fn create_sfu_context(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<CreateSfuContextRequest>,
) -> Result<Json<CreateSfuContextResponse>, ApiError> {
    if request.room_id.trim().is_empty() {
        return Err(ApiError::invalid_request("room_id boş olamaz"));
    }
    if request.participant.trim().is_empty() {
        return Err(ApiError::invalid_request("participant boş olamaz"));
    }

    let provision = state
        .create_sfu_context(request.room_id, request.participant, request.enable_e2ee)
        .await
        .map_err(|err| ApiError::server_error(format!("SFU bağlamı oluşturulamadı: {err}")))?;
    let now = SystemTime::now();
    let expires_in = provision
        .expires_at
        .duration_since(now)
        .unwrap_or_default()
        .as_secs();
    let e2ee = provision.e2ee.map(|step| SfuE2eeEnvelope {
        session_id: URL_SAFE_NO_PAD.encode(step.session_id),
        message_no: step.message_no,
        key: URL_SAFE_NO_PAD.encode(step.message_secret),
        nonce: URL_SAFE_NO_PAD.encode(step.nonce),
    });
    Ok(Json(CreateSfuContextResponse {
        context_id: provision.context_id,
        room_id: provision.room_id,
        participant: provision.participant,
        expires_in,
        e2ee,
    }))
}

#[derive(Deserialize)]
pub struct NextSfuStepRequest {
    pub context_id: String,
}

#[derive(Serialize)]
pub struct NextSfuStepResponse {
    pub context_id: String,
    pub room_id: String,
    pub participant: String,
    pub session_id: String,
    pub message_no: u64,
    pub key: String,
    pub nonce: String,
    pub expires_in: u64,
}

pub async fn next_sfu_step(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<NextSfuStepRequest>,
) -> Result<Json<NextSfuStepResponse>, ApiError> {
    if request.context_id.trim().is_empty() {
        return Err(ApiError::invalid_request("context_id boş olamaz"));
    }

    let outcome = state
        .next_sfu_step(&request.context_id)
        .await
        .map_err(|err| ApiError::server_error(format!("SFU ratchet adımı üretilemedi: {err}")))?;

    match outcome {
        crate::state::SfuStepOutcome::NotFound => {
            Err(ApiError::invalid_request("SFU bağlamı bulunamadı"))
        }
        crate::state::SfuStepOutcome::Expired => {
            Err(ApiError::invalid_grant("SFU bağlamının süresi doldu"))
        }
        crate::state::SfuStepOutcome::E2eeDisabled => Err(ApiError::invalid_request(
            "SFU bağlamı için uçtan uca şifreleme etkin değil",
        )),
        crate::state::SfuStepOutcome::Step(step) => {
            let now = SystemTime::now();
            let expires_in = step
                .expires_at
                .duration_since(now)
                .unwrap_or_default()
                .as_secs();
            Ok(Json(NextSfuStepResponse {
                context_id: request.context_id,
                room_id: step.room_id,
                participant: step.participant,
                session_id: URL_SAFE_NO_PAD.encode(step.session_id),
                message_no: step.message_no,
                key: URL_SAFE_NO_PAD.encode(step.message_secret),
                nonce: URL_SAFE_NO_PAD.encode(step.nonce),
                expires_in,
            }))
        }
    }
}

// Transparency endpoint
#[derive(Serialize)]
pub struct TransparencyResponse {
    pub domain: String,
    pub tree_head: String,
    pub latest_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_hash: Option<String>,
    pub records: Vec<TransparencyRecord>,
}

#[derive(Serialize)]
pub struct TransparencyRecord {
    pub sequence: u64,
    pub timestamp: u64,
    pub key_id: String,
    pub action: String,
}

pub async fn transparency_tree(
    State(state): State<Arc<ServerState>>,
) -> Json<TransparencyResponse> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Get the actual transparency tree snapshot from the state
    let snapshot = state.transparency_tree_snapshot().await;
    let transcript_hash = snapshot
        .transcript_hash()
        .expect("transcript hash")
        .map(hex::encode);

    Json(TransparencyResponse {
        domain: "aunsorm-server".to_string(),
        tree_head: "abc123def456".to_string(),
        latest_sequence: 1,
        transcript_hash,
        records: vec![TransparencyRecord {
            sequence: 1,
            timestamp: now,
            key_id: "test".to_string(),
            action: "publish".to_string(),
        }],
    })
}

#[allow(clippy::cognitive_complexity)]
#[allow(clippy::too_many_lines)]
/// Yönlendirici yapısını oluşturur.
///
/// # Panics
/// `http3-experimental` özelliği etkin ve `Alt-Svc` başlığı oluşturulamazsa panikler.
pub fn build_router(state: &Arc<ServerState>) -> Router {
    let service_mode = std::env::var("SERVICE_MODE").ok();
    tracing::info!("🔧 SERVICE_MODE: {:?}", service_mode);

    let mut router = Router::new()
        // Health endpoints (available on all services)
        .route("/health", get(health))
        .route("/metrics", get(metrics));

    // Service-specific routes based on SERVICE_MODE
    match service_mode.as_deref() {
        Some("gateway") => {
            tracing::info!("🌐 Building GATEWAY routes");
            router = router
                // Random number endpoint (gateway service)
                .route("/random/number", get(random_number))
                .route("/calib/inspect", post(calib_inspect))
                .route("/calib/verify", post(calib_verify))
                // Transparency endpoints (gateway service)
                .route("/transparency/tree", get(transparency_tree))
                .route("/pqc/capabilities", get(pqc_capabilities))
                .route("/http3/capabilities", get(http3_capabilities))
                // Proxy JWT endpoints to auth service
                .route("/security/jwt-verify", post(proxy_jwt_verify))
                .route("/security/generate-media-token", post(proxy_media_token))
                // Proxy ID endpoints to id service
                .route("/id/generate", post(proxy_id_generate))
                .route("/id/generate", head(proxy_id_generate_head))
                // Endpoint validation
                .route("/validate/endpoint", post(validate_endpoint));
        }
        Some("auth-service") => {
            tracing::info!("🔐 Building AUTH SERVICE routes");
            router = router
                // OAuth endpoints (auth service)
                .route("/oauth/begin-auth", post(begin_auth))
                .route("/oauth/token", post(exchange_token))
                .route("/oauth/introspect", post(introspect_token))
                .route("/oauth/transparency", get(oauth_transparency))
                // JWT endpoints (auth service)
                .route("/cli/jwt/verify", post(verify_jwt_token))
                .route("/security/jwt-verify", post(verify_media_token))
                .route("/security/generate-media-token", post(generate_media_token))
                .route("/security/jwe/encrypt", post(security_jwe_encrypt));
        }
        Some("acme-service") => {
            tracing::info!("🔒 Building ACME SERVICE routes");
            router = router
                // ACME endpoints (acme service)
                .route("/acme/directory", get(acme::directory))
                .route("/acme/new-nonce", get(acme::new_nonce))
                .route("/acme/new-account", post(acme_new_account))
                .route("/acme/account/:id", post(acme_account_lookup))
                .route("/acme/new-order", post(acme_new_order))
                .route("/acme/order/:id", post(acme_order_status))
                .route("/acme/order/:id/finalize", post(acme_finalize_order))
                .route("/acme/cert/:id", get(acme_get_certificate))
                .route("/acme/revoke-cert", post(acme_revoke_certificate))
                .route("/acme/validation/http-01", post(acme::publish_http01))
                .route(
                    "/acme/validation/http-01/:token",
                    delete(acme::revoke_http01),
                )
                .route("/acme/validation/dns-01", post(acme::publish_dns01))
                .route("/acme/validation/dns-01/:token", delete(acme::revoke_dns01));
        }
        Some("mdm-service") => {
            tracing::info!("📱 Building MDM SERVICE routes");
            router = router
                // MDM endpoints (mdm service)
                .route("/mdm/register", post(register_device))
                .route("/mdm/policy/:platform", get(fetch_policy))
                .route("/mdm/cert-plan/:device_id", get(fetch_certificate_plan));
        }
        Some("blockchain-service") => {
            tracing::info!("⛓️ Building BLOCKCHAIN SERVICE routes");
            router = router
                // Fabric DID endpoints (blockchain service)
                .route("/blockchain/fabric/did/verify", post(verify_fabric_did))
                .route("/blockchain/media/record", post(blockchain_media_record));
        }
        Some("id-service") => {
            tracing::info!("🆔 Building ID SERVICE routes");
            router = router
                // ID endpoints (id service)
                .route("/id/generate", post(generate_id))
                .route("/id/generate", head(head_generate_id));
        }
        Some("sfu-service") => {
            tracing::info!("📡 Building SFU SERVICE routes");
            router = router
                // SFU endpoints (sfu service)
                .route("/sfu/context", post(create_sfu_context))
                .route("/sfu/context/step", post(next_sfu_step));
        }
        _ => {
            tracing::info!(
                "🔧 Building DEFAULT routes for service_mode: {:?}",
                service_mode
            );
            // Default: expose all endpoints (backwards compatibility)
            router = router
                // Random number endpoint
                .route("/random/number", get(random_number))
                .route("/calib/inspect", post(calib_inspect))
                .route("/calib/verify", post(calib_verify))
                .route("/pqc/capabilities", get(pqc_capabilities))
                // ACME endpoints
                .route("/acme/directory", get(acme::directory))
                .route("/acme/new-nonce", get(acme::new_nonce))
                .route("/acme/new-account", post(acme_new_account))
                .route("/acme/account/:id", post(acme_account_lookup))
                .route("/acme/new-order", post(acme_new_order))
                .route("/acme/order/:id", post(acme_order_status))
                .route("/acme/order/:id/finalize", post(acme_finalize_order))
                .route("/acme/cert/:id", get(acme_get_certificate))
                .route("/acme/revoke-cert", post(acme_revoke_certificate))
                .route("/acme/validation/http-01", post(acme::publish_http01))
                .route(
                    "/acme/validation/http-01/:token",
                    delete(acme::revoke_http01),
                )
                .route("/acme/validation/dns-01", post(acme::publish_dns01))
                .route("/acme/validation/dns-01/:token", delete(acme::revoke_dns01))
                // OAuth endpoints
                .route("/oauth/begin-auth", post(begin_auth))
                .route("/oauth/token", post(exchange_token))
                .route("/oauth/introspect", post(introspect_token))
                .route("/oauth/transparency", get(oauth_transparency))
                // JWT endpoints
                .route("/cli/jwt/verify", post(verify_jwt_token))
                .route("/security/jwt-verify", post(verify_media_token))
                .route("/security/generate-media-token", post(generate_media_token))
                .route("/security/jwe/encrypt", post(security_jwe_encrypt))
                // MDM endpoints
                .route("/mdm/register", post(register_device))
                .route("/mdm/policy/:platform", get(fetch_policy))
                .route("/mdm/cert-plan/:device_id", get(fetch_certificate_plan))
                // Fabric DID endpoints
                .route("/blockchain/fabric/did/verify", post(verify_fabric_did))
                .route("/blockchain/media/record", post(blockchain_media_record))
                // ID endpoints
                .route("/id/generate", post(generate_id))
                .route("/id/generate", head(head_generate_id))
                // SFU endpoints
                .route("/sfu/context", post(create_sfu_context))
                .route("/sfu/context/step", post(next_sfu_step))
                // Transparency endpoints
                .route("/transparency/tree", get(transparency_tree))
                .route("/http3/capabilities", get(http3_capabilities));
        }
    }

    #[cfg(feature = "http3-experimental")]
    let router = {
        let port = state.listen_port();
        let header_value =
            build_alt_svc_header_value(port).expect("Alt-Svc başlığı oluşturulamadı");
        let header_value = Arc::new(header_value);
        router.layer(from_fn(
            move |req: axum::http::Request<Body>, next: Next| {
                let header_value = Arc::clone(&header_value);
                async move {
                    let mut response = next.run(req).await;
                    response
                        .headers_mut()
                        .insert(header::ALT_SVC, header_value.as_ref().clone());
                    response
                }
            },
        ))
    };

    router.with_state(state.clone())
}

// Proxy functions for gateway
#[allow(clippy::option_if_let_else)]
async fn proxy_jwt_verify(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    match client
        .post("http://aun-auth-service:50011/security/jwt-verify")
        .json(&payload)
        .send()
        .await
    {
        Ok(response) => {
            let status_code = match response.status().as_u16() {
                200 => StatusCode::OK,
                400 => StatusCode::BAD_REQUEST,
                404 => StatusCode::NOT_FOUND,
                422 => StatusCode::UNPROCESSABLE_ENTITY,
                500 => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_GATEWAY,
            };
            match response.json::<serde_json::Value>().await {
                Ok(json) => (status_code, Json(json)).into_response(),
                Err(_) => (StatusCode::BAD_GATEWAY, "Proxy error").into_response(),
            }
        }
        Err(_) => (StatusCode::BAD_GATEWAY, "Auth service unavailable").into_response(),
    }
}

#[allow(clippy::option_if_let_else)]
async fn proxy_media_token(
    headers: axum::http::HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let client = reqwest::Client::new();

    let mut request = client
        .post("http://aun-auth-service:50011/security/generate-media-token")
        .json(&payload);

    // Forward relevant headers
    if let Some(content_type) = headers.get("content-type") {
        if let Ok(ct_str) = content_type.to_str() {
            request = request.header("content-type", ct_str);
        }
    }
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            request = request.header("authorization", auth_str);
        }
    }

    match request.send().await {
        Ok(response) => {
            let status_code = match response.status().as_u16() {
                200 => StatusCode::OK,
                400 => StatusCode::BAD_REQUEST,
                404 => StatusCode::NOT_FOUND,
                422 => StatusCode::UNPROCESSABLE_ENTITY,
                500 => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_GATEWAY,
            };
            match response.json::<serde_json::Value>().await {
                Ok(json) => (status_code, Json(json)).into_response(),
                Err(_) => (StatusCode::BAD_GATEWAY, "Proxy error").into_response(),
            }
        }
        Err(_) => (StatusCode::BAD_GATEWAY, "Auth service unavailable").into_response(),
    }
}

#[allow(clippy::option_if_let_else)]
async fn proxy_id_generate(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    match client
        .post("http://aun-id-service:50016/id/generate")
        .json(&payload)
        .send()
        .await
    {
        Ok(response) => {
            let status_code = match response.status().as_u16() {
                200 => StatusCode::OK,
                400 => StatusCode::BAD_REQUEST,
                404 => StatusCode::NOT_FOUND,
                422 => StatusCode::UNPROCESSABLE_ENTITY,
                500 => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_GATEWAY,
            };
            match response.json::<serde_json::Value>().await {
                Ok(json) => (status_code, Json(json)).into_response(),
                Err(_) => (StatusCode::BAD_GATEWAY, "Proxy error").into_response(),
            }
        }
        Err(_) => (StatusCode::BAD_GATEWAY, "ID service unavailable").into_response(),
    }
}

async fn proxy_id_generate_head() -> impl IntoResponse {
    let client = reqwest::Client::new();
    client
        .head("http://aun-id-service:50016/id/generate")
        .send()
        .await
        .map_or_else(
            |_| (StatusCode::BAD_GATEWAY, "ID service unavailable").into_response(),
            |response| {
                let status_code = match response.status().as_u16() {
                    200 => StatusCode::OK,
                    400 => StatusCode::BAD_REQUEST,
                    404 => StatusCode::NOT_FOUND,
                    422 => StatusCode::UNPROCESSABLE_ENTITY,
                    500 => StatusCode::INTERNAL_SERVER_ERROR,
                    _ => StatusCode::BAD_GATEWAY,
                };
                status_code.into_response()
            },
        )
}

/// Starts the aunsorm server with the given configuration.
///
/// # Errors
///
/// Returns `ServerError` if the server fails to start or bind to the specified address.
#[allow(clippy::cognitive_complexity)]
pub async fn serve(config: ServerConfig) -> Result<(), ServerError> {
    let listen = config.listen;
    tracing::info!("🚀 Starting server on {}", listen);
    let state = Arc::new(ServerState::try_new(config)?);
    state.start_clock_refresh();
    let _renewal_task = crate::jobs::spawn_default_acme_renewal_job(Arc::clone(&state));
    #[cfg(feature = "http3-experimental")]
    let _http3_guard = {
        let guard = spawn_http3_poc(listen, Arc::clone(&state))?;
        tracing::info!(
            port = listen.port(),
            "HTTP/3 PoC dinleyicisi etkinleştirildi"
        );
        guard
    };
    let router = build_router(&state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("✅ Server successfully bound to {}", listen);
    tracing::info!("🌐 Starting HTTP server...");
    axum::serve(listener, router.into_make_service()).await?;
    Ok(())
}

/// Endpoint validation handler for testing connectivity and responses
#[allow(clippy::cognitive_complexity)]
async fn validate_endpoint(Json(payload): Json<EndpointValidationRequest>) -> impl IntoResponse {
    use reqwest;

    tracing::info!("🔍 Validating endpoint: {} {}", payload.method, payload.url);

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("Failed to create HTTP client: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Client creation failed").into_response();
        }
    };

    let method = match payload.method.to_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "HEAD" => reqwest::Method::HEAD,
        _ => return (StatusCode::BAD_REQUEST, "Unsupported HTTP method").into_response(),
    };

    let request = client.request(method, &payload.url);

    let request = if let Some(body) = payload.body {
        request.body(body)
    } else {
        request
    };

    let request = if let Some(headers) = payload.headers {
        let mut req = request;
        for (key, value) in headers {
            if let (Ok(name), Ok(val)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                reqwest::header::HeaderValue::from_str(&value),
            ) {
                req = req.header(name, val);
            }
        }
        req
    } else {
        request
    };

    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let headers: std::collections::HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let body = response.text().await.unwrap_or_default();

            Json(EndpointValidationResponse {
                success: true,
                status_code: status,
                headers: Some(headers),
                body: Some(body),
                error: None,
            })
            .into_response()
        }
        Err(e) => {
            tracing::warn!("Endpoint validation failed: {}", e);
            Json(EndpointValidationResponse {
                success: false,
                status_code: 0,
                headers: None,
                body: None,
                error: Some(e.to_string()),
            })
            .into_response()
        }
    }
}

#[derive(serde::Deserialize)]
struct EndpointValidationRequest {
    url: String,
    method: String,
    #[serde(default)]
    headers: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(serde::Serialize)]
struct EndpointValidationResponse {
    success: bool,
    status_code: u16,
    headers: Option<std::collections::HashMap<String, String>>,
    body: Option<String>,
    error: Option<String>,
}

#[cfg(test)]
fn build_test_state() -> Arc<ServerState> {
    use std::net::SocketAddr;
    use std::time::Duration;

    use aunsorm_core::{calibration::calib_from_text, clock::SecureClockSnapshot};

    let listen: SocketAddr = "127.0.0.1:9443".parse().expect("socket address");
    let key_pair =
        aunsorm_jwt::Ed25519KeyPair::generate("test-server").expect("key pair generation");
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
    let calibration_fingerprint = calibration.fingerprint_hex();
    let config = crate::config::ServerConfig::new(
        listen,
        "https://aunsorm.test",
        "test-audience",
        Duration::from_secs(300),
        false,
        key_pair,
        crate::config::LedgerBackend::Memory,
        None,
        calibration_fingerprint,
        Duration::from_secs(300),
        clock_snapshot,
        None,
    )
    .expect("config is valid");
    Arc::new(ServerState::try_new(config).expect("state is constructed"))
}

#[cfg(test)]
mod pqc_tests {
    use super::*;
    use axum::body::to_bytes;
    use tower::ServiceExt;

    #[tokio::test]
    async fn pqc_capabilities_report_feature_flags() {
        let state = build_test_state();
        let response = build_router(&state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/pqc/capabilities")
                    .body(axum::body::Body::empty())
                    .expect("request is built"),
            )
            .await
            .expect("request succeeds");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body is collected");
        let payload: serde_json::Value = serde_json::from_slice(&body).expect("payload parses");

        let strict = payload.get("strict").expect("strict section present");
        assert_eq!(
            strict.get("envVar").and_then(serde_json::Value::as_str),
            Some("AUNSORM_STRICT")
        );
        assert_eq!(
            strict
                .get("defaultEnabled")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );

        let kem = payload
            .get("kem")
            .and_then(serde_json::Value::as_array)
            .expect("kem list present");
        assert!(!kem.is_empty(), "kem capability list should not be empty");

        let mlkem_entry = kem
            .iter()
            .find(|entry| {
                entry.get("algorithm").and_then(serde_json::Value::as_str) == Some("ml-kem-768")
            })
            .expect("ml-kem-768 entry present");
        let mlkem_available = mlkem_entry
            .get("available")
            .and_then(serde_json::Value::as_bool)
            .expect("available bool");
        assert_eq!(
            mlkem_available,
            aunsorm_pqc::kem::KemAlgorithm::MlKem768.is_available()
        );

        let aliases = mlkem_entry
            .get("aliases")
            .and_then(serde_json::Value::as_array)
            .expect("aliases array");
        assert!(
            aliases
                .iter()
                .any(|value| value.as_str() == Some("kyber-768")),
            "aliases should include kyber-768"
        );

        let signatures = payload
            .get("signatures")
            .and_then(serde_json::Value::as_array)
            .expect("signatures list present");
        assert!(signatures.iter().any(|entry| {
            entry.get("algorithm").and_then(serde_json::Value::as_str) == Some("ml-dsa-65")
        }));
    }
}

#[cfg(all(test, feature = "http3-experimental"))]
mod http3_tests {
    use super::*;
    use axum::body::to_bytes;
    use tower::ServiceExt;

    #[tokio::test]
    async fn alt_svc_header_is_injected_for_http3_routes() {
        let state = build_test_state();
        let port = state.listen_port();
        let response = build_router(&state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .expect("request is built"),
            )
            .await
            .expect("request succeeds");
        let header = response
            .headers()
            .get(header::ALT_SVC)
            .expect("Alt-Svc header is present");
        let expected =
            build_alt_svc_header_value(port).expect("expected header can be constructed");
        assert_eq!(header, &expected);
    }

    #[tokio::test]
    async fn http3_capabilities_reports_active_status() {
        let state = build_test_state();
        let response = build_router(&state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/http3/capabilities")
                    .body(axum::body::Body::empty())
                    .expect("request is built"),
            )
            .await
            .expect("request succeeds");
        assert_eq!(response.status(), StatusCode::OK);
        let header = response
            .headers()
            .get(header::ALT_SVC)
            .expect("Alt-Svc header is present");
        let expected =
            build_alt_svc_header_value(state.listen_port()).expect("expected header is built");
        assert_eq!(header, &expected);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body is collected");
        let payload: Http3CapabilitiesResponse =
            serde_json::from_slice(&body).expect("payload parses");
        assert!(payload.enabled);
        assert_eq!(payload.status.as_ref(), "active");
        assert_eq!(payload.alt_svc_port, Some(state.listen_port()));
        assert_eq!(payload.alt_svc_max_age, Some(ALT_SVC_MAX_AGE));
        assert_eq!(payload.datagrams.max_payload_bytes, Some(MAX_PAYLOAD_BYTES));
        assert_eq!(payload.datagrams.channels.len(), 3);
    }
}

#[cfg(test)]
mod jwt_helper_tests {
    use super::{map_jwt_error, sanitize_token_input};
    use aunsorm_jwt::JwtError;
    use std::borrow::Cow;
    use std::io;

    #[test]
    fn sanitize_token_input_trims_whitespace_without_allocating() {
        let result = sanitize_token_input("   my-token   ");
        assert_eq!(result.as_ref(), "my-token");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn sanitize_token_input_removes_case_insensitive_bearer_prefix() {
        let result = sanitize_token_input("  BEARER abc123  ");
        assert_eq!(result.as_ref(), "abc123");
        assert!(matches!(result, Cow::Owned(_)));

        let result = sanitize_token_input("bearer\txyz");
        assert_eq!(result.as_ref(), "xyz");
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn sanitize_token_input_returns_empty_when_bearer_without_token() {
        let result = sanitize_token_input("Bearer   \n\t");
        assert!(result.as_ref().is_empty());
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn map_jwt_error_maps_common_variants_to_human_messages() {
        assert_eq!(
            map_jwt_error(&JwtError::Signature),
            "Invalid token signature"
        );
        assert_eq!(
            map_jwt_error(&JwtError::MissingJti),
            "Token missing jti claim"
        );
        assert_eq!(
            map_jwt_error(&JwtError::UnsupportedAlgorithm("HS256".to_owned())),
            "Unsupported JWT algorithm: HS256"
        );
    }

    #[test]
    fn map_jwt_error_preserves_io_context() {
        let io_error = io::Error::other("disk failure");
        let message = map_jwt_error(&JwtError::Io(io_error));
        assert!(message.contains("disk failure"));
        assert!(message.starts_with("Token verification I/O error:"));
    }
}
