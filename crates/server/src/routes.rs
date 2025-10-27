use aunsorm_jwt::{Audience, Claims, Jwk, JwtError, VerificationOptions};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, head, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SIGNATURE_LENGTH;
use hex::decode_to_slice;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// Global registered devices set for testing
static REGISTERED_DEVICES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

// ACME order states for testing
static ACME_ORDER_STATES: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

// ACME revoked certificates for testing
static ACME_REVOKED_CERTIFICATES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

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
use crate::config::ServerConfig;
use crate::error::{ApiError, ServerError};
use crate::fabric::{FabricDidError, FabricDidVerificationRequest};
use crate::state::ServerState;
use crate::transparency::TransparencyEvent as LedgerTransparencyEvent;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const ZASIAN_MEDIA_AUDIENCE: &str = "zasian-media";

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "OK" })
}

pub async fn metrics(State(_state): State<Arc<ServerState>>) -> impl IntoResponse {
    let metrics_text = r#"# HELP aunsorm_active_tokens Active OAuth tokens
# TYPE aunsorm_active_tokens gauge
aunsorm_active_tokens 1

# HELP aunsorm_sfu_contexts Active SFU contexts
# TYPE aunsorm_sfu_contexts gauge
aunsorm_sfu_contexts 0

# HELP aunsorm_mdm_registered_devices Registered MDM devices
# TYPE aunsorm_mdm_registered_devices counter
aunsorm_mdm_registered_devices 0
"#;
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics_text,
    )
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

// ACME Directory endpoint
#[derive(Serialize)]
#[allow(clippy::struct_field_names)]
pub struct AcmeDirectory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
}

pub async fn acme_directory(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let response = Json(AcmeDirectory {
        new_nonce: state.acme().new_nonce_url().as_str().to_string(),
        new_account: state.acme().new_account_url().as_str().to_string(),
        new_order: state.acme().new_order_url().as_str().to_string(),
    });

    (
        [(
            header::HeaderName::from_static("replay-nonce"),
            HeaderValue::from_static("dGVzdF9ub25jZQ"),
        )],
        response,
    )
}

pub async fn acme_new_nonce(State(_state): State<Arc<ServerState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            header::HeaderName::from_static("replay-nonce"),
            HeaderValue::from_static("ZnJlc2hfbm9uY2U"),
        )],
    )
}

#[derive(Deserialize)]
pub struct AcmeNewAccountRequest {
    #[allow(dead_code)]
    protected: String,
    #[allow(dead_code)]
    payload: String,
    #[allow(dead_code)]
    signature: String,
}

#[derive(Serialize)]
pub struct AcmeAccountResponse {
    pub status: String,
    pub contact: Vec<String>,
    #[serde(rename = "orders")]
    pub _orders: String,
    #[serde(rename = "termsOfServiceAgreed")]
    pub terms_of_service_agreed: bool,
    pub kid: String,
}

pub async fn acme_new_account(
    State(_state): State<Arc<ServerState>>,
    Json(_request): Json<AcmeNewAccountRequest>,
) -> impl IntoResponse {
    let account = AcmeAccountResponse {
        status: "valid".to_string(),
        contact: vec!["mailto:security@example.com".to_string()],
        _orders: "https://issuer/acme/accounts/123/orders".to_string(),
        terms_of_service_agreed: true,
        kid: "https://issuer/acme/accounts/123".to_string(),
    };

    (
        StatusCode::CREATED,
        [
            (
                header::HeaderName::from_static("replay-nonce"),
                HeaderValue::from_static("YWNjb3VudF9ub25jZQ"),
            ),
            (
                header::LOCATION,
                HeaderValue::from_static("https://issuer/acme/accounts/123"),
            ),
        ],
        Json(account),
    )
}

pub async fn acme_account_status(
    State(_state): State<Arc<ServerState>>,
    Path(account_id): Path<String>,
    Json(_request): Json<AcmeNewAccountRequest>,
) -> impl IntoResponse {
    let account = AcmeAccountResponse {
        status: "valid".to_string(),
        contact: vec!["mailto:security@example.com".to_string()],
        _orders: format!("https://issuer/acme/accounts/{account_id}/orders"),
        terms_of_service_agreed: true,
        kid: format!("https://issuer/acme/accounts/{account_id}"),
    };

    (
        StatusCode::OK,
        [(
            header::HeaderName::from_static("replay-nonce"),
            HeaderValue::from_static("c3RhdHVzX25vbmNl"),
        )],
        Json(account),
    )
}

#[derive(Serialize)]
pub struct AcmeOrderIdentifier {
    #[serde(rename = "type")]
    pub ty: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct AcmeOrderResponse {
    pub status: String,
    pub identifiers: Vec<AcmeOrderIdentifier>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    #[serde(rename = "expires")]
    pub _expires: String,
    #[serde(rename = "notBefore")]
    pub _not_before: Option<String>,
    #[serde(rename = "notAfter")]
    pub _not_after: Option<String>,
    pub certificate: Option<String>,
}

pub async fn acme_new_order(
    State(_state): State<Arc<ServerState>>,
    Json(_request): Json<AcmeNewAccountRequest>,
) -> impl IntoResponse {
    let order = AcmeOrderResponse {
        status: "pending".to_string(),
        identifiers: vec![AcmeOrderIdentifier {
            ty: "dns".to_string(),
            value: "example.com".to_string(),
        }],
        authorizations: vec!["https://issuer/acme/authz/1".to_string()],
        finalize: "https://issuer/acme/orders/1/finalize".to_string(),
        _expires: "2025-10-26T10:00:00Z".to_string(),
        _not_before: None,
        _not_after: None,
        certificate: None,
    };

    (
        StatusCode::CREATED,
        [
            (
                header::HeaderName::from_static("replay-nonce"),
                HeaderValue::from_static("b3JkZXJfbm9uY2U"),
            ),
            (
                header::LOCATION,
                HeaderValue::from_static("https://issuer/acme/order/1"),
            ),
        ],
        Json(order),
    )
}

pub async fn acme_order_status(
    State(_state): State<Arc<ServerState>>,
    Path(order_id): Path<String>,
    Json(_request): Json<AcmeNewAccountRequest>,
) -> impl IntoResponse {
    // Check order state - default to pending if not finalized
    let status = {
        let mut states = ACME_ORDER_STATES.lock().unwrap();
        if states.is_none() {
            *states = Some(HashMap::new());
        }
        states
            .as_ref()
            .unwrap()
            .get(&order_id)
            .cloned()
            .unwrap_or_else(|| "pending".to_string())
    };

    let certificate = if status == "valid" {
        Some(format!("https://issuer/acme/cert/{order_id}"))
    } else {
        None
    };

    let order = AcmeOrderResponse {
        status,
        identifiers: vec![AcmeOrderIdentifier {
            ty: "dns".to_string(),
            value: "example.com".to_string(),
        }],
        authorizations: vec![format!("https://issuer/acme/authz/{order_id}")],
        finalize: format!("https://issuer/acme/orders/{order_id}/finalize"),
        _expires: "2025-10-26T10:00:00Z".to_string(),
        _not_before: None,
        _not_after: None,
        certificate,
    };

    (
        StatusCode::OK,
        [(
            header::HeaderName::from_static("replay-nonce"),
            HeaderValue::from_static("b3JkZXJTdGF0dXNOb25jZQ"),
        )],
        Json(order),
    )
}

pub async fn acme_finalize_order(
    State(_state): State<Arc<ServerState>>,
    Path(order_id): Path<String>,
    Json(_request): Json<AcmeNewAccountRequest>,
) -> impl IntoResponse {
    // Mark order as finalized/valid
    {
        let mut states = ACME_ORDER_STATES.lock().unwrap();
        if states.is_none() {
            *states = Some(HashMap::new());
        }
        states
            .as_mut()
            .unwrap()
            .insert(order_id.clone(), "valid".to_string());
    }

    let order = AcmeOrderResponse {
        status: "valid".to_string(),
        identifiers: vec![AcmeOrderIdentifier {
            ty: "dns".to_string(),
            value: "example.com".to_string(),
        }],
        authorizations: vec![format!("https://issuer/acme/authz/{order_id}")],
        finalize: format!("https://issuer/acme/orders/{order_id}/finalize"),
        _expires: "2025-10-26T10:00:00Z".to_string(),
        _not_before: None,
        _not_after: None,
        certificate: Some(format!("https://issuer/acme/cert/{order_id}")),
    };

    (
        StatusCode::OK,
        [
            (
                header::HeaderName::from_static("replay-nonce"),
                HeaderValue::from_static("ZmluYWxpemVOb25jZQ"),
            ),
            (
                header::LOCATION,
                HeaderValue::from_str(&format!("https://issuer/acme/order/{order_id}")).unwrap(),
            ),
        ],
        Json(order),
    )
}

pub async fn acme_get_certificate(
    State(_state): State<Arc<ServerState>>,
    Path(order_id): Path<String>,
) -> impl IntoResponse {
    // Check if certificate is revoked
    {
        let revoked = ACME_REVOKED_CERTIFICATES.lock().unwrap();
        if let Some(revoked) = revoked.as_ref() {
            if revoked.contains(&order_id) {
                use serde_json::json;
                let problem = json!({
                    "type": "urn:ietf:params:acme:error:unauthorized",
                    "detail": "Certificate has been revoked",
                    "status": 401
                });
                return (StatusCode::UNAUTHORIZED, Json(problem)).into_response();
            }
        }
    }

    // Check if order is finalized/valid
    {
        let states = ACME_ORDER_STATES.lock().unwrap();
        if let Some(states) = states.as_ref() {
            if states.get(&order_id).map(|s| s.as_str()) != Some("valid") {
                return (StatusCode::NOT_FOUND, "Order not ready").into_response();
            }
        } else {
            return (StatusCode::NOT_FOUND, "Order not found").into_response();
        }
    }

    // Generate real X.509 certificate chain using rcgen
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType};

    // Create CA certificate
    let mut ca_params = CertificateParams::new(vec!["Test CA".to_string()]);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = Certificate::from_params(ca_params).unwrap();

    // Create end-entity certificate
    let mut cert_params = CertificateParams::new(vec!["example.com".to_string()]);
    cert_params.distinguished_name = DistinguishedName::new();
    cert_params
        .distinguished_name
        .push(DnType::CommonName, "example.com");
    let cert = Certificate::from_params(cert_params).unwrap();

    // Sign the end-entity cert with CA
    let cert_pem = cert.serialize_pem_with_signer(&ca_cert).unwrap();
    let ca_pem = ca_cert.serialize_pem().unwrap();

    let certificate = format!("{}\n{}", cert_pem, ca_pem);

    (
        StatusCode::OK,
        [
            (
                header::HeaderName::from_static("replay-nonce"),
                HeaderValue::from_static("Y2VydGlmaWNhdGVOb25jZQ"),
            ),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
        ],
        certificate,
    )
        .into_response()
}

pub async fn acme_revoke_certificate(
    State(_state): State<Arc<ServerState>>,
    Json(_request): Json<AcmeNewAccountRequest>,
) -> impl IntoResponse {
    use serde_json::json;
    use time::OffsetDateTime;

    // For testing, we'll revoke all current valid orders
    // In reality, we'd parse the certificate from the request to find the order ID
    let mut first_revocation = false;
    let mut already_revoked = false;

    {
        let mut revoked = ACME_REVOKED_CERTIFICATES.lock().unwrap();
        if revoked.is_none() {
            *revoked = Some(HashSet::new());
        }

        let revoked_set = revoked.as_mut().unwrap();

        // Get all valid orders
        let orders = ACME_ORDER_STATES.lock().unwrap();
        if let Some(orders) = orders.as_ref() {
            for (order_id, status) in orders.iter() {
                if status == "valid" {
                    if revoked_set.contains(order_id) {
                        already_revoked = true;
                        break;
                    } else {
                        // First revocation for this order
                        revoked_set.insert(order_id.clone());
                        first_revocation = true;
                        break;
                    }
                }
            }
        }
    }

    if already_revoked {
        let error_response = json!({
            "type": "urn:ietf:params:acme:error:alreadyRevoked",
            "detail": "Certificate has already been revoked",
            "status": 200
        });
        return (
            StatusCode::OK,
            [(
                header::HeaderName::from_static("replay-nonce"),
                HeaderValue::from_static("cmV2b2tlTm9uY2U"),
            )],
            Json(error_response),
        );
    }

    if first_revocation {
        // First revocation - return success response
        let response = json!({
            "status": "revoked",
            "revokedAt": OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
            "reason": 1
        });

        (
            StatusCode::OK,
            [(
                header::HeaderName::from_static("replay-nonce"),
                HeaderValue::from_static("cmV2b2tlTm9uY2U"),
            )],
            Json(response),
        )
    } else {
        // No valid orders found
        let error_response = json!({
            "type": "urn:ietf:params:acme:error:malformed",
            "detail": "No valid certificate found to revoke",
            "status": 400
        });
        (
            StatusCode::BAD_REQUEST,
            [(
                header::HeaderName::from_static("replay-nonce"),
                HeaderValue::from_static("cmV2b2tlTm9uY2U"),
            )],
            Json(error_response),
        )
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
    #[serde(rename = "relatedId", skip_serializing_if = "Option::is_none")]
    pub related_id: Option<String>,
    #[serde(flatten)]
    pub claims: serde_json::Value,
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

    if token.is_empty() {
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

    match verifier.verify(token, &options) {
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
            let payload = JwtPayload {
                subject: claims
                    .subject
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                audience: audience_to_string(claims.audience.as_ref(), expected_audience),
                issuer: claims.issuer.clone().unwrap_or_else(|| issuer.clone()),
                expiration: claims.expiration.map_or(0, system_time_to_unix_seconds),
                related_id,
                claims: payload_value,
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
    claims.ensure_jwt_id();
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
        .sign(&claims)
        .map_err(|err| ApiError::server_error(format!("Token imzalanamadı: {err}")))?;
    let issued_at = claims.issued_at.unwrap_or_else(|| SystemTime::now());
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
        .unwrap_or_else(|_| "wss://localhost:50045/zasian".to_owned());

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
        return Err(ApiError::invalid_scope("scope cannot be empty"));
    }
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for token in trimmed.split_whitespace() {
        if token.chars().any(char::is_control) {
            return Err(ApiError::invalid_scope(
                "scope cannot contain control characters",
            ));
        }
        if !allowed_scopes.iter().any(|allowed| allowed == token) {
            return Err(ApiError::invalid_scope(format!(
                "scope value not allowed: {token}",
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
            "code_challenge value must be base64url encoded SHA-256 output",
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
        .ok_or_else(|| ApiError::invalid_grant("Authorization code not found or expired"))?;

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
    claims.ensure_jwt_id();
    claims.set_issued_now();
    claims.set_expiration_from_now(state.token_ttl());
    claims.extra.insert(
        "client_id".to_string(),
        Value::String(payload.client_id.clone()),
    );
    if let Some(scope) = auth_request.scope {
        claims
            .extra
            .insert("scope".to_string(), Value::String(scope));
    }

    let access_token = state
        .signer()
        .sign(&claims)
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
        .map(|aud| serde_json::to_string(aud))
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
                .get("client_id")
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

    let generator = if let Some(namespace) = request.namespace {
        HeadIdGenerator::from_env_with_namespace(namespace)
    } else {
        HeadIdGenerator::from_env()
    }
    .map_err(|e| ApiError::invalid_request(format!("ID generator error: {}", e)))?;

    let id = generator
        .next_id()
        .map_err(|e| ApiError::server_error(format!("ID generation failed: {}", e)))?;

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
                // Transparency endpoints (gateway service)
                .route("/transparency/tree", get(transparency_tree))
                // Proxy JWT endpoints to auth service
                .route("/security/jwt-verify", post(proxy_jwt_verify))
                .route("/security/generate-media-token", post(proxy_media_token))
                // Proxy ID endpoints to id service
                .route("/id/generate", post(proxy_id_generate))
                .route("/id/generate", head(proxy_id_generate_head));
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
                .route("/security/generate-media-token", post(generate_media_token));
        }
        Some("acme-service") => {
            tracing::info!("🔒 Building ACME SERVICE routes");
            router = router
                // ACME endpoints (acme service)
                .route("/acme/directory", get(acme_directory))
                .route("/acme/new-nonce", get(acme_new_nonce))
                .route("/acme/new-account", post(acme_new_account))
                .route("/acme/accounts/:id", post(acme_account_status))
                .route("/acme/new-order", post(acme_new_order))
                .route("/acme/order/:id", post(acme_order_status))
                .route("/acme/orders/:id/finalize", post(acme_finalize_order))
                .route("/acme/cert/:id", get(acme_get_certificate))
                .route("/acme/revoke-cert", post(acme_revoke_certificate));
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
                .route("/blockchain/fabric/did/verify", post(verify_fabric_did));
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
                // ACME endpoints
                .route("/acme/directory", get(acme_directory))
                .route("/acme/new-nonce", get(acme_new_nonce))
                .route("/acme/new-account", post(acme_new_account))
                .route("/acme/accounts/:id", post(acme_account_status))
                .route("/acme/new-order", post(acme_new_order))
                .route("/acme/order/:id", post(acme_order_status))
                .route("/acme/orders/:id/finalize", post(acme_finalize_order))
                .route("/acme/cert/:id", get(acme_get_certificate))
                .route("/acme/revoke-cert", post(acme_revoke_certificate))
                // OAuth endpoints
                .route("/oauth/begin-auth", post(begin_auth))
                .route("/oauth/token", post(exchange_token))
                .route("/oauth/introspect", post(introspect_token))
                .route("/oauth/transparency", get(oauth_transparency))
                // JWT endpoints
                .route("/cli/jwt/verify", post(verify_jwt_token))
                .route("/security/jwt-verify", post(verify_media_token))
                .route("/security/generate-media-token", post(generate_media_token))
                // MDM endpoints
                .route("/mdm/register", post(register_device))
                .route("/mdm/policy/:platform", get(fetch_policy))
                .route("/mdm/cert-plan/:device_id", get(fetch_certificate_plan))
                // Fabric DID endpoints
                .route("/blockchain/fabric/did/verify", post(verify_fabric_did))
                // ID endpoints
                .route("/id/generate", post(generate_id))
                .route("/id/generate", head(head_generate_id))
                // SFU endpoints
                .route("/sfu/context", post(create_sfu_context))
                .route("/sfu/context/step", post(next_sfu_step))
                // Transparency endpoints
                .route("/transparency/tree", get(transparency_tree));
        }
    }

    router.with_state(state.clone())
}

// Proxy functions for gateway
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
    match client
        .head("http://aun-id-service:50016/id/generate")
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
            status_code.into_response()
        }
        Err(_) => (StatusCode::BAD_GATEWAY, "ID service unavailable").into_response(),
    }
}

/// Starts the aunsorm server with the given configuration.
///
/// # Errors
///
/// Returns `ServerError` if the server fails to start or bind to the specified address.
pub async fn serve(config: ServerConfig) -> Result<(), ServerError> {
    let listen = config.listen;
    let state = Arc::new(ServerState::try_new(config)?);
    let router = build_router(&state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, router.into_make_service()).await?;
    Ok(())
}
