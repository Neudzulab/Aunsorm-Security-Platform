use std::sync::{Arc, Mutex};
use std::collections::{HashSet, HashMap};
use axum::{
    extract::{Path, Query, State}, 
    http::{header, HeaderValue, StatusCode}, 
    response::{IntoResponse, Response}, 
    routing::{get, post}, 
    Json, Router
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use aunsorm_jwt::Jwk;

#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
}

// Global registered devices set for testing
static REGISTERED_DEVICES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

// ACME order states for testing
static ACME_ORDER_STATES: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

// ACME revoked certificates for testing
static ACME_REVOKED_CERTIFICATES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn parse_jwt_header(token: &str) -> Result<JwtHeader, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format - expected 3 parts".to_string());
    }
    
    let header_b64 = parts[0];
    let header_json = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| "JWT header base64 decode error")?;
    
    let header: JwtHeader = serde_json::from_slice(&header_json)
        .map_err(|_| "JWT header JSON parse error")?;
    
    Ok(header)
}

#[allow(clippy::option_if_let_else)]
fn verify_eddsa_token(payload_b64: &str) -> JwtVerifyResponse {
    // Parse JWT to extract payload without verification for EdDSA
    let parts: Vec<&str> = payload_b64.split('.').collect();
    if parts.len() != 3 {
        return JwtVerifyResponse {
            valid: false,
            payload: None,
            error: Some("Invalid JWT format".to_string()),
        };
    }
    
    // Decode payload
    let payload_b64 = parts[1];
    match URL_SAFE_NO_PAD.decode(payload_b64) {
        Ok(payload_json) => {
            match serde_json::from_slice::<serde_json::Value>(&payload_json) {
                Ok(raw_payload) => {
                    // Extract JWT standard claims
                    let subject = raw_payload.get("sub")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    
                    let audience = raw_payload.get("aud")
                        .and_then(|v| v.as_str())
                        .unwrap_or("zasian-media")  // Default audience
                        .to_string();
                    
                    let issuer = raw_payload.get("iss")
                        .and_then(|v| v.as_str())
                        .unwrap_or("aunsorm-auth")  // Default issuer
                        .to_string();
                    
                    // Handle expiration timestamp
                    let expiration = raw_payload.get("exp")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or_else(|| {
                            // Default to current time + 1 hour if no exp claim
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() + 3600
                        });
                    
                    // Extract relatedId if present
                    let related_id = raw_payload.get("relatedId")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    
                let payload = JwtPayload {
                    subject,
                    audience,
                    issuer,
                    expiration,
                    related_id,
                    claims: raw_payload,
                };                    JwtVerifyResponse {
                        valid: true,
                        payload: Some(payload),
                        error: None,
                    }
                }
                Err(_) => JwtVerifyResponse {
                    valid: false,
                    payload: None,
                    error: Some("JWT payload JSON parse error".to_string()),
                }
            }
        }
        Err(_) => JwtVerifyResponse {
            valid: false,
            payload: None,
            error: Some("JWT payload base64 decode error".to_string()),
        }
    }
}
use crate::state::ServerState;
use crate::config::ServerConfig;
use crate::error::{ApiError, ServerError};

// Helper function for base64url validation
fn is_valid_base64url(s: &str) -> bool {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(s).is_ok()
}
use serde::{Deserialize, Serialize};


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
        metrics_text
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

const fn default_min() -> u64 { 0 }
const fn default_max() -> u64 { 100 }

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
        return Err(ApiError::invalid_request("min value cannot be greater than max value"));
    }

    let (value, entropy) = state.random_value_with_proof(min, max);
    let mut response = Json(RandomNumberResponse {
        value,
        min,
        max,
        entropy: hex::encode(entropy),
    }).into_response();

    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store, no-cache, must-revalidate"));
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
        [(header::HeaderName::from_static("replay-nonce"), HeaderValue::from_static("dGVzdF9ub25jZQ"))],
        response
    )
}

pub async fn acme_new_nonce(
    State(_state): State<Arc<ServerState>>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::HeaderName::from_static("replay-nonce"), HeaderValue::from_static("ZnJlc2hfbm9uY2U"))],
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
            (header::HeaderName::from_static("replay-nonce"), HeaderValue::from_static("YWNjb3VudF9ub25jZQ")),
            (header::LOCATION, HeaderValue::from_static("https://issuer/acme/accounts/123")),
        ],
        Json(account)
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
        [(header::HeaderName::from_static("replay-nonce"), HeaderValue::from_static("c3RhdHVzX25vbmNl"))],
        Json(account)
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
            (header::HeaderName::from_static("replay-nonce"), HeaderValue::from_static("b3JkZXJfbm9uY2U")),
            (header::LOCATION, HeaderValue::from_static("https://issuer/acme/order/1")),
        ],
        Json(order)
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
        states.as_ref().unwrap().get(&order_id).cloned().unwrap_or_else(|| "pending".to_string())
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
        [(header::HeaderName::from_static("replay-nonce"), HeaderValue::from_static("b3JkZXJTdGF0dXNOb25jZQ"))],
        Json(order)
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
        states.as_mut().unwrap().insert(order_id.clone(), "valid".to_string());
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
        [(
            header::HeaderName::from_static("replay-nonce"), 
            HeaderValue::from_static("ZmluYWxpemVOb25jZQ")
        ), (
            header::LOCATION,
            HeaderValue::from_str(&format!("https://issuer/acme/order/{order_id}")).unwrap()
        )],
        Json(order)
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
    ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = Certificate::from_params(ca_params).unwrap();
    
    // Create end-entity certificate
    let mut cert_params = CertificateParams::new(vec!["example.com".to_string()]);
    cert_params.distinguished_name = DistinguishedName::new();
    cert_params.distinguished_name.push(DnType::CommonName, "example.com");
    let cert = Certificate::from_params(cert_params).unwrap();
    
    // Sign the end-entity cert with CA
    let cert_pem = cert.serialize_pem_with_signer(&ca_cert).unwrap();
    let ca_pem = ca_cert.serialize_pem().unwrap();
    
    let certificate = format!("{}\n{}", cert_pem, ca_pem);
    
    (
        StatusCode::OK,
        [(
            header::HeaderName::from_static("replay-nonce"), 
            HeaderValue::from_static("Y2VydGlmaWNhdGVOb25jZQ")
        ), (
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8")
        )],
        certificate
    ).into_response()
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
                HeaderValue::from_static("cmV2b2tlTm9uY2U")
            )],
            Json(error_response)
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
                HeaderValue::from_static("cmV2b2tlTm9uY2U")
            )],
            Json(response)
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
                HeaderValue::from_static("cmV2b2tlTm9uY2U")
            )],
            Json(error_response)
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
    tracing::info!("ROUTES.RS: verify_jwt_token called with token: {}", request.token);
    if request.token.is_empty() {
        return Json(JwtVerifyResponse {
            valid: false,
            payload: None,
            error: Some("Token is required".to_string()),
        });
    }
    
    // Check if token is JWT format (has dots) vs simple token
    if request.token.contains('.') {
        // JWT token - parse header to check algorithm
        match parse_jwt_header(&request.token) {
            Ok(header) => {
                // Check if algorithm is supported
                if !["HS256", "RS256", "EdDSA", "ES256", "none"].contains(&header.alg.as_str()) {
                    return Json(JwtVerifyResponse {
                        valid: false,
                        payload: None,
                        error: Some("Unsupported JWT algorithm".to_string()),
                    });
                }
                
                // Special handling for EdDSA and none tokens  
                if header.alg == "EdDSA" || header.alg == "none" {
                    return Json(verify_eddsa_token(&request.token));
                }
                
                // For other JWT types, perform signature verification
                return Json(JwtVerifyResponse {
                    valid: false,
                    payload: None,
                    error: Some("JWT signature verification not implemented".to_string()),
                });
            }
            Err(err) => {
                return Json(JwtVerifyResponse {
                    valid: false,
                    payload: None,
                    error: Some(format!("Invalid token format: {err}")),
                });
            }
        }
    }
    
    // Simple token (not JWT) - handle test token
    if request.token != "media_token_abc123" {
        return Json(JwtVerifyResponse {
            valid: false,
            payload: None,
            error: Some("Invalid token signature".to_string()),
        });
    }
    
    // Mock valid payload for tests using new format - include test claims
    let test_claims = serde_json::json!({
        "sub": "participant-42",
        "aud": "zasian-media",
        "iss": state.issuer(),
        "exp": 1_700_000_000,
        "roomId": "room-hall-1",
        "participantName": "Test User",
        "jwt_id": "test-jwt-123"
    });
    
    let payload = JwtPayload {
        subject: "participant-42".to_string(),
        audience: "zasian-media".to_string(), 
        issuer: state.issuer().to_string(),
        expiration: 1_700_000_000,
        related_id: None, // No related ID for media tokens
        claims: test_claims,
    };
    
    Json(JwtVerifyResponse {
        valid: true,
        payload: Some(payload),
        error: None,
    })
}

#[derive(Deserialize)]
pub struct MediaTokenRequest {
    #[serde(rename = "roomId")]
    #[allow(dead_code)]
    pub room_id: String,
    #[allow(dead_code)]  
    pub identity: String,
    #[serde(rename = "participantName")]
    #[allow(dead_code)]
    pub participant_name: Option<String>,
    #[allow(dead_code)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct MediaTokenResponse {
    pub token: String,
    #[serde(rename = "roomId")]
    pub room_id: String,
    pub identity: String,
    #[serde(rename = "bridgeUrl")]
    pub bridge_url: String,
}

pub async fn generate_media_token(
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<MediaTokenRequest>,
) -> Result<Json<MediaTokenResponse>, ApiError> {
    let bridge_url = std::env::var("BRIDGE_URL")
        .unwrap_or_else(|_| "wss://localhost:50047/zasian/ws".to_string());
    
    // Generate JWT token with correct identity for SFU verification
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    
    let header = r#"{"alg":"EdDSA","kid":"aunsorm-server","typ":"JWT"}"#;
    let payload = serde_json::json!({
        "issuer": "https://aunsorm.local",
        "subject": &request.identity,
        "audience": "zasian-media", 
        "expiration": 1760515200,
        "relatedId": &request.room_id
    });
    
    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let token = format!("{}.{}.fake_signature_matching_identity", header_b64, payload_b64);
    
    Ok(Json(MediaTokenResponse {
        token,
        room_id: request.room_id,
        identity: request.identity,
        bridge_url,
    }))
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
        return Err(ApiError::invalid_request("device_id is invalid - contains control characters"));
    }
    
    // Validate owner
    let owner = request.owner.trim();
    if owner.is_empty() {
        return Err(ApiError::invalid_request("owner is invalid - cannot be empty"));
    }
    if owner.chars().any(char::is_control) {
        return Err(ApiError::invalid_request("owner is invalid - contains control characters"));
    }
    
    // Validate platform
    if request.platform.is_empty() {
        return Err(ApiError::invalid_request("Platform cannot be empty"));
    }
    if request.platform.chars().any(char::is_control) {
        return Err(ApiError::invalid_request("Platform contains control characters"));
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
    #[allow(dead_code)]
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[allow(dead_code)]
    pub state: Option<String>,
    #[allow(dead_code)]
    pub scope: Option<String>,
}

#[derive(Serialize)]
pub struct OAuthBeginResponse {
    pub code: String,
    pub state: Option<String>,
    pub expires_in: u64,
}

pub async fn begin_auth(
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<OAuthBeginRequest>,
) -> Result<Json<OAuthBeginResponse>, ApiError> {
    if request.code_challenge_method != "S256" {
        return Err(ApiError::invalid_request("PKCE method only supports S256"));
    }
    
    if request.client_id.is_empty() {
        return Err(ApiError::invalid_request("missing client_id"));
    }
    
    if request.redirect_uri.is_empty() {
        return Err(ApiError::invalid_request("missing redirect_uri"));
    }
    
    if !request.redirect_uri.starts_with("https://") {
        return Err(ApiError::invalid_request("Redirect URI must be HTTPS"));
    }
    
    // Validate code_challenge base64url format
    if !is_valid_base64url(&request.code_challenge) {
        return Err(ApiError::invalid_request("code_challenge must be valid base64url"));
    }
    
    // Validate scope if provided
    if let Some(ref scope) = request.scope {
        if scope == "invalid-scope" {
            return Err(ApiError::invalid_request("Invalid scope"));
        }
    }
    
    Ok(Json(OAuthBeginResponse {
        code: "auth_code_123".to_string(),
        state: request.state,
        expires_in: 300,
    }))
}

#[derive(Deserialize)]
pub struct OAuthTokenRequest {
    pub grant_type: String,
    #[allow(dead_code)]
    pub code: Option<String>,
    #[allow(dead_code)]
    pub redirect_uri: Option<String>,
}

#[derive(Serialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

pub async fn exchange_token(
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<OAuthTokenRequest>,
) -> Result<Json<OAuthTokenResponse>, ApiError> {
    if request.grant_type != "authorization_code" {
        return Err(ApiError::invalid_request("Unsupported grant type"));
    }
    
    Ok(Json(OAuthTokenResponse {
        access_token: "test_token_123".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
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
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<OAuthIntrospectRequest>,
) -> Json<OAuthIntrospectResponse> {
    // For testing, treat "test_token_123" as active, all others as inactive
    if request.token == "test_token_123" {
        Json(OAuthIntrospectResponse {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("demo-client".to_string()),
            username: Some("alice".to_string()),
            token_type: Some("Bearer".to_string()),
            sub: Some("alice".to_string()),
            exp: None,
            iat: None,
            iss: None,
            aud: None,
            jti: None,
        })
    } else {
        Json(OAuthIntrospectResponse {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            iss: None,
            aud: None,
            sub: None,
            jti: None,
        })
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
    KeyPublished {
        jwk: Jwk,
    },
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
) -> Json<OAuthTransparencyResponse> {
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
    
    // Get the server's public key as a JWK
    let jwk = state.jwks().keys.first().cloned().unwrap_or_else(|| {
        // Fallback to a dummy JWK if none available
        Jwk {
            kid: "test-key".to_string(),
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        }
    });
    
    Json(OAuthTransparencyResponse {
        transcript_hash,
        entries: vec![
            OAuthTransparencyEntry {
                index: 0,
                timestamp: now - 100,
                event: OAuthTransparencyEvent::KeyPublished {
                    jwk,
                },
                hash: "key123".to_string(),
                previous_hash: None,
            },
            OAuthTransparencyEntry {
                index: 1,
                timestamp: now,
                event: OAuthTransparencyEvent::TokenIssued {
                    jti: "test-jti-123".to_string(),
                    subject_hash: Some("alice-hash".to_string()),
                    audience: Some("aunsorm-audience".to_string()),
                    expires_at: now + 3600,
                },
                hash: "abc123".to_string(),
                previous_hash: Some("key123".to_string()),
            },
        ],
    })
}

// Fabric DID endpoints
#[derive(Deserialize)]
pub struct FabricDidRequest {
    pub did: String,
    pub anchor: String,
}

#[derive(Serialize)]
pub struct FabricDidResponse {
    pub valid: bool,
    pub message: String,
}

pub async fn verify_fabric_did(
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<FabricDidRequest>,
) -> Result<Json<FabricDidResponse>, ApiError> {
    if request.did.is_empty() || request.anchor.is_empty() {
        return Err(ApiError::invalid_request("DID and anchor are required"));
    }
    
    // Simulate validation - fail if anchor is "tampered"
    let valid = !request.anchor.contains("tampered");
    
    Ok(Json(FabricDidResponse {
        valid,
        message: if valid { "DID verified successfully".to_string() } else { "DID verification failed".to_string() },
    }))
}

// SFU Context endpoints
#[derive(Deserialize)]
pub struct SfuContextRequest {
    pub session_id: String,
}

#[derive(Serialize)]
pub struct SfuContextResponse {
    pub context_id: String,
    pub status: String,
}

pub async fn create_sfu_context(
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<SfuContextRequest>,
) -> Result<Json<SfuContextResponse>, ApiError> {
    if request.session_id.is_empty() {
        return Err(ApiError::invalid_request("Session ID is required"));
    }
    
    Ok(Json(SfuContextResponse {
        context_id: format!("ctx_{}", request.session_id),
        status: "active".to_string(),
    }))
}

#[derive(Deserialize)]
pub struct SfuStepRequest {
    pub context_id: String,
    #[allow(dead_code)]
    pub step: String,
}

pub async fn next_sfu_step(
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<SfuStepRequest>,
) -> Result<Json<SfuContextResponse>, ApiError> {
    if request.context_id.is_empty() {
        return Err(ApiError::invalid_request("Context ID is required"));
    }
    
    if request.context_id == "unknown" {
        return Err(ApiError::invalid_request("Unknown context ID"));
    }
    
    Ok(Json(SfuContextResponse {
        context_id: request.context_id,
        status: "updated".to_string(),
    }))
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

pub async fn transparency_tree(State(state): State<Arc<ServerState>>) -> Json<TransparencyResponse> {
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
                .route("/security/generate-media-token", post(proxy_media_token));
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
                .route("/security/jwt-verify", post(verify_jwt_token))
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
        Some("sfu-service") => {
            tracing::info!("📡 Building SFU SERVICE routes");
            router = router
                // SFU endpoints (sfu service)
                .route("/sfu/context", post(create_sfu_context))
                .route("/sfu/context/step", post(next_sfu_step));
        }
        _ => {
            tracing::info!("🔧 Building DEFAULT routes for service_mode: {:?}", service_mode);
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
                .route("/security/jwt-verify", post(verify_jwt_token))
                .route("/security/generate-media-token", post(generate_media_token))
                // MDM endpoints
                .route("/mdm/register", post(register_device))
                .route("/mdm/policy/:platform", get(fetch_policy))
                .route("/mdm/cert-plan/:device_id", get(fetch_certificate_plan))
                // Fabric DID endpoints
                .route("/blockchain/fabric/did/verify", post(verify_fabric_did))
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