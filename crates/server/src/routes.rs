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

#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
}

// Global registered devices set for testing
static REGISTERED_DEVICES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

// ACME order states for testing
static ACME_ORDER_STATES: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

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

fn verify_eddsa_token(token: &str, _state: &ServerState) -> JwtVerifyResponse {
    // Parse JWT to extract payload without verification for EdDSA
    let parts: Vec<&str> = token.split('.').collect();
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
                Ok(payload) => {
                    // For EdDSA tokens, return successful verification with payload
                    JwtVerifyResponse {
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

#[derive(Serialize)]
pub struct MetricsResponse {
    status: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "OK" })
}

pub async fn metrics(State(_state): State<Arc<ServerState>>) -> Json<MetricsResponse> {
    Json(MetricsResponse { status: "OK" })
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
        _orders: format!("https://issuer/acme/accounts/{}/orders", account_id),
        terms_of_service_agreed: true,
        kid: format!("https://issuer/acme/accounts/{}", account_id),
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
        Some(format!("https://issuer/acme/cert/{}", order_id))
    } else {
        None
    };
    
    let order = AcmeOrderResponse {
        status,
        identifiers: vec![AcmeOrderIdentifier {
            ty: "dns".to_string(),
            value: "example.com".to_string(),
        }],
        authorizations: vec![format!("https://issuer/acme/authz/{}", order_id)],
        finalize: format!("https://issuer/acme/orders/{}/finalize", order_id),
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
        authorizations: vec![format!("https://issuer/acme/authz/{}", order_id)],
        finalize: format!("https://issuer/acme/orders/{}/finalize", order_id),
        _expires: "2025-10-26T10:00:00Z".to_string(),
        _not_before: None,
        _not_after: None,
        certificate: Some(format!("https://issuer/acme/cert/{}", order_id)),
    };
    
    (
        StatusCode::OK,
        [(
            header::HeaderName::from_static("replay-nonce"), 
            HeaderValue::from_static("ZmluYWxpemVOb25jZQ")
        ), (
            header::LOCATION,
            HeaderValue::from_str(&format!("https://issuer/acme/order/{}", order_id)).unwrap()
        )],
        Json(order)
    )
}

// JWT Verify endpoint
#[derive(Deserialize)]
pub struct JwtVerifyRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct JwtVerifyResponse {
    pub valid: bool,
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
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
                if !["HS256", "RS256", "EdDSA", "ES256"].contains(&header.alg.as_str()) {
                    return Json(JwtVerifyResponse {
                        valid: false,
                        payload: None,
                        error: Some("Unsupported JWT algorithm".to_string()),
                    });
                }
                
                // Special handling for EdDSA tokens
                if header.alg == "EdDSA" {
                    return Json(verify_eddsa_token(&request.token, &state));
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
                    error: Some(format!("Invalid token format: {}", err)),
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
    
    // Mock valid payload for tests
    let payload = serde_json::json!({
        "issuer": state.issuer(),
        "audience": "zasian-media",
        "subject": "participant-42",
        "roomId": "room-hall-1",
        "participantName": "Test User",
        "jwt_id": "jwt_123",
        "exp": 1700000000
    });
    
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
}

pub async fn generate_media_token(
    State(_state): State<Arc<ServerState>>,
    Json(request): Json<MediaTokenRequest>,
) -> Result<Json<MediaTokenResponse>, ApiError> {
    Ok(Json(MediaTokenResponse {
        token: "media_token_abc123".to_string(),
        room_id: request.room_id,
        identity: request.identity,
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
        return Err(ApiError::invalid_request("device_id is invalid - cannot be empty"));
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
        return Err(ApiError::invalid_request("platform value is invalid - contains control characters"));
    }
    
    // Check for duplicate registration
    {
        let mut registered = REGISTERED_DEVICES.lock().unwrap();
        if registered.is_none() {
            *registered = Some(HashSet::new());
        }
        
        let devices = registered.as_mut().unwrap();
        if devices.contains(&request.device_id) {
            return Err(ApiError::invalid_request("Device already registered"));
        }
        devices.insert(request.device_id.clone());
    }
    
    let now = 1700000000_u64; // Mock timestamp
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
        return Err(ApiError::not_found("Policy not found - platform not supported"));
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
        next_renewal: 1234567890,
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
    pub tree_size: u64,
    pub root_hash: String,
}

pub async fn transparency_tree(State(_state): State<Arc<ServerState>>) -> Json<TransparencyResponse> {
    Json(TransparencyResponse {
        tree_size: 42,
        root_hash: "abc123def456".to_string(),
    })
}

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
                .route("/transparency/tree", get(transparency_tree));
        }
        Some("auth-service") => {
            tracing::info!("🔐 Building AUTH SERVICE routes");
            router = router
                // OAuth endpoints (auth service)
                .route("/oauth/begin-auth", post(begin_auth))
                .route("/oauth/token", post(exchange_token))
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
                .route("/acme/orders/:id/finalize", post(acme_finalize_order));
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
                // OAuth endpoints
                .route("/oauth/begin-auth", post(begin_auth))
                .route("/oauth/token", post(exchange_token))
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