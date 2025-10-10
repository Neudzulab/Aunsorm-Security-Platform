use std::borrow::ToOwned;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use aunsorm_jwt::{Audience, Claims, JwtError, VerificationOptions};

use crate::config::ServerConfig;
use crate::error::{ApiError, ServerError};
use crate::state::{auth_ttl, ServerState, SfuStepOutcome};
use crate::transparency::TransparencySnapshot;
use serde_json::{self, Value};

pub fn build_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/oauth/begin-auth", post(begin_auth))
        .route("/oauth/token", post(exchange_token))
        .route("/oauth/introspect", post(introspect))
        .route("/oauth/jwks.json", get(jwks))
        .route("/oauth/transparency", get(transparency))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/sfu/context", post(create_sfu_context))
        .route("/sfu/context/step", post(next_sfu_step))
        .with_state(state)
}

/// HTTP sunucusunu başlatır.
///
/// # Errors
///
/// Ağ dinleyicisi oluşturulamazsa veya HTTP hizmeti başlatılamazsa `ServerError` döner.
pub async fn serve(config: ServerConfig) -> Result<(), ServerError> {
    let listen = config.listen;
    let state = Arc::new(ServerState::try_new(config)?);
    let router = build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!(address = %listen, "aunsorm-server dinlemede");
    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let now = SystemTime::now();
            if let Err(err) = cleanup_state.purge_tokens(now).await {
                warn!(error = %err, "token temizliği başarısız");
            }
        }
    });
    axum::serve(listener, router.into_make_service()).await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct BeginAuthRequest {
    username: String,
    client_id: String,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(Debug, Serialize)]
struct BeginAuthResponse {
    auth_request_id: String,
    expires_in: u64,
}

async fn begin_auth(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<BeginAuthRequest>,
) -> Result<Json<BeginAuthResponse>, ApiError> {
    if payload.code_challenge_method != "S256" {
        return Err(ApiError::invalid_request(
            "PKCE yöntemi yalnızca S256 desteklenir",
        ));
    }
    if URL_SAFE_NO_PAD
        .decode(&payload.code_challenge)
        .map(|bytes| bytes.len())
        .unwrap_or_default()
        != Sha256::output_size()
    {
        return Err(ApiError::invalid_request(
            "code_challenge değeri base64url kodlu SHA-256 çıktısı olmalıdır",
        ));
    }
    let auth_id = state
        .register_auth_request(payload.username, payload.client_id, payload.code_challenge)
        .await;
    Ok(Json(BeginAuthResponse {
        auth_request_id: auth_id,
        expires_in: auth_ttl().as_secs(),
    }))
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    auth_request_id: String,
    code_verifier: String,
    client_id: String,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
}

async fn exchange_token(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    if payload.code_verifier.len() < 43 || payload.code_verifier.len() > 128 {
        return Err(ApiError::invalid_request(
            "code_verifier uzunluğu 43 ile 128 karakter arasında olmalıdır",
        ));
    }
    let auth_request = state
        .consume_auth_request(&payload.auth_request_id)
        .await
        .ok_or_else(|| {
            ApiError::invalid_grant("Yetkilendirme isteği bulunamadı veya süresi doldu")
        })?;
    if auth_request.client_id != payload.client_id {
        return Err(ApiError::invalid_client("client_id eşleşmiyor"));
    }
    let verifier_bytes = payload.code_verifier.as_bytes();
    let digest = Sha256::digest(verifier_bytes);
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    if challenge != auth_request.code_challenge {
        return Err(ApiError::invalid_grant("PKCE doğrulaması başarısız"));
    }

    let mut claims = Claims::new();
    claims.subject = Some(auth_request.subject);
    claims.issuer = Some(state.issuer().to_owned());
    claims.audience = Some(Audience::Single(state.audience().to_owned()));
    claims.ensure_jwt_id();
    claims.set_issued_now();
    claims.set_expiration_from_now(state.token_ttl());
    claims
        .extra
        .insert("client_id".to_string(), Value::String(payload.client_id));
    let subject_for_log = claims.subject.clone();
    let audience_for_log = claims
        .audience
        .clone()
        .map(|aud| {
            serde_json::to_string(&aud)
                .map_err(|err| ApiError::server_error(format!("audience serileştirilemedi: {err}")))
        })
        .transpose()?;
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
        .ok_or_else(|| ApiError::server_error("exp claim'i eksik"))?;
    state
        .record_token(
            &jti,
            expires_at,
            subject_for_log.as_deref(),
            audience_for_log.as_deref(),
        )
        .await
        .map_err(|err| ApiError::server_error(format!("Token kaydı başarısız: {err}")))?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.token_ttl().as_secs(),
    }))
}

#[derive(Debug, Deserialize)]
struct IntrospectRequest {
    token: String,
}

#[derive(Debug, Serialize)]
struct IntrospectResponse {
    active: bool,
    scope: Option<String>,
    client_id: Option<String>,
    username: Option<String>,
    token_type: Option<&'static str>,
    exp: Option<u64>,
    iat: Option<u64>,
    iss: Option<String>,
    aud: Option<String>,
    sub: Option<String>,
    jti: Option<String>,
}

async fn introspect(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, ApiError> {
    let options = VerificationOptions {
        issuer: Some(state.issuer().to_owned()),
        audience: Some(state.audience().to_owned()),
        require_jti: true,
        ..VerificationOptions::default()
    };
    let verification = state.verifier().verify(&payload.token, &options);
    let now = SystemTime::now();
    match verification {
        Ok(claims) => {
            let exp = claims
                .expiration
                .and_then(|ts| ts.duration_since(UNIX_EPOCH).ok())
                .map(|dur| dur.as_secs());
            let iat = claims
                .issued_at
                .and_then(|ts| ts.duration_since(UNIX_EPOCH).ok())
                .map(|dur| dur.as_secs());
            let client_id = claims
                .extra
                .get("client_id")
                .and_then(|value| value.as_str())
                .map(ToOwned::to_owned);
            let jti = claims.jwt_id.clone();
            let active = if let Some(ref jti_value) = jti {
                state.is_token_active(jti_value, now).await.map_err(|err| {
                    ApiError::server_error(format!("Token durumu sorgulanamadı: {err}"))
                })?
            } else {
                false
            };
            let response = IntrospectResponse {
                active,
                scope: None,
                client_id,
                username: claims.subject.clone(),
                token_type: Some("Bearer"),
                exp,
                iat,
                iss: claims.issuer.clone(),
                aud: claims.audience.as_ref().and_then(|aud| match aud {
                    Audience::Single(value) => Some(value.clone()),
                    Audience::Multiple(values) => values.first().cloned(),
                }),
                sub: claims.subject,
                jti,
            };
            Ok(Json(response))
        }
        Err(JwtError::Expired) => Ok(Json(IntrospectResponse {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: Some("Bearer"),
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

async fn transparency(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<TransparencySnapshot>, ApiError> {
    let snapshot = state
        .transparency_snapshot()
        .await
        .map_err(|err| ApiError::server_error(format!("Şeffaflık günlüğü alınamadı: {err}")))?;
    Ok(Json(snapshot))
}

async fn jwks(State(state): State<Arc<ServerState>>) -> Json<aunsorm_jwt::Jwks> {
    Json(state.jwks().clone())
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn metrics(State(state): State<Arc<ServerState>>) -> Result<Response, ApiError> {
    let now = SystemTime::now();
    let pending = state.auth_request_count().await;
    let active = state
        .active_token_count(now)
        .await
        .map_err(|err| ApiError::server_error(format!("Metrik hesaplanamadı: {err}")))?;
    let sfu_contexts = state.sfu_context_count(now).await;
    let body = format!(
        "# HELP aunsorm_pending_auth_requests Bekleyen PKCE yetkilendirme istekleri\n# TYPE aunsorm_pending_auth_requests gauge\naunsorm_pending_auth_requests {pending}\n# HELP aunsorm_active_tokens Aktif erişim belirteci sayısı\n# TYPE aunsorm_active_tokens gauge\naunsorm_active_tokens {active}\n# HELP aunsorm_sfu_contexts Aktif SFU oturum bağlamı sayısı\n# TYPE aunsorm_sfu_contexts gauge\naunsorm_sfu_contexts {sfu_contexts}\n"
    );
    let mut response = Response::new(body.into());
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct CreateSfuContextRequest {
    room_id: String,
    participant: String,
    #[serde(default = "default_enable_e2ee")]
    enable_e2ee: bool,
}

const fn default_enable_e2ee() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
struct SfuE2eeEnvelope {
    session_id: String,
    message_no: u64,
    key: String,
    nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateSfuContextResponse {
    context_id: String,
    room_id: String,
    participant: String,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    e2ee: Option<SfuE2eeEnvelope>,
}

async fn create_sfu_context(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<CreateSfuContextRequest>,
) -> Result<Json<CreateSfuContextResponse>, ApiError> {
    if payload.room_id.trim().is_empty() {
        return Err(ApiError::invalid_request("room_id boş olamaz"));
    }
    if payload.participant.trim().is_empty() {
        return Err(ApiError::invalid_request("participant boş olamaz"));
    }
    let provision = state
        .create_sfu_context(payload.room_id, payload.participant, payload.enable_e2ee)
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

#[derive(Debug, Deserialize)]
struct NextSfuStepRequest {
    context_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
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

async fn next_sfu_step(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<NextSfuStepRequest>,
) -> Result<Json<NextSfuStepResponse>, ApiError> {
    if payload.context_id.trim().is_empty() {
        return Err(ApiError::invalid_request("context_id boş olamaz"));
    }
    let outcome = state
        .next_sfu_step(&payload.context_id)
        .await
        .map_err(|err| ApiError::server_error(format!("SFU ratchet adımı üretilemedi: {err}")))?;
    match outcome {
        SfuStepOutcome::NotFound => Err(ApiError::invalid_request("SFU bağlamı bulunamadı")),
        SfuStepOutcome::Expired => Err(ApiError::invalid_grant("SFU bağlamının süresi doldu")),
        SfuStepOutcome::E2eeDisabled => Err(ApiError::invalid_request(
            "SFU bağlamı için uçtan uca şifreleme etkin değil",
        )),
        SfuStepOutcome::Step(step) => {
            let now = SystemTime::now();
            let expires_in = step
                .expires_at
                .duration_since(now)
                .unwrap_or_default()
                .as_secs();
            Ok(Json(NextSfuStepResponse {
                context_id: payload.context_id,
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
