use std::borrow::ToOwned;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "http3-experimental")]
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
#[cfg(feature = "http3-experimental")]
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use hex::encode as hex_encode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::signal;
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tracing::{info, warn};

use aunsorm_core::transparency::TransparencyRecord;
use aunsorm_jwt::{Audience, Claims, JwtError, VerificationOptions};
use aunsorm_mdm::{
    DeviceCertificatePlan, DevicePlatform, DeviceRecord, EnrollmentRequest, MdmError,
    PolicyDocument,
};

use crate::config::ServerConfig;
use crate::error::{ApiError, ServerError};
#[cfg(feature = "http3-experimental")]
use crate::quic::spawn_http3_poc;
use crate::state::{auth_ttl, ServerState, SfuStepOutcome, TransparencyTreeSnapshot};
use crate::transparency::TransparencySnapshot as LedgerTransparencySnapshot;
use serde_json::Value;

// ID generation types (aunsorm-id crate)
use aunsorm_id::{parse_head_id, HeadIdGenerator, IdError};

/// HTTP yönlendiricisini oluşturur.
///
/// # Panics
///
/// `http3-experimental` özelliği etkinleştirildiğinde `Alt-Svc` başlığı
/// oluşturulamazsa panikler.
pub fn build_router(state: Arc<ServerState>) -> Router {
    let router = Router::new()
        .route("/oauth/begin-auth", post(begin_auth))
        .route("/oauth/token", post(exchange_token))
        .route("/oauth/introspect", post(introspect))
        .route("/oauth/jwks.json", get(jwks))
        .route("/oauth/transparency", get(transparency))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/sfu/context", post(create_sfu_context))
        .route("/sfu/context/step", post(next_sfu_step))
        .route("/mdm/register", post(register_device))
        .route("/mdm/policy/:platform", get(fetch_policy))
        .route("/mdm/cert-plan/:device_id", get(fetch_certificate_plan))
        .route("/transparency/tree", get(transparency_tree))
        // ID Generation endpoints (v0.4.5)
        .route("/id/generate", post(generate_id))
        .route("/id/parse", post(parse_id))
        .route("/id/verify-head", post(verify_head));

    #[cfg(feature = "http3-experimental")]
    let router = {
        let port = state.listen_port();
        let header_value = format!("h3=\":{port}\"; ma=3600, h3-29=\":{port}\"; ma=3600");
        let header_value =
            HeaderValue::from_str(&header_value).expect("Alt-Svc başlığı oluşturulamadı");
        let header_value = Arc::new(header_value);
        router.layer(middleware::from_fn(
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

    router
        .route("/random/number", get(random_number))
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
    #[cfg(feature = "http3-experimental")]
    let _http3_guard = {
        let guard = spawn_http3_poc(listen, Arc::clone(&state))?;
        info!(
            port = listen.port(),
            "HTTP/3 PoC dinleyicisi etkinleştirildi"
        );
        guard
    };
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
    axum::serve(listener, router.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        match signal::ctrl_c().await {
            Ok(()) => info!("SIGINT alındı, kapanış başlatılıyor"),
            Err(err) => warn!(error = %err, "CTRL+C sinyali dinlenemedi"),
        }
    };

    #[cfg(unix)]
    {
        let mut term_signal = match unix_signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(err) => {
                warn!(error = %err, "SIGTERM dinleyicisi kurulamadı");
                ctrl_c.await;
                return;
            }
        };

        tokio::select! {
            () = ctrl_c => (),
            () = async {
                term_signal.recv().await;
                info!("SIGTERM alındı, kapanış başlatılıyor");
            } => (),
        }
    }

    #[cfg(not(unix))]
    ctrl_c.await;
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
    let BeginAuthRequest {
        username,
        client_id,
        code_challenge,
        code_challenge_method,
    } = payload;

    if code_challenge_method != "S256" {
        return Err(ApiError::invalid_request(
            "PKCE yöntemi yalnızca S256 desteklenir",
        ));
    }
    if username.chars().any(char::is_control) {
        return Err(ApiError::invalid_request(
            "kullanıcı adı kontrol karakteri içeremez",
        ));
    }
    let sanitized_username = username.trim();
    if sanitized_username.is_empty() {
        return Err(ApiError::invalid_request("kullanıcı adı boş bırakılamaz"));
    }
    if client_id.chars().any(char::is_control) {
        return Err(ApiError::invalid_request(
            "client_id kontrol karakteri içeremez",
        ));
    }
    let sanitized_client_id = client_id.trim();
    if sanitized_client_id.is_empty() {
        return Err(ApiError::invalid_request("client_id boş bırakılamaz"));
    }
    if URL_SAFE_NO_PAD
        .decode(&code_challenge)
        .map(|bytes| bytes.len())
        .unwrap_or_default()
        != Sha256::output_size()
    {
        return Err(ApiError::invalid_request(
            "code_challenge değeri base64url kodlu SHA-256 çıktısı olmalıdır",
        ));
    }
    let auth_id = state
        .register_auth_request(
            sanitized_username.to_owned(),
            sanitized_client_id.to_owned(),
            code_challenge,
        )
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
struct RandomNumberQuery {
    #[serde(default = "default_min")]
    min: u64,
    #[serde(default = "default_max")]
    max: u64,
}

const fn default_min() -> u64 {
    0
}

const fn default_max() -> u64 {
    100
}

#[derive(Debug, Serialize)]
struct RandomNumberResponse {
    value: u64,
    min: u64,
    max: u64,
    entropy: String,
}

async fn random_number(
    State(state): State<Arc<ServerState>>,
    axum::extract::Query(params): axum::extract::Query<RandomNumberQuery>,
) -> Result<Json<RandomNumberResponse>, ApiError> {
    let min = params.min;
    let max = params.max;
    
    // Validation
    if min > max {
        return Err(ApiError::invalid_request(
            "min değeri max değerinden büyük olamaz",
        ));
    }
    
    if max > u64::MAX / 2 {
        return Err(ApiError::invalid_request(
            "max değeri çok büyük (güvenlik limiti: u64::MAX/2)",
        ));
    }
    
    let (value, entropy) = state.random_value_with_proof(min, max);
    Ok(Json(RandomNumberResponse {
        value,
        min,
        max,
        entropy: hex_encode(entropy),
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

#[derive(Debug, Serialize)]
struct TransparencyRecordBody {
    sequence: u64,
    timestamp: u64,
    key_id: String,
    action: String,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness: Option<String>,
    event_hash: String,
    previous_hash: String,
    tree_hash: String,
}

impl From<TransparencyRecord> for TransparencyRecordBody {
    fn from(record: TransparencyRecord) -> Self {
        let TransparencyRecord {
            sequence,
            timestamp,
            event,
            event_hash,
            previous_hash,
            tree_hash,
        } = record;
        let witness = event.witness.map(|bytes| STANDARD.encode(bytes));
        Self {
            sequence,
            timestamp,
            key_id: event.key_id,
            action: event.action.to_string(),
            public_key: STANDARD.encode(&event.public_key),
            note: event.note,
            witness,
            event_hash: hex_encode(event_hash),
            previous_hash: hex_encode(previous_hash),
            tree_hash: hex_encode(tree_hash),
        }
    }
}

#[derive(Debug, Serialize)]
struct TransparencyResponse {
    domain: String,
    tree_head: String,
    latest_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    transcript_hash: Option<String>,
    records: Vec<TransparencyRecordBody>,
}

impl TransparencyResponse {
    fn from_snapshot(snapshot: TransparencyTreeSnapshot) -> Result<Self, ApiError> {
        let latest_sequence = snapshot.latest_sequence();
        let transcript_hash = snapshot
            .transcript_hash()
            .map_err(|err| {
                ApiError::server_error(
                    format!("Şeffaflık transkript karması doğrulanamadı: {err}",),
                )
            })?
            .map(hex_encode);
        let records = snapshot
            .records
            .into_iter()
            .map(TransparencyRecordBody::from)
            .collect();
        Ok(Self {
            domain: snapshot.domain,
            tree_head: hex_encode(snapshot.head),
            latest_sequence,
            transcript_hash,
            records,
        })
    }
}

async fn transparency(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<LedgerTransparencySnapshot>, ApiError> {
    let snapshot = state
        .transparency_ledger_snapshot()
        .await
        .map_err(|err| ApiError::server_error(format!("Şeffaflık günlüğü alınamadı: {err}")))?;
    Ok(Json(snapshot))
}

async fn transparency_tree(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<TransparencyResponse>, ApiError> {
    let snapshot = state.transparency_tree_snapshot().await;
    let response = TransparencyResponse::from_snapshot(snapshot)?;
    Ok(Json(response))
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
    let mdm_devices = state
        .registered_device_count()
        .map_err(|err| ApiError::server_error(format!("Metrik hesaplanamadı: {err}")))?;
    let body = format!(
        "# HELP aunsorm_pending_auth_requests Bekleyen PKCE yetkilendirme istekleri\n# TYPE aunsorm_pending_auth_requests gauge\naunsorm_pending_auth_requests {pending}\n# HELP aunsorm_active_tokens Aktif erişim belirteci sayısı\n# TYPE aunsorm_active_tokens gauge\naunsorm_active_tokens {active}\n# HELP aunsorm_sfu_contexts Aktif SFU oturum bağlamı sayısı\n# TYPE aunsorm_sfu_contexts gauge\naunsorm_sfu_contexts {sfu_contexts}\n# HELP aunsorm_mdm_registered_devices Kayıtlı MDM cihazı sayısı\n# TYPE aunsorm_mdm_registered_devices gauge\naunsorm_mdm_registered_devices {mdm_devices}\n"
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
struct RegisterDeviceRequest {
    device_id: String,
    owner: String,
    platform: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeviceEnrollmentResponse {
    device: DeviceRecord,
    policy: PolicyDocument,
    certificate: DeviceCertificatePlan,
}

async fn register_device(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<RegisterDeviceRequest>,
) -> Result<Json<DeviceEnrollmentResponse>, ApiError> {
    if payload.device_id.trim().is_empty() {
        return Err(ApiError::invalid_request("device_id boş olamaz"));
    }
    if payload.owner.trim().is_empty() {
        return Err(ApiError::invalid_request("owner boş olamaz"));
    }
    let platform = DevicePlatform::from_str(&payload.platform)
        .map_err(|err| ApiError::invalid_request(format!("platform değeri geçersiz: {err}")))?;
    let enrollment = EnrollmentRequest {
        device_id: payload.device_id,
        owner: payload.owner,
        display_name: payload.display_name,
        platform: platform.clone(),
    };
    let device = state
        .mdm_directory()
        .register_device(enrollment)
        .map_err(|err| match err {
            MdmError::AlreadyRegistered(id) => {
                ApiError::invalid_request(format!("cihaz zaten kayıtlı: {id}"))
            }
            MdmError::InvalidIdentifier(field) => {
                ApiError::invalid_request(format!("{field} değeri geçersiz"))
            }
            other => ApiError::server_error(format!("MDM kaydı tamamlanamadı: {other}")),
        })?;
    let policy = state
        .mdm_directory()
        .policy(&platform)
        .map_err(|err| ApiError::server_error(format!("MDM politikası okunamadı: {err}")))?
        .ok_or_else(|| ApiError::server_error("İlgili platform için politika bulunamadı"))?;
    let certificate = state
        .mdm_directory()
        .device_certificate_plan(&device.device_id)
        .map_err(|err| ApiError::server_error(format!("Sertifika planı hesaplanamadı: {err}")))?
        .ok_or_else(|| ApiError::server_error("Sertifika planı hesaplanamadı"))?;
    Ok(Json(DeviceEnrollmentResponse {
        device,
        policy,
        certificate,
    }))
}

async fn fetch_policy(
    Path(platform): Path<String>,
    State(state): State<Arc<ServerState>>,
) -> Result<Json<PolicyDocument>, ApiError> {
    let platform = DevicePlatform::from_str(&platform)
        .map_err(|err| ApiError::invalid_request(format!("platform değeri geçersiz: {err}")))?;
    let policy = state
        .mdm_directory()
        .policy(&platform)
        .map_err(|err| ApiError::server_error(format!("MDM politikası okunamadı: {err}")))?
        .ok_or_else(|| ApiError::not_found("Politika bulunamadı"))?;
    Ok(Json(policy))
}

async fn fetch_certificate_plan(
    Path(device_id): Path<String>,
    State(state): State<Arc<ServerState>>,
) -> Result<Json<DeviceCertificatePlan>, ApiError> {
    let trimmed = device_id.trim();
    if trimmed.is_empty() {
        return Err(ApiError::invalid_request("device_id boş olamaz"));
    }
    let plan = state
        .mdm_directory()
        .device_certificate_plan(trimmed)
        .map_err(|err| ApiError::server_error(format!("Sertifika planı hesaplanamadı: {err}")))?
        .ok_or_else(|| ApiError::not_found("Cihaz kaydı bulunamadı"))?;
    Ok(Json(plan))
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

// ========================================================================
// ID GENERATION HANDLERS (v0.4.5)
// ========================================================================

/// POST /id/generate request payload
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerateIdRequest {
    /// Namespace (optional, default: from env or "aunsorm")
    #[serde(default)]
    namespace: Option<String>,
}

/// POST /id/generate response
#[derive(Debug, Serialize)]
struct GenerateIdResponse {
    /// Generated ID string
    id: String,
    /// Namespace used
    namespace: String,
    /// HEAD prefix (8 hex chars)
    head_prefix: String,
    /// Full fingerprint (20 hex chars)
    fingerprint: String,
    /// Timestamp in microseconds
    timestamp_micros: u64,
    /// Atomic counter value
    counter: u64,
}

/// POST /id/parse request payload
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParseIdRequest {
    /// ID string to parse
    id: String,
}

/// POST /id/parse response
#[derive(Debug, Serialize)]
struct ParseIdResponse {
    /// Original ID string
    id: String,
    /// Namespace
    namespace: String,
    /// HEAD prefix (8 hex chars)
    head_prefix: String,
    /// Full fingerprint (20 hex chars)
    fingerprint: String,
    /// Timestamp in microseconds
    timestamp_micros: u64,
    /// Atomic counter value
    counter: u64,
    /// Validation status
    valid: bool,
}

/// POST /id/verify-head request payload
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyHeadRequest {
    /// ID string to verify
    id: String,
    /// Git HEAD SHA to verify against
    head: String,
}

/// POST /id/verify-head response
#[derive(Debug, Serialize)]
struct VerifyHeadResponse {
    /// ID string
    id: String,
    /// HEAD provided
    head: String,
    /// Whether the ID matches the HEAD
    matches: bool,
    /// ID fingerprint (for debugging)
    fingerprint: String,
}

/// POST /id/generate handler
async fn generate_id(
    State(_state): State<Arc<ServerState>>,
    Json(payload): Json<GenerateIdRequest>,
) -> Result<Json<GenerateIdResponse>, ApiError> {
    // Try to create generator from environment
    let generator = if let Some(namespace) = payload.namespace {
        HeadIdGenerator::from_env()
            .and_then(|_gen| {
                // Get HEAD from generator, reconstruct with custom namespace
                let head = std::env::var("AUNSORM_HEAD")
                    .or_else(|_| std::env::var("GITHUB_SHA"))
                    .or_else(|_| std::env::var("GIT_COMMIT"))
                    .or_else(|_| std::env::var("CI_COMMIT_SHA"))
                    .or_else(|_| std::env::var("VERGEN_GIT_SHA"))
                    .map_err(|_| IdError::MissingHead)?;
                HeadIdGenerator::with_namespace(head, namespace)
            })
            .map_err(|e| {
                ApiError::server_error(format!(
                    "ID generator oluşturulamadı: {}. Lütfen AUNSORM_HEAD veya GITHUB_SHA environment variable'ını ayarlayın.",
                    e
                ))
            })?
    } else {
        HeadIdGenerator::from_env().map_err(|e| {
            ApiError::server_error(format!(
                "ID generator oluşturulamadı: {}. Lütfen AUNSORM_HEAD veya GITHUB_SHA environment variable'ını ayarlayın.",
                e
            ))
        })?
    };

    // Generate ID
    let id = generator.next_id().map_err(|e| {
        ApiError::server_error(format!("ID üretilemedi: {}", e))
    })?;

    Ok(Json(GenerateIdResponse {
        id: id.as_str().to_owned(),
        namespace: id.namespace().to_owned(),
        head_prefix: id.head_prefix(),
        fingerprint: id.fingerprint_hex(),
        timestamp_micros: id.timestamp_micros(),
        counter: id.counter(),
    }))
}

/// POST /id/parse handler
async fn parse_id(
    State(_state): State<Arc<ServerState>>,
    Json(payload): Json<ParseIdRequest>,
) -> Result<Json<ParseIdResponse>, ApiError> {
    if payload.id.trim().is_empty() {
        return Err(ApiError::invalid_request("id boş olamaz"));
    }

    match parse_head_id(&payload.id) {
        Ok(parsed) => Ok(Json(ParseIdResponse {
            id: parsed.as_str().to_owned(),
            namespace: parsed.namespace().to_owned(),
            head_prefix: parsed.head_prefix(),
            fingerprint: parsed.fingerprint_hex(),
            timestamp_micros: parsed.timestamp_micros(),
            counter: parsed.counter(),
            valid: true,
        })),
        Err(e) => Err(ApiError::invalid_request(format!(
            "ID parse edilemedi: {}",
            e
        ))),
    }
}

/// POST /id/verify-head handler
async fn verify_head(
    State(_state): State<Arc<ServerState>>,
    Json(payload): Json<VerifyHeadRequest>,
) -> Result<Json<VerifyHeadResponse>, ApiError> {
    if payload.id.trim().is_empty() {
        return Err(ApiError::invalid_request("id boş olamaz"));
    }
    if payload.head.trim().is_empty() {
        return Err(ApiError::invalid_request("head boş olamaz"));
    }

    let parsed = parse_head_id(&payload.id).map_err(|e| {
        ApiError::invalid_request(format!("ID parse edilemedi: {}", e))
    })?;

    let matches = parsed.matches_head(&payload.head).map_err(|e| {
        ApiError::invalid_request(format!("HEAD doğrulanamadı: {}", e))
    })?;

    Ok(Json(VerifyHeadResponse {
        id: parsed.as_str().to_owned(),
        head: payload.head,
        matches,
        fingerprint: parsed.fingerprint_hex(),
    }))
}
