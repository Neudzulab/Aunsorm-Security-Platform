#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{net::TcpListener, signal};
use tracing::{info, warn};
use uuid::Uuid;

use aunsorm_jwt::{
    Audience, Claims, Ed25519KeyPair, JtiStore, Jwks, JwtError, JwtSigner, JwtVerifier,
    VerificationOptions,
};

const DEFAULT_CODE_EXPIRATION: Duration = Duration::from_secs(300);
const METRIC_PREFIX: &str = "aunsorm_server";

/// Sunucu yapılandırması.
#[derive(Clone)]
pub struct ServerConfig {
    issuer: String,
    audience: String,
    token_ttl: Duration,
    strict: bool,
    store: JtiStoreConfig,
    signing_key: Ed25519KeyPair,
}

impl ServerConfig {
    /// Yeni bir yapılandırma oluşturur.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(
        issuer: String,
        audience: String,
        token_ttl: Duration,
        strict: bool,
        store: JtiStoreConfig,
        signing_key: Ed25519KeyPair,
    ) -> Self {
        Self {
            issuer,
            audience,
            token_ttl,
            strict,
            store,
            signing_key,
        }
    }

    /// Ortam değişkenlerinden yapılandırma üretir.
    ///
    /// Desteklenen değişkenler:
    /// * `AUNSORM_ISSUER`
    /// * `AUNSORM_AUDIENCE`
    /// * `AUNSORM_TOKEN_TTL` (saniye cinsinden)
    /// * `AUNSORM_STRICT`
    /// * `AUNSORM_JTI_DB`
    ///
    /// # Errors
    ///
    /// `AUNSORM_TOKEN_TTL` geçersiz bir sayı içerirse veya JTI store açılışı
    /// başarısız olursa `ServerError` döner.
    pub fn from_env(signing_key: Ed25519KeyPair) -> Result<Self, ServerError> {
        let issuer =
            std::env::var("AUNSORM_ISSUER").unwrap_or_else(|_| "https://aunsorm.local".to_string());
        let audience =
            std::env::var("AUNSORM_AUDIENCE").unwrap_or_else(|_| "aunsorm-cli".to_string());
        let token_ttl = match std::env::var("AUNSORM_TOKEN_TTL") {
            Ok(value) => parse_duration_seconds(&value)?,
            Err(_) => Duration::from_secs(3600),
        };
        let strict = read_bool_env("AUNSORM_STRICT");
        let store = std::env::var("AUNSORM_JTI_DB")
            .ok()
            .filter(|value| !value.is_empty())
            .map_or(JtiStoreConfig::InMemory, |path| {
                JtiStoreConfig::Sqlite(path.into())
            });
        Ok(Self::new(
            issuer,
            audience,
            token_ttl,
            strict,
            store,
            signing_key,
        ))
    }
}

/// JTI store seçenekleri.
#[derive(Clone)]
pub enum JtiStoreConfig {
    InMemory,
    Sqlite(std::path::PathBuf),
}

impl JtiStoreConfig {
    fn build_store(&self) -> Result<Arc<dyn JtiStore>, ServerError> {
        match self {
            Self::InMemory => Ok(Arc::new(aunsorm_jwt::InMemoryJtiStore::default())),
            Self::Sqlite(path) => {
                let store = aunsorm_jwt::SqliteJtiStore::open(path)?;
                Ok(Arc::new(store))
            }
        }
    }
}

/// Sunucu hataları.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("jwt error: {0}")]
    Jwt(#[from] JwtError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// API hata türü.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
    code: &'static str,
}

impl ApiError {
    fn with_code(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            code,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.code,
            "message": self.message,
        }));
        (self.status, body).into_response()
    }
}

/// Router oluşturur.
///
/// # Errors
///
/// Durum nesnesi veya JTI store hazırlanırken hata oluşursa `ServerError` döner.
pub fn router(config: ServerConfig) -> Result<Router, ServerError> {
    let state = ServerState::new(config)?;
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/oauth/begin-auth", post(begin_auth))
        .route("/oauth/token", post(token))
        .route("/oauth/introspect", post(introspect))
        .route("/oauth/jwks.json", get(jwks))
        .layer(Extension(state));
    Ok(app)
}

/// Axum sunucusunu başlatır ve Ctrl+C bekler.
///
/// # Errors
///
/// TCP soketi bağlanamazsa veya Axum çalışma zamanı hata üretirse `ServerError`
/// döner.
pub async fn serve(config: ServerConfig, addr: SocketAddr) -> Result<(), ServerError> {
    let app = router(config)?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "starting aunsorm-server");
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    info!(%addr, "aunsorm-server shutdown");
    Ok(())
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}

#[derive(Clone)]
pub struct ServerState {
    inner: Arc<InnerState>,
}

impl ServerState {
    fn new(config: ServerConfig) -> Result<Self, ServerError> {
        let signer = JwtSigner::new(config.signing_key.clone());
        let jwks = Jwks {
            keys: vec![config.signing_key.to_jwk()],
        };
        let verifier = JwtVerifier::from_jwks(&jwks)?;
        let store = config.store.build_store()?;
        Ok(Self {
            inner: Arc::new(InnerState {
                issuer: config.issuer,
                audience: config.audience,
                token_ttl: config.token_ttl,
                strict: config.strict,
                signer,
                verifier,
                jwks,
                store,
                pending: Mutex::new(BTreeMap::new()),
                tokens: Mutex::new(BTreeMap::new()),
                metrics: Metrics::default(),
            }),
        })
    }

    fn strict(&self) -> bool {
        self.inner.strict
    }

    fn strict_error(&self, message: impl Into<String>) -> ApiError {
        self.request_error("strict_violation", message)
    }

    fn request_error(&self, code: &'static str, message: impl Into<String>) -> ApiError {
        if self.strict() {
            ApiError::with_code(StatusCode::UNPROCESSABLE_ENTITY, code, message)
        } else {
            ApiError::with_code(StatusCode::BAD_REQUEST, code, message)
        }
    }

    fn record_metric(&self, name: MetricKind) {
        self.inner.metrics.record(name);
    }

    fn purge_expired(&self) -> Result<(), ApiError> {
        let now = SystemTime::now();
        self.inner.store.purge_expired(now).map_err(|err| {
            ApiError::with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "jti_error",
                err.to_string(),
            )
        })?;
        let mut guard = self.inner.tokens.lock();
        let before = guard.len();
        guard.retain(|_, record| record.expires_at > now);
        let removed = before - guard.len();
        drop(guard);
        if removed > 0 {
            self.inner.metrics.decrement_active_by(removed as u64);
        }
        Ok(())
    }
}

struct InnerState {
    issuer: String,
    audience: String,
    token_ttl: Duration,
    strict: bool,
    signer: JwtSigner,
    verifier: JwtVerifier,
    jwks: Jwks,
    store: Arc<dyn JtiStore>,
    pending: Mutex<BTreeMap<String, PendingAuth>>,
    tokens: Mutex<BTreeMap<String, TokenRecord>>,
    metrics: Metrics,
}

#[derive(Default)]
struct Metrics {
    begin_auth_total: std::sync::atomic::AtomicU64,
    token_total: std::sync::atomic::AtomicU64,
    introspect_total: std::sync::atomic::AtomicU64,
    active_tokens: std::sync::atomic::AtomicU64,
}

struct MetricsSnapshot {
    begin_auth_total: u64,
    token_total: u64,
    introspect_total: u64,
    active_tokens: u64,
}

#[derive(Copy, Clone)]
enum MetricKind {
    BeginAuth,
    Token,
    Introspect,
}

impl Metrics {
    fn record(&self, kind: MetricKind) {
        use std::sync::atomic::Ordering::Relaxed;
        match kind {
            MetricKind::BeginAuth => {
                self.begin_auth_total.fetch_add(1, Relaxed);
            }
            MetricKind::Token => {
                self.token_total.fetch_add(1, Relaxed);
            }
            MetricKind::Introspect => {
                self.introspect_total.fetch_add(1, Relaxed);
            }
        }
    }

    fn increment_active(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.active_tokens.fetch_add(1, Relaxed);
    }

    fn decrement_active(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.active_tokens.fetch_sub(1, Relaxed);
    }

    fn decrement_active_by(&self, count: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        self.active_tokens.fetch_sub(count, Relaxed);
    }

    fn snapshot(&self) -> MetricsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        MetricsSnapshot {
            begin_auth_total: self.begin_auth_total.load(Relaxed),
            token_total: self.token_total.load(Relaxed),
            introspect_total: self.introspect_total.load(Relaxed),
            active_tokens: self.active_tokens.load(Relaxed),
        }
    }
}

#[derive(Clone)]
struct PendingAuth {
    client_id: String,
    subject: String,
    scope: String,
    code_challenge: String,
    expires_at: SystemTime,
}

#[derive(Clone)]
struct TokenRecord {
    claims: Claims,
    scope: String,
    expires_at: SystemTime,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    strict: bool,
}

async fn health(Extension(state): Extension<ServerState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        strict: state.strict(),
    })
}

async fn metrics(Extension(state): Extension<ServerState>) -> Response {
    let snapshot = state.inner.metrics.snapshot();
    let body = format!(
        "# TYPE {METRIC_PREFIX}_begin_auth_total counter\n{METRIC_PREFIX}_begin_auth_total {}\n# TYPE {METRIC_PREFIX}_token_total counter\n{METRIC_PREFIX}_token_total {}\n# TYPE {METRIC_PREFIX}_introspect_total counter\n{METRIC_PREFIX}_introspect_total {}\n# TYPE {METRIC_PREFIX}_active_tokens gauge\n{METRIC_PREFIX}_active_tokens {}\n",
        snapshot.begin_auth_total,
        snapshot.token_total,
        snapshot.introspect_total,
        snapshot.active_tokens,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(Body::from(body))
        .unwrap()
}

#[derive(Deserialize)]
struct BeginAuthRequest {
    client_id: String,
    subject: String,
    scope: String,
    code_challenge: String,
    #[serde(default = "default_code_challenge_method")]
    code_challenge_method: String,
}

fn default_code_challenge_method() -> String {
    "S256".to_string()
}

#[derive(Debug, Serialize)]
struct BeginAuthResponse {
    authorization_code: String,
    expires_in: u64,
    strict: bool,
}

async fn begin_auth(
    Extension(state): Extension<ServerState>,
    Json(payload): Json<BeginAuthRequest>,
) -> Result<Json<BeginAuthResponse>, ApiError> {
    state.record_metric(MetricKind::BeginAuth);
    if payload.code_challenge_method.to_uppercase() != "S256" {
        return Err(state.strict_error("PKCE S256 zorunludur"));
    }
    validate_scope(&payload.scope, state.strict())?;
    if payload.code_challenge.len() < 32 {
        return Err(state.strict_error("code_challenge çok kısa"));
    }
    state.purge_expired()?;
    let expires_at = SystemTime::now() + DEFAULT_CODE_EXPIRATION;
    let code = Uuid::new_v4().to_string();
    let request = PendingAuth {
        client_id: payload.client_id,
        subject: payload.subject,
        scope: payload.scope,
        code_challenge: payload.code_challenge,
        expires_at,
    };
    let mut guard = state.inner.pending.lock();
    guard.insert(code.clone(), request);
    drop(guard);
    Ok(Json(BeginAuthResponse {
        authorization_code: code,
        expires_in: DEFAULT_CODE_EXPIRATION.as_secs(),
        strict: state.strict(),
    }))
}

fn validate_scope(scope: &str, strict: bool) -> Result<(), ApiError> {
    if scope.trim().is_empty() {
        let err = ApiError::with_code(
            if strict {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::BAD_REQUEST
            },
            "invalid_scope",
            "scope boş olamaz",
        );
        return Err(err);
    }
    let parts: BTreeSet<&str> = scope.split_whitespace().collect();
    if strict && parts.len() != scope.split_whitespace().count() {
        return Err(ApiError::with_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_scope",
            "scope değerleri benzersiz olmalıdır",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct TokenRequest {
    client_id: String,
    authorization_code: String,
    code_verifier: String,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
}

async fn token(
    Extension(state): Extension<ServerState>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    state.record_metric(MetricKind::Token);
    state.purge_expired()?;
    if payload.code_verifier.len() < 43 {
        return Err(state.strict_error("code_verifier 43+ karakter olmalıdır"));
    }
    let mut guard = state.inner.pending.lock();
    let Some(entry) = guard.remove(&payload.authorization_code) else {
        return Err(state.request_error(
            "invalid_code",
            "authorization_code geçersiz veya süresi dolmuş",
        ));
    };
    drop(guard);
    if entry.client_id != payload.client_id {
        return Err(state.strict_error("client_id eşleşmiyor"));
    }
    if entry.expires_at < SystemTime::now() {
        return Err(state.request_error("expired_code", "authorization_code süresi dolmuş"));
    }
    if !verify_pkce(&payload.code_verifier, &entry.code_challenge) {
        return Err(ApiError::with_code(
            StatusCode::UNAUTHORIZED,
            "pkce_mismatch",
            "code_verifier doğrulanamadı",
        ));
    }
    let scope = entry.scope;
    let mut claims = Claims::new();
    claims.issuer = Some(state.inner.issuer.clone());
    claims.subject = Some(entry.subject);
    claims.audience = Some(Audience::Single(state.inner.audience.clone()));
    claims.set_issued_now();
    claims.set_expiration_from_now(state.inner.token_ttl);
    claims.extra.insert("scope".into(), json!(scope));
    claims.ensure_jwt_id();
    state
        .inner
        .store
        .check_and_insert(
            claims
                .jwt_id
                .as_deref()
                .ok_or_else(|| state.strict_error("jti üretilemedi"))?,
            claims.expiration,
        )
        .map_err(|err| {
            ApiError::with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "jti_error",
                err.to_string(),
            )
        })?;
    let token = state.inner.signer.sign(&claims).map_err(|err| {
        ApiError::with_code(
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing_failed",
            err.to_string(),
        )
    })?;
    let expires_in = state.inner.token_ttl.as_secs();
    let record = TokenRecord {
        expires_at: SystemTime::now() + state.inner.token_ttl,
        scope: scope.clone(),
        claims: claims.clone(),
    };
    state.inner.tokens.lock().insert(token.clone(), record);
    state.inner.metrics.increment_active();
    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in,
        scope,
    }))
}

fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    let digest = Sha256::digest(verifier.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    encoded == challenge
}

#[derive(Deserialize)]
struct IntrospectRequest {
    token: String,
}

#[derive(Serialize)]
struct IntrospectResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
}

async fn introspect(
    Extension(state): Extension<ServerState>,
    Json(payload): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, ApiError> {
    state.record_metric(MetricKind::Introspect);
    state.purge_expired()?;
    let token = payload.token;
    let now = SystemTime::now();
    let (maybe_record, expired) = {
        let mut guard = state.inner.tokens.lock();
        let record = guard.get(&token).cloned();
        let expired = record.as_ref().is_some_and(|rec| rec.expires_at <= now);
        if expired {
            guard.remove(&token);
            state.inner.metrics.decrement_active();
        }
        drop(guard);
        (record, expired)
    };
    let result = if let Some(record) = maybe_record {
        Json(IntrospectResponse {
            active: true,
            scope: Some(record.scope),
            sub: record.claims.subject.clone(),
            exp: record
                .claims
                .expiration
                .and_then(|ts| unix_seconds(ts).ok()),
            iss: record.claims.issuer.clone(),
            aud: record.claims.audience.and_then(|aud| match aud {
                Audience::Single(value) => Some(value),
                Audience::Multiple(list) => list.first().cloned(),
            }),
        })
    } else if expired {
        Json(IntrospectResponse {
            active: false,
            scope: None,
            sub: None,
            exp: None,
            iss: None,
            aud: None,
        })
    } else {
        match state.inner.verifier.verify(
            &token,
            &VerificationOptions {
                issuer: Some(state.inner.issuer.clone()),
                audience: Some(state.inner.audience.clone()),
                require_jti: true,
                now: Some(now),
                ..VerificationOptions::default()
            },
        ) {
            Ok(claims) => Json(IntrospectResponse {
                active: true,
                scope: claims
                    .extra
                    .get("scope")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned),
                sub: claims.subject,
                exp: claims.expiration.and_then(|ts| unix_seconds(ts).ok()),
                iss: claims.issuer,
                aud: claims.audience.and_then(|aud| match aud {
                    Audience::Single(value) => Some(value),
                    Audience::Multiple(list) => list.first().cloned(),
                }),
            }),
            Err(err) => {
                warn!(error = %err, "introspect verification failed");
                Json(IntrospectResponse {
                    active: false,
                    scope: None,
                    sub: None,
                    exp: None,
                    iss: None,
                    aud: None,
                })
            }
        }
    };
    Ok(result)
}

async fn jwks(Extension(state): Extension<ServerState>) -> Json<Jwks> {
    Json(state.inner.jwks.clone())
}

fn parse_duration_seconds(value: &str) -> Result<Duration, ServerError> {
    let seconds: u64 = value
        .parse()
        .map_err(|_| ServerError::Config(format!("AUNSORM_TOKEN_TTL invalid: {value}")))?;
    Ok(Duration::from_secs(seconds))
}

fn read_bool_env(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true")),
        Some(true)
    )
}

fn unix_seconds(time: SystemTime) -> Result<u64, JwtError> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .map_err(|_| JwtError::TimeConversion)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oauth_flow_succeeds() {
        let key = Ed25519KeyPair::generate("test").expect("key generation");
        let config = ServerConfig::new(
            "https://issuer".into(),
            "aunsorm-client".into(),
            Duration::from_secs(600),
            false,
            JtiStoreConfig::InMemory,
            key,
        );
        let state = ServerState::new(config).expect("state");
        let code_verifier = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let begin_payload = BeginAuthRequest {
            client_id: "cli".into(),
            subject: "user".into(),
            scope: "openid profile".into(),
            code_challenge: pkce_challenge(code_verifier),
            code_challenge_method: "S256".into(),
        };
        let begin_response = begin_auth(Extension(state.clone()), Json(begin_payload))
            .await
            .expect("begin auth ok")
            .0;
        let token_payload = TokenRequest {
            client_id: "cli".into(),
            authorization_code: begin_response.authorization_code,
            code_verifier: code_verifier.into(),
        };
        let token_response = token(Extension(state.clone()), Json(token_payload))
            .await
            .expect("token ok")
            .0;
        let access_token = token_response.access_token.clone();
        let introspect_payload = IntrospectRequest {
            token: access_token,
        };
        let introspect_response = introspect(Extension(state), Json(introspect_payload))
            .await
            .expect("introspect ok")
            .0;
        assert!(introspect_response.active);
        assert_eq!(introspect_response.scope.as_deref(), Some("openid profile"));
    }

    #[tokio::test]
    async fn strict_mode_rejects_missing_pkce() {
        let key = Ed25519KeyPair::generate("test").expect("key generation");
        let config = ServerConfig::new(
            "https://issuer".into(),
            "aunsorm-client".into(),
            Duration::from_secs(600),
            true,
            JtiStoreConfig::InMemory,
            key,
        );
        let state = ServerState::new(config).expect("state");
        let payload = BeginAuthRequest {
            client_id: "cli".into(),
            subject: "user".into(),
            scope: "openid".into(),
            code_challenge: "short".into(),
            code_challenge_method: "S256".into(),
        };
        let err = begin_auth(Extension(state), Json(payload))
            .await
            .unwrap_err();
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    fn pkce_challenge(verifier: &str) -> String {
        let digest = Sha256::digest(verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }
}
