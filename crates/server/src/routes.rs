use std::borrow::{Cow, ToOwned};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
#[cfg(feature = "http3-experimental")]
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use hex::{decode_to_slice, encode as hex_encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;
use tokio::signal;
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tracing::{info, warn};

use aunsorm_acme::AcmeJws;
use aunsorm_core::transparency::TransparencyRecord;
use aunsorm_jwt::{Audience, Claims, JwtError, VerificationOptions};
use aunsorm_mdm::{
    DeviceCertificatePlan, DevicePlatform, DeviceRecord, EnrollmentRequest, MdmError,
    PolicyDocument,
};

use crate::acme::{
    AcmeProblem, FinalizeOrderOutcome, NewAccountOutcome, NewOrderOutcome, OrderLookupOutcome,
    RevokeCertOutcome,
};
use crate::config::ServerConfig;
use crate::error::{ApiError, ServerError};
use crate::fabric::{FabricDidError, FabricDidVerificationRequest};
#[cfg(feature = "http3-experimental")]
use crate::quic::datagram::{DatagramChannel, MAX_PAYLOAD_BYTES};
#[cfg(feature = "http3-experimental")]
use crate::quic::{build_alt_svc_header_value, spawn_http3_poc, ALT_SVC_MAX_AGE};
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
        .route("/http3/capabilities", get(http3_capabilities))
        // ID Generation endpoints (v0.4.5)
        .route("/id/generate", post(generate_id))
        .route("/id/parse", post(parse_id))
        .route("/id/verify-head", post(verify_head))
        // ACME protocol endpoints
        .route("/acme/directory", get(acme_directory))
        .route("/acme/new-nonce", get(acme_new_nonce))
        .route("/acme/new-account", post(acme_new_account))
        .route("/acme/new-order", post(acme_new_order))
        .route("/acme/account/:account_id", post(acme_account_lookup))
        .route("/acme/order/:order_id", post(acme_order_status))
        .route("/acme/order/:order_id/finalize", post(acme_finalize_order))
        .route("/acme/cert/:order_id", get(acme_get_certificate))
        .route("/acme/revoke-cert", post(acme_revoke_certificate))
        // Security endpoints (media token generation)
        .route("/security/generate-media-token", post(generate_media_token))
        // Blockchain DID verification PoC
        .route("/blockchain/fabric/did/verify", post(verify_fabric_did));

    #[cfg(feature = "http3-experimental")]
    let router = {
        let port = state.listen_port();
        let header_value =
            build_alt_svc_header_value(port).expect("Alt-Svc başlığı oluşturulamadı");
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

#[derive(Debug, Deserialize)]
struct BeginAuthRequest {
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    code_challenge: String,
    code_challenge_method: String,

    // Optional subject hint (not for authentication)
    #[serde(default)]
    subject: Option<String>,
}

#[derive(Debug, Serialize)]
struct BeginAuthResponse {
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    expires_in: u64,
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
        return Err(ApiError::invalid_scope("scope boş olamaz"));
    }
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for token in trimmed.split_whitespace() {
        if token.chars().any(char::is_control) {
            return Err(ApiError::invalid_scope("scope kontrol karakteri içeremez"));
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

async fn begin_auth(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<BeginAuthRequest>,
) -> Result<Json<BeginAuthResponse>, ApiError> {
    let BeginAuthRequest {
        client_id,
        redirect_uri,
        state: client_state,
        scope,
        code_challenge,
        code_challenge_method,
        subject,
    } = payload;

    // RFC 7636: Validate PKCE method
    if code_challenge_method != "S256" {
        return Err(ApiError::invalid_request(
            "PKCE yöntemi yalnızca S256 desteklenir",
        ));
    }

    // Validate client_id
    if client_id.chars().any(char::is_control) {
        return Err(ApiError::invalid_request(
            "client_id kontrol karakteri içeremez",
        ));
    }
    let sanitized_client_id = client_id.trim();
    if sanitized_client_id.is_empty() {
        return Err(ApiError::invalid_request("client_id boş bırakılamaz"));
    }
    let client = state
        .oauth_client(sanitized_client_id)
        .ok_or_else(|| ApiError::invalid_client("client_id kayıtlı değil"))?;

    // RFC 6749 §3.1.2: Validate redirect_uri (HTTPS required, localhost HTTP allowed)
    let redirect_uri_trimmed = redirect_uri.trim();
    if redirect_uri_trimmed.is_empty() {
        return Err(ApiError::invalid_redirect_uri("redirect_uri gereklidir"));
    }

    // Basic URL validation (scheme check)
    if !redirect_uri_trimmed.starts_with("https://")
        && !redirect_uri_trimmed.starts_with("http://localhost")
        && !redirect_uri_trimmed.starts_with("http://127.0.0.1")
    {
        return Err(ApiError::invalid_redirect_uri(
            "redirect_uri HTTPS kullanmalıdır (localhost için HTTP izinli)",
        ));
    }

    if !client.allows_redirect(redirect_uri_trimmed) {
        return Err(ApiError::invalid_redirect_uri(
            "redirect_uri kayıtlı istemci için yetkili değil",
        ));
    }

    // Validate state if provided (should be opaque string, no control chars)
    if let Some(ref s) = client_state {
        if s.chars().any(char::is_control) {
            return Err(ApiError::invalid_request(
                "state kontrol karakteri içeremez",
            ));
        }
    }

    let normalized_scope = normalize_scope(scope.as_deref(), client.allowed_scopes())?;

    // Validate subject hint if provided
    let final_subject = if let Some(subj) = subject {
        if subj.chars().any(char::is_control) {
            return Err(ApiError::invalid_request(
                "subject kontrol karakteri içeremez",
            ));
        }
        let trimmed = subj.trim();
        if trimmed.is_empty() {
            return Err(ApiError::invalid_request("subject boş olamaz"));
        }
        trimmed.to_owned()
    } else {
        // Default subject if not provided
        format!("client:{sanitized_client_id}")
    };

    // Validate code_challenge
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

    // RFC 6749: Register authorization request
    let authorization_code = state
        .register_auth_request(
            final_subject,
            sanitized_client_id.to_owned(),
            redirect_uri_trimmed.to_owned(),
            client_state.clone(),
            normalized_scope,
            code_challenge,
        )
        .await;

    Ok(Json(BeginAuthResponse {
        code: authorization_code,
        state: client_state,
        expires_in: auth_ttl().as_secs(),
    }))
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    code_verifier: String,
    client_id: String,
    redirect_uri: String,
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
    // RFC 6749 §4.1.3: Validate grant_type
    if payload.grant_type != "authorization_code" {
        return Err(ApiError::invalid_request(
            "grant_type 'authorization_code' olmalıdır",
        ));
    }

    // RFC 7636 §4.1: Validate code_verifier length
    if payload.code_verifier.len() < 43 || payload.code_verifier.len() > 128 {
        return Err(ApiError::invalid_request(
            "code_verifier uzunluğu 43 ile 128 karakter arasında olmalıdır",
        ));
    }

    // Consume authorization code (single-use)
    let auth_request = state
        .consume_auth_request(&payload.code)
        .await
        .ok_or_else(|| {
            ApiError::invalid_grant("Yetkilendirme kodu bulunamadı veya süresi doldu")
        })?;

    // RFC 6749 §4.1.3: Validate client_id match
    if auth_request.client_id != payload.client_id {
        return Err(ApiError::invalid_client("client_id eşleşmiyor"));
    }

    // RFC 6749 §4.1.3: Validate redirect_uri match (CRITICAL for security)
    if auth_request.redirect_uri != payload.redirect_uri {
        return Err(ApiError::invalid_grant("redirect_uri eşleşmiyor"));
    }

    // RFC 7636 §4.6: Verify PKCE code_challenge
    let verifier_bytes = payload.code_verifier.as_bytes();
    let digest = Sha256::digest(verifier_bytes);
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    if challenge != auth_request.code_challenge {
        return Err(ApiError::invalid_grant("PKCE doğrulaması başarısız"));
    }

    // Generate JWT access token
    let mut claims = Claims::new();
    claims.subject = Some(auth_request.subject);
    claims.issuer = Some(state.issuer().to_owned());
    claims.audience = Some(Audience::Single(state.audience().to_owned()));
    claims.ensure_jwt_id();
    claims.set_issued_now();
    claims.set_expiration_from_now(state.token_ttl());

    // Add client_id to token claims
    claims
        .extra
        .insert("client_id".to_string(), Value::String(payload.client_id));

    // Add scope to token claims if provided
    if let Some(scope) = auth_request.scope {
        claims
            .extra
            .insert("scope".to_string(), Value::String(scope));
    }

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

const APPLICATION_JOSE_JSON: &str = "application/jose+json";

fn is_jose_content_type(headers: &axum::http::HeaderMap) -> bool {
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

fn apply_acme_headers(response: &mut Response, nonce: &str) {
    let replay_name = HeaderName::from_static("replay-nonce");
    let value = HeaderValue::from_str(nonce).expect("nonce header değeri geçerli olmalı");
    response.headers_mut().insert(replay_name, value);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn acme_problem_response(problem: &AcmeProblem, nonce: &str) -> Response {
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

async fn acme_directory(State(state): State<Arc<ServerState>>) -> Response {
    let service = state.acme();
    let document = service.directory_document();
    let nonce = service.issue_nonce().await;
    let mut response = (StatusCode::OK, Json(document)).into_response();
    apply_acme_headers(&mut response, &nonce);
    response
}

async fn acme_new_nonce(State(state): State<Arc<ServerState>>) -> Response {
    let service = state.acme();
    let nonce = service.issue_nonce().await;
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    apply_acme_headers(&mut response, &nonce);
    response
}

async fn acme_new_account(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
) -> Response {
    let service = state.acme();
    let (parts, body) = request.into_parts();
    if !is_jose_content_type(&parts.headers) {
        let nonce = service.issue_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.handle_new_account(jws).await {
        Ok(outcome) => {
            let nonce = service.issue_nonce().await;
            acme_account_response(outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.issue_nonce().await;
            acme_problem_response(&problem, &nonce)
        }
    }
}

async fn acme_new_order(State(state): State<Arc<ServerState>>, request: Request<Body>) -> Response {
    let service = state.acme();
    let (parts, body) = request.into_parts();
    if !is_jose_content_type(&parts.headers) {
        let nonce = service.issue_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.handle_new_order(jws).await {
        Ok(outcome) => {
            let nonce = service.issue_nonce().await;
            acme_order_response(outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.issue_nonce().await;
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
        let nonce = service.issue_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.handle_account_lookup(&account_id, jws).await {
        Ok(outcome) => {
            let nonce = service.issue_nonce().await;
            acme_account_response(outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.issue_nonce().await;
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
        let nonce = service.issue_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.handle_finalize_order(&order_id, jws).await {
        Ok(outcome) => {
            let nonce = service.issue_nonce().await;
            acme_finalize_response(outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.issue_nonce().await;
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
            let nonce = service.issue_nonce().await;
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
            let nonce = service.issue_nonce().await;
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
        let nonce = service.issue_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.revoke_certificate(jws).await {
        Ok(outcome) => {
            let nonce = service.issue_nonce().await;
            acme_revoke_response(&outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.issue_nonce().await;
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
        let nonce = service.issue_nonce().await;
        let problem =
            AcmeProblem::malformed("Content-Type application/jose+json olarak ayarlanmalıdır");
        return acme_problem_response(&problem, &nonce);
    }

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem = AcmeProblem::server_internal(format!("İstek gövdesi okunamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    let jws: AcmeJws = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            let nonce = service.issue_nonce().await;
            let problem =
                AcmeProblem::malformed(format!("ACME JWS gövdesi ayrıştırılamadı: {err}"));
            return acme_problem_response(&problem, &nonce);
        }
    };

    match service.handle_order_lookup(&order_id, jws).await {
        Ok(outcome) => {
            let nonce = service.issue_nonce().await;
            acme_order_status_response(outcome, &nonce)
        }
        Err(problem) => {
            let nonce = service.issue_nonce().await;
            acme_problem_response(&problem, &nonce)
        }
    }
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
            let scope = claims
                .extra
                .get("scope")
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
                scope,
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

#[cfg(all(test, feature = "http3-experimental"))]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use std::net::SocketAddr;
    use std::sync::OnceLock;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    use crate::config::{LedgerBackend, ServerConfig};

    const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";

    static ENV_GUARD: OnceLock<Mutex<()>> = OnceLock::new();

    fn build_test_state() -> Arc<ServerState> {
        let listen: SocketAddr = "127.0.0.1:9443".parse().expect("socket address");
        let key_pair =
            aunsorm_jwt::Ed25519KeyPair::generate("test-server").expect("key pair generation");
        let config = ServerConfig::new(
            listen,
            "https://aunsorm.test",
            "test-audience",
            Duration::from_secs(300),
            false,
            key_pair,
            LedgerBackend::Memory,
        )
        .expect("config is valid");
        Arc::new(ServerState::try_new(config).expect("state is constructed"))
    }

    #[tokio::test]
    async fn alt_svc_header_is_injected_for_http3_routes() {
        let state = build_test_state();
        let port = state.listen_port();
        let router = build_router(Arc::clone(&state));
        let response = router
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
        let router = build_router(Arc::clone(&state));
        let response = router
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

    #[tokio::test]
    async fn id_generate_honours_namespace_override() {
        let _guard = ENV_GUARD.get_or_init(|| Mutex::new(())).lock().await;
        let prev_head = std::env::var("AUNSORM_HEAD").ok();
        let prev_namespace = std::env::var("AUNSORM_ID_NAMESPACE").ok();

        std::env::set_var("AUNSORM_HEAD", HEAD);
        std::env::set_var("AUNSORM_ID_NAMESPACE", "default");

        let state = build_test_state();
        let router = build_router(Arc::clone(&state));

        let payload = serde_json::json!({ "namespace": "Ops/Delivery" });
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/id/generate")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(payload.to_string()))
            .expect("request is built");

        let response = router.oneshot(request).await.expect("request succeeds");
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collected");
        let generated: GenerateIdResponse = serde_json::from_slice(&body).expect("response parses");
        assert_eq!(generated.namespace, "ops-delivery");
        assert!(generated.id.starts_with("aid.ops-delivery."));
        let expected_prefix = HeadIdGenerator::with_namespace(HEAD, "ops-delivery")
            .expect("generator")
            .head_prefix()
            .to_owned();
        assert_eq!(generated.head_prefix, expected_prefix);

        if let Some(value) = prev_head {
            std::env::set_var("AUNSORM_HEAD", value);
        } else {
            std::env::remove_var("AUNSORM_HEAD");
        }
        if let Some(value) = prev_namespace {
            std::env::set_var("AUNSORM_ID_NAMESPACE", value);
        } else {
            std::env::remove_var("AUNSORM_ID_NAMESPACE");
        }
    }

    #[tokio::test]
    async fn id_generate_rejects_invalid_namespace() {
        let _guard = ENV_GUARD.get_or_init(|| Mutex::new(())).lock().await;
        let prev_head = std::env::var("AUNSORM_HEAD").ok();
        let prev_namespace = std::env::var("AUNSORM_ID_NAMESPACE").ok();

        std::env::set_var("AUNSORM_HEAD", HEAD);
        std::env::remove_var("AUNSORM_ID_NAMESPACE");

        let state = build_test_state();
        let router = build_router(state);

        let payload = serde_json::json!({ "namespace": "***" });
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/id/generate")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(payload.to_string()))
            .expect("request is built");

        let response = router.oneshot(request).await.expect("request succeeds");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collected");
        let error: serde_json::Value = serde_json::from_slice(&body).expect("payload parses");
        assert_eq!(error["error"], "invalid_request");
        let description = error["error_description"].as_str().expect("description");
        assert!(description.contains("Namespace"));

        if let Some(value) = prev_head {
            std::env::set_var("AUNSORM_HEAD", value);
        } else {
            std::env::remove_var("AUNSORM_HEAD");
        }
        if let Some(value) = prev_namespace {
            std::env::set_var("AUNSORM_ID_NAMESPACE", value);
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
#[derive(Debug, Serialize, Deserialize)]
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

fn generator_config_error(error: &IdError) -> ApiError {
    ApiError::server_error(format!(
        "ID generator oluşturulamadı: {error}. Lütfen AUNSORM_HEAD veya GITHUB_SHA environment variable'ını ayarlayın."
    ))
}

/// POST /id/generate handler
async fn generate_id(
    State(_state): State<Arc<ServerState>>,
    Json(payload): Json<GenerateIdRequest>,
) -> Result<Json<GenerateIdResponse>, ApiError> {
    // Try to create generator from environment
    let generator = match payload.namespace {
        Some(namespace) => {
            HeadIdGenerator::from_env_with_namespace(namespace).map_err(|err| match err {
                IdError::InvalidNamespace | IdError::NamespaceTooLong { .. } => {
                    ApiError::invalid_request(format!("Namespace doğrulanamadı: {err}"))
                }
                _ => generator_config_error(&err),
            })?
        }
        None => HeadIdGenerator::from_env().map_err(|err| generator_config_error(&err))?,
    };

    // Generate ID
    let id = generator
        .next_id()
        .map_err(|e| ApiError::server_error(format!("ID üretilemedi: {e}")))?;

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
            "ID parse edilemedi: {e}"
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

    let parsed = parse_head_id(&payload.id)
        .map_err(|e| ApiError::invalid_request(format!("ID parse edilemedi: {e}")))?;

    let matches = parsed
        .matches_head(&payload.head)
        .map_err(|e| ApiError::invalid_request(format!("HEAD doğrulanamadı: {e}")))?;

    Ok(Json(VerifyHeadResponse {
        id: parsed.as_str().to_owned(),
        head: payload.head,
        matches,
        fingerprint: parsed.fingerprint_hex(),
    }))
}

// ========================================
// Security: Media Token Generation
// ========================================

#[derive(Debug, Deserialize)]
struct MediaTokenRequest {
    #[serde(rename = "roomId")]
    room_id: String,
    identity: String,
    #[serde(rename = "participantName")]
    participant_name: Option<String>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct MediaTokenResponse {
    token: String,
    #[serde(rename = "ttlSeconds")]
    ttl_seconds: u64,
    driver: String,
    #[serde(rename = "bridgeUrl")]
    bridge_url: String,
    #[serde(rename = "issuedAt")]
    issued_at: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "roomId")]
    room_id: String,
    identity: String,
}

/// POST /security/generate-media-token handler
/// Generates JWT token for Zasian media server authentication
async fn generate_media_token(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<MediaTokenRequest>,
) -> Result<Json<MediaTokenResponse>, ApiError> {
    if payload.room_id.trim().is_empty() {
        return Err(ApiError::invalid_request("roomId boş olamaz"));
    }
    if payload.identity.trim().is_empty() {
        return Err(ApiError::invalid_request("identity boş olamaz"));
    }

    let now = SystemTime::now();
    let participant_name = payload
        .participant_name
        .unwrap_or_else(|| payload.identity.clone());

    // Build JWT claims
    let mut claims = Claims {
        subject: Some(payload.identity.clone()),
        issuer: Some(state.issuer().to_owned()),
        audience: Some(Audience::Single("zasian-media".to_owned())),
        ..Default::default()
    };

    // Add custom claims for room and participant
    claims.extra.insert(
        "roomId".to_owned(),
        serde_json::Value::String(payload.room_id.clone()),
    );
    claims.extra.insert(
        "participantName".to_owned(),
        serde_json::Value::String(participant_name.clone()),
    );

    if let Some(metadata) = payload.metadata {
        claims.extra.insert("metadata".to_owned(), metadata);
    }

    claims.ensure_jwt_id();
    claims.set_issued_now();
    claims.set_expiration_from_now(state.token_ttl());

    // Sign the token
    let token = state
        .signer()
        .sign(&claims)
        .map_err(|err| ApiError::server_error(format!("Token imzalanamadı: {err}")))?;

    // Calculate timestamps
    let iat = claims.issued_at.unwrap_or(now);
    let exp = claims
        .expiration
        .unwrap_or_else(|| now + Duration::from_secs(state.token_ttl().as_secs()));

    let ttl_seconds = state.token_ttl().as_secs();

    // Get bridge URL from environment or use default
    let bridge_url = std::env::var("ZASIAN_WEBSOCKET_URL")
        .unwrap_or_else(|_| "wss://localhost:50045/zasian".to_owned());

    // Record token in JTI store (optional, for replay protection)
    let jti = claims
        .jwt_id
        .clone()
        .ok_or_else(|| ApiError::server_error("JTI üretilemedi"))?;

    state
        .record_token(&jti, exp, claims.subject.as_deref(), Some("zasian-media"))
        .await
        .map_err(|err| {
            warn!(jti = %jti, error = %err, "Token kaydı başarısız (JWT yine de kullanılabilir)");
            // Don't fail the request, just log the warning
        })
        .ok();

    Ok(Json(MediaTokenResponse {
        token,
        ttl_seconds,
        driver: "zasian".to_owned(),
        bridge_url,
        issued_at: format_timestamp(iat),
        expires_at: format_timestamp(exp),
        room_id: payload.room_id,
        identity: payload.identity,
    }))
}

const TIMESTAMP_FALLBACK: &str = "1970-01-01T00:00:00.000Z";
const TIMESTAMP_FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

fn format_timestamp(time: SystemTime) -> String {
    let datetime = OffsetDateTime::from(time);
    datetime
        .format(TIMESTAMP_FORMAT)
        .unwrap_or_else(|_| TIMESTAMP_FALLBACK.to_owned())
}

#[cfg(test)]
mod timestamp_tests {
    use super::format_timestamp;
    use super::TIMESTAMP_FALLBACK;
    use std::time::SystemTime;
    use time::macros::datetime;

    #[test]
    fn formats_timestamp_with_millis_precision() {
        let dt = datetime!(2024-05-18 15:04:05.678 UTC);
        let time: SystemTime = dt.into();
        assert_eq!(format_timestamp(time), "2024-05-18T15:04:05.678Z");
    }

    #[test]
    fn preserves_epoch_fallback_when_formatting_fails() {
        // The formatter should never fail for valid format descriptions, but
        // guard against regressions by ensuring the fallback matches the
        // documented value when formatting is not possible.
        let time: SystemTime = datetime!(1970-01-01 00:00:00 UTC).into();
        assert_eq!(format_timestamp(time), TIMESTAMP_FALLBACK);
    }
}

// ========================================
// Blockchain DID Verification (Hyperledger Fabric PoC)
// ========================================

#[derive(Debug, Deserialize)]
struct FabricDidVerificationPayload {
    did: String,
    channel: String,
    proof: FabricDidProofPayload,
}

#[derive(Debug, Deserialize)]
struct FabricDidProofPayload {
    challenge: String,
    signature: String,
    block_hash: String,
    transaction_id: String,
    timestamp_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct FabricDidVerificationResponse {
    did: String,
    verified: bool,
    controller: String,
    status: String,
    channel: String,
    #[serde(rename = "mspId")]
    msp_id: String,
    ledger_anchor: FabricLedgerAnchorResponse,
    verification_method: FabricVerificationMethodResponse,
    service: Option<FabricVerificationServiceResponse>,
    audit: FabricVerificationAuditResponse,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
struct FabricVerificationMethodResponse {
    id: String,
    #[serde(rename = "type")]
    ty: String,
    controller: String,
    #[serde(rename = "publicKeyBase64")]
    public_key_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FabricVerificationServiceResponse {
    id: String,
    #[serde(rename = "type")]
    ty: String,
    endpoint: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FabricVerificationAuditResponse {
    challenge: String,
    #[serde(rename = "checkedAtMs")]
    checked_at_ms: u64,
    #[serde(rename = "clockSkewMs")]
    clock_skew_ms: u64,
}

fn map_fabric_error(error: FabricDidError) -> ApiError {
    match error {
        FabricDidError::UnknownDid(did) => {
            ApiError::not_found(format!("DID kaydı bulunamadı: {did}"))
        }
        FabricDidError::ChannelMismatch { expected, found } => ApiError::invalid_request(format!(
            "channel beklenen değeri karşılamıyor: beklenen {expected}, bulundu {found}"
        )),
        FabricDidError::BlockHashMismatch { expected, found } => {
            ApiError::invalid_request(format!(
                "block_hash ledger kaydıyla eşleşmiyor: beklenen {}, bulundu {}",
                hex_encode(expected),
                hex_encode(found),
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

async fn verify_fabric_did(
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
    if signature_bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err(ApiError::invalid_request(
            "signature uzunluğu 64 bayt olmalıdır",
        ));
    }
    let mut signature = [0_u8; ed25519_dalek::SIGNATURE_LENGTH];
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
