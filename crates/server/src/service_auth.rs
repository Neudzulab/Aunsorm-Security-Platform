//! Hassas uçlar için çağıran (servis) doğrulaması.
//!
//! Medya tokenı basan, oturum anahtarı ve SFU bağlamı üreten uçlar yalnız güvenilen
//! servislerden çağrılabilir. Çağıran iki yoldan biriyle kendini kanıtlar:
//!
//! * `X-Aunsorm-Internal-Secret` başlığı = `AUNSORM_INTERNAL_SECRET` (iç ağ, paylaşılan gizli),
//! * `Authorization: Bearer <jwt>`: gizli (confidential) bir istemcinin `client_credentials`
//!   ile aldığı, `role = service` olan token.
//!
//! `AUNSORM_SERVICE_AUTH_DISABLED=true` yalnız geliştirme içindir; varsayılan kapalıdır ve
//! strict kipte yok sayılır.

use std::sync::Arc;

use aunsorm_jwt::{JwtVerifier, VerificationOptions};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, Request};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::ApiError;
use crate::state::{ServerState, DEFAULT_SERVICE_ROLE};

/// Paylaşılan iç gizli başlığı.
pub const INTERNAL_SECRET_HEADER: &str = "x-aunsorm-internal-secret";

/// Gizli değerin kabul edilmesi için en kısa uzunluk.
const MIN_INTERNAL_SECRET_LEN: usize = 24;

/// Her zaman korunan yol önekleri (`/v1` öneki olsun olmasın).
const DEFAULT_PROTECTED_PREFIXES: [&str; 4] = [
    "/security/generate-media-token",
    "/sessions",
    "/sfu/context",
    // Sunucu anahtarıyla şifre çözer; korumasız hali herkese açık bir çözme kâhiniydi.
    "/security/jwe",
];

/// Servis doğrulama yapılandırması.
#[derive(Debug, Clone, Default)]
pub struct ServiceAuthConfig {
    internal_secret: Option<String>,
    bypass: bool,
    extra_paths: Vec<String>,
}

impl ServiceAuthConfig {
    #[must_use]
    pub fn new(internal_secret: Option<String>, bypass: bool, extra_paths: Vec<String>) -> Self {
        let internal_secret = internal_secret
            .map(|value| value.trim().to_owned())
            .filter(|value| value.len() >= MIN_INTERNAL_SECRET_LEN);
        let extra_paths = extra_paths
            .into_iter()
            .map(|path| path.trim().trim_end_matches('/').to_owned())
            .filter(|path| path.starts_with('/') && path.len() > 1)
            .collect();
        Self {
            internal_secret,
            bypass,
            extra_paths,
        }
    }

    /// Ortam değişkenlerinden okur (`AUNSORM_INTERNAL_SECRET`,
    /// `AUNSORM_SERVICE_AUTH_DISABLED`, `AUNSORM_SERVICE_AUTH_EXTRA_PATHS`).
    #[must_use]
    pub fn from_env() -> Self {
        let secret = std::env::var("AUNSORM_INTERNAL_SECRET").ok();
        let bypass = std::env::var("AUNSORM_SERVICE_AUTH_DISABLED")
            .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true"))
            .unwrap_or(false);
        let extra = std::env::var("AUNSORM_SERVICE_AUTH_EXTRA_PATHS")
            .map(|raw| raw.split(',').map(str::to_owned).collect())
            .unwrap_or_default();
        Self::new(secret, bypass, extra)
    }
}

/// Yolun servis doğrulaması gerektirip gerektirmediğini döndürür.
#[must_use]
pub fn is_protected_path(path: &str, extra_paths: &[String]) -> bool {
    let path = path
        .strip_prefix("/v1")
        .filter(|rest| rest.starts_with('/'))
        .unwrap_or(path);
    let matches = |prefix: &str| {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    };
    DEFAULT_PROTECTED_PREFIXES
        .iter()
        .any(|prefix| matches(prefix))
        || extra_paths.iter().any(|prefix| matches(prefix))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

fn secrets_equal(expected: &str, candidate: &str) -> bool {
    let left: [u8; 32] = Sha256::digest(expected.as_bytes()).into();
    let right: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
    left.ct_eq(&right).into()
}

/// Çağıranı doğrular.
///
/// # Errors
/// Kimlik bilgisi yok/geçersizse 401, token servis tokenı değilse 403.
pub fn authorize(
    state: &ServerState,
    headers: &HeaderMap,
    config: &ServiceAuthConfig,
) -> Result<(), ApiError> {
    if config.bypass && !state.strict() {
        return Ok(());
    }

    if let Some(candidate) = headers.get(INTERNAL_SECRET_HEADER) {
        let candidate = candidate.to_str().unwrap_or_default().trim();
        return match config.internal_secret.as_deref() {
            Some(expected) if secrets_equal(expected, candidate) => Ok(()),
            _ => Err(ApiError::unauthorized("iç servis gizi geçersiz")),
        };
    }

    let token = bearer_token(headers)
        .ok_or_else(|| ApiError::unauthorized("servis kimlik bilgisi gereklidir"))?;
    let verifier = JwtVerifier::from_jwks(state.jwks())
        .map_err(|err| ApiError::server_error(format!("doğrulayıcı kurulamadı: {err}")))?;
    let options = VerificationOptions {
        issuer: Some(state.issuer().to_owned()),
        audience: Some(state.audience().to_owned()),
        require_jti: false,
        ..VerificationOptions::default()
    };
    let claims = verifier
        .verify(token, &options)
        .map_err(|_| ApiError::unauthorized("servis tokenı geçersiz"))?;

    let claim = |name: &str| claims.extras.get(name).and_then(Value::as_str);
    let is_service_role = claim("role") == Some(DEFAULT_SERVICE_ROLE);
    let is_client_credentials = claim("grantType") == Some("client_credentials");
    let is_confidential = claim("clientId")
        .and_then(|client_id| state.oauth_client(client_id))
        .is_some_and(|client| client.has_secret());
    if is_service_role && is_client_credentials && is_confidential {
        Ok(())
    } else {
        Err(ApiError::forbidden("token servis yetkisi taşımıyor"))
    }
}

/// Korunan yollara servis doğrulaması uygulayan ara katman.
pub async fn require_service_caller(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }
    let config = ServiceAuthConfig::from_env();
    if !is_protected_path(request.uri().path(), &config.extra_paths) {
        return next.run(request).await;
    }
    match authorize(&state, request.headers(), &config) {
        Ok(()) => next.run(request).await,
        Err(err) => {
            tracing::warn!(path = request.uri().path(), "servis doğrulaması reddedildi");
            err.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_paths_cover_prefix_and_v1() {
        let extra: Vec<String> = Vec::new();
        for path in [
            "/security/generate-media-token",
            "/v1/security/generate-media-token",
            "/sessions",
            "/sessions/abc/keys",
            "/v1/sessions/abc/keys",
            "/sfu/context",
            "/sfu/context/step",
            "/security/jwe/encrypt",
            "/v1/security/jwe/decrypt",
        ] {
            assert!(is_protected_path(path, &extra), "{path}");
        }
        for path in [
            "/security/jwt-verify",
            "/sessionsx",
            "/security/encrypt",
            "/.well-known/jwks.json",
            "/oauth/token",
            "/v1x/sessions",
        ] {
            assert!(!is_protected_path(path, &extra), "{path}");
        }
    }

    #[test]
    fn extra_paths_are_normalised() {
        let config = ServiceAuthConfig::new(
            None,
            false,
            vec![
                " /security/encrypt/ ".to_owned(),
                "nope".to_owned(),
                "/".to_owned(),
            ],
        );
        assert!(is_protected_path("/security/encrypt", &config.extra_paths));
        assert!(is_protected_path(
            "/v1/security/encrypt",
            &config.extra_paths
        ));
        assert!(!is_protected_path("/security/decrypt", &config.extra_paths));
        assert_eq!(config.extra_paths.len(), 1);
    }

    #[test]
    fn short_internal_secret_is_ignored() {
        let config = ServiceAuthConfig::new(Some("short".to_owned()), false, vec![]);
        assert!(config.internal_secret.is_none());
    }

    #[test]
    fn bearer_parsing() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
        headers.insert(header::AUTHORIZATION, "Bearer   ".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }
}
