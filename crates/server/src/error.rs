use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// Uygulama genel hata türü.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Yapılandırma hatası.
    #[error("configuration error: {0}")]
    Configuration(String),
    /// I/O hatası.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JWT hata sarmalayıcısı.
    #[error(transparent)]
    Jwt(#[from] aunsorm_jwt::JwtError),
    /// `SQLite` hata sarmalayıcısı.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// HTTP sunucu hatası.
    #[error(transparent)]
    Http(#[from] hyper::Error),
    /// Şeffaflık defteri hatası.
    #[error(transparent)]
    Transparency(#[from] aunsorm_core::transparency::TransparencyError),
}

/// RFC 6749 uyumlu API hata yanıtı.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: &'static str,
    pub error_description: String,
}

impl ErrorBody {
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            error: "invalid_request",
            error_description: message.into(),
        }
    }

    pub fn invalid_grant(message: impl Into<String>) -> Self {
        Self {
            error: "invalid_grant",
            error_description: message.into(),
        }
    }

    pub fn invalid_client(message: impl Into<String>) -> Self {
        Self {
            error: "invalid_client",
            error_description: message.into(),
        }
    }

    pub fn server_error(message: impl Into<String>) -> Self {
        Self {
            error: "server_error",
            error_description: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            error: "not_found",
            error_description: message.into(),
        }
    }
}

/// HTTP düzeyinde hata türü.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    body: ErrorBody,
}

impl ApiError {
    #[must_use]
    pub const fn new(status: StatusCode, body: ErrorBody) -> Self {
        Self { status, body }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorBody::invalid_request(message))
    }

    pub fn invalid_grant(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorBody::invalid_grant(message))
    }

    pub fn invalid_client(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorBody::invalid_client(message))
    }

    pub fn server_error(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorBody::server_error(message),
        )
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorBody::not_found(message))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let Self { status, body } = self;
        (status, Json(body)).into_response()
    }
}
