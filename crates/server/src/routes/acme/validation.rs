use std::sync::Arc;

use aunsorm_acme::{
    ChallengeState, Dns01ValidationError, Http01ValidationError, OrderIdentifier,
    OrderIdentifierError,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::ServerState;

#[derive(Debug, Deserialize)]
pub struct Http01PublishRequest {
    pub token: String,
    pub account_thumbprint: String,
}

#[derive(Debug, Serialize)]
pub struct Http01PublishResponse {
    pub state: ChallengeState,
    pub resource_path: String,
    pub body: String,
}

#[derive(Debug, Serialize)]
pub struct Http01RevokeResponse {
    pub state: ChallengeState,
}

#[derive(Debug, Deserialize)]
pub struct Dns01PublishRequest {
    pub token: String,
    pub identifier: String,
    pub account_thumbprint: String,
}

#[derive(Debug, Serialize)]
pub struct Dns01PublishResponse {
    pub state: ChallengeState,
    pub record_name: String,
    pub record_value: String,
}

#[derive(Debug, Serialize)]
pub struct Dns01RevokeResponse {
    pub state: ChallengeState,
}

#[derive(Debug, Serialize)]
struct ValidationErrorBody {
    code: &'static str,
    detail: String,
}

pub async fn publish_http01(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<Http01PublishRequest>,
) -> Response {
    let service = state.acme();
    match service
        .publish_http01_challenge(&payload.token, &payload.account_thumbprint)
        .await
    {
        Ok(info) => Http01PublishResponse {
            state: info.state,
            resource_path: info.publication.resource_path().to_owned(),
            body: info.publication.body().to_owned(),
        }
        .into_response_with(StatusCode::CREATED),
        Err(err) => validation_response(StatusCode::BAD_REQUEST, http01_error_body(err)),
    }
}

pub async fn revoke_http01(
    State(state): State<Arc<ServerState>>,
    Path(token): Path<String>,
) -> Response {
    let service = state.acme();
    service.revoke_http01_challenge(&token).await.map_or_else(
        || {
            validation_response(
                StatusCode::NOT_FOUND,
                ValidationErrorBody {
                    code: "http-01/not-found",
                    detail: format!(
                        "Belirtilen token için yayınlanmış HTTP-01 challenge bulunamadı: {token}"
                    ),
                },
            )
        },
        |state| Http01RevokeResponse { state }.into_response_with(StatusCode::OK),
    )
}

pub async fn publish_dns01(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<Dns01PublishRequest>,
) -> Response {
    let service = state.acme();
    let identifier = match OrderIdentifier::dns(&payload.identifier) {
        Ok(identifier) => identifier,
        Err(err) => {
            return validation_response(StatusCode::BAD_REQUEST, dns_identifier_error_body(&err));
        }
    };
    match service
        .publish_dns01_challenge(&payload.token, &identifier, &payload.account_thumbprint)
        .await
    {
        Ok(info) => Dns01PublishResponse {
            state: info.state,
            record_name: info.publication.record_name().to_owned(),
            record_value: info.publication.record_value().to_owned(),
        }
        .into_response_with(StatusCode::CREATED),
        Err(err) => validation_response(StatusCode::BAD_REQUEST, dns01_error_body(err)),
    }
}

pub async fn revoke_dns01(
    State(state): State<Arc<ServerState>>,
    Path(token): Path<String>,
) -> Response {
    let service = state.acme();
    service.revoke_dns01_challenge(&token).await.map_or_else(
        || {
            validation_response(
                StatusCode::NOT_FOUND,
                ValidationErrorBody {
                    code: "dns-01/not-found",
                    detail: format!(
                        "Belirtilen token için yayınlanmış DNS-01 challenge bulunamadı: {token}"
                    ),
                },
            )
        },
        |state| Dns01RevokeResponse { state }.into_response_with(StatusCode::OK),
    )
}

fn http01_error_body(err: Http01ValidationError) -> ValidationErrorBody {
    match err {
        Http01ValidationError::NotHttp01 => ValidationErrorBody {
            code: "http-01/invalid-type",
            detail: "Challenge HTTP-01 türünde değil".to_string(),
        },
        Http01ValidationError::MissingToken => ValidationErrorBody {
            code: "http-01/missing-token",
            detail: "HTTP-01 challenge token değeri eksik".to_string(),
        },
        Http01ValidationError::InvalidToken { reason } => ValidationErrorBody {
            code: "http-01/invalid-token",
            detail: reason.to_string(),
        },
        Http01ValidationError::EmptyThumbprint => ValidationErrorBody {
            code: "http-01/empty-thumbprint",
            detail: "HTTP-01 challenge için hesap thumbprint değeri boş olamaz".to_string(),
        },
        Http01ValidationError::InvalidThumbprint { reason } => ValidationErrorBody {
            code: "http-01/invalid-thumbprint",
            detail: reason.to_string(),
        },
        Http01ValidationError::BodyMismatch { expected, received } => ValidationErrorBody {
            code: "http-01/body-mismatch",
            detail: format!(
                "HTTP yanıtı beklenen key-authorization değeriyle eşleşmedi. Beklenen: {expected}, Alınan: {received}"
            ),
        },
    }
}

fn dns01_error_body(err: Dns01ValidationError) -> ValidationErrorBody {
    match err {
        Dns01ValidationError::NotDns01 => ValidationErrorBody {
            code: "dns-01/invalid-type",
            detail: "Challenge DNS-01 türünde değil".to_string(),
        },
        Dns01ValidationError::MissingToken => ValidationErrorBody {
            code: "dns-01/missing-token",
            detail: "DNS-01 challenge token değeri eksik".to_string(),
        },
        Dns01ValidationError::UnsupportedIdentifier => ValidationErrorBody {
            code: "dns-01/unsupported-identifier",
            detail: "DNS-01 challenge yalnızca DNS identifier ile kullanılabilir".to_string(),
        },
        Dns01ValidationError::KeyAuthorization { source } => {
            let body = http01_error_body(source);
            ValidationErrorBody {
                code: "dns-01/key-authorization",
                detail: body.detail,
            }
        }
        Dns01ValidationError::MissingRecord => ValidationErrorBody {
            code: "dns-01/missing-record",
            detail: "Sorgulanan DNS yanıtında beklenen TXT kaydı bulunamadı".to_string(),
        },
        Dns01ValidationError::RecordMismatch { expected, received } => ValidationErrorBody {
            code: "dns-01/record-mismatch",
            detail: format!(
                "TXT kaydı beklenen değerle eşleşmedi. Beklenen: {expected}, Alınan: {received:?}"
            ),
        },
    }
}

fn dns_identifier_error_body(err: &OrderIdentifierError) -> ValidationErrorBody {
    ValidationErrorBody {
        code: "dns-01/invalid-identifier",
        detail: format!("DNS identifier değeri geçersiz: {err}"),
    }
}

fn validation_response(status: StatusCode, body: ValidationErrorBody) -> Response {
    (status, Json(body)).into_response()
}

trait IntoResponseWithStatus: Serialize {
    fn into_response_with(self, status: StatusCode) -> Response;
}

impl<T> IntoResponseWithStatus for T
where
    T: Serialize,
{
    fn into_response_with(self, status: StatusCode) -> Response {
        (status, Json(self)).into_response()
    }
}
