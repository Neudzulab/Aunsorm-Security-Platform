use std::sync::Arc;

use aunsorm_acme::{DirectoryService, NonceService};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::state::ServerState;

/// ACME directory keşif uç noktasını işler.
pub async fn directory(State(state): State<Arc<ServerState>>) -> Response {
    let service = state.acme();
    let document = DirectoryService::directory(service)
        .await
        .unwrap_or_else(|never| match never {});
    let nonce = match NonceService::issue_nonce(service).await {
        Ok(value) => value,
        Err(problem) => {
            let fallback = service.next_nonce().await;
            return super::super::acme_problem_response(&problem, &fallback);
        }
    };

    let mut response = (StatusCode::OK, Json(document)).into_response();
    super::super::apply_acme_headers(&mut response, &nonce);
    response
}
