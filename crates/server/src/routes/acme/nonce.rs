use std::sync::Arc;

use aunsorm_acme::NonceService;
use axum::{body::Body, extract::State, http::StatusCode, response::Response};

use crate::state::ServerState;

/// ACME `newNonce` uç noktasını işler.
pub async fn new_nonce(State(state): State<Arc<ServerState>>) -> Response {
    let service = state.acme();
    let nonce = match NonceService::issue_nonce(service).await {
        Ok(value) => value,
        Err(problem) => {
            let fallback = service.next_nonce().await;
            return super::super::acme_problem_response(&problem, &fallback);
        }
    };

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    super::super::apply_acme_headers(&mut response, &nonce);
    response
}
