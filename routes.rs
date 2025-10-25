use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::{
    extract::State,
    http::{Response, StatusCode},
    response::Json,
    routing::{get, Router},
    body::Body,
};

use serde::Serialize;
use tracing::{info, warn, Level};
use tower_http::trace::{
    DefaultMakeSpan, DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer,
};
use tower_http::LatencyUnit;
use tokio::signal;

#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};

use crate::config::ServerConfig;
use crate::error::{ApiError, ServerError};
use crate::state::ServerState;

pub fn build_router(state: Arc<ServerState>) -> Router {
    let router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .with_state(state.clone());

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(
            DefaultOnResponse::new()
                .level(Level::INFO)
                .latency_unit(LatencyUnit::Millis),
        )
        .on_failure(
            DefaultOnFailure::new()
                .level(Level::ERROR)
                .latency_unit(LatencyUnit::Millis),
        );

    router.layer(trace_layer)
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "aunsorm",
    })
}

async fn metrics(State(_state): State<Arc<ServerState>>) -> Result<Response<Body>, ApiError> {
    let metrics_data = "# TYPE requests_total counter\nrequests_total 0\n";
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(Body::from(metrics_data))
        .unwrap())
}

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