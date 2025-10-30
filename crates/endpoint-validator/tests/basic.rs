#![allow(clippy::too_many_lines)]

use std::net::SocketAddr;

use axum::extract::State;
use axum::http::{Method, StatusCode};
use axum::response::{
    sse::{Event, KeepAlive},
    IntoResponse, Response, Sse,
};
use axum::routing::{get, options, post};
use axum::{Json, Router};
use endpoint_validator::{
    validate, AllowlistedFailure, Auth, ValidationOutcome, ValidationReport, ValidatorConfig,
    ValidatorError,
};
use futures::{Stream, StreamExt};
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use url::Url;

#[derive(Clone)]
struct AppState {
    sender: broadcast::Sender<&'static str>,
}

async fn health_handler() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

async fn create_item(Json(payload): Json<Value>) -> impl IntoResponse {
    Json(json!({ "created": payload }))
}

async fn broken_handler() -> impl IntoResponse {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn stream_handler(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let receiver = state.sender.subscribe();
    let stream = BroadcastStream::new(receiver)
        .filter_map(|item| async move { item.ok() })
        .map(|value| Ok::<_, std::convert::Infallible>(Event::default().data(value)));
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn options_allow(methods: &'static str) -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(axum::http::header::ALLOW, methods)
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn openapi() -> impl IntoResponse {
    Json(json!({
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/health": {
                "get": {
                    "responses": {
                        "200": {"description": "OK"}
                    }
                }
            },
            "/items": {
                "post": {
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name"],
                                    "properties": {
                                        "name": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {"description": "Created"}
                    }
                }
            }
        }
    }))
}

async fn sitemap() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/xml")
        .body(axum::body::Body::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset><url><loc>http://localhost/health</loc></url><url><loc>http://localhost/broken</loc></url></urlset>"))
        .unwrap()
}

async fn home() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/html")
        .body(axum::body::Body::from(
            "<html><body><a href=\"/api/v1/docs\">Docs</a></body></html>",
        ))
        .unwrap()
}

fn router() -> Router {
    let (sender, _) = broadcast::channel(16);
    let state = AppState { sender };
    Router::new()
        .route("/", get(home))
        .route("/openapi.json", get(openapi))
        .route("/sitemap.xml", get(sitemap))
        .route(
            "/health",
            get(health_handler).options(options(|| options_allow("GET,OPTIONS"))),
        )
        .route(
            "/items",
            post(create_item).options(options(|| options_allow("POST,OPTIONS"))),
        )
        .route(
            "/broken",
            get(broken_handler).options(options(|| options_allow("GET,OPTIONS"))),
        )
        .route("/stream", get(stream_handler))
        .with_state(state)
}

async fn spawn_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = router();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server");
    });
    addr
}

#[tokio::test]
async fn validator_discovers_endpoints() {
    let addr = spawn_server().await;
    let base_url = Url::parse(&format!("http://{}:{}", addr.ip(), addr.port())).expect("url");
    let mut config = ValidatorConfig::with_base_url(base_url);
    config.include_destructive = true;
    config.seed_paths.push("/stream".to_string());
    config.allowlist.push(AllowlistedFailure {
        method: "GET".to_string(),
        path: "/broken".to_string(),
        statuses: vec![500],
    });
    let report = validate(config).await.expect("report");
    assert_successes(&report);
}

fn assert_successes(report: &ValidationReport) {
    assert!(!report.results.is_empty());
    let mut found_health_get = false;
    let mut found_items_post = false;
    let mut allowed_broken = false;
    for entry in &report.results {
        if entry.path == "/health"
            && entry.method == Method::GET.to_string()
            && matches!(entry.outcome, ValidationOutcome::Success)
        {
            found_health_get = true;
        }
        if entry.path == "/items"
            && entry.method == Method::POST.to_string()
            && matches!(entry.outcome, ValidationOutcome::Success)
        {
            found_items_post = true;
        }
        if entry.path == "/broken" && entry.allowed {
            allowed_broken = true;
        }
    }
    assert!(found_health_get, "GET /health should be validated");
    assert!(found_items_post, "POST /items should be validated");
    assert!(allowed_broken, "broken endpoint should be allowlisted");
}

#[tokio::test]
async fn invalid_auth_header_is_rejected() {
    let base_url = Url::parse("http://example.com/").expect("url");
    let mut config = ValidatorConfig::with_base_url(base_url);
    config.auth = Some(Auth::Bearer("line\nbreak".to_string()));

    let error = validate(config).await.expect_err("should fail");
    match error {
        ValidatorError::InvalidAuthHeader(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}
