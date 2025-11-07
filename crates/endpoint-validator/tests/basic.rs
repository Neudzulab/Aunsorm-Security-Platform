#![allow(clippy::too_many_lines)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::USER_AGENT;
use axum::http::{HeaderMap, Method, StatusCode};
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
use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::BroadcastStream;
use url::Url;

#[derive(Clone)]
struct AppState {
    sender: broadcast::Sender<&'static str>,
    user_agents: Arc<Mutex<Vec<String>>>,
}

impl AppState {
    async fn record_user_agent(&self, headers: &HeaderMap) {
        if let Some(value) = headers.get(USER_AGENT) {
            if let Ok(text) = value.to_str() {
                self.user_agents.lock().await.push(text.to_string());
            }
        }
    }
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

async fn user_agent_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.record_user_agent(&headers).await;
    Json(json!({ "status": "captured" }))
}

fn router(state: AppState) -> Router {
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
        .route(
            "/ua-check",
            get(user_agent_handler).options(options(|| options_allow("GET,OPTIONS"))),
        )
        .with_state(state)
}

struct TestServer {
    addr: SocketAddr,
    user_agents: Arc<Mutex<Vec<String>>>,
}

impl TestServer {
    fn base_url(&self) -> Url {
        Url::parse(&format!("http://{}:{}", self.addr.ip(), self.addr.port())).expect("url")
    }

    async fn recorded_user_agents(&self) -> Vec<String> {
        self.user_agents.lock().await.clone()
    }
}

async fn spawn_server() -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (sender, _) = broadcast::channel(16);
    let user_agents = Arc::new(Mutex::new(Vec::new()));
    let state = AppState {
        sender,
        user_agents: Arc::clone(&user_agents),
    };
    let app = router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server");
    });
    TestServer { addr, user_agents }
}

#[tokio::test]
async fn validator_discovers_endpoints() {
    let server = spawn_server().await;
    let base_url = server.base_url();
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
    let summary = report.summary();
    assert_eq!(summary.total, report.results.len());
    assert!(
        summary.successes >= 3,
        "expected at least three successful endpoints"
    );
    assert!(
        summary.allowed_failures >= 1,
        "expected at least one allowlisted failure"
    );
    assert_eq!(
        summary.successes + summary.failures + summary.allowed_failures + summary.skipped,
        summary.total,
        "summary counts should balance"
    );
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

#[tokio::test]
async fn validator_uses_default_user_agent() {
    let server = spawn_server().await;
    let base_url = server.base_url();
    let mut config = ValidatorConfig::with_base_url(base_url);
    config.seed_paths.push("/ua-check".to_string());

    let report = validate(config).await.expect("report");
    assert!(!report.results.is_empty(), "expected validation results");

    let user_agents = server.recorded_user_agents().await;
    assert!(
        user_agents
            .iter()
            .any(|value| value == "aunsorm-endpoint-validator/0.1"),
        "default user agent not observed: {user_agents:?}"
    );
}

#[tokio::test]
async fn validator_respects_custom_user_agent() {
    let server = spawn_server().await;
    let base_url = server.base_url();
    let mut config = ValidatorConfig::with_base_url(base_url);
    config.seed_paths.push("/ua-check".to_string());
    config.user_agent = Some("custom-validator/9.9".to_string());

    let report = validate(config).await.expect("report");
    assert!(!report.results.is_empty(), "expected validation results");

    let user_agents = server.recorded_user_agents().await;
    assert!(
        !user_agents.is_empty(),
        "expected recorded user agents for /ua-check"
    );
    assert!(
        user_agents
            .iter()
            .all(|value| value == "custom-validator/9.9"),
        "unexpected user agent values: {user_agents:?}"
    );
}
