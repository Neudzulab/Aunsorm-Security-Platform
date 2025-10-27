use std::net::SocketAddr;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{
    sse::{Event, KeepAlive},
    IntoResponse, Response, Sse,
};
use axum::routing::{get, options, post};
use axum::{Json, Router};
use clap::Parser;
use futures::{Stream, StreamExt};
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
}

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
        "info": {"title": "Mock API", "version": "1.0.0"},
        "paths": {
            "/health": {"get": {"responses": {"200": {"description": "OK"}}}},
            "/items": {
                "post": {
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name"],
                                    "properties": {"name": {"type": "string"}}
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}}
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
    let (sender, _) = broadcast::channel(1);
    sender.send("hello").expect("initial event");
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

#[tokio::main]
async fn main() {
    let args = Args::parse();
    tracing_subscriber::fmt::init();
    let app = router();
    println!("Mock API listening on {}", args.bind);
    axum::serve(
        tokio::net::TcpListener::bind(args.bind)
            .await
            .expect("bind"),
        app,
    )
    .await
    .expect("server");
}
