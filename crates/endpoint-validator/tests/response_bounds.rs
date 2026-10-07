#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::time::Duration;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use endpoint_validator::{
    validate, FailureKind, ValidationOutcome, ValidationReport, ValidatorConfig,
};
use futures::{stream, StreamExt};
use serde_json::json;
use tokio::task::JoinHandle;
use url::Url;

const LIMIT: usize = 1024 * 1024;

struct ServerTask(JoinHandle<()>);

impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn response(content_type: &str, body: Body) -> Response {
    Response::builder()
        .header("content-type", content_type)
        .body(body)
        .unwrap()
}

async fn check(router: Router, method: &str, timeout: Duration) -> ValidationReport {
    let method = method.to_owned();
    let router = router.route(
        "/openapi.json",
        get(move || {
            let method = method.clone();
            async move {
                Json(json!({
                    "openapi":"3.0.0", "info":{"title":"Bounds", "version":"1"},
                    "paths":{"/target":{method:{"responses":{"200":{"description":"OK"}}}}}
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = ServerTask(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    }));
    let mut config =
        ValidatorConfig::with_base_url(Url::parse(&format!("http://{addr}/")).unwrap());
    config.timeout = timeout;
    config.retries = 0;
    let report = validate(config).await.unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].path, "/target");
    report
}

#[tokio::test]
async fn exact_limit_json_reaches_eof_and_is_validated() {
    let report = check(
        Router::new().route(
            "/target",
            get(|| async {
                response(
                    "application/json",
                    Body::from(format!("\"{}\"", "x".repeat(LIMIT - 2))),
                )
            }),
        ),
        "get",
        Duration::from_secs(2),
    )
    .await;
    assert!(matches!(
        report.results[0].outcome,
        ValidationOutcome::Success
    ));
    assert!(report.results[0].body_sample.is_none());
}

#[tokio::test]
async fn oversized_known_and_chunked_bodies_are_explicit_failures() {
    for chunked in [false, true] {
        let report = check(
            Router::new().route(
                "/target",
                get(move || async move {
                    let body = if chunked {
                        Body::from_stream(stream::iter([
                            Ok::<_, Infallible>(vec![b'x'; LIMIT]),
                            Ok(vec![b'x']),
                        ]))
                    } else {
                        Body::from(vec![b'x'; LIMIT + 1])
                    };
                    response("application/octet-stream", body)
                }),
            ),
            "get",
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(
            report.results[0].outcome,
            ValidationOutcome::Failure(FailureKind::ResponseTooLarge)
        ));
        assert_eq!(report.results[0].status, Some(200));
        assert!(report.results[0].response_excerpt.is_none());
    }
}

#[tokio::test]
async fn compressed_response_is_bounded_after_decoding() {
    let report = check(
        Router::new().route(
            "/target",
            get(|| async {
                Response::builder()
                    .header("content-encoding", "gzip")
                    .body(Body::from(
                        include_bytes!("data/oversized-discovery.xml.gz").as_slice(),
                    ))
                    .unwrap()
            }),
        ),
        "get",
        Duration::from_secs(2),
    )
    .await;
    assert!(matches!(
        report.results[0].outcome,
        ValidationOutcome::Failure(FailureKind::ResponseTooLarge)
    ));
}

#[tokio::test]
async fn head_and_bodyless_statuses_do_not_require_json_payloads() {
    for status in [
        StatusCode::OK,
        StatusCode::NO_CONTENT,
        StatusCode::RESET_CONTENT,
    ] {
        let report = check(
            Router::new().route(
                "/target",
                get(move || async move {
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .header("content-length", LIMIT + 100)
                        .body(Body::empty())
                        .unwrap()
                }),
            ),
            "head",
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(
            report.results[0].outcome,
            ValidationOutcome::Success
        ));
    }
    for status in [StatusCode::NO_CONTENT, StatusCode::RESET_CONTENT] {
        let report = check(
            Router::new().route(
                "/target",
                get(move || async move {
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(Body::empty())
                        .unwrap()
                }),
            ),
            "get",
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(
            report.results[0].outcome,
            ValidationOutcome::Success
        ));
    }
}

#[tokio::test]
async fn sse_prefix_is_capped_and_labelled_in_json_and_markdown() {
    let report = check(
        Router::new().route(
            "/target",
            get(|| async {
                response(
                    "TEXT/EVENT-STREAM; charset=utf-8",
                    Body::from(vec![b'x'; LIMIT + 1]),
                )
            }),
        ),
        "get",
        Duration::from_secs(2),
    )
    .await;
    let result = &report.results[0];
    assert!(matches!(result.outcome, ValidationOutcome::Success));
    let sample = result.body_sample.as_ref().unwrap();
    assert_eq!((sample.bytes, sample.limit), (1024, 1024));
    assert_eq!(report.to_json()["results"][0]["body_sample"]["bytes"], 1024);
    assert!(report.to_markdown().contains("full stream not validated"));
}

#[tokio::test]
async fn stalled_sse_with_or_without_a_partial_sample_is_a_network_failure() {
    for partial in [false, true] {
        let report = check(
            Router::new().route(
                "/target",
                get(move || async move {
                    let prefix = if partial {
                        vec!["data: partial\n\n"]
                    } else {
                        Vec::new()
                    };
                    response(
                        "text/event-stream",
                        Body::from_stream(
                            stream::iter(prefix.into_iter().map(Ok::<_, Infallible>))
                                .chain(stream::pending()),
                        ),
                    )
                }),
            ),
            "get",
            Duration::from_millis(200),
        )
        .await;
        assert!(matches!(
            report.results[0].outcome,
            ValidationOutcome::Failure(FailureKind::Network)
        ));
        assert!(report.results[0].body_sample.is_none());
        assert_eq!(report.results[0].status, Some(200));
    }
}

#[tokio::test]
async fn partial_regular_body_transfer_error_is_never_a_success() {
    let report = check(
        Router::new().route(
            "/target",
            get(|| async {
                response(
                    "text/plain",
                    Body::from_stream(
                        stream::once(async { Ok::<_, std::io::Error>("partial") }).chain(
                            stream::once(async {
                                tokio::time::sleep(Duration::from_millis(20)).await;
                                Err::<&str, _>(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionReset,
                                    "fixture reset",
                                ))
                            }),
                        ),
                    ),
                )
            }),
        ),
        "get",
        Duration::from_secs(2),
    )
    .await;
    assert!(matches!(
        report.results[0].outcome,
        ValidationOutcome::Failure(FailureKind::Network)
    ));
    assert_eq!(report.results[0].status, Some(200));
}

#[tokio::test]
async fn short_completed_sse_and_invalid_json_keep_distinct_results() {
    for (content_type, valid) in [("text/event-stream", true), ("application/json", false)] {
        let report = check(
            Router::new().route(
                "/target",
                get(move || async move { response(content_type, Body::from("data: done\n\n")) }),
            ),
            "get",
            Duration::from_secs(2),
        )
        .await;
        if valid {
            assert!(matches!(
                report.results[0].outcome,
                ValidationOutcome::Success
            ));
        } else {
            assert!(matches!(
                report.results[0].outcome,
                ValidationOutcome::Failure(FailureKind::InvalidJson)
            ));
        }
        assert!(report.results[0].body_sample.is_none());
    }
}
