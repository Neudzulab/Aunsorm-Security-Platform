#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use endpoint_validator::{
    sitemap::MAX_DOCUMENT_BYTES, validate, Auth, ValidatorConfig, ValidatorError,
};
use tokio::task::JoinHandle;
use url::Url;

struct TestServer {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl TestServer {
    fn base_url(&self) -> Url {
        Url::parse(&format!("http://{}/", self.addr)).unwrap()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(router: Router) -> TestServer {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    TestServer { addr, task }
}

fn xml(body: String) -> Response {
    Response::builder()
        .header("content-type", "application/xml")
        .body(Body::from(body))
        .unwrap()
}

fn config(server: &TestServer) -> ValidatorConfig {
    let mut config = ValidatorConfig::with_base_url(server.base_url());
    config.auth = Some(Auth::Bearer("fixture-token".to_owned()));
    config.additional_headers.push((
        HeaderName::from_static("x-test-key"),
        HeaderValue::from_static("fixture-key"),
    ));
    config
}

fn assert_error_contains(error: &ValidatorError, needle: &str) {
    assert!(
        error.to_string().contains(needle),
        "unexpected error: {error}"
    );
}

async fn authenticated_target(headers: HeaderMap) -> &'static str {
    assert_eq!(
        headers.get("authorization").unwrap(),
        "Bearer fixture-token"
    );
    assert_eq!(headers.get("x-test-key").unwrap(), "fixture-key");
    "ok"
}

#[tokio::test]
async fn index_cycles_namespaces_and_escaped_queries_discover_the_real_endpoint() {
    let router = Router::new()
        .route("/sitemap.xml", get(|| async { xml("<sitemapindex><sitemap><loc>/child.xml</loc></sitemap><sitemap><loc>/sitemap.xml</loc></sitemap></sitemapindex>".to_owned()) }))
        .route("/child.xml", get(|| async { xml("<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'><url><loc>/target?x=1&amp;y=2</loc></url></urlset>".to_owned()) }))
        .route("/target", get(authenticated_target).options(|| async { (StatusCode::NO_CONTENT, [("allow", "GET,OPTIONS")]) }));
    let server = serve(router).await;
    let report = validate(config(&server)).await.unwrap();
    assert!(report
        .results
        .iter()
        .any(|result| result.path == "/target?x=1&y=2" && result.status == Some(200)));
}

#[tokio::test]
async fn same_origin_redirect_resolves_index_children_relative_to_the_final_document() {
    let router = Router::new()
        .route(
            "/sitemap.xml",
            get(|| async { (StatusCode::FOUND, [("location", "/redirect/root.xml")]) }),
        )
        .route(
            "/redirect/root.xml",
            get(|| async {
                xml(
                    "<sitemapindex><sitemap><loc>child.xml</loc></sitemap></sitemapindex>"
                        .to_owned(),
                )
            }),
        )
        .route(
            "/redirect/child.xml",
            get(|| async { xml("<urlset><url><loc>/target</loc></url></urlset>".to_owned()) }),
        )
        .route(
            "/target",
            get(|| async { "ok" })
                .options(|| async { (StatusCode::NO_CONTENT, [("allow", "GET,OPTIONS")]) }),
        );
    let server = serve(router).await;
    let report = validate(config(&server)).await.unwrap();
    assert!(report
        .results
        .iter()
        .any(|result| result.path == "/target" && result.status == Some(200)));
}

#[tokio::test]
async fn cross_origin_indexes_and_redirects_do_not_send_authenticated_requests() {
    let hits = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::clone(&hits);
    let foreign = serve(Router::new().fallback(get(move || {
        let recorded = Arc::clone(&recorded);
        async move {
            recorded.fetch_add(1, Ordering::SeqCst);
            "outside"
        }
    })))
    .await;
    let target = foreign.base_url().join("external.xml").unwrap().to_string();
    for redirect in [false, true] {
        let target = target.clone();
        let router = Router::new().route(
            "/sitemap.xml",
            get(move || {
                let target = target.clone();
                async move {
                    if redirect {
                        Response::builder()
                            .status(StatusCode::FOUND)
                            .header("location", target)
                            .body(Body::empty())
                            .unwrap()
                    } else {
                        xml(format!(
                            "<sitemapindex><sitemap><loc>{target}</loc></sitemap></sitemapindex>"
                        ))
                    }
                }
            }),
        );
        let server = serve(router).await;
        assert!(validate(config(&server)).await.is_err());
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "credentials were sent outside the configured origin"
        );
    }
}

#[tokio::test]
async fn unavailable_index_children_fail_instead_of_yielding_partial_coverage() {
    let router = Router::new().route(
        "/sitemap.xml",
        get(|| async {
            xml(
                "<sitemapindex><sitemap><loc>/missing.xml</loc></sitemap></sitemapindex>"
                    .to_owned(),
            )
        }),
    );
    let server = serve(router).await;
    assert_error_contains(&validate(config(&server)).await.unwrap_err(), "unavailable");
}

#[tokio::test]
async fn index_cannot_reuse_an_optional_root_that_was_unavailable() {
    let router = Router::new().route(
        "/sitemap_index.xml",
        get(|| async {
            xml(
                "<sitemapindex><sitemap><loc>/sitemap.xml</loc></sitemap></sitemapindex>"
                    .to_owned(),
            )
        }),
    );
    let server = serve(router).await;
    assert_error_contains(
        &validate(config(&server)).await.unwrap_err(),
        "unavailable document",
    );
}

#[tokio::test]
async fn embedded_url_credentials_are_rejected_even_on_the_configured_origin() {
    let router = Router::new().route("/sitemap.xml", get(|headers: HeaderMap| async move {
        let host = headers.get("host").unwrap().to_str().unwrap();
        xml(format!("<sitemapindex><sitemap><loc>http://embedded:fixture@{host}/child.xml</loc></sitemap></sitemapindex>"))
    }));
    let server = serve(router).await;
    assert_error_contains(
        &validate(config(&server)).await.unwrap_err(),
        "without URL credentials",
    );
}

#[tokio::test]
async fn seed_openapi_and_html_scheme_paths_cannot_send_validation_credentials_cross_origin() {
    let hits = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::clone(&hits);
    let foreign = serve(Router::new().fallback(get(move || {
        let recorded = Arc::clone(&recorded);
        async move {
            recorded.fetch_add(1, Ordering::SeqCst);
            "outside"
        }
    })))
    .await;
    let hostile_path = format!("/{}", foreign.base_url().join("api/escaped").unwrap());
    for source in ["seed", "openapi", "html"] {
        let mut router = Router::new();
        if source == "openapi" {
            let path = hostile_path.clone();
            router = router.route("/openapi.json", get(move || {
                let path = path.clone();
                async move {
                    let mut paths = serde_json::Map::new();
                    paths.insert(path, serde_json::json!({"get":{"responses":{"200":{"description":"OK"}}}}));
                    axum::Json(serde_json::json!({"openapi":"3.0.3","info":{"title":"Hostile path","version":"1"},"paths":paths}))
                }
            }));
        } else if source == "html" {
            let path = hostile_path.clone();
            router = router.route(
                "/",
                get(move || {
                    let path = path.clone();
                    async move { axum::response::Html(format!("<a href='{path}'>bad target</a>")) }
                }),
            );
        }
        let server = serve(router).await;
        let mut configuration = config(&server);
        if source == "seed" {
            configuration.seed_paths.push(hostile_path.clone());
        }
        assert_error_contains(
            &validate(configuration).await.unwrap_err(),
            "configured origin",
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "untrusted {source} sent requests outside the origin"
        );
    }
}

#[tokio::test]
async fn excessive_index_document_counts_fail_before_following_all_links() {
    let mut links = String::new();
    for index in 0..17 {
        write!(links, "<sitemap><loc>/child-{index}.xml</loc></sitemap>").unwrap();
    }
    let router = Router::new().route(
        "/sitemap.xml",
        get(move || {
            let links = links.clone();
            async move { xml(format!("<sitemapindex>{links}</sitemapindex>")) }
        }),
    );
    let server = serve(router).await;
    assert_error_contains(
        &validate(config(&server)).await.unwrap_err(),
        "traversal budget",
    );
}

#[tokio::test]
async fn both_content_length_and_chunked_discovery_bodies_are_bounded() {
    for chunked in [false, true] {
        let router = Router::new().route(
            "/sitemap.xml",
            get(move || async move {
                if chunked {
                    let stream = futures::stream::iter(
                        std::iter::repeat_with(|| Ok::<_, Infallible>(vec![b'x'; 65_536])).take(17),
                    );
                    Response::new(Body::from_stream(stream))
                } else {
                    Response::new(Body::from(vec![b'x'; MAX_DOCUMENT_BYTES + 1]))
                }
            }),
        );
        let server = serve(router).await;
        assert_error_contains(&validate(config(&server)).await.unwrap_err(), "byte budget");
    }
}

#[tokio::test]
async fn decoded_gzip_body_is_bounded_even_when_compressed_length_is_small() {
    let gzip = include_bytes!("data/oversized-discovery.xml.gz").as_slice();
    assert!(gzip.len() < MAX_DOCUMENT_BYTES);
    let router = Router::new().route(
        "/sitemap.xml",
        get(move || async move {
            Response::builder()
                .header("content-encoding", "gzip")
                .body(Body::from(gzip))
                .unwrap()
        }),
    );
    let server = serve(router).await;
    assert_error_contains(&validate(config(&server)).await.unwrap_err(), "byte budget");
}
