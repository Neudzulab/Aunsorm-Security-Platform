#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures::stream::{FuturesUnordered, StreamExt as FuturesStreamExt};
use http::header::{
    HeaderName, HeaderValue, InvalidHeaderValue, ALLOW, AUTHORIZATION, CONTENT_TYPE, USER_AGENT,
};
use http::{HeaderMap, Method};
use openapiv3::{OpenAPI, Operation, ReferenceOr, RequestBody};
use quick_xml::de::from_str as parse_xml;
use regex::Regex;
use reqwest::{Client, Response};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{interval, Interval, MissedTickBehavior};
use tokio_stream::StreamExt as TokioStreamExt;
use url::Url;

const USER_AGENT_VALUE: &str = "aunsorm-endpoint-validator/0.1";
const STREAM_SAMPLE_LIMIT: usize = 1024;
const RESPONSE_EXCERPT_LIMIT: usize = 200;

/// Authentication strategy applied to outbound requests.
#[derive(Clone, Debug)]
pub enum Auth {
    /// HTTP basic authentication with pre-encoded credentials.
    Basic { username: String, password: String },
    /// Bearer token used with the `Authorization` header.
    Bearer(String),
    /// Raw header override. Multiple entries may be provided via the
    /// configuration `additional_headers` field.
    Header {
        name: HeaderName,
        value: HeaderValue,
    },
}

impl Auth {
    fn apply(&self, headers: &mut HeaderMap) -> Result<(), InvalidHeaderValue> {
        match self {
            Self::Basic { username, password } => {
                let credentials = format!("{username}:{password}");
                let value = format!("Basic {}", STANDARD.encode(credentials));
                let header_value = HeaderValue::from_str(&value)?;
                headers.insert(AUTHORIZATION, header_value);
            }
            Self::Bearer(token) => {
                let value = format!("Bearer {token}");
                let header_value = HeaderValue::from_str(&value)?;
                headers.insert(AUTHORIZATION, header_value);
            }
            Self::Header { name, value } => {
                headers.insert(name.clone(), value.clone());
            }
        }
        Ok(())
    }
}
/// Allowlist entry for known failing endpoints.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct AllowlistedFailure {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub statuses: Vec<u16>,
}

impl AllowlistedFailure {
    fn matches(&self, method: &str, path: &str, status: Option<u16>) -> bool {
        if self.method.eq_ignore_ascii_case(method) && self.path == path {
            if self.statuses.is_empty() {
                return true;
            }
            if let Some(value) = status {
                return self.statuses.contains(&value);
            }
        }
        false
    }
}

/// Validator configuration supplied by the caller.
#[derive(Clone, Debug)]
pub struct ValidatorConfig {
    pub base_url: Url,
    pub auth: Option<Auth>,
    pub seed_paths: Vec<String>,
    pub include_destructive: bool,
    pub concurrency: usize,
    pub rate_limit_per_second: Option<u32>,
    pub allowlist: Vec<AllowlistedFailure>,
    pub timeout: Duration,
    pub retries: usize,
    pub backoff_base: Duration,
    pub additional_headers: Vec<(HeaderName, HeaderValue)>,
}

impl ValidatorConfig {
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_base_url(base_url: Url) -> Self {
        Self {
            base_url,
            auth: None,
            seed_paths: Vec::new(),
            include_destructive: false,
            concurrency: 4,
            rate_limit_per_second: None,
            allowlist: Vec::new(),
            timeout: Duration::from_secs(10),
            retries: 2,
            backoff_base: Duration::from_millis(500),
            additional_headers: Vec::new(),
        }
    }
}

/// Execution level errors that prevent validation from running.
#[derive(Debug, Error)]
pub enum ValidatorError {
    #[error("failed to build HTTP client: {0}")]
    ClientBuild(reqwest::Error),
    #[error("HTTP error during discovery: {0}")]
    Discovery(reqwest::Error),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("invalid auth header value: {0}")]
    InvalidAuthHeader(#[from] InvalidHeaderValue),
    #[error("unexpected error: {0}")]
    Other(String),
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "detail")]
pub enum ValidationOutcome {
    Success,
    Failure(FailureKind),
    Skipped { reason: String },
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", content = "message")]
pub enum FailureKind {
    Missing,
    MethodNotAllowed,
    ServerError,
    InvalidJson,
    Network,
    UnexpectedStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidationResult {
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub latency_ms: Option<u128>,
    pub outcome: ValidationOutcome,
    pub response_excerpt: Option<String>,
    pub likely_cause: Option<String>,
    pub suggested_fix: Option<String>,
    pub allowed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidationReport {
    pub base_url: String,
    pub results: Vec<ValidationResult>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ValidationSummary {
    pub total: usize,
    pub successes: usize,
    pub failures: usize,
    pub skipped: usize,
    pub allowed_failures: usize,
}

impl ValidationReport {
    #[must_use]
    pub fn summary(&self) -> ValidationSummary {
        let mut successes = 0usize;
        let mut failures = 0usize;
        let mut skipped = 0usize;
        let mut allowed_failures = 0usize;

        for result in &self.results {
            match &result.outcome {
                ValidationOutcome::Success => successes += 1,
                ValidationOutcome::Skipped { .. } => skipped += 1,
                ValidationOutcome::Failure(_) => {
                    if result.allowed {
                        allowed_failures += 1;
                    } else {
                        failures += 1;
                    }
                }
            }
        }

        ValidationSummary {
            total: self.results.len(),
            successes,
            failures,
            skipped,
            allowed_failures,
        }
    }

    #[must_use]
    pub fn failures(&self) -> Vec<&ValidationResult> {
        self.results
            .iter()
            .filter(|result| {
                matches!(result.outcome, ValidationOutcome::Failure(_)) && !result.allowed
            })
            .collect()
    }

    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut output = String::new();
        writeln!(output, "# Endpoint Validation Report").expect("write should succeed");
        writeln!(output).expect("write should succeed");
        writeln!(output, "Base URL: {}", self.base_url).expect("write should succeed");
        let summary = self.summary();
        writeln!(output, "Total endpoints: {}", summary.total).expect("write should succeed");
        writeln!(output, "Successful: {}", summary.successes).expect("write should succeed");
        writeln!(output, "Skipped: {}", summary.skipped).expect("write should succeed");
        writeln!(
            output,
            "Failures: {} (allowlisted: {})",
            summary.failures, summary.allowed_failures
        )
        .expect("write should succeed");
        writeln!(output).expect("write should succeed");

        let failures = self.failures();
        if failures.is_empty() {
            writeln!(output, "No failing endpoints detected.").expect("write should succeed");
            return output;
        }

        writeln!(
            output,
            "| Method | Path | Status | Latency (ms) | Excerpt | Likely Cause | Suggested Fix |"
        )
        .expect("write should succeed");
        writeln!(output, "| --- | --- | --- | --- | --- | --- | --- |")
            .expect("write should succeed");

        for failure in failures {
            let excerpt = failure
                .response_excerpt
                .as_deref()
                .map(|value| value.replace('|', "\u{2758}"))
                .unwrap_or_default();
            writeln!(
                output,
                "| {} | {} | {} | {} | {} | {} | {} |",
                failure.method,
                failure.path,
                failure
                    .status
                    .map_or_else(|| "-".to_string(), |status| status.to_string()),
                failure
                    .latency_ms
                    .map_or_else(|| "-".to_string(), |latency| latency.to_string()),
                excerpt,
                failure
                    .likely_cause
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
                failure
                    .suggested_fix
                    .clone()
                    .unwrap_or_else(|| "-".to_string())
            )
            .expect("write should succeed");
        }

        output
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        let summary = self.summary();
        json!({
            "base_url": self.base_url,
            "summary": summary,
            "results": self.results,
        })
    }
}

#[derive(Clone, Debug, Default)]
struct RequestTemplate {
    content_type: Option<String>,
    body: Option<Value>,
}

#[derive(Clone, Debug)]
struct EndpointSpec {
    methods: BTreeMap<String, RequestTemplate>,
}

/// Runs the endpoint discovery and validation workflow.
///
/// # Errors
/// Returns [`ValidatorError`] when the base URL cannot be resolved, discovery
/// requests fail, or issuing validation calls produces an unrecoverable HTTP
/// error.
///
/// # Panics
/// Panics if the internal concurrency semaphore becomes poisoned, which is
/// not expected during normal execution but would indicate a logic error in
/// the async runtime.
#[allow(clippy::too_many_lines)]
pub async fn validate(config: ValidatorConfig) -> Result<ValidationReport, ValidatorError> {
    let mut default_headers = HeaderMap::new();
    default_headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
    if let Some(auth) = &config.auth {
        auth.apply(&mut default_headers)?;
    }
    for (name, value) in &config.additional_headers {
        default_headers.insert(name.clone(), value.clone());
    }

    let client = Client::builder()
        .timeout(config.timeout)
        .default_headers(default_headers)
        .build()
        .map_err(ValidatorError::ClientBuild)?;

    let seeds = discover_endpoints(&client, &config).await?;
    let mut endpoint_map: BTreeMap<String, EndpointSpec> = BTreeMap::new();
    for (path, maybe_method, template) in seeds {
        endpoint_map
            .entry(path.clone())
            .and_modify(|existing| {
                if let Some(method) = maybe_method.clone() {
                    existing
                        .methods
                        .entry(method.to_string())
                        .or_insert_with(|| template.clone());
                }
            })
            .or_insert_with(|| {
                let mut methods = BTreeMap::new();
                if let Some(method) = maybe_method {
                    methods.insert(method.to_string(), template.clone());
                }
                EndpointSpec { methods }
            });
    }

    for seed_path in &config.seed_paths {
        let normalized = normalize_path(seed_path);
        endpoint_map
            .entry(normalized.clone())
            .or_insert_with(|| EndpointSpec {
                methods: BTreeMap::new(),
            });
    }

    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let rate_limiter = RateLimiter::new(config.rate_limit_per_second);

    let mut results = Vec::new();
    let mut tasks = FuturesUnordered::new();

    for (path, spec) in &endpoint_map {
        let methods = if spec.methods.is_empty() {
            fetch_allowed_methods(&client, &config, path).await?
        } else {
            spec.methods
                .keys()
                .filter_map(|name| Method::from_bytes(name.as_bytes()).ok())
                .collect::<Vec<_>>()
        };

        for method in methods {
            let is_destructive = matches!(
                method,
                Method::POST | Method::PUT | Method::PATCH | Method::DELETE | Method::CONNECT
            );
            if is_destructive && !config.include_destructive {
                results.push(ValidationResult {
                    method: method.to_string(),
                    path: path.clone(),
                    status: None,
                    latency_ms: None,
                    outcome: ValidationOutcome::Skipped {
                        reason: "Destructive methods disabled".to_string(),
                    },
                    response_excerpt: None,
                    likely_cause: None,
                    suggested_fix: None,
                    allowed: true,
                });
                continue;
            }

            let client = client.clone();
            let semaphore = Arc::clone(&semaphore);
            let rate_limiter = rate_limiter.clone();
            let config = config.clone();
            let template = spec
                .methods
                .get(method.as_str())
                .cloned()
                .unwrap_or_default();
            let path = path.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await.expect("semaphore");
                rate_limiter.wait().await;
                run_check(&client, &config, &path, method.clone(), template).await
            }));
        }
    }

    while let Some(task) = FuturesStreamExt::next(&mut tasks).await {
        match task {
            Ok(Ok(result)) => results.push(result),
            Ok(Err(error)) => {
                results.push(ValidationResult {
                    method: "UNKNOWN".to_string(),
                    path: "-".to_string(),
                    status: None,
                    latency_ms: None,
                    outcome: ValidationOutcome::Failure(FailureKind::Network),
                    response_excerpt: Some(error.to_string()),
                    likely_cause: Some("Network or runtime error".to_string()),
                    suggested_fix: Some("Inspect validator logs".to_string()),
                    allowed: false,
                });
            }
            Err(join_error) => {
                results.push(ValidationResult {
                    method: "UNKNOWN".to_string(),
                    path: "-".to_string(),
                    status: None,
                    latency_ms: None,
                    outcome: ValidationOutcome::Failure(FailureKind::Network),
                    response_excerpt: Some(join_error.to_string()),
                    likely_cause: Some("Task join error".to_string()),
                    suggested_fix: Some("Inspect spawned task".to_string()),
                    allowed: false,
                });
            }
        }
    }

    for result in &mut results {
        if matches!(result.outcome, ValidationOutcome::Failure(_))
            && config
                .allowlist
                .iter()
                .any(|entry| entry.matches(&result.method, &result.path, result.status))
        {
            result.allowed = true;
        }
    }

    results.sort_by(|left, right| {
        let path_cmp = left.path.cmp(&right.path);
        if path_cmp == std::cmp::Ordering::Equal {
            left.method.cmp(&right.method)
        } else {
            path_cmp
        }
    });

    Ok(ValidationReport {
        base_url: config.base_url.to_string(),
        results,
    })
}

#[derive(Clone)]
struct RateLimiter {
    inner: Option<Arc<Mutex<Interval>>>,
}

impl RateLimiter {
    fn new(limit_per_second: Option<u32>) -> Self {
        let inner = limit_per_second.map(|limit| {
            let mut interval = interval(Duration::from_secs_f64(1.0 / f64::from(limit.max(1))));
            // Tick once to avoid immediate wait on the first call.
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            Arc::new(Mutex::new(interval))
        });
        Self { inner }
    }

    async fn wait(&self) {
        let Some(interval) = &self.inner else {
            return;
        };

        interval.lock().await.tick().await;
    }
}
async fn discover_endpoints(
    client: &Client,
    config: &ValidatorConfig,
) -> Result<Vec<(String, Option<Method>, RequestTemplate)>, ValidatorError> {
    let mut entries: Vec<(String, Option<Method>, RequestTemplate)> = Vec::new();
    let mut seen_paths: HashSet<String> = HashSet::new();

    if let Some(openapi_entries) = discover_from_openapi(client, config).await? {
        for (path, method, template) in openapi_entries {
            let normalized = normalize_path(&path);
            seen_paths.insert(normalized.clone());
            entries.push((normalized, Some(method), template));
        }
    }

    for path in discover_from_sitemaps(client, config).await? {
        let normalized = normalize_path(&path);
        if seen_paths.insert(normalized.clone()) {
            entries.push((normalized, None, RequestTemplate::default()));
        }
    }

    for path in discover_from_html(client, config).await? {
        let normalized = normalize_path(&path);
        if seen_paths.insert(normalized.clone()) {
            entries.push((normalized, None, RequestTemplate::default()));
        }
    }

    for path in probe_common_prefixes(client, config).await? {
        let normalized = normalize_path(&path);
        if seen_paths.insert(normalized.clone()) {
            entries.push((normalized, None, RequestTemplate::default()));
        }
    }

    Ok(entries)
}

async fn discover_from_openapi(
    client: &Client,
    config: &ValidatorConfig,
) -> Result<Option<Vec<(String, Method, RequestTemplate)>>, ValidatorError> {
    let candidates = [
        ".well-known/openapi.json",
        "openapi.json",
        "openapi.yaml",
        "swagger.json",
        "swagger/v1/swagger.json",
    ];

    for candidate in candidates {
        let candidate_url = config.base_url.join(candidate)?;
        let response = match client.get(candidate_url.clone()).send().await {
            Ok(response) => response,
            Err(error) => {
                if error.is_timeout() {
                    continue;
                }
                continue;
            }
        };
        if !response.status().is_success() {
            continue;
        }
        let text = response.text().await.map_err(ValidatorError::Discovery)?;
        let spec: OpenAPI = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(_) => match serde_yaml::from_str(&text) {
                Ok(value) => value,
                Err(_) => continue,
            },
        };
        let entries = extract_openapi_operations(&spec);
        if !entries.is_empty() {
            return Ok(Some(entries));
        }
    }

    Ok(None)
}

fn extract_openapi_operations(spec: &OpenAPI) -> Vec<(String, Method, RequestTemplate)> {
    let mut entries = Vec::new();
    let components = spec.components.as_ref();
    for (path, item) in &spec.paths.paths {
        if let Some(item) = item.as_item() {
            push_operation(
                &mut entries,
                Method::GET,
                item.get.as_ref(),
                path,
                components,
            );
            push_operation(
                &mut entries,
                Method::POST,
                item.post.as_ref(),
                path,
                components,
            );
            push_operation(
                &mut entries,
                Method::PUT,
                item.put.as_ref(),
                path,
                components,
            );
            push_operation(
                &mut entries,
                Method::PATCH,
                item.patch.as_ref(),
                path,
                components,
            );
            push_operation(
                &mut entries,
                Method::DELETE,
                item.delete.as_ref(),
                path,
                components,
            );
            push_operation(
                &mut entries,
                Method::OPTIONS,
                item.options.as_ref(),
                path,
                components,
            );
            push_operation(
                &mut entries,
                Method::HEAD,
                item.head.as_ref(),
                path,
                components,
            );
        }
    }
    entries
}

fn push_operation(
    entries: &mut Vec<(String, Method, RequestTemplate)>,
    method: Method,
    operation: Option<&Operation>,
    path: &str,
    components: Option<&openapiv3::Components>,
) {
    let Some(operation) = operation else {
        return;
    };
    let template = operation
        .request_body
        .as_ref()
        .and_then(|body| create_request_template(body, components))
        .unwrap_or_default();
    entries.push((path.to_string(), method, template));
}

fn create_request_template(
    body: &ReferenceOr<RequestBody>,
    components: Option<&openapiv3::Components>,
) -> Option<RequestTemplate> {
    let resolved = resolve_request_body(body, components)?;
    for (content_type, media_type) in &resolved.content {
        if !content_type.contains("json") {
            continue;
        }
        if let Some(example) = &media_type.example {
            return Some(RequestTemplate {
                content_type: Some(content_type.clone()),
                body: Some(example.clone()),
            });
        }
        if let Some(example) = media_type
            .examples
            .values()
            .find_map(|example| match example {
                ReferenceOr::Reference { .. } => None,
                ReferenceOr::Item(example) => example.value.clone(),
            })
        {
            return Some(RequestTemplate {
                content_type: Some(content_type.clone()),
                body: Some(example),
            });
        }
        return Some(RequestTemplate {
            content_type: Some(content_type.clone()),
            body: Some(json!({})),
        });
    }
    Some(RequestTemplate {
        content_type: Some("application/json".to_string()),
        body: Some(json!({})),
    })
}

fn resolve_request_body<'a>(
    body: &'a ReferenceOr<RequestBody>,
    components: Option<&'a openapiv3::Components>,
) -> Option<&'a RequestBody> {
    match body {
        ReferenceOr::Item(item) => Some(item),
        ReferenceOr::Reference { reference } => {
            let components = components?;
            let name = reference.rsplit('/').next()?;
            components.request_bodies.get(name)?.as_item()
        }
    }
}

async fn discover_from_sitemaps(
    client: &Client,
    config: &ValidatorConfig,
) -> Result<Vec<String>, ValidatorError> {
    #[derive(Debug, Deserialize, Default)]
    struct UrlSet {
        #[serde(rename = "url", default)]
        urls: Vec<SiteUrl>,
    }

    #[derive(Debug, Deserialize, Default)]
    struct SiteUrl {
        #[serde(rename = "loc", default)]
        loc: String,
    }

    let mut paths = Vec::new();
    let candidates = ["sitemap.xml", "sitemap_index.xml"];
    for candidate in candidates {
        let url = config.base_url.join(candidate)?;
        let Ok(response) = client.get(url.clone()).send().await else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let text = response.text().await.map_err(ValidatorError::Discovery)?;
        if let Ok(parsed) = parse_xml::<UrlSet>(&text) {
            for entry in parsed.urls {
                if !entry.loc.is_empty() {
                    paths.push(entry.loc);
                }
            }
        }
    }
    Ok(paths)
}

async fn discover_from_html(
    client: &Client,
    config: &ValidatorConfig,
) -> Result<Vec<String>, ValidatorError> {
    let response = client
        .get(config.base_url.clone())
        .send()
        .await
        .map_err(ValidatorError::Discovery)?;
    if !response.status().is_success() {
        return Ok(Vec::new());
    }
    let body = response.text().await.map_err(ValidatorError::Discovery)?;
    let document = Html::parse_document(&body);
    let selector = Selector::parse("a[href]").expect("valid selector");
    let mut paths = Vec::new();
    let api_pattern = Regex::new(r"(?i)/(api|rest|v\d+)/").expect("regex");
    for element in document.select(&selector) {
        let Some(href) = element.value().attr("href") else {
            continue;
        };
        let is_json = href
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("json"));
        if api_pattern.is_match(href) || is_json {
            paths.push(href.to_string());
        }
    }
    Ok(paths)
}

async fn probe_common_prefixes(
    client: &Client,
    config: &ValidatorConfig,
) -> Result<Vec<String>, ValidatorError> {
    let prefixes = [
        "/api/", "/api/v1/", "/api/v2/", "/v1/", "/v2/", "/rest/", "/graphql",
    ];
    let mut paths = Vec::new();
    for prefix in prefixes {
        let url = config.base_url.join(prefix.trim_start_matches('/'))?;
        let Ok(response) = client.request(Method::HEAD, url.clone()).send().await else {
            continue;
        };
        if response.status() != reqwest::StatusCode::NOT_FOUND {
            paths.push(prefix.to_string());
        }
    }
    Ok(paths)
}

async fn fetch_allowed_methods(
    client: &Client,
    config: &ValidatorConfig,
    path: &str,
) -> Result<Vec<Method>, ValidatorError> {
    let url = config.base_url.join(path.trim_start_matches('/'))?;
    let response = match client.request(Method::OPTIONS, url).send().await {
        Ok(response) => response,
        Err(error) => {
            if error.is_timeout() {
                return Ok(vec![Method::GET]);
            }
            return Err(ValidatorError::Discovery(error));
        }
    };
    if response.status().is_success() {
        if let Some(allow) = response.headers().get(ALLOW) {
            if let Ok(value) = allow.to_str() {
                let methods = value
                    .split(',')
                    .filter_map(|method| Method::from_bytes(method.trim().as_bytes()).ok())
                    .collect::<Vec<_>>();
                if !methods.is_empty() {
                    return Ok(methods);
                }
            }
        }
    }
    Ok(vec![Method::GET])
}

async fn run_check(
    client: &Client,
    config: &ValidatorConfig,
    path: &str,
    method: Method,
    template: RequestTemplate,
) -> Result<ValidationResult, anyhow::Error> {
    let mut attempt = 0usize;
    loop {
        let url = config
            .base_url
            .join(path.trim_start_matches('/'))
            .with_context(|| format!("building URL for path {path}"))?;
        let mut request = client.request(method.clone(), url);
        let mut body = template.body.clone();
        let mut content_type = template.content_type.clone();
        if body.is_none() && matches!(method, Method::POST | Method::PUT | Method::PATCH) {
            body = Some(json!({}));
            content_type.get_or_insert_with(|| "application/json".to_string());
        }
        if let Some(value) = &content_type {
            request = request.header(CONTENT_TYPE, value.as_str());
        }
        if let Some(payload) = &body {
            request = request.json(payload);
        }

        let start = Instant::now();
        match request.send().await {
            Ok(response) => {
                let latency = start.elapsed().as_millis();
                return Ok(evaluate_response(path, &method, response, latency).await);
            }
            Err(error) => {
                let captured_error = anyhow!(error);
                if attempt >= config.retries {
                    return Err(captured_error);
                }
                attempt += 1;
                let multiplier = u32::try_from(attempt).unwrap_or(u32::MAX);
                let backoff = config.backoff_base * multiplier;
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

async fn evaluate_response(
    path: &str,
    method: &Method,
    response: Response,
    latency_ms: u128,
) -> ValidationResult {
    let status = response.status();
    let content_type_header = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(std::string::ToString::to_string);
    let is_event_stream = content_type_header
        .as_deref()
        .is_some_and(|value| value.contains("text/event-stream"));

    let body_bytes = if is_event_stream {
        let mut stream = response.bytes_stream();
        let mut collected: Vec<u8> = Vec::new();
        while let Some(item) = TokioStreamExt::next(&mut stream).await {
            if let Ok(chunk) = item {
                collected.extend_from_slice(&chunk);
                if collected.len() >= STREAM_SAMPLE_LIMIT {
                    break;
                }
            } else {
                break;
            }
        }
        collected
    } else {
        response
            .bytes()
            .await
            .map_or_else(|_| Vec::new(), |bytes| bytes.to_vec())
    };

    let excerpt = if body_bytes.is_empty() {
        None
    } else {
        let text = String::from_utf8_lossy(&body_bytes);
        Some(text.chars().take(RESPONSE_EXCERPT_LIMIT).collect())
    };

    let mut result = ValidationResult {
        method: method.to_string(),
        path: path.to_string(),
        status: Some(status.as_u16()),
        latency_ms: Some(latency_ms),
        outcome: ValidationOutcome::Success,
        response_excerpt: excerpt,
        likely_cause: None,
        suggested_fix: None,
        allowed: false,
    };

    if status == reqwest::StatusCode::NOT_FOUND {
        result.outcome = ValidationOutcome::Failure(FailureKind::Missing);
        result.likely_cause = Some("Endpoint not deployed".to_string());
        result.suggested_fix = Some("Add route or update discovery configuration".to_string());
        return result;
    }

    if status == reqwest::StatusCode::METHOD_NOT_ALLOWED {
        result.outcome = ValidationOutcome::Failure(FailureKind::MethodNotAllowed);
        result.likely_cause = Some("Method not supported".to_string());
        result.suggested_fix = Some("Adjust allowed methods or update validator".to_string());
        return result;
    }

    if status.is_server_error() {
        result.outcome = ValidationOutcome::Failure(FailureKind::ServerError);
        result.likely_cause = Some("Server returned 5xx".to_string());
        result.suggested_fix = Some("Inspect server logs".to_string());
        return result;
    }

    if status.is_redirection() || status.is_client_error() {
        result.outcome = ValidationOutcome::Failure(FailureKind::UnexpectedStatus);
        result.likely_cause = Some(format!("Unexpected status: {status}"));
        result.suggested_fix = Some("Review API contract".to_string());
        return result;
    }

    if status.is_success() {
        let expects_json = content_type_header
            .as_deref()
            .is_some_and(|value| value.contains("json"));
        if expects_json {
            if body_bytes.is_empty() {
                result.outcome = ValidationOutcome::Failure(FailureKind::InvalidJson);
                result.likely_cause = Some("Empty body where JSON expected".to_string());
                result.suggested_fix = Some("Return a JSON payload".to_string());
            } else if serde_json::from_slice::<Value>(&body_bytes).is_err() {
                result.outcome = ValidationOutcome::Failure(FailureKind::InvalidJson);
                result.likely_cause = Some("Response was not valid JSON".to_string());
                result.suggested_fix = Some("Ensure endpoint returns valid JSON".to_string());
            }
        }
        return result;
    }

    result.outcome = ValidationOutcome::Failure(FailureKind::UnexpectedStatus);
    result.likely_cause = Some(format!("Unhandled status: {status}"));
    result.suggested_fix = Some("Verify API response".to_string());
    result
}

fn normalize_path(input: &str) -> String {
    Url::parse(input).map_or_else(
        |_| {
            if input.starts_with('/') {
                input.to_string()
            } else {
                format!("/{input}")
            }
        },
        |url| {
            let mut path = url.path().to_string();
            if let Some(query) = url.query() {
                if !query.is_empty() {
                    path.push('?');
                    path.push_str(query);
                }
            }
            if path.is_empty() {
                "/".to_string()
            } else {
                path
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_path, AllowlistedFailure, FailureKind, ValidationOutcome, ValidationReport,
        ValidationResult, ValidationSummary,
    };

    #[test]
    fn allowlisted_failure_matches_expected_cases() {
        let allowlisted = AllowlistedFailure {
            method: "GET".to_string(),
            path: "/items".to_string(),
            statuses: Vec::new(),
        };

        assert!(allowlisted.matches("get", "/items", None));
        assert!(allowlisted.matches("GET", "/items", Some(404)));
        assert!(!allowlisted.matches("POST", "/items", Some(404)));

        let status_scoped = AllowlistedFailure {
            method: "DELETE".to_string(),
            path: "/archive".to_string(),
            statuses: vec![410, 404],
        };

        assert!(status_scoped.matches("delete", "/archive", Some(410)));
        assert!(!status_scoped.matches("delete", "/archive", Some(500)));
        assert!(!status_scoped.matches("delete", "/archive", None));
    }

    #[test]
    fn normalize_path_handles_relative_and_absolute_inputs() {
        assert_eq!(normalize_path("/health"), "/health");
        assert_eq!(normalize_path("status"), "/status");
        assert_eq!(
            normalize_path("http://example.com/api/v1/items"),
            "/api/v1/items"
        );
        assert_eq!(
            normalize_path("https://example.com/metrics?window=30s"),
            "/metrics?window=30s"
        );
        assert_eq!(normalize_path("https://example.com"), "/");
    }

    #[test]
    fn report_to_markdown_sanitizes_excerpts() {
        let report = ValidationReport {
            base_url: "https://validator.test".to_string(),
            results: vec![
                ValidationResult {
                    method: "GET".to_string(),
                    path: "/ok".to_string(),
                    status: Some(200),
                    latency_ms: Some(12),
                    outcome: ValidationOutcome::Success,
                    response_excerpt: None,
                    likely_cause: None,
                    suggested_fix: None,
                    allowed: false,
                },
                ValidationResult {
                    method: "POST".to_string(),
                    path: "/broken".to_string(),
                    status: Some(500),
                    latency_ms: Some(34),
                    outcome: ValidationOutcome::Failure(FailureKind::ServerError),
                    response_excerpt: Some("pipe | content".to_string()),
                    likely_cause: Some("backend".to_string()),
                    suggested_fix: Some("restart".to_string()),
                    allowed: false,
                },
            ],
        };

        let markdown = report.to_markdown();
        assert!(markdown.contains("pipe ❘ content"));
        assert!(!markdown.contains("pipe | content"));
        assert!(markdown.contains("Total endpoints: 2"));
        assert!(markdown.contains("Successful: 1"));
        assert!(markdown.contains("Failures: 1 (allowlisted: 0)"));
        assert!(markdown.contains("| Method | Path | Status |"));
    }

    #[test]
    fn report_to_markdown_without_failures_is_minimal() {
        let report = ValidationReport {
            base_url: "https://validator.test".to_string(),
            results: vec![ValidationResult {
                method: "GET".to_string(),
                path: "/ok".to_string(),
                status: Some(200),
                latency_ms: Some(10),
                outcome: ValidationOutcome::Success,
                response_excerpt: None,
                likely_cause: None,
                suggested_fix: None,
                allowed: false,
            }],
        };

        let markdown = report.to_markdown();
        assert!(markdown.contains("No failing endpoints detected."));
        assert!(markdown.contains("Successful: 1"));
        assert!(markdown.contains("Failures: 0 (allowlisted: 0)"));
        assert!(!markdown.contains("| Method |"));
    }

    #[test]
    fn summary_counts_outcomes() {
        let report = ValidationReport {
            base_url: "https://validator.test".to_string(),
            results: vec![
                ValidationResult {
                    method: "GET".to_string(),
                    path: "/ok".to_string(),
                    status: Some(200),
                    latency_ms: Some(10),
                    outcome: ValidationOutcome::Success,
                    response_excerpt: None,
                    likely_cause: None,
                    suggested_fix: None,
                    allowed: false,
                },
                ValidationResult {
                    method: "GET".to_string(),
                    path: "/allowed".to_string(),
                    status: Some(500),
                    latency_ms: Some(30),
                    outcome: ValidationOutcome::Failure(FailureKind::ServerError),
                    response_excerpt: None,
                    likely_cause: None,
                    suggested_fix: None,
                    allowed: true,
                },
                ValidationResult {
                    method: "GET".to_string(),
                    path: "/fail".to_string(),
                    status: Some(404),
                    latency_ms: Some(15),
                    outcome: ValidationOutcome::Failure(FailureKind::Missing),
                    response_excerpt: None,
                    likely_cause: None,
                    suggested_fix: None,
                    allowed: false,
                },
                ValidationResult {
                    method: "DELETE".to_string(),
                    path: "/skip".to_string(),
                    status: None,
                    latency_ms: None,
                    outcome: ValidationOutcome::Skipped {
                        reason: "dangerous".to_string(),
                    },
                    response_excerpt: None,
                    likely_cause: None,
                    suggested_fix: None,
                    allowed: true,
                },
            ],
        };

        let summary = report.summary();
        assert_eq!(
            summary,
            ValidationSummary {
                total: 4,
                successes: 1,
                failures: 1,
                skipped: 1,
                allowed_failures: 1,
            }
        );
    }
}
