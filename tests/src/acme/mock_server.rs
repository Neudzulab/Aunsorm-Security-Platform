use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aunsorm_acme::{ReplayNonce, REPLAY_NONCE_HEADER};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Clone)]
pub struct MockAcmeServer {
    base_url: String,
    state: MockAcmeState,
}

impl MockAcmeServer {
    pub fn letsencrypt_like() -> Self {
        Self::with_allowed_domains(["example.org", "www.example.org", "api.example.org"])
    }

    pub fn with_allowed_domains<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let base_url = "https://mock-acme.invalid".to_owned();
        let state = MockAcmeState::new(base_url.clone(), domains);

        Self { base_url, state }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn state(&self) -> MockAcmeState {
        self.state.clone()
    }
}

#[derive(Clone)]
struct MockAcmeState {
    inner: Arc<MockAcmeInner>,
}

struct MockAcmeInner {
    base_url: String,
    directory: Arc<Value>,
    allowed_domains: HashSet<String>,
    require_contact_email: bool,
    nonce_counter: AtomicU64,
    account_counter: AtomicU64,
    order_counter: AtomicU64,
}

impl MockAcmeState {
    fn new<I, S>(base_url: String, allowed_domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let allowed_domains = allowed_domains.into_iter().map(Into::into).collect();
        let directory = Arc::new(directory_document(&base_url));

        Self {
            inner: Arc::new(MockAcmeInner {
                base_url,
                directory,
                allowed_domains,
                require_contact_email: true,
                nonce_counter: AtomicU64::new(0),
                account_counter: AtomicU64::new(0),
                order_counter: AtomicU64::new(0),
            }),
        }
    }

    fn directory(&self) -> Value {
        self.inner.directory.as_ref().clone()
    }

    fn attach_nonce(&self, response: &mut Response) {
        let nonce = self.issue_nonce();
        let value = HeaderValue::from_str(&nonce).expect("nonce header");
        response.headers_mut().insert(REPLAY_NONCE_HEADER, value);
    }

    fn issue_nonce(&self) -> String {
        let current = self.inner.nonce_counter.fetch_add(1, Ordering::Relaxed) + 1;
        URL_SAFE_NO_PAD.encode(current.to_be_bytes())
    }

    fn next_account_id(&self) -> u64 {
        self.inner.account_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn next_order_id(&self) -> u64 {
        self.inner.order_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn account_url(&self, account_id: u64) -> String {
        format!("{}/acme/account/{}", self.inner.base_url, account_id)
    }

    fn orders_url(&self, account_id: u64) -> String {
        format!("{}/acme/account/{}/orders", self.inner.base_url, account_id)
    }

    fn order_url(&self, order_id: u64) -> String {
        format!("{}/acme/order/{}", self.inner.base_url, order_id)
    }

    fn finalize_url(&self, order_id: u64) -> String {
        format!("{}/acme/order/{}/finalize", self.inner.base_url, order_id)
    }

    fn authorizations(&self, identifiers: &[OrderIdentifier]) -> Vec<String> {
        identifiers
            .iter()
            .map(|identifier| {
                let path_fragment = identifier.value.replace('.', "-");
                format!("{}/acme/authz/{}", self.inner.base_url, path_fragment)
            })
            .collect()
    }

    fn is_domain_allowed(&self, domain: &str) -> bool {
        self.inner.allowed_domains.contains(domain)
    }

    fn json_response(&self, status: StatusCode, payload: Value) -> Response {
        let mut response = (status, Json(payload)).into_response();
        self.attach_nonce(&mut response);
        response
    }

    fn problem_response(
        &self,
        status: StatusCode,
        error_type: &str,
        detail: impl Into<String>,
    ) -> Response {
        let detail = detail.into();
        let payload = json!({
            "type": error_type,
            "detail": detail,
            "status": status.as_u16(),
        });
        self.json_response(status, payload)
    }
}

fn directory_document(base_url: &str) -> Value {
    json!({
        "newNonce": format!("{base_url}/acme/new-nonce"),
        "newAccount": format!("{base_url}/acme/new-account"),
        "newOrder": format!("{base_url}/acme/new-order"),
        "revokeCert": format!("{base_url}/acme/revoke-cert"),
        "keyChange": format!("{base_url}/acme/key-change"),
        "newAuthz": format!("{base_url}/acme/new-authz"),
        "renewalInfo": format!("{base_url}/acme/renewal-info"),
        "meta": {
            "termsOfService": format!("{base_url}/terms-of-service"),
            "website": "https://docs.aunsorm.example/acme",
            "caaIdentities": ["letsencrypt.org", "aunsorm.example"],
            "externalAccountRequired": false,
        }
    })
}

#[allow(clippy::unused_async)] // Axum handlers require async signatures.
async fn directory_handler(State(state): State<MockAcmeState>) -> Response {
    state.json_response(StatusCode::OK, state.directory())
}

#[allow(clippy::unused_async)] // Axum handlers require async signatures.
async fn new_nonce_handler(State(state): State<MockAcmeState>) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    state.attach_nonce(&mut response);
    response
}

#[derive(Debug, Clone, Deserialize)]
struct NewAccountRequest {
    contact: Vec<String>,
    #[serde(rename = "termsOfServiceAgreed")]
    terms_of_service_agreed: bool,
}

#[allow(clippy::unused_async)] // Axum handlers require async signatures.
async fn new_account_handler(
    State(state): State<MockAcmeState>,
    Json(payload): Json<NewAccountRequest>,
) -> Response {
    if state.inner.require_contact_email
        && payload
            .contact
            .iter()
            .all(|contact| !contact.starts_with("mailto:"))
    {
        return state.problem_response(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:malformed",
            "en az bir mailto: contact adresi gerekli".to_owned(),
        );
    }

    if !payload.terms_of_service_agreed {
        return state.problem_response(
            StatusCode::PRECONDITION_REQUIRED,
            "urn:ietf:params:acme:error:userActionRequired",
            "kullanım şartları kabul edilmelidir".to_owned(),
        );
    }

    let account_id = state.next_account_id();
    let account_url = state.account_url(account_id);
    let orders_url = state.orders_url(account_id);

    let mut response = state.json_response(
        StatusCode::CREATED,
        json!({
            "status": "valid",
            "contact": payload.contact,
            "orders": orders_url,
        }),
    );

    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&account_url).expect("account header"),
    );
    response
}

#[derive(Debug, Clone, Deserialize)]
struct OrderIdentifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

#[derive(Debug, Clone, Deserialize)]
struct NewOrderRequest {
    identifiers: Vec<OrderIdentifier>,
}

#[allow(clippy::unused_async)] // Axum handlers require async signatures.
async fn new_order_handler(
    State(state): State<MockAcmeState>,
    Json(payload): Json<NewOrderRequest>,
) -> Response {
    if payload.identifiers.is_empty() {
        return state.problem_response(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:malformed",
            "en az bir identifier belirtilmelidir".to_owned(),
        );
    }

    for identifier in &payload.identifiers {
        if identifier.kind != "dns" {
            return state.problem_response(
                StatusCode::BAD_REQUEST,
                "urn:ietf:params:acme:error:unsupportedIdentifier",
                format!("desteklenmeyen identifier türü: {}", identifier.kind),
            );
        }

        if !state.is_domain_allowed(&identifier.value) {
            return state.problem_response(
                StatusCode::FORBIDDEN,
                "urn:ietf:params:acme:error:rejectedIdentifier",
                format!("yetkisiz alan adı: {}", identifier.value),
            );
        }
    }

    let order_id = state.next_order_id();
    let order_url = state.order_url(order_id);
    let finalize_url = state.finalize_url(order_id);
    let authorizations = state.authorizations(&payload.identifiers);
    let identifiers: Vec<Value> = payload
        .identifiers
        .iter()
        .map(|identifier| {
            json!({
                "type": identifier.kind,
                "value": identifier.value,
            })
        })
        .collect();

    let mut response = state.json_response(
        StatusCode::CREATED,
        json!({
            "status": "pending",
            "expires": "2024-01-01T00:00:00Z",
            "identifiers": identifiers,
            "authorizations": authorizations,
            "finalize": finalize_url,
        }),
    );

    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&order_url).expect("order header"),
    );
    response
}

#[tokio::test]
async fn happy_path_account_and_order_flow() {
    let server = MockAcmeServer::letsencrypt_like();
    let base_url = server.base_url().to_owned();
    let state = server.state();

    let directory_response = directory_handler(State(state.clone())).await;

    assert_eq!(directory_response.status(), StatusCode::OK);
    let nonce = directory_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("directory nonce");
    ReplayNonce::parse(nonce).expect("nonce parse");

    let directory_body = directory_response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let document: Value = serde_json::from_slice(&directory_body).expect("directory json");
    assert_eq!(
        document["newNonce"],
        Value::String(format!("{base_url}/acme/new-nonce"))
    );
    assert_eq!(
        document["newAccount"],
        Value::String(format!("{base_url}/acme/new-account"))
    );

    let nonce_response = new_nonce_handler(State(state.clone())).await;
    assert_eq!(nonce_response.status(), StatusCode::OK);
    let fresh_nonce = nonce_response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("fresh nonce");
    ReplayNonce::parse(fresh_nonce).expect("valid nonce");

    let account_payload = NewAccountRequest {
        contact: vec!["mailto:infra@example.org".to_owned()],
        terms_of_service_agreed: true,
    };
    let account_response = new_account_handler(State(state.clone()), Json(account_payload)).await;
    assert_eq!(account_response.status(), StatusCode::CREATED);
    let account_location = account_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("account location");
    assert!(account_location.starts_with(&format!("{base_url}/acme/account/")));

    let account_body = account_response
        .into_body()
        .collect()
        .await
        .expect("account body")
        .to_bytes();
    let account_json: Value = serde_json::from_slice(&account_body).expect("account json");
    assert_eq!(account_json["status"], Value::String("valid".to_owned()));
    assert_eq!(
        account_json["orders"],
        Value::String(format!("{base_url}/acme/account/1/orders"))
    );

    let order_payload = NewOrderRequest {
        identifiers: vec![
            OrderIdentifier {
                kind: "dns".to_owned(),
                value: "example.org".to_owned(),
            },
            OrderIdentifier {
                kind: "dns".to_owned(),
                value: "www.example.org".to_owned(),
            },
        ],
    };
    let order_response = new_order_handler(State(state.clone()), Json(order_payload)).await;
    assert_eq!(order_response.status(), StatusCode::CREATED);
    let order_location = order_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("order location");
    assert!(order_location.starts_with(&format!("{base_url}/acme/order/")));

    let order_body = order_response
        .into_body()
        .collect()
        .await
        .expect("order body")
        .to_bytes();
    let order_json: Value = serde_json::from_slice(&order_body).expect("order json");
    assert_eq!(order_json["status"], Value::String("pending".to_owned()));
    let authorizations = order_json["authorizations"]
        .as_array()
        .expect("authorizations array");
    assert_eq!(authorizations.len(), 2);
    assert!(authorizations[0]
        .as_str()
        .expect("auth url")
        .starts_with(&format!("{base_url}/acme/authz/")));
}

#[tokio::test]
async fn sad_path_rejects_unknown_domain() {
    let server = MockAcmeServer::with_allowed_domains(["example.org"]);
    let state = server.state();
    let payload = NewOrderRequest {
        identifiers: vec![OrderIdentifier {
            kind: "dns".to_owned(),
            value: "forbidden.example".to_owned(),
        }],
    };

    let response = new_order_handler(State(state), Json(payload)).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let nonce = response
        .headers()
        .get(REPLAY_NONCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("error nonce");
    ReplayNonce::parse(nonce).expect("nonce parse");

    let body = response
        .into_body()
        .collect()
        .await
        .expect("error body")
        .to_bytes();
    let problem: Value = serde_json::from_slice(&body).expect("problem json");
    assert_eq!(
        problem["type"],
        Value::String("urn:ietf:params:acme:error:rejectedIdentifier".to_owned())
    );
    assert!(problem["detail"]
        .as_str()
        .expect("detail string")
        .contains("forbidden.example"));
}
