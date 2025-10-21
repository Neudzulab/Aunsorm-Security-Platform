#![allow(clippy::module_name_repetitions)]

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use rand_core::{OsRng, RngCore};
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use signature::Verifier;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use tracing::info;
use url::{ParseError, Url};

use aunsorm_acme::{
    AccountContact, AcmeJws, IdentifierKind, OrderIdentifier, OrderIdentifierError, ReplayNonce,
};

use crate::error::ServerError;

const ORDER_EXPIRATION: Duration = Duration::hours(8);

#[derive(Debug)]
pub struct AcmeService {
    endpoints: AcmeEndpoints,
    directory: DirectoryResponse,
    terms_of_service: Option<String>,
    nonces: Mutex<NonceState>,
    accounts: Mutex<AccountStore>,
    orders: Mutex<HashMap<String, AcmeOrder>>,
    next_account: AtomicU64,
    next_order: AtomicU64,
}

impl AcmeService {
    pub fn new(base_url: &str) -> Result<Self, ServerError> {
        let mut base = Url::parse(base_url).map_err(|err| {
            ServerError::Configuration(format!("ACME taban URL'i geçersiz: {err}"))
        })?;
        if !base.path().ends_with('/') {
            let mut path = base.path().to_owned();
            if !path.ends_with('/') {
                path.push('/');
            }
            base.set_path(&path);
        }

        let endpoints = AcmeEndpoints::try_new(&base).map_err(|err| {
            ServerError::Configuration(format!("ACME endpoint'leri oluşturulamadı: {err}"))
        })?;

        let terms = endpoints
            .base
            .join("docs/terms-of-service")
            .ok()
            .map(|url| url.to_string());
        let website = endpoints.base.join("docs").ok().map(|url| url.to_string());

        let directory = DirectoryResponse::new(&endpoints, terms.clone(), website);

        Ok(Self {
            endpoints,
            directory,
            terms_of_service: terms,
            nonces: Mutex::new(NonceState::default()),
            accounts: Mutex::new(AccountStore::default()),
            orders: Mutex::new(HashMap::new()),
            next_account: AtomicU64::new(0),
            next_order: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn directory_document(&self) -> DirectoryResponse {
        self.directory.clone()
    }

    #[must_use]
    pub const fn directory_url(&self) -> &Url {
        &self.endpoints.directory
    }

    #[must_use]
    pub const fn new_nonce_url(&self) -> &Url {
        &self.endpoints.new_nonce
    }

    #[must_use]
    pub const fn new_account_url(&self) -> &Url {
        &self.endpoints.new_account
    }

    #[must_use]
    pub const fn new_order_url(&self) -> &Url {
        &self.endpoints.new_order
    }

    pub async fn issue_nonce(&self) -> String {
        let mut guard = self.nonces.lock().await;
        guard.issue()
    }

    async fn consume_nonce(&self, nonce: &str) -> Result<(), AcmeProblem> {
        let parsed = ReplayNonce::parse(nonce).map_err(|_| AcmeProblem::bad_nonce())?;
        let mut guard = self.nonces.lock().await;
        if guard.consume(&parsed) {
            Ok(())
        } else {
            Err(AcmeProblem::bad_nonce())
        }
    }

    pub async fn handle_new_account(&self, jws: AcmeJws) -> Result<NewAccountOutcome, AcmeProblem> {
        let header = parse_protected_header(&jws.protected)?;
        if header.url != self.endpoints.new_account.as_str() {
            return Err(AcmeProblem::malformed(
                "protected header içindeki url new-account uç noktasını göstermeli",
            ));
        }
        if header.kid.is_some() {
            return Err(AcmeProblem::malformed(
                "newAccount isteği kid alanı içeremez",
            ));
        }
        let account_jwk = header
            .jwk
            .ok_or_else(|| AcmeProblem::malformed("newAccount isteği JWK içermeli"))?;
        let (key, thumbprint) = parse_account_key(&header.alg, account_jwk)?;
        self.consume_nonce(&header.nonce).await?;
        verify_signature(&key, &jws)?;
        let IncomingNewAccountPayload {
            contact,
            terms_of_service_agreed,
            only_return_existing,
            external_account_binding,
        } = parse_new_account_payload(&jws.payload)?;
        let contacts = normalize_contacts(&contact)?;
        let created_at = OffsetDateTime::now_utc();

        let existing = {
            let mut accounts = self.accounts.lock().await;
            accounts
                .get_by_thumbprint_mut(&thumbprint)
                .map(|account| {
                    if !only_return_existing {
                        account.contacts.clone_from(&contacts);
                        account.terms_of_service_agreed = terms_of_service_agreed;
                    }
                    AccountResponse::from_account(account)
                })
                .map(|response| NewAccountOutcome {
                    location: response.kid.clone(),
                    status: StatusCode::OK,
                    link_terms: self.terms_of_service.clone(),
                    response,
                })
        };

        if let Some(outcome) = existing {
            return Ok(outcome);
        }

        if only_return_existing {
            return Err(AcmeProblem::account_does_not_exist());
        }

        let account_id = format!(
            "acct-{:016x}",
            self.next_account.fetch_add(1, Ordering::SeqCst) + 1
        );
        let location = self
            .endpoints
            .account_url(&account_id)
            .map_err(|err| {
                AcmeProblem::server_internal(format!("Hesap URL'i oluşturulamadı: {err}"))
            })?
            .to_string();
        let orders_url = self
            .endpoints
            .account_orders_url(&account_id)
            .map_err(|err| {
                AcmeProblem::server_internal(format!("Order URL'i oluşturulamadı: {err}"))
            })?
            .to_string();

        let account = AcmeAccount {
            id: account_id,
            location: location.clone(),
            orders_url: orders_url.clone(),
            thumbprint,
            key,
            contacts: contacts.clone(),
            terms_of_service_agreed,
            created_at,
            _external_account_binding: external_account_binding,
        };
        let response = AccountResponse::from_account(&account);
        self.accounts.lock().await.insert_new(account);
        Ok(NewAccountOutcome {
            response,
            location,
            status: StatusCode::CREATED,
            link_terms: self.terms_of_service.clone(),
        })
    }

    #[allow(clippy::too_many_lines)] // ACME RFC 8555 validations require a single flow for clarity
    pub async fn handle_new_order(&self, jws: AcmeJws) -> Result<NewOrderOutcome, AcmeProblem> {
        let header = parse_protected_header(&jws.protected)?;
        if header.url != self.endpoints.new_order.as_str() {
            return Err(AcmeProblem::malformed(
                "protected header içindeki url new-order uç noktasını göstermeli",
            ));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AcmeProblem::malformed("newOrder isteği kid alanı içermeli"))?;
        if header.jwk.is_some() {
            return Err(AcmeProblem::malformed(
                "newOrder isteği JWK taşıyamaz; mevcut hesabın kid'i kullanılmalıdır",
            ));
        }

        self.consume_nonce(&header.nonce).await?;

        let accounts = self.accounts.lock().await;
        let account = accounts
            .get_by_kid(kid)
            .ok_or_else(|| AcmeProblem::unauthorized("Hesap bulunamadı"))?;
        verify_signature(&account.key, &jws)?;
        let payload = parse_new_order_payload(&jws.payload)?;
        drop(accounts);

        let IncomingNewOrderPayload {
            identifiers: identifier_payloads,
            not_before,
            not_after,
        } = payload;
        if let (Some(nb), Some(na)) = (not_before, not_after) {
            if na < nb {
                return Err(AcmeProblem::malformed(
                    "notAfter değeri notBefore değerinden önce olamaz",
                ));
            }
        }

        let identifiers = convert_identifiers(&identifier_payloads)?;
        let now = OffsetDateTime::now_utc();
        let expires = now + ORDER_EXPIRATION;
        let order_id = format!(
            "ord-{:016x}",
            self.next_order.fetch_add(1, Ordering::SeqCst) + 1
        );
        let order_url = self
            .endpoints
            .order_url(&order_id)
            .map_err(|err| {
                AcmeProblem::server_internal(format!("Order URL'i oluşturulamadı: {err}"))
            })?
            .to_string();
        let finalize = self
            .endpoints
            .order_finalize_url(&order_id)
            .map_err(|err| {
                AcmeProblem::server_internal(format!("Finalize URL'i oluşturulamadı: {err}"))
            })?
            .to_string();

        let mut authorizations = Vec::with_capacity(identifiers.len());
        for (index, _) in identifiers.iter().enumerate() {
            let url = self
                .endpoints
                .authorization_url(&order_id, index)
                .map_err(|err| {
                    AcmeProblem::server_internal(format!(
                        "Authorization URL'i oluşturulamadı: {err}"
                    ))
                })?;
            authorizations.push(url.to_string());
        }

        let order = AcmeOrder {
            id: order_id.clone(),
            account_id: kid.to_owned(),
            status: OrderStatus::Pending,
            identifiers,
            not_before,
            not_after,
            expires,
            authorizations,
            finalize,
        };
        let response = order.to_response();
        let account_for_log = order.account_id.clone();

        let mut orders = self.orders.lock().await;
        orders.insert(order.id.clone(), order);
        drop(orders);

        info!(order_id = %order_id, account = %account_for_log, "ACME order oluşturuldu");

        Ok(NewOrderOutcome {
            response,
            location: order_url,
        })
    }

    #[must_use]
    pub fn terms_of_service(&self) -> Option<&str> {
        self.terms_of_service.as_deref()
    }
}

#[derive(Debug, Clone)]
struct AcmeEndpoints {
    base: Url,
    directory: Url,
    new_nonce: Url,
    new_account: Url,
    new_order: Url,
    revoke_cert: Url,
    key_change: Url,
    account_base: Url,
    order_base: Url,
    authz_base: Url,
}

impl AcmeEndpoints {
    fn try_new(base: &Url) -> Result<Self, ParseError> {
        Ok(Self {
            base: base.clone(),
            directory: base.join("acme/directory")?,
            new_nonce: base.join("acme/new-nonce")?,
            new_account: base.join("acme/new-account")?,
            new_order: base.join("acme/new-order")?,
            revoke_cert: base.join("acme/revoke-cert")?,
            key_change: base.join("acme/key-change")?,
            account_base: base.join("acme/account/")?,
            order_base: base.join("acme/order/")?,
            authz_base: base.join("acme/authz/")?,
        })
    }

    fn account_url(&self, id: &str) -> Result<Url, ParseError> {
        self.account_base.join(id)
    }

    fn account_orders_url(&self, id: &str) -> Result<Url, ParseError> {
        self.account_url(id)?.join("orders")
    }

    fn order_url(&self, id: &str) -> Result<Url, ParseError> {
        self.order_base.join(id)
    }

    fn order_finalize_url(&self, id: &str) -> Result<Url, ParseError> {
        self.order_url(id)?.join("finalize")
    }

    fn authorization_url(&self, order_id: &str, index: usize) -> Result<Url, ParseError> {
        self.authz_base.join(&format!("{order_id}-{index:02}"))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryResponse {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
    #[serde(rename = "revokeCert")]
    revoke_cert: String,
    #[serde(rename = "keyChange")]
    key_change: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<DirectoryMeta>,
}

impl DirectoryResponse {
    fn new(endpoints: &AcmeEndpoints, terms: Option<String>, website: Option<String>) -> Self {
        let meta = Some(DirectoryMeta {
            terms_of_service: terms,
            website,
            caa_identities: vec!["aunsorm.example".to_string()],
            external_account_required: false,
        });
        Self {
            new_nonce: endpoints.new_nonce.to_string(),
            new_account: endpoints.new_account.to_string(),
            new_order: endpoints.new_order.to_string(),
            revoke_cert: endpoints.revoke_cert.to_string(),
            key_change: endpoints.key_change.to_string(),
            meta,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct DirectoryMeta {
    #[serde(rename = "termsOfService", skip_serializing_if = "Option::is_none")]
    terms_of_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    website: Option<String>,
    #[serde(rename = "caaIdentities")]
    caa_identities: Vec<String>,
    #[serde(rename = "externalAccountRequired")]
    external_account_required: bool,
}

#[derive(Debug, Default)]
struct NonceState {
    minted: HashSet<String>,
}

impl NonceState {
    fn issue(&mut self) -> String {
        loop {
            let mut bytes = [0_u8; 16];
            OsRng.fill_bytes(&mut bytes);
            let value = URL_SAFE_NO_PAD.encode(bytes);
            if self.minted.insert(value.clone()) {
                return value;
            }
        }
    }

    fn consume(&mut self, nonce: &ReplayNonce) -> bool {
        self.minted.remove(nonce.as_str())
    }
}

#[derive(Debug, Default)]
struct AccountStore {
    accounts: HashMap<String, AcmeAccount>,
    by_thumbprint: HashMap<String, String>,
    by_kid: HashMap<String, String>,
}

impl AccountStore {
    fn get_by_thumbprint_mut(&mut self, thumbprint: &str) -> Option<&mut AcmeAccount> {
        let id = self.by_thumbprint.get(thumbprint)?;
        self.accounts.get_mut(id)
    }

    fn get_by_kid(&self, kid: &str) -> Option<&AcmeAccount> {
        let id = self.by_kid.get(kid)?;
        self.accounts.get(id)
    }

    fn insert_new(&mut self, account: AcmeAccount) {
        let thumbprint = account.thumbprint.clone();
        let kid = account.location.clone();
        let id = account.id.clone();
        self.accounts.insert(id.clone(), account);
        self.by_thumbprint.insert(thumbprint, id.clone());
        self.by_kid.insert(kid, id);
    }
}

#[derive(Debug)]
struct AcmeAccount {
    id: String,
    location: String,
    orders_url: String,
    thumbprint: String,
    key: AccountKey,
    contacts: Vec<String>,
    terms_of_service_agreed: bool,
    created_at: OffsetDateTime,
    _external_account_binding: Option<Value>,
}

impl AcmeAccount {
    fn contacts(&self) -> Vec<String> {
        self.contacts.clone()
    }
}

#[derive(Debug)]
struct AcmeOrder {
    id: String,
    account_id: String,
    status: OrderStatus,
    identifiers: Vec<OrderIdentifier>,
    not_before: Option<OffsetDateTime>,
    not_after: Option<OffsetDateTime>,
    expires: OffsetDateTime,
    authorizations: Vec<String>,
    finalize: String,
}

impl AcmeOrder {
    fn to_response(&self) -> OrderResponse {
        OrderResponse {
            status: self.status.as_str(),
            identifiers: self
                .identifiers
                .iter()
                .map(OrderIdentifierBody::from_identifier)
                .collect(),
            authorizations: self.authorizations.clone(),
            finalize: self.finalize.clone(),
            expires: self.expires,
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum OrderStatus {
    Pending,
}

impl OrderStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
        }
    }
}

#[derive(Debug, Clone)]
enum AccountKey {
    Ed25519(Ed25519VerifyingKey),
    Es256(P256VerifyingKey),
    Rs256(RsaVerifyingKey<Sha256>),
}

impl AccountKey {
    fn verify(&self, signing_input: &[u8], signature_b64: &str) -> Result<(), AcmeProblem> {
        let signature_bytes = decode_base64(signature_b64)
            .map_err(|_| AcmeProblem::bad_signature("İmza base64 olarak çözülemedi"))?;
        match self {
            Self::Ed25519(key) => {
                let signature = Ed25519Signature::try_from(signature_bytes.as_slice())
                    .map_err(|_| AcmeProblem::bad_signature("Ed25519 imzası ayrıştırılamadı"))?;
                key.verify_strict(signing_input, &signature)
                    .map_err(|_| AcmeProblem::bad_signature("Ed25519 imzası doğrulanamadı"))
            }
            Self::Es256(key) => {
                let signature = P256Signature::from_der(&signature_bytes).map_err(|_| {
                    AcmeProblem::bad_signature("ES256 imzası DER olarak ayrıştırılamadı")
                })?;
                key.verify(signing_input, &signature)
                    .map_err(|_| AcmeProblem::bad_signature("ES256 imzası doğrulanamadı"))
            }
            Self::Rs256(key) => {
                let signature = RsaSignature::try_from(signature_bytes.as_slice())
                    .map_err(|_| AcmeProblem::bad_signature("RS256 imzası ayrıştırılamadı"))?;
                key.verify(signing_input, &signature)
                    .map_err(|_| AcmeProblem::bad_signature("RS256 imzası doğrulanamadı"))
            }
        }
    }
}

#[derive(Debug)]
pub struct NewAccountOutcome {
    pub response: AccountResponse,
    pub location: String,
    pub status: StatusCode,
    pub link_terms: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AccountResponse {
    status: &'static str,
    contact: Vec<String>,
    orders: String,
    #[serde(rename = "termsOfServiceAgreed")]
    terms_of_service_agreed: bool,
    kid: String,
    #[serde(rename = "createdAt", with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl AccountResponse {
    fn from_account(account: &AcmeAccount) -> Self {
        Self {
            status: "valid",
            contact: account.contacts(),
            orders: account.orders_url.clone(),
            terms_of_service_agreed: account.terms_of_service_agreed,
            kid: account.location.clone(),
            created_at: account.created_at,
        }
    }
}

#[derive(Debug)]
pub struct NewOrderOutcome {
    pub response: OrderResponse,
    pub location: String,
}

#[derive(Debug, Serialize)]
pub struct OrderResponse {
    status: &'static str,
    identifiers: Vec<OrderIdentifierBody>,
    authorizations: Vec<String>,
    finalize: String,
    #[serde(with = "time::serde::rfc3339")]
    expires: OffsetDateTime,
    #[serde(
        rename = "notBefore",
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    not_before: Option<OffsetDateTime>,
    #[serde(
        rename = "notAfter",
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    not_after: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
struct OrderIdentifierBody {
    #[serde(rename = "type")]
    ty: &'static str,
    value: String,
}

impl OrderIdentifierBody {
    fn from_identifier(identifier: &OrderIdentifier) -> Self {
        let ty = match identifier.kind() {
            IdentifierKind::Dns => "dns",
            IdentifierKind::Ip => "ip",
        };
        Self {
            ty,
            value: identifier.value().into_owned(),
        }
    }
}

#[derive(Debug)]
pub struct AcmeProblem {
    status: StatusCode,
    problem_type: &'static str,
    detail: String,
}

impl AcmeProblem {
    fn new(status: StatusCode, problem_type: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            problem_type,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub fn body(&self) -> ProblemBody {
        ProblemBody {
            problem_type: self.problem_type,
            detail: self.detail.clone(),
            status: self.status.as_u16(),
        }
    }

    pub fn bad_nonce() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:badNonce",
            "Replay-Nonce değeri geçersiz veya daha önce kullanıldı",
        )
    }

    fn bad_signature(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:badSignature",
            detail,
        )
    }

    fn bad_signature_algorithm(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:badSignatureAlgorithm",
            detail,
        )
    }

    pub(crate) fn malformed(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:malformed",
            detail,
        )
    }

    fn invalid_contact(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:invalidContact",
            detail,
        )
    }

    fn account_does_not_exist() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:accountDoesNotExist",
            "Belirtilen hesap mevcut değil",
        )
    }

    fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "urn:ietf:params:acme:error:unauthorized",
            detail,
        )
    }

    pub(crate) fn server_internal(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "urn:ietf:params:acme:error:serverInternal",
            detail,
        )
    }
}

#[derive(Debug, Serialize)]
pub struct ProblemBody {
    #[serde(rename = "type")]
    problem_type: &'static str,
    detail: String,
    status: u16,
}

#[derive(Debug, Deserialize)]
struct ProtectedHeader {
    alg: String,
    nonce: String,
    url: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    jwk: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct IncomingNewAccountPayload {
    #[serde(default)]
    contact: Vec<String>,
    #[serde(rename = "termsOfServiceAgreed", default)]
    terms_of_service_agreed: bool,
    #[serde(rename = "onlyReturnExisting", default)]
    only_return_existing: bool,
    #[serde(rename = "externalAccountBinding")]
    external_account_binding: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct IncomingNewOrderPayload {
    identifiers: Vec<IdentifierPayload>,
    #[serde(rename = "notBefore", default, with = "time::serde::rfc3339::option")]
    not_before: Option<OffsetDateTime>,
    #[serde(rename = "notAfter", default, with = "time::serde::rfc3339::option")]
    not_after: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize)]
struct IdentifierPayload {
    #[serde(rename = "type")]
    ty: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct OkpJwk {
    kty: String,
    crv: String,
    x: String,
}

#[derive(Debug, Deserialize)]
struct EcJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Deserialize)]
struct RsaJwk {
    kty: String,
    n: String,
    e: String,
}

fn parse_protected_header(encoded: &str) -> Result<ProtectedHeader, AcmeProblem> {
    let bytes = decode_base64(encoded)
        .map_err(|_| AcmeProblem::malformed("protected header base64 olarak çözülemedi"))?;
    serde_json::from_slice(&bytes).map_err(|err| {
        AcmeProblem::malformed(format!("protected header JSON ayrıştırılamadı: {err}"))
    })
}

fn parse_new_account_payload(encoded: &str) -> Result<IncomingNewAccountPayload, AcmeProblem> {
    let bytes =
        decode_base64(encoded).map_err(|_| AcmeProblem::malformed("payload base64 çözülemedi"))?;
    serde_json::from_slice(&bytes).map_err(|err| {
        AcmeProblem::malformed(format!("newAccount payload JSON ayrıştırılamadı: {err}"))
    })
}

fn parse_new_order_payload(encoded: &str) -> Result<IncomingNewOrderPayload, AcmeProblem> {
    let bytes =
        decode_base64(encoded).map_err(|_| AcmeProblem::malformed("payload base64 çözülemedi"))?;
    serde_json::from_slice(&bytes).map_err(|err| {
        AcmeProblem::malformed(format!("newOrder payload JSON ayrıştırılamadı: {err}"))
    })
}

fn normalize_contacts(values: &[String]) -> Result<Vec<String>, AcmeProblem> {
    values
        .iter()
        .map(|value| {
            AccountContact::from_uri(value)
                .map(|contact| contact.uri().to_owned())
                .map_err(|err| {
                    AcmeProblem::invalid_contact(format!("Geçersiz iletişim girdisi: {err}"))
                })
        })
        .collect()
}

fn convert_identifiers(payload: &[IdentifierPayload]) -> Result<Vec<OrderIdentifier>, AcmeProblem> {
    if payload.is_empty() {
        return Err(AcmeProblem::malformed(
            "newOrder isteği en az bir identifier içermelidir",
        ));
    }

    payload
        .iter()
        .map(|identifier| match identifier.ty.as_str() {
            "dns" => OrderIdentifier::dns(&identifier.value).map_err(|err| match err {
                OrderIdentifierError::EmptyDns => {
                    AcmeProblem::malformed("DNS identifier değeri boş olamaz")
                }
                OrderIdentifierError::InvalidDns { value } => {
                    AcmeProblem::malformed(format!("DNS identifier değeri geçersiz: {value}"))
                }
                OrderIdentifierError::InvalidIp { .. } => {
                    AcmeProblem::malformed("DNS identifier IP adresi olamaz")
                }
            }),
            "ip" => OrderIdentifier::ip(&identifier.value).map_err(|err| {
                AcmeProblem::malformed(format!("IP identifier değeri ayrıştırılamadı: {err}"))
            }),
            other => Err(AcmeProblem::malformed(format!(
                "Desteklenmeyen identifier türü: {other}"
            ))),
        })
        .collect()
}

fn parse_account_key(alg: &str, jwk: Value) -> Result<(AccountKey, String), AcmeProblem> {
    match alg {
        "EdDSA" => {
            let jwk: OkpJwk = serde_json::from_value(jwk).map_err(|err| {
                AcmeProblem::bad_signature_algorithm(format!("Ed25519 JWK ayrıştırılamadı: {err}"))
            })?;
            if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
                return Err(AcmeProblem::bad_signature_algorithm(
                    "Ed25519 JWK bekleniyordu",
                ));
            }
            let key_bytes = decode_base64(&jwk.x).map_err(|_| {
                AcmeProblem::bad_signature_algorithm(
                    "Ed25519 JWK x alanı base64url olarak çözülemedi",
                )
            })?;
            let bytes: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
                AcmeProblem::bad_signature_algorithm("Ed25519 anahtar uzunluğu 32 bayt olmalı")
            })?;
            let verifying = Ed25519VerifyingKey::from_bytes(&bytes)
                .map_err(|_| AcmeProblem::bad_signature_algorithm("Ed25519 anahtarı geçersiz"))?;
            let thumbprint = compute_thumbprint(&[
                ("crv", jwk.crv.as_str()),
                ("kty", jwk.kty.as_str()),
                ("x", jwk.x.as_str()),
            ]);
            Ok((AccountKey::Ed25519(verifying), thumbprint))
        }
        "ES256" => {
            let jwk: EcJwk = serde_json::from_value(jwk).map_err(|err| {
                AcmeProblem::bad_signature_algorithm(format!("ES256 JWK ayrıştırılamadı: {err}"))
            })?;
            if jwk.kty != "EC" || jwk.crv != "P-256" {
                return Err(AcmeProblem::bad_signature_algorithm(
                    "ES256 JWK bekleniyordu",
                ));
            }
            let x = decode_base64(&jwk.x).map_err(|_| {
                AcmeProblem::bad_signature_algorithm("ES256 JWK x alanı çözülemedi")
            })?;
            let y = decode_base64(&jwk.y).map_err(|_| {
                AcmeProblem::bad_signature_algorithm("ES256 JWK y alanı çözülemedi")
            })?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AcmeProblem::bad_signature_algorithm(
                    "ES256 koordinat uzunluğu 32 bayt olmalı",
                ));
            }
            let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let verifying = P256VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| {
                AcmeProblem::bad_signature_algorithm("ES256 anahtarı doğrulanamadı")
            })?;
            let thumbprint = compute_thumbprint(&[
                ("crv", jwk.crv.as_str()),
                ("kty", jwk.kty.as_str()),
                ("x", jwk.x.as_str()),
                ("y", jwk.y.as_str()),
            ]);
            Ok((AccountKey::Es256(verifying), thumbprint))
        }
        "RS256" => {
            let jwk: RsaJwk = serde_json::from_value(jwk).map_err(|err| {
                AcmeProblem::bad_signature_algorithm(format!("RS256 JWK ayrıştırılamadı: {err}"))
            })?;
            if jwk.kty != "RSA" {
                return Err(AcmeProblem::bad_signature_algorithm("RSA JWK bekleniyordu"));
            }
            let n = decode_base64(&jwk.n).map_err(|_| {
                AcmeProblem::bad_signature_algorithm("RSA modülü base64 çözülemedi")
            })?;
            let e = decode_base64(&jwk.e)
                .map_err(|_| AcmeProblem::bad_signature_algorithm("RSA üssü base64 çözülemedi"))?;
            let modulus = BigUint::from_bytes_be(&n);
            let exponent = BigUint::from_bytes_be(&e);
            let public = RsaPublicKey::new(modulus, exponent).map_err(|err| {
                AcmeProblem::bad_signature_algorithm(format!("RSA anahtarı geçersiz: {err}"))
            })?;
            let verifying = RsaVerifyingKey::<Sha256>::new(public);
            let thumbprint = compute_thumbprint(&[
                ("e", jwk.e.as_str()),
                ("kty", jwk.kty.as_str()),
                ("n", jwk.n.as_str()),
            ]);
            Ok((AccountKey::Rs256(verifying), thumbprint))
        }
        other => Err(AcmeProblem::bad_signature_algorithm(format!(
            "Desteklenmeyen imza algoritması: {other}"
        ))),
    }
}

fn verify_signature(key: &AccountKey, jws: &AcmeJws) -> Result<(), AcmeProblem> {
    let signing_input = format!("{}.{}", jws.protected, jws.payload);
    key.verify(signing_input.as_bytes(), &jws.signature)
}

fn compute_thumbprint(entries: &[(&str, &str)]) -> String {
    let mut sorted = entries.to_vec();
    sorted.sort_unstable_by(|lhs, rhs| lhs.0.cmp(rhs.0));
    let mut serialized = String::from("{");
    for (index, (name, value)) in sorted.iter().enumerate() {
        if index > 0 {
            serialized.push(',');
        }
        serialized.push('"');
        serialized.push_str(name);
        serialized.push_str("\":\"");
        serialized.push_str(value);
        serialized.push('"');
    }
    serialized.push('}');
    let digest = Sha256::digest(serialized.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(value)
}
