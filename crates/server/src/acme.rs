#![allow(clippy::module_name_repetitions)]

use std::borrow::ToOwned;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::rng::AunsormNativeRng;
use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use pem::Pem;
use rand_core::RngCore;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequest, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SerialNumber, PKCS_ED25519,
};
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
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use aunsorm_acme::{
    AccountContact, AcmeJws, IdentifierKind, OrderIdentifier, OrderIdentifierError, ReplayNonce,
};

use crate::error::ServerError;

const ORDER_EXPIRATION: Duration = Duration::hours(8);

pub struct AcmeService {
    endpoints: AcmeEndpoints,
    directory: DirectoryResponse,
    terms_of_service: Option<String>,
    nonces: Mutex<NonceState>,
    accounts: Mutex<AccountStore>,
    orders: Mutex<HashMap<String, AcmeOrder>>,
    ca_certificate: Certificate,
    ca_pem: String,
    issued_certificates: Mutex<HashMap<String, StoredCertificate>>,
    next_account: AtomicU64,
    next_order: AtomicU64,
}

impl fmt::Debug for AcmeService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeService")
            .field("endpoints", &self.endpoints)
            .field("directory", &self.directory)
            .field("terms_of_service", &self.terms_of_service)
            .field("next_account", &self.next_account.load(Ordering::SeqCst))
            .field("next_order", &self.next_order.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
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
        let (ca_certificate, ca_pem) = generate_acme_ca(&endpoints.base)?;

        Ok(Self {
            endpoints,
            directory,
            terms_of_service: terms,
            nonces: Mutex::new(NonceState::default()),
            accounts: Mutex::new(AccountStore::default()),
            orders: Mutex::new(HashMap::new()),
            ca_certificate,
            ca_pem,
            issued_certificates: Mutex::new(HashMap::new()),
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

    #[must_use]
    pub const fn revoke_cert_url(&self) -> &Url {
        &self.endpoints.revoke_cert
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

    pub async fn handle_account_lookup(
        &self,
        account_id: &str,
        jws: AcmeJws,
    ) -> Result<NewAccountOutcome, AcmeProblem> {
        let account_url = self.endpoints.account_url(account_id).map_err(|err| {
            AcmeProblem::server_internal(format!("Hesap URL'i oluşturulamadı: {err}"))
        })?;
        let account_url_string = account_url.to_string();
        let header = parse_protected_header(&jws.protected)?;
        if header.url != account_url_string {
            return Err(AcmeProblem::malformed(
                "protected header içindeki url hesap kaynağını göstermeli",
            ));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AcmeProblem::malformed("account sorgusu kid alanı içermeli"))?;
        if header.jwk.is_some() {
            return Err(AcmeProblem::malformed(
                "account sorgusu JWK taşıyamaz; mevcut hesabın kid'i kullanılmalıdır",
            ));
        }

        self.consume_nonce(&header.nonce).await?;
        ensure_post_as_get_payload(&jws.payload)?;

        let accounts = self.accounts.lock().await;
        let account = accounts
            .get_by_kid(kid)
            .ok_or_else(|| AcmeProblem::unauthorized("Hesap bulunamadı"))?;
        if account.location != account_url_string {
            return Err(AcmeProblem::unauthorized(
                "Hesap isteği farklı bir account kaynağını hedefliyor",
            ));
        }
        let key = account.key.clone();
        let response = AccountResponse::from_account(account);
        let location = account.location.clone();
        drop(accounts);

        verify_signature(&key, &jws)?;

        Ok(NewAccountOutcome {
            response,
            location,
            status: StatusCode::OK,
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
            certificate: None,
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

    pub async fn handle_order_lookup(
        &self,
        order_id: &str,
        jws: AcmeJws,
    ) -> Result<OrderLookupOutcome, AcmeProblem> {
        let order_url = self.endpoints.order_url(order_id).map_err(|err| {
            AcmeProblem::server_internal(format!("Order URL'i oluşturulamadı: {err}"))
        })?;
        let order_url_string = order_url.to_string();
        let header = parse_protected_header(&jws.protected)?;
        if header.url != order_url_string {
            return Err(AcmeProblem::malformed(
                "protected header içindeki url order kaynağını göstermeli",
            ));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AcmeProblem::malformed("order sorgusu kid alanı içermeli"))?;
        if header.jwk.is_some() {
            return Err(AcmeProblem::malformed(
                "order sorgusu JWK taşıyamaz; mevcut hesabın kid'i kullanılmalıdır",
            ));
        }

        self.consume_nonce(&header.nonce).await?;
        ensure_post_as_get_payload(&jws.payload)?;

        let accounts = self.accounts.lock().await;
        let account = accounts
            .get_by_kid(kid)
            .ok_or_else(|| AcmeProblem::unauthorized("Hesap bulunamadı"))?;
        let key = account.key.clone();
        drop(accounts);
        verify_signature(&key, &jws)?;

        let orders = self.orders.lock().await;
        let order = orders
            .get(order_id)
            .ok_or_else(|| AcmeProblem::unauthorized("Order bulunamadı"))?;
        if order.account_id != kid {
            return Err(AcmeProblem::unauthorized(
                "Order belirtilen hesapla ilişkili değil",
            ));
        }
        let response = order.to_response();
        drop(orders);

        Ok(OrderLookupOutcome {
            response,
            location: order_url_string,
        })
    }

    #[allow(clippy::significant_drop_tightening)] // Mutex guard intentionally spans full finalize update for atomicity
    pub async fn handle_finalize_order(
        &self,
        order_id: &str,
        jws: AcmeJws,
    ) -> Result<FinalizeOrderOutcome, AcmeProblem> {
        let finalize_url = self
            .endpoints
            .order_finalize_url(order_id)
            .map_err(|err| {
                AcmeProblem::server_internal(format!("Finalize URL'i oluşturulamadı: {err}"))
            })?
            .to_string();
        let order_url = self
            .endpoints
            .order_url(order_id)
            .map_err(|err| {
                AcmeProblem::server_internal(format!("Order URL'i oluşturulamadı: {err}"))
            })?
            .to_string();
        let certificate_url = self
            .endpoints
            .certificate_url(order_id)
            .map_err(|err| {
                AcmeProblem::server_internal(format!("Certificate URL'i oluşturulamadı: {err}"))
            })?
            .to_string();

        let header = parse_protected_header(&jws.protected)?;
        if header.url != finalize_url {
            return Err(AcmeProblem::malformed(
                "protected header içindeki url finalize uç noktasını göstermeli",
            ));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AcmeProblem::malformed("finalize isteği kid alanı içermeli"))?;
        if header.jwk.is_some() {
            return Err(AcmeProblem::malformed(
                "finalize isteği JWK taşıyamaz; mevcut hesabın kid'i kullanılmalıdır",
            ));
        }

        self.consume_nonce(&header.nonce).await?;

        let accounts = self.accounts.lock().await;
        let account = accounts
            .get_by_kid(kid)
            .ok_or_else(|| AcmeProblem::unauthorized("Hesap bulunamadı"))?;
        verify_signature(&account.key, &jws)?;
        drop(accounts);

        let finalize_payload = parse_finalize_payload(&jws.payload)?;
        let csr_bytes = decode_base64(&finalize_payload.csr)
            .map_err(|_| AcmeProblem::malformed("CSR base64url olarak çözülemedi"))?;
        let (_, csr) = X509CertificationRequest::from_der(&csr_bytes)
            .map_err(|err| AcmeProblem::malformed(format!("CSR ayrıştırılamadı: {err}")))?;
        csr.verify_signature()
            .map_err(|err| AcmeProblem::malformed(format!("CSR imzası doğrulanamadı: {err}")))?;
        let mut signing_request =
            CertificateSigningRequest::from_der(&csr_bytes).map_err(|err| {
                AcmeProblem::malformed(format!("CSR imzalama isteği ayrıştırılamadı: {err}"))
            })?;
        let csr_identifiers = collect_csr_identifiers(&csr)?;

        let (response, not_before, not_after) = {
            let mut orders = self.orders.lock().await;
            let order = orders
                .get_mut(order_id)
                .ok_or_else(|| AcmeProblem::unauthorized("Order bulunamadı"))?;
            if order.account_id != kid {
                return Err(AcmeProblem::unauthorized(
                    "Order belirtilen hesapla ilişkili değil",
                ));
            }
            if OffsetDateTime::now_utc() > order.expires {
                return Err(AcmeProblem::malformed("Order süresi doldu"));
            }
            ensure_identifiers_covered(&csr_identifiers, &order.identifiers)?;

            if matches!(order.status, OrderStatus::Valid) {
                if order.certificate.is_none() {
                    order.certificate = Some(certificate_url.clone());
                }
            } else {
                order.status = OrderStatus::Valid;
                order.certificate = Some(certificate_url.clone());
            }
            let not_before = order.not_before;
            let not_after = order.not_after;
            let response = order.to_response();
            (response, not_before, not_after)
        };

        self.issue_certificate_if_needed(order_id, &mut signing_request, not_before, not_after)
            .await?;

        Ok(FinalizeOrderOutcome {
            response,
            location: order_url,
        })
    }

    async fn issue_certificate_if_needed(
        &self,
        order_id: &str,
        csr: &mut CertificateSigningRequest,
        not_before: Option<OffsetDateTime>,
        not_after: Option<OffsetDateTime>,
    ) -> Result<(), AcmeProblem> {
        if self.issued_certificates.lock().await.contains_key(order_id) {
            return Ok(());
        }

        let now = OffsetDateTime::now_utc();
        let start = not_before.unwrap_or(now - Duration::hours(1));
        let end = not_after.unwrap_or(now + Duration::days(90));
        csr.params.not_before = start;
        csr.params.not_after = end;
        csr.params.is_ca = IsCa::NoCa;

        if !csr
            .params
            .key_usages
            .iter()
            .any(|usage| matches!(usage, KeyUsagePurpose::DigitalSignature))
        {
            csr.params
                .key_usages
                .push(KeyUsagePurpose::DigitalSignature);
        }
        if !csr
            .params
            .key_usages
            .iter()
            .any(|usage| matches!(usage, KeyUsagePurpose::KeyEncipherment))
        {
            csr.params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        }
        if !csr
            .params
            .extended_key_usages
            .iter()
            .any(|usage| matches!(usage, ExtendedKeyUsagePurpose::ServerAuth))
        {
            csr.params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);
        }
        csr.params.use_authority_key_identifier_extension = true;
        csr.params.serial_number = Some(random_serial_number());

        let leaf_der = csr
            .serialize_der_with_signer(&self.ca_certificate)
            .map_err(|err| {
                AcmeProblem::server_internal(format!("Sertifika imzalanamadı: {err}"))
            })?;
        let leaf_pem = pem::encode(&Pem::new("CERTIFICATE", leaf_der.clone()));
        let stored = StoredCertificate::new(leaf_pem, leaf_der, self.ca_pem.clone());
        let mut issued = self.issued_certificates.lock().await;
        if issued.contains_key(order_id) {
            return Ok(());
        }
        issued.insert(order_id.to_owned(), stored);
        drop(issued);
        Ok(())
    }

    pub async fn certificate_pem_bundle(&self, order_id: &str) -> Result<String, AcmeProblem> {
        let status = self
            .orders
            .lock()
            .await
            .get(order_id)
            .map(|order| order.status)
            .ok_or_else(|| AcmeProblem::unauthorized("Order bulunamadı"))?;
        if !matches!(status, OrderStatus::Valid) {
            return Err(AcmeProblem::order_not_ready(
                "Order henüz valid durumda değil",
            ));
        }

        let stored = self
            .issued_certificates
            .lock()
            .await
            .get(order_id)
            .cloned()
            .ok_or_else(|| AcmeProblem::order_not_ready("Order için sertifika yayınlanmadı"))?;
        if stored.is_revoked() {
            return Err(AcmeProblem::unauthorized("Sertifika iptal edildi"));
        }
        Ok(stored.as_pem_bundle())
    }

    pub async fn revoke_certificate(&self, jws: AcmeJws) -> Result<RevokeCertOutcome, AcmeProblem> {
        let header = parse_protected_header(&jws.protected)?;
        if header.url != self.endpoints.revoke_cert.as_str() {
            return Err(AcmeProblem::malformed(
                "protected header içindeki url revoke-cert uç noktasını göstermeli",
            ));
        }
        if header.jwk.is_some() {
            return Err(AcmeProblem::malformed("revokeCert isteği JWK içeremez"));
        }
        let kid = header
            .kid
            .ok_or_else(|| AcmeProblem::malformed("revokeCert isteği kid alanı içermeli"))?;

        let accounts_guard = self.accounts.lock().await;
        let account = accounts_guard
            .get_by_kid(&kid)
            .ok_or_else(AcmeProblem::account_does_not_exist)?;
        let account_id = account.location.clone();
        let key = account.key.clone();
        drop(accounts_guard);

        self.consume_nonce(&header.nonce).await?;
        verify_signature(&key, &jws)?;

        let payload = parse_revoke_payload(&jws.payload)?;
        if let Some(reason) = payload.reason {
            validate_revocation_reason(reason)?;
        }
        let certificate_der = decode_base64(&payload.certificate).map_err(|_| {
            AcmeProblem::malformed("certificate değeri base64url olarak çözülemedi")
        })?;

        let orders_guard = self.orders.lock().await;
        let mut issued_guard = self.issued_certificates.lock().await;
        let (order_id_key, stored) = issued_guard
            .iter_mut()
            .find(|(_, cert)| cert.matches_der(&certificate_der))
            .ok_or_else(|| {
                AcmeProblem::malformed("Sertifika mevcut ACME order kayıtlarıyla eşleşmedi")
            })?;
        let order = orders_guard
            .get(order_id_key)
            .ok_or_else(|| AcmeProblem::server_internal("Order kaydı bulunamadı"))?;
        if order.account_id != account_id {
            return Err(AcmeProblem::unauthorized(
                "Sertifika belirtilen hesapla ilişkili değil",
            ));
        }
        if stored.is_revoked() {
            return Err(AcmeProblem::already_revoked(
                "Sertifika daha önce iptal edildi",
            ));
        }
        let record = stored.set_revoked(payload.reason);
        let order_id = order_id_key.clone();
        drop(issued_guard);
        drop(orders_guard);

        info!(%kid, order_id = %order_id, reason = ?record.reason, "ACME sertifika iptal edildi");

        Ok(RevokeCertOutcome {
            revoked_at: record.revoked_at,
            reason: record.reason,
        })
    }

    #[must_use]
    pub fn terms_of_service(&self) -> Option<&str> {
        self.terms_of_service.as_deref()
    }
}

fn generate_acme_ca(base: &Url) -> Result<(Certificate, String), ServerError> {
    let host = base
        .host_str()
        .map_or_else(|| "aunsorm.local".to_owned(), ToOwned::to_owned);
    let mut params = CertificateParams::new(vec![format!("Aunsorm ACME Issuing CA ({host})")]);
    params.alg = &PKCS_ED25519;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.extended_key_usages.clear();
    params.subject_alt_names.clear();
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(365 * 5);
    params.serial_number = Some(random_serial_number());
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Aunsorm Security Platform");
    params.distinguished_name.push(
        DnType::CommonName,
        format!("Aunsorm ACME Issuing CA ({host})"),
    );

    let certificate = Certificate::from_params(params)
        .map_err(|err| ServerError::Configuration(format!("ACME CA oluşturulamadı: {err}")))?;
    let pem = certificate.serialize_pem().map_err(|err| {
        ServerError::Configuration(format!("ACME CA PEM üretimi başarısız: {err}"))
    })?;
    Ok((certificate, pem))
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
    certificate_base: Url,
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
            certificate_base: base.join("acme/cert/")?,
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
        self.order_base.join(&format!("{id}/finalize"))
    }

    fn authorization_url(&self, order_id: &str, index: usize) -> Result<Url, ParseError> {
        self.authz_base.join(&format!("{order_id}-{index:02}"))
    }

    fn certificate_url(&self, order_id: &str) -> Result<Url, ParseError> {
        self.certificate_base.join(order_id)
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
    rng: AunsormNativeRng,
}

impl NonceState {
    fn issue(&mut self) -> String {
        loop {
            let mut bytes = [0_u8; 16];
            self.rng.fill_bytes(&mut bytes);
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
    certificate: Option<String>,
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
            certificate: self.certificate.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct StoredCertificate {
    leaf_pem: String,
    leaf_der: Vec<u8>,
    issuer_chain: Vec<String>,
    revocation: Option<RevocationRecord>,
}

impl StoredCertificate {
    fn new(leaf_pem: String, leaf_der: Vec<u8>, issuer_pem: String) -> Self {
        Self {
            leaf_pem,
            leaf_der,
            issuer_chain: vec![issuer_pem],
            revocation: None,
        }
    }

    fn as_pem_bundle(&self) -> String {
        let mut bundle = String::new();
        append_pem_block(&mut bundle, &self.leaf_pem);
        for certificate in &self.issuer_chain {
            append_pem_block(&mut bundle, certificate);
        }
        bundle
    }

    fn matches_der(&self, candidate: &[u8]) -> bool {
        self.leaf_der == candidate
    }

    const fn is_revoked(&self) -> bool {
        self.revocation.is_some()
    }

    fn set_revoked(&mut self, reason: Option<u8>) -> RevocationRecord {
        let record = RevocationRecord {
            revoked_at: OffsetDateTime::now_utc(),
            reason,
        };
        self.revocation = Some(record);
        record
    }
}

#[derive(Debug, Clone, Copy)]
struct RevocationRecord {
    revoked_at: OffsetDateTime,
    reason: Option<u8>,
}

fn append_pem_block(target: &mut String, pem: &str) {
    target.push_str(pem);
    if !pem.ends_with('\n') {
        target.push('\n');
    }
}

fn random_serial_number() -> SerialNumber {
    let mut bytes = [0_u8; 16];
    let mut rng = AunsormNativeRng::new();
    rng.fill_bytes(&mut bytes);
    SerialNumber::from(bytes.to_vec())
}

#[derive(Debug, Clone, Copy)]
enum OrderStatus {
    Pending,
    Valid,
}

impl OrderStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
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

#[derive(Debug)]
pub struct OrderLookupOutcome {
    pub response: OrderResponse,
    pub location: String,
}

#[derive(Debug)]
pub struct FinalizeOrderOutcome {
    pub response: OrderResponse,
    pub location: String,
}

#[derive(Debug)]
pub struct RevokeCertOutcome {
    pub revoked_at: OffsetDateTime,
    pub reason: Option<u8>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
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

    fn order_not_ready(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "urn:ietf:params:acme:error:orderNotReady",
            detail,
        )
    }

    fn already_revoked(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::OK,
            "urn:ietf:params:acme:error:alreadyRevoked",
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
struct IncomingFinalizePayload {
    csr: String,
}

#[derive(Debug, Deserialize)]
struct IncomingRevokePayload {
    certificate: String,
    #[serde(default)]
    reason: Option<u8>,
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

fn parse_finalize_payload(encoded: &str) -> Result<IncomingFinalizePayload, AcmeProblem> {
    let bytes =
        decode_base64(encoded).map_err(|_| AcmeProblem::malformed("payload base64 çözülemedi"))?;
    serde_json::from_slice(&bytes).map_err(|err| {
        AcmeProblem::malformed(format!("finalize payload JSON ayrıştırılamadı: {err}"))
    })
}

fn parse_revoke_payload(encoded: &str) -> Result<IncomingRevokePayload, AcmeProblem> {
    let bytes =
        decode_base64(encoded).map_err(|_| AcmeProblem::malformed("payload base64 çözülemedi"))?;
    serde_json::from_slice(&bytes).map_err(|err| {
        AcmeProblem::malformed(format!("revokeCert payload JSON ayrıştırılamadı: {err}"))
    })
}

fn ensure_post_as_get_payload(payload: &str) -> Result<(), AcmeProblem> {
    if payload.is_empty() {
        return Ok(());
    }

    let decoded = decode_base64(payload).map_err(|_| {
        AcmeProblem::malformed("POST-as-GET isteği payload base64 olarak çözülemedi")
    })?;
    if decoded.is_empty() {
        return Ok(());
    }
    let trimmed: Vec<u8> = decoded
        .into_iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if trimmed.is_empty() || trimmed == b"{}" {
        return Ok(());
    }

    Err(AcmeProblem::malformed(
        "POST-as-GET isteği boş payload içermelidir",
    ))
}

fn validate_revocation_reason(reason: u8) -> Result<(), AcmeProblem> {
    if reason <= 10 {
        Ok(())
    } else {
        Err(AcmeProblem::malformed(
            "revokeCert reason değeri 0 ile 10 arasında olmalıdır",
        ))
    }
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

#[derive(Default)]
struct CsrIdentifiers {
    dns: HashSet<String>,
    ips: HashSet<IpAddr>,
}

fn collect_csr_identifiers(
    csr: &X509CertificationRequest<'_>,
) -> Result<CsrIdentifiers, AcmeProblem> {
    let mut identifiers = CsrIdentifiers::default();
    let mut saw_san = false;
    if let Some(extensions) = csr.requested_extensions() {
        for extension in extensions {
            if let ParsedExtension::SubjectAlternativeName(san) = extension {
                saw_san = true;
                for general in &san.general_names {
                    match general {
                        GeneralName::DNSName(value) => {
                            identifiers.dns.insert(normalize_dns_name(value));
                        }
                        GeneralName::IPAddress(raw) => {
                            let ip = parse_csr_ip_address(raw)?;
                            identifiers.ips.insert(ip);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    if !saw_san {
        return Err(AcmeProblem::malformed(
            "CSR SubjectAltName uzantısı içermeli",
        ));
    }

    Ok(identifiers)
}

fn ensure_identifiers_covered(
    csr_identifiers: &CsrIdentifiers,
    order_identifiers: &[OrderIdentifier],
) -> Result<(), AcmeProblem> {
    for identifier in order_identifiers {
        match identifier {
            OrderIdentifier::Dns(value) => {
                if !csr_identifiers.dns.contains(value.as_str()) {
                    return Err(AcmeProblem::malformed(format!(
                        "CSR SubjectAltName {value} değerini içermiyor"
                    )));
                }
            }
            OrderIdentifier::Ip(addr) => {
                if !csr_identifiers.ips.contains(addr) {
                    return Err(AcmeProblem::malformed(format!(
                        "CSR SubjectAltName IP {addr} değerini içermiyor"
                    )));
                }
            }
        }
    }

    Ok(())
}

fn normalize_dns_name(value: &str) -> String {
    let trimmed = value.trim().trim_end_matches('.');
    trimmed.to_ascii_lowercase()
}

fn parse_csr_ip_address(bytes: &[u8]) -> Result<IpAddr, AcmeProblem> {
    match bytes.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let mut raw = [0_u8; 16];
            raw.copy_from_slice(bytes);
            Ok(IpAddr::V6(Ipv6Addr::from(raw)))
        }
        _ => Err(AcmeProblem::malformed(
            "CSR SubjectAltName IPAddress alanı 4 veya 16 bayt olmalıdır",
        )),
    }
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
