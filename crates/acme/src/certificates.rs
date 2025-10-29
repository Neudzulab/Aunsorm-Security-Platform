use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use aunsorm_x509::ca::GeneratedCsr;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use pem::Pem;
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::{AcmeJws, JwsError, OrderService};

/// ACME order durumları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderStatus {
    /// Order henüz tüm doğrulamaları tamamlamadı.
    Pending,
    /// Order doğrulamaları tamamladı ve finalize edilmeyi bekliyor.
    Ready,
    /// Order finalize edildi ve CA tarafından işleniyor.
    Processing,
    /// Order başarıyla sonuçlandı ve sertifika hazır.
    Valid,
    /// Order başarısız oldu ve artık devam ettirilemez.
    Invalid,
}

impl OrderStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Processing => "processing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }
}

impl fmt::Display for OrderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Order durum yanıtlarından beklenen ortak alanlar.
pub trait OrderStatusSnapshot {
    /// Order'ın mevcut durumunu döndürür.
    fn status(&self) -> OrderStatus;

    /// Sertifika zinciri URL'si mevcutsa döndürür.
    fn certificate_url(&self) -> Option<&str>;

    /// Sunucunun önerdiği tekrar deneme süresi (Retry-After) değeri.
    #[allow(unused_variables)]
    fn retry_after(&self) -> Option<Duration> {
        None
    }
}

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("CSR PEM ayrıştırılamadı: {0}")]
    InvalidCsrPem(String),
    #[error("ACME finalize imzası üretilemedi: {0}")]
    Signing(#[from] JwsError),
    #[error("ACME finalize isteği başarısız: {0}")]
    Finalize(Box<dyn StdError + Send + Sync>),
    #[error("ACME order sorgusu başarısız: {0}")]
    Lookup(Box<dyn StdError + Send + Sync>),
    #[error("sertifika indirme başarısız: {0}")]
    Download(Box<dyn StdError + Send + Sync>),
    #[error("sertifika zinciri PEM verisi geçersiz: {0}")]
    InvalidCertificate(String),
    #[error("sertifika URL'i ayrıştırılamadı: {value}: {source}")]
    InvalidCertificateUrl {
        value: String,
        source: url::ParseError,
    },
    #[error("ACME order invalid durumuna geçti")]
    OrderMarkedInvalid,
    #[error(
        "ACME order valid durumuna ulaşmadan {attempts} deneme tüketildi (son durum {last_status})"
    )]
    PollAttemptsExceeded {
        attempts: usize,
        last_status: OrderStatus,
    },
    #[error("ACME order sertifika URL'i sağlamadı")]
    MissingCertificateUrl,
    #[error("sertifika zinciri boş")]
    EmptyChain,
}

#[derive(Debug, Clone, Serialize)]
pub struct FinalizePayload {
    pub csr: String,
}

/// Builds the finalize payload body by base64url encoding the CSR DER.
///
/// # Errors
///
/// Returns [`CertificateError::InvalidCsrPem`] when the provided PEM cannot be parsed or does not
/// contain a certificate signing request block.
pub fn build_finalize_payload(csr_pem: &str) -> Result<FinalizePayload, CertificateError> {
    let parsed =
        pem::parse(csr_pem).map_err(|err| CertificateError::InvalidCsrPem(err.to_string()))?;
    if parsed.tag() != "CERTIFICATE REQUEST" && parsed.tag() != "NEW CERTIFICATE REQUEST" {
        return Err(CertificateError::InvalidCsrPem(format!(
            "beklenmeyen PEM etiketi: {}",
            parsed.tag()
        )));
    }
    let csr = URL_SAFE_NO_PAD.encode(parsed.contents());
    Ok(FinalizePayload { csr })
}

/// Submits the CSR finalize request through the provided ACME [`OrderService`].
///
/// # Errors
///
/// Returns [`CertificateError`] when CSR encoding fails, signing fails or the order service
/// rejects the finalize request.
pub async fn finalize_order_with_csr<S, Signer>(
    service: &S,
    order_id: &str,
    csr: &GeneratedCsr,
    signer: Signer,
) -> Result<S::FinalizeOrder, CertificateError>
where
    S: OrderService + Sync,
    S::Error: StdError + Send + Sync + 'static,
    for<'a> S::FinalizeFuture<'a>: Send,
    Signer: FnOnce(FinalizePayload, GeneratedCsr) -> Result<AcmeJws, CertificateError>,
{
    let payload = build_finalize_payload(&csr.csr_pem)?;
    let jws = signer(payload, csr.clone())?;
    service
        .finalize_order(order_id, jws)
        .await
        .map_err(|err| CertificateError::Finalize(Box::new(err)))
}

/// Finalize sonrasında sertifika indirme ve order poll akışı için seçenekler.
#[derive(Debug, Clone, Copy)]
pub struct FinalizeOptions {
    /// `query_order` çağrısı ile yapılacak maksimum poll deneme sayısı.
    pub max_poll_attempts: usize,
}

impl FinalizeOptions {
    #[must_use]
    pub const fn new(max_poll_attempts: usize) -> Self {
        Self { max_poll_attempts }
    }
}

impl Default for FinalizeOptions {
    fn default() -> Self {
        Self {
            max_poll_attempts: 5,
        }
    }
}

/// Finalize ve indirme akışında kullanılacak yardımcı closure'lar.
#[derive(Debug)]
pub struct FinalizeWorkflow<FinalizeSigner, QuerySigner, Fetcher, Sleep> {
    pub finalize_signer: FinalizeSigner,
    pub query_signer: QuerySigner,
    pub fetcher: Fetcher,
    pub sleep: Sleep,
    pub options: FinalizeOptions,
}

impl<FinalizeSigner, QuerySigner, Fetcher, Sleep>
    FinalizeWorkflow<FinalizeSigner, QuerySigner, Fetcher, Sleep>
{
    #[must_use]
    pub fn new(
        finalize_signer: FinalizeSigner,
        query_signer: QuerySigner,
        fetcher: Fetcher,
        sleep: Sleep,
    ) -> Self {
        Self {
            finalize_signer,
            query_signer,
            fetcher,
            sleep,
            options: FinalizeOptions::default(),
        }
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_options(mut self, options: FinalizeOptions) -> Self {
        self.options = options;
        self
    }
}

#[derive(Debug, Clone)]
pub struct CertificateDownload {
    certificates: Vec<String>,
}

impl CertificateDownload {
    /// Creates a new download bundle.
    ///
    /// # Errors
    ///
    /// Returns [`CertificateError::EmptyChain`] when no certificate material is provided.
    pub fn new(certificates: Vec<String>) -> Result<Self, CertificateError> {
        if certificates.is_empty() {
            return Err(CertificateError::EmptyChain);
        }
        Ok(Self { certificates })
    }

    #[must_use]
    pub fn certificates(&self) -> &[String] {
        &self.certificates
    }

    #[must_use]
    pub fn leaf(&self) -> &str {
        &self.certificates[0]
    }

    #[must_use]
    pub fn intermediates(&self) -> &[String] {
        match self.certificates.len() {
            0..=2 => &self.certificates[0..0],
            len => &self.certificates[1..len - 1],
        }
    }

    #[must_use]
    pub fn root(&self) -> Option<&str> {
        self.certificates.last().map(String::as_str)
    }
}

/// Downloads the certificate chain using the provided fetcher and parses the PEM data.
///
/// # Errors
///
/// Returns [`CertificateError`] when fetching fails or the returned PEM blocks are invalid.
pub async fn download_certificate_chain<F, Fut, E>(
    url: &Url,
    fetcher: F,
) -> Result<CertificateDownload, CertificateError>
where
    F: FnOnce(&Url) -> Fut,
    Fut: Future<Output = Result<String, E>> + Send,
    E: StdError + Send + Sync + 'static,
{
    let body = fetcher(url)
        .await
        .map_err(|err| CertificateError::Download(Box::new(err)))?;
    parse_certificate_chain(&body)
}

/// RFC 8555 §7.4.2 akışına uygun olarak order finalize edip sertifikayı indirir.
///
/// Finalize isteği başarılı olduktan sonra order durumu `valid` olana dek poll yapılır ve
/// sertifika URL'i üzerinden zincir indirildikten sonra [`CertificateDownload`] olarak
/// döndürülür.
///
/// # Errors
///
/// - [`CertificateError::Signing`] finalize isteği imzalanamazsa.
/// - [`CertificateError::Finalize`] finalize isteği HTTP katmanında başarısız olursa.
/// - [`CertificateError::OrderMarkedInvalid`] order `invalid` durumuna geçerse.
/// - [`CertificateError::PollAttemptsExceeded`] izin verilen deneme sayısı aşılırsa.
/// - [`CertificateError::MissingCertificateUrl`] order `valid` olduğunda sertifika URL'i yoksa.
/// - [`CertificateError::InvalidCertificateUrl`] URL ayrıştırılamazsa.
/// - [`CertificateError::Download`] sertifika indirilemezse.
pub async fn finalize_and_download_certificate<
    S,
    FinalizeSigner,
    QuerySigner,
    Fetcher,
    FetchFuture,
    FetchError,
    Sleep,
    SleepFuture,
>(
    service: &S,
    order_id: &str,
    csr: &GeneratedCsr,
    workflow: FinalizeWorkflow<FinalizeSigner, QuerySigner, Fetcher, Sleep>,
) -> Result<CertificateDownload, CertificateError>
where
    S: OrderService + Sync,
    S::Error: StdError + Send + Sync + 'static,
    S::FinalizeOrder: OrderStatusSnapshot + Send,
    S::LookupOrder: OrderStatusSnapshot + Send,
    for<'a> S::FinalizeFuture<'a>: Send,
    for<'a> S::LookupFuture<'a>: Send,
    FinalizeWorkflow<FinalizeSigner, QuerySigner, Fetcher, Sleep>: Send,
    FinalizeSigner:
        FnOnce(FinalizePayload, GeneratedCsr) -> Result<AcmeJws, CertificateError> + Send,
    QuerySigner: FnMut(String) -> Result<AcmeJws, CertificateError> + Send,
    Fetcher: FnOnce(&Url) -> FetchFuture + Send,
    FetchFuture: Future<Output = Result<String, FetchError>> + Send,
    FetchError: StdError + Send + Sync + 'static,
    Sleep: Fn(Duration) -> SleepFuture + Send + Sync,
    SleepFuture: Future<Output = ()> + Send,
{
    let FinalizeWorkflow {
        finalize_signer,
        mut query_signer,
        fetcher,
        sleep,
        options,
    } = workflow;

    let finalize_response =
        finalize_order_with_csr(service, order_id, csr, finalize_signer).await?;
    let sleep_ref = &sleep;
    let certificate_url = match finalize_response.status() {
        OrderStatus::Valid => extract_certificate_url(&finalize_response),
        OrderStatus::Invalid => Err(CertificateError::OrderMarkedInvalid),
        OrderStatus::Pending | OrderStatus::Ready | OrderStatus::Processing => {
            if let Some(delay) = finalize_response.retry_after() {
                (sleep_ref)(delay).await;
            }
            wait_for_certificate(
                service,
                order_id,
                &mut query_signer,
                sleep_ref,
                options.max_poll_attempts,
            )
            .await
        }
    }?;

    download_certificate_chain(&certificate_url, fetcher).await
}

async fn wait_for_certificate<S, QuerySigner, Sleep, SleepFuture>(
    service: &S,
    order_id: &str,
    query_signer: &mut QuerySigner,
    sleep: &Sleep,
    max_attempts: usize,
) -> Result<Url, CertificateError>
where
    S: OrderService + Sync,
    S::Error: StdError + Send + Sync + 'static,
    S::LookupOrder: OrderStatusSnapshot + Send,
    for<'a> S::LookupFuture<'a>: Send,
    QuerySigner: FnMut(String) -> Result<AcmeJws, CertificateError> + Send,
    Sleep: Fn(Duration) -> SleepFuture + Send + Sync,
    SleepFuture: Future<Output = ()> + Send,
{
    let mut attempts = 0;
    let mut last_status = OrderStatus::Processing;
    while attempts < max_attempts {
        attempts += 1;
        let jws = query_signer(order_id.to_owned())?;
        let response = service
            .query_order(order_id, jws)
            .await
            .map_err(|err| CertificateError::Lookup(Box::new(err)))?;
        last_status = response.status();
        match last_status {
            OrderStatus::Valid => return extract_certificate_url(&response),
            OrderStatus::Invalid => return Err(CertificateError::OrderMarkedInvalid),
            OrderStatus::Pending | OrderStatus::Ready | OrderStatus::Processing => {
                if let Some(delay) = response.retry_after() {
                    (sleep)(delay).await;
                }
            }
        }
    }

    Err(CertificateError::PollAttemptsExceeded {
        attempts: max_attempts,
        last_status,
    })
}

fn extract_certificate_url(snapshot: &impl OrderStatusSnapshot) -> Result<Url, CertificateError> {
    let value = snapshot
        .certificate_url()
        .ok_or(CertificateError::MissingCertificateUrl)?;
    Url::parse(value).map_err(|source| CertificateError::InvalidCertificateUrl {
        value: value.to_owned(),
        source,
    })
}

fn parse_certificate_chain(body: &str) -> Result<CertificateDownload, CertificateError> {
    let mut certificates = Vec::new();
    for section in pem::parse_many(body.as_bytes())
        .map_err(|err| CertificateError::InvalidCertificate(err.to_string()))?
    {
        if section.tag() != "CERTIFICATE" {
            return Err(CertificateError::InvalidCertificate(format!(
                "beklenen CERTIFICATE etiketi, bulundu {}",
                section.tag()
            )));
        }
        certificates.push(pem::encode(&Pem::new("CERTIFICATE", section.contents())));
    }
    CertificateDownload::new(certificates)
}
