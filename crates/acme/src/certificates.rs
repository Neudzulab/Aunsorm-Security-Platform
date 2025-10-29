use std::error::Error as StdError;
use std::future::Future;

use aunsorm_x509::ca::GeneratedCsr;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use pem::Pem;
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::{AcmeJws, JwsError, OrderService};

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("CSR PEM ayrıştırılamadı: {0}")]
    InvalidCsrPem(String),
    #[error("ACME finalize imzası üretilemedi: {0}")]
    Signing(#[from] JwsError),
    #[error("ACME finalize isteği başarısız: {0}")]
    Finalize(Box<dyn StdError + Send + Sync>),
    #[error("sertifika indirme başarısız: {0}")]
    Download(Box<dyn StdError + Send + Sync>),
    #[error("sertifika zinciri PEM verisi geçersiz: {0}")]
    InvalidCertificate(String),
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
    Signer: FnOnce(&FinalizePayload, &GeneratedCsr) -> Result<AcmeJws, CertificateError>,
{
    let payload = build_finalize_payload(&csr.csr_pem)?;
    let jws = signer(&payload, csr)?;
    service
        .finalize_order(order_id, jws)
        .await
        .map_err(|err| CertificateError::Finalize(Box::new(err)))
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
