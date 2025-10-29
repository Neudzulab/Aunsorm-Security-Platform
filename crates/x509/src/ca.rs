//! Aunsorm Certificate Authority (CA) implementation.
//!
//! This module provides functionality to:
//! 1. Generate Root CA certificates (Ed25519)
//! 2. Sign server certificates with CA key
//! 3. Build certificate chains with Aunsorm calibration metadata
//!
//! ## Usage Example
//!
//! ```rust
//! use aunsorm_x509::ca::{RootCaParams, ServerCertParams, KeyAlgorithm};
//! use aunsorm_x509::ca::{generate_root_ca, sign_server_cert};
//! use std::net::IpAddr;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Generate Root CA
//! let root_params = RootCaParams {
//!     common_name: "MyeOffice Root CA",
//!     org_salt: b"base64-decoded-salt",
//!     calibration_text: "MyeOffice Root CA 2025",
//!     validity_days: 3650,
//!     cps_uris: &[],
//!     policy_oids: &[],
//!     key_algorithm: Some(KeyAlgorithm::Ed25519),
//! };
//! let root_ca = generate_root_ca(&root_params)?;
//!
//! // 2. Sign server certificate  
//! let localhost_ip: IpAddr = "127.0.0.1".parse()?;
//! let server_params = ServerCertParams {
//!     hostname: "localhost",
//!     org_salt: b"base64-decoded-salt",
//!     calibration_text: "MyeOffice Localhost Server",
//!     ca_cert_pem: &root_ca.certificate_pem,
//!     ca_key_pem: &root_ca.private_key_pem,
//!     validity_days: 365,
//!     extra_dns: &["*.localhost".to_owned()],
//!     extra_ips: &[localhost_ip],
//!     key_algorithm: Some(KeyAlgorithm::Ed25519),
//! };
//! let server_cert = sign_server_cert(&server_params)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## CLI Usage
//!
//! ```bash
//! # Generate Root CA
//! aunsorm-cli x509 root-ca \
//!   --org-salt "base64-salt" \
//!   --calib-text "MyeOffice Root CA 2025" \
//!   --cert-out ./root-ca.crt \
//!   --key-out ./root-ca.key
//!
//! # Install to system trust store (Windows)
//! certutil -addstore Root root-ca.crt
//!
//! # Sign server certificate
//! aunsorm-cli x509 sign-server \
//!   --ca-cert ./root-ca.crt \
//!   --ca-key ./root-ca.key \
//!   --hostname localhost \
//!   --cert-out ./server.crt \
//!   --key-out ./server.key
//! ```

use std::net::IpAddr;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SignatureAlgorithm, SigningKey,
};
use time::{Duration, OffsetDateTime};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::{
    build_extension_oid, calib_from_text, calibration_extension_from_parts, deterministic_serial,
    SubjectAltName, X509Error, CALIBRATION_EXTENSION_ARC, DEFAULT_BASE_OID,
};

/// Key algorithm for certificate generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// Ed25519 (modern, fast, recommended)
    Ed25519,
    /// RSA 2048-bit (legacy compatibility)
    Rsa2048,
    /// RSA 4096-bit (maximum security)
    Rsa4096,
}

impl Default for KeyAlgorithm {
    fn default() -> Self {
        Self::Ed25519
    }
}

impl KeyAlgorithm {
    /// Generate keypair for this algorithm.
    fn generate_keypair(self) -> Result<KeyPair, X509Error> {
        match self {
            Self::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519)
                .map_err(|e| X509Error::KeyGeneration(e.to_string())),
            Self::Rsa2048 => generate_rsa_keypair(2048),
            Self::Rsa4096 => generate_rsa_keypair(4096),
        }
    }
}

fn generate_rsa_keypair(bits: usize) -> Result<KeyPair, X509Error> {
    // Use optimized RSA generation for better performance
    crate::optimizations::generate_optimized_rsa_keypair(bits)
}

/// Parameters for Root CA generation.
pub struct RootCaParams<'a> {
    /// Certificate common name (CN).
    pub common_name: &'a str,
    /// Organization salt for calibration.
    pub org_salt: &'a [u8],
    /// Calibration text.
    pub calibration_text: &'a str,
    /// Validity period in days.
    pub validity_days: u32,
    /// CPS URIs.
    pub cps_uris: &'a [String],
    /// Policy OIDs.
    pub policy_oids: &'a [String],
    /// Key algorithm (default: Ed25519).
    #[doc = "Use Ed25519 for modern systems, RSA for legacy compatibility."]
    pub key_algorithm: Option<KeyAlgorithm>,
}

/// Generated Root CA certificate.
pub struct RootCaCert {
    /// Certificate PEM.
    pub certificate_pem: String,
    /// Private key PEM.
    pub private_key_pem: String,
    /// Calibration ID.
    pub calibration_id: String,
}

/// Parameters for intermediate CA issuance.
pub struct IntermediateCaParams<'a> {
    /// Intermediate common name (CN).
    pub common_name: &'a str,
    /// Organization salt for calibration.
    pub org_salt: &'a [u8],
    /// Calibration text.
    pub calibration_text: &'a str,
    /// Validity period in days.
    pub validity_days: u32,
    /// CPS URIs.
    pub cps_uris: &'a [String],
    /// Policy OIDs.
    pub policy_oids: &'a [String],
    /// Issuer certificate PEM.
    pub issuer_cert_pem: &'a str,
    /// Issuer private key PEM.
    pub issuer_key_pem: &'a str,
}

/// Issued intermediate CA certificate.
pub struct IntermediateCaCert {
    /// Certificate PEM.
    pub certificate_pem: String,
    /// Private key PEM.
    pub private_key_pem: String,
    /// Calibration ID.
    pub calibration_id: String,
}

/// Signing backend abstraction for CA operations.
pub trait CaSigningBackend {
    /// Returns PEM encoded issuer certificate.
    fn certificate_pem(&self) -> &str;
    /// Returns underlying signature algorithm.
    fn signature_algorithm(&self) -> &'static SignatureAlgorithm;
    /// Returns raw public key bytes (without algorithm wrapping).
    fn public_key_raw(&self) -> &[u8];
    /// Produces signature over provided message.
    ///
    /// # Errors
    ///
    /// Returns [`X509Error`] when signing fails.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, X509Error>;
}

/// File-based signing backend backed by PEM encoded issuer key pair.
pub struct FileCaBackend<'a> {
    certificate_pem: &'a str,
    key_pair: KeyPair,
    public_key_raw: Vec<u8>,
}

impl<'a> FileCaBackend<'a> {
    /// Constructs backend from issuer certificate and key PEM.
    ///
    /// # Errors
    ///
    /// Returns [`X509Error`] when issuer material cannot be parsed or validated.
    pub fn new(certificate_pem: &'a str, key_pem: &'a str) -> Result<Self, X509Error> {
        let key_pair = KeyPair::from_pem(key_pem)?;
        let parsed_certificate = pem::parse(certificate_pem)
            .map_err(|err| X509Error::IssuerCertificate(err.to_string()))?;
        let (_, certificate) = X509Certificate::from_der(parsed_certificate.contents())
            .map_err(|err| X509Error::IssuerCertificate(err.to_string()))?;
        let subject_pki = &certificate.tbs_certificate.subject_pki;
        if subject_pki.subject_public_key.unused_bits != 0 {
            return Err(X509Error::IssuerPublicKey(
                "public key contains unused bits".to_owned(),
            ));
        }
        let public_key_raw = subject_pki.subject_public_key.data.to_vec();
        if public_key_raw.is_empty() {
            return Err(X509Error::IssuerPublicKey("public key is empty".to_owned()));
        }
        Ok(Self {
            certificate_pem,
            key_pair,
            public_key_raw,
        })
    }
}

impl CaSigningBackend for FileCaBackend<'_> {
    fn certificate_pem(&self) -> &str {
        self.certificate_pem
    }

    fn signature_algorithm(&self) -> &'static SignatureAlgorithm {
        self.key_pair.algorithm()
    }

    fn public_key_raw(&self) -> &[u8] {
        &self.public_key_raw
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, X509Error> {
        Ok(self.key_pair.sign(message)?)
    }
}

/// Parameters for server certificate signing.
pub struct ServerCertParams<'a> {
    /// Server hostname.
    pub hostname: &'a str,
    /// Organization salt for calibration.
    pub org_salt: &'a [u8],
    /// Calibration text (server-specific).
    pub calibration_text: &'a str,
    /// CA certificate PEM.
    pub ca_cert_pem: &'a str,
    /// CA private key PEM.
    pub ca_key_pem: &'a str,
    /// Validity period in days.
    pub validity_days: u32,
    /// Extra DNS Subject Alternative Names.
    pub extra_dns: &'a [String],
    /// Extra IP Subject Alternative Names.
    pub extra_ips: &'a [IpAddr],
    /// Key algorithm (default: Ed25519).
    #[doc = "Should match CA algorithm for compatibility. Ed25519 for modern, RSA for legacy."]
    pub key_algorithm: Option<KeyAlgorithm>,
}

/// Generated server certificate.
pub struct ServerCert {
    /// Certificate PEM.
    pub certificate_pem: String,
    /// Private key PEM.
    pub private_key_pem: String,
    /// Calibration ID.
    pub calibration_id: String,
}

/// Parameters used to generate a certificate signing request (CSR).
pub struct CertificateSigningRequestParams<'a> {
    /// Common Name (CN) that will appear in the CSR subject.
    pub common_name: &'a str,
    /// Subject Alternative Name entries that should be encoded into the CSR.
    pub subject_alt_names: &'a [SubjectAltName],
    /// Key algorithm to be used when generating the CSR key pair.
    pub key_algorithm: Option<KeyAlgorithm>,
}

/// Generated CSR artifacts containing both the request and the subject's private key.
pub struct GeneratedCsr {
    /// PEM encoded certificate signing request.
    pub csr_pem: String,
    /// PEM encoded private key corresponding to the CSR subject.
    pub private_key_pem: String,
    /// Algorithm used for the CSR key pair.
    pub key_algorithm: KeyAlgorithm,
}

/// Result of verifying a certificate chain.
pub struct ChainValidation {
    /// Ordered subject names starting from the leaf up to the root certificate.
    pub subjects: Vec<String>,
    /// Earliest expiry across the validated chain.
    pub not_after: OffsetDateTime,
}

/// Generates a Root CA certificate with Ed25519.
///
/// The generated certificate:
/// - Is self-signed
/// - Has `CA:TRUE` basic constraint
/// - Can sign other certificates (`KeyCertSign` usage)
/// - Contains Aunsorm calibration metadata
///
/// # Errors
///
/// Returns `X509Error` if certificate generation fails.
pub fn generate_root_ca(params: &RootCaParams<'_>) -> Result<RootCaCert, X509Error> {
    let (calibration, calibration_id) = calib_from_text(params.org_salt, params.calibration_text)?;
    let base_oid =
        std::env::var("AUNSORM_OID_BASE").unwrap_or_else(|_| DEFAULT_BASE_OID.to_owned());
    let extension_oid = build_extension_oid(&base_oid, CALIBRATION_EXTENSION_ARC)?;

    let algorithm = params.key_algorithm.unwrap_or_default();

    let mut cert_params = CertificateParams::new(vec![params.common_name.to_owned()])?;
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cert_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    cert_params
        .distinguished_name
        .push(DnType::CommonName, params.common_name);
    let now = OffsetDateTime::now_utc();
    cert_params.not_before = now - Duration::days(1);
    cert_params.not_after = now + Duration::days(i64::from(params.validity_days));
    cert_params.serial_number = Some(deterministic_serial(&calibration));

    let calibration_extension = calibration_extension_from_parts(
        &extension_oid,
        &calibration,
        params.calibration_text,
        params.cps_uris,
        params.policy_oids,
    )?;
    cert_params.custom_extensions.push(calibration_extension);

    let key_pair = algorithm.generate_keypair()?;
    let certificate = cert_params.self_signed(&key_pair)?;

    Ok(RootCaCert {
        certificate_pem: certificate.pem(),
        private_key_pem: key_pair.serialize_pem(),
        calibration_id,
    })
}

/// Issues an intermediate CA certificate signed by an existing issuer.
///
/// # Errors
///
/// Returns `X509Error` if certificate signing fails.
pub fn issue_intermediate_ca(
    params: &IntermediateCaParams<'_>,
) -> Result<IntermediateCaCert, X509Error> {
    let backend = FileCaBackend::new(params.issuer_cert_pem, params.issuer_key_pem)?;
    issue_intermediate_ca_with_backend(params, &backend)
}

/// Issues an intermediate CA certificate using the provided signing backend.
///
/// # Errors
///
/// Returns `X509Error` if certificate signing fails.
pub fn issue_intermediate_ca_with_backend(
    params: &IntermediateCaParams<'_>,
    backend: &impl CaSigningBackend,
) -> Result<IntermediateCaCert, X509Error> {
    let (calibration, calibration_id) = calib_from_text(params.org_salt, params.calibration_text)?;
    let base_oid =
        std::env::var("AUNSORM_OID_BASE").unwrap_or_else(|_| DEFAULT_BASE_OID.to_owned());
    let extension_oid = build_extension_oid(&base_oid, CALIBRATION_EXTENSION_ARC)?;

    let mut cert_params = CertificateParams::new(vec![params.common_name.to_owned()])?;
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cert_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    cert_params
        .distinguished_name
        .push(DnType::CommonName, params.common_name);
    let now = OffsetDateTime::now_utc();
    cert_params.not_before = now - Duration::days(1);
    cert_params.not_after = now + Duration::days(i64::from(params.validity_days));
    cert_params.serial_number = Some(deterministic_serial(&calibration));

    let calibration_extension = calibration_extension_from_parts(
        &extension_oid,
        &calibration,
        params.calibration_text,
        params.cps_uris,
        params.policy_oids,
    )?;
    cert_params.custom_extensions.push(calibration_extension);

    let issuer_key = BackendSigningKey::new(backend);
    let issuer = Issuer::from_ca_cert_pem(backend.certificate_pem(), issuer_key)?;
    let intermediate_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let certificate = cert_params.signed_by(&intermediate_key, &issuer)?;

    Ok(IntermediateCaCert {
        certificate_pem: certificate.pem(),
        private_key_pem: intermediate_key.serialize_pem(),
        calibration_id,
    })
}

/// Signs a server certificate with CA key.
///
/// The generated certificate:
/// - Is signed by CA (not self-signed)
/// - Has `CA:FALSE` basic constraint
/// - Server authentication purpose (`ExtendedKeyUsage`)
/// - Contains server-specific Aunsorm calibration
/// - Includes Subject Alternative Names (DNS + IP)
///
/// # Errors
///
/// Returns `X509Error` if certificate signing fails.
pub fn sign_server_cert(params: &ServerCertParams<'_>) -> Result<ServerCert, X509Error> {
    if params.hostname.trim().is_empty() {
        return Err(X509Error::EmptyHostname);
    }

    let (calibration, calibration_id) = calib_from_text(params.org_salt, params.calibration_text)?;
    let base_oid =
        std::env::var("AUNSORM_OID_BASE").unwrap_or_else(|_| DEFAULT_BASE_OID.to_owned());
    let extension_oid = build_extension_oid(&base_oid, CALIBRATION_EXTENSION_ARC)?;

    let algorithm = params.key_algorithm.unwrap_or_default();

    let mut cert_params = CertificateParams::new(vec![params.hostname.to_owned()])?;
    cert_params.is_ca = IsCa::NoCa;
    cert_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    cert_params
        .distinguished_name
        .push(DnType::CommonName, params.hostname);
    let now = OffsetDateTime::now_utc();
    cert_params.not_before = now - Duration::days(1);
    cert_params.not_after = now + Duration::days(i64::from(params.validity_days));
    cert_params.serial_number = Some(deterministic_serial(&calibration));

    for dns in params.extra_dns {
        let trimmed = dns.trim();
        if trimmed.is_empty() {
            continue;
        }
        let san = SubjectAltName::Dns(trimmed.to_owned()).to_san_type()?;
        cert_params.subject_alt_names.push(san);
    }
    for ip in params.extra_ips {
        let san = SubjectAltName::Ip(*ip).to_san_type()?;
        cert_params.subject_alt_names.push(san);
    }

    let empty: &[String] = &[];
    let calibration_extension = calibration_extension_from_parts(
        &extension_oid,
        &calibration,
        params.calibration_text,
        empty,
        empty,
    )?;
    cert_params.custom_extensions.push(calibration_extension);

    let ca_key = KeyPair::from_pem(params.ca_key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(params.ca_cert_pem, ca_key)?;
    let server_key = algorithm.generate_keypair()?;
    let certificate = cert_params.signed_by(&server_key, &issuer)?;

    Ok(ServerCert {
        certificate_pem: certificate.pem(),
        private_key_pem: server_key.serialize_pem(),
        calibration_id,
    })
}

/// Generates a CSR alongside the subject private key using the provided parameters.
///
/// # Errors
///
/// Returns [`X509Error`] when the CSR cannot be generated or the common name is empty.
pub fn generate_certificate_signing_request(
    params: &CertificateSigningRequestParams<'_>,
) -> Result<GeneratedCsr, X509Error> {
    if params.common_name.trim().is_empty() {
        return Err(X509Error::ProfileValidation(
            "CSR common_name boş olamaz".to_owned(),
        ));
    }

    let mut cert_params = CertificateParams::new(vec![params.common_name.to_owned()])?;
    cert_params.is_ca = IsCa::NoCa;
    cert_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    cert_params
        .distinguished_name
        .push(DnType::CommonName, params.common_name);
    cert_params.use_authority_key_identifier_extension = false;
    cert_params.subject_alt_names.clear();
    for san in params.subject_alt_names {
        cert_params.subject_alt_names.push(san.to_san_type()?);
    }

    let algorithm = params.key_algorithm.unwrap_or_default();
    let key_pair = match algorithm {
        KeyAlgorithm::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|err| X509Error::KeyGeneration(err.to_string()))?,
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => algorithm.generate_keypair()?,
    };

    let csr = cert_params.serialize_request(&key_pair)?;
    let csr_pem = csr.pem()?;
    let private_key_pem = key_pair.serialize_pem();

    Ok(GeneratedCsr {
        csr_pem,
        private_key_pem,
        key_algorithm: algorithm,
    })
}

/// Verifies that the provided leaf certificate chains up to the root using the optional
/// intermediate certificates.
///
/// # Errors
///
/// Returns [`X509Error`] when the PEM structures are invalid, the chain breaks or
/// any certificate is expired at verification time.
pub fn verify_certificate_chain(
    leaf_pem: &str,
    intermediates: &[&str],
    root_pem: &str,
) -> Result<ChainValidation, X509Error> {
    let now = OffsetDateTime::now_utc();
    let mut subjects = Vec::new();
    let mut expiries = Vec::new();

    let mut chain: Vec<Vec<u8>> = Vec::with_capacity(intermediates.len() + 2);
    chain.push(parse_pem_certificate(leaf_pem)?);
    for pem in intermediates {
        chain.push(parse_pem_certificate(pem)?);
    }
    let root_der = parse_pem_certificate(root_pem)?;
    chain.push(root_der);

    for index in 0..(chain.len() - 1) {
        let (_, subject) = X509Certificate::from_der(&chain[index])
            .map_err(|err| X509Error::ChainParse(err.to_string()))?;
        let (_, issuer) = X509Certificate::from_der(&chain[index + 1])
            .map_err(|err| X509Error::ChainParse(err.to_string()))?;

        subject
            .verify_signature(Some(issuer.public_key()))
            .map_err(|err| {
                X509Error::ChainVerification(format!(
                    "imza doğrulaması başarısız (konum {index}): {err}"
                ))
            })?;

        if subject.tbs_certificate.issuer != issuer.tbs_certificate.subject {
            return Err(X509Error::ChainVerification(format!(
                "issuer subject eşleşmiyor: beklenen {} fakat {}",
                issuer.tbs_certificate.subject, subject.tbs_certificate.issuer
            )));
        }

        let validity = subject.validity();
        let not_before = validity.not_before.to_datetime();
        let not_after = validity.not_after.to_datetime();
        if now < not_before || now > not_after {
            return Err(X509Error::ChainVerification(format!(
                "sertifika geçerli değil: {}",
                subject.tbs_certificate.subject
            )));
        }
        subjects.push(subject.tbs_certificate.subject.to_string());
        expiries.push(not_after);
    }

    let root_bytes = chain
        .last()
        .ok_or_else(|| X509Error::ChainParse("root sertifikası eksik".to_owned()))?
        .as_slice();
    let (_, root_cert) = X509Certificate::from_der(root_bytes)
        .map_err(|err| X509Error::ChainParse(err.to_string()))?;
    root_cert.verify_signature(None).map_err(|err| {
        X509Error::ChainVerification(format!("root self-signature başarısız: {err}"))
    })?;
    let validity = root_cert.validity();
    let root_not_after = validity.not_after.to_datetime();
    let root_not_before = validity.not_before.to_datetime();
    if now < root_not_before || now > root_not_after {
        return Err(X509Error::ChainVerification(
            "root sertifika geçerli değil".to_owned(),
        ));
    }
    subjects.push(root_cert.tbs_certificate.subject.to_string());
    expiries.push(root_not_after);

    let not_after = expiries
        .into_iter()
        .min()
        .ok_or_else(|| X509Error::ChainVerification("zincir boş".to_owned()))?;

    Ok(ChainValidation {
        subjects,
        not_after,
    })
}

fn parse_pem_certificate(pem_value: &str) -> Result<Vec<u8>, X509Error> {
    let parsed = pem::parse(pem_value).map_err(|err| X509Error::ChainParse(err.to_string()))?;
    if parsed.tag() != "CERTIFICATE" {
        return Err(X509Error::ChainParse(format!(
            "beklenen CERTIFICATE etiketi, bulundu {}",
            parsed.tag()
        )));
    }
    Ok(parsed.into_contents())
}

struct BackendSigningKey<'a, B: CaSigningBackend + ?Sized> {
    backend: &'a B,
    algorithm: &'static SignatureAlgorithm,
    public_key_raw: &'a [u8],
}

impl<'a, B: CaSigningBackend + ?Sized> BackendSigningKey<'a, B> {
    fn new(backend: &'a B) -> Self {
        Self {
            backend,
            algorithm: backend.signature_algorithm(),
            public_key_raw: backend.public_key_raw(),
        }
    }
}

impl<B: CaSigningBackend + ?Sized> rcgen::PublicKeyData for BackendSigningKey<'_, B> {
    fn der_bytes(&self) -> &[u8] {
        self.public_key_raw
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}

impl<B: CaSigningBackend + ?Sized> rcgen::SigningKey for BackendSigningKey<'_, B> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.backend
            .sign(msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calib_from_text;
    use pem::parse;
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use std::net::Ipv4Addr;
    use x509_parser::{
        certification_request::X509CertificationRequest,
        extensions::{GeneralName, ParsedExtension},
        prelude::{FromDer, X509Certificate},
    };

    #[test]
    fn generate_root_ca_produces_calibration_extension() {
        let params = RootCaParams {
            common_name: "Test Root CA",
            org_salt: b"test-salt",
            calibration_text: "Test Calibration",
            validity_days: 3650,
            cps_uris: &[],
            policy_oids: &[],
            key_algorithm: None,
        };

        let ca = generate_root_ca(&params).expect("generate root CA");
        assert!(ca.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.private_key_pem.contains("BEGIN PRIVATE KEY"));

        let ca_der = parse(ca.certificate_pem.clone())
            .expect("pem")
            .contents()
            .to_vec();
        let (_, certificate) = X509Certificate::from_der(&ca_der).expect("parse CA");

        assert_eq!(
            certificate.tbs_certificate.subject,
            certificate.tbs_certificate.issuer
        );
        let basic_constraints = certificate
            .extensions()
            .iter()
            .find(|ext| matches!(ext.parsed_extension(), ParsedExtension::BasicConstraints(_)))
            .expect("basic constraints");
        if let ParsedExtension::BasicConstraints(bc) = basic_constraints.parsed_extension() {
            assert!(bc.ca);
        }

        let (_, expected_id) = calib_from_text(params.org_salt, params.calibration_text)
            .expect("expected calibration");
        assert_eq!(ca.calibration_id, expected_id);
        assert!(ca_der
            .windows(ca.calibration_id.len())
            .any(|window| window == ca.calibration_id.as_bytes()));
    }

    #[test]
    fn sign_server_cert_uses_ca_issuer() {
        let root_params = RootCaParams {
            common_name: "Test Root CA",
            org_salt: b"test-salt",
            calibration_text: "Test CA Calibration",
            validity_days: 3650,
            cps_uris: &[],
            policy_oids: &[],
            key_algorithm: None,
        };
        let ca = generate_root_ca(&root_params).expect("generate CA");

        let server_params = ServerCertParams {
            hostname: "localhost",
            org_salt: b"test-salt",
            calibration_text: "Test Server Calibration",
            ca_cert_pem: &ca.certificate_pem,
            ca_key_pem: &ca.private_key_pem,
            validity_days: 365,
            extra_dns: &["*.localhost".to_owned()],
            extra_ips: &["127.0.0.1".parse().expect("ip")],
            key_algorithm: None,
        };

        let server = sign_server_cert(&server_params).expect("sign server cert");
        assert!(server.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(server.private_key_pem.contains("BEGIN PRIVATE KEY"));

        let server_der = parse(server.certificate_pem.clone())
            .expect("server pem")
            .contents()
            .to_vec();
        let (_, server_cert) = X509Certificate::from_der(&server_der).expect("parse server");

        let ca_der = parse(ca.certificate_pem.clone())
            .expect("ca pem")
            .contents()
            .to_vec();
        let (_, ca_cert) = X509Certificate::from_der(&ca_der).expect("parse ca");

        assert_eq!(
            server_cert.tbs_certificate.issuer,
            ca_cert.tbs_certificate.subject
        );
        let eku_ext = server_cert
            .extensions()
            .iter()
            .find(|ext| matches!(ext.parsed_extension(), ParsedExtension::ExtendedKeyUsage(_)))
            .expect("eku extension");
        if let ParsedExtension::ExtendedKeyUsage(eku) = eku_ext.parsed_extension() {
            assert!(eku.server_auth);
        }

        let san_ext = server_cert
            .extensions()
            .iter()
            .find(|ext| {
                matches!(
                    ext.parsed_extension(),
                    ParsedExtension::SubjectAlternativeName(_)
                )
            })
            .expect("san extension");
        if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
            let mut has_localhost = false;
            let mut has_wildcard_localhost = false;
            let mut has_loopback_ipv4 = false;

            for general_name in &san.general_names {
                match general_name {
                    GeneralName::DNSName(value) => {
                        if *value == "localhost" {
                            has_localhost = true;
                        } else if *value == "*.localhost" {
                            has_wildcard_localhost = true;
                        }
                    }
                    GeneralName::IPAddress(bytes) => {
                        if bytes.len() == 4 {
                            let ipv4 = IpAddr::from(<[u8; 4]>::try_from(&bytes[..]).expect("ipv4"));
                            if ipv4 == IpAddr::V4(Ipv4Addr::LOCALHOST) {
                                has_loopback_ipv4 = true;
                            }
                        }
                    }
                    _ => {}
                }
            }

            assert!(has_localhost);
            assert!(has_wildcard_localhost);
            assert!(has_loopback_ipv4);
        }

        assert!(!server.calibration_id.is_empty());
        assert!(server_der
            .windows(server.calibration_id.len())
            .any(|window| window == server.calibration_id.as_bytes()));
    }

    fn assert_rsa_certificate_chain(key_algorithm: KeyAlgorithm, expected_bits: usize) {
        let root_calibration = format!("RSA Root Calibration {expected_bits}");
        let server_calibration = format!("RSA Server Calibration {expected_bits}");
        let root_params = RootCaParams {
            common_name: "RSA Root CA",
            org_salt: b"rsa-root-salt",
            calibration_text: root_calibration.as_str(),
            validity_days: 3650,
            cps_uris: &[],
            policy_oids: &[],
            key_algorithm: Some(key_algorithm),
        };
        let root = generate_root_ca(&root_params).expect("generate RSA root");
        let server_params = ServerCertParams {
            hostname: "rsa.example.com",
            org_salt: b"rsa-server-salt",
            calibration_text: server_calibration.as_str(),
            ca_cert_pem: &root.certificate_pem,
            ca_key_pem: &root.private_key_pem,
            validity_days: 825,
            extra_dns: &[],
            extra_ips: &[],
            key_algorithm: Some(key_algorithm),
        };
        let server = sign_server_cert(&server_params).expect("sign RSA server");

        let root_der = parse(root.certificate_pem.clone())
            .expect("root pem")
            .contents()
            .to_vec();
        let server_der = parse(server.certificate_pem.clone())
            .expect("server pem")
            .contents()
            .to_vec();
        let (_, root_cert) = X509Certificate::from_der(&root_der).expect("root der");
        let (_, server_cert) = X509Certificate::from_der(&server_der).expect("server der");

        root_cert.verify_signature(None).expect("root self-signed");
        server_cert
            .verify_signature(Some(root_cert.public_key()))
            .expect("server signature");

        let root_public =
            RsaPublicKey::from_pkcs1_der(root_cert.public_key().subject_public_key.data.as_ref())
                .expect("root public");
        assert_eq!(root_public.n().bits(), expected_bits);

        let server_public =
            RsaPublicKey::from_pkcs1_der(server_cert.public_key().subject_public_key.data.as_ref())
                .expect("server public");
        assert_eq!(server_public.n().bits(), expected_bits);

        assert!(!root.calibration_id.is_empty());
        assert!(!server.calibration_id.is_empty());
        assert!(server.private_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn rsa_certificate_chains_validate() {
        assert_rsa_certificate_chain(KeyAlgorithm::Rsa2048, 2048);
        if std::env::var_os("AUNSORM_TEST_RSA4096").is_some() {
            assert_rsa_certificate_chain(KeyAlgorithm::Rsa4096, 4096);
        }
    }

    #[test]
    fn csr_generation_includes_subject_alt_names() {
        let sans = vec![
            SubjectAltName::Dns("example.com".to_owned()),
            SubjectAltName::Dns("www.example.com".to_owned()),
        ];
        let params = CertificateSigningRequestParams {
            common_name: "example.com",
            subject_alt_names: &sans,
            key_algorithm: Some(KeyAlgorithm::Ed25519),
        };

        let csr = generate_certificate_signing_request(&params).expect("csr generation");
        assert!(csr.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));

        let parsed = pem::parse(csr.csr_pem.as_str()).expect("csr pem");
        let (_, request) = X509CertificationRequest::from_der(parsed.contents()).expect("csr der");
        let mut dns_names = Vec::new();
        if let Some(extensions) = request.requested_extensions() {
            for extension in extensions {
                if let ParsedExtension::SubjectAlternativeName(san) = extension {
                    for name in &san.general_names {
                        if let GeneralName::DNSName(value) = name {
                            dns_names.push((*value).to_owned());
                        }
                    }
                }
            }
        }
        assert!(dns_names.contains(&"example.com".to_owned()));
        assert!(dns_names.contains(&"www.example.com".to_owned()));
    }

    #[test]
    fn rsa_csr_uses_native_rng() {
        let params = CertificateSigningRequestParams {
            common_name: "rsa.example",
            subject_alt_names: &[],
            key_algorithm: Some(KeyAlgorithm::Rsa2048),
        };

        let csr = generate_certificate_signing_request(&params).expect("csr");
        let private_key = RsaPrivateKey::from_pkcs8_pem(&csr.private_key_pem).expect("rsa pem");
        assert_eq!(private_key.n().bits(), 2048);
    }

    #[test]
    fn certificate_chain_verification_succeeds() {
        let root_params = RootCaParams {
            common_name: "Demo Root",
            org_salt: b"demo-salt",
            calibration_text: "Demo Root Calibration",
            validity_days: 3650,
            cps_uris: &[],
            policy_oids: &[],
            key_algorithm: None,
        };
        let root = generate_root_ca(&root_params).expect("root");

        let server_params = ServerCertParams {
            hostname: "demo.aunsorm.test",
            org_salt: b"demo-salt",
            calibration_text: "Demo Server",
            ca_cert_pem: &root.certificate_pem,
            ca_key_pem: &root.private_key_pem,
            validity_days: 365,
            extra_dns: &[],
            extra_ips: &[],
            key_algorithm: None,
        };
        let server = sign_server_cert(&server_params).expect("server");

        let validation =
            verify_certificate_chain(&server.certificate_pem, &[], &root.certificate_pem)
                .expect("chain validation");
        assert_eq!(validation.subjects.len(), 2);
    }

    #[test]
    fn issue_intermediate_ca_produces_valid_chain() {
        let root_params = RootCaParams {
            common_name: "Test Root CA",
            org_salt: b"test-salt",
            calibration_text: "Root Calibration",
            validity_days: 3650,
            cps_uris: &[],
            policy_oids: &[],
            key_algorithm: None,
        };
        let root = generate_root_ca(&root_params).expect("generate root");

        let issuing_params = IntermediateCaParams {
            common_name: "Test Issuing CA",
            org_salt: b"test-salt",
            calibration_text: "Issuing Calibration",
            validity_days: 1825,
            cps_uris: &[],
            policy_oids: &[],
            issuer_cert_pem: &root.certificate_pem,
            issuer_key_pem: &root.private_key_pem,
        };

        let issuing = issue_intermediate_ca(&issuing_params).expect("issue intermediate");
        assert!(issuing.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(issuing.private_key_pem.contains("BEGIN PRIVATE KEY"));

        let issuing_der = parse(issuing.certificate_pem.clone())
            .expect("issuing pem")
            .contents()
            .to_vec();
        let (_, issuing_cert) = X509Certificate::from_der(&issuing_der).expect("issuing");
        let root_der = parse(root.certificate_pem.clone())
            .expect("root pem")
            .contents()
            .to_vec();
        let (_, root_cert) = X509Certificate::from_der(&root_der).expect("root");

        assert_eq!(
            issuing_cert.tbs_certificate.issuer,
            root_cert.tbs_certificate.subject
        );
        let basic_constraints = issuing_cert
            .extensions()
            .iter()
            .find(|ext| matches!(ext.parsed_extension(), ParsedExtension::BasicConstraints(_)))
            .expect("basic constraints");
        if let ParsedExtension::BasicConstraints(bc) = basic_constraints.parsed_extension() {
            assert!(bc.ca);
        }
        assert!(!issuing.calibration_id.is_empty());
        assert!(issuing_der
            .windows(issuing.calibration_id.len())
            .any(|window| window == issuing.calibration_id.as_bytes()));
    }

    #[test]
    fn file_backend_signs_intermediate() {
        let root_params = RootCaParams {
            common_name: "Demo Root",
            org_salt: b"demo-salt",
            calibration_text: "Demo Root Calibration",
            validity_days: 3650,
            cps_uris: &[],
            policy_oids: &[],
            key_algorithm: None,
        };
        let root = generate_root_ca(&root_params).expect("root");
        let backend =
            FileCaBackend::new(&root.certificate_pem, &root.private_key_pem).expect("backend");

        let issuing_params = IntermediateCaParams {
            common_name: "Demo Issuing",
            org_salt: b"demo-salt",
            calibration_text: "Demo Issuing Calibration",
            validity_days: 730,
            cps_uris: &[],
            policy_oids: &[],
            issuer_cert_pem: &root.certificate_pem,
            issuer_key_pem: &root.private_key_pem,
        };

        let issuing = issue_intermediate_ca_with_backend(&issuing_params, &backend).expect("issue");
        assert!(!issuing.certificate_pem.is_empty());
        assert!(!issuing.private_key_pem.is_empty());
        assert!(!issuing.calibration_id.is_empty());
    }
}
