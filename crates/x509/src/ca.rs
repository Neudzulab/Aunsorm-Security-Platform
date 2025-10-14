//! Aunsorm Certificate Authority (CA) implementation.
//!
//! This module provides functionality to:
//! 1. Generate Root CA certificates (Ed25519)
//! 2. Sign server certificates with CA key
//! 3. Build certificate chains with Aunsorm calibration metadata
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use aunsorm_x509::ca::{RootCaParams, ServerCertParams};
//!
//! // 1. Generate Root CA
//! let root_params = RootCaParams {
//!     common_name: "MyeOffice Root CA",
//!     org_salt: b"base64-decoded-salt",
//!     calibration_text: "MyeOffice Root CA 2025",
//!     validity_days: 3650,
//! };
//! let root_ca = generate_root_ca(&root_params)?;
//!
//! // 2. Sign server certificate
//! let server_params = ServerCertParams {
//!     hostname: "localhost",
//!     org_salt: b"base64-decoded-salt",
//!     calibration_text: "MyeOffice Localhost Server",
//!     ca_cert_pem: &root_ca.certificate_pem,
//!     ca_key_pem: &root_ca.private_key_pem,
//!     validity_days: 365,
//!     extra_dns: &["*.localhost".to_owned()],
//!     extra_ips: &["127.0.0.1".parse()?],
//! };
//! let server_cert = sign_server_cert(&server_params)?;
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
    KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

use crate::{
    build_extension_oid, calib_from_text, calibration_extension_from_parts, deterministic_serial,
    SubjectAltName, X509Error, CALIBRATION_EXTENSION_ARC, DEFAULT_BASE_OID,
};

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

    let empty: &[String] = &[];
    let calibration_extension = calibration_extension_from_parts(
        &extension_oid,
        &calibration,
        params.calibration_text,
        empty,
        empty,
    )?;
    cert_params.custom_extensions.push(calibration_extension);

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let certificate = cert_params.self_signed(&key_pair)?;

    Ok(RootCaCert {
        certificate_pem: certificate.pem(),
        private_key_pem: key_pair.serialize_pem(),
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

    let mut cert_params = CertificateParams::new(vec![params.hostname.to_owned()])?;
    cert_params.is_ca = IsCa::ExplicitNoCa;
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
    let server_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let certificate = cert_params.signed_by(&server_key, &issuer)?;

    Ok(ServerCert {
        certificate_pem: certificate.pem(),
        private_key_pem: server_key.serialize_pem(),
        calibration_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calib_from_text;
    use pem::parse;
    use std::net::Ipv4Addr;
    use x509_parser::{
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
}
