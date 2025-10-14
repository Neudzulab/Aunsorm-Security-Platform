#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! Ed25519 tabanlı X.509 sertifika üretim yardımcıları.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

use aunsorm_core::{calib_from_text, Calibration};

const DEFAULT_BASE_OID: &str = "1.3.6.1.4.1.61012.1";
const CALIBRATION_EXTENSION_ARC: &[u64] = &[1, 1];

/// Hata türü.
#[derive(Debug, Error)]
pub enum X509Error {
    /// Taban OID değeri geçersiz.
    #[error("geçersiz OID: {0}")]
    InvalidOid(String),
    /// Yerel HTTPS hostname değeri boş.
    #[error("hostname boş olamaz")]
    EmptyHostname,
    /// Subject Alternative Name değeri geçersiz.
    #[error("geçersiz Subject Alternative Name: {0}")]
    InvalidSan(String),
    /// Sertifika parametreleri oluşturulamadı.
    #[error("sertifika üretimi başarısız: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// Kalibrasyon girdileri geçersiz.
    #[error("kalibrasyon hatası: {0}")]
    Core(#[from] aunsorm_core::CoreError),
}

/// Öz-imzalı sertifika üretimi için parametreler.
#[derive(Debug)]
pub struct SelfSignedCertParams<'a> {
    /// Sertifika ortak adı (CN).
    pub common_name: &'a str,
    /// Organizasyon tuzu.
    pub org_salt: &'a [u8],
    /// EXTERNAL kalibrasyon metni.
    pub calibration_text: &'a str,
    /// CPS URL listesi.
    pub cps_uris: &'a [String],
    /// Politika OID listesi.
    pub policy_oids: &'a [String],
    /// Geçerlilik süresi (gün).
    pub validity_days: u32,
    /// Subject Alternative Name girdileri.
    pub subject_alt_names: Vec<SubjectAltName>,
}

/// Üretilen sertifika çıktıları.
#[derive(Debug, Clone)]
pub struct SelfSignedCert {
    /// Sertifika PEM çıktısı.
    pub certificate_pem: String,
    /// Özel anahtar PEM çıktısı.
    pub private_key_pem: String,
    /// Hesaplanan kalibrasyon kimliği.
    pub calibration_id: String,
}

/// Öz-imzalı Ed25519 sertifika üretir.
///
/// # Errors
///
/// Hatalı OID veya sertifika oluşturma sırasında hata oluşursa `X509Error`
/// döner.
#[allow(clippy::too_many_lines)]
pub fn generate_self_signed(
    params: &SelfSignedCertParams<'_>,
) -> Result<SelfSignedCert, X509Error> {
    let (calibration, calibration_id) = calib_from_text(params.org_salt, params.calibration_text)?;
    let base_oid =
        std::env::var("AUNSORM_OID_BASE").unwrap_or_else(|_| DEFAULT_BASE_OID.to_owned());
    let extension_oid = build_extension_oid(&base_oid, CALIBRATION_EXTENSION_ARC)?;

    let mut cert_params = CertificateParams::new(vec![params.common_name.to_owned()])?;
    cert_params.is_ca = IsCa::ExplicitNoCa;
    cert_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    cert_params
        .distinguished_name
        .push(DnType::CommonName, params.common_name);
    let now = OffsetDateTime::now_utc();
    cert_params.not_before = now - Duration::days(1);
    cert_params.not_after = now + Duration::days(i64::from(params.validity_days));
    cert_params.serial_number = Some(deterministic_serial(&calibration));
    for san in &params.subject_alt_names {
        cert_params.subject_alt_names.push(san.to_san_type()?);
    }

    let calibration_extension = build_calibration_extension(&extension_oid, &calibration, params)?;
    cert_params.custom_extensions.push(calibration_extension);

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let certificate = cert_params.self_signed(&key_pair)?;
    let certificate_pem = certificate.pem();
    let private_key_pem = key_pair.serialize_pem();

    Ok(SelfSignedCert {
        certificate_pem,
        private_key_pem,
        calibration_id,
    })
}

fn deterministic_serial(calibration: &Calibration) -> SerialNumber {
    let mut hasher = Sha256::new();
    hasher.update(b"Aunsorm/1.01/x509/serial");
    hasher.update(calibration.fingerprint());
    hasher.update(calibration.id.as_str().as_bytes());
    let digest = hasher.finalize();
    let mut serial = vec![0_u8; 20];
    serial.copy_from_slice(&digest[..20]);
    SerialNumber::from(serial)
}

fn build_extension_oid(base: &str, arc: &[u64]) -> Result<Vec<u64>, X509Error> {
    let mut values = parse_oid(base)?;
    values.extend_from_slice(arc);
    Ok(values)
}

fn parse_oid(value: &str) -> Result<Vec<u64>, X509Error> {
    if value.trim().is_empty() {
        return Err(X509Error::InvalidOid(value.to_owned()));
    }
    value
        .split('.')
        .map(|part| {
            part.parse::<u64>()
                .map_err(|_| X509Error::InvalidOid(value.to_owned()))
        })
        .collect()
}

#[derive(Serialize)]
struct CalibrationMetadata<'a> {
    calibration_id: &'a str,
    fingerprint_b64: String,
    fingerprint_hex: String,
    note_sha256: String,
    cps_uris: &'a [String],
    policy_oids: &'a [String],
}

fn build_calibration_extension(
    oid: &[u64],
    calibration: &Calibration,
    params: &SelfSignedCertParams<'_>,
) -> Result<CustomExtension, X509Error> {
    let mut note_hasher = Sha256::new();
    note_hasher.update(params.calibration_text.as_bytes());
    let note_hash = note_hasher.finalize();

    let metadata = CalibrationMetadata {
        calibration_id: calibration.id.as_str(),
        fingerprint_b64: calibration.fingerprint_b64(),
        fingerprint_hex: calibration.fingerprint_hex(),
        note_sha256: hex::encode(note_hash),
        cps_uris: params.cps_uris,
        policy_oids: params.policy_oids,
    };
    let json =
        serde_json::to_vec(&metadata).map_err(|_| X509Error::InvalidOid("metadata".to_owned()))?;
    Ok(CustomExtension::from_oid_content(oid, json))
}

/// Yerel geliştirme ortamları için hostname ve localhost alternatif adlarını
/// içeren öz-imzalı sertifika parametreleri.
///
/// SAN (Subject Alternative Name) uzantısını otomatik olarak doldurarak haricî
/// araçlara gerek bırakmadan modern tarayıcıların beklediği yapılandırmayı
/// sağlar.
#[derive(Debug)]
pub struct LocalHttpsCertParams<'a> {
    /// Ortak ad olarak kullanılacak ana hostname.
    pub hostname: &'a str,
    /// Organizasyon tuzu.
    pub org_salt: &'a [u8],
    /// EXTERNAL kalibrasyon metni.
    pub calibration_text: &'a str,
    /// CPS URL listesi.
    pub cps_uris: &'a [String],
    /// Politika OID listesi.
    pub policy_oids: &'a [String],
    /// Geçerlilik süresi (gün).
    pub validity_days: u32,
    /// Ek DNS Subject Alternative Name girdileri.
    pub extra_dns: &'a [String],
    /// Ek IP Subject Alternative Name girdileri.
    pub extra_ips: &'a [IpAddr],
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Sertifikalarda Subject Alternative Name (SAN) girdilerini temsil eder.
pub enum SubjectAltName {
    /// DNS tabanlı Subject Alternative Name girdisi.
    Dns(String),
    /// IP tabanlı Subject Alternative Name girdisi.
    Ip(IpAddr),
}

impl SubjectAltName {
    fn to_san_type(&self) -> Result<SanType, X509Error> {
        match self {
            Self::Dns(name) => Ok(SanType::DnsName(
                Ia5String::try_from(name.clone())
                    .map_err(|_| X509Error::InvalidSan(name.clone()))?,
            )),
            Self::Ip(addr) => Ok(SanType::IpAddress(*addr)),
        }
    }
}

impl LocalHttpsCertParams<'_> {
    fn build_subject_alt_names(&self) -> Result<Vec<SubjectAltName>, X509Error> {
        if self.hostname.trim().is_empty() {
            return Err(X509Error::EmptyHostname);
        }
        let mut dns_names: BTreeSet<String> = BTreeSet::new();
        dns_names.insert(self.hostname.trim().to_owned());
        dns_names.insert("localhost".to_owned());
        for value in self.extra_dns {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                dns_names.insert(trimmed.to_owned());
            }
        }
        // CertificateParams::new ilk DNS girdisini otomatik olarak SAN listesine ekler.
        dns_names.remove(self.hostname.trim());

        let mut sans: Vec<SubjectAltName> =
            dns_names.into_iter().map(SubjectAltName::Dns).collect();

        let mut ip_addrs: BTreeSet<IpAddr> = BTreeSet::new();
        ip_addrs.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        ip_addrs.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
        for addr in self.extra_ips {
            ip_addrs.insert(*addr);
        }
        sans.extend(ip_addrs.into_iter().map(SubjectAltName::Ip));
        Ok(sans)
    }
}

/// Yerel HTTPS geliştirme ortamları için uygun öz-imzalı sertifika parametreleri oluşturur.
///
/// Ortak ad olarak verilen hostname kullanılır ve `localhost`, `127.0.0.1`, `::1`
/// varsayılan Subject Alternative Name girdileri eklenir.
///
/// # Errors
///
/// Hostname boşsa veya sertifika parametreleri oluşturulamazsa hata döner.
pub fn prepare_local_https_params<'a>(
    params: &'a LocalHttpsCertParams<'a>,
) -> Result<SelfSignedCertParams<'a>, X509Error> {
    let subject_alt_names = params.build_subject_alt_names()?;
    Ok(SelfSignedCertParams {
        common_name: params.hostname,
        org_salt: params.org_salt,
        calibration_text: params.calibration_text,
        cps_uris: params.cps_uris,
        policy_oids: params.policy_oids,
        validity_days: params.validity_days,
        subject_alt_names,
    })
}

/// Yerel HTTPS geliştirme ortamları için öz-imzalı sertifika üretir.
///
/// # Errors
///
/// Hostname boşsa veya sertifika üretimi sırasında hata oluşursa `X509Error`
/// döner.
pub fn generate_local_https_cert(
    params: &LocalHttpsCertParams<'_>,
) -> Result<SelfSignedCert, X509Error> {
    let derived = prepare_local_https_params(params)?;
    generate_self_signed(&derived)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use x509_parser::{
        extensions::{GeneralName, ParsedExtension},
        prelude::{FromDer, X509Certificate},
    };

    #[test]
    fn certificate_contains_calibration_extension() {
        let cps = vec!["https://example.com/cps".to_string()];
        let policies = vec!["1.2.3.4".to_string()];
        let params = SelfSignedCertParams {
            common_name: "Test",
            org_salt: b"org-salt",
            calibration_text: "Calibration",
            cps_uris: &cps,
            policy_oids: &policies,
            validity_days: 365,
            subject_alt_names: Vec::new(),
        };
        let (calibration, _) =
            calib_from_text(params.org_salt, params.calibration_text).expect("calibration");
        let cert = generate_self_signed(&params).expect("certificate");
        assert!(cert.certificate_pem.contains("BEGIN CERTIFICATE"));
        let der = pem::parse(cert.certificate_pem)
            .expect("pem")
            .contents()
            .to_vec();
        assert!(der
            .windows(cert.calibration_id.len())
            .any(|window| window == cert.calibration_id.as_bytes()));
        let expected_fp_hex = calibration.fingerprint_hex();
        assert!(der
            .windows(expected_fp_hex.len())
            .any(|window| window == expected_fp_hex.as_bytes()));
        let expected_hash = hex::encode(Sha256::digest(params.calibration_text.as_bytes()));
        assert!(der
            .windows(expected_hash.len())
            .any(|window| window == expected_hash.as_bytes()));
    }

    #[test]
    fn local_https_certificate_includes_default_sans() {
        let cps = vec![];
        let policies = vec![];
        let extra_dns = vec!["dev.aunsorm.test".to_string()];
        let extra_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))];
        let params = LocalHttpsCertParams {
            hostname: "localhost",
            org_salt: b"org-salt",
            calibration_text: "Calibration",
            cps_uris: &cps,
            policy_oids: &policies,
            validity_days: 90,
            extra_dns: &extra_dns,
            extra_ips: &extra_ips,
        };
        let derived = prepare_local_https_params(&params).expect("params");
        let cert = generate_self_signed(&derived).expect("certificate");
        let der = pem::parse(cert.certificate_pem)
            .expect("pem")
            .contents()
            .to_vec();
        let (_, parsed) = X509Certificate::from_der(&der).expect("parse");
        let san_ext = parsed
            .extensions()
            .iter()
            .find(|ext| {
                matches!(
                    ext.parsed_extension(),
                    ParsedExtension::SubjectAlternativeName(_)
                )
            })
            .expect("san extension");
        let eku_ext = parsed
            .extensions()
            .iter()
            .find(|ext| matches!(ext.parsed_extension(), ParsedExtension::ExtendedKeyUsage(_)))
            .expect("eku extension");

        if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
            let dns_names: Vec<String> = san
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(value) => Some((*value).to_owned()),
                    _ => None,
                })
                .collect();
            assert!(dns_names.contains(&"localhost".to_string()));
            assert!(dns_names.contains(&"dev.aunsorm.test".to_string()));

            let ip_names: Vec<String> = san
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::IPAddress(bytes) => Some(if bytes.len() == 4 {
                        IpAddr::from(<[u8; 4]>::try_from(&bytes[..]).expect("ipv4")).to_string()
                    } else {
                        IpAddr::from(<[u8; 16]>::try_from(&bytes[..]).expect("ipv6")).to_string()
                    }),
                    _ => None,
                })
                .collect();
            assert!(ip_names.contains(&"127.0.0.1".to_string()));
            assert!(ip_names.contains(&"::1".to_string()));
            assert!(ip_names.contains(&"192.168.1.10".to_string()));
        } else {
            panic!("SAN extension missing");
        }

        if let ParsedExtension::ExtendedKeyUsage(eku) = eku_ext.parsed_extension() {
            assert!(eku.server_auth);
        } else {
            panic!("EKU extension missing");
        }
    }
}
