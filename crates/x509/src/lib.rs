#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

//! Ed25519 tabanlı X.509 sertifika üretim yardımcıları.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use rcgen::{
    CertificateParams, CustomExtension, DnType, IsCa, KeyPair, KeyUsagePurpose, SerialNumber,
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
    /// Sertifika parametreleri oluşturulamadı.
    #[error("sertifika üretimi başarısız: {0}")]
    Rcgen(#[from] rcgen::Error),
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
    let (calibration, calibration_id) = calib_from_text(params.org_salt, params.calibration_text);
    let base_oid =
        std::env::var("AUNSORM_OID_BASE").unwrap_or_else(|_| DEFAULT_BASE_OID.to_owned());
    let extension_oid = build_extension_oid(&base_oid, CALIBRATION_EXTENSION_ARC)?;

    let mut cert_params = CertificateParams::new(vec![params.common_name.to_owned()])?;
    cert_params.is_ca = IsCa::ExplicitNoCa;
    cert_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cert_params
        .distinguished_name
        .push(DnType::CommonName, params.common_name);
    let now = OffsetDateTime::now_utc();
    cert_params.not_before = now - Duration::days(1);
    cert_params.not_after = now + Duration::days(i64::from(params.validity_days));
    cert_params.serial_number = Some(deterministic_serial(&calibration));

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
        fingerprint_b64: STANDARD_NO_PAD.encode(calibration.fingerprint()),
        note_sha256: hex::encode(note_hash),
        cps_uris: params.cps_uris,
        policy_oids: params.policy_oids,
    };
    let json =
        serde_json::to_vec(&metadata).map_err(|_| X509Error::InvalidOid("metadata".to_owned()))?;
    Ok(CustomExtension::from_oid_content(oid, json))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let cert = generate_self_signed(&params).expect("certificate");
        assert!(cert.certificate_pem.contains("BEGIN CERTIFICATE"));
        let der = pem::parse(cert.certificate_pem)
            .expect("pem")
            .contents()
            .to_vec();
        assert!(der
            .windows(cert.calibration_id.len())
            .any(|window| window == cert.calibration_id.as_bytes()));
        let expected_hash = hex::encode(Sha256::digest(params.calibration_text.as_bytes()));
        assert!(der
            .windows(expected_hash.len())
            .any(|window| window == expected_hash.as_bytes()));
    }
}
