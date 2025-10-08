#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]
#![doc = "Python referans vektörleri ile uyumluluk testlerini sağlayan yardımcı crate"]

use std::fmt;

use aunsorm_core::{calib_from_text, salts::Salts, CoreError, KdfPreset, KdfProfile};
use aunsorm_packet::{decrypt_one_shot, AeadAlgorithm, DecryptParams, PacketError};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use once_cell::sync::Lazy;
use serde::Deserialize;
use thiserror::Error;

const RAW_VECTORS: &str = include_str!("../vectors/reference.json");

/// Python referans çıktılarından türetilmiş test vektörü.
#[derive(Debug, Clone)]
pub struct ReferenceCase {
    pub name: String,
    pub description: String,
    pub password: String,
    pub password_salt: Vec<u8>,
    pub salts: Salts,
    pub org_salt: Vec<u8>,
    pub calib_text: String,
    pub aad: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub packet_b64: String,
    pub profile: KdfProfile,
    pub aead: AeadAlgorithm,
    pub strict: bool,
    pub pqc_label: Option<String>,
    pub expected: ExpectedOutcome,
}

impl ReferenceCase {
    /// Şifre çözme işlemini gerçekleştirir.
    pub fn decrypt(&self) -> Result<aunsorm_packet::DecryptOk, PacketError> {
        let (calibration, _) = calib_from_text(&self.org_salt, &self.calib_text);
        let params = DecryptParams {
            password: &self.password,
            password_salt: &self.password_salt,
            calibration: &calibration,
            salts: &self.salts,
            profile: self.profile,
            aad: &self.aad,
            strict: self.strict,
            packet: &self.packet_b64,
        };
        decrypt_one_shot(&params)
    }

    /// Beklenen sonuca göre doğrulama yapar.
    pub fn validate(&self) -> Result<(), CaseValidationError> {
        match &self.expected {
            ExpectedOutcome::Success => {
                let result =
                    self.decrypt()
                        .map_err(|error| CaseValidationError::UnexpectedFailure {
                            case: self.name.clone(),
                            error: error.to_string(),
                        })?;
                if result.plaintext != self.plaintext {
                    return Err(CaseValidationError::PlaintextMismatch {
                        case: self.name.clone(),
                    });
                }
                if result.header.aead.alg != self.aead {
                    return Err(CaseValidationError::AeadMismatch {
                        case: self.name.clone(),
                        expected: self.aead.label().to_string(),
                        actual: result.header.aead.alg.label().to_string(),
                    });
                }
                Ok(())
            }
            ExpectedOutcome::Failure { contains } => match self.decrypt() {
                Ok(_) => Err(CaseValidationError::UnexpectedSuccess {
                    case: self.name.clone(),
                    expected: contains.clone(),
                }),
                Err(error) => {
                    let msg = error.to_string();
                    if msg.contains(contains) {
                        Ok(())
                    } else {
                        Err(CaseValidationError::FailureMismatch {
                            case: self.name.clone(),
                            expected: contains.clone(),
                            actual: msg,
                        })
                    }
                }
            },
        }
    }
}

/// Beklenen test sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedOutcome {
    Success,
    Failure { contains: String },
}

#[derive(Debug, Error)]
pub enum CaseValidationError {
    #[error("case {case}: expected failure containing '{expected}', got success")]
    UnexpectedSuccess { case: String, expected: String },
    #[error("case {case}: expected success but got error: {error}")]
    UnexpectedFailure { case: String, error: String },
    #[error("case {case}: plaintext mismatch with reference implementation")]
    PlaintextMismatch { case: String },
    #[error("case {case}: expected AEAD {expected}, got {actual}")]
    AeadMismatch {
        case: String,
        expected: String,
        actual: String,
    },
    #[error(
        "case {case}: failure message '{actual}' does not contain expected substring '{expected}'"
    )]
    FailureMismatch {
        case: String,
        expected: String,
        actual: String,
    },
}

#[derive(Debug, Error)]
pub enum VectorError {
    #[error("JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid base64 in field '{field}': {source}")]
    Base64 {
        field: String,
        #[source]
        source: base64::DecodeError,
    },
    #[error("invalid salts: {0}")]
    Salts(#[from] CoreError),
    #[error("unknown KDF profile '{0}'")]
    Profile(String),
    #[error("unknown AEAD algorithm '{0}'")]
    Aead(String),
    #[error("invalid expected result '{0}'")]
    Expected(String),
}

#[derive(Debug, Deserialize)]
struct RawCase {
    name: String,
    description: String,
    profile: String,
    aead: String,
    strict: bool,
    password: String,
    password_salt_b64: String,
    org_salt_b64: String,
    calib_text: String,
    aad_b64: String,
    plaintext_b64: String,
    packet_b64: String,
    pqc_label: Option<String>,
    salts: RawSalts,
    expected: RawExpected,
}

#[derive(Debug, Deserialize)]
struct RawSalts {
    #[serde(rename = "calibration_b64")]
    calibration: String,
    #[serde(rename = "chain_b64")]
    chain: String,
    #[serde(rename = "coord_b64")]
    coord: String,
}

#[derive(Debug, Deserialize)]
struct RawExpected {
    result: String,
    #[serde(default)]
    contains: Option<String>,
}

impl TryFrom<RawCase> for ReferenceCase {
    type Error = VectorError;

    fn try_from(value: RawCase) -> Result<Self, Self::Error> {
        let password_salt = decode_field("password_salt_b64", &value.password_salt_b64)?;
        let org_salt = decode_field("org_salt_b64", &value.org_salt_b64)?;
        let aad = decode_field("aad_b64", &value.aad_b64)?;
        let plaintext = decode_field("plaintext_b64", &value.plaintext_b64)?;
        let salts = Salts::new(
            decode_field("salts.calibration_b64", &value.salts.calibration)?,
            decode_field("salts.chain_b64", &value.salts.chain)?,
            decode_field("salts.coord_b64", &value.salts.coord)?,
        )?;

        let profile = parse_profile(&value.profile)?;
        let aead_alg = parse_aead(&value.aead)?;
        let expected = parse_expected(value.expected)?;

        Ok(Self {
            name: value.name,
            description: value.description,
            password: value.password,
            password_salt,
            salts,
            org_salt,
            calib_text: value.calib_text,
            aad,
            plaintext,
            packet_b64: value.packet_b64,
            profile,
            aead: aead_alg,
            strict: value.strict,
            pqc_label: value.pqc_label,
            expected,
        })
    }
}

fn parse_profile(label: &str) -> Result<KdfProfile, VectorError> {
    let preset = match label {
        "mobile" => KdfPreset::Mobile,
        "low" => KdfPreset::Low,
        "medium" => KdfPreset::Medium,
        "high" => KdfPreset::High,
        "ultra" => KdfPreset::Ultra,
        "auto" => KdfPreset::Auto,
        other => return Err(VectorError::Profile(other.to_string())),
    };
    Ok(KdfProfile::preset(preset))
}

fn parse_aead(label: &str) -> Result<AeadAlgorithm, VectorError> {
    match label {
        "aes-gcm" => Ok(AeadAlgorithm::AesGcm),
        "chacha20poly1305" => Ok(AeadAlgorithm::Chacha20Poly1305),
        other => Err(VectorError::Aead(other.to_string())),
    }
}

fn parse_expected(raw: RawExpected) -> Result<ExpectedOutcome, VectorError> {
    match raw.result.as_str() {
        "ok" => Ok(ExpectedOutcome::Success),
        "error" => Ok(ExpectedOutcome::Failure {
            contains: raw.contains.unwrap_or_else(|| "error".to_string()),
        }),
        other => Err(VectorError::Expected(other.to_string())),
    }
}

fn decode_field(field: &str, value: &str) -> Result<Vec<u8>, VectorError> {
    STANDARD_NO_PAD
        .decode(value)
        .map_err(|source| VectorError::Base64 {
            field: field.to_string(),
            source,
        })
}

fn load_vectors() -> Result<Vec<ReferenceCase>, VectorError> {
    let raw: Vec<RawCase> = serde_json::from_str(RAW_VECTORS)?;
    raw.into_iter().map(ReferenceCase::try_from).collect()
}

static REFERENCE_CASES: Lazy<Vec<ReferenceCase>> = Lazy::new(|| {
    load_vectors().unwrap_or_else(|err| {
        panic!("failed to load python reference vectors: {err}");
    })
});

/// Python referans test vektörleri.
#[must_use]
pub fn reference_cases() -> &'static [ReferenceCase] {
    &REFERENCE_CASES
}

impl fmt::Display for ExpectedOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => f.write_str("ok"),
            Self::Failure { contains } => write!(f, "error contains '{contains}'"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_vectors_are_satisfied() {
        for case in reference_cases() {
            if let Some(label) = &case.pqc_label {
                if label == "ml-kem-768" && !aunsorm_pqc::kem::KemAlgorithm::MlKem768.is_available()
                {
                    eprintln!("skipping {} due to missing PQC support", case.name);
                    continue;
                }
            }
            case.validate().unwrap_or_else(|err| panic!("{err}"));
        }
    }
}
