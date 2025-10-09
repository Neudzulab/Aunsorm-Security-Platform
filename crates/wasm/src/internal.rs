use std::env;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use aunsorm_core::{calib_from_text, salts::Salts, CoreError, KdfPreset, KdfProfile};
use aunsorm_packet::{
    decrypt_one_shot, encrypt_one_shot, peek_header as packet_peek_header, AeadAlgorithm,
    DecryptParams, EncryptParams, Header, KemPayload, PacketError,
};

#[derive(Debug, Error)]
pub enum WasmError {
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("packet error: {0}")]
    Packet(#[from] PacketError),
    #[error("invalid kdf profile: {0}")]
    InvalidProfile(String),
    #[error("invalid aead algorithm: {0}")]
    InvalidAead(String),
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("serde error: {0}")]
    Serde(#[from] serde_wasm_bindgen::Error),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptRequest {
    pub password: String,
    pub plaintext: Vec<u8>,
    pub org_salt_b64: String,
    pub calib_text: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub aead: Option<String>,
    #[serde(default)]
    pub aad: Option<Vec<u8>>,
    #[serde(default)]
    pub strict: Option<bool>,
    #[serde(default)]
    pub kem: Option<KemInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptRequest {
    pub password: String,
    pub packet_b64: String,
    pub org_salt_b64: String,
    pub calib_text: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub aad: Option<Vec<u8>>,
    #[serde(default)]
    pub strict: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KemInput {
    pub kem: String,
    #[serde(default)]
    pub pk: Option<Vec<u8>>,
    #[serde(default)]
    pub ctkem: Option<Vec<u8>>,
    #[serde(default)]
    pub rbkem: Option<Vec<u8>>,
    #[serde(default)]
    pub ss: Option<Vec<u8>>,
}

impl KemInput {
    fn as_payload(&self) -> KemPayload<'_> {
        KemPayload {
            kem: self.kem.as_str(),
            pk: self.pk.as_deref(),
            ctkem: self.ctkem.as_deref(),
            rbkem: self.rbkem.as_deref(),
            ss: self.ss.as_deref(),
        }
    }
}

pub fn encrypt(request: EncryptRequest) -> Result<String, WasmError> {
    let org_salt = decode_org_salt(&request.org_salt_b64)?;
    let (calibration, _) = calib_from_text(&org_salt, &request.calib_text)?;
    let (password_salt, salts) = derive_salts(&org_salt, calibration.id.as_str())?;
    let profile = parse_profile(request.profile.as_deref())?;
    let algorithm = parse_aead(request.aead.as_deref())?;
    let aad = request.aad.unwrap_or_default();
    let strict = request.strict.unwrap_or_else(default_strict);

    let kem = request.kem.as_ref().map(KemInput::as_payload);
    let packet = encrypt_one_shot(EncryptParams {
        password: &request.password,
        password_salt: password_salt.as_ref(),
        calibration: &calibration,
        salts: &salts,
        plaintext: &request.plaintext,
        aad: &aad,
        profile,
        algorithm,
        strict,
        kem,
    })?;
    let encoded = packet.to_base64()?;
    Ok(encoded)
}

pub fn decrypt(request: DecryptRequest) -> Result<Vec<u8>, WasmError> {
    let org_salt = decode_org_salt(&request.org_salt_b64)?;
    let (calibration, _) = calib_from_text(&org_salt, &request.calib_text)?;
    let (password_salt, salts) = derive_salts(&org_salt, calibration.id.as_str())?;
    let profile = parse_profile(request.profile.as_deref())?;
    let aad = request.aad.unwrap_or_default();
    let strict = request.strict.unwrap_or_else(default_strict);

    let params = DecryptParams {
        password: &request.password,
        password_salt: password_salt.as_ref(),
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: &aad,
        strict,
        packet: request.packet_b64.trim(),
    };
    let result = decrypt_one_shot(&params)?;
    Ok(result.plaintext)
}

pub fn peek_header(packet_b64: &str) -> Result<Header, WasmError> {
    let header = packet_peek_header(packet_b64)?;
    Ok(header)
}

fn decode_org_salt(value: &str) -> Result<Vec<u8>, WasmError> {
    Ok(STANDARD.decode(value.trim())?)
}

fn parse_profile(input: Option<&str>) -> Result<KdfProfile, WasmError> {
    let preset = match input.unwrap_or("medium").to_ascii_lowercase().as_str() {
        "mobile" => KdfPreset::Mobile,
        "low" => KdfPreset::Low,
        "medium" => KdfPreset::Medium,
        "high" => KdfPreset::High,
        "ultra" => KdfPreset::Ultra,
        "auto" => KdfPreset::Auto,
        other => return Err(WasmError::InvalidProfile(other.to_owned())),
    };
    Ok(KdfProfile::preset(preset))
}

fn parse_aead(input: Option<&str>) -> Result<AeadAlgorithm, WasmError> {
    match input.unwrap_or("aes-gcm").to_ascii_lowercase().as_str() {
        "aes-gcm" => Ok(AeadAlgorithm::AesGcm),
        "chacha20poly1305" => Ok(AeadAlgorithm::Chacha20Poly1305),
        #[cfg(feature = "aes-siv")]
        "aes-siv" => Ok(AeadAlgorithm::AesSiv),
        other => Err(WasmError::InvalidAead(other.to_owned())),
    }
}

fn derive_salts(
    org_salt: &[u8],
    calibration_id: &str,
) -> Result<(Zeroizing<Vec<u8>>, Salts), WasmError> {
    let hk = Hkdf::<Sha256>::new(Some(org_salt), calibration_id.as_bytes());
    let mut password_salt = Zeroizing::new(vec![0_u8; 32]);
    let mut calibration_salt = vec![0_u8; 32];
    let mut chain_salt = vec![0_u8; 32];
    let mut coord_salt = vec![0_u8; 32];

    hk.expand(b"Aunsorm/1.01/password-salt", password_salt.as_mut())
        .map_err(|_| WasmError::Hkdf)?;
    hk.expand(b"Aunsorm/1.01/calibration-salt", &mut calibration_salt)
        .map_err(|_| WasmError::Hkdf)?;
    hk.expand(b"Aunsorm/1.01/chain-salt", &mut chain_salt)
        .map_err(|_| WasmError::Hkdf)?;
    hk.expand(b"Aunsorm/1.01/coord-salt", &mut coord_salt)
        .map_err(|_| WasmError::Hkdf)?;

    let salts = Salts::new(calibration_salt, chain_salt, coord_salt)?;
    Ok((password_salt, salts))
}

fn default_strict() -> bool {
    env::var("AUNSORM_STRICT")
        .map(|value| matches_ignore_case(&value, ["1", "true"]))
        .unwrap_or(false)
}

fn matches_ignore_case(value: &str, accepted: [&str; 2]) -> bool {
    accepted
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}
