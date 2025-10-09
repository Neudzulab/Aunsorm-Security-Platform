use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};

use crate::{error::CoreError, salts::Salts};

const MIN_ORG_SALT_LEN: usize = 8;
const MAX_NOTE_LEN: usize = 2048;

/// Kalibrasyon aralığı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalibrationRange {
    pub start: u16,
    pub end: u16,
    pub step: u16,
}

impl CalibrationRange {
    fn new(start: u16, length: u16, step: u16) -> Self {
        let end = start.saturating_add(length.max(1));
        Self {
            start,
            end,
            step: step.max(1),
        }
    }
}

/// Kalibrasyon kimliğini temsil eden tür.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CalibrationId(String);

impl CalibrationId {
    /// Kimliği string olarak döndürür.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CalibrationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Kalibrasyon çıktısı.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Calibration {
    pub id: CalibrationId,
    pub alpha_long: u16,
    pub alpha_short: u16,
    pub beta_long: u16,
    pub beta_short: u16,
    pub tau: u16,
    pub ranges: [CalibrationRange; 5],
    fingerprint: [u8; 32],
}

impl Calibration {
    fn new(org_salt: &[u8], note_text: &str) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(b"Aunsorm/1.01/calibration");
        hasher.update(org_salt);
        hasher.update(note_text.as_bytes());
        let digest = hasher.finalize();

        let mut id_bytes = [0_u8; 18];
        id_bytes.copy_from_slice(&digest[..18]);
        let id = CalibrationId(URL_SAFE_NO_PAD.encode(id_bytes));

        let alpha_long = 1024 + u16::from_be_bytes([digest[18], digest[19]]) % 4096;
        let alpha_short = 512 + u16::from_be_bytes([digest[20], digest[21]]) % 2048;
        let beta_long = 1024 + u16::from_be_bytes([digest[22], digest[23]]) % 4096;
        let beta_short = 512 + u16::from_be_bytes([digest[24], digest[25]]) % 2048;
        let tau = 256 + u16::from_be_bytes([digest[26], digest[27]]) % 2048;

        let ranges = std::array::from_fn(|idx| {
            let base = 28 + idx * 6;
            let start = 128 + u16::from_be_bytes([digest[base], digest[base + 1]]) % 4096;
            let length = 256 + u16::from_be_bytes([digest[base + 2], digest[base + 3]]) % 2048;
            let step = 1 + (u16::from(digest[base + 4]) + (u16::from(digest[base + 5]) << 8)) % 257;
            CalibrationRange::new(start, length, step)
        });

        let mut fp_hasher = Sha256::new();
        fp_hasher.update(b"Aunsorm/1.01/calibration-fingerprint");
        fp_hasher.update(digest);
        let fingerprint: [u8; 32] = fp_hasher.finalize().into();

        Self {
            id,
            alpha_long,
            alpha_short,
            beta_long,
            beta_short,
            tau,
            ranges,
            fingerprint,
        }
    }

    /// Kalibrasyon parmak izini döndürür.
    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

/// Organizasyon tuzu ve kalibrasyon metninden kalibrasyon bilgisi üretir.
///
/// # Errors
/// Girdi boyutları bekleneni sağlamazsa veya HKDF işlemi başarısız olursa `CoreError`
/// döndürülür.
///
/// # Örnek
/// ```
/// use aunsorm_core::calibration::calib_from_text;
///
/// # fn main() -> Result<(), aunsorm_core::CoreError> {
/// let (calibration, id) = calib_from_text(b"org-salt", "Example calibration note")?;
/// assert_eq!(calibration.id.as_str(), id);
/// # Ok(())
/// # }
/// ```
pub fn calib_from_text(
    org_salt: &[u8],
    note_text: &str,
) -> Result<(Calibration, String), CoreError> {
    validate_calibration_inputs(org_salt, note_text)?;
    let calibration = Calibration::new(org_salt, note_text);
    let id = calibration.id.as_str().to_owned();
    Ok((calibration, id))
}

/// Kalibrasyon ve salt girdilerinden deterministik koordinat üretir.
///
/// # Errors
/// HKDF işlemi başarısız olursa veya `seed64` beklenen uzunlukta değilse `CoreError`
/// döner.
///
/// # Örnek
/// ```
/// use aunsorm_core::{
///     calibration::{calib_from_text, coord32_derive},
///     kdf::{derive_seed64_and_pdk, KdfProfile, KdfPreset},
///     salts::Salts,
/// };
///
/// # fn main() -> Result<(), aunsorm_core::CoreError> {
/// let profile = KdfProfile::preset(KdfPreset::Low);
/// let (seed, _, _) = derive_seed64_and_pdk(
///     "password",
///     b"salt-pwd-123",
///     b"salt-calib-456",
///     b"salt-chain-789",
///     profile,
/// )?;
/// let (calib, _) = calib_from_text(b"org-salt", "note")?;
/// let salts = Salts::new(
///     b"salt-calib-456".to_vec(),
///     b"salt-chain-789".to_vec(),
///     b"coord-salt".to_vec(),
/// )?;
/// let (coord_id, coord_bytes) = coord32_derive(seed.as_ref(), &calib, &salts)?;
/// assert_eq!(coord_bytes.len(), 32);
/// assert!(!coord_id.is_empty());
/// # Ok(())
/// # }
/// ```
pub fn coord32_derive(
    seed64: &[u8],
    calibration: &Calibration,
    salts: &Salts,
) -> Result<(String, [u8; 32]), CoreError> {
    if seed64.len() != 64 {
        return Err(CoreError::invalid_input("seed64 must be exactly 64 bytes"));
    }

    let hkdf_salt = salts.digest_for_coord(calibration.id.as_str());
    let hk = Hkdf::<Sha256>::new(Some(&hkdf_salt), seed64);

    let mut coord = [0_u8; 32];
    let mut info = b"Aunsorm/1.01/coord32".to_vec();
    info.extend_from_slice(calibration.fingerprint());
    hk.expand(&info, &mut coord)
        .map_err(|_| CoreError::hkdf_length())?;

    let mut digest_hasher = Sha256::new();
    digest_hasher.update(b"Aunsorm/1.01/coord-digest");
    digest_hasher.update(coord);
    let coord_digest = digest_hasher.finalize();
    let coord_id = URL_SAFE_NO_PAD.encode(coord_digest);

    Ok((coord_id, coord))
}

fn validate_calibration_inputs(org_salt: &[u8], note_text: &str) -> Result<(), CoreError> {
    if org_salt.len() < MIN_ORG_SALT_LEN {
        return Err(CoreError::salt_too_short("org salt must be >= 8 bytes"));
    }

    if note_text.len() > MAX_NOTE_LEN {
        return Err(CoreError::invalid_input(
            "calibration text must be <= 2048 bytes",
        ));
    }

    let trimmed = note_text.trim();
    if trimmed.is_empty() {
        return Err(CoreError::invalid_input(
            "calibration text must not be empty",
        ));
    }

    if note_text
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Err(CoreError::invalid_input(
            "calibration text contains disallowed control characters",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KdfPreset, KdfProfile};

    #[test]
    fn calibration_is_deterministic() {
        let (cal_a, id_a) = calib_from_text(b"org-salt", "note").expect("calibration");
        let (cal_b, id_b) = calib_from_text(b"org-salt", "note").expect("calibration");
        assert_eq!(cal_a, cal_b);
        assert_eq!(id_a, id_b);
    }

    #[test]
    fn coord_is_deterministic() {
        let (seed, _, _) = crate::kdf::derive_seed64_and_pdk(
            "password",
            b"password-salt",
            b"calib-salt",
            b"chain-salt",
            KdfProfile::preset(KdfPreset::Low),
        )
        .unwrap();
        let (calibration, _) = calib_from_text(b"org-salt", "note").expect("calibration");
        let salts = Salts::new(
            b"calib-salt".to_vec(),
            b"chain-salt".to_vec(),
            b"coord-salt".to_vec(),
        )
        .unwrap();
        let (coord_id_a, coord_a) = coord32_derive(seed.as_ref(), &calibration, &salts).unwrap();
        let (coord_id_b, coord_b) = coord32_derive(seed.as_ref(), &calibration, &salts).unwrap();
        assert_eq!(coord_id_a, coord_id_b);
        assert_eq!(coord_a, coord_b);
    }

    #[test]
    fn rejects_wrong_seed_length() {
        let (calibration, _) = calib_from_text(b"org-salt", "note").expect("calibration");
        let salts = Salts::new(
            b"calib-salt".to_vec(),
            b"chain-salt".to_vec(),
            b"coord-salt".to_vec(),
        )
        .unwrap();
        let result = coord32_derive(&[0_u8; 32], &calibration, &salts);
        assert!(matches!(result, Err(CoreError::InvalidInput(_))));
    }

    #[test]
    fn rejects_short_org_salt() {
        let err = calib_from_text(b"short", "note").unwrap_err();
        assert!(matches!(err, CoreError::SaltTooShort(_)));
    }

    #[test]
    fn rejects_empty_note() {
        let err = calib_from_text(b"org-salt", "   \t\n").unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn rejects_control_characters() {
        let err = calib_from_text(b"org-salt", "ok\u{07}bad").unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn rejects_overlong_note() {
        let long = "a".repeat(MAX_NOTE_LEN + 1);
        let err = calib_from_text(b"org-salt", &long).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }
}
