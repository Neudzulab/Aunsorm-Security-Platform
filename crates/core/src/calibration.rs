use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;

use crate::{error::CoreError, salts::Salts};

const MIN_ORG_SALT_LEN: usize = 8;
const MAX_NOTE_LEN: usize = 2048;

fn normalize_note_text(note_text: &str) -> String {
    let nfc = note_text.nfc().collect::<String>();
    let mut normalized = String::with_capacity(nfc.len());
    let mut parts = nfc.split_whitespace();
    if let Some(first) = parts.next() {
        normalized.push_str(first);
        for part in parts {
            normalized.push(' ');
            normalized.push_str(part);
        }
    }
    normalized
}

fn find_invisible_format_char(text: &str) -> Option<char> {
    text.chars().find(|&ch| {
        matches!(
            ch,
            // Zero-width spacing and joiner characters (Cf)
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{180E}'
                | '\u{061C}'
                | '\u{00AD}'
                | '\u{034F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0001}'
                | '\u{E0020}'..='\u{E007F}'
        )
    })
}

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
    note_text: String,
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
            note_text: note_text.to_owned(),
            fingerprint,
        }
    }

    /// Kalibrasyon parmak izini döndürür.
    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Kalibrasyon parmak izini URL-safe Base64 (padding'siz) olarak döndürür.
    #[must_use]
    pub fn fingerprint_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.fingerprint)
    }

    /// Kalibrasyon parmak izini hex (küçük harf) olarak döndürür.
    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    /// Normalize edilmiş kalibrasyon metnini döndürür.
    #[must_use]
    pub fn note_text(&self) -> &str {
        &self.note_text
    }
}

/// Organizasyon tuzu ve kalibrasyon metninden kalibrasyon bilgisi üretir.
///
/// # Errors
/// Girdi boyutları bekleneni sağlamazsa veya HKDF işlemi başarısız olursa `CoreError`
/// döndürülür.
/// Kalibrasyon metni otomatik olarak NFC normalize edilir ve boşluk dizileri tek
/// boşluğa indirgenir; böylece aynı anlamlı içerik aynı kimliği üretir.
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
    validate_org_salt(org_salt)?;
    let normalized_note = normalize_calibration_text(note_text)?;
    let calibration = Calibration::new(org_salt, &normalized_note);
    let id = calibration.id.as_str().to_owned();
    Ok((calibration, id))
}

/// Kalibrasyon metnini normalize ederek doğrular.
///
/// Girdi metni NFC formuna dönüştürülür, fazladan boşluklar tek boşluğa indirgenir,
/// kontrol karakterleri ve görünmez biçimlendirme işaretleri reddedilir.
///
/// # Errors
/// Metin boş, çok uzun veya yasaklı kontrol karakterleri içeriyorsa `CoreError`
/// döner.
#[allow(clippy::missing_panics_doc)]
pub fn normalize_calibration_text(note_text: &str) -> Result<String, CoreError> {
    let normalized_note = normalize_note_text(note_text);
    validate_note_text(note_text, &normalized_note)?;
    Ok(normalized_note)
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

const fn validate_org_salt(org_salt: &[u8]) -> Result<(), CoreError> {
    if org_salt.len() < MIN_ORG_SALT_LEN {
        return Err(CoreError::salt_too_short("org salt must be >= 8 bytes"));
    }

    Ok(())
}

fn validate_note_text(raw_note_text: &str, normalized_note_text: &str) -> Result<(), CoreError> {
    if normalized_note_text.len() > MAX_NOTE_LEN {
        return Err(CoreError::invalid_input(
            "calibration text must be <= 2048 bytes",
        ));
    }

    if normalized_note_text.is_empty() {
        return Err(CoreError::invalid_input(
            "calibration text must not be empty",
        ));
    }

    if raw_note_text
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Err(CoreError::invalid_input(
            "calibration text contains disallowed control characters",
        ));
    }

    if find_invisible_format_char(raw_note_text)
        .or_else(|| find_invisible_format_char(normalized_note_text))
        .is_some()
    {
        return Err(CoreError::invalid_input(
            "calibration text contains invisible formatting characters",
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
        assert_eq!(cal_a.note_text(), cal_b.note_text());
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
    fn rejects_invisible_format_characters() {
        let err = calib_from_text(b"org-salt", "Prod\u{200B}2025").unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));

        let err = normalize_calibration_text("Prod\u{202E}2025").unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn rejects_overlong_note() {
        let long = "a".repeat(MAX_NOTE_LEN + 1);
        let err = calib_from_text(b"org-salt", &long).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn normalizes_unicode_and_whitespace() {
        let baseline = "Neudzulab Prod 2025";
        let variant_spacing = "  Neudzulab\nProd\t2025  ";
        let composed = "\u{00C5}rhus | Kanal";
        let decomposed = "A\u{030A}rhus | Kanal";

        let (cal_a, id_a) = calib_from_text(b"org-salt", baseline).expect("calibration");
        let (cal_b, id_b) = calib_from_text(b"org-salt", variant_spacing).expect("calibration");
        let (_, id_c) = calib_from_text(b"org-salt", composed).expect("calibration");
        let (_, id_d) = calib_from_text(b"org-salt", decomposed).expect("calibration");

        assert_eq!(cal_a, cal_b);
        assert_eq!(id_a, id_b);
        assert_eq!(id_c, id_d);
        let normalized = normalize_calibration_text(baseline).expect("normalize");
        assert_eq!(cal_a.note_text(), normalized);
        assert_eq!(cal_b.note_text(), normalized);
    }

    #[test]
    fn fingerprint_b64_is_url_safe() {
        let (calibration, _) = calib_from_text(b"org-salt", "note").expect("calibration");
        let expected = URL_SAFE_NO_PAD.encode(calibration.fingerprint());
        assert_eq!(calibration.fingerprint_b64(), expected);
        assert!(!calibration.fingerprint_b64().contains(['+', '/', '=']));
    }

    #[test]
    fn fingerprint_hex_matches_bytes() {
        let (calibration, _) = calib_from_text(b"org-salt", "note").expect("calibration");
        let expected = hex::encode(calibration.fingerprint());
        assert_eq!(calibration.fingerprint_hex(), expected);
        assert!(calibration
            .fingerprint_hex()
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }

    #[test]
    fn normalize_calibration_text_collapses_whitespace() {
        let normalized = normalize_calibration_text("  Aunsorm\nProd\t2025  ").expect("normalize");
        assert_eq!(normalized, "Aunsorm Prod 2025");
    }

    #[test]
    fn normalize_calibration_text_rejects_invalid_chars() {
        let err = normalize_calibration_text("Valid\u{07}Invalid").unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }
}
