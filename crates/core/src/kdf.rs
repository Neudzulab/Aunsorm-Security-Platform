use std::fmt;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use sysinfo::{System, SystemExt};
use zeroize::Zeroizing;

/// Zeroize garantisi sağlayan byte vektörü sargısı.
#[derive(Clone)]
pub struct SensitiveVec(Zeroizing<Vec<u8>>);

impl fmt::Debug for SensitiveVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitiveVec")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for SensitiveVec {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice()).into()
    }
}

impl Eq for SensitiveVec {}

impl SensitiveVec {
    /// Yeni bir `SensitiveVec` oluşturur.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// İçerdiği veriyi dilim olarak döndürür.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// İçerdiği veriyi mut dilim olarak döndürür.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl AsRef<[u8]> for SensitiveVec {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for SensitiveVec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Deref for SensitiveVec {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SensitiveVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

use crate::error::CoreError;

/// Argon2id parametre setini temsil eder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfProfile {
    /// Tur sayısı.
    pub t: u32,
    /// Bellek kullanım miktarı (KiB cinsinden).
    pub m_kib: u32,
    /// Paralellik derecesi.
    pub p: u32,
}

impl KdfProfile {
    /// Yeni bir profil oluşturur ve doğrular.
    ///
    /// # Errors
    /// Parametreler geçersiz olduğunda `CoreError::InvalidProfile` döner.
    pub const fn new(t: u32, m_kib: u32, p: u32) -> Result<Self, CoreError> {
        if t == 0 {
            return Err(CoreError::invalid_profile("t must be greater than zero"));
        }
        if m_kib < 8 {
            return Err(CoreError::invalid_profile("m_kib must be at least 8"));
        }
        if p == 0 {
            return Err(CoreError::invalid_profile("p must be greater than zero"));
        }
        Ok(Self { t, m_kib, p })
    }

    /// Profil için hazır tanımlı değerler döndürür.
    #[must_use]
    pub fn preset(preset: KdfPreset) -> Self {
        match preset {
            KdfPreset::Mobile => Self::from_components(1, 32 * 1024, 1),
            KdfPreset::Low => Self::from_components(2, 64 * 1024, 1),
            KdfPreset::Medium => Self::from_components(3, 128 * 1024, 1),
            KdfPreset::High => Self::from_components(4, 256 * 1024, 2),
            KdfPreset::Ultra => Self::from_components(5, 512 * 1024, 2),
            KdfPreset::Auto => Self::auto(),
        }
    }

    const fn from_components(t: u32, m_kib: u32, p: u32) -> Self {
        Self { t, m_kib, p }
    }

    /// Donanım kaynaklarına göre en uygun profil seçimini yapar.
    #[must_use]
    pub fn auto() -> Self {
        let mut system = System::new_all();
        system.refresh_memory();
        system.refresh_cpu();
        let total_memory_mib = system.total_memory() / 1024;
        let physical_cores = system
            .physical_core_count()
            .unwrap_or_else(|| system.cpus().len().max(1));
        let preset = select_preset_for_specs(total_memory_mib, physical_cores);
        Self::preset(preset)
    }

    pub(crate) fn params(&self) -> Result<Params, CoreError> {
        Params::new(self.m_kib, self.t, self.p, None)
            .map_err(|_| CoreError::invalid_profile("argon2 parameters could not be constructed"))
    }
}

impl Default for KdfProfile {
    fn default() -> Self {
        Self::preset(KdfPreset::Medium)
    }
}

impl fmt::Display for KdfProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t={} m_kib={} p={}", self.t, self.m_kib, self.p)
    }
}

/// Hatalı ön ayar etiketini temsil eden hata türü.
///
/// # Examples
/// ```
/// use aunsorm_core::KdfPreset;
///
/// let err = KdfPreset::parse("invalid").unwrap_err();
/// assert_eq!(err.label(), "invalid");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfPresetParseError {
    invalid: String,
}

impl KdfPresetParseError {
    /// Hatanın oluşmasına sebep olan etiketi döndürür.
    ///
    /// # Examples
    /// ```
    /// use aunsorm_core::KdfPreset;
    ///
    /// let err = KdfPreset::parse("unknown").unwrap_err();
    /// assert_eq!(err.label(), "unknown");
    /// ```
    #[must_use]
    pub fn label(&self) -> &str {
        &self.invalid
    }
}

impl fmt::Display for KdfPresetParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown KDF preset '{}'", self.invalid)
    }
}

impl std::error::Error for KdfPresetParseError {}

/// Hazır profil isimleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfPreset {
    Mobile,
    Low,
    Medium,
    High,
    Ultra,
    Auto,
}

impl KdfPreset {
    /// KDF ön ayar etiketini ASCII küçük harfe dönüştürülmüş olarak döndürür.
    ///
    /// # Examples
    /// ```
    /// use aunsorm_core::KdfPreset;
    ///
    /// assert_eq!(KdfPreset::High.as_str(), "high");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mobile => "mobile",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Ultra => "ultra",
            Self::Auto => "auto",
        }
    }

    /// ASCII büyük/küçük harfe duyarsız şekilde KDF ön ayar etiketini çözümler.
    ///
    /// # Errors
    /// Girdi bilinen ön ayarlardan biriyle eşleşmediğinde `KdfPresetParseError` döner.
    ///
    /// # Examples
    /// ```
    /// use aunsorm_core::KdfPreset;
    ///
    /// let preset = KdfPreset::parse("Medium").expect("parse preset");
    /// assert_eq!(preset, KdfPreset::Medium);
    /// ```
    pub fn parse(value: &str) -> Result<Self, KdfPresetParseError> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "mobile" => Ok(Self::Mobile),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "ultra" => Ok(Self::Ultra),
            "auto" => Ok(Self::Auto),
            _ => Err(KdfPresetParseError {
                invalid: value.trim().to_string(),
            }),
        }
    }
}

impl fmt::Display for KdfPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KdfPreset {
    type Err = KdfPresetParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

const fn select_preset_for_specs(memory_mib: u64, cores: usize) -> KdfPreset {
    if memory_mib < 4_096 || cores <= 2 {
        KdfPreset::Mobile
    } else if memory_mib < 8_192 || cores <= 4 {
        KdfPreset::Low
    } else if memory_mib < 16_384 || cores <= 8 {
        KdfPreset::Medium
    } else if memory_mib < 32_768 || cores <= 16 {
        KdfPreset::High
    } else {
        KdfPreset::Ultra
    }
}

/// KDF yürütmesi hakkında meta bilgi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfInfo {
    /// Kullanılan profil.
    pub profile: KdfProfile,
    /// Parola saltı karması.
    pub password_salt_digest: [u8; 32],
    /// Kalibrasyon saltı karması.
    pub calibration_salt_digest: [u8; 32],
    /// Zincir saltı karması.
    pub chain_salt_digest: [u8; 32],
    /// Argon2 parametre versiyonu.
    pub version: Version,
}

impl KdfInfo {
    fn new(
        profile: KdfProfile,
        password_salt: &[u8],
        calibration_salt: &[u8],
        chain_salt: &[u8],
    ) -> Self {
        Self {
            profile,
            password_salt_digest: digest_salt(password_salt),
            calibration_salt_digest: digest_salt(calibration_salt),
            chain_salt_digest: digest_salt(chain_salt),
            version: Version::V0x13,
        }
    }
}

fn digest_salt(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"Aunsorm/1.01/salt-digest");
    hasher.update(input);
    hasher.finalize().into()
}

fn derive_hkdf_outputs(
    master: &[u8; 64],
    salt_calib: &[u8],
    salt_chain: &[u8],
) -> Result<(SensitiveVec, SensitiveVec), CoreError> {
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(b"Aunsorm/1.01/hkdf-salt");
    salt_hasher.update(salt_calib);
    salt_hasher.update(salt_chain);
    let hkdf_salt = salt_hasher.finalize();

    let hk = Hkdf::<Sha256>::new(Some(&hkdf_salt), master);

    let mut seed64 = SensitiveVec::new(vec![0_u8; 64]);
    let mut pdk = SensitiveVec::new(vec![0_u8; 32]);
    let mut info_seed = b"Aunsorm/1.01/seed64".to_vec();
    info_seed.extend_from_slice(salt_calib);
    hk.expand(&info_seed, seed64.as_mut_slice())
        .map_err(|_| CoreError::hkdf_length())?;

    let mut info_pdk = b"Aunsorm/1.01/pdk".to_vec();
    info_pdk.extend_from_slice(salt_chain);
    hk.expand(&info_pdk, pdk.as_mut_slice())
        .map_err(|_| CoreError::hkdf_length())?;

    Ok((seed64, pdk))
}

/// Parola ve salt girdilerinden 64 baytlık tohum ve paket türetme anahtarı üretir.
///
/// Fonksiyon Argon2id algoritmasını kullanır; çıktı deterministiktir ve aynı girdiler
/// tekrarlandığında aynı sonuçlar alınır.
///
/// # Errors
/// Salt uzunlukları yetersiz olduğunda veya Argon2/HKDF işlemleri başarısız olduğunda
/// `CoreError` döner.
///
/// * `CoreError::InvalidInput` — Parola boş olduğunda.
///
/// # Örnek
/// ```
/// use aunsorm_core::{kdf::{KdfProfile, KdfPreset}, derive_seed64_and_pdk};
///
/// let profile = KdfProfile::preset(KdfPreset::Low);
/// let password = "correct horse battery staple";
/// let salt_pwd = b"demo-pwd-salt";
/// let salt_calib = b"demo-calib-salt";
/// let salt_chain = b"demo-chain-salt";
/// let (seed, pdk, info) = derive_seed64_and_pdk(
///     password,
///     salt_pwd,
///     salt_calib,
///     salt_chain,
///     profile,
/// ).expect("kdf");
/// assert_eq!(seed.len(), 64);
/// assert_eq!(pdk.len(), 32);
/// assert_eq!(info.profile, profile);
/// ```
#[allow(clippy::missing_panics_doc)]
pub fn derive_seed64_and_pdk(
    password: &str,
    salt_pwd: &[u8],
    salt_calib: &[u8],
    salt_chain: &[u8],
    profile: KdfProfile,
) -> Result<(SensitiveVec, SensitiveVec, KdfInfo), CoreError> {
    if password.is_empty() {
        return Err(CoreError::invalid_input("password must not be empty"));
    }

    if salt_pwd.len() < 8 {
        return Err(CoreError::salt_too_short(
            "password salt must be >= 8 bytes",
        ));
    }
    if salt_calib.len() < 8 {
        return Err(CoreError::salt_too_short(
            "calibration salt must be >= 8 bytes",
        ));
    }
    if salt_chain.len() < 8 {
        return Err(CoreError::salt_too_short("chain salt must be >= 8 bytes"));
    }

    let params = profile.params()?;
    let argon2 = Argon2::new_with_secret(salt_chain, Algorithm::Argon2id, Version::V0x13, params)
        .map_err(CoreError::Argon2Config)?;
    let mut master = Zeroizing::new([0_u8; 64]);
    argon2
        .hash_password_into(password.as_bytes(), salt_pwd, master.as_mut())
        .map_err(CoreError::Argon2Config)?;

    let (seed64, pdk) = derive_hkdf_outputs(&master, salt_calib, salt_chain)?;

    let info = KdfInfo::new(profile, salt_pwd, salt_calib, salt_chain);

    Ok((seed64, pdk, info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_profiles_are_valid() {
        for preset in [
            KdfPreset::Mobile,
            KdfPreset::Low,
            KdfPreset::Medium,
            KdfPreset::High,
            KdfPreset::Ultra,
            KdfPreset::Auto,
        ] {
            let profile = KdfProfile::preset(preset);
            assert!(profile.params().is_ok());
        }
    }

    #[test]
    fn auto_selection_scales_with_resources() {
        assert_eq!(select_preset_for_specs(2_048, 2), KdfPreset::Mobile);
        assert_eq!(select_preset_for_specs(6_144, 4), KdfPreset::Low);
        assert_eq!(select_preset_for_specs(12_288, 6), KdfPreset::Medium);
        assert_eq!(select_preset_for_specs(24_576, 12), KdfPreset::High);
        assert_eq!(select_preset_for_specs(65_536, 24), KdfPreset::Ultra);
    }

    #[test]
    fn derive_seed64_is_deterministic() {
        let profile = KdfProfile::preset(KdfPreset::Low);
        let password = "test";
        let salt_pwd = b"12345678";
        let salt_calib = b"abcdefgh";
        let salt_chain = b"ABCDEFGH";

        let (seed_a, pdk_a, info_a) =
            derive_seed64_and_pdk(password, salt_pwd, salt_calib, salt_chain, profile).unwrap();
        let (seed_b, pdk_b, info_b) =
            derive_seed64_and_pdk(password, salt_pwd, salt_calib, salt_chain, profile).unwrap();

        assert_eq!(seed_a, seed_b);
        assert_eq!(pdk_a, pdk_b);
        assert_eq!(info_a.profile, info_b.profile);
        assert_eq!(info_a.password_salt_digest, info_b.password_salt_digest);
    }

    #[test]
    fn derive_seed64_rejects_empty_password() {
        let profile = KdfProfile::preset(KdfPreset::Low);
        let err =
            derive_seed64_and_pdk("", b"12345678", b"abcdefgh", b"ABCDEFGH", profile).unwrap_err();

        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn sensitive_vec_comparison_is_constant_time_like() {
        let a = SensitiveVec::new(vec![0xAA, 0xBB, 0xCC]);
        let mut b = SensitiveVec::new(vec![0xAA, 0xBB, 0xCC]);
        let c = SensitiveVec::new(vec![0xAA, 0xBB, 0xCD]);
        let shorter = SensitiveVec::new(vec![0xAA, 0xBB]);

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, shorter);

        b.as_mut_slice()[2] ^= 0x01;
        assert_ne!(a, b);
    }

    #[test]
    fn sensitive_vec_debug_is_redacted() {
        let secret = SensitiveVec::new(vec![0x41, 0x42, 0x43, 0x44]);
        let formatted = format!("{secret:?}");

        assert!(formatted.contains("SensitiveVec"));
        assert!(formatted.contains("len: 4"));
        assert!(!formatted.contains("0x41"));
        assert!(!formatted.contains("0x42"));
    }

    #[test]
    fn preset_parse_accepts_case_insensitive_labels() {
        let cases = [
            ("Mobile", KdfPreset::Mobile),
            ("LOW", KdfPreset::Low),
            ("medium", KdfPreset::Medium),
            ("High", KdfPreset::High),
            ("ULTRA", KdfPreset::Ultra),
            ("auto", KdfPreset::Auto),
        ];

        for (label, expected) in cases {
            let preset = KdfPreset::parse(label).expect("parse preset");
            assert_eq!(preset, expected);
            assert_eq!(preset.as_str(), expected.as_str());
        }
    }

    #[test]
    fn preset_parse_rejects_unknown_label() {
        let err = KdfPreset::parse("unsupported").unwrap_err();
        assert_eq!(err.label(), "unsupported");
        assert_eq!(err.to_string(), "unknown KDF preset 'unsupported'");
    }
}
