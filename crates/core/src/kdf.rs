use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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
    pub const fn preset(preset: KdfPreset) -> Self {
        match preset {
            KdfPreset::Mobile => Self {
                t: 1,
                m_kib: 32 * 1024,
                p: 1,
            },
            KdfPreset::Low => Self {
                t: 2,
                m_kib: 64 * 1024,
                p: 1,
            },
            KdfPreset::Medium => Self {
                t: 3,
                m_kib: 128 * 1024,
                p: 1,
            },
            KdfPreset::High => Self {
                t: 4,
                m_kib: 256 * 1024,
                p: 2,
            },
            KdfPreset::Ultra => Self {
                t: 5,
                m_kib: 512 * 1024,
                p: 2,
            },
        }
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

/// Hazır profil isimleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfPreset {
    Mobile,
    Low,
    Medium,
    High,
    Ultra,
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
) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(b"Aunsorm/1.01/hkdf-salt");
    salt_hasher.update(salt_calib);
    salt_hasher.update(salt_chain);
    let hkdf_salt = salt_hasher.finalize();

    let hk = Hkdf::<Sha256>::new(Some(&hkdf_salt), master);

    let mut seed64 = vec![0_u8; 64];
    let mut pdk = vec![0_u8; 32];
    let mut info_seed = b"Aunsorm/1.01/seed64".to_vec();
    info_seed.extend_from_slice(salt_calib);
    hk.expand(&info_seed, &mut seed64)
        .map_err(|_| CoreError::hkdf_length())?;

    let mut info_pdk = b"Aunsorm/1.01/pdk".to_vec();
    info_pdk.extend_from_slice(salt_chain);
    hk.expand(&info_pdk, &mut pdk)
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
) -> Result<(Vec<u8>, Vec<u8>, KdfInfo), CoreError> {
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
        ] {
            let profile = KdfProfile::preset(preset);
            assert!(profile.params().is_ok());
        }
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
}
