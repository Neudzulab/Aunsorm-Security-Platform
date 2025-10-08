use std::fmt;

use serde::{Deserialize, Serialize};

use crate::crypto::digest_bytes;

/// Desteklenen AEAD algoritmaları.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AeadAlgorithm {
    /// AES-256-GCM algoritması.
    #[serde(alias = "AES-GCM")]
    AesGcm,
    /// ChaCha20-Poly1305 algoritması.
    #[serde(alias = "CHACHA20-POLY1305")]
    Chacha20Poly1305,
    /// AES-SIV algoritması.
    #[cfg(feature = "aes-siv")]
    #[serde(alias = "AES-SIV")]
    AesSiv,
}

impl fmt::Display for AeadAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AesGcm => "aes-gcm",
            Self::Chacha20Poly1305 => "chacha20poly1305",
            #[cfg(feature = "aes-siv")]
            Self::AesSiv => "aes-siv",
        })
    }
}

impl AeadAlgorithm {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AesGcm => "aes-gcm",
            Self::Chacha20Poly1305 => "chacha20poly1305",
            #[cfg(feature = "aes-siv")]
            Self::AesSiv => "aes-siv",
        }
    }
}

/// KDF profilini temsil eden başlık alanı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderProfile {
    pub t: u32,
    pub m_kib: u32,
    pub p: u32,
}

impl From<aunsorm_core::KdfProfile> for HeaderProfile {
    fn from(value: aunsorm_core::KdfProfile) -> Self {
        Self {
            t: value.t,
            m_kib: value.m_kib,
            p: value.p,
        }
    }
}

impl HeaderProfile {
    #[must_use]
    pub const fn matches_profile(&self, profile: &aunsorm_core::KdfProfile) -> bool {
        self.t == profile.t && self.m_kib == profile.m_kib && self.p == profile.p
    }
}

/// Salt alanları.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderSalts {
    pub password: String,
    pub calibration: String,
    pub chain: String,
    pub coord: String,
}

impl HeaderSalts {
    #[must_use]
    pub fn from_bytes(password: &[u8], salts: &aunsorm_core::Salts) -> Self {
        Self {
            password: digest_bytes(password),
            calibration: digest_bytes(salts.calibration()),
            chain: digest_bytes(salts.chain()),
            coord: digest_bytes(salts.coord()),
        }
    }

    #[must_use]
    pub fn matches(&self, password: &[u8], salts: &aunsorm_core::Salts) -> bool {
        self.password == digest_bytes(password)
            && self.calibration == digest_bytes(salts.calibration())
            && self.chain == digest_bytes(salts.chain())
            && self.coord == digest_bytes(salts.coord())
    }
}

/// KEM bilgisi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderKem {
    pub kem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctkem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rbkem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ss: Option<String>,
}

impl HeaderKem {
    #[must_use]
    pub fn none() -> Self {
        Self {
            kem: "none".to_string(),
            pk: None,
            ctkem: None,
            rbkem: None,
            ss: None,
        }
    }
}

/// AEAD alanı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderAead {
    pub alg: AeadAlgorithm,
    pub nonce: String,
    pub aad_digest: String,
}

/// Oturum alanı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderSession {
    pub id: String,
    pub message_no: u64,
    pub new: bool,
}

/// Boyut bilgisi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderSizes {
    pub plaintext: usize,
    pub ciphertext: usize,
}

/// Paket başlığı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub version: String,
    pub profile: HeaderProfile,
    pub calib_id: String,
    pub coord_digest: String,
    pub salts: HeaderSalts,
    pub kem: HeaderKem,
    pub aead: HeaderAead,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<HeaderSession>,
    pub sizes: HeaderSizes,
    pub hdrmac: String,
}

impl Header {
    #[must_use]
    pub fn without_mac(&self) -> HeaderForMac<'_> {
        HeaderForMac {
            version: &self.version,
            profile: self.profile,
            calib_id: &self.calib_id,
            coord_digest: &self.coord_digest,
            salts: &self.salts,
            kem: &self.kem,
            aead: &self.aead,
            session: self.session.as_ref(),
            sizes: self.sizes,
        }
    }
}

#[derive(Serialize)]
pub struct HeaderForMac<'a> {
    pub version: &'a str,
    pub profile: HeaderProfile,
    pub calib_id: &'a str,
    pub coord_digest: &'a str,
    pub salts: &'a HeaderSalts,
    pub kem: &'a HeaderKem,
    pub aead: &'a HeaderAead,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<&'a HeaderSession>,
    pub sizes: HeaderSizes,
}
