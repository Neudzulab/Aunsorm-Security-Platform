#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{JwtError, Result};

/// JWT `aud` alanı tekil veya çoklu değer alabilir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// Tekil hedef.
    Single(String),
    /// Çoklu hedef listesi.
    Multiple(Vec<String>),
}

impl Audience {
    /// Hedef listesinde verilen değerin bulunup bulunmadığını kontrol eder.
    #[must_use]
    pub fn contains(&self, candidate: &str) -> bool {
        match self {
            Self::Single(aud) => aud == candidate,
            Self::Multiple(list) => list.iter().any(|aud| aud == candidate),
        }
    }
}

/// JWT claim set'ini temsil eder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// `iss`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// `sub`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// `aud`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    /// `exp`
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "serde_opt_timestamp"
    )]
    pub expiration: Option<SystemTime>,
    /// `nbf`
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "serde_opt_timestamp"
    )]
    pub not_before: Option<SystemTime>,
    /// `iat`
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "serde_opt_timestamp"
    )]
    pub issued_at: Option<SystemTime>,
    /// `jti`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,
    /// Ek claim alanları.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Claims {
    /// Boş bir claim set'i oluşturur.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            issuer: None,
            subject: None,
            audience: None,
            expiration: None,
            not_before: None,
            issued_at: None,
            jwt_id: None,
            extra: BTreeMap::new(),
        }
    }

    /// `jti` alanı yoksa Aunsorm native RNG ile rastgele üretir.
    pub fn ensure_jwt_id(&mut self) {
        if self.jwt_id.is_none() {
            use crate::rng::AunsormNativeRng;
            let mut rng = AunsormNativeRng::new();
            let mut buf = [0_u8; 16];
            rng.fill_bytes(&mut buf);
            self.jwt_id = Some(hex::encode(buf));
        }
    }

    /// Claim'lerin zaman tutarlılığını kontrol eder.
    ///
    /// # Errors
    ///
    /// `exp` alanı `nbf` değerinden küçükse `JwtError::InvalidClaim` döner.
    pub fn validate_temporal_consistency(&self) -> Result<()> {
        if let (Some(exp), Some(nbf)) = (self.expiration, self.not_before) {
            if exp < nbf {
                return Err(JwtError::InvalidClaim(
                    "exp",
                    "expiration must be after not_before",
                ));
            }
        }
        Ok(())
    }

    /// `iat` alanını şu anki zamana ayarlar.
    pub fn set_issued_now(&mut self) {
        self.issued_at = Some(SystemTime::now());
    }

    /// `exp` alanını, şu andan verilen süre kadar sonrasına ayarlar.
    pub fn set_expiration_from_now(&mut self, ttl: Duration) {
        self.expiration = Some(SystemTime::now() + ttl);
    }
}

impl Default for Claims {
    fn default() -> Self {
        Self::new()
    }
}

/// Serde yardımcı modülü: `SystemTime` <-> unix epoch saniyesi.
mod serde_opt_timestamp {
    use super::{Duration, SystemTime, UNIX_EPOCH};
    use std::convert::TryFrom;
    use thiserror::Error;

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(
        value: &Option<SystemTime>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match value {
            Some(ts) => {
                serializer.serialize_some(&to_unix_seconds(*ts).map_err(serde::ser::Error::custom)?)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<SystemTime>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let opt: Option<i64> = serde::Deserialize::deserialize(deserializer)?;
        opt.map(from_unix_seconds)
            .transpose()
            .map_err(serde::de::Error::custom)
    }

    fn to_unix_seconds(value: SystemTime) -> std::result::Result<i64, TimeError> {
        let secs = value.duration_since(UNIX_EPOCH)?.as_secs();
        i64::try_from(secs).map_err(|_| TimeError::Overflow)
    }

    fn from_unix_seconds(value: i64) -> std::result::Result<SystemTime, TimeError> {
        if value < 0 {
            return Err(TimeError::BeforeEpoch);
        }
        let secs = u64::try_from(value).map_err(|_| TimeError::BeforeEpoch)?;
        Ok(UNIX_EPOCH + Duration::from_secs(secs))
    }

    #[derive(Debug, Error)]
    enum TimeError {
        #[error("timestamp before unix epoch")]
        BeforeEpoch,
        #[error("system time error: {0}")]
        SystemTime(#[from] std::time::SystemTimeError),
        #[error("timestamp overflow")]
        Overflow,
    }
}
