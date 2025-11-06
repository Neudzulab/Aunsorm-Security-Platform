#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{JwtError, Result};

const RESERVED_STANDARD_CLAIMS: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];
const RESERVED_KEY_ERROR: &str = "reserved claim name must not appear in extras";
const CUSTOM_KEY_FORMAT_ERROR: &str = "custom claim keys must be camelCase alphanumeric";

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
    #[serde(skip_serializing_if = "Option::is_none", rename = "iss")]
    pub issuer: Option<String>,
    /// `sub`
    #[serde(skip_serializing_if = "Option::is_none", rename = "sub")]
    pub subject: Option<String>,
    /// `aud`
    #[serde(skip_serializing_if = "Option::is_none", rename = "aud")]
    pub audience: Option<Audience>,
    /// `exp`
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "serde_opt_timestamp",
        rename = "exp"
    )]
    pub expiration: Option<SystemTime>,
    /// `nbf`
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "serde_opt_timestamp",
        rename = "nbf"
    )]
    pub not_before: Option<SystemTime>,
    /// `iat`
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "serde_opt_timestamp",
        rename = "iat"
    )]
    pub issued_at: Option<SystemTime>,
    /// `jti`
    #[serde(skip_serializing_if = "Option::is_none", rename = "jti")]
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

    /// Özel claim alanlarının kurallara uyduğunu doğrular.
    ///
    /// # Errors
    ///
    /// `JwtError::InvalidClaim` döner:
    /// - `extras` içindeki anahtarlardan biri standart claim adlarıyla çakışırsa.
    /// - Anahtar camelCase biçimini bozarsa veya iç içe JSON değerleri camelCase
    ///   zorunluluğunu ihlal ederse.
    pub fn validate_custom_claims(&self) -> Result<()> {
        for key in self.extra.keys() {
            if RESERVED_STANDARD_CLAIMS.contains(&key.as_str()) {
                return Err(JwtError::InvalidClaim("extras", RESERVED_KEY_ERROR));
            }
            if !is_camel_case(key) {
                return Err(JwtError::InvalidClaim("extras", CUSTOM_KEY_FORMAT_ERROR));
            }
        }
        for value in self.extra.values() {
            if !validate_custom_value(value) {
                return Err(JwtError::InvalidClaim("extras", CUSTOM_KEY_FORMAT_ERROR));
            }
        }
        Ok(())
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
        if let (Some(exp), Some(iat)) = (self.expiration, self.issued_at) {
            if exp < iat {
                return Err(JwtError::InvalidClaim(
                    "exp",
                    "expiration must be after issued_at",
                ));
            }
        }
        if let (Some(nbf), Some(iat)) = (self.not_before, self.issued_at) {
            if nbf < iat {
                return Err(JwtError::InvalidClaim(
                    "nbf",
                    "not_before must be after issued_at",
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

fn is_camel_case(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() && ch != '_')
}

fn validate_custom_value(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.keys().all(|key| is_camel_case(key)) && map.values().all(validate_custom_value)
        }
        Value::Array(list) => list.iter().all(validate_custom_value),
        _ => true,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn temporal_consistency_accepts_monotonic_claims() {
        let base = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut claims = Claims::new();
        claims.issued_at = Some(base);
        claims.not_before = Some(base + Duration::from_secs(30));
        claims.expiration = Some(base + Duration::from_secs(120));
        assert!(
            claims.validate_temporal_consistency().is_ok(),
            "monotonic claims should pass"
        );
    }

    #[test]
    fn temporal_consistency_rejects_exp_before_not_before() {
        let base = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut claims = Claims::new();
        claims.not_before = Some(base + Duration::from_secs(120));
        claims.expiration = Some(base + Duration::from_secs(60));
        let err = claims
            .validate_temporal_consistency()
            .expect_err("expiration before not_before must fail");
        assert!(matches!(
            err,
            JwtError::InvalidClaim("exp", "expiration must be after not_before")
        ));
    }

    #[test]
    fn temporal_consistency_rejects_exp_before_issued() {
        let base = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut claims = Claims::new();
        claims.issued_at = Some(base + Duration::from_secs(120));
        claims.expiration = Some(base + Duration::from_secs(60));
        let err = claims
            .validate_temporal_consistency()
            .expect_err("expiration before issued_at must fail");
        assert!(matches!(
            err,
            JwtError::InvalidClaim("exp", "expiration must be after issued_at")
        ));
    }

    #[test]
    fn temporal_consistency_rejects_not_before_before_issued() {
        let base = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut claims = Claims::new();
        claims.issued_at = Some(base + Duration::from_secs(120));
        claims.not_before = Some(base + Duration::from_secs(60));
        let err = claims
            .validate_temporal_consistency()
            .expect_err("not_before before issued_at must fail");
        assert!(matches!(
            err,
            JwtError::InvalidClaim("nbf", "not_before must be after issued_at")
        ));
    }
}
