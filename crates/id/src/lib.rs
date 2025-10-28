#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![doc = "Projeler arası HEAD bağlı benzersiz kimlik üreticisi."]

mod rng;

pub use crate::rng::{create_aunsorm_rng, AunsormNativeRng};

use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use once_cell::sync::Lazy;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const DEFAULT_NAMESPACE: &str = "aunsorm";
const HEAD_ENV_KEYS: &[&str] = &[
    "AUNSORM_HEAD",
    "VERGEN_GIT_SHA",
    "GIT_COMMIT",
    "GITHUB_SHA",
    "CI_COMMIT_SHA",
];
const FINGERPRINT_LEN: usize = 10;
const FINGERPRINT_PREFIX_BYTES: usize = 4;
const ENTROPY_LEN: usize = 8;
const TIMESTAMP_LEN: usize = 8;
const COUNTER_LEN: usize = 8;
const PAYLOAD_LEN: usize = FINGERPRINT_LEN + ENTROPY_LEN + TIMESTAMP_LEN + COUNTER_LEN;

static PROCESS_ENTROPY: Lazy<[u8; ENTROPY_LEN]> = Lazy::new(|| {
    let mut rng = crate::rng::create_aunsorm_rng();
    let mut entropy = [0_u8; ENTROPY_LEN];
    rng.fill_bytes(&mut entropy);
    entropy
});

/// Kimlik üretimi sırasında oluşabilecek hatalar.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdError {
    /// Ortamda HEAD bilgisi bulunamadı.
    #[error(
        "git HEAD bilgisi bulunamadı; AUNSORM_HEAD veya GITHUB_SHA gibi değişkenleri sağlayın"
    )]
    MissingHead,
    /// HEAD değeri yeterince uzun değil.
    #[error("git HEAD karması en az 7 hex karakter olmalıdır")]
    HeadTooShort,
    /// HEAD değeri hex karakterlerinden oluşmuyor.
    #[error("git HEAD karması yalnızca hex karakterlerden oluşmalıdır")]
    HeadNotHex,
    /// Namespace boş veya sadece özel karakterlerden oluşuyor.
    #[error("namespace en az bir alfasayısal karakter içermelidir")]
    InvalidNamespace,
    /// Namespace izin verilen maksimum uzunluğu aştı.
    #[error("namespace uzunluğu {max} değerini aşamaz")]
    NamespaceTooLong { max: usize },
    /// Base64 ile kodlanan payload çözümlenemedi.
    #[error("kimlik payload'ı çözümlenemedi")]
    InvalidPayload,
    /// Kimlik biçimi beklendiği gibi değil.
    #[error("kimlik biçimi aid.<namespace>.<head>.<payload> kalıbıyla uyumlu değil")]
    InvalidFormat,
    /// Kimlik içerisindeki HEAD parmak izi beklenen değerle uyuşmuyor.
    #[error("kimlik içerisindeki HEAD parmak izi beklenen öneki taşımıyor")]
    FingerprintMismatch,
    /// Sistem saati Unix epoch öncesini döndürdü.
    #[error("sistem saati unix epoch öncesini döndürdü")]
    TimeBeforeEpoch,
    /// Mikro saniye değeri `u64` üst sınırını aştı.
    #[error("mikro saniye değeri u64 sınırını aşıyor")]
    TimeOverflow,
}

/// HEAD karması baz alınarak benzersiz kimlik üreten yapı.
///
/// # Examples
///
/// ```
/// use aunsorm_id::HeadIdGenerator;
///
/// let generator = HeadIdGenerator::with_namespace(
///     "0123456789abcdef0123456789abcdef01234567",
///     "inventory",
/// )?;
/// let id = generator.next_id()?;
/// assert!(id.as_str().starts_with("aid.inventory."));
/// # Ok::<(), aunsorm_id::IdError>(())
/// ```
#[derive(Debug)]
pub struct HeadIdGenerator {
    namespace: String,
    fingerprint: [u8; FINGERPRINT_LEN],
    prefix_hex: String,
    counter: AtomicU64,
    last_timestamp: AtomicU64,
}

impl HeadIdGenerator {
    /// Ortam değişkenlerinden HEAD bilgisini çekip jeneratör oluşturur.
    ///
    /// Öncelik sırası `AUNSORM_HEAD`, `VERGEN_GIT_SHA`, `GIT_COMMIT`,
    /// `GITHUB_SHA`, `CI_COMMIT_SHA` şeklindedir. Namespace belirtilmezse
    /// `"aunsorm"` varsayılır.
    ///
    /// # Errors
    ///
    /// Ortamda geçerli bir HEAD değeri yoksa veya namespace uygunsuz ise
    /// [`IdError`] döner.
    pub fn from_env() -> Result<Self, IdError> {
        let namespace =
            std::env::var("AUNSORM_ID_NAMESPACE").unwrap_or_else(|_| DEFAULT_NAMESPACE.to_owned());
        Self::from_env_with_namespace(namespace)
    }

    /// Ortam değişkenlerinden HEAD bilgisini okuyarak verilen namespace ile
    /// jeneratörü oluşturur.
    ///
    /// Bu yardımcı, varsayılan namespace yerine çalışma anında sağlanan
    /// namespace'i kullanarak generator oluşturmayı kolaylaştırır.
    ///
    /// # Errors
    ///
    /// Ortamda geçerli bir HEAD değeri yoksa veya namespace doğrulaması
    /// başarısız olursa [`IdError`] döner.
    pub fn from_env_with_namespace(namespace: impl AsRef<str>) -> Result<Self, IdError> {
        let head = infer_head_from_env()?;
        Self::with_namespace(head, namespace)
    }

    /// Verilen HEAD ve namespace ile jeneratör oluşturur.
    ///
    /// Namespace yalnızca ASCII alfasayısal karakterler ve tire (`-`) içerecek
    /// şekilde normalize edilir. Ardışık olmayan tireler korunur; diğer tüm
    /// karakterler tireye dönüştürülür ve baş/son tireler atılır.
    ///
    /// # Errors
    ///
    /// HEAD değeri yeterince uzun değilse, hex dışı karakter içeriyorsa veya
    /// namespace boş/uzun ise [`IdError`] döner.
    pub fn with_namespace(
        head: impl AsRef<str>,
        namespace: impl AsRef<str>,
    ) -> Result<Self, IdError> {
        let normalized_head = normalize_head(head.as_ref())?;
        let namespace = normalize_namespace(namespace.as_ref())?;
        let fingerprint = fingerprint_from_head(&normalized_head);
        let prefix_hex = hex::encode(&fingerprint[..FINGERPRINT_PREFIX_BYTES]);
        let mut rng = crate::rng::create_aunsorm_rng();
        let counter_seed = rng.next_u64();
        Ok(Self {
            namespace,
            fingerprint,
            prefix_hex,
            counter: AtomicU64::new(counter_seed),
            last_timestamp: AtomicU64::new(0),
        })
    }

    /// Varsayılan namespace ile jeneratör oluşturur.
    ///
    /// # Errors
    ///
    /// HEAD değeri yeterince uzun değilse veya hex dışı karakter içeriyorsa
    /// [`IdError`] döner.
    pub fn new(head: impl AsRef<str>) -> Result<Self, IdError> {
        Self::with_namespace(head, DEFAULT_NAMESPACE)
    }

    /// Bir sonraki benzersiz kimliği üretir.
    ///
    /// Kimlikler `aid.<namespace>.<head>.<payload>` biçiminde döner ve
    /// payload alanı URL güvenli Base64 ile kodlanmış süreç entropisi,
    /// monotonik zaman damgası ve atomik sayaç içerir.
    ///
    /// # Errors
    ///
    /// Sistem saati Unix epoch öncesine dönerse [`IdError::TimeBeforeEpoch`]
    /// döner.
    pub fn next_id(&self) -> Result<HeadStampedId, IdError> {
        let timestamp = unix_micros(SystemTime::now())?;
        let monotonic = self.next_monotonic_timestamp(timestamp);
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);

        let mut payload = [0_u8; PAYLOAD_LEN];
        payload[..FINGERPRINT_LEN].copy_from_slice(&self.fingerprint);
        payload[FINGERPRINT_LEN..FINGERPRINT_LEN + ENTROPY_LEN]
            .copy_from_slice(&PROCESS_ENTROPY[..]);
        payload[FINGERPRINT_LEN + ENTROPY_LEN..FINGERPRINT_LEN + ENTROPY_LEN + TIMESTAMP_LEN]
            .copy_from_slice(&monotonic.to_be_bytes());
        payload[FINGERPRINT_LEN + ENTROPY_LEN + TIMESTAMP_LEN..]
            .copy_from_slice(&counter.to_be_bytes());

        let encoded = URL_SAFE_NO_PAD.encode(payload);
        let raw = format!("aid.{}.{}.{}", self.namespace, self.prefix_hex, encoded);

        Ok(HeadStampedId {
            raw,
            namespace: self.namespace.clone(),
            head_fingerprint: self.fingerprint,
            timestamp_micros: monotonic,
            counter,
        })
    }

    /// Namespace değerini döner.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// HEAD parmak izi önekini döner (8 hex karakter).
    #[must_use]
    pub fn head_prefix(&self) -> &str {
        &self.prefix_hex
    }

    /// HEAD parmak izini ham byte dizisi olarak döner.
    ///
    /// # Examples
    ///
    /// ```
    /// use aunsorm_id::HeadIdGenerator;
    ///
    /// let generator = HeadIdGenerator::with_namespace(
    ///     "0123456789abcdef0123456789abcdef01234567",
    ///     "inventory",
    /// )?;
    /// let fingerprint = generator.head_fingerprint_bytes();
    /// assert_eq!(fingerprint.len(), 10);
    /// assert_ne!(fingerprint, [0_u8; 10]);
    /// # Ok::<(), aunsorm_id::IdError>(())
    /// ```
    #[must_use]
    pub const fn head_fingerprint_bytes(&self) -> [u8; FINGERPRINT_LEN] {
        self.fingerprint
    }

    fn next_monotonic_timestamp(&self, candidate: u64) -> u64 {
        let mut last = self.last_timestamp.load(Ordering::SeqCst);
        let mut next = candidate;
        loop {
            if next <= last {
                next = last + 1;
            }
            match self.last_timestamp.compare_exchange(
                last,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return next,
                Err(observed) => {
                    last = observed;
                    if next <= last {
                        next = last + 1;
                    }
                }
            }
        }
    }
}

/// HEAD parmak izi ve meta bilgileri ile birlikte kimliği temsil eder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadStampedId {
    raw: String,
    namespace: String,
    head_fingerprint: [u8; FINGERPRINT_LEN],
    timestamp_micros: u64,
    counter: u64,
}

impl HeadStampedId {
    /// Kimliğin düz metin gösterimini döner.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Namespace değerini döner.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// HEAD parmak izi önekini 8 hex karakter olarak döner.
    #[must_use]
    pub fn head_prefix(&self) -> String {
        hex::encode(&self.head_fingerprint[..FINGERPRINT_PREFIX_BYTES])
    }

    /// HEAD parmak izini 20 hex karakter olarak döner.
    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.head_fingerprint)
    }

    /// HEAD parmak izini ham byte dizisi olarak döner.
    ///
    /// # Examples
    ///
    /// ```
    /// use aunsorm_id::{HeadIdGenerator, IdError};
    ///
    /// let generator = HeadIdGenerator::new(
    ///     "0123456789abcdef0123456789abcdef01234567",
    /// )?;
    /// let id = generator.next_id()?;
    /// let fingerprint = id.fingerprint_bytes();
    /// assert_eq!(fingerprint.len(), 10);
    /// assert_ne!(fingerprint, [0_u8; 10]);
    /// # Ok::<(), IdError>(())
    /// ```
    #[must_use]
    pub const fn fingerprint_bytes(&self) -> [u8; FINGERPRINT_LEN] {
        self.head_fingerprint
    }

    /// Verilen HEAD karmasının bu kimlik ile uyumlu olup olmadığını kontrol eder.
    ///
    /// HEAD değeri normalize edilerek parmak izi yeniden hesaplanır ve kimlikteki
    /// fingerprint ile karşılaştırılır.
    ///
    /// # Examples
    ///
    /// ```
    /// use aunsorm_id::{HeadIdGenerator, IdError};
    ///
    /// let generator = HeadIdGenerator::new(
    ///     "0123456789abcdef0123456789abcdef01234567",
    /// )?;
    /// let id = generator.next_id()?;
    /// assert!(id.matches_head(
    ///     "0123456789abcdef0123456789abcdef01234567",
    /// )?);
    /// assert!(!id.matches_head(
    ///     "fedcba9876543210fedcba9876543210fedcba98",
    /// )?);
    /// # Ok::<(), IdError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// HEAD değeri yeterince uzun değilse veya hex dışı karakter içeriyorsa
    /// [`IdError`] döner.
    pub fn matches_head(&self, head: impl AsRef<str>) -> Result<bool, IdError> {
        let normalized = normalize_head(head.as_ref())?;
        Ok(fingerprint_from_head(&normalized) == self.head_fingerprint)
    }

    /// Mikro saniye cinsinden zaman damgasını döner.
    #[must_use]
    pub const fn timestamp_micros(&self) -> u64 {
        self.timestamp_micros
    }

    /// Atomik sayaç değerini döner.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }
}

impl fmt::Display for HeadStampedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl AsRef<str> for HeadStampedId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for HeadStampedId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_head_id(s)
    }
}

#[cfg(feature = "serde")]
impl Serialize for HeadStampedId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for HeadStampedId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        parse_head_id(&raw).map_err(serde::de::Error::custom)
    }
}

/// Kimliği çözümleyip doğrulayan yardımcı fonksiyon.
///
/// # Examples
///
/// ```
/// use aunsorm_id::{parse_head_id, HeadIdGenerator};
///
/// let generator = HeadIdGenerator::new(
///     "0123456789abcdef0123456789abcdef01234567",
/// )?;
/// let produced = generator.next_id()?;
/// let parsed = parse_head_id(produced.as_str())?;
/// assert_eq!(parsed.as_str(), produced.as_str());
/// # Ok::<(), aunsorm_id::IdError>(())
/// ```
///
/// # Errors
///
/// Kimlik biçimi bozuksa, payload decode edilemiyorsa veya HEAD parmak izi
/// tutarsızsa [`IdError`] döner.
pub fn parse_head_id(raw: &str) -> Result<HeadStampedId, IdError> {
    let mut parts = raw.split('.');
    let Some(prefix) = parts.next() else {
        return Err(IdError::InvalidFormat);
    };
    if prefix != "aid" {
        return Err(IdError::InvalidFormat);
    }
    let Some(namespace) = parts.next() else {
        return Err(IdError::InvalidFormat);
    };
    let normalized_namespace = normalize_namespace(namespace)?;
    if normalized_namespace != namespace {
        return Err(IdError::InvalidNamespace);
    }
    let Some(head_prefix) = parts.next() else {
        return Err(IdError::InvalidFormat);
    };
    let Some(payload) = parts.next() else {
        return Err(IdError::InvalidFormat);
    };
    if parts.next().is_some() {
        return Err(IdError::InvalidFormat);
    }
    if head_prefix.len() != FINGERPRINT_PREFIX_BYTES * 2
        || !head_prefix.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(IdError::InvalidFormat);
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|_| IdError::InvalidPayload)?;
    if decoded.len() != PAYLOAD_LEN {
        return Err(IdError::InvalidPayload);
    }

    let mut fingerprint = [0_u8; FINGERPRINT_LEN];
    fingerprint.copy_from_slice(&decoded[..FINGERPRINT_LEN]);

    let prefix_expected = hex::encode(&fingerprint[..FINGERPRINT_PREFIX_BYTES]);
    if prefix_expected != head_prefix {
        return Err(IdError::FingerprintMismatch);
    }

    let mut timestamp_bytes = [0_u8; TIMESTAMP_LEN];
    timestamp_bytes.copy_from_slice(
        &decoded[FINGERPRINT_LEN + ENTROPY_LEN..FINGERPRINT_LEN + ENTROPY_LEN + TIMESTAMP_LEN],
    );
    let timestamp = u64::from_be_bytes(timestamp_bytes);

    let mut counter_bytes = [0_u8; COUNTER_LEN];
    counter_bytes.copy_from_slice(&decoded[FINGERPRINT_LEN + ENTROPY_LEN + TIMESTAMP_LEN..]);
    let counter = u64::from_be_bytes(counter_bytes);

    Ok(HeadStampedId {
        raw: raw.to_owned(),
        namespace: namespace.to_owned(),
        head_fingerprint: fingerprint,
        timestamp_micros: timestamp,
        counter,
    })
}

fn normalize_head(head: &str) -> Result<String, IdError> {
    let trimmed = head.trim();
    if trimmed.len() < 7 {
        return Err(IdError::HeadTooShort);
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(IdError::HeadNotHex);
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn normalize_namespace(namespace: &str) -> Result<String, IdError> {
    const MAX_LEN: usize = 32;
    let trimmed = namespace.trim();
    if trimmed.is_empty() {
        return Err(IdError::InvalidNamespace);
    }
    let mut normalized = String::with_capacity(trimmed.len());
    let mut last_dash = false;
    for ch in trimmed.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            Some(ch.to_ascii_lowercase())
        } else if matches!(ch, '-' | '_' | ':' | '/' | '.') {
            Some('-')
        } else {
            None
        };
        if let Some(mut candidate) = mapped {
            if candidate == '-' {
                if last_dash {
                    continue;
                }
                last_dash = true;
            } else {
                last_dash = false;
                candidate = candidate.to_ascii_lowercase();
            }
            normalized.push(candidate);
        }
    }
    let normalized = normalized.trim_matches('-').to_owned();
    if normalized.is_empty() {
        return Err(IdError::InvalidNamespace);
    }
    if normalized.len() > MAX_LEN {
        return Err(IdError::NamespaceTooLong { max: MAX_LEN });
    }
    Ok(normalized)
}

fn fingerprint_from_head(head: &str) -> [u8; FINGERPRINT_LEN] {
    let digest = Sha256::digest(head.as_bytes());
    let mut out = [0_u8; FINGERPRINT_LEN];
    out.copy_from_slice(&digest[..FINGERPRINT_LEN]);
    out
}

fn infer_head_from_env() -> Result<String, IdError> {
    for key in HEAD_ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_owned());
            }
        }
    }
    Err(IdError::MissingHead)
}

fn unix_micros(time: SystemTime) -> Result<u64, IdError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IdError::TimeBeforeEpoch)?;
    u64::try_from(duration.as_micros()).map_err(|_| IdError::TimeOverflow)
}

#[cfg(test)]
mod tests {
    use super::{
        parse_head_id, HeadIdGenerator, IdError, FINGERPRINT_LEN, FINGERPRINT_PREFIX_BYTES,
        PROCESS_ENTROPY,
    };
    use base64::Engine;
    use sha2::{Digest, Sha256};

    #[cfg(feature = "serde")]
    use super::HeadStampedId;

    const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn generates_unique_ids() {
        let generator = HeadIdGenerator::with_namespace(HEAD, "inventory").expect("generator");
        let first = generator.next_id().expect("first");
        let second = generator.next_id().expect("second");
        assert_ne!(first.as_str(), second.as_str());
        assert!(second.timestamp_micros() >= first.timestamp_micros());
        assert!(second.counter() > first.counter());
        assert_eq!(first.namespace(), "inventory");
        assert!(first.as_str().starts_with("aid.inventory."));
    }

    #[test]
    fn parse_roundtrip() {
        let generator = HeadIdGenerator::new(HEAD).expect("generator");
        let produced = generator.next_id().expect("id");
        let parsed = parse_head_id(produced.as_str()).expect("parsed");
        assert_eq!(parsed.as_str(), produced.as_str());
        assert_eq!(parsed.namespace(), generator.namespace());
        assert_eq!(parsed.head_prefix(), generator.head_prefix());
        assert_eq!(parsed.fingerprint_hex(), produced.fingerprint_hex());
        assert_eq!(parsed.counter(), produced.counter());
        assert_eq!(parsed.timestamp_micros(), produced.timestamp_micros());
    }

    #[test]
    fn rejects_short_head() {
        let err = HeadIdGenerator::new("dead").expect_err("short head");
        assert_eq!(err, IdError::HeadTooShort);
    }

    #[test]
    fn rejects_non_hex_head() {
        let err = HeadIdGenerator::new("zzzzzzzz").expect_err("non hex");
        assert_eq!(err, IdError::HeadNotHex);
    }

    #[test]
    fn namespace_normalization() {
        let generator =
            HeadIdGenerator::with_namespace(HEAD, " Inventory/West ").expect("generator");
        assert_eq!(generator.namespace(), "inventory-west");
        let id = generator.next_id().expect("id");
        assert!(id.as_str().starts_with("aid.inventory-west."));
    }

    #[test]
    fn namespace_too_long() {
        let ns = "x".repeat(40);
        let err = HeadIdGenerator::with_namespace(HEAD, ns).expect_err("too long");
        assert_eq!(err, IdError::NamespaceTooLong { max: 32 });
    }

    #[test]
    fn fingerprint_bytes_exposed_for_generator_and_id() {
        let generator = HeadIdGenerator::new(HEAD).expect("generator");
        let expected = {
            let digest = Sha256::digest(HEAD.as_bytes());
            let mut out = [0_u8; FINGERPRINT_LEN];
            out.copy_from_slice(&digest[..FINGERPRINT_LEN]);
            out
        };

        assert_eq!(generator.head_fingerprint_bytes(), expected);

        let id = generator.next_id().expect("id");
        assert_eq!(id.fingerprint_bytes(), expected);
    }

    #[test]
    fn parse_invalid_prefix() {
        let generator = HeadIdGenerator::new(HEAD).expect("generator");
        let id = generator.next_id().expect("id");
        let tampered = id.as_str().replace("aid", "bad");
        assert!(matches!(
            parse_head_id(&tampered),
            Err(IdError::InvalidFormat)
        ));

        let mut tampered = id.as_str().to_owned();
        tampered.push_str(".extra");
        assert!(matches!(
            parse_head_id(&tampered),
            Err(IdError::InvalidFormat)
        ));

        let mut components = id.as_str().split('.').collect::<Vec<_>>();
        components[2] = "zzzzzzzz";
        let tampered = components.join(".");
        assert!(matches!(
            parse_head_id(&tampered),
            Err(IdError::InvalidFormat)
        ));

        let mut payload = id.as_str().rsplit_once('.').unwrap().1.to_owned();
        payload.push('-');
        let tampered = format!(
            "aid.{}.{}.{}",
            id.namespace(),
            generator.head_prefix(),
            payload
        );
        assert!(matches!(
            parse_head_id(&tampered),
            Err(IdError::InvalidPayload)
        ));
    }

    #[test]
    fn parse_rejects_non_canonical_namespace() {
        let generator = HeadIdGenerator::new(HEAD).expect("generator");
        let id = generator.next_id().expect("id");
        let payload = id
            .as_str()
            .rsplit_once('.')
            .map(|(_, payload)| payload.to_owned())
            .expect("payload");
        let head_prefix = generator.head_prefix().to_owned();

        for ns in ["Inventory", "-inventory", "inventory--west", ""] {
            let tampered = format!("aid.{ns}.{head_prefix}.{payload}");
            let err = parse_head_id(&tampered).expect_err("namespace should be rejected");
            assert_eq!(err, IdError::InvalidNamespace);
        }
    }

    #[test]
    fn fingerprint_must_match() {
        let generator = HeadIdGenerator::new(HEAD).expect("generator");
        let id = generator.next_id().expect("id");
        let mut decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(id.as_str().rsplit_once('.').unwrap().1)
            .expect("decoded");
        decoded[0] ^= 0xFF;
        let tampered_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded);
        let tampered = format!(
            "aid.{}.{}.{}",
            id.namespace(),
            generator.head_prefix(),
            tampered_payload
        );
        assert!(matches!(
            parse_head_id(&tampered),
            Err(IdError::FingerprintMismatch)
        ));
    }

    #[test]
    fn environment_integration_tests() {
        // Save current environment state at the start
        let prev_head = std::env::var("AUNSORM_HEAD").ok();
        let prev_vergen = std::env::var("VERGEN_GIT_SHA").ok();
        let prev_namespace = std::env::var("AUNSORM_ID_NAMESPACE").ok();

        // Test 1: env_fallbacks scenario
        {
            // Clear and set test environment for env_fallbacks
            std::env::remove_var("AUNSORM_HEAD");
            std::env::remove_var("AUNSORM_ID_NAMESPACE");
            std::env::set_var("VERGEN_GIT_SHA", HEAD);
            std::env::set_var("AUNSORM_ID_NAMESPACE", "ci/Flow");

            let generator = HeadIdGenerator::from_env().expect("env");
            assert_eq!(generator.namespace(), "ci-flow");
            let expected_prefix = {
                let digest = Sha256::digest(HEAD.as_bytes());
                hex::encode(&digest[..FINGERPRINT_PREFIX_BYTES])
            };
            assert_eq!(generator.head_prefix(), expected_prefix);
        }

        // Test 2: from_env_with_namespace_overrides_request_namespace scenario
        {
            // Clear and set test environment for namespace override test
            std::env::remove_var("AUNSORM_HEAD");
            std::env::remove_var("VERGEN_GIT_SHA");
            std::env::remove_var("AUNSORM_ID_NAMESPACE");
            std::env::set_var("AUNSORM_HEAD", HEAD);
            std::env::set_var("AUNSORM_ID_NAMESPACE", "default-ns");

            let generator =
                HeadIdGenerator::from_env_with_namespace("Ops/Delivery").expect("generator");
            assert_eq!(generator.namespace(), "ops-delivery");
            let expected_prefix = {
                let digest = Sha256::digest(HEAD.as_bytes());
                hex::encode(&digest[..FINGERPRINT_PREFIX_BYTES])
            };
            assert_eq!(generator.head_prefix(), expected_prefix);
        }

        // Restore original environment state at the end
        if let Some(value) = prev_head {
            std::env::set_var("AUNSORM_HEAD", value);
        } else {
            std::env::remove_var("AUNSORM_HEAD");
        }
        if let Some(value) = prev_vergen {
            std::env::set_var("VERGEN_GIT_SHA", value);
        } else {
            std::env::remove_var("VERGEN_GIT_SHA");
        }
        if let Some(value) = prev_namespace {
            std::env::set_var("AUNSORM_ID_NAMESPACE", value);
        } else {
            std::env::remove_var("AUNSORM_ID_NAMESPACE");
        }
    }

    #[test]
    fn process_entropy_is_non_zero() {
        assert!(PROCESS_ENTROPY.iter().any(|&b| b != 0));
    }

    #[test]
    fn matches_head_validates_expected_head() {
        let generator = HeadIdGenerator::new(HEAD).expect("generator");
        let id = generator.next_id().expect("id");
        assert!(id.matches_head(HEAD).expect("match"));

        let other_head = "fedcba9876543210fedcba9876543210fedcba98";
        assert!(!id.matches_head(other_head).expect("should not match"));
    }

    #[test]
    fn matches_head_propagates_head_errors() {
        let generator = HeadIdGenerator::new(HEAD).expect("generator");
        let id = generator.next_id().expect("id");
        let err = id.matches_head("invalid").expect_err("invalid head");
        assert_eq!(err, IdError::HeadNotHex);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip_preserves_id() {
        let generator = HeadIdGenerator::new(HEAD).expect("generator");
        let id = generator.next_id().expect("id");
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, format!("\"{}\"", id.as_str()));
        let decoded: HeadStampedId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, id);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_errors_wrap_parse_failures() {
        let err =
            serde_json::from_str::<HeadStampedId>("\"aid.invalid\"").expect_err("invalid payload");
        let message = err.to_string();
        assert!(message.contains("kimlik"), "unexpected error: {message}");
    }
}
