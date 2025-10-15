use std::collections::VecDeque;
use std::str::FromStr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http::header::{HeaderMap, ToStrError};
use thiserror::Error;

/// ACME protokolünde kullanılan `Replay-Nonce` başlığının adı.
pub const REPLAY_NONCE_HEADER: &str = "Replay-Nonce";

/// Nonce doğrulama ve havuzu ile ilişkili hata türleri.
#[derive(Debug, Error)]
pub enum NonceError {
    /// Boş bir nonce değeri ile karşılaşıldı.
    #[error("Replay-Nonce değeri boş olamaz")]
    Empty,
    /// Nonce base64url (padding'siz) formatında değil.
    #[error("Replay-Nonce değeri base64url olarak ayrıştırılamadı: {source}")]
    InvalidBase64 {
        /// Base64 ayrıştırma hatasının kaynağı.
        #[source]
        source: base64::DecodeError,
    },
    /// HTTP başlığındaki nonce UTF-8 olarak çözümlenemedi.
    #[error("Replay-Nonce HTTP başlığı UTF-8 olarak çözümlenemedi: {source}")]
    InvalidHeaderEncoding {
        /// HTTP başlık değeri dönüşümü sırasında oluşan hata.
        #[source]
        source: ToStrError,
    },
    /// Havuz kapasitesi sıfır olarak yapılandırılmaya çalışıldı.
    #[error("nonce havuzu kapasitesi en az 1 olmalıdır")]
    InvalidCapacity,
}

/// ACME sunucuları tarafından döndürülen, base64url kodlu nonce değeri.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplayNonce(String);

impl ReplayNonce {
    /// Metinsel bir değerden nonce üretir ve RFC 8555'e uygunluğunu doğrular.
    ///
    /// # Errors
    ///
    /// * `NonceError::Empty` - değer yalnızca boşluklardan oluştuğunda.
    /// * `NonceError::InvalidBase64` - değer base64url olarak çözümlenemediğinde.
    pub fn parse<S: AsRef<str>>(value: S) -> Result<Self, NonceError> {
        let trimmed = value.as_ref().trim();
        if trimmed.is_empty() {
            return Err(NonceError::Empty);
        }

        URL_SAFE_NO_PAD
            .decode(trimmed)
            .map_err(|source| NonceError::InvalidBase64 { source })?;

        Ok(Self(trimmed.to_owned()))
    }

    /// Nonce değerini base64url kodlu metin olarak döndürür.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Nonce değerini sahipli metin olarak döndürür.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl FromStr for ReplayNonce {
    type Err = NonceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// ACME Replay-Nonce değerlerini saklayan küçük bir FIFO havuzu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoncePool {
    capacity: usize,
    nonces: VecDeque<ReplayNonce>,
}

impl NoncePool {
    /// Varsayılan havuz kapasitesi.
    pub const DEFAULT_CAPACITY: usize = 4;

    /// Belirtilen kapasite ile yeni bir nonce havuzu oluşturur.
    ///
    /// # Errors
    ///
    /// Kapasite sıfır olduğunda `NonceError::InvalidCapacity` döner.
    pub fn new(capacity: usize) -> Result<Self, NonceError> {
        if capacity == 0 {
            return Err(NonceError::InvalidCapacity);
        }

        Ok(Self {
            capacity,
            nonces: VecDeque::with_capacity(capacity),
        })
    }

    /// Varsayılan kapasite ile boş bir nonce havuzu oluşturur.
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self {
            capacity: Self::DEFAULT_CAPACITY,
            nonces: VecDeque::with_capacity(Self::DEFAULT_CAPACITY),
        }
    }

    /// Havuzdaki nonce sayısını döndürür.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nonces.len()
    }

    /// Havuzun boş olup olmadığını bildirir.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nonces.is_empty()
    }

    /// Havuzun kapasitesini döndürür.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Havuzun en yeni nonce değerini referans olarak döndürür.
    #[must_use]
    pub fn peek(&self) -> Option<&ReplayNonce> {
        self.nonces.back()
    }

    /// Havuzdan kullanılmak üzere en yeni nonce değerini alır.
    #[must_use]
    pub fn pop(&mut self) -> Option<ReplayNonce> {
        self.nonces.pop_back()
    }

    /// Yeni bir nonce değerini havuza ekler.
    ///
    /// Daha önce eklenmiş olan nonce değerleri tekrar eklenmez.
    pub fn push(&mut self, nonce: ReplayNonce) {
        if self.nonces.contains(&nonce) {
            return;
        }

        if self.nonces.len() == self.capacity {
            self.nonces.pop_front();
        }

        self.nonces.push_back(nonce);
    }

    /// HTTP `Replay-Nonce` başlığı üzerinden yeni bir nonce değeri alır ve havuza ekler.
    ///
    /// # Errors
    ///
    /// * `NonceError::InvalidHeaderEncoding` - başlık değeri UTF-8 değilse.
    /// * `NonceError::Empty` veya `NonceError::InvalidBase64` - nonce değeri hatalıysa.
    pub fn absorb_replay_nonce_header(
        &mut self,
        headers: &HeaderMap,
    ) -> Result<Option<ReplayNonce>, NonceError> {
        let Some(value) = headers.get(REPLAY_NONCE_HEADER) else {
            return Ok(None);
        };

        let as_str = value
            .to_str()
            .map_err(|source| NonceError::InvalidHeaderEncoding { source })?;
        let nonce = ReplayNonce::parse(as_str)?;
        self.push(nonce.clone());
        Ok(Some(nonce))
    }
}

impl Default for NoncePool {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_nonce_accepts_base64url_value() {
        let value = "z9lqO7iAJ6T4tO4Hq8xPRA";
        let nonce = ReplayNonce::parse(value).expect("nonce parse edilmeli");
        assert_eq!(nonce.as_str(), value);
    }

    #[test]
    fn replay_nonce_rejects_padding() {
        let value = "z9lqO7iAJ6T4tO4Hq8xPRA==";
        let err = ReplayNonce::parse(value).unwrap_err();
        assert!(matches!(err, NonceError::InvalidBase64 { .. }));
    }

    #[test]
    fn pool_drops_oldest_when_capacity_exceeded() {
        let mut pool = NoncePool::new(2).unwrap();
        pool.push(ReplayNonce::parse("AAAABBBB").unwrap());
        pool.push(ReplayNonce::parse("CCCCDDDD").unwrap());
        pool.push(ReplayNonce::parse("EEEFFFFF").unwrap());

        assert_eq!(pool.len(), 2);
        assert_eq!(pool.peek().unwrap().as_str(), "EEEFFFFF");
        let newest = pool.pop().unwrap();
        let older = pool.pop().unwrap();
        assert_eq!(newest.as_str(), "EEEFFFFF");
        assert_eq!(older.as_str(), "CCCCDDDD");
        assert!(pool.pop().is_none());
    }

    #[test]
    fn pool_avoids_duplicates() {
        let mut pool = NoncePool::default();
        let nonce = ReplayNonce::parse("1234ABCD").unwrap();
        pool.push(nonce.clone());
        pool.push(nonce);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn absorb_header_extracts_and_stores_nonce() {
        let mut pool = NoncePool::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            REPLAY_NONCE_HEADER,
            "tN3MwZ6QslW7yA5kuQ5YPA".parse().unwrap(),
        );

        let extracted = pool
            .absorb_replay_nonce_header(&headers)
            .expect("başlık okunmalı")
            .expect("nonce bulunmalı");

        assert_eq!(extracted.as_str(), "tN3MwZ6QslW7yA5kuQ5YPA");
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.peek().unwrap().as_str(), extracted.as_str());
    }

    #[test]
    fn absorb_header_without_value_returns_none() {
        let mut pool = NoncePool::default();
        let headers = HeaderMap::new();
        assert!(pool.absorb_replay_nonce_header(&headers).unwrap().is_none());
        assert!(pool.is_empty());
    }
}
