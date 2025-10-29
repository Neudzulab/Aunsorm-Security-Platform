use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::validation::{ChallengeState, Dns01TxtRecord, Dns01ValidationError};

pub mod cloudflare;
pub mod route53;

pub use cloudflare::CloudflareDnsProvider;
pub use route53::Route53DnsProvider;

/// TXT kaydı yayınlandıktan sonra sağlayıcı tarafından döndürülen referans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsRecordHandle {
    provider: &'static str,
    record_id: String,
    record_name: String,
    record_value: String,
}

#[allow(clippy::missing_const_for_fn)]
impl DnsRecordHandle {
    /// Yeni bir TXT kayıt tanımlayıcısı üretir.
    #[must_use]
    pub fn new(
        provider: &'static str,
        record_id: String,
        record_name: String,
        record_value: String,
    ) -> Self {
        Self {
            provider,
            record_id,
            record_name,
            record_value,
        }
    }

    /// Sağlayıcı adını döndürür.
    #[must_use]
    pub const fn provider(&self) -> &'static str {
        self.provider
    }

    /// Sağlayıcıya özgü kayıt kimliğini döndürür.
    #[must_use]
    pub fn record_id(&self) -> &str {
        self.record_id.as_str()
    }

    /// TXT kaydı alan adını döndürür.
    #[must_use]
    pub fn record_name(&self) -> &str {
        self.record_name.as_str()
    }

    /// TXT kaydı değerini döndürür.
    #[must_use]
    pub fn record_value(&self) -> &str {
        self.record_value.as_str()
    }
}

/// DNS sağlayıcı katmanında oluşabilecek hatalar.
#[derive(Debug, Error)]
pub enum DnsProviderError {
    /// Sağlayıcı kimlik doğrulaması başarısız oldu.
    #[error("DNS sağlayıcısına kimlik doğrulama yapılamadı: {message}")]
    Authentication { message: String },
    /// Sağlayıcı isteği reddetti.
    #[error("DNS sağlayıcısı isteği reddetti: {message}")]
    Provider { message: String },
    /// TXT kaydı doğrulanamadı.
    #[error("DNS TXT kaydı doğrulanamadı: {0}")]
    Validation(#[from] Dns01ValidationError),
    /// Sağlayıcı henüz uygulanmadı.
    #[error("{provider} sağlayıcısı {operation} operasyonunu henüz desteklemiyor")]
    NotImplemented {
        /// Sağlayıcı adı.
        provider: &'static str,
        /// Uygulanmamış operasyon.
        operation: &'static str,
    },
}

/// DNS sağlayıcıları için ortak arayüz.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// TXT kaydını yayınlar ve sağlayıcıya özgü tanımlayıcıyı döndürür.
    async fn publish_txt_record(
        &self,
        record: &Dns01TxtRecord,
    ) -> Result<DnsRecordHandle, DnsProviderError>;

    /// Daha önce yayınlanan TXT kaydını siler veya geçersiz kılar.
    async fn revoke_txt_record(
        &self,
        handle: &DnsRecordHandle,
    ) -> Result<ChallengeState, DnsProviderError>;

    /// TXT kaydının yayılım durumunu sorgular.
    async fn verify_propagation(
        &self,
        handle: &DnsRecordHandle,
    ) -> Result<ChallengeState, DnsProviderError>;
}
