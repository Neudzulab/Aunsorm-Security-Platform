use std::env;
use std::path::{Path, PathBuf};

use crate::error::{KmsError, Result};

/// Desteklenen KMS sağlayıcı türleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// Yerel JSON tabanlı anahtar deposu.
    Local,
    /// Google Cloud KMS entegrasyonu.
    Gcp,
    /// Azure Key Vault entegrasyonu.
    Azure,
    /// PKCS#11 uyumlu HSM entegrasyonu.
    Pkcs11,
}

/// Belirli bir backend ve anahtar kimliğini adresler.
#[derive(Debug, Clone)]
pub struct BackendLocator {
    kind: BackendKind,
    key_id: String,
}

impl BackendLocator {
    /// Yeni bir adres oluşturur.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(kind: BackendKind, key_id: impl Into<String>) -> Self {
        Self {
            kind,
            key_id: key_id.into(),
        }
    }

    /// Backend türünü döndürür.
    #[must_use]
    pub const fn kind(&self) -> BackendKind {
        self.kind
    }

    /// Anahtar kimliğini döndürür.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Birincil ve isteğe bağlı fallback anahtar tanımlayıcısı.
#[derive(Debug, Clone)]
pub struct KeyDescriptor {
    primary: BackendLocator,
    fallback: Option<BackendLocator>,
}

impl KeyDescriptor {
    /// Yalnızca birincil backend ile yeni bir tanımlayıcı oluşturur.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(primary: BackendLocator) -> Self {
        Self {
            primary,
            fallback: None,
        }
    }

    /// Fallback backend ekler.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_fallback(mut self, fallback: BackendLocator) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// Birincil backend referansını döndürür.
    #[must_use]
    pub const fn primary(&self) -> &BackendLocator {
        &self.primary
    }

    /// Fallback backend'i (varsa) döndürür.
    #[must_use]
    pub const fn fallback(&self) -> Option<&BackendLocator> {
        match &self.fallback {
            Some(locator) => Some(locator),
            None => None,
        }
    }
}

/// KMS istemcisini yapılandırmak için kullanılan ayarlar.
#[derive(Debug, Clone)]
pub struct KmsConfig {
    pub(crate) strict: bool,
    pub(crate) allow_fallback: bool,
    pub(crate) local_store: Option<LocalStoreConfig>,
    #[cfg(feature = "kms-gcp")]
    pub(crate) gcp_store: Option<RemoteStoreConfig>,
    #[cfg(feature = "kms-azure")]
    pub(crate) azure_store: Option<RemoteStoreConfig>,
    #[cfg(feature = "kms-pkcs11")]
    pub(crate) pkcs11_store: Option<RemoteStoreConfig>,
}

impl Default for KmsConfig {
    fn default() -> Self {
        Self {
            strict: false,
            allow_fallback: true,
            local_store: None,
            #[cfg(feature = "kms-gcp")]
            gcp_store: None,
            #[cfg(feature = "kms-azure")]
            azure_store: None,
            #[cfg(feature = "kms-pkcs11")]
            pkcs11_store: None,
        }
    }
}

impl KmsConfig {
    /// Ortam değişkenlerinden yapılandırma üretir.
    ///
    /// Desteklenen değişkenler:
    /// - `AUNSORM_STRICT`: `1` veya `true` ise strict kip aktif.
    /// - `AUNSORM_KMS_FALLBACK`: `1` ise fallback denemelerine izin verilir.
    /// - `AUNSORM_KMS_LOCAL_STORE`: Yerel store JSON dosya yolu.
    ///
    /// # Errors
    ///
    /// Yerel store yolunun okunması başarısız olursa `KmsError` döner.
    pub fn from_env() -> Result<Self> {
        let strict = parse_bool(env::var("AUNSORM_STRICT").ok().as_deref()).unwrap_or(false);
        let allow_fallback =
            parse_bool(env::var("AUNSORM_KMS_FALLBACK").ok().as_deref()).unwrap_or(true);
        let local_store = match env::var("AUNSORM_KMS_LOCAL_STORE").ok() {
            Some(path) if !path.trim().is_empty() => {
                Some(LocalStoreConfig::new(PathBuf::from(path)))
            }
            _ => None,
        };
        Ok(Self {
            strict,
            allow_fallback,
            local_store,
            #[cfg(feature = "kms-gcp")]
            gcp_store: env::var("AUNSORM_KMS_GCP_STORE").ok().and_then(|path| {
                (!path.trim().is_empty()).then(|| RemoteStoreConfig::new(PathBuf::from(path)))
            }),
            #[cfg(feature = "kms-azure")]
            azure_store: env::var("AUNSORM_KMS_AZURE_STORE").ok().and_then(|path| {
                (!path.trim().is_empty()).then(|| RemoteStoreConfig::new(PathBuf::from(path)))
            }),
            #[cfg(feature = "kms-pkcs11")]
            pkcs11_store: env::var("AUNSORM_KMS_PKCS11_STORE").ok().and_then(|path| {
                (!path.trim().is_empty()).then(|| RemoteStoreConfig::new(PathBuf::from(path)))
            }),
        })
    }

    /// Sadece yerel store kullanacak şekilde konfigürasyon üretir.
    ///
    /// # Errors
    ///
    /// `path` boş ise `KmsError::Config` döner.
    pub fn local_only<P: AsRef<Path>>(path: P) -> Result<Self> {
        let store_path = path.as_ref();
        if store_path.as_os_str().is_empty() {
            return Err(KmsError::Config("local store path is empty".into()));
        }
        Ok(Self {
            strict: false,
            allow_fallback: true,
            local_store: Some(LocalStoreConfig::new(store_path.to_path_buf())),
            #[cfg(feature = "kms-gcp")]
            gcp_store: None,
            #[cfg(feature = "kms-azure")]
            azure_store: None,
            #[cfg(feature = "kms-pkcs11")]
            pkcs11_store: None,
        })
    }

    /// Yerel store dosyasını ayarlar.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_local_store(mut self, path: impl Into<PathBuf>) -> Self {
        self.local_store = Some(LocalStoreConfig::new(path.into()));
        self
    }

    /// GCP backend yapılandırmasını ayarlar.
    #[must_use]
    #[cfg(feature = "kms-gcp")]
    pub fn with_gcp_store(mut self, path: impl Into<PathBuf>) -> Self {
        self.gcp_store = Some(RemoteStoreConfig::new(path.into()));
        self
    }

    /// Azure backend yapılandırmasını ayarlar.
    #[must_use]
    #[cfg(feature = "kms-azure")]
    pub fn with_azure_store(mut self, path: impl Into<PathBuf>) -> Self {
        self.azure_store = Some(RemoteStoreConfig::new(path.into()));
        self
    }

    /// PKCS#11 backend yapılandırmasını ayarlar.
    #[must_use]
    #[cfg(feature = "kms-pkcs11")]
    pub fn with_pkcs11_store(mut self, path: impl Into<PathBuf>) -> Self {
        self.pkcs11_store = Some(RemoteStoreConfig::new(path.into()));
        self
    }

    /// Strict kip değerini değiştirir.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Fallback izin ayarını değiştirir.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_fallback(mut self, allow: bool) -> Self {
        self.allow_fallback = allow;
        self
    }
}

/// Yerel JSON store yapılandırması.
#[derive(Debug, Clone)]
pub struct LocalStoreConfig {
    path: PathBuf,
}

impl LocalStoreConfig {
    /// Yeni yapılandırma oluşturur.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Store dosya yolunu döndürür.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11"))]
#[derive(Debug, Clone)]
pub struct RemoteStoreConfig {
    path: PathBuf,
}

#[cfg(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11"))]
impl RemoteStoreConfig {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn parse_bool(value: Option<&str>) -> Option<bool> {
    let raw = value?;
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}
