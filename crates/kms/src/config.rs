use std::env;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::Zeroizing;

#[cfg(feature = "kms-pkcs11")]
use crate::approval::ApprovalPolicyConfig;
use crate::error::{KmsError, Result};
#[cfg(feature = "kms-pkcs11")]
use crate::rotation::RotationPolicyConfig;

const LOCAL_STORE_KEY_ENV: &str = "AUNSORM_KMS_LOCAL_STORE_KEY";

#[cfg(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11"))]
use serde::{de::DeserializeOwned, Deserialize};

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

#[cfg(feature = "kms-gcp")]
#[derive(Debug, Clone, Deserialize)]
pub struct GcpBackendConfig {
    pub base_url: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default = "GcpBackendConfig::default_max_retries")]
    pub max_retries: usize,
    #[serde(default = "GcpBackendConfig::default_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
    #[serde(default)]
    pub keys: Vec<GcpKeyConfig>,
}

#[cfg(feature = "kms-gcp")]
impl GcpBackendConfig {
    const fn default_max_retries() -> usize {
        2
    }

    const fn default_retry_backoff_ms() -> u64 {
        50
    }
}

#[cfg(feature = "kms-gcp")]
#[derive(Debug, Clone, Deserialize)]
pub struct GcpKeyConfig {
    pub key_id: String,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
}

#[cfg(feature = "kms-azure")]
#[derive(Debug, Clone, Deserialize)]
pub struct AzureBackendConfig {
    pub base_url: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default = "AzureBackendConfig::default_max_retries")]
    pub max_retries: usize,
    #[serde(default = "AzureBackendConfig::default_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
    #[serde(default)]
    pub keys: Vec<AzureKeyConfig>,
}

#[cfg(feature = "kms-azure")]
impl AzureBackendConfig {
    const fn default_max_retries() -> usize {
        2
    }

    const fn default_retry_backoff_ms() -> u64 {
        50
    }
}

#[cfg(feature = "kms-azure")]
#[derive(Debug, Clone, Deserialize)]
pub struct AzureKeyConfig {
    pub key_id: String,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub key_name: Option<String>,
    #[serde(default)]
    pub key_version: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub local_private_key: Option<String>,
}

#[cfg(feature = "kms-pkcs11")]
#[derive(Debug, Clone, Deserialize)]
pub struct Pkcs11BackendConfig {
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub slot: Option<u64>,
    #[serde(default)]
    pub token_label: Option<String>,
    #[serde(default)]
    pub user_pin_env: Option<String>,
    #[serde(default)]
    pub keys: Vec<Pkcs11KeyConfig>,
}

#[cfg(feature = "kms-pkcs11")]
#[derive(Debug, Clone, Deserialize)]
pub struct Pkcs11KeyConfig {
    pub key_id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub wrapped_seed: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub rotation: Option<RotationPolicyConfig>,
    #[serde(default)]
    pub approvals: Option<ApprovalPolicyConfig>,
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
    pub(crate) gcp: Option<GcpBackendConfig>,
    #[cfg(feature = "kms-azure")]
    pub(crate) azure: Option<AzureBackendConfig>,
    #[cfg(feature = "kms-pkcs11")]
    pub(crate) pkcs11: Option<Pkcs11BackendConfig>,
}

impl KmsConfig {
    /// Ortam değişkenlerinden yapılandırma üretir.
    ///
    /// Desteklenen değişkenler:
    /// - `AUNSORM_STRICT`: `1` veya `true` ise strict kip aktif.
    /// - `AUNSORM_KMS_FALLBACK`: `1` ise fallback denemelerine izin verilir (varsayılan: devre dışı).
    /// - `AUNSORM_KMS_LOCAL_STORE`: Yerel store JSON dosya yolu.
    ///
    /// # Errors
    ///
    /// Yerel store yolunun okunması başarısız olursa `KmsError` döner.
    pub fn from_env() -> Result<Self> {
        let strict = parse_bool(env::var("AUNSORM_STRICT").ok().as_deref()).unwrap_or(false);
        let allow_fallback =
            parse_bool(env::var("AUNSORM_KMS_FALLBACK").ok().as_deref()).unwrap_or(false);
        let local_store = match env::var("AUNSORM_KMS_LOCAL_STORE").ok() {
            Some(path) if !path.trim().is_empty() => {
                let key = load_local_store_key_from_env()?;
                Some(LocalStoreConfig::new(PathBuf::from(path), key))
            }
            _ => None,
        };
        #[cfg(feature = "kms-gcp")]
        let gcp = parse_json_config::<GcpBackendConfig>(
            env::var("AUNSORM_KMS_GCP_CONFIG").ok(),
            "AUNSORM_KMS_GCP_CONFIG",
        )?;
        #[cfg(feature = "kms-azure")]
        let azure = parse_json_config::<AzureBackendConfig>(
            env::var("AUNSORM_KMS_AZURE_CONFIG").ok(),
            "AUNSORM_KMS_AZURE_CONFIG",
        )?;
        #[cfg(feature = "kms-pkcs11")]
        let pkcs11 = parse_json_config::<Pkcs11BackendConfig>(
            env::var("AUNSORM_KMS_PKCS11_CONFIG").ok(),
            "AUNSORM_KMS_PKCS11_CONFIG",
        )?;

        Ok(Self {
            strict,
            allow_fallback,
            local_store,
            #[cfg(feature = "kms-gcp")]
            gcp,
            #[cfg(feature = "kms-azure")]
            azure,
            #[cfg(feature = "kms-pkcs11")]
            pkcs11,
        })
    }

    /// Sadece yerel store kullanacak şekilde konfigürasyon üretir.
    ///
    /// Varsayılan olarak fallback denemeleri kapalıdır; gerekirse
    /// `with_fallback(true)` çağrısı ile etkinleştirilmelidir.
    ///
    /// # Errors
    ///
    /// `path` boş ise `KmsError::Config` döner.
    pub fn local_only<P: AsRef<Path>>(path: P) -> Result<Self> {
        let key = load_local_store_key_from_env()?;
        Self::local_only_with_key(path, key.as_ref())
    }

    /// Sadece yerel store kullanacak şekilde konfigürasyon üretir, key materyali doğrudan
    /// çağıran tarafından sağlanır.
    ///
    /// # Errors
    ///
    /// `path` boş ise `KmsError::Config` döner.
    pub fn local_only_with_key<P: AsRef<Path>>(path: P, key: &[u8]) -> Result<Self> {
        let store_path = path.as_ref();
        if store_path.as_os_str().is_empty() {
            return Err(KmsError::Config("local store path is empty".into()));
        }
        if key.len() != 32 {
            return Err(KmsError::Config(
                "local store key must decode to exactly 32 bytes".into(),
            ));
        }
        let mut encryption_key = Zeroizing::new([0u8; 32]);
        encryption_key.copy_from_slice(key);
        Ok(Self {
            strict: false,
            allow_fallback: false,
            local_store: Some(LocalStoreConfig::new(
                store_path.to_path_buf(),
                encryption_key,
            )),
            #[cfg(feature = "kms-gcp")]
            gcp: None,
            #[cfg(feature = "kms-azure")]
            azure: None,
            #[cfg(feature = "kms-pkcs11")]
            pkcs11: None,
        })
    }

    /// Yerel store dosyasını ayarlar.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_local_store(mut self, path: impl Into<PathBuf>, key: &[u8; 32]) -> Self {
        let mut encryption_key = Zeroizing::new([0u8; 32]);
        encryption_key.copy_from_slice(key);
        self.local_store = Some(LocalStoreConfig::new(path.into(), encryption_key));
        self
    }

    /// GCP backend yapılandırmasını ekler.
    #[cfg(feature = "kms-gcp")]
    #[must_use]
    pub fn with_gcp(mut self, config: GcpBackendConfig) -> Self {
        self.gcp = Some(config);
        self
    }

    /// Azure backend yapılandırmasını ekler.
    #[cfg(feature = "kms-azure")]
    #[must_use]
    pub fn with_azure(mut self, config: AzureBackendConfig) -> Self {
        self.azure = Some(config);
        self
    }

    /// PKCS#11 backend yapılandırmasını ekler.
    #[cfg(feature = "kms-pkcs11")]
    #[must_use]
    pub fn with_pkcs11(mut self, config: Pkcs11BackendConfig) -> Self {
        self.pkcs11 = Some(config);
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
    encryption_key: Zeroizing<[u8; 32]>,
}

impl LocalStoreConfig {
    /// Yeni yapılandırma oluşturur.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(path: PathBuf, encryption_key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            path,
            encryption_key,
        }
    }

    /// Store dosya yolunu döndürür.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Şifreleme anahtarını döndürür.
    #[must_use]
    pub fn encryption_key(&self) -> &[u8; 32] {
        &self.encryption_key
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

#[cfg(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11"))]
fn parse_json_config<T: DeserializeOwned>(value: Option<String>, name: &str) -> Result<Option<T>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|err| KmsError::Config(format!("invalid {name} json: {err}")))
}

fn load_local_store_key_from_env() -> Result<Zeroizing<[u8; 32]>> {
    let raw = env::var(LOCAL_STORE_KEY_ENV).map_err(|_| {
        KmsError::Config(format!(
            "{LOCAL_STORE_KEY_ENV} must be set when local store is enabled"
        ))
    })?;
    decode_key_material(&raw, LOCAL_STORE_KEY_ENV)
}

fn decode_key_material(value: &str, name: &str) -> Result<Zeroizing<[u8; 32]>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(KmsError::Config(format!("{name} cannot be empty")));
    }
    let decoded = STANDARD
        .decode(trimmed.as_bytes())
        .map_err(|err| KmsError::Config(format!("failed to decode {name}: {err}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    if decoded.len() != key.len() {
        return Err(KmsError::Config(format!(
            "{name} must decode to exactly 32 bytes"
        )));
    }
    key.copy_from_slice(&decoded);
    Ok(key)
}
