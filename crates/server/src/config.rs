use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use zeroize::Zeroizing;

use aunsorm_core::clock::SecureClockSnapshot;
use aunsorm_jwt::Ed25519KeyPair;

use crate::error::ServerError;

/// JTI defterinin arka ucunu temsil eder.
#[derive(Debug, Clone)]
pub enum LedgerBackend {
    /// Bellek içi; yalnızca geliştirme içindir.
    Memory,
    /// `SQLite` tabanlı kalıcı depolama.
    Sqlite(PathBuf),
}

impl LedgerBackend {
    fn from_env(strict: bool) -> Result<Self, ServerError> {
        match env::var("AUNSORM_JTI_DB") {
            Ok(path) => Ok(Self::Sqlite(PathBuf::from(path))),
            Err(env::VarError::NotPresent) if strict => Err(ServerError::Configuration(
                "AUNSORM_STRICT=1 iken AUNSORM_JTI_DB zorunludur".to_string(),
            )),
            Err(env::VarError::NotPresent) => Ok(Self::Memory),
            Err(env::VarError::NotUnicode(_)) => Err(ServerError::Configuration(
                "AUNSORM_JTI_DB geçerli bir yol değil".to_string(),
            )),
        }
    }
}

/// Hyperledger Fabric chaincode invocation configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Future blockchain integration
pub struct FabricChaincodeConfig {
    pub(crate) channel: String,
    pub(crate) chaincode: String,
}

impl FabricChaincodeConfig {
    pub fn new(channel: impl Into<String>, chaincode: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            chaincode: chaincode.into(),
        }
    }

    #[must_use]
    #[allow(dead_code)] // Future blockchain integration
    pub(crate) fn channel(&self) -> &str {
        &self.channel
    }

    #[must_use]
    #[allow(dead_code)] // Future blockchain integration
    pub(crate) fn chaincode(&self) -> &str {
        &self.chaincode
    }
}

/// Sunucu yapılandırması.
pub struct ServerConfig {
    pub(crate) listen: SocketAddr,
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) token_ttl: Duration,
    pub(crate) strict: bool,
    pub(crate) key_pair: Ed25519KeyPair,
    pub(crate) ledger: LedgerBackend,
    pub(crate) fabric: Option<FabricChaincodeConfig>,
    pub(crate) calibration_fingerprint: String,
    pub(crate) clock_snapshot: SecureClockSnapshot,
}

impl ServerConfig {
    /// Çevre değişkenlerinden yapılandırmayı oluşturur.
    ///
    /// # Errors
    ///
    /// Gerekli alanlar eksikse veya geçersizse `ServerError` döner.
    pub fn from_env() -> Result<Self, ServerError> {
        let listen = env::var("AUNSORM_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()
            .map_err(|err| ServerError::Configuration(format!("Dinleme adresi geçersiz: {err}")))?;
        let issuer =
            env::var("AUNSORM_ISSUER").unwrap_or_else(|_| "https://aunsorm.local".to_string());
        let audience =
            env::var("AUNSORM_AUDIENCE").unwrap_or_else(|_| "aunsorm-clients".to_string());
        let token_ttl = env::var("AUNSORM_TOKEN_TTL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map_or_else(|| Duration::from_secs(3600), Duration::from_secs);
        let strict = env::var("AUNSORM_STRICT")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(false);

        let ledger = LedgerBackend::from_env(strict)?;

        let kid = env::var("AUNSORM_JWT_KID").unwrap_or_else(|_| "aunsorm-server".to_string());
        let seed_b64 = env::var("AUNSORM_JWT_SEED_B64");
        let key_pair = match seed_b64 {
            Ok(value) => {
                let decoded = STANDARD.decode(value).map_err(|err| {
                    ServerError::Configuration(format!("JWT seed base64 çözülemedi: {err}"))
                })?;
                if decoded.len() != 32 {
                    return Err(ServerError::Configuration(
                        "AUNSORM_JWT_SEED_B64 değeri 32 bayt olmalıdır".to_string(),
                    ));
                }
                let mut seed = Zeroizing::new([0_u8; 32]);
                seed.copy_from_slice(&decoded);
                Ed25519KeyPair::from_seed(kid, *seed)?
            }
            Err(env::VarError::NotPresent) if strict => {
                return Err(ServerError::Configuration(
                    "Strict kipte AUNSORM_JWT_SEED_B64 zorunludur".to_string(),
                ))
            }
            Err(_) => Ed25519KeyPair::generate("aunsorm-server")?,
        };

        let fabric = match (
            env::var("AUNSORM_FABRIC_CHANNEL").ok(),
            env::var("AUNSORM_FABRIC_CHAINCODE").ok(),
        ) {
            (Some(channel), Some(chaincode)) => Some(FabricChaincodeConfig::new(channel, chaincode)),
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => {
                return Err(ServerError::Configuration(
                    "Fabric entegrasyonu için hem AUNSORM_FABRIC_CHANNEL hem de AUNSORM_FABRIC_CHAINCODE gereklidir"
                        .to_string(),
                ))
            }
        };

        let calibration_fingerprint =
            env::var("AUNSORM_CALIBRATION_FINGERPRINT").map_err(|_| {
                ServerError::Configuration(
                    "AUNSORM_CALIBRATION_FINGERPRINT çevre değişkeni zorunludur".to_string(),
                )
            })?;

        if calibration_fingerprint.len() != 64
            || !calibration_fingerprint
                .chars()
                .all(|ch| ch.is_ascii_hexdigit())
        {
            return Err(ServerError::Configuration(
                "AUNSORM_CALIBRATION_FINGERPRINT 64 karakterlik hex dizesi olmalıdır".to_string(),
            ));
        }

        let attestation = env::var("AUNSORM_CLOCK_ATTESTATION").map_err(|_| {
            ServerError::Configuration(
                "AUNSORM_CLOCK_ATTESTATION çevre değişkeni zorunludur".to_string(),
            )
        })?;
        let clock_snapshot: SecureClockSnapshot =
            serde_json::from_str(&attestation).map_err(|err| {
                ServerError::Configuration(format!(
                    "AUNSORM_CLOCK_ATTESTATION JSON parse edilemedi: {err}"
                ))
            })?;

        if clock_snapshot.signature_b64.trim().is_empty() {
            return Err(ServerError::Configuration(
                "AUNSORM_CLOCK_ATTESTATION.signature_b64 boş bırakılamaz".to_string(),
            ));
        }

        Self::new(
            listen,
            issuer,
            audience,
            token_ttl,
            strict,
            key_pair,
            ledger,
            fabric,
            calibration_fingerprint,
            clock_snapshot,
        )
    }

    /// Elle yapılandırma oluşturur.
    ///
    /// # Errors
    ///
    /// Strict kip ve in-memory defter kombinasyonu gibi tutarsızlıklar `ServerError` üretir.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        listen: SocketAddr,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        token_ttl: Duration,
        strict: bool,
        key_pair: Ed25519KeyPair,
        ledger: LedgerBackend,
        fabric: Option<FabricChaincodeConfig>,
        calibration_fingerprint: impl Into<String>,
        clock_snapshot: SecureClockSnapshot,
    ) -> Result<Self, ServerError> {
        if strict && matches!(ledger, LedgerBackend::Memory) {
            return Err(ServerError::Configuration(
                "Strict kipte bellek içi JTI deposu kullanılamaz".to_string(),
            ));
        }
        if clock_snapshot.signature_b64.trim().is_empty() {
            return Err(ServerError::Configuration(
                "Saat doğrulama imzası boş olamaz".to_string(),
            ));
        }
        let calibration_fingerprint = calibration_fingerprint.into();
        if calibration_fingerprint.len() != 64
            || !calibration_fingerprint
                .chars()
                .all(|ch| ch.is_ascii_hexdigit())
        {
            return Err(ServerError::Configuration(
                "Kalibrasyon fingerprint'i 64 haneli hex dize olmalıdır".to_string(),
            ));
        }
        Ok(Self {
            listen,
            issuer: issuer.into(),
            audience: audience.into(),
            token_ttl,
            strict,
            key_pair,
            ledger,
            fabric,
            calibration_fingerprint,
            clock_snapshot,
        })
    }

    #[must_use]
    #[allow(dead_code)] // Future blockchain integration
    pub(crate) const fn fabric(&self) -> Option<&FabricChaincodeConfig> {
        match &self.fabric {
            Some(cfg) => Some(cfg),
            None => None,
        }
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    #[allow(dead_code)] // Available for external audit proof verification
    pub(crate) fn calibration_fingerprint(&self) -> &str {
        &self.calibration_fingerprint
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    #[allow(dead_code)] // Available for clock refresh service integration
    pub(crate) fn clock_snapshot(&self) -> &SecureClockSnapshot {
        &self.clock_snapshot
    }
}
