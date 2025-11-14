use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use zeroize::Zeroizing;

use aunsorm_core::clock::SecureClockSnapshot;
use aunsorm_jwt::Ed25519KeyPair;
use url::Url;

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

fn invalid_listen_address(err: impl std::fmt::Display) -> ServerError {
    ServerError::Configuration(format!("Dinleme adresi geçersiz: {err}"))
}

fn derive_listen_addr(
    listen_raw: Option<String>,
    host_raw: Option<String>,
) -> Result<SocketAddr, ServerError> {
    if let Some(raw) = listen_raw {
        return raw.parse().map_err(invalid_listen_address);
    }

    if let Some(host_value) = host_raw {
        let normalized = normalize_host_value(host_value)?;
        return normalized.parse().map_err(invalid_listen_address);
    }

    Ok(SocketAddr::from(([127, 0, 0, 1], 8080)))
}

fn normalize_host_value(host_raw: String) -> Result<String, ServerError> {
    let trimmed = host_raw.trim();
    if trimmed.is_empty() {
        return Err(ServerError::Configuration(
            "HOST değeri boş olamaz".to_string(),
        ));
    }

    if trimmed.parse::<SocketAddr>().is_ok() {
        return Ok(trimmed.to_string());
    }

    let without_scheme = match trimmed.split_once("://") {
        Some((_, rest)) => rest,
        None => trimmed,
    };

    let authority = without_scheme
        .split(|ch| matches!(ch, '/' | '?'))
        .next()
        .unwrap_or("")
        .trim();

    if authority.is_empty() {
        return Err(ServerError::Configuration(
            "HOST değeri geçerli bir adres içermiyor".to_string(),
        ));
    }

    if authority.parse::<SocketAddr>().is_ok() {
        return Ok(authority.to_string());
    }

    if authority.contains(':') && !authority.contains('[') && !authority.contains(']') {
        if authority.matches(':').count() == 1 {
            return Err(invalid_listen_address(authority));
        }
    }

    let host_body = authority.trim_matches(['[', ']']);
    if host_body.is_empty() {
        return Err(ServerError::Configuration(
            "HOST değeri geçerli bir ana bilgisayar içermiyor".to_string(),
        ));
    }

    let default_port = 8080;
    let candidate = if host_body.contains(':') {
        format!("[{host_body}]:{default_port}")
    } else {
        format!("{host_body}:{default_port}")
    };

    Ok(candidate)
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
    pub(crate) clock_max_age: Duration,
    pub(crate) clock_snapshot: SecureClockSnapshot,
    pub(crate) clock_refresh: Option<ClockRefreshConfig>,
    pub(crate) revocation_webhook: Option<RevocationWebhookConfig>,
}

/// Configuration for the background clock refresh worker.
#[derive(Debug, Clone)]
pub struct ClockRefreshConfig {
    pub(crate) url: String,
    pub(crate) interval: Duration,
}

impl ClockRefreshConfig {
    #[must_use]
    pub fn new(url: impl Into<String>, interval: Duration) -> Self {
        Self {
            url: url.into(),
            interval,
        }
    }

    #[must_use]
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub(crate) const fn interval(&self) -> Duration {
        self.interval
    }
}

/// Webhook configuration for token revocation events.
#[derive(Debug, Clone)]
pub struct RevocationWebhookConfig {
    endpoint: Url,
    secret: String,
    timeout: Duration,
}

impl RevocationWebhookConfig {
    /// Builds a new webhook configuration, validating URL and secret inputs.
    ///
    /// # Errors
    /// Returns [`ServerError::Configuration`] when the URL scheme is unsupported or
    /// the provided secret is empty.
    pub fn new(
        endpoint: Url,
        secret: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, ServerError> {
        if endpoint.scheme() != "https" && endpoint.scheme() != "http" {
            return Err(ServerError::Configuration(
                "Webhook URL sadece http(s) şemasını destekler".to_string(),
            ));
        }
        if timeout.is_zero() {
            return Err(ServerError::Configuration(
                "Webhook zaman aşımı 0 olamaz".to_string(),
            ));
        }
        let secret = secret.into();
        if secret.trim().len() < 32 {
            return Err(ServerError::Configuration(
                "Webhook secret en az 32 karakter olmalıdır".to_string(),
            ));
        }
        Ok(Self {
            endpoint,
            secret,
            timeout,
        })
    }

    #[must_use]
    pub(crate) fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    #[must_use]
    pub(crate) fn secret(&self) -> &str {
        &self.secret
    }

    #[must_use]
    pub(crate) const fn timeout(&self) -> Duration {
        self.timeout
    }
}

use std::time::{SystemTime, UNIX_EPOCH};

impl ServerConfig {
    /// Çevre değişkenlerinden yapılandırmayı oluşturur.
    ///
    /// # Errors
    ///
    /// Gerekli alanlar eksikse veya geçersizse `ServerError` döner.
    #[allow(clippy::too_many_lines)]
    pub fn from_env() -> Result<Self, ServerError> {
        let listen = derive_listen_addr(env::var("AUNSORM_LISTEN").ok(), env::var("HOST").ok())?;
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

        let clock_max_age_secs = match env::var("AUNSORM_CLOCK_MAX_AGE_SECS") {
            Ok(value) => value.parse::<u64>().map_err(|err| {
                ServerError::Configuration(format!(
                    "AUNSORM_CLOCK_MAX_AGE_SECS geçerli bir sayı değil: {err}"
                ))
            })?,
            Err(env::VarError::NotPresent) => {
                if strict {
                    30
                } else {
                    300
                }
            }
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ServerError::Configuration(
                    "AUNSORM_CLOCK_MAX_AGE_SECS ASCII olmayan karakterler içeriyor".to_string(),
                ));
            }
        };

        if clock_max_age_secs == 0 {
            return Err(ServerError::Configuration(
                "AUNSORM_CLOCK_MAX_AGE_SECS değeri 0 olamaz".to_string(),
            ));
        }

        if strict && clock_max_age_secs > 30 {
            return Err(ServerError::Configuration(format!(
                "Strict kipte AUNSORM_CLOCK_MAX_AGE_SECS en fazla 30 saniye olabilir (şu an {clock_max_age_secs})"
            )));
        }

        let clock_max_age = Duration::from_secs(clock_max_age_secs);

        let clock_refresh = match env::var("AUNSORM_CLOCK_REFRESH_URL") {
            Ok(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(ServerError::Configuration(
                        "AUNSORM_CLOCK_REFRESH_URL boş olamaz".to_string(),
                    ));
                }

                let interval_secs = match env::var("AUNSORM_CLOCK_REFRESH_INTERVAL_SECS") {
                    Ok(raw) => raw.parse::<u64>().map_err(|err| {
                        ServerError::Configuration(format!(
                            "AUNSORM_CLOCK_REFRESH_INTERVAL_SECS geçerli bir sayı değil: {err}"
                        ))
                    })?,
                    Err(env::VarError::NotPresent) => 15,
                    Err(env::VarError::NotUnicode(_)) => {
                        return Err(ServerError::Configuration(
                            "AUNSORM_CLOCK_REFRESH_INTERVAL_SECS ASCII olmayan karakterler içeriyor"
                                .to_string(),
                        ));
                    }
                };

                if interval_secs == 0 {
                    return Err(ServerError::Configuration(
                        "AUNSORM_CLOCK_REFRESH_INTERVAL_SECS 0 olamaz".to_string(),
                    ));
                }

                if strict {
                    let half_window = clock_max_age_secs / 2;
                    if half_window == 0 || interval_secs > half_window {
                        return Err(ServerError::Configuration(format!(
                            "Strict kipte AUNSORM_CLOCK_REFRESH_INTERVAL_SECS en fazla {} saniye olabilir (şu an {interval_secs})",
                            half_window.max(1)
                        )));
                    }
                }

                Some(ClockRefreshConfig::new(
                    trimmed.to_string(),
                    Duration::from_secs(interval_secs),
                ))
            }
            Err(env::VarError::NotPresent) => {
                if strict {
                    return Err(ServerError::Configuration(
                        "Strict kipte AUNSORM_CLOCK_REFRESH_URL zorunludur".to_string(),
                    ));
                }
                None
            }
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ServerError::Configuration(
                    "AUNSORM_CLOCK_REFRESH_URL ASCII olmayan karakterler içeriyor".to_string(),
                ));
            }
        };

        let revocation_webhook = match env::var("AUNSORM_WEBHOOK_URL") {
            Ok(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(ServerError::Configuration(
                        "AUNSORM_WEBHOOK_URL boş olamaz".to_string(),
                    ));
                }
                let endpoint = Url::parse(trimmed).map_err(|err| {
                    ServerError::Configuration(format!(
                        "AUNSORM_WEBHOOK_URL parse edilemedi: {err}"
                    ))
                })?;
                let secret = env::var("AUNSORM_WEBHOOK_SECRET").map_err(|_| {
                    ServerError::Configuration(
                        "AUNSORM_WEBHOOK_SECRET çevre değişkeni zorunludur".to_string(),
                    )
                })?;
                let timeout_ms = env::var("AUNSORM_WEBHOOK_TIMEOUT_MS")
                    .ok()
                    .and_then(|raw| raw.parse::<u64>().ok())
                    .unwrap_or(1_500);
                if timeout_ms == 0 {
                    return Err(ServerError::Configuration(
                        "AUNSORM_WEBHOOK_TIMEOUT_MS 0 olamaz".to_string(),
                    ));
                }
                Some(RevocationWebhookConfig::new(
                    endpoint,
                    secret,
                    Duration::from_millis(timeout_ms),
                )?)
            }
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ServerError::Configuration(
                    "AUNSORM_WEBHOOK_URL ASCII olmayan karakterler içeriyor".to_string(),
                ));
            }
        };

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
        let mut clock_snapshot: SecureClockSnapshot =
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

        if !strict && clock_refresh.is_none() {
            // Auto-update timestamp to current time (development mode)
            // Production should use NTP attestation server with real signatures
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| ServerError::Configuration(format!("System time error: {err}")))?
                .as_millis()
                .try_into()
                .map_err(|_| ServerError::Configuration("Timestamp overflow".to_string()))?;

            clock_snapshot.unix_time_ms = now_ms;
            tracing::debug!(
                "🕐 Clock attestation timestamp updated to current time: {}",
                now_ms
            );
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
            clock_max_age,
            clock_snapshot,
            clock_refresh,
            revocation_webhook,
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
        clock_max_age: Duration,
        clock_snapshot: SecureClockSnapshot,
        clock_refresh: Option<ClockRefreshConfig>,
        revocation_webhook: Option<RevocationWebhookConfig>,
    ) -> Result<Self, ServerError> {
        if strict && matches!(ledger, LedgerBackend::Memory) {
            return Err(ServerError::Configuration(
                "Strict kipte bellek içi JTI deposu kullanılamaz".to_string(),
            ));
        }
        if clock_max_age.is_zero() {
            return Err(ServerError::Configuration(
                "Saat doğrulama penceresi 0 olamaz".to_string(),
            ));
        }
        if strict && clock_max_age > Duration::from_secs(30) {
            return Err(ServerError::Configuration(format!(
                "Strict kipte saat doğrulama penceresi en fazla 30 saniye olabilir (şu an {} saniye)",
                clock_max_age.as_secs()
            )));
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
            clock_max_age,
            clock_snapshot,
            clock_refresh,
            revocation_webhook,
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

    #[must_use]
    #[allow(dead_code)] // Exposed for background refresh scheduling
    pub(crate) const fn clock_max_age(&self) -> Duration {
        self.clock_max_age
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use aunsorm_core::clock::SecureClockSnapshot;
    use aunsorm_jwt::Ed25519KeyPair;

    fn sample_snapshot() -> SecureClockSnapshot {
        SecureClockSnapshot {
            authority_id: "ntp.test.aunsorm".to_string(),
            authority_fingerprint_hex:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            unix_time_ms: 1_730_000_000_000,
            stratum: 2,
            round_trip_ms: 8,
            dispersion_ms: 12,
            estimated_offset_ms: 0,
            signature_b64: "dGVzdC1zaWduYXR1cmU=".to_string(),
        }
    }

    fn sample_calibration() -> String {
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()
    }

    #[test]
    fn strict_mode_rejects_large_clock_max_age() {
        let result = ServerConfig::new(
            "127.0.0.1:18080".parse().expect("socket"),
            "https://strict.test",
            "strict-audience",
            Duration::from_secs(300),
            true,
            Ed25519KeyPair::generate("strict-test").expect("key pair"),
            LedgerBackend::Sqlite(PathBuf::from("./strict-ledger.db")),
            None,
            sample_calibration(),
            Duration::from_secs(45),
            sample_snapshot(),
            None,
            None,
        );

        assert!(
            matches!(result, Err(ServerError::Configuration(message)) if message.contains("30 saniye"))
        );
    }

    #[test]
    fn rejects_zero_clock_max_age() {
        let result = ServerConfig::new(
            "127.0.0.1:18081".parse().expect("socket"),
            "https://dev.test",
            "dev-audience",
            Duration::from_secs(300),
            false,
            Ed25519KeyPair::generate("dev-test").expect("key pair"),
            LedgerBackend::Memory,
            None,
            sample_calibration(),
            Duration::from_secs(0),
            sample_snapshot(),
            None,
            None,
        );

        assert!(
            matches!(result, Err(ServerError::Configuration(message)) if message.contains("0 olamaz"))
        );
    }

    #[test]
    fn derive_listen_addr_prefers_aunsorm_listen() {
        let addr = derive_listen_addr(
            Some("0.0.0.0:18080".to_string()),
            Some("127.0.0.1".to_string()),
        )
        .expect("listen address");

        assert_eq!(addr, "0.0.0.0:18080".parse().expect("addr"));
    }

    #[test]
    fn derive_listen_addr_uses_host_with_port() {
        let addr =
            derive_listen_addr(None, Some("0.0.0.0:19090".to_string())).expect("listen address");

        assert_eq!(addr, "0.0.0.0:19090".parse().expect("addr"));
    }

    #[test]
    fn derive_listen_addr_appends_default_port_when_missing() {
        let addr = derive_listen_addr(None, Some("0.0.0.0".to_string())).expect("listen address");

        assert_eq!(addr, "0.0.0.0:8080".parse().expect("addr"));
    }

    #[test]
    fn derive_listen_addr_respects_scheme_and_path() {
        let addr = derive_listen_addr(
            None,
            Some("https://0.0.0.0:50010/api/v1?token=1".to_string()),
        )
        .expect("listen address");

        assert_eq!(addr, "0.0.0.0:50010".parse().expect("addr"));
    }

    #[test]
    fn derive_listen_addr_supports_ipv6_without_port() {
        let addr = derive_listen_addr(None, Some("::1".to_string())).expect("listen address");

        assert_eq!(addr, "[::1]:8080".parse().expect("addr"));
    }
}
