//! Clock attestation refresh service
//!
//! Production'da NTP sunucusundan periyodik olarak yeni attestation alır.
//! Development'ta statik attestation kullanır veya mock server'dan çeker.

use std::convert::TryFrom;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{watch, RwLock};
use tokio::time::interval;

use aunsorm_core::clock::{ClockError, SecureClockSnapshot, SecureClockVerifier};
use reqwest::header::CONTENT_TYPE;
use thiserror::Error;

const MAX_ATTESTATION_BYTES: usize = 16 * 1024;

/// Clock attestation'ı periyodik olarak yenileyen servis
pub struct ClockRefreshService {
    /// Current valid attestation
    current: Arc<RwLock<SecureClockSnapshot>>,
    /// NTP server URL (optional for dev mode)
    ntp_url: Option<String>,
    /// Refresh interval (default: 15 seconds for 30s `max_age`)
    refresh_interval: Duration,
    /// Broadcast channel for attestation updates
    notifier: watch::Sender<SecureClockSnapshot>,
    /// Hardened verifier for attestation validation
    verifier: Arc<SecureClockVerifier>,
}

impl ClockRefreshService {
    /// Create a new refresh service.
    ///
    /// # Errors
    ///
    /// Returns a [`ClockRefreshError`] when the provided NTP URL is not a
    /// valid HTTPS endpoint. The URL validation occurs before the service is
    /// constructed so misconfigurations are surfaced immediately.
    pub fn new(
        initial: SecureClockSnapshot,
        ntp_url: Option<String>,
        refresh_interval: Duration,
        verifier: Arc<SecureClockVerifier>,
    ) -> Result<Self, ClockRefreshError> {
        if let Some(url) = &ntp_url {
            Self::validate_url(url)?;
        }

        let (notifier, _) = watch::channel(initial.clone());
        Ok(Self {
            current: Arc::new(RwLock::new(initial)),
            ntp_url,
            refresh_interval,
            notifier,
            verifier,
        })
    }

    /// Get the current valid attestation
    pub async fn get_current(&self) -> SecureClockSnapshot {
        self.current.read().await.clone()
    }

    /// Obtain a shared view of the attestation store.
    #[must_use]
    pub fn attestation(&self) -> Arc<RwLock<SecureClockSnapshot>> {
        Arc::clone(&self.current)
    }

    /// Subscribe to attestation updates.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<SecureClockSnapshot> {
        self.notifier.subscribe()
    }

    /// Start the background refresh task
    #[must_use]
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(self.refresh_interval);

            loop {
                ticker.tick().await;

                if let Err(err) = self.refresh_once().await {
                    tracing::warn!("Clock attestation refresh failed: {err}");
                    // Continue using old attestation until successful refresh
                }
            }
        })
    }

    /// Attempt to refresh attestation once
    async fn refresh_once(&self) -> Result<(), ClockRefreshError> {
        let new_snapshot = if let Some(ref url) = self.ntp_url {
            // Production: Fetch from NTP server
            self.fetch_from_ntp(url).await?
        } else {
            // Development: Generate mock attestation with current timestamp
            let template = self.current.read().await.clone();
            Self::generate_dev_attestation(&template)?
        };

        self.accept_snapshot(new_snapshot).await
    }

    /// Fetch fresh attestation from NTP server
    async fn fetch_from_ntp(&self, url: &str) -> Result<SecureClockSnapshot, ClockRefreshError> {
        let parsed = reqwest::Url::parse(url)?;
        if parsed.scheme() != "https" {
            return Err(ClockRefreshError::InsecureScheme {
                scheme: parsed.scheme().to_owned(),
            });
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        let response = client.get(parsed).send().await?.error_for_status()?;
        if let Some(content_type) = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
        {
            if !content_type.starts_with("application/json") {
                return Err(ClockRefreshError::InvalidContentType(
                    content_type.to_owned(),
                ));
            }
        }

        let body = response.bytes().await?;
        if body.len() > MAX_ATTESTATION_BYTES {
            return Err(ClockRefreshError::PayloadTooLarge {
                size: body.len(),
                max: MAX_ATTESTATION_BYTES,
            });
        }

        let snapshot: SecureClockSnapshot = serde_json::from_slice(&body)?;

        Ok(snapshot)
    }

    /// Generate dev-mode attestation with current timestamp
    fn generate_dev_attestation(
        template: &SecureClockSnapshot,
    ) -> Result<SecureClockSnapshot, ClockRefreshError> {
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(ClockRefreshError::SystemTime)?
                .as_millis(),
        )
        .map_err(|_| ClockRefreshError::TimestampOverflow)?;

        Ok(SecureClockSnapshot {
            authority_id: template.authority_id.clone(),
            authority_fingerprint_hex: template.authority_fingerprint_hex.clone(),
            unix_time_ms: now_ms,
            stratum: template.stratum,
            round_trip_ms: template.round_trip_ms,
            dispersion_ms: template.dispersion_ms,
            estimated_offset_ms: 0,
            signature_b64: template.signature_b64.clone(),
        })
    }

    async fn accept_snapshot(
        &self,
        snapshot: SecureClockSnapshot,
    ) -> Result<(), ClockRefreshError> {
        self.verifier.verify(&snapshot)?;

        let mut guard = self.current.write().await;
        *guard = snapshot.clone();
        drop(guard);
        let _ = self.notifier.send(snapshot);
        tracing::debug!("Clock attestation refreshed successfully");

        Ok(())
    }

    fn validate_url(candidate: &str) -> Result<(), ClockRefreshError> {
        let parsed = reqwest::Url::parse(candidate)?;
        if parsed.scheme() != "https" {
            return Err(ClockRefreshError::InsecureScheme {
                scheme: parsed.scheme().to_owned(),
            });
        }
        Ok(())
    }
}

/// Errors produced by the clock refresh workflow.
#[derive(Debug, Error)]
pub enum ClockRefreshError {
    /// The provided URL is invalid.
    #[error("clock attestation URL invalid: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// HTTP transport or TLS failure.
    #[error("clock attestation HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Response declared a non-JSON content type.
    #[error("clock attestation content-type is not application/json: {0}")]
    InvalidContentType(String),
    /// Body exceeded the configured limit.
    #[error("clock attestation payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },
    /// Local clock was behind the UNIX epoch.
    #[error("system clock is earlier than unix epoch")]
    SystemTime(#[from] std::time::SystemTimeError),
    /// Converting the timestamp exceeded bounds.
    #[error("clock attestation timestamp overflowed supported range")]
    TimestampOverflow,
    /// Verifier rejected the attestation payload.
    #[error(transparent)]
    Verification(#[from] ClockError),
    /// Clock refresh URL is using an insecure scheme.
    #[error("clock attestation URL must use https scheme (found {scheme})")]
    InsecureScheme { scheme: String },
    /// JSON payload could not be decoded.
    #[error("clock attestation payload parse failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use aunsorm_core::clock::ClockAuthority;

    #[tokio::test]
    async fn test_dev_attestation_generation() {
        let initial = SecureClockSnapshot {
            authority_id: "test".to_string(),
            authority_fingerprint_hex: "00".repeat(32),
            unix_time_ms: 1_000_000_000_000,
            stratum: 2,
            round_trip_ms: 10,
            dispersion_ms: 10,
            estimated_offset_ms: 0,
            signature_b64: "test".to_string(),
        };

        let authority = ClockAuthority::new(
            initial.authority_id.clone(),
            initial.authority_fingerprint_hex.clone(),
        );
        let verifier = Arc::new(
            SecureClockVerifier::configurable(vec![authority], Duration::from_secs(300))
                .expect("verifier"),
        );

        let service = Arc::new(
            ClockRefreshService::new(initial, None, Duration::from_secs(1), verifier)
                .expect("clock refresh"),
        );

        let snapshot1 = service.get_current().await;
        let mut rx = service.subscribe();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Refresh should generate new timestamp
        service.refresh_once().await.expect("refresh");
        // Wait for notifier to propagate the update
        rx.changed().await.unwrap();
        let snapshot2 = service.get_current().await;

        assert!(snapshot2.unix_time_ms > snapshot1.unix_time_ms);
    }

    #[test]
    fn rejects_insecure_refresh_url() {
        let initial = SecureClockSnapshot {
            authority_id: "ntp.dev".to_string(),
            authority_fingerprint_hex: "11".repeat(32),
            unix_time_ms: 1_600_000_000_000,
            stratum: 2,
            round_trip_ms: 10,
            dispersion_ms: 10,
            estimated_offset_ms: 0,
            signature_b64: "dev".to_string(),
        };
        let authority = ClockAuthority::new(
            initial.authority_id.clone(),
            initial.authority_fingerprint_hex.clone(),
        );
        let verifier = Arc::new(
            SecureClockVerifier::configurable(vec![authority], Duration::from_secs(300))
                .expect("verifier"),
        );

        let result = ClockRefreshService::new(
            initial,
            Some("http://example.com/attest".to_string()),
            Duration::from_secs(15),
            verifier,
        );

        assert!(matches!(
            result,
            Err(ClockRefreshError::InsecureScheme { ref scheme }) if scheme == "http"
        ));
    }
}
