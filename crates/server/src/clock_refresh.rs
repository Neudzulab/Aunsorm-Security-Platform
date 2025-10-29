//! Clock attestation refresh service
//!
//! Production'da NTP sunucusundan periyodik olarak yeni attestation alır.
//! Development'ta statik attestation kullanır veya mock server'dan çeker.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;

use aunsorm_core::clock::SecureClockSnapshot;

/// Clock attestation'ı periyodik olarak yenileyen servis
pub struct ClockRefreshService {
    /// Current valid attestation
    current: Arc<RwLock<SecureClockSnapshot>>,
    /// NTP server URL (optional for dev mode)
    ntp_url: Option<String>,
    /// Refresh interval (default: 15 seconds for 30s max_age)
    refresh_interval: Duration,
}

impl ClockRefreshService {
    /// Create a new refresh service
    pub fn new(
        initial: SecureClockSnapshot,
        ntp_url: Option<String>,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            current: Arc::new(RwLock::new(initial)),
            ntp_url,
            refresh_interval,
        }
    }

    /// Get the current valid attestation
    pub async fn get_current(&self) -> SecureClockSnapshot {
        self.current.read().await.clone()
    }

    /// Start the background refresh task
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(self.refresh_interval);

            loop {
                ticker.tick().await;

                if let Err(e) = self.refresh_once().await {
                    tracing::warn!("Clock attestation refresh failed: {}", e);
                    // Continue using old attestation until successful refresh
                }
            }
        })
    }

    /// Attempt to refresh attestation once
    async fn refresh_once(&self) -> Result<(), Box<dyn std::error::Error>> {
        let new_snapshot = if let Some(ref url) = self.ntp_url {
            // Production: Fetch from NTP server
            self.fetch_from_ntp(url).await?
        } else {
            // Development: Generate mock attestation with current timestamp
            self.generate_dev_attestation()?
        };

        // Update current attestation
        *self.current.write().await = new_snapshot;
        tracing::debug!("Clock attestation refreshed successfully");

        Ok(())
    }

    /// Fetch fresh attestation from NTP server
    async fn fetch_from_ntp(
        &self,
        url: &str,
    ) -> Result<SecureClockSnapshot, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        let response = client.get(url).send().await?;
        let snapshot: SecureClockSnapshot = response.json().await?;

        Ok(snapshot)
    }

    /// Generate dev-mode attestation with current timestamp
    fn generate_dev_attestation(&self) -> Result<SecureClockSnapshot, Box<dyn std::error::Error>> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

        Ok(SecureClockSnapshot {
            authority_id: "ntp.dev.aunsorm".to_string(),
            authority_fingerprint_hex:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            unix_time_ms: now_ms,
            stratum: 2,
            round_trip_ms: 8,
            dispersion_ms: 12,
            estimated_offset_ms: 0,
            signature_b64: "ZGV2X21vY2tfc2lnbmF0dXJl".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dev_attestation_generation() {
        let initial = SecureClockSnapshot {
            authority_id: "test".to_string(),
            authority_fingerprint_hex: "00".repeat(32),
            unix_time_ms: 1000000000000,
            stratum: 2,
            round_trip_ms: 10,
            dispersion_ms: 10,
            estimated_offset_ms: 0,
            signature_b64: "test".to_string(),
        };

        let service = Arc::new(ClockRefreshService::new(
            initial,
            None, // Dev mode
            Duration::from_secs(1),
        ));

        let snapshot1 = service.get_current().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Refresh should generate new timestamp
        service.refresh_once().await.unwrap();
        let snapshot2 = service.get_current().await;

        assert!(snapshot2.unix_time_ms > snapshot1.unix_time_ms);
    }
}
