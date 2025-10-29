#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;

use async_trait::async_trait as async_trait_macro;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Re-exports the [`async_trait`] macro for consumers implementing [`RenewalInventory`].
pub use async_trait::async_trait;

/// Default window used by the server to determine when certificates should be
/// renewed.
pub const DEFAULT_RENEWAL_THRESHOLD: Duration = Duration::days(30);

/// Metadata describing a certificate managed by the renewal subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCertificate {
    order_id: String,
    identifiers: Vec<String>,
    expires_at: OffsetDateTime,
    last_renewed_at: Option<OffsetDateTime>,
    metadata: BTreeMap<String, String>,
}

impl ManagedCertificate {
    /// Creates a new managed certificate entry.
    #[must_use]
    pub fn new(
        order_id: impl Into<String>,
        identifiers: Vec<String>,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            order_id: order_id.into(),
            identifiers,
            expires_at,
            last_renewed_at: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Returns the associated order identifier.
    #[must_use]
    pub fn order_id(&self) -> &str {
        &self.order_id
    }

    /// Returns the identifiers the certificate covers (for example DNS names).
    #[must_use]
    pub fn identifiers(&self) -> &[String] {
        &self.identifiers
    }

    /// Returns the expiry timestamp of the certificate.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Returns the timestamp of the last successful renewal, if known.
    #[must_use]
    pub const fn last_renewed_at(&self) -> Option<OffsetDateTime> {
        self.last_renewed_at
    }

    /// Updates the stored timestamp of the last successful renewal.
    #[allow(clippy::missing_const_for_fn)]
    pub fn set_last_renewed_at(&mut self, value: Option<OffsetDateTime>) {
        self.last_renewed_at = value;
    }

    /// Returns the metadata map associated with the certificate.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }

    /// Returns a mutable reference to the metadata map so that callers can enrich it.
    #[allow(clippy::missing_const_for_fn)]
    pub fn metadata_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.metadata
    }
}

/// A certificate that is within the renewal window and should be processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalCandidate {
    order_id: String,
    identifiers: Vec<String>,
    expires_at: OffsetDateTime,
    time_until_expiry: Duration,
    metadata: BTreeMap<String, String>,
}

impl RenewalCandidate {
    #[must_use]
    pub fn order_id(&self) -> &str {
        &self.order_id
    }

    #[must_use]
    pub fn identifiers(&self) -> &[String] {
        &self.identifiers
    }

    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    #[must_use]
    pub const fn time_until_expiry(&self) -> Duration {
        self.time_until_expiry
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }
}

/// Inventory providers expose the certificates managed by a controller.
#[async_trait_macro]
pub trait RenewalInventory: Send + Sync {
    /// Error type produced when the inventory cannot be queried.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Loads the currently managed certificates.
    async fn load(&self) -> Result<Vec<ManagedCertificate>, Self::Error>;
}

/// Errors that can arise while executing the renewal scanning job.
#[derive(Debug, Error)]
pub enum RenewalJobError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// The configured threshold was negative, therefore the renewal window is invalid.
    #[error("yenileme eşiği negatif olamaz")]
    NegativeThreshold,
    /// The inventory backend failed to provide certificate metadata.
    #[error("sertifika envanteri okunamadı: {0}")]
    Inventory(#[source] E),
}

/// Job responsible for detecting certificates that are about to expire.
#[derive(Debug, Clone)]
pub struct RenewalJob<S> {
    inventory: S,
    threshold: Duration,
}

impl<S> RenewalJob<S> {
    /// Builds a new renewal job from the provided inventory source and threshold.
    #[must_use]
    pub const fn new(inventory: S, threshold: Duration) -> Self {
        Self {
            inventory,
            threshold,
        }
    }

    /// Returns the currently configured renewal threshold.
    #[must_use]
    pub const fn threshold(&self) -> Duration {
        self.threshold
    }
}

impl<S> RenewalJob<S>
where
    S: RenewalInventory,
{
    /// Scans the managed certificates and returns those that must be renewed.
    ///
    /// # Errors
    ///
    /// Propagates [`RenewalJobError::Inventory`] when the underlying inventory cannot be
    /// queried or [`RenewalJobError::NegativeThreshold`] when the configured threshold is
    /// invalid.
    pub async fn scan(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<RenewalCandidate>, RenewalJobError<S::Error>> {
        if self.threshold.is_negative() {
            return Err(RenewalJobError::NegativeThreshold);
        }

        let window_end = now + self.threshold;

        let mut candidates = Vec::new();
        let managed = self
            .inventory
            .load()
            .await
            .map_err(RenewalJobError::Inventory)?;

        for certificate in managed {
            if certificate.expires_at > window_end {
                continue;
            }
            let remaining = certificate.expires_at - now;
            candidates.push(RenewalCandidate {
                order_id: certificate.order_id.clone(),
                identifiers: certificate.identifiers.clone(),
                expires_at: certificate.expires_at,
                time_until_expiry: remaining,
                metadata: certificate.metadata,
            });
        }

        candidates.sort_by(|a, b| a.expires_at.cmp(&b.expires_at));
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::async_trait_macro;
    use super::{ManagedCertificate, RenewalInventory, RenewalJob, RenewalJobError};
    use time::macros::datetime;
    use time::Duration;

    struct MemoryInventory {
        certificates: Vec<ManagedCertificate>,
    }

    #[async_trait_macro]
    impl RenewalInventory for MemoryInventory {
        type Error = std::convert::Infallible;

        async fn load(&self) -> Result<Vec<ManagedCertificate>, Self::Error> {
            Ok(self.certificates.clone())
        }
    }

    #[tokio::test]
    async fn scan_returns_expiring_certificates_sorted() {
        let now = datetime!(2024-01-15 12:00 UTC);
        let mut first = ManagedCertificate::new(
            "order-1",
            vec!["example.com".to_string()],
            now - Duration::days(1),
        );
        first
            .metadata_mut()
            .insert("note".to_string(), "already expired".to_string());
        let second = ManagedCertificate::new(
            "order-2",
            vec!["service.example".to_string()],
            now + Duration::days(10),
        );
        let third = ManagedCertificate::new(
            "order-3",
            vec!["long-lived.example".to_string()],
            now + Duration::days(60),
        );
        let inventory = MemoryInventory {
            certificates: vec![third, first.clone(), second.clone()],
        };
        let job = RenewalJob::new(inventory, Duration::days(30));
        let candidates = job.scan(now).await.expect("scan");
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].order_id(), "order-1");
        assert!(candidates[0].time_until_expiry().is_negative());
        assert_eq!(
            candidates[0]
                .metadata()
                .get("note")
                .expect("metadata preserved"),
            "already expired"
        );
        assert_eq!(candidates[1].order_id(), "order-2");
        assert_eq!(
            candidates[1].identifiers(),
            &["service.example".to_string()]
        );
        assert_eq!(candidates[1].time_until_expiry().whole_days(), 10);
    }

    #[tokio::test]
    async fn scan_rejects_negative_threshold() {
        let inventory = MemoryInventory {
            certificates: Vec::new(),
        };
        let job = RenewalJob::new(inventory, Duration::days(-1));
        let now = datetime!(2024-01-01 00:00 UTC);
        let err = job.scan(now).await.unwrap_err();
        match err {
            RenewalJobError::NegativeThreshold => {}
            RenewalJobError::Inventory(err) => panic!("unexpected inventory error: {err}"),
        }
    }
}
