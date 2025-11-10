use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::error::{KmsError, Result};

/// Declarative configuration describing when a key must be rotated.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RotationPolicyConfig {
    #[serde(default)]
    pub auto_rotate: bool,
    pub expires_after_seconds: u64,
    #[serde(default)]
    pub grace_period_seconds: Option<u64>,
}

impl RotationPolicyConfig {
    fn validate(&self) -> Result<()> {
        if self.expires_after_seconds == 0 {
            return Err(KmsError::Rotation(
                "rotation policy must expire keys after a positive duration".into(),
            ));
        }
        if let Some(grace) = self.grace_period_seconds {
            if grace == 0 {
                return Err(KmsError::Rotation(
                    "rotation policy grace period must be positive".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Runtime rotation policy with concrete durations.
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    auto_rotate: bool,
    expires_after: Duration,
    grace_period: Duration,
}

impl RotationPolicy {
    /// Constructs a runtime policy from configuration.
    pub fn from_config(config: &RotationPolicyConfig) -> Result<Self> {
        config.validate()?;
        let expires_after =
            Duration::seconds(i64::try_from(config.expires_after_seconds).map_err(|_| {
                KmsError::Rotation("rotation expiry exceeds i64::MAX seconds".into())
            })?);
        let grace_secs = config.grace_period_seconds.unwrap_or(0);
        let grace_period = Duration::seconds(i64::try_from(grace_secs).map_err(|_| {
            KmsError::Rotation("rotation grace period exceeds i64::MAX seconds".into())
        })?);
        Ok(Self {
            auto_rotate: config.auto_rotate,
            expires_after,
            grace_period,
        })
    }

    /// Whether automatic rotation should be attempted.
    pub const fn auto_rotate(&self) -> bool {
        self.auto_rotate
    }

    /// Computes the expiration timestamp relative to a creation instant.
    pub fn compute_expiration(&self, created_at: OffsetDateTime) -> OffsetDateTime {
        created_at + self.expires_after
    }

    /// Computes grace deadline for previous key versions.
    pub fn compute_grace_deadline(&self, activated_at: OffsetDateTime) -> OffsetDateTime {
        activated_at + self.grace_period
    }

    /// Whether the key requires rotation given creation time and current clock.
    pub fn is_expired(&self, created_at: OffsetDateTime, now: OffsetDateTime) -> bool {
        now >= self.compute_expiration(created_at)
    }
}

/// Details about a rotation event emitted by backends.
#[derive(Debug, Clone)]
pub struct RotationEvent {
    pub key_id: String,
    pub old_kid: Option<String>,
    pub new_kid: String,
    pub activated_at: OffsetDateTime,
    pub previous_valid_until: Option<OffsetDateTime>,
}

impl RotationEvent {
    /// Creates an event for a rotation operation.
    #[must_use]
    pub fn new(
        key_id: impl Into<String>,
        old_kid: Option<String>,
        new_kid: String,
        activated_at: OffsetDateTime,
        previous_valid_until: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            old_kid,
            new_kid,
            activated_at,
            previous_valid_until,
        }
    }
}
