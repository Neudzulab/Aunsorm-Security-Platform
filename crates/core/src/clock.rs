use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Clock authority metadata recognised by the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockAuthority {
    /// Human readable identifier (e.g. host name).
    pub id: String,
    /// Hex encoded SHA-256 fingerprint of the authority certificate.
    pub fingerprint_hex: String,
}

impl ClockAuthority {
    /// Creates a new clock authority descriptor.
    ///
    /// # Examples
    /// ```
    /// use aunsorm_core::clock::ClockAuthority;
    ///
    /// let authority = ClockAuthority::new(
    ///     "ntp.example.org",
    ///     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    /// );
    /// assert_eq!(authority.id, "ntp.example.org");
    /// ```
    #[must_use]
    pub fn new(id: impl Into<String>, fingerprint_hex: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            fingerprint_hex: fingerprint_hex.into(),
        }
    }
}

/// Serialized NTP snapshot and accompanying attestation values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureClockSnapshot {
    /// Authority identifier that produced the measurement.
    pub authority_id: String,
    /// Hex encoded certificate fingerprint that signed the sample.
    pub authority_fingerprint_hex: String,
    /// Measured UNIX timestamp in milliseconds.
    pub unix_time_ms: u64,
    /// Reported stratum of the NTP source.
    pub stratum: u8,
    /// Round-trip delay estimate in milliseconds.
    pub round_trip_ms: u32,
    /// Dispersion/uncertainty window in milliseconds.
    pub dispersion_ms: u32,
    /// Observed offset between the local monotonic clock and the authority (ms).
    pub estimated_offset_ms: i64,
    /// Base64url signature or MAC over the NTP packet and authority identity.
    pub signature_b64: String,
}

impl SecureClockSnapshot {
    /// Returns the attested UNIX time as [`SystemTime`].
    fn attested_time(&self) -> Result<SystemTime, ClockError> {
        UNIX_EPOCH
            .checked_add(Duration::from_millis(self.unix_time_ms))
            .ok_or(ClockError::TimestampOverflow)
    }
}

/// Result of a successful clock validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockValidation {
    /// Identifier of the authority that issued the attestation.
    pub authority_id: String,
    /// Hex encoded fingerprint of the authority certificate.
    pub authority_fingerprint_hex: String,
    /// UNIX timestamp in milliseconds validated by the authority.
    pub unix_time_ms: u64,
    /// Absolute skew between system clock and attested clock (ms).
    pub skew_ms: u64,
    /// Round-trip delay estimate in milliseconds.
    pub round_trip_ms: u32,
    /// Dispersion/uncertainty window in milliseconds.
    pub dispersion_ms: u32,
    /// Base64url signature provided by the authority.
    pub signature_b64: String,
}

/// Errors produced while validating NTP or secure clock attestations.
#[derive(Debug, Error)]
pub enum ClockError {
    /// No authorities were configured.
    #[error("no trusted clock authorities configured")]
    EmptyAuthorities,
    /// The attestation references an authority that is not trusted.
    #[error("untrusted clock authority: {fingerprint_hex}")]
    UntrustedAuthority { fingerprint_hex: String },
    /// The stratum of the authority exceeds the configured upper bound.
    #[error("ntp stratum {stratum} exceeds allowed maximum {max}")]
    InvalidStratum { stratum: u8, max: u8 },
    /// Round-trip delay is outside the acceptable threshold.
    #[error("round-trip delay {round_trip_ms}ms exceeds allowed {max_ms}ms")]
    ExcessiveRoundTrip { round_trip_ms: u32, max_ms: u32 },
    /// Dispersion/uncertainty is above the limit.
    #[error("dispersion {dispersion_ms}ms exceeds allowed {max_ms}ms")]
    ExcessiveDispersion { dispersion_ms: u32, max_ms: u32 },
    /// The authority reported an excessive clock offset.
    #[error("clock skew {offset_ms}ms exceeds allowed {max_ms}ms")]
    ExcessiveSkew { offset_ms: i64, max_ms: u64 },
    /// Attestation timestamp is too far in the future compared to local clock.
    #[error("clock attestation references future instant {offset_ms}ms ahead")]
    FutureTimestamp { offset_ms: i64 },
    /// Attestation is considered stale.
    #[error("clock attestation stale by {age_ms}ms (max {max_ms}ms)")]
    StaleAttestation { age_ms: u128, max_ms: u128 },
    /// Signature or MAC payload is missing.
    #[error("clock attestation signature missing")]
    MissingSignature,
    /// Conversion from unix timestamp overflowed the `SystemTime` domain.
    #[error("clock attestation timestamp overflow")]
    TimestampOverflow,
}

/// Validates secure NTP attestations against configured authorities and limits.
#[derive(Debug, Clone)]
pub struct SecureClockVerifier {
    authorities: HashSet<String>,
    max_stratum: u8,
    max_round_trip: Duration,
    max_dispersion: Duration,
    max_skew: Duration,
    max_age: Duration,
}

impl SecureClockVerifier {
    /// Builds a new verifier.
    ///
    /// # Errors
    /// Returns [`ClockError::EmptyAuthorities`] when the authority list is empty.
    ///
    /// # Examples
    /// ```
    /// # use std::time::Duration;
    /// # use aunsorm_core::clock::{ClockAuthority, SecureClockVerifier};
    /// let authority = ClockAuthority::new(
    ///     "ntp.example.org",
    ///     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    /// );
    /// let verifier = SecureClockVerifier::new(
    ///     vec![authority],
    ///     4,
    ///     Duration::from_millis(50),
    ///     Duration::from_millis(25),
    ///     Duration::from_millis(150),
    ///     Duration::from_secs(30),
    /// )?;
    /// # let _ = verifier;
    /// # Ok::<(), aunsorm_core::clock::ClockError>(())
    /// ```
    pub fn new(
        authorities: Vec<ClockAuthority>,
        max_stratum: u8,
        max_round_trip: Duration,
        max_dispersion: Duration,
        max_skew: Duration,
        max_age: Duration,
    ) -> Result<Self, ClockError> {
        if authorities.is_empty() {
            return Err(ClockError::EmptyAuthorities);
        }
        let normalized = authorities
            .into_iter()
            .map(|authority| authority.fingerprint_hex)
            .collect::<HashSet<_>>();
        Ok(Self {
            authorities: normalized,
            max_stratum,
            max_round_trip,
            max_dispersion,
            max_skew,
            max_age,
        })
    }

    /// Provides a hardened default verifier accepting only stratum <= 3 sources.
    /// The caller must still supply the trust anchor list.
    ///
    /// # Errors
    /// Returns [`ClockError::EmptyAuthorities`] when the authority list is empty.
    ///
    /// # Examples
    /// ```
    /// # use aunsorm_core::clock::{ClockAuthority, SecureClockVerifier};
    /// let authority = ClockAuthority::new(
    ///     "ntp.example.org",
    ///     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    /// );
    /// let verifier = SecureClockVerifier::strict(vec![authority])?;
    /// # let _ = verifier;
    /// # Ok::<(), aunsorm_core::clock::ClockError>(())
    /// ```
    pub fn strict(authorities: Vec<ClockAuthority>) -> Result<Self, ClockError> {
        Self::new(
            authorities,
            3,
            Duration::from_millis(50),
            Duration::from_millis(25),
            Duration::from_millis(150),
            Duration::from_secs(30), // Production: 30s max_age (NTP attestation must be fresh)
        )
    }

    /// Creates a verifier with configurable max_age for different environments.
    ///
    /// **Production**: Use 30s max_age with real NTP server that refreshes attestation every ~15s
    /// **Staging/Development**: Use higher max_age (300s) if using static/manual attestations
    ///
    /// # Examples
    /// ```
    /// use std::time::Duration;
    /// use aunsorm_core::clock::{ClockAuthority, SecureClockVerifier};
    ///
    /// let authority = ClockAuthority::new("ntp.example.org", "0123...");
    ///
    /// // Development: Tolerant of static attestations
    /// let dev_verifier = SecureClockVerifier::configurable(
    ///     vec![authority.clone()],
    ///     Duration::from_secs(300), // 5 minutes
    /// )?;
    ///
    /// // Production: Strict NTP freshness
    /// let prod_verifier = SecureClockVerifier::configurable(
    ///     vec![authority],
    ///     Duration::from_secs(30),
    /// )?;
    /// # Ok::<(), aunsorm_core::clock::ClockError>(())
    /// ```
    pub fn configurable(
        authorities: Vec<ClockAuthority>,
        max_age: Duration,
    ) -> Result<Self, ClockError> {
        Self::new(
            authorities,
            3,
            Duration::from_millis(50),
            Duration::from_millis(25),
            Duration::from_millis(150),
            max_age,
        )
    }

    /// Validates the provided snapshot, returning the canonical timestamp and
    /// derived metadata if successful.
    ///
    /// # Errors
    /// Returns [`ClockError`] when the attestation violates trust constraints or
    /// timestamp conversions overflow the supported range.
    ///
    /// # Examples
    /// ```
    /// # use std::time::{Duration, SystemTime, UNIX_EPOCH};
    /// # use aunsorm_core::clock::{ClockAuthority, SecureClockSnapshot, SecureClockVerifier};
    /// let authority = ClockAuthority::new(
    ///     "ntp.example.org",
    ///     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    /// );
    /// let verifier = SecureClockVerifier::strict(vec![authority.clone()])?;
    /// let now_ms = SystemTime::now()
    ///     .duration_since(UNIX_EPOCH)
    ///     .expect("system clock is before unix epoch")
    ///     .as_millis() as u64;
    /// let snapshot = SecureClockSnapshot {
    ///     authority_id: authority.id.clone(),
    ///     authority_fingerprint_hex: authority.fingerprint_hex.clone(),
    ///     unix_time_ms: now_ms,
    ///     stratum: 2,
    ///     round_trip_ms: 8,
    ///     dispersion_ms: 12,
    ///     estimated_offset_ms: 0,
    ///     signature_b64: "ZHVtbXktc2lnbmF0dXJl".to_owned(),
    /// };
    /// let validation = verifier.verify(&snapshot)?;
    /// assert_eq!(validation.unix_time_ms, snapshot.unix_time_ms);
    /// # Ok::<(), aunsorm_core::clock::ClockError>(())
    /// ```
    pub fn verify(&self, snapshot: &SecureClockSnapshot) -> Result<ClockValidation, ClockError> {
        if snapshot.signature_b64.trim().is_empty() {
            return Err(ClockError::MissingSignature);
        }

        if !self
            .authorities
            .contains(&snapshot.authority_fingerprint_hex)
        {
            return Err(ClockError::UntrustedAuthority {
                fingerprint_hex: snapshot.authority_fingerprint_hex.clone(),
            });
        }
        if snapshot.stratum == 0 || snapshot.stratum > self.max_stratum {
            return Err(ClockError::InvalidStratum {
                stratum: snapshot.stratum,
                max: self.max_stratum,
            });
        }
        let round_trip = Duration::from_millis(u64::from(snapshot.round_trip_ms));
        let max_round_trip_ms = u32::try_from(self.max_round_trip.as_millis()).unwrap_or(u32::MAX);
        if round_trip > self.max_round_trip {
            return Err(ClockError::ExcessiveRoundTrip {
                round_trip_ms: snapshot.round_trip_ms,
                max_ms: max_round_trip_ms,
            });
        }
        let dispersion = Duration::from_millis(u64::from(snapshot.dispersion_ms));
        let max_dispersion_ms = u32::try_from(self.max_dispersion.as_millis()).unwrap_or(u32::MAX);
        if dispersion > self.max_dispersion {
            return Err(ClockError::ExcessiveDispersion {
                dispersion_ms: snapshot.dispersion_ms,
                max_ms: max_dispersion_ms,
            });
        }
        let offset_abs = snapshot.estimated_offset_ms.unsigned_abs();
        let max_skew_ms = u64::try_from(self.max_skew.as_millis()).unwrap_or(u64::MAX);
        if offset_abs > max_skew_ms {
            return Err(ClockError::ExcessiveSkew {
                offset_ms: snapshot.estimated_offset_ms,
                max_ms: max_skew_ms,
            });
        }

        let attested_time = snapshot.attested_time()?;
        let now = SystemTime::now();
        match attested_time.duration_since(now) {
            Ok(delta) if delta > self.max_skew => {
                let offset_ms = i64::try_from(delta.as_millis()).unwrap_or(i64::MAX);
                return Err(ClockError::FutureTimestamp { offset_ms });
            }
            Err(err) => {
                let behind = err.duration().as_millis();
                let max_age_ms = self.max_age.as_millis();
                if behind > max_age_ms {
                    return Err(ClockError::StaleAttestation {
                        age_ms: behind,
                        max_ms: max_age_ms,
                    });
                }
            }
            _ => {}
        }

        Ok(ClockValidation {
            authority_id: snapshot.authority_id.clone(),
            authority_fingerprint_hex: snapshot.authority_fingerprint_hex.clone(),
            unix_time_ms: snapshot.unix_time_ms,
            skew_ms: offset_abs,
            round_trip_ms: snapshot.round_trip_ms,
            dispersion_ms: snapshot.dispersion_ms,
            signature_b64: snapshot.signature_b64.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_authority() -> ClockAuthority {
        ClockAuthority::new(
            "ntp.example.org",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
    }

    fn sample_snapshot() -> SecureClockSnapshot {
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        SecureClockSnapshot {
            authority_id: "ntp.example.org".to_owned(),
            authority_fingerprint_hex:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            unix_time_ms: now_ms,
            stratum: 2,
            round_trip_ms: 8,
            dispersion_ms: 12,
            estimated_offset_ms: 4,
            signature_b64: "ZHVtbXktc2lnbmF0dXJl".to_owned(),
        }
    }

    #[test]
    fn verify_accepts_valid_snapshot() {
        let snapshot = sample_snapshot();
        let verifier = SecureClockVerifier::strict(vec![sample_authority()]).expect("verifier");
        let validation = verifier.verify(&snapshot).expect("valid");
        assert_eq!(validation.authority_id, "ntp.example.org");
        assert_eq!(validation.round_trip_ms, 8);
        assert_eq!(validation.skew_ms, 4);
    }

    #[test]
    fn verify_rejects_untrusted_authority() {
        let mut snapshot = sample_snapshot();
        snapshot.authority_fingerprint_hex =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        let verifier = SecureClockVerifier::strict(vec![sample_authority()]).expect("verifier");
        let err = verifier.verify(&snapshot).unwrap_err();
        assert!(matches!(err, ClockError::UntrustedAuthority { .. }));
    }

    #[test]
    fn verify_rejects_stale_snapshot() {
        let mut snapshot = sample_snapshot();
        snapshot.unix_time_ms -= 120_000; // 120 seconds in the past
        let verifier = SecureClockVerifier::new(
            vec![sample_authority()],
            3,
            Duration::from_millis(50),
            Duration::from_millis(25),
            Duration::from_millis(150),
            Duration::from_secs(30),
        )
        .expect("verifier");
        let err = verifier.verify(&snapshot).unwrap_err();
        assert!(matches!(err, ClockError::StaleAttestation { .. }));
    }
}
