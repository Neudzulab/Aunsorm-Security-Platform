use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::mock_ledger::LedgerEntry;

/// Validation errors returned when constructing media ledger records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediaRecordError {
    /// Provided field is empty or consists only of whitespace.
    EmptyField(&'static str),
    /// RFC3339 timestamp parsing failed for the supplied value.
    InvalidTimestamp { value: String },
    /// Timestamp resolved to an instant prior to the Unix epoch.
    TimestampOutOfRange { value: String },
}

/// Canonical representation of a media transparency record bound for the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaLedgerRecord {
    video_hash: String,
    image_hash: String,
    audio_hash: String,
    calibration_id: String,
    captured_at: OffsetDateTime,
}

impl MediaLedgerRecord {
    /// Builds a new media ledger record, ensuring all invariants required by the tests.
    pub fn new(
        video_hash: impl Into<String>,
        image_hash: impl Into<String>,
        audio_hash: impl Into<String>,
        calibration_id: impl Into<String>,
        captured_at_rfc3339: &str,
    ) -> Result<Self, MediaRecordError> {
        let video_hash = Self::normalize(video_hash, "video_hash")?;
        let image_hash = Self::normalize(image_hash, "image_hash")?;
        let audio_hash = Self::normalize(audio_hash, "audio_hash")?;
        let calibration_id = Self::normalize(calibration_id, "calibration_id")?;
        let captured_at = OffsetDateTime::parse(captured_at_rfc3339, &Rfc3339).map_err(|_| {
            MediaRecordError::InvalidTimestamp {
                value: captured_at_rfc3339.to_owned(),
            }
        })?;
        if captured_at.unix_timestamp_nanos() < 0 {
            return Err(MediaRecordError::TimestampOutOfRange {
                value: captured_at_rfc3339.to_owned(),
            });
        }
        Ok(Self {
            video_hash,
            image_hash,
            audio_hash,
            calibration_id,
            captured_at,
        })
    }

    fn normalize(
        value: impl Into<String>,
        field: &'static str,
    ) -> Result<String, MediaRecordError> {
        let owned = value.into();
        if owned.trim().is_empty() {
            return Err(MediaRecordError::EmptyField(field));
        }
        Ok(owned)
    }

    /// Returns the captured_at value as milliseconds since the Unix epoch.
    fn captured_at_ms(&self) -> u64 {
        let nanos = self.captured_at.unix_timestamp_nanos();
        u64::try_from(nanos / 1_000_000).expect("timestamp already validated")
    }

    /// Returns the timestamp encoded in canonical RFC3339 format.
    #[must_use]
    pub fn captured_at_rfc3339(&self) -> String {
        self.captured_at
            .format(&Rfc3339)
            .expect("RFC3339 formatting is infallible")
    }

    /// Produces the canonical payload stored in the ledger.
    #[must_use]
    pub fn canonical_payload(&self) -> Vec<u8> {
        format!(
            "video_hash={};image_hash={};audio_hash={};calibration_id={};captured_at={}",
            self.video_hash,
            self.image_hash,
            self.audio_hash,
            self.calibration_id,
            self.captured_at_rfc3339(),
        )
        .into_bytes()
    }

    /// Creates a ledger entry derived from the record contents.
    pub fn into_ledger_entry(self, index: u64, prev_hash: [u8; 32]) -> LedgerEntry {
        LedgerEntry::new(
            index,
            prev_hash,
            self.canonical_payload(),
            self.captured_at_ms(),
        )
    }

    /// Exposes the hashes for assertions without cloning the underlying strings.
    #[must_use]
    pub fn hashes(&self) -> (&str, &str, &str) {
        (&self.video_hash, &self.image_hash, &self.audio_hash)
    }

    /// Returns the calibration identifier.
    #[must_use]
    pub fn calibration_id(&self) -> &str {
        &self.calibration_id
    }

    /// Provides access to the timestamp for advanced checks without leaking mutability.
    #[must_use]
    pub fn captured_at(&self) -> OffsetDateTime {
        self.captured_at
    }
}
