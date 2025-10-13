#![allow(clippy::module_name_repetitions)]

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Hata türü.
#[derive(Debug, Error)]
pub enum TransparencyError {
    /// Zaman damgası UNIX başlangıcının öncesinde.
    #[error("timestamp before unix epoch")]
    TimestampUnderflow,
    /// Zincir sırası bozuldu.
    #[error("transparency chain broken at sequence {0}")]
    ChainBroken(u64),
    /// Zaman damgası geriye gitti.
    #[error("timestamp regression at sequence {sequence}")]
    TimestampRegression { sequence: u64 },
    /// Desteklenen kayıt sınırı aşıldı.
    #[error("transparency log sequence overflow")]
    SequenceOverflow,
}

/// Event tipleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransparencyEventKind {
    /// Yeni kamu anahtarı yayımlandı.
    Publish,
    /// Anahtar geri çekildi.
    Revoke,
    /// Anahtar döndürmesi bildirildi.
    Rotate,
}

impl TransparencyEventKind {
    #[must_use]
    const fn label(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Revoke => "revoke",
            Self::Rotate => "rotate",
        }
    }
}

impl fmt::Display for TransparencyEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Şeffaflık defterindeki tekil olay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyEvent {
    pub key_id: String,
    pub action: TransparencyEventKind,
    pub public_key: Vec<u8>,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Vec<u8>>,
}

impl TransparencyEvent {
    /// Yayınlama olayı oluşturur.
    #[must_use]
    pub fn publish(
        key_id: impl Into<String>,
        public_key: impl AsRef<[u8]>,
        timestamp: u64,
        note: Option<String>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            action: TransparencyEventKind::Publish,
            public_key: public_key.as_ref().to_vec(),
            timestamp,
            note,
            witness: None,
        }
    }

    /// Anahtarın geri çekildiğini bildiren olay oluşturur.
    ///
    /// Public key alanı revokasyon kayıtlarında boş bırakılır; bu davranış zincir
    /// karması hesaplamalarında da göz önünde bulundurulur.
    ///
    /// # Örnek
    /// ```
    /// use aunsorm_core::transparency::{TransparencyEvent, TransparencyEventKind};
    ///
    /// let event = TransparencyEvent::revoke("kid-1", 42, Some("compromised".into()));
    /// assert_eq!(event.action, TransparencyEventKind::Revoke);
    /// assert!(event.public_key.is_empty());
    /// ```
    #[must_use]
    pub fn revoke(key_id: impl Into<String>, timestamp: u64, note: Option<String>) -> Self {
        Self {
            key_id: key_id.into(),
            action: TransparencyEventKind::Revoke,
            public_key: Vec::new(),
            timestamp,
            note,
            witness: None,
        }
    }

    /// Anahtar döndürmesini bildiren olay oluşturur.
    ///
    /// # Örnek
    /// ```
    /// use aunsorm_core::transparency::{TransparencyEvent, TransparencyEventKind};
    ///
    /// let event = TransparencyEvent::rotate("kid-1", [0xAB_u8; 32], 7, None);
    /// assert_eq!(event.action, TransparencyEventKind::Rotate);
    /// assert_eq!(event.public_key.len(), 32);
    /// ```
    #[must_use]
    pub fn rotate(
        key_id: impl Into<String>,
        public_key: impl AsRef<[u8]>,
        timestamp: u64,
        note: Option<String>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            action: TransparencyEventKind::Rotate,
            public_key: public_key.as_ref().to_vec(),
            timestamp,
            note,
            witness: None,
        }
    }

    /// Şeffaflık olayına transcript kanıtı ekler.
    #[must_use]
    pub fn with_witness(mut self, witness: Option<Vec<u8>>) -> Self {
        self.witness = witness;
        self
    }
}

/// Deftere ait kayıt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyRecord {
    pub sequence: u64,
    pub timestamp: u64,
    pub event: TransparencyEvent,
    pub event_hash: [u8; 32],
    pub previous_hash: [u8; 32],
    pub tree_hash: [u8; 32],
}

impl TransparencyRecord {
    fn latest_sequence(records: &[Self]) -> u64 {
        records.last().map_or(0, |record| record.sequence)
    }
}

/// Zincir durumunun özetini tutan kontrol noktası bilgisi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyCheckpoint {
    /// En son kaydın sıra numarası.
    pub sequence: u64,
    /// En son kaydın zaman damgası.
    pub timestamp: u64,
    /// Güncel Merkle-benzeri ağaç başı karması.
    pub tree_hash: [u8; 32],
}

impl TransparencyCheckpoint {
    /// Yeni bir kontrol noktası oluşturur.
    #[must_use]
    pub const fn new(sequence: u64, timestamp: u64, tree_hash: [u8; 32]) -> Self {
        Self {
            sequence,
            timestamp,
            tree_hash,
        }
    }
}

fn hash_with_length(hasher: &mut Sha256, value: &[u8]) {
    let len = value.len() as u64;
    hasher.update(len.to_be_bytes());
    hasher.update(value);
}

fn hash_event(domain: &str, event: &TransparencyEvent) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"Aunsorm/1.01/key-transparency/event");
    hash_with_length(&mut hasher, domain.as_bytes());
    hash_with_length(&mut hasher, event.key_id.as_bytes());
    hash_with_length(&mut hasher, event.action.label().as_bytes());
    hash_with_length(&mut hasher, &event.public_key);
    hasher.update(event.timestamp.to_be_bytes());
    if let Some(note) = &event.note {
        hash_with_length(&mut hasher, note.as_bytes());
    } else {
        hash_with_length(&mut hasher, &[]);
    }
    if let Some(witness) = &event.witness {
        hash_with_length(&mut hasher, witness);
    } else {
        hash_with_length(&mut hasher, &[]);
    }
    hasher.finalize().into()
}

fn hash_record(
    domain: &str,
    sequence: u64,
    timestamp: u64,
    previous: [u8; 32],
    event_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"Aunsorm/1.01/key-transparency/record");
    hash_with_length(&mut hasher, domain.as_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(previous);
    hasher.update(event_hash);
    hasher.finalize().into()
}

/// Şeffaflık defteri.
#[derive(Debug)]
pub struct KeyTransparencyLog {
    domain: String,
    records: Vec<TransparencyRecord>,
    head: [u8; 32],
    last_timestamp: u64,
}

impl KeyTransparencyLog {
    /// Yeni defter oluşturur.
    #[must_use]
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            records: Vec::new(),
            head: [0_u8; 32],
            last_timestamp: 0,
        }
    }

    /// Deftere kayıt ekler.
    ///
    /// # Errors
    /// Zaman damgası geriye gidiyorsa `TransparencyError::TimestampRegression` döner.
    pub fn append(
        &mut self,
        event: TransparencyEvent,
    ) -> Result<TransparencyRecord, TransparencyError> {
        if event.timestamp < self.last_timestamp {
            return Err(TransparencyError::TimestampRegression {
                sequence: TransparencyRecord::latest_sequence(&self.records),
            });
        }
        let sequence =
            u64::try_from(self.records.len()).map_err(|_| TransparencyError::SequenceOverflow)?;
        let event_hash = hash_event(&self.domain, &event);
        let tree_hash = hash_record(
            &self.domain,
            sequence,
            event.timestamp,
            self.head,
            event_hash,
        );
        let record = TransparencyRecord {
            sequence,
            timestamp: event.timestamp,
            event,
            event_hash,
            previous_hash: self.head,
            tree_hash,
        };
        self.last_timestamp = record.timestamp;
        self.head = record.tree_hash;
        self.records.push(record.clone());
        Ok(record)
    }

    /// Tüm kayıtları döndürür.
    #[must_use]
    pub fn records(&self) -> &[TransparencyRecord] {
        &self.records
    }

    /// Güncel ağaç başını döndürür.
    #[must_use]
    pub const fn tree_head(&self) -> [u8; 32] {
        self.head
    }

    /// Log alanı.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// En son kaydı temsil eden kontrol noktasını döndürür.
    #[must_use]
    pub fn checkpoint(&self) -> Option<TransparencyCheckpoint> {
        self.records.last().map(|record| {
            TransparencyCheckpoint::new(record.sequence, record.timestamp, record.tree_hash)
        })
    }

    /// Zincirin bütünlüğünü doğrular.
    ///
    /// # Errors
    /// Alan uyuşmazsa veya zincir bozulmuşsa `TransparencyError` döner.
    pub fn verify_chain(
        domain: &str,
        records: &[TransparencyRecord],
    ) -> Result<(), TransparencyError> {
        let mut head = [0_u8; 32];
        let mut last_timestamp = 0_u64;
        for record in records {
            if record.timestamp < last_timestamp {
                return Err(TransparencyError::TimestampRegression {
                    sequence: record.sequence,
                });
            }
            let event_hash = hash_event(domain, &record.event);
            if event_hash != record.event_hash {
                return Err(TransparencyError::ChainBroken(record.sequence));
            }
            let tree_hash = hash_record(
                domain,
                record.sequence,
                record.timestamp,
                head,
                record.event_hash,
            );
            if tree_hash != record.tree_hash {
                return Err(TransparencyError::ChainBroken(record.sequence));
            }
            if record.previous_hash != head {
                return Err(TransparencyError::ChainBroken(record.sequence));
            }
            head = record.tree_hash;
            last_timestamp = record.timestamp;
        }
        Ok(())
    }

    /// Kayıt dizisi için transkript karması üretir.
    ///
    /// Fonksiyon önce zincirin bütünlüğünü `verify_chain` ile doğrular. Alan adı
    /// uyuşmazlığı veya kayıtların bozulması durumunda hata döner.
    ///
    /// # Errors
    /// Alan adı uyuşmazsa veya zincirde tahrifat tespit edilirse
    /// `TransparencyError` döndürülür.
    pub fn transcript_hash(
        domain: &str,
        records: &[TransparencyRecord],
    ) -> Result<[u8; 32], TransparencyError> {
        if records.is_empty() {
            return Ok([0_u8; 32]);
        }
        Self::verify_chain(domain, records)?;
        let mut hasher = Sha256::new();
        hasher.update(b"Aunsorm/1.01/key-transparency/transcript");
        hash_with_length(&mut hasher, domain.as_bytes());
        for record in records {
            hasher.update(record.sequence.to_be_bytes());
            hasher.update(record.timestamp.to_be_bytes());
            hash_with_length(&mut hasher, &record.tree_hash);
        }
        Ok(hasher.finalize().into())
    }

    /// Kayıt dizisinden kontrol noktası üretir.
    ///
    /// # Errors
    /// Alan adı uyuşmazlığı veya zincirde bozulma tespit edilirse hata döner.
    pub fn checkpoint_from_records(
        domain: &str,
        records: &[TransparencyRecord],
    ) -> Result<Option<TransparencyCheckpoint>, TransparencyError> {
        if records.is_empty() {
            return Ok(None);
        }
        Self::verify_chain(domain, records)?;
        Ok(records.last().map(|record| {
            TransparencyCheckpoint::new(record.sequence, record.timestamp, record.tree_hash)
        }))
    }
}

/// UNIX zaman damgasını saniye cinsinden döndürür.
///
/// # Errors
/// Zaman UNIX başlangıcından öncesine işaret ediyorsa `TransparencyError::TimestampUnderflow` döner.
pub fn unix_timestamp(time: SystemTime) -> Result<u64, TransparencyError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TransparencyError::TimestampUnderflow)?;
    Ok(duration.as_secs())
}

impl fmt::Display for TransparencyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{} {} {}",
            self.sequence,
            self.event.action.label(),
            self.event.key_id
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{
        unix_timestamp, KeyTransparencyLog, TransparencyCheckpoint, TransparencyError,
        TransparencyEvent, TransparencyEventKind,
    };

    #[test]
    fn transcript_hash_is_deterministic() {
        let mut log = KeyTransparencyLog::new("aunsorm-demo");
        let record1 = log
            .append(TransparencyEvent::publish(
                "key-1",
                [1_u8, 2, 3, 4],
                1,
                Some("first".to_string()),
            ))
            .expect("record");
        let record2 = log
            .append(TransparencyEvent::publish(
                "key-2",
                [5_u8, 6, 7, 8],
                2,
                Some("second".to_string()),
            ))
            .expect("record");
        let log_entries = vec![record1, record2];
        let hash_a = KeyTransparencyLog::transcript_hash("aunsorm-demo", &log_entries).unwrap();
        let hash_b = KeyTransparencyLog::transcript_hash("aunsorm-demo", &log_entries).unwrap();
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn transcript_hash_detects_tampering() {
        let mut log = KeyTransparencyLog::new("aunsorm-demo");
        log.append(TransparencyEvent::publish(
            "key-1",
            [1_u8, 2, 3, 4],
            1,
            None,
        ))
        .expect("record");
        let mut records = log.records().to_vec();
        records[0].timestamp += 1;
        let result = KeyTransparencyLog::transcript_hash("aunsorm-demo", &records);
        assert!(result.is_err());
    }

    #[test]
    fn revoke_event_has_expected_shape() {
        let event = TransparencyEvent::revoke("key-1", 5, Some("suspected".into()));
        assert_eq!(event.action, TransparencyEventKind::Revoke);
        assert!(event.public_key.is_empty());
        assert_eq!(event.timestamp, 5);
        assert_eq!(event.note.as_deref(), Some("suspected"));
    }

    #[test]
    fn rotate_event_preserves_public_key() {
        let event = TransparencyEvent::rotate("key-2", [0xAA_u8; 16], 9, None);
        assert_eq!(event.action, TransparencyEventKind::Rotate);
        assert_eq!(event.public_key, vec![0xAA; 16]);
        assert_eq!(event.timestamp, 9);
        assert!(event.note.is_none());
    }

    #[test]
    fn checkpoint_matches_latest_record() {
        let mut log = KeyTransparencyLog::new("aunsorm-demo");
        assert!(log.checkpoint().is_none());
        let record = log
            .append(TransparencyEvent::publish(
                "key-1",
                [0x01_u8; 4],
                10,
                Some("initial".into()),
            ))
            .expect("record");
        let checkpoint = log.checkpoint().expect("checkpoint");
        assert_eq!(
            checkpoint,
            TransparencyCheckpoint::new(record.sequence, record.timestamp, record.tree_hash)
        );
        assert_eq!(checkpoint.tree_hash, log.tree_head());
    }

    #[test]
    fn witness_roundtrip_and_chain_integrity() {
        let mut log = KeyTransparencyLog::new("aunsorm-demo");
        let record = log
            .append(
                TransparencyEvent::publish("key-1", [0x11_u8; 4], 3, None)
                    .with_witness(Some(vec![0xAA, 0xBB, 0xCC])),
            )
            .expect("record");

        let records = vec![record];
        assert_eq!(
            records[0].event.witness.as_deref().expect("witness"),
            &[0xAA, 0xBB, 0xCC]
        );
        KeyTransparencyLog::verify_chain("aunsorm-demo", &records).expect("valid chain");

        let mut tampered = records;
        tampered[0].event.witness = Some(vec![0xAA, 0xCC, 0xBB]);
        let result = KeyTransparencyLog::verify_chain("aunsorm-demo", &tampered);
        assert!(matches!(result, Err(TransparencyError::ChainBroken(0))));
    }

    #[test]
    fn checkpoint_from_records_validates_chain() {
        let mut log = KeyTransparencyLog::new("aunsorm-demo");
        log.append(TransparencyEvent::publish("key-1", [0xAA_u8; 8], 1, None))
            .expect("record");
        log.append(TransparencyEvent::rotate("key-1", [0xBB_u8; 8], 2, None))
            .expect("record");

        let records = log.records().to_vec();
        let checkpoint = KeyTransparencyLog::checkpoint_from_records("aunsorm-demo", &records)
            .expect("checkpoint")
            .expect("non-empty");
        assert_eq!(checkpoint.tree_hash, log.tree_head());
        let last_sequence = records.last().map(|record| record.sequence).unwrap();
        assert_eq!(checkpoint.sequence, last_sequence);

        let mut tampered = records;
        tampered[1].tree_hash[0] ^= 0xFF;
        let result = KeyTransparencyLog::checkpoint_from_records("aunsorm-demo", &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn transcript_hash_empty_returns_zero() {
        let hash = KeyTransparencyLog::transcript_hash("aunsorm-demo", &[])
            .expect("empty transcript succeeds");
        assert_eq!(hash, [0_u8; 32]);
    }

    #[test]
    fn unix_timestamp_handles_epoch_boundaries() {
        let epoch_plus = SystemTime::UNIX_EPOCH + Duration::from_secs(42);
        let epoch_minus = SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("pre-epoch time");

        let ts = unix_timestamp(epoch_plus).expect("epoch forward");
        assert_eq!(ts, 42);

        let err = unix_timestamp(epoch_minus).expect_err("pre-epoch should fail");
        assert!(matches!(err, TransparencyError::TimestampUnderflow));
    }
}
