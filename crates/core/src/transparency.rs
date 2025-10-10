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
    use super::{KeyTransparencyLog, TransparencyEvent};

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
}
