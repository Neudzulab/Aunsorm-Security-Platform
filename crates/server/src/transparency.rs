#![allow(clippy::module_name_repetitions)]

use std::borrow::ToOwned;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use aunsorm_jwt::Jwk;

use crate::config::LedgerBackend;
use crate::error::ServerError;

const HASH_SIZE: usize = 32;

/// Şeffaflık günlüğünde saklanan olay türleri.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransparencyEvent {
    /// Sunucunun yayınladığı bir JWK anahtarını temsil eder.
    KeyPublished { jwk: Jwk },
    /// JWT üretiminde kullanılan meta verileri taşır.
    TokenIssued {
        jti: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        subject_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        audience: Option<String>,
        expires_at: u64,
    },
    /// Medya kayıtlarının blokzincir çapası ve kalibrasyon izini bildirir.
    ///
    /// * `calibration_id` alanı, ilgili JWE üretimi sırasında yayımlanan
    ///   kalibrasyon parmak iziyle birebir eşleşmelidir. Böylece zincire
    ///   aktarılan medya kanıtı ile istemcilere dağıtılan şifreli oturum
    ///   materyali arasında denetlenebilir bir bağ sağlanır.
    /// * `blockchain_tx_hash` alanı, blokzincirdeki kesin işlem hash'ini
    ///   taşır ve `blockchain_height` ile birlikte doğrulama sırasında
    ///   yeniden sorgulanması beklenir.
    /// * `media_commitment_sha256` değeri, medya içeriğinin kalıcı olarak
    ///   saklanmayan haline ait SHA-256 taahhüdüdür; denetim sırasında eşleşme
    ///   zorunludur.
    MediaRecord {
        calibration_id: String,
        media_commitment_sha256: String,
        blockchain_tx_hash: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        blockchain_height: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        media_profile: Option<String>,
    },
}

impl TransparencyEvent {
    #[must_use]
    pub const fn key_published(jwk: Jwk) -> Self {
        Self::KeyPublished { jwk }
    }
}

/// Şeffaflık günlüğündeki tekil kayıt.
#[derive(Debug, Clone, Serialize)]
pub struct TransparencyLogEntry {
    pub index: u64,
    pub timestamp: u64,
    pub event: TransparencyEvent,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
}

/// Şeffaflık günlük anlık görüntüsü.
#[derive(Debug, Clone, Serialize)]
pub struct TransparencySnapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_hash: Option<String>,
    pub entries: Vec<TransparencyLogEntry>,
}

#[derive(Debug, Clone)]
struct InternalEntry {
    index: u64,
    timestamp: u64,
    event: TransparencyEvent,
    hash: [u8; HASH_SIZE],
}

impl InternalEntry {
    fn new(
        index: u64,
        timestamp: u64,
        event: TransparencyEvent,
        previous: Option<&[u8; HASH_SIZE]>,
    ) -> Result<Self, ServerError> {
        let payload = serde_json::to_vec(&event).map_err(|err| {
            ServerError::Configuration(format!("şeffaflık olayı serileştirilemedi: {err}"))
        })?;
        let hash = compute_hash(previous, index, timestamp, &payload);
        Ok(Self {
            index,
            timestamp,
            event,
            hash,
        })
    }

    fn to_public(&self, previous: Option<&[u8; HASH_SIZE]>) -> TransparencyLogEntry {
        TransparencyLogEntry {
            index: self.index,
            timestamp: self.timestamp,
            event: self.event.clone(),
            hash: encode_hash(&self.hash),
            previous_hash: previous.map(encode_hash),
        }
    }
}

#[derive(Debug)]
enum TransparencyLedgerInner {
    Memory {
        entries: Mutex<Vec<InternalEntry>>,
    },
    Sqlite {
        conn: Arc<StdMutex<rusqlite::Connection>>,
    },
}

/// Şeffaflık günlüğü depolaması.
#[derive(Debug)]
pub struct TransparencyLedger {
    inner: TransparencyLedgerInner,
}

impl TransparencyLedger {
    /// Yeni bir günlük oluşturur ve verilen başlangıç olaylarını kaydeder.
    pub fn new(
        backend: LedgerBackend,
        initial_events: Vec<TransparencyEvent>,
    ) -> Result<Self, ServerError> {
        match backend {
            LedgerBackend::Memory => {
                let mut entries = Vec::with_capacity(initial_events.len());
                let mut previous: Option<[u8; HASH_SIZE]> = None;
                for (offset, event) in initial_events.into_iter().enumerate() {
                    let index = u64::try_from(offset).map_err(|err| {
                        ServerError::Configuration(format!("günlük indeks dönüştürülemedi: {err}"))
                    })? + 1;
                    let timestamp = unix_seconds(SystemTime::now())?;
                    let entry = InternalEntry::new(index, timestamp, event, previous.as_ref())?;
                    previous = Some(entry.hash);
                    entries.push(entry);
                }
                Ok(Self {
                    inner: TransparencyLedgerInner::Memory {
                        entries: Mutex::new(entries),
                    },
                })
            }
            LedgerBackend::Sqlite(path) => {
                use rusqlite::{Connection, OpenFlags};

                let conn = Connection::open_with_flags(
                    path,
                    OpenFlags::SQLITE_OPEN_CREATE
                        | OpenFlags::SQLITE_OPEN_READ_WRITE
                        | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
                )?;
                conn.pragma_update(None, "journal_mode", "WAL")?;
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS transparency_events (
                        idx INTEGER PRIMARY KEY,
                        event_ts INTEGER NOT NULL,
                        event_json TEXT NOT NULL,
                        hash BLOB NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_transparency_ts ON transparency_events(event_ts);",
                )?;

                let existing: i64 =
                    conn.query_row("SELECT COUNT(*) FROM transparency_events", [], |row| {
                        row.get(0)
                    })?;
                if existing == 0 {
                    let mut previous: Option<[u8; HASH_SIZE]> = None;
                    for (offset, event) in initial_events.into_iter().enumerate() {
                        let index = u64::try_from(offset).map_err(|err| {
                            ServerError::Configuration(format!(
                                "günlük indeks dönüştürülemedi: {err}"
                            ))
                        })? + 1;
                        let timestamp = unix_seconds(SystemTime::now())?;
                        let payload = serde_json::to_string(&event).map_err(|err| {
                            ServerError::Configuration(format!(
                                "şeffaflık olayı serileştirilemedi: {err}"
                            ))
                        })?;
                        let hash =
                            compute_hash(previous.as_ref(), index, timestamp, payload.as_bytes());
                        conn.execute(
                            "INSERT INTO transparency_events(idx, event_ts, event_json, hash)
                             VALUES (?1, ?2, ?3, ?4)",
                            (
                                i64::try_from(index).map_err(|err| {
                                    ServerError::Configuration(format!(
                                        "günlük indeks sınırı aşıldı: {err}"
                                    ))
                                })?,
                                i64::try_from(timestamp).map_err(|err| {
                                    ServerError::Configuration(format!(
                                        "zaman damgası sınırı aşıldı: {err}"
                                    ))
                                })?,
                                payload,
                                hash.to_vec(),
                            ),
                        )?;
                        previous = Some(hash);
                    }
                }

                Ok(Self {
                    inner: TransparencyLedgerInner::Sqlite {
                        conn: Arc::new(StdMutex::new(conn)),
                    },
                })
            }
        }
    }

    /// JWT üretiminde kullanılan meta verileri kaydeder.
    pub async fn record_token(
        &self,
        jti: &str,
        subject: Option<&str>,
        audience: Option<&str>,
        expires_at: SystemTime,
    ) -> Result<(), ServerError> {
        let subject_hash = subject.map(hash_subject);
        let event = TransparencyEvent::TokenIssued {
            jti: jti.to_owned(),
            subject_hash,
            audience: audience.map(ToOwned::to_owned),
            expires_at: unix_seconds(expires_at)?,
        };
        self.append_event(event).await
    }

    /// Günlüğün anlık görüntüsünü döndürür.
    pub async fn snapshot(&self) -> Result<TransparencySnapshot, ServerError> {
        match &self.inner {
            TransparencyLedgerInner::Memory { entries } => {
                let guard = entries.lock().await;
                Ok(snapshot_from_entries(&guard))
            }
            TransparencyLedgerInner::Sqlite { conn } => {
                let conn = Arc::clone(conn);
                let entries = tokio::task::spawn_blocking(move || -> Result<Vec<InternalEntry>, ServerError> {
                    let conn_guard = conn.lock().map_err(|_| {
                        ServerError::Configuration("SQLite lock poisoned".to_string())
                    })?;
                    let mut stmt = conn_guard.prepare(
                        "SELECT idx, event_ts, event_json, hash FROM transparency_events ORDER BY idx ASC",
                    )?;
                    let mut rows = stmt.query([])?;
                    let mut entries = Vec::new();
                    while let Some(row) = rows.next()? {
                        let idx: i64 = row.get(0)?;
                        let ts: i64 = row.get(1)?;
                        let payload: String = row.get(2)?;
                        let hash_blob: Vec<u8> = row.get(3)?;
                        if hash_blob.len() != HASH_SIZE {
                            return Err(ServerError::Configuration(
                                "geçersiz hash uzunluğu".to_string(),
                            ));
                        }
                        let event: TransparencyEvent = serde_json::from_str(&payload).map_err(|err| {
                            ServerError::Configuration(format!(
                                "şeffaflık olayı parse edilemedi: {err}"
                            ))
                        })?;
                        let mut hash = [0_u8; HASH_SIZE];
                        hash.copy_from_slice(&hash_blob);
                        entries.push(InternalEntry {
                            index: u64::try_from(idx).map_err(|err| {
                                ServerError::Configuration(format!(
                                    "günlük indeks sınırı aşıldı: {err}"
                                ))
                            })?,
                            timestamp: u64::try_from(ts).map_err(|err| {
                                ServerError::Configuration(format!(
                                    "zaman damgası sınırı aşıldı: {err}"
                                ))
                            })?,
                            event,
                            hash,
                        });
                    }
                    drop(rows);
                    drop(stmt);
                    drop(conn_guard);
                    Ok(entries)
                })
                .await
                .map_err(|err| {
                    ServerError::Configuration(format!(
                        "SQLite görevi tamamlanamadı: {err}"
                    ))
                })??;

                Ok(snapshot_from_entries(&entries))
            }
        }
    }

    async fn append_event(&self, event: TransparencyEvent) -> Result<(), ServerError> {
        match &self.inner {
            TransparencyLedgerInner::Memory { entries } => {
                let mut guard = entries.lock().await;
                let (index, prev_hash) = guard
                    .last()
                    .map_or((1, None), |entry| (entry.index + 1, Some(entry.hash)));
                let timestamp = unix_seconds(SystemTime::now())?;
                let entry = InternalEntry::new(index, timestamp, event, prev_hash.as_ref())?;
                guard.push(entry);
                drop(guard);
                Ok(())
            }
            TransparencyLedgerInner::Sqlite { conn } => {
                let conn = Arc::clone(conn);
                tokio::task::spawn_blocking(move || -> Result<(), ServerError> {
                    let timestamp = unix_seconds(SystemTime::now())?;
                    let payload = serde_json::to_string(&event).map_err(|err| {
                        ServerError::Configuration(format!(
                            "şeffaflık olayı serileştirilemedi: {err}"
                        ))
                    })?;
                    let (prev_hash, last_index) = {
                        let conn_guard = conn.lock().map_err(|_| {
                            ServerError::Configuration("SQLite lock poisoned".to_string())
                        })?;
                        let mut stmt = conn_guard.prepare(
                            "SELECT idx, hash FROM transparency_events ORDER BY idx DESC LIMIT 1",
                        )?;
                        let mut rows = stmt.query([])?;
                        let result: Result<(Option<[u8; HASH_SIZE]>, u64), ServerError> =
                            if let Some(row) = rows.next()? {
                                let idx: i64 = row.get(0)?;
                                let hash_blob: Vec<u8> = row.get(1)?;
                                if hash_blob.len() != HASH_SIZE {
                                    return Err(ServerError::Configuration(
                                        "geçersiz hash uzunluğu".to_string(),
                                    ));
                                }
                                let mut hash = [0_u8; HASH_SIZE];
                                hash.copy_from_slice(&hash_blob);
                                Ok((
                                    Some(hash),
                                    u64::try_from(idx).map_err(|err| {
                                        ServerError::Configuration(format!(
                                            "günlük indeks sınırı aşıldı: {err}"
                                        ))
                                    })?,
                                ))
                            } else {
                                Ok((None, 0_u64))
                            };
                        drop(rows);
                        drop(stmt);
                        drop(conn_guard);
                        result?
                    };
                    let index = last_index + 1;
                    let hash =
                        compute_hash(prev_hash.as_ref(), index, timestamp, payload.as_bytes());
                    {
                        let conn_guard = conn.lock().map_err(|_| {
                            ServerError::Configuration("SQLite lock poisoned".to_string())
                        })?;
                        conn_guard.execute(
                            "INSERT INTO transparency_events(idx, event_ts, event_json, hash)
                             VALUES (?1, ?2, ?3, ?4)",
                            (
                                i64::try_from(index).map_err(|err| {
                                    ServerError::Configuration(format!(
                                        "günlük indeks sınırı aşıldı: {err}"
                                    ))
                                })?,
                                i64::try_from(timestamp).map_err(|err| {
                                    ServerError::Configuration(format!(
                                        "zaman damgası sınırı aşıldı: {err}"
                                    ))
                                })?,
                                payload,
                                hash.to_vec(),
                            ),
                        )?;
                    }
                    Ok(())
                })
                .await
                .map_err(|err| {
                    ServerError::Configuration(format!("SQLite görevi tamamlanamadı: {err}"))
                })?
            }
        }?;
        Ok(())
    }
}

fn snapshot_from_entries(entries: &[InternalEntry]) -> TransparencySnapshot {
    let mut logs = Vec::with_capacity(entries.len());
    let mut previous: Option<[u8; HASH_SIZE]> = None;
    for entry in entries {
        logs.push(entry.to_public(previous.as_ref()));
        previous = Some(entry.hash);
    }
    let transcript_hash = previous.map(|hash| encode_hash(&hash));
    TransparencySnapshot {
        transcript_hash,
        entries: logs,
    }
}

fn compute_hash(
    previous: Option<&[u8; HASH_SIZE]>,
    index: u64,
    timestamp: u64,
    payload: &[u8],
) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    if let Some(prev) = previous {
        hasher.update(prev);
    }
    hasher.update(index.to_le_bytes());
    hasher.update(timestamp.to_le_bytes());
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut out = [0_u8; HASH_SIZE];
    out.copy_from_slice(&digest);
    out
}

fn encode_hash(hash: &[u8; HASH_SIZE]) -> String {
    URL_SAFE_NO_PAD.encode(hash)
}

fn unix_seconds(time: SystemTime) -> Result<u64, ServerError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ServerError::Configuration("timestamp before epoch".to_string()))?;
    Ok(duration.as_secs())
}

fn hash_subject(subject: &str) -> String {
    let digest = Sha256::digest(subject.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::{compute_hash, encode_hash, hash_subject, TransparencyEvent, TransparencyLedger};
    use crate::config::LedgerBackend;
    use aunsorm_jwt::Jwk;
    use std::time::SystemTime;

    #[test]
    fn subject_hash_consistency() {
        let first = hash_subject("alice");
        let second = hash_subject("alice");
        assert_eq!(first, second);
        assert_ne!(first, hash_subject("bob"));
    }

    #[tokio::test]
    async fn memory_ledger_records_events() {
        let jwk = Jwk {
            kid: "demo".to_string(),
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            x: "test".to_string(),
        };
        let ledger = TransparencyLedger::new(
            LedgerBackend::Memory,
            vec![TransparencyEvent::key_published(jwk.clone())],
        )
        .expect("ledger");
        ledger
            .record_token("abc", Some("alice"), Some("aud"), SystemTime::now())
            .await
            .expect("record token");
        let snapshot = ledger.snapshot().await.expect("snapshot");
        assert_eq!(snapshot.entries.len(), 2);
        assert!(snapshot.transcript_hash.is_some());
    }

    #[test]
    fn hash_depends_on_previous() {
        let payload = br#"{"kind":"token_issued"}"#;
        let h1 = compute_hash(None, 1, 10, payload);
        let h2 = compute_hash(Some(&h1), 2, 11, payload);
        assert_ne!(encode_hash(&h1), encode_hash(&h2));
    }
}
