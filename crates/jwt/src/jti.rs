use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{JwtError, Result};

/// JTI store arayüzü.
pub trait JtiStore: Send + Sync {
    /// `jti` değerini ekler, daha önce varsa `false` döner.
    ///
    /// # Errors
    ///
    /// Kilit zehirlenirse veya süre hesaplaması başarısız olursa `JwtError` döner.
    fn check_and_insert(&self, jti: &str, expires_at: Option<SystemTime>) -> Result<bool>;
    /// Süresi dolan kayıtları temizler ve silinen kayıt sayısını döner.
    ///
    /// # Errors
    ///
    /// Kilit zehirlenirse veya süre hesaplaması başarısız olursa `JwtError` döner.
    fn purge_expired(&self, now: SystemTime) -> Result<usize>;
}

/// Bellek içi JTI store.
#[derive(Debug, Default)]
pub struct InMemoryJtiStore {
    inner: Mutex<HashMap<String, Option<SystemTime>>>,
}

impl InMemoryJtiStore {
    fn cleanup_locked(map: &mut HashMap<String, Option<SystemTime>>, now: SystemTime) {
        map.retain(|_, expires| expires.map_or(true, |exp| exp > now));
    }
}

impl JtiStore for InMemoryJtiStore {
    fn check_and_insert(&self, jti: &str, expires_at: Option<SystemTime>) -> Result<bool> {
        let now = SystemTime::now();
        {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| JwtError::JtiStore("lock poisoned"))?;
            Self::cleanup_locked(&mut guard, now);
            if guard.contains_key(jti) {
                return Ok(false);
            }
            guard.insert(jti.to_owned(), expires_at);
        }
        Ok(true)
    }

    fn purge_expired(&self, now: SystemTime) -> Result<usize> {
        let removed = {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| JwtError::JtiStore("lock poisoned"))?;
            let before = guard.len();
            Self::cleanup_locked(&mut guard, now);
            before - guard.len()
        };
        Ok(removed)
    }
}

/// `SQLite` tabanlı JTI store.
#[cfg(feature = "sqlite")]
pub struct SqliteJtiStore {
    conn: Mutex<rusqlite::Connection>,
}

#[cfg(feature = "sqlite")]
impl SqliteJtiStore {
    /// Yeni bir `SQLite` store oluşturur.
    ///
    /// # Errors
    ///
    /// Veritabanı bağlantısı açılamazsa veya şema oluşturulamazsa `JwtError` döner.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        use rusqlite::{Connection, OpenFlags};

        let path_buf = path.as_ref().to_path_buf();
        if let Some(parent) = path_buf.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let conn = Connection::open_with_flags(
            &path_buf,
            OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS jti (
                jti TEXT PRIMARY KEY,
                expires_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_jti_expires ON jti(expires_at);",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn delete_expired(conn: &rusqlite::Connection, now: i64) -> Result<usize> {
        Ok(conn.execute(
            "DELETE FROM jti WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            [now],
        )?)
    }
}

#[cfg(feature = "sqlite")]
impl JtiStore for SqliteJtiStore {
    fn check_and_insert(&self, jti: &str, expires_at: Option<SystemTime>) -> Result<bool> {
        use rusqlite::params;

        let inserted = {
            let conn = self
                .conn
                .lock()
                .map_err(|_| JwtError::JtiStore("lock poisoned"))?;
            let now = unix_seconds(SystemTime::now())?;
            let _ = Self::delete_expired(&conn, now)?;
            let expiry = expires_at.map(unix_seconds).transpose()?;
            conn.execute(
                "INSERT OR IGNORE INTO jti(jti, expires_at) VALUES (?1, ?2)",
                params![jti, expiry],
            )?
        };
        Ok(inserted > 0)
    }

    fn purge_expired(&self, now: SystemTime) -> Result<usize> {
        let removed = {
            let conn = self
                .conn
                .lock()
                .map_err(|_| JwtError::JtiStore("lock poisoned"))?;
            let now = unix_seconds(now)?;
            Self::delete_expired(&conn, now)?
        };
        Ok(removed)
    }
}

fn unix_seconds(time: SystemTime) -> Result<i64> {
    time.duration_since(UNIX_EPOCH)
        .map_err(|_| JwtError::TimeConversion)
        .and_then(|dur| i64::try_from(dur.as_secs()).map_err(|_| JwtError::TimeConversion))
}
