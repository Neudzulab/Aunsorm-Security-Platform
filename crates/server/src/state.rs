use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_jwt::{Jwks, JwtSigner, JwtVerifier};
use rand_core::{OsRng, RngCore};
use tokio::sync::Mutex;

use crate::config::{LedgerBackend, ServerConfig};
use crate::error::ServerError;

const AUTH_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub subject: String,
    pub client_id: String,
    pub code_challenge: String,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

#[derive(Debug, Default)]
struct AuthStore {
    entries: Mutex<HashMap<String, AuthRequest>>,
}

impl AuthStore {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    async fn insert(&self, request: AuthRequest) -> String {
        let mut guard = self.entries.lock().await;
        Self::purge_locked(&mut guard, SystemTime::now());
        let id = generate_id();
        guard.insert(id.clone(), request);
        id
    }

    async fn take(&self, id: &str) -> Option<AuthRequest> {
        let mut guard = self.entries.lock().await;
        Self::purge_locked(&mut guard, SystemTime::now());
        guard.remove(id)
    }

    async fn len(&self, now: SystemTime) -> usize {
        let mut guard = self.entries.lock().await;
        Self::purge_locked(&mut guard, now);
        guard.len()
    }

    fn purge_locked(map: &mut HashMap<String, AuthRequest>, now: SystemTime) {
        map.retain(|_, value| value.expires_at > now);
    }
}

fn generate_id() -> String {
    let mut buf = [0_u8; 16];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub struct TokenLedger {
    inner: TokenLedgerInner,
}

enum TokenLedgerInner {
    Memory {
        entries: Mutex<HashMap<String, SystemTime>>,
    },
    Sqlite {
        conn: Arc<StdMutex<rusqlite::Connection>>,
    },
}

impl TokenLedger {
    pub fn new(backend: LedgerBackend) -> Result<Self, ServerError> {
        match backend {
            LedgerBackend::Memory => Ok(Self {
                inner: TokenLedgerInner::Memory {
                    entries: Mutex::new(HashMap::new()),
                },
            }),
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
                    "CREATE TABLE IF NOT EXISTS tokens (
                        jti TEXT PRIMARY KEY,
                        expires_at INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at);",
                )?;
                Ok(Self {
                    inner: TokenLedgerInner::Sqlite {
                        conn: Arc::new(StdMutex::new(conn)),
                    },
                })
            }
        }
    }

    pub async fn insert(&self, jti: &str, expires_at: SystemTime) -> Result<(), ServerError> {
        match &self.inner {
            TokenLedgerInner::Memory { entries } => {
                {
                    let mut guard = entries.lock().await;
                    purge_map(&mut guard, SystemTime::now());
                    guard.insert(jti.to_owned(), expires_at);
                }
                Ok(())
            }
            TokenLedgerInner::Sqlite { conn } => {
                let conn = Arc::clone(conn);
                let jti = jti.to_owned();
                let expires = unix_seconds(expires_at)?;
                tokio::task::spawn_blocking(move || -> Result<(), ServerError> {
                    {
                        let conn_guard = conn.lock().map_err(|_| {
                            ServerError::Configuration("SQLite lock poisoned".to_string())
                        })?;
                        conn_guard.execute(
                            "INSERT OR REPLACE INTO tokens(jti, expires_at) VALUES (?1, ?2)",
                            (jti, expires),
                        )?;
                    }
                    Ok(())
                })
                .await
                .map_err(|err| {
                    ServerError::Configuration(format!("SQLite task failed: {err}"))
                })??;
                Ok(())
            }
        }
    }

    pub async fn is_active(&self, jti: &str, now: SystemTime) -> Result<bool, ServerError> {
        match &self.inner {
            TokenLedgerInner::Memory { entries } => {
                let mut guard = entries.lock().await;
                purge_map(&mut guard, now);
                Ok(guard.contains_key(jti))
            }
            TokenLedgerInner::Sqlite { conn } => {
                let conn = Arc::clone(conn);
                let jti = jti.to_owned();
                let now_val = unix_seconds(now)?;
                let exists = tokio::task::spawn_blocking(move || -> Result<bool, ServerError> {
                    {
                        let conn_guard = conn.lock().map_err(|_| {
                            ServerError::Configuration("SQLite lock poisoned".to_string())
                        })?;
                        conn_guard
                            .execute("DELETE FROM tokens WHERE expires_at <= ?1", [now_val])?;
                    }
                    let exists = {
                        let conn_guard = conn.lock().map_err(|_| {
                            ServerError::Configuration("SQLite lock poisoned".to_string())
                        })?;
                        let mut stmt =
                            conn_guard.prepare("SELECT 1 FROM tokens WHERE jti = ?1 LIMIT 1")?;
                        let mut rows = stmt.query([jti])?;
                        let result = rows.next()?.is_some();
                        drop(rows);
                        drop(stmt);
                        drop(conn_guard);
                        result
                    };
                    Ok(exists)
                })
                .await
                .map_err(|err| {
                    ServerError::Configuration(format!("SQLite task failed: {err}"))
                })??;
                Ok(exists)
            }
        }
    }

    pub async fn purge(&self, now: SystemTime) -> Result<usize, ServerError> {
        match &self.inner {
            TokenLedgerInner::Memory { entries } => {
                let mut guard = entries.lock().await;
                let before = guard.len();
                purge_map(&mut guard, now);
                Ok(before - guard.len())
            }
            TokenLedgerInner::Sqlite { conn } => {
                let conn = Arc::clone(conn);
                let now_val = unix_seconds(now)?;
                let removed = tokio::task::spawn_blocking(move || -> Result<usize, ServerError> {
                    let removed = {
                        let conn_guard = conn.lock().map_err(|_| {
                            ServerError::Configuration("SQLite lock poisoned".to_string())
                        })?;
                        conn_guard
                            .execute("DELETE FROM tokens WHERE expires_at <= ?1", [now_val])?
                    };
                    Ok(removed)
                })
                .await
                .map_err(|err| {
                    ServerError::Configuration(format!("SQLite task failed: {err}"))
                })??;
                Ok(removed)
            }
        }
    }

    pub async fn count_active(&self, now: SystemTime) -> Result<usize, ServerError> {
        match &self.inner {
            TokenLedgerInner::Memory { entries } => {
                let mut guard = entries.lock().await;
                purge_map(&mut guard, now);
                Ok(guard.len())
            }
            TokenLedgerInner::Sqlite { conn } => {
                let conn = Arc::clone(conn);
                let now_val = unix_seconds(now)?;
                let count = tokio::task::spawn_blocking(move || -> Result<usize, ServerError> {
                    let count = {
                        let conn_guard = conn.lock().map_err(|_| {
                            ServerError::Configuration("SQLite lock poisoned".to_string())
                        })?;
                        let mut stmt = conn_guard
                            .prepare("SELECT COUNT(*) FROM tokens WHERE expires_at > ?1")?;
                        let result = stmt.query_row([now_val], |row| row.get(0))?;
                        drop(stmt);
                        drop(conn_guard);
                        result
                    };
                    Ok(count)
                })
                .await
                .map_err(|err| {
                    ServerError::Configuration(format!("SQLite task failed: {err}"))
                })??;
                Ok(count)
            }
        }
    }
}

fn purge_map(map: &mut HashMap<String, SystemTime>, now: SystemTime) {
    map.retain(|_, expires| *expires > now);
}

fn unix_seconds(time: SystemTime) -> Result<i64, ServerError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ServerError::Configuration("timestamp before epoch".to_string()))?;
    i64::try_from(duration.as_secs())
        .map_err(|_| ServerError::Configuration("timestamp overflow".to_string()))
}

pub struct ServerState {
    issuer: String,
    audience: String,
    token_ttl: Duration,
    strict: bool,
    signer: JwtSigner,
    verifier: JwtVerifier,
    jwks: Jwks,
    auth_store: AuthStore,
    ledger: TokenLedger,
}

impl ServerState {
    /// Yapılandırmadan sunucu durumunu üretir.
    ///
    /// # Errors
    ///
    /// JTI defteri başlatılırken hata oluşursa `ServerError` döner.
    pub fn try_new(config: ServerConfig) -> Result<Self, ServerError> {
        let ServerConfig {
            listen: _,
            issuer,
            audience,
            token_ttl,
            strict,
            key_pair,
            ledger,
        } = config;
        let signer = JwtSigner::new(key_pair.clone());
        let public = key_pair.public_key();
        let verifier = JwtVerifier::new(vec![public.clone()]);
        let jwks = Jwks {
            keys: vec![public.to_jwk()],
        };
        let ledger = TokenLedger::new(ledger)?;
        Ok(Self {
            issuer,
            audience,
            token_ttl,
            strict,
            signer,
            verifier,
            jwks,
            auth_store: AuthStore::new(),
            ledger,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub const fn token_ttl(&self) -> Duration {
        self.token_ttl
    }

    pub const fn signer(&self) -> &JwtSigner {
        &self.signer
    }

    pub const fn verifier(&self) -> &JwtVerifier {
        &self.verifier
    }

    pub const fn jwks(&self) -> &Jwks {
        &self.jwks
    }

    pub const fn strict(&self) -> bool {
        self.strict
    }

    pub async fn register_auth_request(
        &self,
        subject: String,
        client_id: String,
        code_challenge: String,
    ) -> String {
        let now = SystemTime::now();
        let request = AuthRequest {
            subject,
            client_id,
            code_challenge,
            created_at: now,
            expires_at: now + AUTH_TTL,
        };
        self.auth_store.insert(request).await
    }

    pub async fn consume_auth_request(&self, id: &str) -> Option<AuthRequest> {
        self.auth_store.take(id).await
    }

    pub async fn auth_request_count(&self) -> usize {
        self.auth_store.len(SystemTime::now()).await
    }

    /// Aktif belirteç defterine bir kayıt ekler.
    ///
    /// # Errors
    ///
    /// `SQLite` işlemi veya bellek kilidi başarısız olursa `ServerError` döner.
    pub async fn record_token(&self, jti: &str, expires_at: SystemTime) -> Result<(), ServerError> {
        self.ledger.insert(jti, expires_at).await
    }

    /// Belirtilen `jti` değerinin aktif olup olmadığını döndürür.
    ///
    /// # Errors
    ///
    /// Depo sorgusu sırasında hata oluşursa `ServerError` döner.
    pub async fn is_token_active(&self, jti: &str, now: SystemTime) -> Result<bool, ServerError> {
        self.ledger.is_active(jti, now).await
    }

    /// Süresi geçmiş token kayıtlarını temizler.
    ///
    /// # Errors
    ///
    /// Depo temizliği sırasında hata oluşursa `ServerError` döner.
    pub async fn purge_tokens(&self, now: SystemTime) -> Result<usize, ServerError> {
        self.ledger.purge(now).await
    }

    /// Aktif token sayısını döndürür.
    ///
    /// # Errors
    ///
    /// Depo sorgusu başarısız olursa `ServerError` döner.
    pub async fn active_token_count(&self, now: SystemTime) -> Result<usize, ServerError> {
        self.ledger.count_active(now).await
    }
}

pub const fn auth_ttl() -> Duration {
    AUTH_TTL
}
