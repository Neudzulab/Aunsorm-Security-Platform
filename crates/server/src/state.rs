use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_core::{
    transparency::{unix_timestamp, KeyTransparencyLog, TransparencyEvent, TransparencyRecord},
    CoreError, SessionRatchet,
};
use aunsorm_jwt::{Jwks, JwtSigner, JwtVerifier};
use rand_core::{OsRng, RngCore};
use tokio::sync::{Mutex, RwLock};

use crate::config::{LedgerBackend, ServerConfig};
use crate::error::ServerError;
use crate::transparency::{TransparencyEvent, TransparencyLedger, TransparencySnapshot};

const AUTH_TTL: Duration = Duration::from_secs(300);
const SFU_CONTEXT_TTL: Duration = Duration::from_secs(900);

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

#[derive(Debug, Clone)]
pub struct SfuStepInfo {
    pub session_id: [u8; 16],
    pub message_no: u64,
    pub message_secret: [u8; 32],
    pub nonce: [u8; 12],
    pub expires_at: SystemTime,
    pub room_id: String,
    pub participant: String,
}

#[derive(Debug, Clone)]
pub struct SfuContextProvision {
    pub context_id: String,
    pub expires_at: SystemTime,
    pub room_id: String,
    pub participant: String,
    pub e2ee: Option<SfuStepInfo>,
}

#[derive(Debug, Clone)]
pub enum SfuStepOutcome {
    NotFound,
    Expired,
    E2eeDisabled,
    Step(SfuStepInfo),
}

#[derive(Debug)]
struct SfuContext {
    room_id: String,
    participant: String,
    expires_at: SystemTime,
    ratchet: Option<Mutex<SessionRatchet>>,
    session_id: Option<[u8; 16]>,
}

impl SfuContext {
    fn new(
        room_id: String,
        participant: String,
        strict: bool,
        enable_e2ee: bool,
        now: SystemTime,
    ) -> Self {
        let expires_at = now + SFU_CONTEXT_TTL;
        if enable_e2ee {
            let mut root = [0_u8; 32];
            OsRng.fill_bytes(&mut root);
            let mut session_id = [0_u8; 16];
            OsRng.fill_bytes(&mut session_id);
            let ratchet = SessionRatchet::new(root, session_id, strict);
            Self {
                room_id,
                participant,
                expires_at,
                ratchet: Some(Mutex::new(ratchet)),
                session_id: Some(session_id),
            }
        } else {
            Self {
                room_id,
                participant,
                expires_at,
                ratchet: None,
                session_id: None,
            }
        }
    }

    fn is_expired(&self, now: SystemTime) -> bool {
        self.expires_at <= now
    }

    const fn has_e2ee(&self) -> bool {
        self.ratchet.is_some()
    }

    async fn produce_step(&self) -> Result<Option<SfuStepInfo>, CoreError> {
        let Some(ratchet) = &self.ratchet else {
            return Ok(None);
        };
        let Some(session_id) = self.session_id else {
            return Ok(None);
        };
        let step = {
            let mut guard = ratchet.lock().await;
            guard.next_step()?
        };
        Ok(Some(SfuStepInfo {
            session_id,
            message_no: step.message_no(),
            message_secret: *step.message_secret(),
            nonce: *step.nonce(),
            expires_at: self.expires_at,
            room_id: self.room_id.clone(),
            participant: self.participant.clone(),
        }))
    }
}

#[derive(Debug, Default)]
struct SfuStore {
    entries: Mutex<HashMap<String, Arc<SfuContext>>>,
}

impl SfuStore {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    async fn create(
        &self,
        room_id: String,
        participant: String,
        strict: bool,
        enable_e2ee: bool,
    ) -> Result<SfuContextProvision, ServerError> {
        let now = SystemTime::now();
        let context = Arc::new(SfuContext::new(
            room_id,
            participant,
            strict,
            enable_e2ee,
            now,
        ));
        let e2ee = context.produce_step().await.map_err(|err| {
            ServerError::Configuration(format!("SFU ratchet adımı üretilemedi: {err}"))
        })?;
        let id = generate_id();
        {
            let mut guard = self.entries.lock().await;
            Self::purge_locked(&mut guard, now);
            guard.insert(id.clone(), Arc::clone(&context));
        }
        Ok(SfuContextProvision {
            context_id: id,
            expires_at: context.expires_at,
            room_id: context.room_id.clone(),
            participant: context.participant.clone(),
            e2ee,
        })
    }

    async fn next_step(&self, id: &str, now: SystemTime) -> Result<SfuStepOutcome, ServerError> {
        let mut guard = self.entries.lock().await;
        let context = match guard.get(id) {
            Some(ctx) if ctx.is_expired(now) => {
                guard.remove(id);
                return Ok(SfuStepOutcome::Expired);
            }
            Some(ctx) => Arc::clone(ctx),
            None => {
                Self::purge_locked(&mut guard, now);
                return Ok(SfuStepOutcome::NotFound);
            }
        };
        Self::purge_locked(&mut guard, now);
        drop(guard);
        if !context.has_e2ee() {
            return Ok(SfuStepOutcome::E2eeDisabled);
        }
        let step = context.produce_step().await.map_err(|err| {
            ServerError::Configuration(format!("SFU ratchet adımı üretilemedi: {err}"))
        })?;
        let Some(step) = step else {
            return Ok(SfuStepOutcome::E2eeDisabled);
        };
        Ok(SfuStepOutcome::Step(step))
    }

    async fn count(&self, now: SystemTime) -> usize {
        let mut guard = self.entries.lock().await;
        Self::purge_locked(&mut guard, now);
        guard.len()
    }

    fn purge_locked(map: &mut HashMap<String, Arc<SfuContext>>, now: SystemTime) {
        map.retain(|_, ctx| !ctx.is_expired(now));
    }
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
    sfu_store: SfuStore,
    transparency: RwLock<KeyTransparencyLog>,
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
        let public_jwk = public.to_jwk();
        let verifier = JwtVerifier::new(vec![public]);
        let jwks = Jwks {
            keys: vec![public_jwk.clone()],
        };
        let ledger_backend = ledger.clone();
        let ledger = TokenLedger::new(ledger)?;
        let mut transparency = KeyTransparencyLog::new("aunsorm-server");
        let timestamp = unix_timestamp(SystemTime::now())?;
        let publish = TransparencyEvent::publish(
            key_pair.kid().to_owned(),
            public.verifying_key().as_bytes(),
            timestamp,
            Some("initial-jwks".to_string()),
        );
        transparency.append(publish)?;
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
            sfu_store: SfuStore::new(),
            transparency: RwLock::new(transparency),
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

    /// Aktif belirteç defterine bir kayıt ekler ve şeffaflık günlüğüne yazar.
    ///
    /// # Errors
    ///
    /// `SQLite` işlemi, bellek kilidi veya günlük kaydı başarısız olursa `ServerError` döner.
    pub async fn record_token(
        &self,
        jti: &str,
        expires_at: SystemTime,
        subject: Option<&str>,
        audience: Option<&str>,
    ) -> Result<(), ServerError> {
        self.ledger.insert(jti, expires_at).await?;
        self.transparency
            .record_token(jti, subject, audience, expires_at)
            .await
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

    /// Şeffaflık günlüğünün anlık görüntüsünü döndürür.
    ///
    /// # Errors
    ///
    /// Günlük sorgusu sırasında hata oluşursa `ServerError` döner.
    pub async fn transparency_snapshot(&self) -> Result<TransparencySnapshot, ServerError> {
        self.transparency.snapshot().await
    }

    /// SFU entegrasyonu için yeni bir bağlam oluşturur.
    ///
    /// # Errors
    ///
    /// Ratchet üretimi veya depo erişimi başarısız olursa `ServerError` döner.
    pub async fn create_sfu_context(
        &self,
        room_id: String,
        participant: String,
        enable_e2ee: bool,
    ) -> Result<SfuContextProvision, ServerError> {
        self.sfu_store
            .create(room_id, participant, self.strict, enable_e2ee)
            .await
    }

    /// Mevcut SFU bağlamı için bir sonraki anahtar adımını hesaplar.
    ///
    /// # Errors
    ///
    /// Depo erişimi veya ratchet üretimi başarısız olursa `ServerError` döner.
    pub async fn next_sfu_step(&self, context_id: &str) -> Result<SfuStepOutcome, ServerError> {
        self.sfu_store
            .next_step(context_id, SystemTime::now())
            .await
    }

    pub async fn sfu_context_count(&self, now: SystemTime) -> usize {
        self.sfu_store.count(now).await
    }

    /// Şeffaflık defterinin anlık görüntüsünü döndürür.
    pub async fn transparency_snapshot(&self) -> TransparencySnapshot {
        let guard = self.transparency.read().await;
        TransparencySnapshot {
            domain: guard.domain().to_owned(),
            head: guard.tree_head(),
            records: guard.records().to_vec(),
        }
    }
}

pub const fn auth_ttl() -> Duration {
    AUTH_TTL
}

#[derive(Debug, Clone)]
pub struct TransparencySnapshot {
    pub domain: String,
    pub head: [u8; 32],
    pub records: Vec<TransparencyRecord>,
}

impl TransparencySnapshot {
    #[must_use]
    pub fn latest_sequence(&self) -> u64 {
        self.records.last().map_or(0, |record| record.sequence)
    }
}
