use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::rng::AunsormNativeRng;
use aunsorm_core::{
    clock::{ClockAuthority, ClockValidation, SecureClockSnapshot, SecureClockVerifier},
    transparency::{
        unix_timestamp, KeyTransparencyLog, TransparencyError,
        TransparencyEvent as CoreTransparencyEvent, TransparencyRecord,
    },
    CoreError, SessionRatchet,
};
use aunsorm_jwt::{InMemoryJtiStore, JtiStore, Jwk, Jwks, JwtSigner, JwtVerifier, SqliteJtiStore};
use aunsorm_mdm::{
    CertificateDistributionPlan, DevicePlatform, EnrollmentMode, MdmDirectory, MdmError,
    PolicyDocument, PolicyRule,
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::acme::AcmeService;
use crate::clock_refresh::ClockRefreshService;
use crate::config::{ClockRefreshConfig, LedgerBackend, ServerConfig};
use crate::error::ServerError;
use crate::fabric::FabricDidRegistry;
use crate::quic::datagram::{AuditEvent, AuditOutcome};
#[cfg(feature = "http3-experimental")]
use crate::quic::datagram::{
    DatagramPayload, OtelPayload, QuicDatagramV1, RatchetProbe, RatchetStatus,
};
use crate::transparency::{
    TransparencyEvent as LedgerTransparencyEvent, TransparencyLedger,
    TransparencySnapshot as LedgerTransparencySnapshot,
};

const AUTH_TTL: Duration = Duration::from_secs(300);
const SFU_CONTEXT_TTL: Duration = Duration::from_secs(900);

#[derive(Debug, Clone)]
pub struct OAuthClient {
    allowed_redirects: Vec<String>,
    allowed_scopes: Vec<String>,
}

impl OAuthClient {
    pub const fn new(allowed_redirects: Vec<String>, allowed_scopes: Vec<String>) -> Self {
        Self {
            allowed_redirects,
            allowed_scopes,
        }
    }

    pub fn allows_redirect(&self, candidate: &str) -> bool {
        self.allowed_redirects
            .iter()
            .any(|allowed| allowed == candidate)
    }

    pub fn allowed_scopes(&self) -> &[String] {
        &self.allowed_scopes
    }
}

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub subject: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub scope: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditProofDocument {
    pub calibration_fingerprint: String,
    pub authority: String,
    pub authority_fingerprint: String,
    pub attested_unix_ms: u64,
    pub clock_signature: String,
    pub audit_digest_hex: String,
}

#[derive(Debug, Clone)]
pub struct AuditProof {
    calibration_fingerprint: String,
    authority: String,
    authority_fingerprint: String,
    attested_unix_ms: u64,
    digest: [u8; 32],
    clock_signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditProofValidationError {
    CalibrationFingerprint,
    Authority,
    AuthorityFingerprint,
    Timestamp,
    ClockSignature,
    Digest,
}

impl fmt::Display for AuditProofValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::CalibrationFingerprint => "kalibrasyon fingerprint doğrulanamadı",
            Self::Authority => "audit proof beklenen saat otoritesiyle uyuşmuyor",
            Self::AuthorityFingerprint => "saat otoritesi sertifika parmak izi eşleşmiyor",
            Self::Timestamp => "audit proof zaman damgası beklenen değerle uyuşmuyor",
            Self::ClockSignature => "saat imzası beklenen değeri sağlamıyor",
            Self::Digest => "audit proof özeti beklenen değeri sağlamıyor",
        };
        f.write_str(message)
    }
}

impl std::error::Error for AuditProofValidationError {}

impl AuditProof {
    fn compute_digest(calibration_fingerprint: &str, validation: &ClockValidation) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"Aunsorm/1.01/audit-proof");
        hasher.update(calibration_fingerprint.as_bytes());
        hasher.update(validation.authority_fingerprint_hex.as_bytes());
        hasher.update(validation.unix_time_ms.to_be_bytes());
        hasher.update(validation.signature_b64.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest[..32]);
        out
    }

    pub fn new(calibration_fingerprint: impl Into<String>, validation: ClockValidation) -> Self {
        let calibration_fingerprint = calibration_fingerprint.into();
        let digest = Self::compute_digest(&calibration_fingerprint, &validation);
        Self {
            calibration_fingerprint,
            authority: validation.authority_id,
            authority_fingerprint: validation.authority_fingerprint_hex,
            attested_unix_ms: validation.unix_time_ms,
            digest,
            clock_signature: validation.signature_b64,
        }
    }

    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest)
    }

    #[must_use]
    pub fn document(&self) -> AuditProofDocument {
        AuditProofDocument {
            calibration_fingerprint: self.calibration_fingerprint.clone(),
            authority: self.authority.clone(),
            authority_fingerprint: self.authority_fingerprint.clone(),
            attested_unix_ms: self.attested_unix_ms,
            clock_signature: self.clock_signature.clone(),
            audit_digest_hex: self.digest_hex(),
        }
    }

    pub fn verify_document(
        &self,
        candidate: &AuditProofDocument,
    ) -> Result<(), AuditProofValidationError> {
        if candidate.calibration_fingerprint != self.calibration_fingerprint {
            return Err(AuditProofValidationError::CalibrationFingerprint);
        }
        if candidate.authority != self.authority {
            return Err(AuditProofValidationError::Authority);
        }
        if candidate.authority_fingerprint != self.authority_fingerprint {
            return Err(AuditProofValidationError::AuthorityFingerprint);
        }
        if candidate.attested_unix_ms != self.attested_unix_ms {
            return Err(AuditProofValidationError::Timestamp);
        }
        if candidate.clock_signature != self.clock_signature {
            return Err(AuditProofValidationError::ClockSignature);
        }
        if candidate.audit_digest_hex != self.digest_hex() {
            return Err(AuditProofValidationError::Digest);
        }
        Ok(())
    }
}

fn generate_id() -> String {
    static RNG: OnceLock<StdMutex<AunsormNativeRng>> = OnceLock::new();
    let mut buf = [0_u8; 16];
    RNG.get_or_init(|| StdMutex::new(AunsormNativeRng::new()))
        .lock()
        .expect("Aunsorm native RNG mutex poisoned while generating id")
        .fill_bytes(&mut buf);
    hex::encode(buf)
}

fn default_oauth_clients() -> HashMap<String, OAuthClient> {
    let mut clients = HashMap::new();

    // Build redirect URIs with environment variable support
    let mut redirect_uris = vec![
        "https://app.example.com/callback".to_string(),
        "https://demo.example.com/oauth/callback".to_string(),
    ];

    // Add localhost callbacks (development/testing)
    if let Ok(host) = std::env::var("HOST") {
        redirect_uris.extend(vec![
            format!("http://{}:3000/callback", host),
            format!("http://{}:8080/callback", host),
        ]);
    } else {
        // Fallback to localhost for development
        redirect_uris.extend(vec![
            "http://localhost:3000/callback".to_string(),
            "http://127.0.0.1:3000/callback".to_string(),
            "http://localhost:8080/callback".to_string(),
        ]);
    }

    // Add production callback if configured
    if let Ok(prod_callback) = std::env::var("OAUTH_PRODUCTION_CALLBACK") {
        redirect_uris.push(prod_callback);
    }

    clients.insert(
        "demo-client".to_string(),
        OAuthClient::new(
            redirect_uris,
            vec![
                "read".to_string(),
                "write".to_string(),
                "introspect".to_string(),
            ],
        ),
    );
    clients.insert(
        "webapp-123".to_string(),
        OAuthClient::new(
            vec!["https://app.example.com/callback".to_string()],
            vec!["read".to_string(), "write".to_string()],
        ),
    );
    clients
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
            let mut rng = AunsormNativeRng::new();
            let mut root = [0_u8; 32];
            rng.fill_bytes(&mut root);
            let mut session_id = [0_u8; 16];
            rng.fill_bytes(&mut session_id);
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

fn map_mdm_error(err: &MdmError) -> ServerError {
    ServerError::Configuration(format!("MDM directory error: {err}"))
}

#[allow(clippy::too_many_lines)]
fn default_mdm_directory() -> Result<MdmDirectory, ServerError> {
    let directory = MdmDirectory::new(CertificateDistributionPlan {
        profile_name: "aunsorm-mdm-default".to_owned(),
        certificate_authority: "CN=Aunsorm Device CA,O=Aunsorm".to_owned(),
        enrollment_mode: EnrollmentMode::Automated,
        distribution_endpoints: vec![
            "https://mdm.aunsorm.dev/scep".to_owned(),
            "https://mdm.aunsorm.dev/acme/device".to_owned(),
        ],
        renewal_window_days: 45,
        grace_period_hours: 96,
        bootstrap_package: "https://downloads.aunsorm.dev/mdm/bootstrap.pkg".to_owned(),
    });
    let now = SystemTime::now();
    directory
        .upsert_policy(
            DevicePlatform::Ios,
            PolicyDocument {
                version: "2025.10-ios".to_owned(),
                description: "iOS cihazları için temel güvenlik gereksinimleri".to_owned(),
                published_at: now,
                rules: vec![
                    PolicyRule {
                        id: "screen-lock".to_owned(),
                        statement: "Cihazlar 60 saniye içinde otomatik kilitlenmelidir".to_owned(),
                        mandatory: true,
                        remediation: Some("MDM profilini yeniden dağıt".to_owned()),
                    },
                    PolicyRule {
                        id: "os-version".to_owned(),
                        statement: "Minimum iOS sürümü 18.0".to_owned(),
                        mandatory: true,
                        remediation: Some(
                            "Güncelleme tamamlanana kadar erişimi kısıtla".to_owned(),
                        ),
                    },
                    PolicyRule {
                        id: "calibration-binding".to_owned(),
                        statement: "Aunsorm ajanı EXTERNAL kalibrasyon kimliğini doğrulamalıdır"
                            .to_owned(),
                        mandatory: true,
                        remediation: Some("Ajan yapılandırmasını yeniden uygula".to_owned()),
                    },
                ],
            },
        )
        .map_err(|err| map_mdm_error(&err))?;
    directory
        .upsert_policy(
            DevicePlatform::Android,
            PolicyDocument {
                version: "2025.10-android".to_owned(),
                description: "Android cihazları için temel güvenlik gereksinimleri".to_owned(),
                published_at: now,
                rules: vec![
                    PolicyRule {
                        id: "play-protect".to_owned(),
                        statement: "Play Protect ve zararlı yazılım taraması aktif olmalıdır"
                            .to_owned(),
                        mandatory: true,
                        remediation: Some("Uzak komut ile taramayı etkinleştir".to_owned()),
                    },
                    PolicyRule {
                        id: "os-version".to_owned(),
                        statement: "Minimum Android sürümü 15".to_owned(),
                        mandatory: true,
                        remediation: Some("OTA güncellemesini zorunlu tut".to_owned()),
                    },
                    PolicyRule {
                        id: "storage-encryption".to_owned(),
                        statement: "Tam disk şifreleme devre dışı bırakılamaz".to_owned(),
                        mandatory: true,
                        remediation: Some(
                            "Cihazı yeniden başlatıp şifrelemeyi zorunlu kıl".to_owned(),
                        ),
                    },
                ],
            },
        )
        .map_err(|err| map_mdm_error(&err))?;
    directory
        .upsert_policy(
            DevicePlatform::Macos,
            PolicyDocument {
                version: "2025.10-macos".to_owned(),
                description: "macOS cihazları için temel güvenlik gereksinimleri".to_owned(),
                published_at: now,
                rules: vec![
                    PolicyRule {
                        id: "filevault".to_owned(),
                        statement: "FileVault tüm cihazlarda aktif olmalıdır".to_owned(),
                        mandatory: true,
                        remediation: Some("FileVault profilini yeniden uygula".to_owned()),
                    },
                    PolicyRule {
                        id: "gatekeeper".to_owned(),
                        statement: "Gatekeeper yalnızca imzalı uygulamalara izin vermelidir"
                            .to_owned(),
                        mandatory: true,
                        remediation: Some("Yetkisiz uygulamaları kaldır".to_owned()),
                    },
                    PolicyRule {
                        id: "agent-health".to_owned(),
                        statement: "Aunsorm MDM ajanı 30 dakikadan uzun süre çevrimdışı kalamaz"
                            .to_owned(),
                        mandatory: true,
                        remediation: Some("Ajan servislerini yeniden başlat".to_owned()),
                    },
                ],
            },
        )
        .map_err(|err| map_mdm_error(&err))?;
    directory
        .upsert_policy(
            DevicePlatform::Windows,
            PolicyDocument {
                version: "2025.10-windows".to_owned(),
                description: "Windows cihazları için temel güvenlik gereksinimleri".to_owned(),
                published_at: now,
                rules: vec![
                    PolicyRule {
                        id: "bitlocker".to_owned(),
                        statement: "BitLocker koruması devre dışı bırakılamaz".to_owned(),
                        mandatory: true,
                        remediation: Some("TPM kilidini uzaktan yeniden anahtarla".to_owned()),
                    },
                    PolicyRule {
                        id: "secure-boot".to_owned(),
                        statement: "Secure Boot her zaman aktif olmalıdır".to_owned(),
                        mandatory: true,
                        remediation: Some("BIOS yapılandırmasını doğrula".to_owned()),
                    },
                    PolicyRule {
                        id: "defender".to_owned(),
                        statement: "Microsoft Defender gerçek zamanlı koruması açık kalmalıdır"
                            .to_owned(),
                        mandatory: true,
                        remediation: Some("Koruma politikalarını yeniden uygula".to_owned()),
                    },
                ],
            },
        )
        .map_err(|err| map_mdm_error(&err))?;
    directory
        .upsert_policy(
            DevicePlatform::Linux,
            PolicyDocument {
                version: "2025.10-linux".to_owned(),
                description: "Linux cihazları için temel güvenlik gereksinimleri".to_owned(),
                published_at: now,
                rules: vec![
                    PolicyRule {
                        id: "disk-encryption".to_owned(),
                        statement: "LUKS tam disk şifrelemesi zorunludur".to_owned(),
                        mandatory: true,
                        remediation: Some("Initramfs politikasını yeniden oluştur".to_owned()),
                    },
                    PolicyRule {
                        id: "secure-boot".to_owned(),
                        statement: "Secure Boot devre dışı bırakılamaz".to_owned(),
                        mandatory: true,
                        remediation: Some("EFI imza paketini yenile".to_owned()),
                    },
                    PolicyRule {
                        id: "agent-service".to_owned(),
                        statement: "Aunsorm ajan servisi systemd üzerinden etkin olmalıdır"
                            .to_owned(),
                        mandatory: true,
                        remediation: Some("systemctl ile servisi yeniden başlat".to_owned()),
                    },
                ],
            },
        )
        .map_err(|err| map_mdm_error(&err))?;
    Ok(directory)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClockHealthStatus {
    pub status: &'static str,
    pub age_ms: u128,
    pub max_ms: u128,
    pub authority: String,
    pub attested_unix_ms: u64,
    pub refresh_enabled: bool,
    pub message: Option<String>,
}

pub struct ServerState {
    listen_port: u16,
    issuer: String,
    audience: String,
    token_ttl: Duration,
    strict: bool,
    signer: JwtSigner,
    verifier: JwtVerifier,
    jwks: Jwks,
    oauth_clients: Arc<HashMap<String, OAuthClient>>,
    auth_store: AuthStore,
    ledger: TokenLedger,
    sfu_store: SfuStore,
    transparency_tree: RwLock<KeyTransparencyLog>,
    transparency_ledger: TransparencyLedger,
    mdm: MdmDirectory,
    fabric: FabricDidRegistry,
    acme: AcmeService,
    rng: StdMutex<AunsormNativeRng>,
    audit_proof: Arc<RwLock<AuditProof>>,
    audit_events: RwLock<Vec<AuditEvent>>,
    calibration_fingerprint: String,
    clock_max_age: Duration,
    clock_snapshot: Arc<RwLock<SecureClockSnapshot>>,
    clock_verifier: Arc<SecureClockVerifier>,
    clock_refresh_service: Option<Arc<ClockRefreshService>>,
    clock_refresh_task: OnceLock<JoinHandle<()>>,
    clock_monitor_task: OnceLock<JoinHandle<()>>,
}

struct ClockRuntime {
    verifier: Arc<SecureClockVerifier>,
    audit_proof: Arc<RwLock<AuditProof>>,
    snapshot_store: Arc<RwLock<SecureClockSnapshot>>,
    refresh_service: Option<Arc<ClockRefreshService>>,
    calibration_fingerprint: String,
}

impl ServerState {
    /// Yapılandırmadan sunucu durumunu üretir.
    ///
    /// # Errors
    ///
    /// JTI defteri başlatılırken hata oluşursa `ServerError` döner.
    pub fn try_new(config: ServerConfig) -> Result<Self, ServerError> {
        let ServerConfig {
            listen,
            issuer,
            audience,
            token_ttl,
            strict,
            key_pair,
            ledger,
            fabric: _fabric,
            calibration_fingerprint,
            clock_snapshot,
            clock_max_age,
            clock_refresh,
        } = config;
        let signer = JwtSigner::new(key_pair.clone());
        let public = key_pair.public_key();
        let public_jwk = public.to_jwk();
        let store: Arc<dyn JtiStore> = match &ledger {
            LedgerBackend::Memory => Arc::new(InMemoryJtiStore::default()),
            LedgerBackend::Sqlite(path) => Arc::new(SqliteJtiStore::open(path)?),
        };
        let verifier = JwtVerifier::new(vec![public.clone()]).with_store(store);
        let jwks = Jwks {
            keys: vec![public_jwk.clone()],
        };

        let ClockRuntime {
            verifier: clock_verifier,
            audit_proof,
            snapshot_store: clock_snapshot_store,
            refresh_service: clock_refresh_service,
            calibration_fingerprint: calibration_fingerprint_owned,
        } = Self::build_clock_components(
            clock_snapshot,
            clock_max_age,
            calibration_fingerprint,
            clock_refresh,
        )?;

        let (ledger, transparency_tree, transparency_ledger) = Self::build_transparency_components(
            ledger,
            key_pair.kid(),
            public.verifying_key().as_bytes(),
            public_jwk,
        )?;

        let mdm = default_mdm_directory()?;
        let fabric = FabricDidRegistry::poc()?;
        let acme = AcmeService::new(&issuer)?;
        let oauth_clients = Arc::new(default_oauth_clients());
        Ok(Self {
            listen_port: listen.port(),
            issuer,
            audience,
            token_ttl,
            strict,
            signer,
            verifier,
            jwks,
            oauth_clients,
            auth_store: AuthStore::new(),
            ledger,
            sfu_store: SfuStore::new(),
            transparency_tree: RwLock::new(transparency_tree),
            transparency_ledger,
            mdm,
            fabric,
            acme,
            rng: StdMutex::new(AunsormNativeRng::new()),
            audit_proof,
            audit_events: RwLock::new(Vec::new()),
            calibration_fingerprint: calibration_fingerprint_owned,
            clock_max_age,
            clock_snapshot: clock_snapshot_store,
            clock_verifier,
            clock_refresh_service,
            clock_refresh_task: OnceLock::new(),
            clock_monitor_task: OnceLock::new(),
        })
    }

    fn build_clock_components(
        clock_snapshot: SecureClockSnapshot,
        clock_max_age: Duration,
        calibration_fingerprint: String,
        clock_refresh: Option<ClockRefreshConfig>,
    ) -> Result<ClockRuntime, ServerError> {
        let authority = ClockAuthority::new(
            clock_snapshot.authority_id.clone(),
            clock_snapshot.authority_fingerprint_hex.clone(),
        );
        let max_age_secs = clock_max_age.as_secs();
        if max_age_secs > 60 {
            tracing::warn!(
                "⚠️  Clock max_age set to {} seconds (production should use ≤30s with NTP refresh)",
                max_age_secs
            );
        }
        let clock_verifier = Arc::new(SecureClockVerifier::configurable(
            vec![authority],
            clock_max_age,
        )?);
        let validation = clock_verifier.verify(&clock_snapshot)?;
        let calibration_fingerprint_owned = calibration_fingerprint;
        let audit_proof = Arc::new(RwLock::new(AuditProof::new(
            calibration_fingerprint_owned.clone(),
            validation,
        )));
        let (clock_refresh_service, clock_snapshot_store) = match (clock_refresh, clock_snapshot) {
            (Some(refresh), snapshot) => {
                let service = Arc::new(ClockRefreshService::new(
                    snapshot,
                    Some(refresh.url().to_string()),
                    refresh.interval(),
                    Arc::clone(&clock_verifier),
                )?);
                let store = service.attestation();
                (Some(service), store)
            }
            (None, snapshot) => (None, Arc::new(RwLock::new(snapshot))),
        };
        Ok(ClockRuntime {
            verifier: clock_verifier,
            audit_proof,
            snapshot_store: clock_snapshot_store,
            refresh_service: clock_refresh_service,
            calibration_fingerprint: calibration_fingerprint_owned,
        })
    }

    fn build_transparency_components(
        ledger: LedgerBackend,
        key_id: &str,
        public_key_bytes: &[u8],
        public_jwk: Jwk,
    ) -> Result<(TokenLedger, KeyTransparencyLog, TransparencyLedger), ServerError> {
        let transparency_backend = ledger.clone();
        let token_ledger = TokenLedger::new(ledger)?;
        let mut transparency_tree = KeyTransparencyLog::new("aunsorm-server");
        let timestamp = unix_timestamp(SystemTime::now())?;
        let publish = CoreTransparencyEvent::publish(
            key_id.to_owned(),
            public_key_bytes,
            timestamp,
            Some("initial-jwks".to_string()),
        );
        transparency_tree.append(publish)?;
        let transparency_ledger = TransparencyLedger::new(
            transparency_backend,
            vec![LedgerTransparencyEvent::key_published(public_jwk)],
        )?;
        Ok((token_ledger, transparency_tree, transparency_ledger))
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub const fn listen_port(&self) -> u16 {
        self.listen_port
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

    pub async fn audit_proof_document(&self) -> AuditProofDocument {
        self.audit_proof.read().await.document()
    }

    /// Verilen audit kanıtını beklenen değerlerle karşılaştırır.
    ///
    /// # Errors
    /// Sağlanan kanıtın herhangi bir bileşeni uyuşmadığında
    /// [`AuditProofValidationError`] döndürür.
    pub async fn verify_audit_proof(
        &self,
        candidate: &AuditProofDocument,
    ) -> Result<(), AuditProofValidationError> {
        self.audit_proof.read().await.verify_document(candidate)
    }

    fn attestation_age_ms(unix_ms: u64) -> u128 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0);
        now_ms.saturating_sub(u128::from(unix_ms))
    }

    pub async fn current_clock_snapshot(&self) -> SecureClockSnapshot {
        if let Some(service) = &self.clock_refresh_service {
            service.get_current().await
        } else {
            self.clock_snapshot.read().await.clone()
        }
    }

    pub const fn clock_refresh_enabled(&self) -> bool {
        self.clock_refresh_service.is_some()
    }

    pub const fn clock_max_age(&self) -> Duration {
        self.clock_max_age
    }

    pub async fn clock_health_status(&self) -> ClockHealthStatus {
        let snapshot = self.current_clock_snapshot().await;
        let refresh_enabled = self.clock_refresh_enabled();
        match self.clock_verifier.verify(&snapshot) {
            Ok(validation) => {
                let age_ms = Self::attestation_age_ms(validation.unix_time_ms);
                ClockHealthStatus {
                    status: "ok",
                    age_ms,
                    max_ms: self.clock_max_age.as_millis(),
                    authority: validation.authority_id,
                    attested_unix_ms: validation.unix_time_ms,
                    refresh_enabled,
                    message: None,
                }
            }
            Err(err) => {
                let age_ms = Self::attestation_age_ms(snapshot.unix_time_ms);
                ClockHealthStatus {
                    status: "error",
                    age_ms,
                    max_ms: self.clock_max_age.as_millis(),
                    authority: snapshot.authority_id.clone(),
                    attested_unix_ms: snapshot.unix_time_ms,
                    refresh_enabled,
                    message: Some(err.to_string()),
                }
            }
        }
    }

    pub fn start_clock_refresh(self: &Arc<Self>) {
        if let Some(service) = &self.clock_refresh_service {
            if self.clock_refresh_task.get().is_none() {
                let refresh_handle = Arc::clone(service).start();
                let _ = self.clock_refresh_task.set(refresh_handle);

                let mut receiver = service.subscribe();
                let verifier = Arc::clone(&self.clock_verifier);
                let audit_proof = Arc::clone(&self.audit_proof);
                let calibration_fingerprint = self.calibration_fingerprint.clone();
                let snapshot_store: Arc<RwLock<SecureClockSnapshot>> =
                    Arc::clone(&self.clock_snapshot);
                let monitor = tokio::spawn(async move {
                    while receiver.changed().await.is_ok() {
                        let snapshot = receiver.borrow().clone();
                        match verifier.verify(&snapshot) {
                            Ok(validation) => {
                                {
                                    let mut guard = audit_proof.write().await;
                                    *guard = AuditProof::new(
                                        calibration_fingerprint.clone(),
                                        validation.clone(),
                                    );
                                }
                                *snapshot_store.write().await = snapshot.clone();
                                tracing::info!(
                                    unix_ms = validation.unix_time_ms,
                                    authority = %validation.authority_id,
                                    "Clock attestation validated"
                                );
                            }
                            Err(err) => {
                                tracing::error!("Clock attestation validation failed: {}", err);
                            }
                        }
                    }
                });
                let _ = self.clock_monitor_task.set(monitor);
            }
        }
    }

    pub fn oauth_client(&self, client_id: &str) -> Option<&OAuthClient> {
        self.oauth_clients.get(client_id)
    }

    pub const fn acme(&self) -> &AcmeService {
        &self.acme
    }

    pub const fn strict(&self) -> bool {
        self.strict
    }

    pub const fn mdm_directory(&self) -> &MdmDirectory {
        &self.mdm
    }

    pub const fn fabric_registry(&self) -> &FabricDidRegistry {
        &self.fabric
    }

    /// Returns the number of devices registered in the in-memory MDM directory.
    ///
    /// # Errors
    ///
    /// Propagates [`ServerError::Configuration`] when the underlying directory
    /// locks are poisoned.
    pub fn registered_device_count(&self) -> Result<usize, ServerError> {
        self.mdm.device_count().map_err(|err| map_mdm_error(&err))
    }

    #[cfg(feature = "http3-experimental")]
    /// HTTP/3 denetim ve telemetri datagramlarını üretir.
    ///
    /// # Errors
    ///
    /// İç metrik sorguları başarısız olursa veya değerler temsil sınırlarını
    /// aşarsa `ServerError` döner.
    pub async fn http3_datagram_batch(
        &self,
        base_sequence: u32,
        timestamp_ms: u64,
    ) -> Result<Vec<QuicDatagramV1>, ServerError> {
        const MAX_EXACT_IN_F64: u64 = 1_u64 << f64::MANTISSA_DIGITS;

        let now = SystemTime::now();
        let pending = self.auth_request_count().await;
        let active = self.active_token_count(now).await?;
        let sfu = self.sfu_context_count(now).await;
        let devices = self.registered_device_count()?;

        let to_u64 = |value: usize, field: &str| -> Result<u64, ServerError> {
            u64::try_from(value)
                .map_err(|_| ServerError::Configuration(format!("{field} 64-bit sınırını aştı")))
        };

        let pending_u64 = to_u64(pending, "bekleyen yetkilendirme sayısı")?;
        let active_u64 = to_u64(active, "aktif token sayısı")?;
        let sfu_u64 = to_u64(sfu, "SFU bağlam sayısı")?;
        let devices_u64 = to_u64(devices, "MDM cihaz sayısı")?;

        let coerce_to_f64 = |value: u64, field: &str| -> Result<f64, ServerError> {
            if value > MAX_EXACT_IN_F64 {
                return Err(ServerError::Configuration(format!(
                    "{field} f64 hassasiyet sınırını aştı"
                )));
            }
            #[allow(clippy::cast_precision_loss)]
            // Yukarıda doğrulanan değerler f64 mantissa sınırları içinde kalır.
            let coerced = value as f64;
            Ok(coerced)
        };

        let map_err = |err: crate::quic::datagram::DatagramError| {
            ServerError::Configuration(format!("HTTP/3 datagram üretilemedi: {err}"))
        };

        let mut otel = OtelPayload::new();
        otel.add_counter("pending_auth_requests", pending_u64);
        otel.add_counter("active_tokens", active_u64);
        let sfu_gauge = coerce_to_f64(sfu_u64, "SFU bağlam sayısı")?;
        otel.add_gauge("sfu_contexts", sfu_gauge).map_err(map_err)?;
        let devices_gauge = coerce_to_f64(devices_u64, "MDM cihaz sayısı")?;
        otel.add_gauge("mdm_registered_devices", devices_gauge)
            .map_err(map_err)?;

        let mut sequence = base_sequence;
        let telemetry = QuicDatagramV1::new(sequence, timestamp_ms, DatagramPayload::Otel(otel))
            .map_err(map_err)?;

        sequence = sequence.wrapping_add(1);
        let audit = QuicDatagramV1::new(
            sequence,
            timestamp_ms,
            DatagramPayload::Audit(AuditEvent {
                event_id: format!("{timestamp_ms:016x}:{sequence:08x}"),
                principal_id: "system@aunsorm".to_owned(),
                outcome: AuditOutcome::Success,
                resource: format!("telemetry://{}", self.issuer()),
            }),
        )
        .map_err(map_err)?;

        sequence = sequence.wrapping_add(1);
        let mut session_id = [0_u8; 16];
        session_id[..4].copy_from_slice(&sequence.to_be_bytes());
        let drift = if pending_u64 >= active_u64 {
            i64::try_from(pending_u64 - active_u64).unwrap_or(i64::MAX)
        } else {
            -i64::try_from(active_u64 - pending_u64).unwrap_or(i64::MAX)
        };
        let ratchet = QuicDatagramV1::new(
            sequence,
            timestamp_ms,
            DatagramPayload::Ratchet(RatchetProbe {
                session_id,
                step: u64::from(sequence),
                drift,
                status: if pending_u64 > 0 {
                    RatchetStatus::Advancing
                } else {
                    RatchetStatus::Stalled
                },
            }),
        )
        .map_err(map_err)?;

        Ok(vec![telemetry, audit, ratchet])
    }

    pub async fn register_auth_request(
        &self,
        subject: String,
        client_id: String,
        redirect_uri: String,
        state: Option<String>,
        scope: Option<String>,
        code_challenge: String,
    ) -> String {
        let now = SystemTime::now();
        let request = AuthRequest {
            subject,
            client_id,
            redirect_uri,
            state,
            scope,
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
        self.transparency_ledger
            .record_token(jti, subject, audience, expires_at)
            .await?;
        Ok(())
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

    fn next_entropy_block(&self) -> [u8; 32] {
        let mut buf = [0_u8; 32];
        let mut rng = self
            .rng
            .lock()
            .expect("Aunsorm native RNG mutex poisoned while deriving entropy");
        rng.fill_bytes(&mut buf);
        buf
    }

    /// Constant-time rejection sampling ile timing attack koruması
    ///
    /// # Güvenlik
    /// - Her 8-byte chunk işlenir (early return yok)
    /// - Conditional logic yerine bitwise operations
    /// - Execution time entropy'ye bağlı değil (timing leak yok)
    fn map_entropy_to_range(entropy: &[u8; 32], min: u64, max: u64) -> Option<u64> {
        if min == max {
            return Some(min);
        }
        let span = max.checked_sub(min)?;
        let range = u128::from(span) + 1;
        let total_space = u128::from(u64::MAX) + 1;
        let threshold = total_space - total_space % range;

        // Constant-time rejection sampling:
        // Tüm chunk'lar işlenir ve veri bağımlı dallanma kullanılmaz
        let mut selected = 0_u64;
        let mut found_mask = 0_u64; // 0 -> bulunmadı, 1 -> bulundu

        for chunk in entropy.chunks_exact(8) {
            let mut buf = [0_u8; 8];
            buf.copy_from_slice(chunk);
            let candidate = u128::from(u64::from_be_bytes(buf));

            // Her zaman hesapla: hem mod işlemi hem de eşik kontrolü
            let offset = u64::try_from(candidate % range)
                .expect("entropy map offset should always fit within u64 range");
            let result = min
                .checked_add(offset)
                .expect("result overflow when sampling randomness");
            let is_valid = u64::from(candidate < threshold);

            // Sadece ilk geçerli değeri seç: (1 ^ found_mask) bitwise olarak "bulunmadı"yı temsil eder
            let take_mask = is_valid & (1_u64 ^ found_mask);
            let full_mask = u64::MAX.wrapping_mul(take_mask);

            // Branchless seçim: maske 0xFFFF.. ise result, aksi halde mevcut değer korunur
            selected = (selected & !full_mask) | (result & full_mask);
            found_mask |= take_mask;
        }

        if found_mask == 1 {
            Some(selected)
        } else {
            None
        }
    }

    /// Üretilen rastgele değeri ve kaynak entropisini döndürür.
    ///
    /// # Panics
    ///
    /// `min` değeri `max` değerinden büyükse paniğe neden olur.
    pub fn random_value_with_proof(&self, min: u64, max: u64) -> (u64, [u8; 32]) {
        assert!(min <= max, "min must not exceed max");
        loop {
            let entropy = self.next_entropy_block();
            if let Some(value) = Self::map_entropy_to_range(&entropy, min, max) {
                return (value, entropy);
            }
        }
    }

    pub fn random_inclusive(&self, min: u64, max: u64) -> u64 {
        self.random_value_with_proof(min, max).0
    }

    /// Şeffaflık günlüğünün (token kayıtları) anlık görüntüsünü döndürür.
    ///
    /// # Errors
    ///
    /// Günlük sorgusu sırasında hata oluşursa `ServerError` döner.
    pub async fn transparency_ledger_snapshot(
        &self,
    ) -> Result<LedgerTransparencySnapshot, ServerError> {
        self.transparency_ledger.snapshot().await
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

    /// Şeffaflık ağacının anlık görüntüsünü döndürür.
    pub async fn transparency_tree_snapshot(&self) -> TransparencyTreeSnapshot {
        let guard = self.transparency_tree.read().await;
        TransparencyTreeSnapshot {
            domain: guard.domain().to_owned(),
            head: guard.tree_head(),
            records: guard.records().to_vec(),
        }
    }

    pub async fn record_calibration_failure(
        &self,
        calibration_id: &str,
        expected_hex: &str,
        actual_hex: &str,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let event = AuditEvent {
            event_id: format!("calibration::{timestamp:016x}:{calibration_id}"),
            principal_id: "system@aunsorm".to_owned(),
            outcome: AuditOutcome::Failure,
            resource: format!(
                "calibration://{calibration_id}?expected={expected_hex}&actual={actual_hex}"
            ),
        };
        self.audit_events.write().await.push(event);
    }

    pub async fn audit_events(&self) -> Vec<AuditEvent> {
        self.audit_events.read().await.clone()
    }
}

#[allow(dead_code)]
pub const fn auth_ttl() -> Duration {
    AUTH_TTL
}

#[derive(Debug, Clone)]
pub struct TransparencyTreeSnapshot {
    pub domain: String,
    pub head: [u8; 32],
    pub records: Vec<TransparencyRecord>,
}

impl TransparencyTreeSnapshot {
    #[must_use]
    pub fn latest_sequence(&self) -> u64 {
        self.records.last().map_or(0, |record| record.sequence)
    }

    /// Transkript karmasını döndürür.
    pub fn transcript_hash(&self) -> Result<Option<[u8; 32]>, TransparencyError> {
        if self.records.is_empty() {
            return Ok(None);
        }
        KeyTransparencyLog::transcript_hash(&self.domain, &self.records).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuditProof, AuditProofValidationError, ServerState};
    use aunsorm_core::clock::ClockValidation;

    fn sample_validation() -> ClockValidation {
        ClockValidation {
            authority_id: "ntp.test.aunsorm".to_owned(),
            authority_fingerprint_hex:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            unix_time_ms: 1_720_000_000_000,
            skew_ms: 4,
            round_trip_ms: 8,
            dispersion_ms: 12,
            signature_b64: "dGVzdC1jbG9jay1zaWc".to_owned(),
        }
    }

    #[test]
    fn map_entropy_to_range_selects_first_valid_candidate() {
        let entropy = [0_u8; 32];
        let result = ServerState::map_entropy_to_range(&entropy, 10, 15);
        assert_eq!(result, Some(10));
    }

    #[test]
    fn map_entropy_to_range_returns_none_when_all_candidates_invalid() {
        let entropy = [0xFF_u8; 32];
        let result = ServerState::map_entropy_to_range(&entropy, 10, 15);
        assert_eq!(result, None);
    }

    #[test]
    fn map_entropy_to_range_preserves_first_valid_value() {
        let mut entropy = [0xFF_u8; 32];
        // İlk chunk geçersiz (0xFF..). İkinci chunk 0 → 10 değeri.
        entropy[8..16].copy_from_slice(&0_u64.to_be_bytes());
        // Sonraki chunk'lar farklı geçerli değerler üretse bile ilk değer korunmalı.
        entropy[16..24].copy_from_slice(&1_u64.to_be_bytes());
        entropy[24..32].copy_from_slice(&2_u64.to_be_bytes());

        let result = ServerState::map_entropy_to_range(&entropy, 10, 15);
        assert_eq!(result, Some(10));
    }

    #[test]
    fn map_entropy_to_range_handles_full_u64_span() {
        let mut entropy = [0_u8; 32];
        entropy[..8].copy_from_slice(&u64::MAX.to_be_bytes());

        let result = ServerState::map_entropy_to_range(&entropy, 0, u64::MAX);
        assert_eq!(result, Some(u64::MAX));

        let min = u64::MAX - 5;
        let max = u64::MAX;
        let range = u128::from(max - min) + 1;
        let total_space = u128::from(u64::MAX) + 1;
        let threshold = total_space - total_space % range;
        let valid_candidate = u64::try_from(threshold - 1).expect("threshold fits in u64");
        entropy[8..16].copy_from_slice(&valid_candidate.to_be_bytes());

        let expected_offset =
            u64::try_from(valid_candidate as u128 % range).expect("offset fits in u64");
        let result = ServerState::map_entropy_to_range(&entropy, min, max);
        assert_eq!(result, Some(min + expected_offset));
    }

    #[test]
    fn audit_proof_valid_document_passes() {
        let validation = sample_validation();
        let proof = AuditProof::new(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            validation,
        );
        let document = proof.document();
        assert!(proof.verify_document(&document).is_ok());
    }

    #[test]
    fn audit_proof_mismatch_detected() {
        let validation = sample_validation();
        let proof = AuditProof::new(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            validation,
        );
        let mut document = proof.document();
        document.audit_digest_hex = "deadbeef".to_owned();
        let err = proof.verify_document(&document).unwrap_err();
        assert_eq!(err, AuditProofValidationError::Digest);
    }
}
