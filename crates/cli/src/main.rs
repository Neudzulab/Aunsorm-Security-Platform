#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hkdf::Hkdf;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use aunsorm_core::{
    calib_from_text, salts::Salts, KdfPreset, KdfProfile, SessionRatchet, SessionRatchetState,
};
use aunsorm_jwt::SqliteJtiStore;
use aunsorm_jwt::{
    Audience, Claims, Ed25519KeyPair, Ed25519PublicKey, Jwk, Jwks, JwtSigner, JwtVerifier,
    VerificationOptions,
};
use aunsorm_packet::{
    decrypt_one_shot, decrypt_session, encrypt_one_shot, encrypt_session, peek_header,
    AeadAlgorithm, DecryptParams, EncryptParams, KemPayload, SessionDecryptParams,
    SessionEncryptParams, SessionMetadata, SessionStore,
};

#[derive(Parser)]
#[command(
    name = "aunsorm-cli",
    version,
    about = "Aunsorm güvenlik araçları için CLI"
)]
struct Cli {
    /// Strict kipini zorla (`AUNSORM_STRICT` env değişkeni ile birleştirilir)
    #[arg(long, global = true)]
    strict: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// EXTERNAL kalibrasyon bağlamı ile paket şifrele
    Encrypt(EncryptArgs),
    /// EXTERNAL kalibrasyon bağlamı ile paketi çöz
    Decrypt(DecryptArgs),
    /// Paket başlığını incele
    Peek(PeekArgs),
    /// Oturum mesajını şifrele
    #[command(name = "session-encrypt")]
    SessionEncrypt(SessionEncryptArgs),
    /// Oturum mesajını çöz
    #[command(name = "session-decrypt")]
    SessionDecrypt(SessionDecryptArgs),
    /// JWT işlemleri
    #[command(subcommand)]
    Jwt(JwtCommands),
}

#[derive(Subcommand)]
enum JwtCommands {
    /// Ed25519 JWT anahtarı üret
    Keygen(JwtKeygenArgs),
    /// JWT imzala
    Sign(JwtSignArgs),
    /// JWT doğrula
    Verify(JwtVerifyArgs),
    /// Anahtar dosyalarından JWKS üret
    ExportJwks(JwtExportJwksArgs),
}

#[derive(Args)]
struct EncryptArgs {
    /// Parola
    #[arg(long)]
    password: String,
    /// Girdi dosyası
    #[arg(long, value_name = "PATH")]
    r#in: PathBuf,
    /// Çıktı dosyası (Base64 paket)
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// Organizasyon tuzu (Base64)
    #[arg(long, value_name = "B64")]
    org_salt: String,
    /// Kalibrasyon metni
    #[arg(long)]
    calib_text: String,
    /// KDF profili
    #[arg(long, default_value = "medium")]
    kdf: ProfileArg,
    /// AEAD algoritması
    #[arg(long, default_value = "aes-gcm")]
    aead: AeadArg,
    /// Ek AAD metni
    #[arg(long, value_name = "TEXT")]
    aad: Option<String>,
    /// Ek AAD dosyası
    #[arg(long, value_name = "PATH")]
    aad_file: Option<PathBuf>,
    /// KEM algoritma etiketi (ör. ml-kem-768)
    #[arg(long, value_name = "NAME")]
    kem: Option<String>,
    /// KEM açık anahtarı (Base64)
    #[arg(long, value_name = "B64")]
    kem_public: Option<String>,
    /// KEM kapsül ciphertext'i (Base64)
    #[arg(long, value_name = "B64")]
    kem_ciphertext: Option<String>,
    /// KEM responder anahtarı (Base64)
    #[arg(long, value_name = "B64")]
    kem_responder: Option<String>,
    /// KEM paylaşılan sırrı (Base64)
    #[arg(long, value_name = "B64")]
    kem_shared: Option<String>,
}

#[derive(Args)]
struct DecryptArgs {
    /// Parola
    #[arg(long)]
    password: String,
    /// Girdi Base64 paket dosyası
    #[arg(long, value_name = "PATH")]
    r#in: PathBuf,
    /// Çözülen çıktı dosyası
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// Organizasyon tuzu (Base64)
    #[arg(long, value_name = "B64")]
    org_salt: String,
    /// Kalibrasyon metni
    #[arg(long)]
    calib_text: String,
    /// KDF profili
    #[arg(long, default_value = "medium")]
    kdf: ProfileArg,
    /// Ek AAD metni
    #[arg(long, value_name = "TEXT")]
    aad: Option<String>,
    /// Ek AAD dosyası
    #[arg(long, value_name = "PATH")]
    aad_file: Option<PathBuf>,
    /// Oturum meta verisini JSON olarak kaydet
    #[arg(long, value_name = "PATH")]
    metadata_out: Option<PathBuf>,
}

#[derive(Args)]
struct PeekArgs {
    /// Girdi Base64 paket dosyası
    #[arg(long, value_name = "PATH")]
    r#in: PathBuf,
}

#[derive(Args)]
struct SessionEncryptArgs {
    /// Oturum meta verisi JSON dosyası
    #[arg(long, value_name = "PATH")]
    metadata: PathBuf,
    /// Ratchet durum dosyası (JSON)
    #[arg(long, value_name = "PATH")]
    state: PathBuf,
    /// Girdi düz metin dosyası
    #[arg(long, value_name = "PATH")]
    r#in: PathBuf,
    /// Çıktı paket dosyası (Base64)
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// Ek AAD metni
    #[arg(long, value_name = "TEXT")]
    aad: Option<String>,
    /// Ek AAD dosyası
    #[arg(long, value_name = "PATH")]
    aad_file: Option<PathBuf>,
    /// İlk kullanım için ratchet kök anahtarı (Base64)
    #[arg(long, value_name = "B64")]
    ratchet_root: Option<String>,
    /// İlk kullanım için oturum kimliği (Base64)
    #[arg(long, value_name = "B64")]
    session_id: Option<String>,
}

#[derive(Args)]
struct SessionDecryptArgs {
    /// Oturum meta verisi JSON dosyası
    #[arg(long, value_name = "PATH")]
    metadata: PathBuf,
    /// Ratchet durum dosyası (JSON)
    #[arg(long, value_name = "PATH")]
    state: PathBuf,
    /// Replay store dosyası (JSON)
    #[arg(long, value_name = "PATH")]
    store: PathBuf,
    /// Girdi paket dosyası (Base64)
    #[arg(long, value_name = "PATH")]
    r#in: PathBuf,
    /// Çözülen çıktı dosyası
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// Ek AAD metni
    #[arg(long, value_name = "TEXT")]
    aad: Option<String>,
    /// Ek AAD dosyası
    #[arg(long, value_name = "PATH")]
    aad_file: Option<PathBuf>,
    /// İlk kullanım için ratchet kök anahtarı (Base64)
    #[arg(long, value_name = "B64")]
    ratchet_root: Option<String>,
    /// İlk kullanım için oturum kimliği (Base64)
    #[arg(long, value_name = "B64")]
    session_id: Option<String>,
}

#[derive(Args)]
struct JwtKeygenArgs {
    /// Üretilecek anahtar kimliği (kid)
    #[arg(long)]
    kid: String,
    /// Gizli anahtar çıktı dosyası (JSON)
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// JWK (public) çıktı dosyası
    #[arg(long, value_name = "PATH")]
    public_out: Option<PathBuf>,
    /// JWKS çıktı dosyası
    #[arg(long, value_name = "PATH")]
    jwks_out: Option<PathBuf>,
}

#[derive(Args)]
struct JwtSignArgs {
    /// Anahtar dosyası (keygen çıktısı)
    #[arg(long, value_name = "PATH")]
    key: PathBuf,
    /// Üretilen JWT çıktı dosyası
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// issuer claim değeri
    #[arg(long)]
    issuer: Option<String>,
    /// subject claim değeri
    #[arg(long)]
    subject: Option<String>,
    /// audience claim değerleri (birden çok kullanılabilir)
    #[arg(long = "audience", value_name = "AUD")]
    audience: Vec<String>,
    /// Token geçerlilik süresi (örn. 15m, 1h)
    #[arg(long, value_name = "DURATION", value_parser = humantime::parse_duration)]
    expires_in: Option<Duration>,
    /// Token'ın geçerli olmaya başlayacağı süre (now + duration)
    #[arg(long, value_name = "DURATION", value_parser = humantime::parse_duration)]
    not_before_in: Option<Duration>,
    /// `issued_at` alanını devre dışı bırak
    #[arg(long)]
    no_issued_at: bool,
    /// Özel jti değeri; verilmezse otomatik üretilecek
    #[arg(long)]
    jti: Option<String>,
    /// Ek claim'ler JSON dosyası
    #[arg(long, value_name = "PATH")]
    claims: Option<PathBuf>,
}

#[derive(Args)]
struct JwtVerifyArgs {
    /// Doğrulanacak JWT dosyası
    #[arg(long, value_name = "PATH")]
    token: PathBuf,
    /// JWKS dosyaları (birden fazla olabilir)
    #[arg(long = "jwks", value_name = "PATH")]
    jwks_files: Vec<PathBuf>,
    /// JWK dosyaları
    #[arg(long = "jwk", value_name = "PATH")]
    jwk_files: Vec<PathBuf>,
    /// Gizli anahtar dosyaları (public anahtar çıkarmak için)
    #[arg(long = "key", value_name = "PATH")]
    key_files: Vec<PathBuf>,
    /// Doğrulanan claim çıktısı (JSON); belirtilmezse stdout'a yazılır
    #[arg(long, value_name = "PATH")]
    claims_out: Option<PathBuf>,
    /// issuer beklenen değeri
    #[arg(long)]
    issuer: Option<String>,
    /// subject beklenen değeri
    #[arg(long)]
    subject: Option<String>,
    /// audience beklenen değeri
    #[arg(long)]
    audience: Option<String>,
    /// jti alanı eksikse doğrulamayı kabul et
    #[arg(long)]
    allow_missing_jti: bool,
    /// Zaman toleransı (varsayılan 30s)
    #[arg(long, value_name = "DURATION", value_parser = humantime::parse_duration)]
    leeway: Option<Duration>,
    /// `SQLite` JTI store dosyası; belirtilirse replay koruması sağlanır
    #[arg(long, value_name = "PATH")]
    sqlite_store: Option<PathBuf>,
}

#[derive(Args)]
struct JwtExportJwksArgs {
    /// Gizli anahtar dosyaları (keygen çıktısı)
    #[arg(long = "key", value_name = "PATH")]
    key_files: Vec<PathBuf>,
    /// JWK dosyaları
    #[arg(long = "jwk", value_name = "PATH")]
    jwk_files: Vec<PathBuf>,
    /// JWKS çıktı dosyası
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    Mobile,
    Low,
    Medium,
    High,
    Ultra,
    Auto,
}

impl ProfileArg {
    fn as_profile(self) -> KdfProfile {
        KdfProfile::preset(match self {
            Self::Mobile => KdfPreset::Mobile,
            Self::Low => KdfPreset::Low,
            Self::Medium => KdfPreset::Medium,
            Self::High => KdfPreset::High,
            Self::Ultra => KdfPreset::Ultra,
            Self::Auto => KdfPreset::Auto,
        })
    }
}

impl std::fmt::Display for ProfileArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Mobile => "mobile",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Ultra => "ultra",
            Self::Auto => "auto",
        })
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum AeadArg {
    #[value(alias = "AES-GCM")]
    AesGcm,
    #[value(alias = "CHACHA20-POLY1305")]
    Chacha20Poly1305,
}

impl AeadArg {
    const fn as_algorithm(self) -> AeadAlgorithm {
        match self {
            Self::AesGcm => AeadAlgorithm::AesGcm,
            Self::Chacha20Poly1305 => AeadAlgorithm::Chacha20Poly1305,
        }
    }
}

impl std::fmt::Display for AeadArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AesGcm => "aes-gcm",
            Self::Chacha20Poly1305 => "chacha20poly1305",
        })
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("core error: {0}")]
    Core(#[from] aunsorm_core::CoreError),
    #[error("packet error: {0}")]
    Packet(#[from] aunsorm_packet::PacketError),
    #[error("pqc error: {0}")]
    Pqc(#[from] aunsorm_pqc::PqcError),
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("AAD metni ile dosyası birlikte kullanılamaz")]
    AadConflict,
    #[error("serde hatası: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{context} uzunluğu {actual} bayt; {expected} bekleniyordu")]
    InvalidLength {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("{0} parametresi gerekli")]
    MissingParam(&'static str),
    #[error("metadata dosyası eksik alan: {0}")]
    Metadata(&'static str),
    #[error("durum dosyası oturum kimliği ile uyuşmuyor")]
    StateSessionMismatch,
    #[error("durum dosyası strict kip ile uyuşmuyor")]
    StateStrictMismatch,
    #[error("store dosyası oturum kimliği ile uyuşmuyor")]
    StoreSessionMismatch,
    #[error("jwt hatası: {0}")]
    Jwt(#[from] aunsorm_jwt::JwtError),
    #[error("jwt anahtar dosyası geçersiz: {0}")]
    JwtKeyFile(&'static str),
    #[error("claim alanı rezerve edildi: {0}")]
    ClaimReserved(String),
    #[error("jwt anahtar materyali belirtilmelidir")]
    MissingJwtMaterial,
    #[error("claims dosyası geçersiz: {0}")]
    JwtClaimsFile(&'static str),
}

type CliResult<T> = Result<T, CliError>;

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("hata: {err}");
        let mut cursor = err.source();
        while let Some(cause) = cursor {
            eprintln!("  neden: {cause}");
            cursor = cause.source();
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> CliResult<()> {
    let strict = cli.strict || env_strict();
    match cli.command {
        Commands::Encrypt(args) => handle_encrypt(args, strict),
        Commands::Decrypt(args) => handle_decrypt(args, strict),
        Commands::Peek(args) => handle_peek(&args),
        Commands::SessionEncrypt(args) => handle_session_encrypt(&args, strict),
        Commands::SessionDecrypt(args) => handle_session_decrypt(&args, strict),
        Commands::Jwt(command) => handle_jwt(command),
    }
}

fn handle_encrypt(args: EncryptArgs, strict: bool) -> CliResult<()> {
    let plaintext = fs::read(&args.r#in)?;
    let aad = load_aad(args.aad.as_deref(), args.aad_file.as_deref())?;
    let org_salt = decode_org_salt(&args.org_salt)?;
    let password = Zeroizing::new(args.password);

    let (calibration, _) = calib_from_text(&org_salt, &args.calib_text);
    let (password_salt, salts) = derive_salts(&org_salt, calibration.id.as_str())?;

    let kem_fields = build_kem_fields(
        args.kem.as_deref(),
        args.kem_public.as_deref(),
        args.kem_ciphertext.as_deref(),
        args.kem_responder.as_deref(),
        args.kem_shared.as_deref(),
    )?;
    let profile = args.kdf.as_profile();
    let algorithm = args.aead.as_algorithm();

    let packet = if let Some(ref kem) = kem_fields {
        encrypt_one_shot(EncryptParams {
            password: &password,
            password_salt: &password_salt,
            calibration: &calibration,
            salts: &salts,
            plaintext: &plaintext,
            aad: &aad,
            profile,
            algorithm,
            strict,
            kem: Some(kem.as_payload()),
        })?
    } else {
        encrypt_one_shot(EncryptParams {
            password: &password,
            password_salt: &password_salt,
            calibration: &calibration,
            salts: &salts,
            plaintext: &plaintext,
            aad: &aad,
            profile,
            algorithm,
            strict,
            kem: None,
        })?
    };

    let encoded = packet.to_base64()?;
    fs::write(&args.out, encoded.as_bytes())?;

    println!(
        "şifreleme tamamlandı: çıktı={} | calib_id={} | profile={} | aead={} | strict={} | kem={}",
        args.out.display(),
        calibration.id.as_str(),
        args.kdf,
        args.aead,
        strict,
        kem_fields.as_ref().map_or("none", |k| k.kem_name.as_str()),
    );
    Ok(())
}

fn handle_decrypt(args: DecryptArgs, strict: bool) -> CliResult<()> {
    let packet_b64 = fs::read_to_string(&args.r#in)?;
    let aad = load_aad(args.aad.as_deref(), args.aad_file.as_deref())?;
    let org_salt = decode_org_salt(&args.org_salt)?;
    let password = Zeroizing::new(args.password);

    let (calibration, _) = calib_from_text(&org_salt, &args.calib_text);
    let (password_salt, salts) = derive_salts(&org_salt, calibration.id.as_str())?;
    let profile = args.kdf.as_profile();

    let params = DecryptParams {
        password: &password,
        password_salt: &password_salt,
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: &aad,
        strict,
        packet: packet_b64.trim(),
    };
    let decrypted = decrypt_one_shot(&params)?;

    fs::write(&args.out, &decrypted.plaintext)?;

    if let Some(path) = args.metadata_out.as_deref() {
        write_metadata_file(path, &decrypted.metadata)?;
    }

    let metadata_note = args
        .metadata_out
        .as_ref()
        .map(|path| format!(" | metadata={}", path.display()))
        .unwrap_or_default();

    println!(
        "deşifre başarılı: çıktı={} | calib_id={} | coord_id={} | aead={} | strict={} | msg_len={}B{}",
        args.out.display(),
        decrypted.header.calib_id,
        decrypted.coord_id,
        decrypted.header.aead.alg,
        strict,
        decrypted.plaintext.len(),
        metadata_note,
    );
    Ok(())
}

fn handle_session_encrypt(args: &SessionEncryptArgs, strict: bool) -> CliResult<()> {
    let metadata = load_metadata_file(&args.metadata)?;
    ensure_metadata_ready(&metadata)?;
    let plaintext = fs::read(&args.r#in)?;
    let aad = load_aad(args.aad.as_deref(), args.aad_file.as_deref())?;

    let mut ratchet = load_or_initialize_ratchet(
        &args.state,
        strict,
        args.ratchet_root.as_deref(),
        args.session_id.as_deref(),
    )?;

    metadata.ensure_strict(ratchet.is_strict())?;

    let params = SessionEncryptParams {
        ratchet: &mut ratchet,
        metadata: &metadata,
        plaintext: &plaintext,
        aad: &aad,
    };
    let (packet, outcome) = encrypt_session(params)?;
    let encoded = packet.to_base64()?;
    fs::write(&args.out, encoded.as_bytes())?;

    save_ratchet_state(&args.state, &ratchet)?;

    println!(
        "oturum şifreleme tamamlandı: çıktı={} | session_id={} | msg_no={} | strict={}",
        args.out.display(),
        STANDARD.encode(outcome.session_id),
        outcome.message_no,
        ratchet.is_strict(),
    );
    Ok(())
}

fn handle_session_decrypt(args: &SessionDecryptArgs, strict: bool) -> CliResult<()> {
    let metadata = load_metadata_file(&args.metadata)?;
    ensure_metadata_ready(&metadata)?;
    let packet_b64 = fs::read_to_string(&args.r#in)?;
    let aad = load_aad(args.aad.as_deref(), args.aad_file.as_deref())?;

    let mut ratchet = load_or_initialize_ratchet(
        &args.state,
        strict,
        args.ratchet_root.as_deref(),
        args.session_id.as_deref(),
    )?;
    metadata.ensure_strict(ratchet.is_strict())?;

    let session_id_b64 = STANDARD.encode(ratchet.session_id());
    let mut replay_store = load_replay_store(&args.store, &session_id_b64)?;
    let mut store = SessionStore::new();
    for msg_no in &replay_store.seen {
        let _ = store.register(ratchet.session_id(), *msg_no);
    }

    let params = SessionDecryptParams {
        ratchet: &mut ratchet,
        metadata: &metadata,
        store: &mut store,
        aad: &aad,
        packet: packet_b64.trim(),
    };
    let (decrypted, outcome) = decrypt_session(params)?;
    fs::write(&args.out, &decrypted.plaintext)?;

    replay_store.seen.insert(outcome.message_no);
    save_replay_store(&args.store, &replay_store)?;
    save_ratchet_state(&args.state, &ratchet)?;

    println!(
        "oturum deşifre tamamlandı: çıktı={} | session_id={} | msg_no={} | strict={} | replay_seen={}",
        args.out.display(),
        session_id_b64,
        outcome.message_no,
        ratchet.is_strict(),
        replay_store.seen.len(),
    );
    Ok(())
}

fn handle_peek(args: &PeekArgs) -> CliResult<()> {
    let packet_b64 = fs::read_to_string(&args.r#in)?;
    let header = peek_header(packet_b64.trim())?;
    let json = serde_json::to_string_pretty(&header)?;
    println!("{json}");
    Ok(())
}

fn handle_jwt(command: JwtCommands) -> CliResult<()> {
    match command {
        JwtCommands::Keygen(args) => handle_jwt_keygen(&args),
        JwtCommands::Sign(args) => handle_jwt_sign(&args),
        JwtCommands::Verify(args) => handle_jwt_verify(&args),
        JwtCommands::ExportJwks(args) => handle_jwt_export_jwks(&args),
    }
}

fn handle_jwt_keygen(args: &JwtKeygenArgs) -> CliResult<()> {
    let key = Ed25519KeyPair::generate(args.kid.clone())?;
    write_jwt_key_file(&args.out, &key)?;
    if let Some(path) = args.public_out.as_deref() {
        write_json_pretty(path, &key.to_jwk())?;
    }
    if let Some(path) = args.jwks_out.as_deref() {
        let jwks = Jwks {
            keys: vec![key.to_jwk()],
        };
        write_json_pretty(path, &jwks)?;
    }
    println!(
        "jwt anahtarı üretildi: kid={} | secret={}{}{}",
        key.kid(),
        args.out.display(),
        args.public_out
            .as_ref()
            .map(|p| format!(" | public={}", p.display()))
            .unwrap_or_default(),
        args.jwks_out
            .as_ref()
            .map(|p| format!(" | jwks={}", p.display()))
            .unwrap_or_default()
    );
    Ok(())
}

fn handle_jwt_sign(args: &JwtSignArgs) -> CliResult<()> {
    let key = load_jwt_keypair(&args.key)?;
    let mut claims = build_claims_from_args(args)?;
    if args.jti.is_none() {
        claims.ensure_jwt_id();
    }
    let signer = JwtSigner::new(key.clone());
    let token = signer.sign(&claims)?;
    fs::write(&args.out, token.as_bytes())?;
    println!(
        "jwt imzalandı: kid={} | jti={} | out={} | exp={:?}",
        key.kid(),
        claims.jwt_id.as_deref().unwrap_or("<none>"),
        args.out.display(),
        claims.expiration
    );
    Ok(())
}

fn handle_jwt_verify(args: &JwtVerifyArgs) -> CliResult<()> {
    let keys = load_verification_keys(args)?;
    if keys.is_empty() {
        return Err(CliError::MissingJwtMaterial);
    }
    let mut verifier = JwtVerifier::new(keys);
    if let Some(leeway) = args.leeway {
        verifier = verifier.with_leeway(leeway);
    }
    if let Some(path) = args.sqlite_store.as_deref() {
        let store = SqliteJtiStore::open(path)?;
        verifier = verifier.with_store(Arc::new(store));
    }
    let token_raw = fs::read_to_string(&args.token)?;
    let token = token_raw.trim();
    let options = VerificationOptions {
        issuer: args.issuer.clone(),
        subject: args.subject.clone(),
        audience: args.audience.clone(),
        require_jti: !args.allow_missing_jti,
        now: None,
    };
    let claims = verifier.verify(token, &options)?;
    if let Some(out) = args.claims_out.as_deref() {
        write_json_pretty(out, &claims)?;
        println!(
            "jwt doğrulandı: token={} | jti={} | claims={}",
            args.token.display(),
            claims.jwt_id.as_deref().unwrap_or("<none>"),
            out.display(),
        );
    } else {
        let json = serde_json::to_string_pretty(&claims)?;
        println!("{json}");
    }
    Ok(())
}

fn handle_jwt_export_jwks(args: &JwtExportJwksArgs) -> CliResult<()> {
    let mut jwk_map = std::collections::BTreeMap::new();
    for path in &args.key_files {
        let key = load_jwt_keypair(path)?;
        jwk_map.insert(key.kid().to_string(), key.to_jwk());
    }
    for path in &args.jwk_files {
        let jwk: Jwk = read_json_file(path)?;
        jwk_map.insert(jwk.kid.clone(), jwk);
    }
    if jwk_map.is_empty() {
        return Err(CliError::MissingJwtMaterial);
    }
    let jwks = Jwks {
        keys: jwk_map.into_values().collect(),
    };
    write_json_pretty(&args.out, &jwks)?;
    println!(
        "jwks üretildi: anahtar_sayısı={} | çıktı={}",
        jwks.keys.len(),
        args.out.display(),
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct MetadataFile {
    metadata: SessionMetadata,
}

#[derive(Serialize, Deserialize)]
struct PersistedRatchet {
    session_id: String,
    root_key: String,
    message_no: u64,
    strict: bool,
}

impl PersistedRatchet {
    fn from_state(state: &SessionRatchetState) -> Self {
        Self {
            session_id: STANDARD.encode(state.session_id),
            root_key: STANDARD.encode(state.root_key),
            message_no: state.message_no,
            strict: state.strict,
        }
    }

    fn to_state(&self) -> CliResult<SessionRatchetState> {
        let session_id = decode_fixed::<16>(&self.session_id, "session-id")?;
        let root_key = decode_fixed::<32>(&self.root_key, "ratchet-root")?;
        Ok(SessionRatchetState::new(
            root_key,
            session_id,
            self.message_no,
            self.strict,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedReplayStore {
    session_id: String,
    #[serde(default)]
    seen: BTreeSet<u64>,
}

#[derive(Serialize, Deserialize)]
struct JwtKeyMaterial {
    kid: String,
    seed: String,
}

fn load_metadata_file(path: &Path) -> CliResult<SessionMetadata> {
    let json = fs::read_to_string(path)?;
    let file: MetadataFile = serde_json::from_str(&json)?;
    ensure_metadata_ready(&file.metadata)?;
    Ok(file.metadata)
}

fn write_metadata_file(path: &Path, metadata: &SessionMetadata) -> CliResult<()> {
    ensure_metadata_ready(metadata)?;
    let payload = MetadataFile {
        metadata: metadata.clone(),
    };
    write_json_pretty(path, &payload)?;
    Ok(())
}

#[allow(clippy::missing_const_for_fn)]
fn ensure_metadata_ready(metadata: &SessionMetadata) -> CliResult<()> {
    if metadata.coord_id.is_none() {
        return Err(CliError::Metadata("coord_id"));
    }
    if metadata.coord.is_none() {
        return Err(CliError::Metadata("coord"));
    }
    Ok(())
}

fn load_or_initialize_ratchet(
    state_path: &Path,
    strict: bool,
    ratchet_root: Option<&str>,
    session_id: Option<&str>,
) -> CliResult<SessionRatchet> {
    if state_path.exists() {
        let json = fs::read_to_string(state_path)?;
        let persisted: PersistedRatchet = serde_json::from_str(&json)?;
        let state = persisted.to_state()?;
        if let Some(expected) = session_id {
            let expected_id = decode_fixed::<16>(expected, "session-id")?;
            if expected_id != state.session_id {
                return Err(CliError::StateSessionMismatch);
            }
        }
        if state.strict != strict {
            return Err(CliError::StateStrictMismatch);
        }
        Ok(SessionRatchet::from_state(state))
    } else {
        let root = ratchet_root.ok_or(CliError::MissingParam("ratchet-root"))?;
        let session = session_id.ok_or(CliError::MissingParam("session-id"))?;
        let root_key = decode_fixed::<32>(root, "ratchet-root")?;
        let session_bytes = decode_fixed::<16>(session, "session-id")?;
        let state = SessionRatchetState::new(root_key, session_bytes, 0, strict);
        let ratchet = SessionRatchet::from_state(state);
        save_ratchet_state(state_path, &ratchet)?;
        Ok(ratchet)
    }
}

fn save_ratchet_state(path: &Path, ratchet: &SessionRatchet) -> CliResult<()> {
    let state = ratchet.export_state();
    let persisted = PersistedRatchet::from_state(&state);
    write_json_pretty(path, &persisted)
}

fn load_replay_store(path: &Path, session_id_b64: &str) -> CliResult<PersistedReplayStore> {
    if path.exists() {
        let json = fs::read_to_string(path)?;
        let store: PersistedReplayStore = serde_json::from_str(&json)?;
        if store.session_id != session_id_b64 {
            return Err(CliError::StoreSessionMismatch);
        }
        Ok(store)
    } else {
        Ok(PersistedReplayStore {
            session_id: session_id_b64.to_owned(),
            seen: BTreeSet::new(),
        })
    }
}

fn save_replay_store(path: &Path, store: &PersistedReplayStore) -> CliResult<()> {
    write_json_pretty(path, store)
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> CliResult<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json.as_bytes())?;
    Ok(())
}

fn decode_fixed<const N: usize>(value: &str, context: &'static str) -> CliResult<[u8; N]> {
    let bytes = STANDARD.decode(value.trim())?;
    if bytes.len() != N {
        return Err(CliError::InvalidLength {
            context,
            expected: N,
            actual: bytes.len(),
        });
    }
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn load_aad(aad_text: Option<&str>, aad_file: Option<&Path>) -> CliResult<Vec<u8>> {
    match (aad_text, aad_file) {
        (Some(_), Some(_)) => Err(CliError::AadConflict),
        (Some(text), None) => Ok(text.as_bytes().to_vec()),
        (None, Some(path)) => Ok(fs::read(path)?),
        (None, None) => Ok(Vec::new()),
    }
}

fn decode_org_salt(value: &str) -> CliResult<Vec<u8>> {
    Ok(STANDARD.decode(value.trim())?)
}

struct KemFields {
    kem_name: String,
    pk: Option<Vec<u8>>,
    ctkem: Option<Vec<u8>>,
    rbkem: Option<Vec<u8>>,
    ss: Option<Vec<u8>>,
}

impl KemFields {
    fn as_payload(&self) -> KemPayload<'_> {
        KemPayload {
            kem: &self.kem_name,
            pk: self.pk.as_deref(),
            ctkem: self.ctkem.as_deref(),
            rbkem: self.rbkem.as_deref(),
            ss: self.ss.as_deref(),
        }
    }
}

fn build_kem_fields(
    kem_name: Option<&str>,
    pk: Option<&str>,
    ctkem: Option<&str>,
    rbkem: Option<&str>,
    ss: Option<&str>,
) -> CliResult<Option<KemFields>> {
    let name = kem_name.unwrap_or("none").to_ascii_lowercase();
    if name == "none" {
        return Ok(None);
    }
    let decode_opt = |input: Option<&str>| -> CliResult<Option<Vec<u8>>> {
        input
            .map(|val| STANDARD.decode(val.trim()).map_err(CliError::from))
            .transpose()
    };

    Ok(Some(KemFields {
        kem_name: name,
        pk: decode_opt(pk)?,
        ctkem: decode_opt(ctkem)?,
        rbkem: decode_opt(rbkem)?,
        ss: decode_opt(ss)?,
    }))
}

fn derive_salts(org_salt: &[u8], calibration_id: &str) -> CliResult<(Zeroizing<Vec<u8>>, Salts)> {
    let hk = Hkdf::<Sha256>::new(Some(org_salt), calibration_id.as_bytes());
    let mut password_salt = Zeroizing::new(vec![0_u8; 32]);
    let mut calibration_salt = vec![0_u8; 32];
    let mut chain_salt = vec![0_u8; 32];
    let mut coord_salt = vec![0_u8; 32];

    hk.expand(b"Aunsorm/1.01/password-salt", password_salt.as_mut())
        .map_err(|_| CliError::Hkdf)?;
    hk.expand(b"Aunsorm/1.01/calibration-salt", &mut calibration_salt)
        .map_err(|_| CliError::Hkdf)?;
    hk.expand(b"Aunsorm/1.01/chain-salt", &mut chain_salt)
        .map_err(|_| CliError::Hkdf)?;
    hk.expand(b"Aunsorm/1.01/coord-salt", &mut coord_salt)
        .map_err(|_| CliError::Hkdf)?;

    let salts = Salts::new(calibration_salt, chain_salt, coord_salt)?;
    Ok((password_salt, salts))
}

fn env_strict() -> bool {
    matches!(
        std::env::var("AUNSORM_STRICT")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1" | "true" | "TRUE" | "on" | "ON")
    )
}

fn write_jwt_key_file(path: &Path, key: &Ed25519KeyPair) -> CliResult<()> {
    let material = JwtKeyMaterial {
        kid: key.kid().to_string(),
        seed: STANDARD.encode(key.signing_key().to_bytes()),
    };
    write_json_pretty(path, &material)
}

fn load_jwt_keypair(path: &Path) -> CliResult<Ed25519KeyPair> {
    let material: JwtKeyMaterial = read_json_file(path)?;
    if material.kid.trim().is_empty() {
        return Err(CliError::JwtKeyFile("kid alanı boş"));
    }
    let seed = Zeroizing::new(STANDARD.decode(material.seed.trim())?);
    if seed.len() != 32 {
        return Err(CliError::InvalidLength {
            context: "jwt seed",
            expected: 32,
            actual: seed.len(),
        });
    }
    let mut buf = [0_u8; 32];
    buf.copy_from_slice(&seed);
    Ok(Ed25519KeyPair::from_seed(material.kid, buf)?)
}

fn build_claims_from_args(args: &JwtSignArgs) -> CliResult<Claims> {
    let mut claims = Claims::new();
    claims.issuer.clone_from(&args.issuer);
    claims.subject.clone_from(&args.subject);
    if !args.audience.is_empty() {
        claims.audience = Some(if args.audience.len() == 1 {
            Audience::Single(args.audience[0].clone())
        } else {
            Audience::Multiple(args.audience.clone())
        });
    }
    if let Some(ttl) = args.expires_in {
        claims.set_expiration_from_now(ttl);
    }
    if let Some(offset) = args.not_before_in {
        claims.not_before = Some(SystemTime::now() + offset);
    }
    if !args.no_issued_at {
        claims.set_issued_now();
    }
    if let Some(jti) = &args.jti {
        claims.jwt_id = Some(jti.clone());
    }
    if let Some(path) = args.claims.as_deref() {
        merge_extra_claims(&mut claims, path)?;
    }
    Ok(claims)
}

fn merge_extra_claims(claims: &mut Claims, path: &Path) -> CliResult<()> {
    let value: Value = read_json_file(path)?;
    let map = value
        .as_object()
        .ok_or(CliError::JwtClaimsFile("JSON object bekleniyordu"))?;
    for (key, val) in map {
        match key.as_str() {
            "iss" | "sub" | "aud" | "exp" | "nbf" | "iat" | "jti" => {
                return Err(CliError::ClaimReserved(key.clone()))
            }
            _ => {
                claims.extra.insert(key.clone(), val.clone());
            }
        }
    }
    Ok(())
}

fn load_verification_keys(args: &JwtVerifyArgs) -> CliResult<Vec<Ed25519PublicKey>> {
    let mut map: BTreeMap<String, Ed25519PublicKey> = BTreeMap::new();
    for path in &args.jwks_files {
        let jwks: Jwks = read_json_file(path)?;
        for jwk in jwks.keys {
            let key = Ed25519PublicKey::from_jwk(&jwk)?;
            map.insert(jwk.kid.clone(), key);
        }
    }
    for path in &args.jwk_files {
        let jwk: Jwk = read_json_file(path)?;
        let key = Ed25519PublicKey::from_jwk(&jwk)?;
        map.insert(jwk.kid.clone(), key);
    }
    for path in &args.key_files {
        let key = load_jwt_keypair(path)?;
        map.insert(key.kid().to_string(), key.public_key());
    }
    Ok(map.into_values().collect())
}

fn read_json_file<T>(path: &Path) -> CliResult<T>
where
    T: DeserializeOwned,
{
    let data = fs::read(path)?;
    Ok(serde_json::from_slice(&data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aunsorm_packet::{AeadAlgorithm, HeaderKem, HeaderProfile, HeaderSalts};
    use tempfile::NamedTempFile;

    #[test]
    fn salts_are_deterministic() {
        let org = STANDARD.decode("V2VBcmVLdXQuZXU=").expect("org salt");
        let (calibration, _) = calib_from_text(&org, "demo calib");
        let (pwd_a, salts_a) = derive_salts(&org, calibration.id.as_str()).expect("salts");
        let (pwd_b, salts_b) = derive_salts(&org, calibration.id.as_str()).expect("salts");
        assert_eq!(pwd_a.as_slice(), pwd_b.as_slice());
        assert_eq!(salts_a, salts_b);
    }

    #[test]
    fn aad_conflict_is_rejected() {
        let err = load_aad(Some("demo"), Some(Path::new("/tmp/demo"))).unwrap_err();
        assert!(matches!(err, CliError::AadConflict));
    }

    #[test]
    fn metadata_roundtrip() {
        let metadata = SessionMetadata {
            version: "1.01".to_string(),
            profile: HeaderProfile {
                t: 2,
                m_kib: 32,
                p: 1,
            },
            calib_id: "calib".to_string(),
            coord_digest: "digest".to_string(),
            coord_id: Some("coord-123".to_string()),
            coord: Some([7_u8; 32]),
            salts: HeaderSalts {
                password: "pw".to_string(),
                calibration: "cal".to_string(),
                chain: "chain".to_string(),
                coord: "coord".to_string(),
            },
            kem: HeaderKem::none(),
            algorithm: AeadAlgorithm::AesGcm,
        };
        let file = NamedTempFile::new().expect("tmp");
        write_metadata_file(file.path(), &metadata).expect("write");
        let loaded = load_metadata_file(file.path()).expect("load");
        assert_eq!(loaded, metadata);
    }

    #[test]
    fn ratchet_state_is_persisted() {
        let mut ratchet = SessionRatchet::new([9_u8; 32], [4_u8; 16], false);
        let _ = ratchet.next_step().expect("step");
        let file = NamedTempFile::new().expect("tmp");
        save_ratchet_state(file.path(), &ratchet).expect("save");
        let restored = load_or_initialize_ratchet(file.path(), false, None, None).expect("load");
        assert_eq!(restored.message_no(), ratchet.message_no());
    }

    #[test]
    fn decode_fixed_detects_length() {
        let err = decode_fixed::<4>("AA==", "test").unwrap_err();
        assert!(matches!(err, CliError::InvalidLength { .. }));
    }

    #[test]
    fn jwt_key_file_roundtrip() {
        let key = Ed25519KeyPair::generate("cli-test").expect("key");
        let file = NamedTempFile::new().expect("tmp");
        write_jwt_key_file(file.path(), &key).expect("write");
        let loaded = load_jwt_keypair(file.path()).expect("load");
        assert_eq!(loaded.kid(), key.kid());
    }

    #[test]
    fn jwt_extra_claims_rejects_reserved() {
        let file = NamedTempFile::new().expect("tmp");
        fs::write(file.path(), "{\"iss\":\"demo\"}").expect("write");
        let mut claims = Claims::new();
        let err = merge_extra_claims(&mut claims, file.path()).unwrap_err();
        assert!(matches!(err, CliError::ClaimReserved(_)));
    }

    #[test]
    fn jwt_sign_verify_roundtrip() {
        let key = Ed25519KeyPair::generate("cli-flow").expect("key");
        let key_file = NamedTempFile::new().expect("key file");
        write_jwt_key_file(key_file.path(), &key).expect("write key");

        let token_file = NamedTempFile::new().expect("token file");
        let sign_args = JwtSignArgs {
            key: key_file.path().to_path_buf(),
            out: token_file.path().to_path_buf(),
            issuer: Some("aunsorm".to_string()),
            subject: Some("user-123".to_string()),
            audience: vec!["cli".to_string()],
            expires_in: Some(Duration::from_secs(60)),
            not_before_in: None,
            no_issued_at: false,
            jti: None,
            claims: None,
        };
        handle_jwt_sign(&sign_args).expect("sign");

        let claims_out = NamedTempFile::new().expect("claims");
        let verify_args = JwtVerifyArgs {
            token: token_file.path().to_path_buf(),
            jwks_files: Vec::new(),
            jwk_files: Vec::new(),
            key_files: vec![key_file.path().to_path_buf()],
            claims_out: Some(claims_out.path().to_path_buf()),
            issuer: Some("aunsorm".to_string()),
            subject: Some("user-123".to_string()),
            audience: Some("cli".to_string()),
            allow_missing_jti: false,
            leeway: None,
            sqlite_store: None,
        };
        handle_jwt_verify(&verify_args).expect("verify");

        let claims_json = fs::read_to_string(claims_out.path()).expect("read claims");
        let claims: Claims = serde_json::from_str(&claims_json).expect("claims json");
        assert_eq!(claims.issuer.as_deref(), Some("aunsorm"));
        assert!(claims.jwt_id.is_some());
    }
}
