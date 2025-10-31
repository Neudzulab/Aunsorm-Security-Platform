#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

mod rng;

use crate::rng::AunsormNativeRng;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as _;
use std::fs;
use std::io::{self, Write as _};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hkdf::Hkdf;
use http::{header::LOCATION, HeaderMap, HeaderName, HeaderValue, StatusCode};
use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use ureq::{Agent, Error as UreqError};
use url::Url;
use zeroize::Zeroizing;

use aunsorm_acme::{
    AccountContact, AccountContactError, AcmeDirectory, AcmeDirectoryError, AcmeJws,
    Ed25519AccountKey, JwsError, KeyBinding, NewAccountRequest, NewNonceRequester, NewOrderError,
    NewOrderRequest, NonceError, NonceManager, NonceManagerError, NonceRequestError, ReplayNonce,
    REPLAY_NONCE_HEADER,
};
use aunsorm_core::{
    calib_from_text, coord32_derive, derive_seed64_and_pdk, salts::Salts, Calibration, KdfInfo,
    KdfPreset, KdfProfile, SessionRatchet, SessionRatchetState,
};
use aunsorm_jwt::SqliteJtiStore;
use aunsorm_jwt::{
    Audience, Claims, Ed25519KeyPair, Ed25519PublicKey, Jwk, Jwks, JwtSigner, JwtVerifier,
    VerificationOptions,
};
use aunsorm_kms::{
    BackendKind as KmsBackendKind, BackendLocator as KmsBackendLocator,
    KeyDescriptor as KmsKeyDescriptor, KmsClient, KmsConfig,
};
use aunsorm_packet::{
    decrypt_one_shot, decrypt_session, encrypt_one_shot, encrypt_session, peek_header,
    AeadAlgorithm, DecryptParams, EncryptParams, KemPayload, SessionDecryptParams,
    SessionEncryptParams, SessionMetadata, SessionStore,
};
use aunsorm_pqc::{
    kem::KemAlgorithm,
    signature::{SignatureAlgorithm, SignatureChecklist},
    strict::StrictMode,
};
use aunsorm_x509::{
    automation::{CaAutomationProfile, CaBundle, CaBundleEntry},
    ca::{
        generate_root_ca, issue_intermediate_ca, IntermediateCaParams as X509IntermediateCaParams,
        RootCaParams as X509RootCaParams,
    },
    compute_key_identifier, deterministic_serial_hex,
    generate_self_signed as generate_self_signed_cert, prepare_local_https_params,
    LocalHttpsCertParams as X509LocalHttpsParams, SelfSignedCertParams as X509SelfSignedParams,
    SubjectAltName as X509SubjectAltName,
};
use endpoint_validator::{validate, AllowlistedFailure, Auth as EndpointAuth, ValidatorConfig};
use tokio::runtime::Runtime;

/// Environment-aware default URL for Aunsorm server
fn default_server_url() -> String {
    if let Ok(url) = std::env::var("AUNSORM_SERVER_URL") {
        return url;
    }

    if let Ok(host) = std::env::var("HOST") {
        return host_to_server_url(&host);
    }

    "http://localhost:8080".to_string()
}

fn host_to_server_url(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return "http://localhost:8080".to_string();
    }

    match trimmed.parse::<IpAddr>() {
        Ok(IpAddr::V6(addr)) => format!("http://[{addr}]:8080"),
        _ => format!("http://{trimmed}:8080"),
    }
}

/// Environment-aware default hostname
fn default_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "localhost".to_string())
}

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
    /// Kalibrasyon parametrelerini görüntüle
    #[command(subcommand)]
    Calib(CalibCommands),
    /// Oturum mesajını şifrele
    #[command(name = "session-encrypt")]
    SessionEncrypt(SessionEncryptArgs),
    /// Oturum mesajını çöz
    #[command(name = "session-decrypt")]
    SessionDecrypt(SessionDecryptArgs),
    /// PQC hazır olma durumunu raporla
    #[command(subcommand)]
    Pq(PqCommands),
    /// JWT işlemleri
    #[command(subcommand)]
    Jwt(JwtCommands),
    /// X.509 işlemleri
    #[command(subcommand)]
    X509(X509Commands),
    /// ACME otomasyon komutları
    #[command(subcommand)]
    Acme(AcmeCommands),
    /// Uzak API uçlarını doğrula
    #[command(name = "validate-endpoints")]
    ValidateEndpoints(EndpointValidatorArgs),
}

#[derive(Subcommand)]
enum CalibCommands {
    /// Kalibrasyon metninden deterministik parametre üret
    Inspect(CalibInspectArgs),
    /// Koordinat kimliğini ve değerini türet
    #[command(name = "derive-coord")]
    DeriveCoord(CalibCoordArgs),
    /// Kalibrasyon parmak izini raporla
    Fingerprint(CalibFingerprintArgs),
    /// Kalibrasyon kimliğini ve parmak izini doğrula
    Verify(CalibVerifyArgs),
}

#[derive(Subcommand)]
enum PqCommands {
    /// PQC hazır olma durumunu görüntüle
    Status(PqStatusArgs),
    /// İmza algoritmaları için sertleştirme kontrol listesi
    Checklist(PqChecklistArgs),
}

#[derive(Args)]
struct PqStatusArgs {
    /// Çıktı formatı (text veya json)
    #[arg(long, value_enum, default_value_t = PqStatusFormat::Text)]
    format: PqStatusFormat,
}

#[derive(Args)]
struct PqChecklistArgs {
    /// İncelenecek PQC imza algoritması
    #[arg(long, value_enum, default_value_t = SignatureAlgorithmArg::MlDsa65)]
    algorithm: SignatureAlgorithmArg,
    /// Çıktı formatı (text veya json)
    #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
    format: ReportFormat,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum PqStatusFormat {
    /// Metin tabanlı çıktı
    Text,
    /// JSON çıktısı
    Json,
}

impl Default for PqStatusFormat {
    fn default() -> Self {
        Self::Text
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum SignatureAlgorithmArg {
    #[value(alias = "ml-dsa-65")]
    MlDsa65,
    #[value(alias = "falcon-512")]
    Falcon512,
    #[value(alias = "sphincs-shake-128f", alias = "sphincs+-shake-128f")]
    SphincsShake128f,
}

impl SignatureAlgorithmArg {
    const fn to_algorithm(self) -> SignatureAlgorithm {
        match self {
            Self::MlDsa65 => SignatureAlgorithm::MlDsa65,
            Self::Falcon512 => SignatureAlgorithm::Falcon512,
            Self::SphincsShake128f => SignatureAlgorithm::SphincsShake128f,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ReportFormat {
    /// JSON çıktısı
    Json,
    /// Metin tabanlı çıktı
    Text,
}

impl Default for ReportFormat {
    fn default() -> Self {
        Self::Json
    }
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

#[derive(Subcommand)]
enum X509Commands {
    /// Ed25519 öz-imzalı sertifika üret
    #[command(name = "self-signed")]
    SelfSigned(X509SelfSignedArgs),
    /// Yerel HTTPS geliştirme sertifikası üret (SAN uzantıları dahil)
    #[command(name = "local-dev")]
    LocalDev(X509LocalDevArgs),
    /// CA otomasyon komutları
    #[command(subcommand)]
    Ca(X509CaCommands),
}

#[derive(Subcommand)]
enum AcmeCommands {
    /// ACME directory belgesini keşfet ve özeti göster
    Directory(AcmeDirectoryArgs),
    /// ACME hesabı oluştur veya mevcut hesabı sorgula
    Register(AcmeRegisterArgs),
    /// Yeni bir ACME order'ı başlat
    Order(AcmeOrderArgs),
    /// Mevcut ACME order'ını CSR ile finalize et
    Finalize(AcmeFinalizeArgs),
    /// Son ACME order'ı için sertifika paketini indir
    #[command(name = "fetch-cert")]
    FetchCert(AcmeFetchCertArgs),
    /// Yayınlanan sertifika zincirini iptal et
    #[command(name = "revoke")]
    Revoke(AcmeRevokeArgs),
}

#[derive(Args)]
struct AcmeDirectoryArgs {
    /// ACME sunucu taban URL'si (ör. <http://localhost:8080>)
    #[arg(long, default_value_t = default_server_url())]
    server: String,
    /// Directory çıktısını JSON olarak yazdır
    #[arg(long)]
    json: bool,
    /// Directory JSON çıktısını dosyaya kaydet
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct AcmeRegisterArgs {
    /// ACME sunucu taban URL'si (ör. <http://localhost:8080>)
    #[arg(long, default_value_t = default_server_url())]
    server: String,
    /// Hesap durum dosyası (anahtar + meta bilgiler)
    #[arg(long, value_name = "PATH")]
    account: PathBuf,
    /// ACME hesabı için e-posta adresi
    #[arg(long = "email", value_name = "EMAIL")]
    email: Vec<String>,
    /// ACME hesabı için iletişim URI'si (ör. `mailto:dest@example.com` veya `tel:+905551234567`)
    #[arg(long = "contact", value_name = "URI")]
    contact: Vec<String>,
    /// Hizmet şartlarını kabul et
    #[arg(long)]
    accept_terms: bool,
    /// Sadece mevcut hesabı döndürmeyi talep et
    #[arg(long)]
    only_existing: bool,
}

#[derive(Args)]
struct AcmeOrderArgs {
    /// ACME sunucu taban URL'si (ör. <http://localhost:8080>)
    #[arg(long, default_value_t = default_server_url())]
    server: String,
    /// Hesap durum dosyası (anahtar + meta bilgiler)
    #[arg(long, value_name = "PATH")]
    account: PathBuf,
    /// Order'da kullanılacak DNS alan adı (birden çok kez verilebilir)
    #[arg(long = "domain", value_name = "DNS", required = true)]
    domains: Vec<String>,
    /// Order yanıtını JSON olarak dosyaya kaydet
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct AcmeFinalizeArgs {
    /// ACME sunucu taban URL'si (ör. <http://localhost:8080>)
    #[arg(long, default_value_t = default_server_url())]
    server: String,
    /// Hesap durum dosyası (anahtar + meta bilgiler)
    #[arg(long, value_name = "PATH")]
    account: PathBuf,
    /// CSR (PEM veya DER)
    #[arg(long, value_name = "PATH")]
    csr: PathBuf,
    /// Finalize yanıtını JSON olarak dosyaya kaydet
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct AcmeFetchCertArgs {
    /// ACME sunucu taban URL'si (ör. <http://localhost:8080>)
    #[arg(long, default_value_t = default_server_url())]
    server: String,
    /// Hesap durum dosyası (anahtar + meta bilgiler)
    #[arg(long, value_name = "PATH")]
    account: PathBuf,
    /// Sertifika paketinin yazılacağı dosya yolu (`-` stdout'a yazar)
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
}

#[derive(Args)]
struct AcmeRevokeArgs {
    /// ACME sunucu taban URL'si (ör. <http://localhost:8080>)
    #[arg(long, default_value_t = default_server_url())]
    server: String,
    /// Hesap durum dosyası (anahtar + meta bilgiler)
    #[arg(long, value_name = "PATH")]
    account: PathBuf,
    /// İptal edilecek sertifika (PEM veya DER; bundle ise ilk leaf kullanılır)
    #[arg(long, value_name = "PATH")]
    certificate: PathBuf,
    /// Opsiyonel CRL reason kodu (0-10 arası, RFC 5280)
    #[arg(
        long,
        value_name = "CODE",
        value_parser = clap::value_parser!(u8).range(0..=10)
    )]
    reason: Option<u8>,
}

#[derive(Args)]
struct EndpointValidatorArgs {
    /// Test edilecek API taban URL'si (örn. <https://api.example.com>)
    #[arg(long, value_name = "URL")]
    base_url: String,
    /// Authorization başlığına Bearer token ekle
    #[arg(long, value_name = "TOKEN")]
    auth_bearer: Option<String>,
    /// Authorization başlığına Basic kimlik bilgisi ekle (`kullanici:sifre`)
    #[arg(long, value_name = "KULLANICI:SIFRE")]
    auth_basic: Option<String>,
    /// İsteklere eklenecek ekstra HTTP başlığı (`--header "X-Key: value"`)
    #[arg(long = "header", value_name = "AD:DEGER")]
    headers: Vec<String>,
    /// Keşif sürecine dahil edilecek yol
    #[arg(long = "seed", value_name = "YOL")]
    seeds: Vec<String>,
    /// Aynı anda gönderilecek maksimum istek sayısı
    #[arg(long, default_value_t = 4)]
    concurrency: usize,
    /// Saniye başına istek kotası (ayarlanmazsa sınırsız)
    #[arg(long)]
    rate_limit_per_second: Option<u32>,
    /// POST/PUT/DELETE gibi yıkıcı metodları da çalıştır
    #[arg(long)]
    include_destructive: bool,
    /// Allowlist JSON dosyası (bilinen hatalar)
    #[arg(long, value_name = "PATH")]
    allowlist: Option<PathBuf>,
    /// Markdown rapor dosyası
    #[arg(long, value_name = "PATH")]
    markdown_report: Option<PathBuf>,
    /// JSON sonuç dosyası
    #[arg(long, value_name = "PATH")]
    json_output: Option<PathBuf>,
    /// İstek zaman aşımı (saniye)
    #[arg(long, default_value_t = 10)]
    timeout_secs: u64,
    /// Yeniden deneme sayısı
    #[arg(long, default_value_t = 2)]
    retries: usize,
    /// İlk geri çekilme süresi (ms)
    #[arg(long, default_value_t = 500)]
    backoff_ms: u64,
}

#[derive(Args)]
struct EncryptArgs {
    /// Parola (veya --password-file kullanın)
    #[arg(
        long,
        conflicts_with = "password_file",
        required_unless_present = "password_file"
    )]
    password: Option<String>,
    /// Parolayı dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "password",
        required_unless_present = "password"
    )]
    password_file: Option<PathBuf>,
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
    #[arg(
        long,
        conflicts_with = "calib_file",
        required_unless_present = "calib_file"
    )]
    calib_text: Option<String>,
    /// Kalibrasyon metnini dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "calib_text",
        required_unless_present = "calib_text"
    )]
    calib_file: Option<PathBuf>,
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
    /// Parola (veya --password-file kullanın)
    #[arg(
        long,
        conflicts_with = "password_file",
        required_unless_present = "password_file"
    )]
    password: Option<String>,
    /// Parolayı dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "password",
        required_unless_present = "password"
    )]
    password_file: Option<PathBuf>,
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
    #[arg(
        long,
        conflicts_with = "calib_file",
        required_unless_present = "calib_file"
    )]
    calib_text: Option<String>,
    /// Kalibrasyon metnini dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "calib_text",
        required_unless_present = "calib_text"
    )]
    calib_file: Option<PathBuf>,
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
struct CalibInspectArgs {
    /// Organizasyon tuzu (Base64)
    #[arg(long, value_name = "B64")]
    org_salt: String,
    /// Kalibrasyon metni
    #[arg(
        long,
        conflicts_with = "calib_file",
        required_unless_present = "calib_file"
    )]
    calib_text: Option<String>,
    /// Kalibrasyon metnini dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "calib_text",
        required_unless_present = "calib_text"
    )]
    calib_file: Option<PathBuf>,
    /// Çıktı formatı (text veya json)
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    format: ReportFormat,
    /// Çıktıyı dosyaya yaz
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct CalibFingerprintArgs {
    /// Organizasyon tuzu (Base64)
    #[arg(long, value_name = "B64")]
    org_salt: String,
    /// Kalibrasyon metni
    #[arg(
        long,
        conflicts_with = "calib_file",
        required_unless_present = "calib_file"
    )]
    calib_text: Option<String>,
    /// Kalibrasyon metnini dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "calib_text",
        required_unless_present = "calib_text"
    )]
    calib_file: Option<PathBuf>,
    /// Çıktı formatı (text veya json)
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    format: ReportFormat,
    /// Çıktıyı dosyaya yaz
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct CalibVerifyArgs {
    /// Organizasyon tuzu (Base64)
    #[arg(long, value_name = "B64")]
    org_salt: String,
    /// Kalibrasyon metni
    #[arg(
        long,
        conflicts_with = "calib_file",
        required_unless_present = "calib_file"
    )]
    calib_text: Option<String>,
    /// Kalibrasyon metnini dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "calib_text",
        required_unless_present = "calib_text"
    )]
    calib_file: Option<PathBuf>,
    /// Beklenen kalibrasyon kimliği
    #[arg(long, value_name = "ID")]
    expect_id: Option<String>,
    /// Beklenen parmak izi (Base64, URL-safe, padding'siz)
    #[arg(long, value_name = "B64")]
    expect_fingerprint_b64: Option<String>,
    /// Beklenen parmak izi (hex, küçük harf)
    #[arg(long, value_name = "HEX")]
    expect_fingerprint_hex: Option<String>,
    /// Çıktı formatı (text veya json)
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    format: ReportFormat,
    /// Çıktıyı dosyaya yaz
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct CalibCoordArgs {
    /// Parola (veya --password-file kullanın)
    #[arg(
        long,
        conflicts_with = "password_file",
        required_unless_present = "password_file"
    )]
    password: Option<String>,
    /// Parolayı dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "password",
        required_unless_present = "password"
    )]
    password_file: Option<PathBuf>,
    /// Organizasyon tuzu (Base64)
    #[arg(long, value_name = "B64")]
    org_salt: String,
    /// Kalibrasyon metni
    #[arg(
        long,
        conflicts_with = "calib_file",
        required_unless_present = "calib_file"
    )]
    calib_text: Option<String>,
    /// Kalibrasyon metnini dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "calib_text",
        required_unless_present = "calib_text"
    )]
    calib_file: Option<PathBuf>,
    /// KDF profili
    #[arg(long, default_value = "medium")]
    kdf: ProfileArg,
    /// Çıktı formatı (text veya json)
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    format: ReportFormat,
    /// Çıktıyı dosyaya yaz
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
    /// Türetilen koordinat değerini ham bayt olarak yaz
    #[arg(long = "coord-raw-out", value_name = "PATH")]
    coord_raw_out: Option<PathBuf>,
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
    #[arg(long, value_name = "PATH", conflicts_with = "kms_backend")]
    key: Option<PathBuf>,
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
    /// KMS backend türü
    #[arg(long, value_enum, conflicts_with = "key")]
    kms_backend: Option<KmsBackendArg>,
    /// KMS anahtar kimliği
    #[arg(long, value_name = "ID", requires = "kms_backend")]
    kms_key_id: Option<String>,
    /// Fallback backend türü
    #[arg(long, value_enum, requires_all = ["kms_backend", "kms_key_id"])]
    kms_fallback_backend: Option<KmsBackendArg>,
    /// Fallback anahtar kimliği
    #[arg(long, value_name = "ID", requires = "kms_fallback_backend")]
    kms_fallback_key_id: Option<String>,
    /// Yerel KMS store dosyası
    #[arg(long, value_name = "PATH", requires = "kms_backend")]
    kms_store: Option<PathBuf>,
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

#[derive(Args)]
struct X509SelfSignedArgs {
    /// Sertifika ortak adı (CN)
    #[arg(long)]
    common_name: String,
    /// Kalibrasyon metni
    #[arg(
        long,
        conflicts_with = "calib_file",
        required_unless_present = "calib_file"
    )]
    calib_text: Option<String>,
    /// Kalibrasyon metnini dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "calib_text",
        required_unless_present = "calib_text"
    )]
    calib_file: Option<PathBuf>,
    /// Organizasyon tuzu (Base64)
    #[arg(long, value_name = "B64")]
    org_salt: String,
    /// Sertifika çıktısı (PEM)
    #[arg(long, value_name = "PATH")]
    cert_out: PathBuf,
    /// Özel anahtar çıktısı (PEM)
    #[arg(long, value_name = "PATH")]
    key_out: PathBuf,
    /// CPS URI değerleri
    #[arg(long = "cps", value_name = "URI")]
    cps: Vec<String>,
    /// Politika OID değerleri
    #[arg(long = "policy-oid", value_name = "OID")]
    policy_oids: Vec<String>,
    /// Geçerlilik süresi (gün)
    #[arg(long, value_name = "DAYS", default_value_t = 365)]
    validity_days: u32,
}

#[derive(Args)]
struct X509LocalDevArgs {
    /// Sertifika ortak adı ve varsayılan DNS SAN girdisi (Subject Alternative Name)
    #[arg(long, default_value_t = default_hostname())]
    hostname: String,
    /// Kalibrasyon metni
    #[arg(
        long,
        conflicts_with = "calib_file",
        required_unless_present = "calib_file"
    )]
    calib_text: Option<String>,
    /// Kalibrasyon metnini dosyadan oku (satır sonu otomatik kırpılır)
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "calib_text",
        required_unless_present = "calib_text"
    )]
    calib_file: Option<PathBuf>,
    /// Organizasyon tuzu (Base64)
    #[arg(long, value_name = "B64")]
    org_salt: String,
    /// Sertifika çıktısı (PEM)
    #[arg(long, value_name = "PATH")]
    cert_out: PathBuf,
    /// Özel anahtar çıktısı (PEM)
    #[arg(long, value_name = "PATH")]
    key_out: PathBuf,
    /// CPS URI değerleri
    #[arg(long = "cps", value_name = "URI")]
    cps: Vec<String>,
    /// Politika OID değerleri
    #[arg(long = "policy-oid", value_name = "OID")]
    policy_oids: Vec<String>,
    /// Ek DNS Subject Alternative Name girdileri
    #[arg(long = "extra-dns", value_name = "DNS")]
    extra_dns: Vec<String>,
    /// Ek IP Subject Alternative Name girdileri
    #[arg(long = "extra-ip", value_name = "IP")]
    extra_ips: Vec<String>,
    /// Geçerlilik süresi (gün)
    #[arg(long, value_name = "DAYS", default_value_t = 365)]
    validity_days: u32,
}

#[derive(Subcommand)]
enum X509CaCommands {
    /// Kök CA profilini doğrula ve sertifika üret
    Init(X509CaInitArgs),
    /// Ara CA sertifikası üret
    Issue(X509CaIssueArgs),
    /// Server sertifikasını CA ile imzala
    SignServer(X509CaSignServerArgs),
}

#[derive(Args)]
struct X509CaInitArgs {
    /// Otomasyon profili dosyası (YAML/JSON)
    #[arg(long, value_name = "PATH")]
    profile: PathBuf,
    /// Kök CA sertifika çıktısı (PEM)
    #[arg(long, value_name = "PATH")]
    cert_out: PathBuf,
    /// Kök CA özel anahtar çıktısı (PEM)
    #[arg(long, value_name = "PATH")]
    key_out: PathBuf,
    /// Anahtar algoritması (ed25519, rsa2048, rsa4096)
    #[arg(long, value_enum, default_value = "ed25519")]
    algorithm: KeyAlgorithmArg,
    /// JSON özet çıktısı (stdout için `-` kullanın)
    #[arg(long, value_name = "PATH")]
    summary_out: Option<PathBuf>,
    /// Güncellenecek CA paketi dosyası (JSON)
    #[arg(long, value_name = "PATH")]
    bundle_out: Option<PathBuf>,
}

#[derive(Args)]
struct X509CaIssueArgs {
    /// Otomasyon profili dosyası (YAML/JSON)
    #[arg(long, value_name = "PATH")]
    profile: PathBuf,
    /// Üretilecek ara profil adı
    #[arg(long, value_name = "NAME")]
    intermediate: String,
    /// İssuer sertifikası (PEM)
    #[arg(long, value_name = "PATH")]
    issuer_cert: PathBuf,
    /// İssuer özel anahtarı (PEM)
    #[arg(long, value_name = "PATH")]
    issuer_key: PathBuf,
    /// Ara CA sertifika çıktısı (PEM)
    #[arg(long, value_name = "PATH")]
    cert_out: PathBuf,
    /// Ara CA özel anahtar çıktısı (PEM)
    #[arg(long, value_name = "PATH")]
    key_out: PathBuf,
    /// JSON özet çıktısı (stdout için `-` kullanın)
    #[arg(long, value_name = "PATH")]
    summary_out: Option<PathBuf>,
    /// Güncellenecek CA paketi dosyası (JSON)
    #[arg(long, value_name = "PATH")]
    bundle_out: Option<PathBuf>,
}

#[derive(Args)]
struct X509CaSignServerArgs {
    /// CA sertifikası (PEM)
    #[arg(long, value_name = "PATH")]
    ca_cert: PathBuf,
    /// CA özel anahtarı (PEM)
    #[arg(long, value_name = "PATH")]
    ca_key: PathBuf,
    /// Sunucu hostname'i (örn: localhost, example.com)
    #[arg(long, value_name = "HOSTNAME")]
    hostname: String,
    /// Organization salt (hex formatında)
    #[arg(long, value_name = "HEX")]
    org_salt: String,
    /// Kalibrasyon metni
    #[arg(long, value_name = "TEXT")]
    calibration_text: String,
    /// Sunucu sertifika çıktısı (PEM)
    #[arg(long, value_name = "PATH")]
    cert_out: PathBuf,
    /// Sunucu özel anahtar çıktısı (PEM)
    #[arg(long, value_name = "PATH")]
    key_out: PathBuf,
    /// Ek DNS SANs (virgülle ayrılmış)
    #[arg(long, value_name = "DNS1,DNS2")]
    extra_dns: Option<String>,
    /// Ek IP SANs (virgülle ayrılmış)
    #[arg(long, value_name = "IP1,IP2")]
    extra_ip: Option<String>,
    /// Geçerlilik süresi (gün, varsayılan 365)
    #[arg(long, default_value = "365")]
    validity_days: u32,
    /// Anahtar algoritması (ed25519, rsa2048, rsa4096)
    #[arg(long, value_enum, default_value = "ed25519")]
    algorithm: KeyAlgorithmArg,
}

#[derive(Serialize, Deserialize)]
struct CaInitReport {
    profile_id: String,
    root_common_name: String,
    calibration_id: String,
    serial_hex: String,
    key_id: String,
    bundle_path: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CaIssueReport {
    profile_id: String,
    intermediate: String,
    calibration_id: String,
    serial_hex: String,
    key_id: String,
    issuer_cert: String,
    bundle_path: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum KeyAlgorithmArg {
    /// Ed25519 (modern, fast, recommended)
    Ed25519,
    /// RSA 2048-bit (legacy compatibility)
    Rsa2048,
    /// RSA 4096-bit (maximum security)
    Rsa4096,
}

impl KeyAlgorithmArg {
    const fn to_key_algorithm(self) -> aunsorm_x509::ca::KeyAlgorithm {
        use aunsorm_x509::ca::KeyAlgorithm;
        match self {
            Self::Ed25519 => KeyAlgorithm::Ed25519,
            Self::Rsa2048 => KeyAlgorithm::Rsa2048,
            Self::Rsa4096 => KeyAlgorithm::Rsa4096,
        }
    }
}

impl Default for KeyAlgorithmArg {
    fn default() -> Self {
        Self::Ed25519
    }
}

impl std::fmt::Display for KeyAlgorithmArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ed25519 => "ed25519",
            Self::Rsa2048 => "rsa2048",
            Self::Rsa4096 => "rsa4096",
        })
    }
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
    #[cfg(feature = "aes-siv")]
    #[value(alias = "AES-SIV")]
    AesSiv,
}

impl AeadArg {
    const fn as_algorithm(self) -> AeadAlgorithm {
        match self {
            Self::AesGcm => AeadAlgorithm::AesGcm,
            Self::Chacha20Poly1305 => AeadAlgorithm::Chacha20Poly1305,
            #[cfg(feature = "aes-siv")]
            Self::AesSiv => AeadAlgorithm::AesSiv,
        }
    }
}

impl std::fmt::Display for AeadArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AesGcm => "aes-gcm",
            Self::Chacha20Poly1305 => "chacha20poly1305",
            #[cfg(feature = "aes-siv")]
            Self::AesSiv => "aes-siv",
        })
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum KmsBackendArg {
    Local,
    Gcp,
    Azure,
    Pkcs11,
}

impl From<KmsBackendArg> for KmsBackendKind {
    fn from(value: KmsBackendArg) -> Self {
        match value {
            KmsBackendArg::Local => Self::Local,
            KmsBackendArg::Gcp => Self::Gcp,
            KmsBackendArg::Azure => Self::Azure,
            KmsBackendArg::Pkcs11 => Self::Pkcs11,
        }
    }
}

impl std::fmt::Display for KmsBackendArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Local => "local",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
            Self::Pkcs11 => "pkcs11",
        })
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
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
    #[error("{0} boş olamaz")]
    EmptySecret(&'static str),
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
    #[error("claim anahtarı camelCase olmalıdır: {0}")]
    ClaimInvalidFormat(String),
    #[error("jwt anahtar materyali belirtilmelidir")]
    MissingJwtMaterial,
    #[error("kms hatası: {0}")]
    Kms(#[from] aunsorm_kms::KmsError),
    #[error("claims dosyası geçersiz: {0}")]
    JwtClaimsFile(&'static str),
    #[error("x509 hatası: {0}")]
    X509(#[from] aunsorm_x509::X509Error),
    #[error("geçerlilik süresi en az 1 gün olmalıdır")]
    InvalidValidityDays,
    #[error("kalibrasyon doğrulaması başarısız")]
    ExpectationFailed,
    #[error("IP adresi parse edilemedi: {0}")]
    InvalidIpAddress(String),
    #[error("CA bundle güncellemesi için dosya yolu gerekli")]
    BundleRequiresFile,
    #[error("CA bundle dosyası bulunamadı: {0}")]
    MissingBundle(PathBuf),
    #[error("CA bundle profili uyuşmuyor: bundle={expected} | profil={actual}")]
    BundleProfileMismatch { expected: String, actual: String },
    #[error("ACME directory ayrıştırma hatası: {0}")]
    AcmeDirectory(#[from] AcmeDirectoryError),
    #[error("ACME iletişim bilgisi hatası: {0}")]
    AcmeContact(#[from] AccountContactError),
    #[error("ACME order isteği hatası: {0}")]
    AcmeOrder(#[from] NewOrderError),
    #[error("ACME nonce yöneticisi hatası: {0}")]
    AcmeNonce(#[from] NonceManagerError),
    #[error("ACME Replay-Nonce hatası: {0}")]
    AcmeNonceValue(#[from] NonceError),
    #[error("ACME JWS hatası: {0}")]
    AcmeJws(#[from] JwsError),
    #[error("ACME HTTP hatası: {message}")]
    AcmeHttp { message: String },
    #[error("ACME sunucusu problem döndürdü ({status} {problem_type}): {detail}")]
    AcmeProblem {
        status: u16,
        problem_type: String,
        detail: String,
    },
    #[error("ACME hesap durumu geçersiz: {0}")]
    AcmeState(String),
    #[error("geçersiz header değeri: {0}")]
    InvalidHeader(String),
    #[error("Geçersiz URL: {0}")]
    InvalidUrl(String),
    #[error("endpoint validator hatası: {0}")]
    EndpointValidator(String),
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

#[derive(Clone, Copy, Debug, Default)]
struct StrictContext {
    cli_flag: bool,
    env_active: bool,
}

impl StrictContext {
    #[must_use]
    const fn effective(self) -> bool {
        self.cli_flag || self.env_active
    }
}

#[derive(Copy, Clone)]
struct AlgorithmDescriptor<A> {
    algorithm: A,
    description: &'static str,
    feature: &'static str,
}

const KEM_DESCRIPTORS: &[AlgorithmDescriptor<KemAlgorithm>] = &[
    AlgorithmDescriptor {
        algorithm: KemAlgorithm::MlKem768,
        description: "ML-KEM-768 (NIST L3, varsayılan)",
        feature: "kem-mlkem-768",
    },
    AlgorithmDescriptor {
        algorithm: KemAlgorithm::MlKem1024,
        description: "ML-KEM-1024 (NIST L5, yüksek güven)",
        feature: "kem-mlkem-1024",
    },
];

const SIGNATURE_DESCRIPTORS: &[AlgorithmDescriptor<SignatureAlgorithm>] = &[
    AlgorithmDescriptor {
        algorithm: SignatureAlgorithm::MlDsa65,
        description: "ML-DSA-65 (Dilithium5, NIST L5)",
        feature: "sig-mldsa-65",
    },
    AlgorithmDescriptor {
        algorithm: SignatureAlgorithm::Falcon512,
        description: "Falcon-512 (NIST L3, düşük imza boyu)",
        feature: "sig-falcon-512",
    },
    AlgorithmDescriptor {
        algorithm: SignatureAlgorithm::SphincsShake128f,
        description: "SPHINCS+-SHAKE-128f (stateless hash imzası)",
        feature: "sig-sphincs-shake-128f",
    },
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PqAlgorithmStatus {
    name: &'static str,
    description: &'static str,
    feature: &'static str,
    available: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct StrictStatus {
    cli_flag: bool,
    env_flag: bool,
    effective: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ReadinessStatus {
    kem_ready: bool,
    signature_ready: bool,
    strict_compliant: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PqStatusReport {
    strict: StrictStatus,
    readiness: ReadinessStatus,
    kem: Vec<PqAlgorithmStatus>,
    signatures: Vec<PqAlgorithmStatus>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SignatureChecklistReport {
    algorithm: &'static str,
    available: bool,
    nist_category: &'static str,
    public_key_bytes: usize,
    secret_key_bytes: usize,
    signature_bytes: usize,
    deterministic: bool,
    strict_effective: bool,
    client_actions: Vec<String>,
    runtime_assertions: Vec<String>,
    references: Vec<String>,
}

fn handle_pq(command: PqCommands, strict: StrictContext) -> CliResult<()> {
    match command {
        PqCommands::Status(args) => handle_pq_status(&args, strict),
        PqCommands::Checklist(args) => handle_pq_checklist(&args, strict),
    }
}

fn handle_pq_status(args: &PqStatusArgs, strict: StrictContext) -> CliResult<()> {
    let report = build_pq_status_report(strict);
    match args.format {
        PqStatusFormat::Text => {
            println!("{}", render_pq_status_text(&report));
        }
        PqStatusFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

fn handle_pq_checklist(args: &PqChecklistArgs, strict: StrictContext) -> CliResult<()> {
    let algorithm = args.algorithm.to_algorithm();
    let checklist = algorithm.checklist();
    let report = build_signature_checklist_report(&checklist, strict);
    match args.format {
        ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        ReportFormat::Text => println!("{}", render_signature_checklist_text(&report)),
    }
    Ok(())
}

fn build_pq_status_report(strict: StrictContext) -> PqStatusReport {
    let kem: Vec<PqAlgorithmStatus> = KEM_DESCRIPTORS
        .iter()
        .map(|descriptor| PqAlgorithmStatus {
            name: descriptor.algorithm.name(),
            description: descriptor.description,
            feature: descriptor.feature,
            available: descriptor.algorithm.is_available(),
        })
        .collect();
    let signatures: Vec<PqAlgorithmStatus> = SIGNATURE_DESCRIPTORS
        .iter()
        .map(|descriptor| PqAlgorithmStatus {
            name: descriptor.algorithm.name(),
            description: descriptor.description,
            feature: descriptor.feature,
            available: descriptor.algorithm.is_available(),
        })
        .collect();

    let kem_ready = kem.iter().any(|status| status.available);
    let signature_ready = signatures.iter().any(|status| status.available);
    let strict_compliant = kem_ready && signature_ready;
    let effective_strict = strict.effective();

    let mut warnings = Vec::new();
    if !kem_ready {
        warnings.push(format!(
            "PQ KEM etkin değil; şu özelliklerden birini etkinleştirin: {}",
            format_feature_list(&kem)
        ));
    }
    if !signature_ready {
        warnings.push(format!(
            "PQ imza algoritması etkin değil; şu özelliklerden birini etkinleştirin: {}",
            format_feature_list(&signatures)
        ));
    }
    if effective_strict && !strict_compliant {
        warnings.push(
            "Strict kip etkin ancak PQ kapsamı eksik; lütfen eksik algoritmaları etkinleştirin."
                .to_owned(),
        );
    }

    PqStatusReport {
        strict: StrictStatus {
            cli_flag: strict.cli_flag,
            env_flag: strict.env_active,
            effective: effective_strict,
        },
        readiness: ReadinessStatus {
            kem_ready,
            signature_ready,
            strict_compliant,
        },
        kem,
        signatures,
        warnings,
    }
}

fn render_pq_status_text(report: &PqStatusReport) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    out.push_str("Strict flag (--strict): ");
    out.push_str(bool_word(report.strict.cli_flag));
    out.push('\n');
    out.push_str("Strict env (AUNSORM_STRICT): ");
    out.push_str(bool_word(report.strict.env_flag));
    out.push('\n');
    out.push_str("Effective strict: ");
    out.push_str(bool_word(report.strict.effective));
    out.push('\n');
    out.push_str("KEM ready: ");
    out.push_str(bool_word(report.readiness.kem_ready));
    out.push('\n');
    out.push_str("Signature ready: ");
    out.push_str(bool_word(report.readiness.signature_ready));
    out.push('\n');
    out.push_str("Strict compliant: ");
    out.push_str(bool_word(report.readiness.strict_compliant));
    out.push_str("\n\n");

    out.push_str("KEM algoritmaları:\n");
    for status in &report.kem {
        writeln!(
            &mut out,
            "  - {:<24} {} ({})",
            status.name,
            availability_label(status),
            status.description
        )
        .expect("writing to string");
    }
    out.push('\n');
    out.push_str("İmza algoritmaları:\n");
    for status in &report.signatures {
        writeln!(
            &mut out,
            "  - {:<24} {} ({})",
            status.name,
            availability_label(status),
            status.description
        )
        .expect("writing to string");
    }
    out.push('\n');
    if report.warnings.is_empty() {
        out.push_str("Warnings: none\n");
    } else {
        out.push_str("Warnings:\n");
        for warning in &report.warnings {
            out.push_str("  - ");
            out.push_str(warning);
            out.push('\n');
        }
    }
    out
}

fn build_signature_checklist_report(
    checklist: &SignatureChecklist,
    strict: StrictContext,
) -> SignatureChecklistReport {
    SignatureChecklistReport {
        algorithm: checklist.algorithm().name(),
        available: checklist.algorithm().is_available(),
        nist_category: checklist.nist_category(),
        public_key_bytes: checklist.public_key_bytes(),
        secret_key_bytes: checklist.secret_key_bytes(),
        signature_bytes: checklist.signature_bytes(),
        deterministic: checklist.deterministic(),
        strict_effective: strict.effective(),
        client_actions: checklist
            .client_actions()
            .map(std::string::ToString::to_string)
            .collect(),
        runtime_assertions: checklist
            .runtime_assertions()
            .map(std::string::ToString::to_string)
            .collect(),
        references: checklist
            .references()
            .map(std::string::ToString::to_string)
            .collect(),
    }
}

fn render_signature_checklist_text(report: &SignatureChecklistReport) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    writeln!(&mut out, "Algorithm: {}", report.algorithm).expect("writing algorithm");
    writeln!(&mut out, "NIST category: {}", report.nist_category).expect("writing category");
    writeln!(&mut out, "Public key bytes: {}", report.public_key_bytes).expect("writing pk size");
    writeln!(&mut out, "Secret key bytes: {}", report.secret_key_bytes).expect("writing sk size");
    writeln!(&mut out, "Signature bytes: {}", report.signature_bytes).expect("writing sig size");
    writeln!(
        &mut out,
        "Deterministic: {}",
        bool_word(report.deterministic)
    )
    .expect("writing determinism");
    writeln!(
        &mut out,
        "Available in build: {}",
        bool_word(report.available)
    )
    .expect("writing availability");
    writeln!(
        &mut out,
        "Strict active: {}",
        bool_word(report.strict_effective)
    )
    .expect("writing strict state");

    if !report.available {
        writeln!(
            &mut out,
            "Warning: enable the corresponding feature flag before production rollout."
        )
        .expect("writing availability warning");
    }
    if report.strict_effective && !report.available {
        writeln!(
            &mut out,
            "Warning: strict mode is active but this algorithm is missing; enable the feature to avoid downgrade."
        )
        .expect("writing strict warning");
    }

    out.push_str("\nClient hardening steps:\n");
    for action in &report.client_actions {
        writeln!(&mut out, "  - {action}").expect("writing client action");
    }

    out.push_str("\nRuntime assertions:\n");
    for assertion in &report.runtime_assertions {
        writeln!(&mut out, "  - {assertion}").expect("writing runtime assertion");
    }

    out.push_str("\nReferences:\n");
    for reference in &report.references {
        writeln!(&mut out, "  - {reference}").expect("writing reference");
    }

    out
}

fn availability_label(status: &PqAlgorithmStatus) -> String {
    if status.available {
        "available".to_owned()
    } else {
        format!("missing (enable feature `{}`)", status.feature)
    }
}

const fn bool_word(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_feature_list(statuses: &[PqAlgorithmStatus]) -> String {
    statuses
        .iter()
        .map(|status| format!("`{}`", status.feature))
        .collect::<Vec<_>>()
        .join(", ")
}

fn run(cli: Cli) -> CliResult<()> {
    let cli_flag = cli.strict;
    if cli_flag {
        std::env::set_var("AUNSORM_STRICT", "1");
    }
    let env_active = env_strict();
    let strict_ctx = StrictContext {
        cli_flag,
        env_active,
    };
    let strict = strict_ctx.effective();
    match cli.command {
        Commands::Encrypt(args) => handle_encrypt(args, strict),
        Commands::Decrypt(args) => handle_decrypt(args, strict),
        Commands::Peek(args) => handle_peek(&args),
        Commands::Calib(command) => handle_calib(command),
        Commands::SessionEncrypt(args) => handle_session_encrypt(&args, strict),
        Commands::SessionDecrypt(args) => handle_session_decrypt(&args, strict),
        Commands::Pq(command) => handle_pq(command, strict_ctx),
        Commands::Jwt(command) => handle_jwt(command),
        Commands::X509(command) => handle_x509(command),
        Commands::Acme(command) => handle_acme(command),
        Commands::ValidateEndpoints(args) => handle_validate_endpoints(args),
    }
}

fn handle_encrypt(args: EncryptArgs, strict: bool) -> CliResult<()> {
    let EncryptArgs {
        password,
        password_file,
        r#in,
        out,
        org_salt,
        calib_text,
        calib_file,
        kdf,
        aead,
        aad,
        aad_file,
        kem,
        kem_public,
        kem_ciphertext,
        kem_responder,
        kem_shared,
    } = args;

    let plaintext = fs::read(&r#in)?;
    let aad = load_aad(aad.as_deref(), aad_file.as_deref())?;
    let org_salt = decode_org_salt(&org_salt)?;
    let password = load_password(password.as_deref(), password_file.as_deref())?;
    let calib_text = load_calibration_text(calib_text.as_deref(), calib_file.as_deref())?;

    let (calibration, _) = calib_from_text(&org_salt, &calib_text)?;
    let (password_salt, salts) = derive_salts(&org_salt, calibration.id.as_str())?;

    let kem_fields = build_kem_fields(
        kem.as_deref(),
        kem_public.as_deref(),
        kem_ciphertext.as_deref(),
        kem_responder.as_deref(),
        kem_shared.as_deref(),
    )?;
    let profile = kdf.as_profile();
    let algorithm = aead.as_algorithm();

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

    let transcript = packet.transcript_hash(&aad)?;
    let encoded = packet.to_base64()?;
    let writing_to_stdout = is_stdout_path(&out);
    write_bytes(&out, encoded.as_bytes())?;

    if writing_to_stdout {
        eprintln!(
            "şifreleme tamamlandı: çıktı={} | calib_id={} | profile={} | aead={} | strict={} | kem={} | transcript={}",
            out.display(),
            calibration.id.as_str(),
            kdf,
            aead,
            strict,
            kem_fields.as_ref().map_or("none", |k| k.kem_name.as_str()),
            transcript,
        );
    } else {
        println!(
            "şifreleme tamamlandı: çıktı={} | calib_id={} | profile={} | aead={} | strict={} | kem={} | transcript={}",
            out.display(),
            calibration.id.as_str(),
            kdf,
            aead,
            strict,
            kem_fields.as_ref().map_or("none", |k| k.kem_name.as_str()),
            transcript,
        );
    }
    Ok(())
}

fn handle_decrypt(args: DecryptArgs, strict: bool) -> CliResult<()> {
    let DecryptArgs {
        password,
        password_file,
        r#in,
        out,
        org_salt,
        calib_text,
        calib_file,
        kdf,
        aad,
        aad_file,
        metadata_out,
    } = args;

    let packet_b64 = fs::read_to_string(&r#in)?;
    let aad = load_aad(aad.as_deref(), aad_file.as_deref())?;
    let org_salt = decode_org_salt(&org_salt)?;
    let password = load_password(password.as_deref(), password_file.as_deref())?;
    let calib_text = load_calibration_text(calib_text.as_deref(), calib_file.as_deref())?;

    let (calibration, _) = calib_from_text(&org_salt, &calib_text)?;
    let (password_salt, salts) = derive_salts(&org_salt, calibration.id.as_str())?;
    let profile = kdf.as_profile();

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

    let output_to_stdout = is_stdout_path(&out);
    write_bytes(&out, &decrypted.plaintext)?;

    if let Some(path) = metadata_out.as_deref() {
        write_metadata_file(path, &decrypted.metadata)?;
    }

    let metadata_note = metadata_out
        .as_ref()
        .map(|path| format!(" | metadata={}", path.display()))
        .unwrap_or_default();
    let metadata_to_stdout = metadata_out.as_deref().is_some_and(is_stdout_path);

    let message = format!(
        "deşifre başarılı: çıktı={} | calib_id={} | coord_id={} | aead={} | strict={} | msg_len={}B{} | packet_id={} | transcript={}",
        out.display(),
        decrypted.header.calib_id,
        decrypted.coord_id,
        decrypted.header.aead.alg,
        strict,
        decrypted.plaintext.len(),
        metadata_note,
        decrypted.packet_id,
        decrypted.transcript,
    );

    if output_to_stdout || metadata_to_stdout {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }
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
    let transcript = packet.transcript_hash(&aad)?;
    let encoded = packet.to_base64()?;
    let output_to_stdout = is_stdout_path(&args.out);
    write_bytes(&args.out, encoded.as_bytes())?;

    save_ratchet_state(&args.state, &ratchet)?;

    if output_to_stdout {
        eprintln!(
            "oturum şifreleme tamamlandı: çıktı={} | session_id={} | msg_no={} | strict={} | transcript={}",
            args.out.display(),
            STANDARD.encode(outcome.session_id),
            outcome.message_no,
            ratchet.is_strict(),
            transcript,
        );
    } else {
        println!(
            "oturum şifreleme tamamlandı: çıktı={} | session_id={} | msg_no={} | strict={} | transcript={}",
            args.out.display(),
            STANDARD.encode(outcome.session_id),
            outcome.message_no,
            ratchet.is_strict(),
            transcript,
        );
    }
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
    let output_to_stdout = is_stdout_path(&args.out);
    write_bytes(&args.out, &decrypted.plaintext)?;

    replay_store.seen.insert(outcome.message_no);
    let store_to_stdout = is_stdout_path(&args.store);
    save_replay_store(&args.store, &replay_store)?;
    let state_to_stdout = is_stdout_path(&args.state);
    save_ratchet_state(&args.state, &ratchet)?;

    if output_to_stdout || store_to_stdout || state_to_stdout {
        eprintln!(
            "oturum deşifre tamamlandı: çıktı={} | session_id={} | msg_no={} | strict={} | replay_seen={} | transcript={}",
            args.out.display(),
            session_id_b64,
            outcome.message_no,
            ratchet.is_strict(),
            replay_store.seen.len(),
            decrypted.transcript,
        );
    } else {
        println!(
            "oturum deşifre tamamlandı: çıktı={} | session_id={} | msg_no={} | strict={} | replay_seen={} | transcript={}",
            args.out.display(),
            session_id_b64,
            outcome.message_no,
            ratchet.is_strict(),
            replay_store.seen.len(),
            decrypted.transcript,
        );
    }
    Ok(())
}

fn handle_peek(args: &PeekArgs) -> CliResult<()> {
    let packet_b64 = fs::read_to_string(&args.r#in)?;
    let header = peek_header(packet_b64.trim())?;
    let json = serde_json::to_string_pretty(&header)?;
    println!("{json}");
    Ok(())
}

fn handle_calib(command: CalibCommands) -> CliResult<()> {
    match command {
        CalibCommands::Inspect(args) => handle_calib_inspect(&args),
        CalibCommands::DeriveCoord(args) => handle_calib_coord(&args),
        CalibCommands::Fingerprint(args) => handle_calib_fingerprint(&args),
        CalibCommands::Verify(args) => handle_calib_verify(&args),
    }
}

fn handle_calib_inspect(args: &CalibInspectArgs) -> CliResult<()> {
    let org_salt = decode_org_salt(&args.org_salt)?;
    let calib_text = load_calibration_text(args.calib_text.as_deref(), args.calib_file.as_deref())?;
    let (calibration, _) = calib_from_text(&org_salt, &calib_text)?;
    let report = build_calibration_report(&calibration);
    emit_calibration_report(&report, args.format, args.out.as_deref())
}

fn handle_calib_coord(args: &CalibCoordArgs) -> CliResult<()> {
    let org_salt = decode_org_salt(&args.org_salt)?;
    let calib_text = load_calibration_text(args.calib_text.as_deref(), args.calib_file.as_deref())?;
    let (calibration, _) = calib_from_text(&org_salt, &calib_text)?;
    let profile = args.kdf.as_profile();
    let (password_salt, salts) = derive_salts(&org_salt, calibration.id.as_str())?;
    let password = load_password(args.password.as_deref(), args.password_file.as_deref())?;
    let (seed64, _pdk, info) = derive_seed64_and_pdk(
        &password,
        password_salt.as_slice(),
        salts.calibration(),
        salts.chain(),
        profile,
    )?;
    let (coord_id, coord) = coord32_derive(seed64.as_ref(), &calibration, &salts)?;
    write_coord_raw(args.coord_raw_out.as_deref(), &coord)?;
    let report = build_coordinate_report(&calibration, coord_id, coord, args.kdf, &info);
    emit_coordinate_report(&report, args.format, args.out.as_deref())
}

fn handle_calib_fingerprint(args: &CalibFingerprintArgs) -> CliResult<()> {
    let org_salt = decode_org_salt(&args.org_salt)?;
    let calib_text = load_calibration_text(args.calib_text.as_deref(), args.calib_file.as_deref())?;
    let (calibration, _) = calib_from_text(&org_salt, &calib_text)?;
    let report = build_calibration_fingerprint_report(&calibration);
    emit_calibration_fingerprint_report(&report, args.format, args.out.as_deref())
}

fn handle_calib_verify(args: &CalibVerifyArgs) -> CliResult<()> {
    if args.expect_id.is_none()
        && args.expect_fingerprint_b64.is_none()
        && args.expect_fingerprint_hex.is_none()
    {
        return Err(CliError::MissingParam("expect-id/expect-fingerprint"));
    }

    let org_salt = decode_org_salt(&args.org_salt)?;
    let calib_text = load_calibration_text(args.calib_text.as_deref(), args.calib_file.as_deref())?;
    let (calibration, _) = calib_from_text(&org_salt, &calib_text)?;
    let actual_fingerprint = calibration.fingerprint();

    let id_match = args
        .expect_id
        .as_ref()
        .map(|expected| expected == calibration.id.as_str());

    let fingerprint_b64_match = if let Some(expected) = args.expect_fingerprint_b64.as_ref() {
        let decoded = URL_SAFE_NO_PAD.decode(expected)?;
        Some(decoded.as_slice() == actual_fingerprint.as_ref())
    } else {
        None
    };

    let fingerprint_hex_match = if let Some(expected) = args.expect_fingerprint_hex.as_ref() {
        let decoded = hex::decode(expected)?;
        Some(decoded.as_slice() == actual_fingerprint.as_ref())
    } else {
        None
    };

    let report = build_calibration_verify_report(
        &calibration,
        args.expect_id.clone(),
        args.expect_fingerprint_b64.clone(),
        args.expect_fingerprint_hex.clone(),
        id_match,
        fingerprint_b64_match,
        fingerprint_hex_match,
    );

    emit_calibration_verify_report(&report, args.format, args.out.as_deref())?;

    if report
        .results
        .iter()
        .any(|status| matches!(status, Some(false)))
    {
        Err(CliError::ExpectationFailed)
    } else {
        Ok(())
    }
}

fn emit_json_pretty<T>(value: &T, out: Option<&Path>) -> CliResult<()>
where
    T: Serialize,
{
    if let Some(path) = out {
        if is_stdout_path(path) {
            let json = serde_json::to_string_pretty(value)?;
            println!("{json}");
            Ok(())
        } else {
            write_json_pretty(path, value)
        }
    } else {
        let json = serde_json::to_string_pretty(value)?;
        println!("{json}");
        Ok(())
    }
}

fn emit_text(value: &str, out: Option<&Path>) -> CliResult<()> {
    if let Some(path) = out {
        if is_stdout_path(path) {
            println!("{value}");
        } else {
            ensure_parent_dir(path)?;
            let mut owned = value.to_owned();
            owned.push('\n');
            fs::write(path, owned)?;
        }
    } else {
        println!("{value}");
    }
    Ok(())
}

fn write_coord_raw(path: Option<&Path>, coord: &[u8; 32]) -> CliResult<()> {
    if let Some(path) = path {
        write_bytes(path, coord)?;
    }
    Ok(())
}

fn write_bytes(path: &Path, data: &[u8]) -> CliResult<()> {
    if is_stdout_path(path) {
        let mut stdout = io::stdout().lock();
        stdout.write_all(data)?;
        stdout.flush()?;
    } else {
        ensure_parent_dir(path)?;
        fs::write(path, data)?;
    }
    Ok(())
}

fn is_stdout_path(path: &Path) -> bool {
    path == Path::new("-")
}

fn emit_calibration_report(
    report: &CalibrationReport,
    format: ReportFormat,
    out: Option<&Path>,
) -> CliResult<()> {
    match format {
        ReportFormat::Json => emit_json_pretty(report, out),
        ReportFormat::Text => {
            let rendered = render_calibration_report_text(report);
            emit_text(&rendered, out)
        }
    }
}

fn emit_calibration_fingerprint_report(
    report: &CalibrationFingerprintReport,
    format: ReportFormat,
    out: Option<&Path>,
) -> CliResult<()> {
    match format {
        ReportFormat::Json => emit_json_pretty(report, out),
        ReportFormat::Text => {
            let rendered = render_calibration_fingerprint_report_text(report);
            emit_text(&rendered, out)
        }
    }
}

fn emit_calibration_verify_report(
    report: &CalibrationVerifyReport,
    format: ReportFormat,
    out: Option<&Path>,
) -> CliResult<()> {
    match format {
        ReportFormat::Json => emit_json_pretty(report, out),
        ReportFormat::Text => {
            let rendered = render_calibration_verify_report_text(report);
            emit_text(&rendered, out)
        }
    }
}

fn emit_coordinate_report(
    report: &CoordinateReport,
    format: ReportFormat,
    out: Option<&Path>,
) -> CliResult<()> {
    match format {
        ReportFormat::Json => emit_json_pretty(report, out),
        ReportFormat::Text => {
            let rendered = render_coordinate_report_text(report);
            emit_text(&rendered, out)
        }
    }
}

#[derive(Serialize)]
struct CalibrationRangeReport {
    start: u16,
    end: u16,
    step: u16,
}

#[derive(Serialize)]
struct CalibrationReport {
    calibration_id: String,
    note_text: String,
    alpha_long: u16,
    alpha_short: u16,
    beta_long: u16,
    beta_short: u16,
    tau: u16,
    fingerprint: String,
    fingerprint_hex: String,
    ranges: [CalibrationRangeReport; 5],
}

#[derive(Serialize)]
struct CalibrationFingerprintReport {
    calibration_id: String,
    fingerprint_b64: String,
    fingerprint_hex: String,
}

#[derive(Serialize)]
struct CalibrationVerifyReport {
    calibration_id: String,
    fingerprint_b64: String,
    fingerprint_hex: String,
    expectations: CalibrationVerifyExpectations,
    results: CalibrationVerifyResults,
}

#[derive(Serialize)]
struct CalibrationVerifyExpectations {
    id: Option<String>,
    fingerprint_b64: Option<String>,
    fingerprint_hex: Option<String>,
}

#[derive(Serialize)]
struct CalibrationVerifyResults {
    id: Option<bool>,
    fingerprint_b64: Option<bool>,
    fingerprint_hex: Option<bool>,
}

fn build_calibration_report(calibration: &Calibration) -> CalibrationReport {
    let ranges = std::array::from_fn(|idx| {
        let range = calibration.ranges[idx];
        CalibrationRangeReport {
            start: range.start,
            end: range.end,
            step: range.step,
        }
    });
    CalibrationReport {
        calibration_id: calibration.id.as_str().to_string(),
        note_text: calibration.note_text().to_string(),
        alpha_long: calibration.alpha_long,
        alpha_short: calibration.alpha_short,
        beta_long: calibration.beta_long,
        beta_short: calibration.beta_short,
        tau: calibration.tau,
        fingerprint: calibration.fingerprint_b64(),
        fingerprint_hex: calibration.fingerprint_hex(),
        ranges,
    }
}

fn build_calibration_fingerprint_report(calibration: &Calibration) -> CalibrationFingerprintReport {
    let fingerprint_b64 = calibration.fingerprint_b64();
    let fingerprint_hex = calibration.fingerprint_hex();
    CalibrationFingerprintReport {
        calibration_id: calibration.id.as_str().to_string(),
        fingerprint_b64,
        fingerprint_hex,
    }
}

fn build_calibration_verify_report(
    calibration: &Calibration,
    expected_id: Option<String>,
    expected_fingerprint_b64: Option<String>,
    expected_fingerprint_hex: Option<String>,
    id_match: Option<bool>,
    fingerprint_b64_match: Option<bool>,
    fingerprint_hex_match: Option<bool>,
) -> CalibrationVerifyReport {
    CalibrationVerifyReport {
        calibration_id: calibration.id.as_str().to_string(),
        fingerprint_b64: calibration.fingerprint_b64(),
        fingerprint_hex: calibration.fingerprint_hex(),
        expectations: CalibrationVerifyExpectations {
            id: expected_id,
            fingerprint_b64: expected_fingerprint_b64,
            fingerprint_hex: expected_fingerprint_hex,
        },
        results: CalibrationVerifyResults {
            id: id_match,
            fingerprint_b64: fingerprint_b64_match,
            fingerprint_hex: fingerprint_hex_match,
        },
    }
}

fn render_calibration_report_text(report: &CalibrationReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Kalibrasyon Kimliği : {}", report.calibration_id));
    lines.push(format!("Normalize Metin     : {}", report.note_text));
    lines.push(format!(
        "Alpha (L/S)          : {}/{}",
        report.alpha_long, report.alpha_short
    ));
    lines.push(format!(
        "Beta (L/S)           : {}/{}",
        report.beta_long, report.beta_short
    ));
    lines.push(format!("Tau                  : {}", report.tau));
    lines.push(format!("Parmak izi (B64)     : {}", report.fingerprint));
    lines.push(format!("Parmak izi (Hex)     : {}", report.fingerprint_hex));
    lines.push("Aralıklar:".to_string());
    for (idx, range) in report.ranges.iter().enumerate() {
        lines.push(format!(
            "  [{}] başlangıç={} | bitiş={} | adım={}",
            idx + 1,
            range.start,
            range.end,
            range.step
        ));
    }
    lines.join("\n")
}

fn render_calibration_fingerprint_report_text(report: &CalibrationFingerprintReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "Kalibrasyon Kimliği     : {}",
        report.calibration_id
    ));
    lines.push(format!(
        "Parmak izi (Base64)     : {}",
        report.fingerprint_b64
    ));
    lines.push(format!(
        "Parmak izi (hex)        : {}",
        report.fingerprint_hex
    ));
    lines.join("\n")
}

fn render_calibration_verify_report_text(report: &CalibrationVerifyReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "Kalibrasyon Kimliği      : {}",
        report.calibration_id
    ));
    lines.push(format!(
        "Parmak izi (Base64)      : {}",
        report.fingerprint_b64
    ));
    lines.push(format!(
        "Parmak izi (hex)         : {}",
        report.fingerprint_hex
    ));
    lines.push(format!(
        "Beklenen Kimlik          : {}",
        report.expectations.id.as_deref().unwrap_or("-")
    ));
    lines.push(format!(
        "Kimlik Doğrulaması       : {}",
        status_text(report.results.id)
    ));
    lines.push(format!(
        "Beklenen Parmak izi (B64): {}",
        report
            .expectations
            .fingerprint_b64
            .as_deref()
            .unwrap_or("-")
    ));
    lines.push(format!(
        "Base64 Doğrulaması       : {}",
        status_text(report.results.fingerprint_b64)
    ));
    lines.push(format!(
        "Beklenen Parmak izi (hex): {}",
        report
            .expectations
            .fingerprint_hex
            .as_deref()
            .unwrap_or("-")
    ));
    lines.push(format!(
        "Hex Doğrulaması          : {}",
        status_text(report.results.fingerprint_hex)
    ));
    lines.join("\n")
}

const fn status_text(status: Option<bool>) -> &'static str {
    match status {
        Some(true) => "OK",
        Some(false) => "HATA",
        None => "Atlanıyor",
    }
}

impl CalibrationVerifyResults {
    fn iter(&self) -> impl Iterator<Item = Option<bool>> + '_ {
        [self.id, self.fingerprint_b64, self.fingerprint_hex].into_iter()
    }
}

#[derive(Serialize)]
struct CoordinateReport {
    calibration_id: String,
    coord_id: String,
    coord: String,
    profile: String,
    password_salt_digest: String,
    calibration_salt_digest: String,
    chain_salt_digest: String,
}

fn build_coordinate_report(
    calibration: &Calibration,
    coord_id: String,
    coord: [u8; 32],
    profile: ProfileArg,
    info: &KdfInfo,
) -> CoordinateReport {
    CoordinateReport {
        calibration_id: calibration.id.as_str().to_string(),
        coord_id,
        coord: STANDARD.encode(coord),
        profile: profile.to_string(),
        password_salt_digest: STANDARD.encode(info.password_salt_digest),
        calibration_salt_digest: STANDARD.encode(info.calibration_salt_digest),
        chain_salt_digest: STANDARD.encode(info.chain_salt_digest),
    }
}

fn render_coordinate_report_text(report: &CoordinateReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Kalibrasyon Kimliği : {}", report.calibration_id));
    lines.push(format!("Koordinat Kimliği   : {}", report.coord_id));
    lines.push(format!("Koordinat (B64)     : {}", report.coord));
    lines.push(format!("KDF Profili         : {}", report.profile));
    lines.push("Tuz Özetleri:".to_string());
    lines.push(format!(
        "  parola            : {}",
        report.password_salt_digest
    ));
    lines.push(format!(
        "  kalibrasyon       : {}",
        report.calibration_salt_digest
    ));
    lines.push(format!(
        "  zincir            : {}",
        report.chain_salt_digest
    ));
    lines.join("\n")
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
    let log_to_stderr = is_stdout_path(&args.out)
        || args.public_out.as_deref().is_some_and(is_stdout_path)
        || args.jwks_out.as_deref().is_some_and(is_stdout_path);
    if log_to_stderr {
        eprintln!(
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
    } else {
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
    }
    Ok(())
}

fn handle_jwt_sign(args: &JwtSignArgs) -> CliResult<()> {
    let mut claims = build_claims_from_args(args)?;
    let (kid, token, extra_info) = if let Some(path) = args.key.as_deref() {
        let key = load_jwt_keypair(path)?;
        let signer = JwtSigner::new(key.clone());
        let token = signer.sign(&mut claims)?;
        (key.kid().to_string(), token, None)
    } else if let Some(backend) = args.kms_backend {
        let kms_key_id = args
            .kms_key_id
            .as_ref()
            .ok_or(CliError::MissingParam("kms-key-id"))?
            .clone();
        if args.kms_fallback_backend.is_some() != args.kms_fallback_key_id.is_some() {
            return Err(CliError::MissingParam("kms fallback"));
        }
        let mut config = KmsConfig::from_env()?;
        if let Some(store) = args.kms_store.as_ref() {
            config = config.with_local_store(store.clone());
        }
        let client = KmsClient::from_config(config)?;
        let primary = KmsBackendLocator::new(backend.into(), kms_key_id.clone());
        let descriptor = if let Some(fallback_backend) = args.kms_fallback_backend {
            let fallback_id = args
                .kms_fallback_key_id
                .as_ref()
                .ok_or(CliError::MissingParam("kms-fallback-key-id"))?
                .clone();
            KmsKeyDescriptor::new(primary)
                .with_fallback(KmsBackendLocator::new(fallback_backend.into(), fallback_id))
        } else {
            if args.kms_fallback_key_id.is_some() {
                return Err(CliError::MissingParam("kms-fallback-backend"));
            }
            KmsKeyDescriptor::new(primary)
        };
        let signer = aunsorm_jwt::KmsJwtSigner::new(&client, descriptor)?;
        let token = signer.sign(&mut claims)?;
        let kms_info = format!(" | kms={backend}::{kms_key_id}");
        (signer.kid().to_string(), token, Some(kms_info))
    } else {
        return Err(CliError::MissingJwtMaterial);
    };
    let output_to_stdout = is_stdout_path(&args.out);
    write_bytes(&args.out, token.as_bytes())?;
    if output_to_stdout {
        eprintln!(
            "jwt imzalandı: kid={} | jti={} | out={} | exp={:?}{}",
            kid,
            claims.jwt_id.as_deref().unwrap_or("<none>"),
            args.out.display(),
            claims.expiration,
            extra_info.unwrap_or_default(),
        );
    } else {
        println!(
            "jwt imzalandı: kid={} | jti={} | out={} | exp={:?}{}",
            kid,
            claims.jwt_id.as_deref().unwrap_or("<none>"),
            args.out.display(),
            claims.expiration,
            extra_info.unwrap_or_default(),
        );
    }
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
        let claims_to_stdout = is_stdout_path(out);
        write_json_pretty(out, &claims)?;
        if claims_to_stdout {
            eprintln!(
                "jwt doğrulandı: token={} | jti={} | claims={}",
                args.token.display(),
                claims.jwt_id.as_deref().unwrap_or("<none>"),
                out.display(),
            );
        } else {
            println!(
                "jwt doğrulandı: token={} | jti={} | claims={}",
                args.token.display(),
                claims.jwt_id.as_deref().unwrap_or("<none>"),
                out.display(),
            );
        }
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
    let output_to_stdout = is_stdout_path(&args.out);
    write_json_pretty(&args.out, &jwks)?;
    if output_to_stdout {
        eprintln!(
            "jwks üretildi: anahtar_sayısı={} | çıktı={}",
            jwks.keys.len(),
            args.out.display(),
        );
    } else {
        println!(
            "jwks üretildi: anahtar_sayısı={} | çıktı={}",
            jwks.keys.len(),
            args.out.display(),
        );
    }
    Ok(())
}

fn handle_x509(command: X509Commands) -> CliResult<()> {
    match command {
        X509Commands::SelfSigned(args) => handle_x509_self_signed(&args),
        X509Commands::LocalDev(args) => handle_x509_local_dev(&args),
        X509Commands::Ca(command) => handle_x509_ca(command),
    }
}

fn handle_x509_self_signed(args: &X509SelfSignedArgs) -> CliResult<()> {
    let validity_days = args.validity_days;
    if validity_days == 0 {
        return Err(CliError::InvalidValidityDays);
    }
    let org_salt = decode_org_salt(&args.org_salt)?;
    let calib_text = load_calibration_text(args.calib_text.as_deref(), args.calib_file.as_deref())?;
    let params = X509SelfSignedParams {
        common_name: &args.common_name,
        org_salt: &org_salt,
        calibration_text: &calib_text,
        cps_uris: &args.cps,
        policy_oids: &args.policy_oids,
        validity_days,
        subject_alt_names: Vec::new(),
    };
    let cert = generate_self_signed_cert(&params)?;
    write_text_file(&args.cert_out, &cert.certificate_pem)?;
    write_text_file(&args.key_out, &cert.private_key_pem)?;
    let log_to_stderr = is_stdout_path(&args.cert_out) || is_stdout_path(&args.key_out);
    if log_to_stderr {
        eprintln!(
            "x509 sertifikası üretildi: cn={} | calib_id={} | validity={} gün | cert={} | key={} | cps={} | policies={}",
            args.common_name,
            cert.calibration_id,
            validity_days,
            args.cert_out.display(),
            args.key_out.display(),
            args.cps.len(),
            args.policy_oids.len(),
        );
    } else {
        println!(
            "x509 sertifikası üretildi: cn={} | calib_id={} | validity={} gün | cert={} | key={} | cps={} | policies={}",
            args.common_name,
            cert.calibration_id,
            validity_days,
            args.cert_out.display(),
            args.key_out.display(),
            args.cps.len(),
            args.policy_oids.len(),
        );
    }
    Ok(())
}

fn handle_x509_local_dev(args: &X509LocalDevArgs) -> CliResult<()> {
    let validity_days = args.validity_days;
    if validity_days == 0 {
        return Err(CliError::InvalidValidityDays);
    }
    let hostname_trimmed = args.hostname.trim();
    if hostname_trimmed.is_empty() {
        return Err(CliError::MissingParam("hostname"));
    }
    let org_salt = decode_org_salt(&args.org_salt)?;
    let calib_text = load_calibration_text(args.calib_text.as_deref(), args.calib_file.as_deref())?;
    let sanitized_dns: Vec<String> = args
        .extra_dns
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(std::borrow::ToOwned::to_owned)
        .collect();
    let extra_ips = parse_ip_addrs(&args.extra_ips)?;
    let params = X509LocalHttpsParams {
        hostname: hostname_trimmed,
        org_salt: &org_salt,
        calibration_text: &calib_text,
        cps_uris: &args.cps,
        policy_oids: &args.policy_oids,
        validity_days,
        extra_dns: &sanitized_dns,
        extra_ips: &extra_ips,
    };
    let prepared = prepare_local_https_params(&params)?;
    let cert = generate_self_signed_cert(&prepared)?;
    write_text_file(&args.cert_out, &cert.certificate_pem)?;
    write_text_file(&args.key_out, &cert.private_key_pem)?;

    let mut dns_entries: Vec<String> = Vec::new();
    dns_entries.push(hostname_trimmed.to_owned());
    dns_entries.extend(
        prepared
            .subject_alt_names
            .iter()
            .filter_map(|san| match san {
                X509SubjectAltName::Dns(name) => Some(name.clone()),
                X509SubjectAltName::Ip(_) => None,
            }),
    );
    let ip_entries: Vec<String> = prepared
        .subject_alt_names
        .iter()
        .filter_map(|san| match san {
            X509SubjectAltName::Ip(addr) => Some(addr.to_string()),
            X509SubjectAltName::Dns(_) => None,
        })
        .collect();
    let dns_list = dns_entries.join(",");
    let ip_list = if ip_entries.is_empty() {
        String::from("-")
    } else {
        ip_entries.join(",")
    };
    let log_to_stderr = is_stdout_path(&args.cert_out) || is_stdout_path(&args.key_out);
    let message = format!(
        "x509 local-dev sertifikası üretildi: hostname={} | calib_id={} | validity={} gün | cert={} | key={} | dns_san={} | ip_san={}",
        hostname_trimmed,
        cert.calibration_id,
        validity_days,
        args.cert_out.display(),
        args.key_out.display(),
        dns_list,
        ip_list,
    );
    if log_to_stderr {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }
    Ok(())
}

fn handle_x509_ca(command: X509CaCommands) -> CliResult<()> {
    match command {
        X509CaCommands::Init(args) => handle_x509_ca_init(&args),
        X509CaCommands::Issue(args) => handle_x509_ca_issue(&args),
        X509CaCommands::SignServer(args) => handle_x509_ca_sign_server(&args),
    }
}

fn handle_x509_ca_init(args: &X509CaInitArgs) -> CliResult<()> {
    let profile = CaAutomationProfile::from_path(&args.profile)?;
    let org_salt = profile.decode_org_salt()?;
    let root_section = &profile.root;

    let params = X509RootCaParams {
        common_name: &root_section.common_name,
        org_salt: &org_salt,
        calibration_text: &root_section.calibration_text,
        validity_days: root_section.validity_days,
        cps_uris: &root_section.cps_uris,
        policy_oids: &root_section.policy_oids,
        key_algorithm: Some(args.algorithm.to_key_algorithm()),
    };
    let cert = generate_root_ca(&params)?;
    write_text_file(&args.cert_out, &cert.certificate_pem)?;
    write_text_file(&args.key_out, &cert.private_key_pem)?;

    let (calibration, _) = calib_from_text(&org_salt, &root_section.calibration_text)?;
    let serial_hex = deterministic_serial_hex(&calibration);
    let key_id = compute_key_identifier(&cert.private_key_pem)?;

    let report = CaInitReport {
        profile_id: profile.profile_id.clone(),
        root_common_name: root_section.common_name.clone(),
        calibration_id: cert.calibration_id.clone(),
        serial_hex,
        key_id,
        bundle_path: args
            .bundle_out
            .as_ref()
            .map(|path| path.display().to_string()),
    };

    let summary_path = args
        .summary_out
        .as_deref()
        .unwrap_or_else(|| Path::new("-"));
    write_json_pretty(summary_path, &report)?;

    if let Some(path) = args.bundle_out.as_deref() {
        let bundle = CaBundle::new(
            profile.profile_id.clone(),
            CaBundleEntry {
                certificate_pem: cert.certificate_pem.clone(),
                calibration_id: cert.calibration_id.clone(),
            },
        );
        write_json_pretty(path, &bundle)?;
    }

    let summary_to_stdout = is_stdout_path(summary_path);
    let bundle_to_stdout = args.bundle_out.as_deref().is_some_and(is_stdout_path);
    let log_to_stderr = is_stdout_path(&args.cert_out)
        || is_stdout_path(&args.key_out)
        || summary_to_stdout
        || bundle_to_stdout;
    let bundle_fragment = args
        .bundle_out
        .as_ref()
        .map(|path| format!(" | bundle={}", path.display()))
        .unwrap_or_default();
    let message = format!(
        "x509 ca init: profile={} | cn={} | algorithm={} | calib_id={} | serial={} | key_id={} | cert={} | key={}{}",
        args.profile.display(),
        root_section.common_name,
        args.algorithm,
        cert.calibration_id,
        report.serial_hex,
        report.key_id,
        args.cert_out.display(),
        args.key_out.display(),
        bundle_fragment,
    );
    if log_to_stderr {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }

    Ok(())
}

fn handle_x509_ca_issue(args: &X509CaIssueArgs) -> CliResult<()> {
    let profile = CaAutomationProfile::from_path(&args.profile)?;
    let org_salt = profile.decode_org_salt()?;
    let section = profile.intermediate(&args.intermediate)?;
    let issuer_cert = fs::read_to_string(&args.issuer_cert)?;
    let issuer_key = fs::read_to_string(&args.issuer_key)?;

    let params = X509IntermediateCaParams {
        common_name: &section.common_name,
        org_salt: &org_salt,
        calibration_text: &section.calibration_text,
        validity_days: section.validity_days,
        cps_uris: &section.cps_uris,
        policy_oids: &section.policy_oids,
        issuer_cert_pem: &issuer_cert,
        issuer_key_pem: &issuer_key,
    };
    let cert = issue_intermediate_ca(&params)?;
    write_text_file(&args.cert_out, &cert.certificate_pem)?;
    write_text_file(&args.key_out, &cert.private_key_pem)?;

    let (calibration, _) = calib_from_text(&org_salt, &section.calibration_text)?;
    let serial_hex = deterministic_serial_hex(&calibration);
    let key_id = compute_key_identifier(&cert.private_key_pem)?;

    let report = CaIssueReport {
        profile_id: profile.profile_id.clone(),
        intermediate: args.intermediate.clone(),
        calibration_id: cert.calibration_id.clone(),
        serial_hex,
        key_id,
        issuer_cert: args.issuer_cert.display().to_string(),
        bundle_path: args
            .bundle_out
            .as_ref()
            .map(|path| path.display().to_string()),
    };

    let summary_path = args
        .summary_out
        .as_deref()
        .unwrap_or_else(|| Path::new("-"));
    write_json_pretty(summary_path, &report)?;

    if let Some(path) = args.bundle_out.as_deref() {
        if is_stdout_path(path) {
            return Err(CliError::BundleRequiresFile);
        }
        if !path.exists() {
            return Err(CliError::MissingBundle(path.to_path_buf()));
        }
        let mut bundle: CaBundle = read_json_file(path)?;
        if bundle.profile_id != profile.profile_id {
            return Err(CliError::BundleProfileMismatch {
                expected: bundle.profile_id,
                actual: profile.profile_id,
            });
        }
        bundle.upsert_intermediate(
            &args.intermediate,
            CaBundleEntry {
                certificate_pem: cert.certificate_pem.clone(),
                calibration_id: cert.calibration_id.clone(),
            },
        );
        write_json_pretty(path, &bundle)?;
    }

    let summary_to_stdout = is_stdout_path(summary_path);
    let bundle_to_stdout = args.bundle_out.as_deref().is_some_and(is_stdout_path);
    let log_to_stderr = is_stdout_path(&args.cert_out)
        || is_stdout_path(&args.key_out)
        || summary_to_stdout
        || bundle_to_stdout;
    let bundle_fragment = args
        .bundle_out
        .as_ref()
        .map(|path| format!(" | bundle={}", path.display()))
        .unwrap_or_default();
    let message = format!(
        "x509 ca issue: profile={} | intermediate={} | calib_id={} | serial={} | key_id={} | issuer={} | cert={} | key={}{}",
        args.profile.display(),
        args.intermediate,
        cert.calibration_id,
        report.serial_hex,
        report.key_id,
        args.issuer_cert.display(),
        args.cert_out.display(),
        args.key_out.display(),
        bundle_fragment,
    );
    if log_to_stderr {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }

    Ok(())
}

fn handle_x509_ca_sign_server(args: &X509CaSignServerArgs) -> CliResult<()> {
    use aunsorm_x509::ca::{sign_server_cert, ServerCertParams};
    use std::net::IpAddr;

    let ca_cert_pem = fs::read_to_string(&args.ca_cert)?;
    let ca_key_pem = fs::read_to_string(&args.ca_key)?;
    let org_salt = hex::decode(&args.org_salt)?;

    let extra_dns: Vec<String> = args
        .extra_dns
        .as_ref()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let extra_ips: Vec<IpAddr> = args
        .extra_ip
        .as_ref()
        .map(|s| {
            s.split(',')
                .map(|s| s.trim().parse::<IpAddr>())
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(|e| CliError::InvalidIpAddress(e.to_string()))?
        .unwrap_or_default();

    let params = ServerCertParams {
        hostname: &args.hostname,
        org_salt: &org_salt,
        calibration_text: &args.calibration_text,
        ca_cert_pem: &ca_cert_pem,
        ca_key_pem: &ca_key_pem,
        extra_dns: &extra_dns,
        extra_ips: &extra_ips,
        validity_days: args.validity_days,
        key_algorithm: Some(args.algorithm.to_key_algorithm()),
    };

    let cert = sign_server_cert(&params)?;

    write_text_file(&args.cert_out, &cert.certificate_pem)?;
    write_text_file(&args.key_out, &cert.private_key_pem)?;

    let log_to_stderr = is_stdout_path(&args.cert_out) || is_stdout_path(&args.key_out);
    let dns_fragment = if extra_dns.is_empty() {
        String::new()
    } else {
        format!(" | dns={}", extra_dns.join(","))
    };
    let ip_fragment = if extra_ips.is_empty() {
        String::new()
    } else {
        format!(
            " | ips={}",
            extra_ips
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let message = format!(
        "x509 ca sign-server: hostname={} | ca={} | cert={} | key={} | validity_days={} | algorithm={} | calib_id={}{}{}",
        args.hostname,
        args.ca_cert.display(),
        args.cert_out.display(),
        args.key_out.display(),
        args.validity_days,
        args.algorithm,
        cert.calibration_id,
        dns_fragment,
        ip_fragment,
    );
    if log_to_stderr {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }

    Ok(())
}

fn handle_acme(command: AcmeCommands) -> CliResult<()> {
    match command {
        AcmeCommands::Directory(args) => handle_acme_directory(&args),
        AcmeCommands::Register(args) => handle_acme_register(&args),
        AcmeCommands::Order(args) => handle_acme_order(&args),
        AcmeCommands::Finalize(args) => handle_acme_finalize(&args),
        AcmeCommands::FetchCert(args) => handle_acme_fetch_cert(&args),
        AcmeCommands::Revoke(args) => handle_acme_revoke(&args),
    }
}

fn handle_acme_directory(args: &AcmeDirectoryArgs) -> CliResult<()> {
    let mut client = AcmeClient::new(&args.server)?;
    let discovery = client.fetch_directory()?;
    let DirectoryDiscovery {
        directory,
        raw_json,
    } = discovery;

    println!(
        "acme directory: newNonce={} | newAccount={} | newOrder={} | revokeCert={} | keyChange={}",
        directory.new_nonce,
        directory.new_account,
        directory.new_order,
        directory.revoke_cert,
        directory.key_change,
    );
    if let Some(meta) = &directory.meta {
        if let Some(tos) = &meta.terms_of_service {
            println!("  termsOfService={tos}");
        }
        if let Some(website) = &meta.website {
            println!("  website={website}");
        }
        if !meta.caa_identities.is_empty() {
            println!("  caaIdentities={}", meta.caa_identities.join(", "));
        }
        println!(
            "  externalAccountRequired={}",
            if meta.external_account_required {
                "true"
            } else {
                "false"
            }
        );
    }
    if !directory.additional_endpoints.is_empty() {
        println!("  ek uç noktalar:");
        for (name, url) in &directory.additional_endpoints {
            println!("    - {name} -> {url}");
        }
    }

    if args.json || args.output.is_some() {
        let value: Value = serde_json::from_str(&raw_json)?;
        if args.json {
            let pretty = serde_json::to_string_pretty(&value)?;
            println!("{pretty}");
        }
        if let Some(path) = &args.output {
            write_json_pretty(path, &value)?;
        }
    }

    Ok(())
}

fn handle_acme_register(args: &AcmeRegisterArgs) -> CliResult<()> {
    let mut client = AcmeClient::new(&args.server)?;
    let (mut state, key, newly_created) = load_or_create_account_state(&args.account)?;
    if newly_created {
        println!(
            "acme register: yeni hesap anahtarı oluşturuldu -> {}",
            args.account.display()
        );
    }

    let contacts = build_acme_contacts(args)?;
    if contacts.is_empty() {
        return Err(CliError::MissingParam("email/contact"));
    }

    let mut builder = NewAccountRequest::builder();
    for contact in contacts {
        builder = builder.contact(contact);
    }
    if args.accept_terms {
        builder = builder.agree_to_terms();
    }
    if args.only_existing {
        builder = builder.query_existing();
    }
    let payload: NewAccountRequest = builder.build();

    let nonce = client.next_nonce()?;
    let new_account_url = client.new_account_url().clone();
    let jws = key.sign_json(&payload, &nonce, &new_account_url, KeyBinding::Jwk)?;
    let response = client.post_jose(&new_account_url, &jws)?;
    if response.status != StatusCode::CREATED && response.status != StatusCode::OK {
        return Err(CliError::AcmeHttp {
            message: format!("ACME new-account beklenmeyen durum: {}", response.status),
        });
    }

    let account: AccountResponseBody = serde_json::from_str(&response.body)?;
    state.update_from_account_response(&account);
    save_account_state(&args.account, &state)?;

    let location = response
        .headers
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| account.kid.clone(), String::from);
    let contacts_summary = if account.contact.is_empty() {
        "(yok)".to_string()
    } else {
        account.contact.join(", ")
    };
    println!(
        "acme register: status={} | location={} | orders={} | contacts={} | tos={} | created_at={}",
        account.status,
        location,
        account.orders,
        contacts_summary,
        if account.terms_of_service_agreed {
            "kabul"
        } else {
            "bekleniyor"
        },
        account.created_at,
    );
    println!("  durum dosyası: {}", args.account.display());

    Ok(())
}

fn handle_acme_order(args: &AcmeOrderArgs) -> CliResult<()> {
    let mut client = AcmeClient::new(&args.server)?;
    let (mut state, key) = load_account_state(&args.account)?;
    let kid = state
        .kid
        .as_deref()
        .ok_or_else(|| CliError::AcmeState("hesap dosyasında kid alanı bulunamadı".to_string()))?;

    let order_request = NewOrderRequest::for_dns_names(&args.domains)?;
    let nonce = client.next_nonce()?;
    let new_order_url = client.new_order_url().clone();
    let jws = key.sign_json(&order_request, &nonce, &new_order_url, KeyBinding::Kid(kid))?;
    let response = client.post_jose(&new_order_url, &jws)?;
    if response.status != StatusCode::CREATED {
        return Err(CliError::AcmeHttp {
            message: format!("ACME new-order beklenmeyen durum: {}", response.status),
        });
    }

    let order: OrderResponseBody = serde_json::from_str(&response.body)?;
    let location = response
        .headers
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| order.finalize.clone(), String::from);

    state.record_last_order(location.clone(), &order);
    save_account_state(&args.account, &state)?;

    if let Some(path) = &args.output {
        write_response_json(path, &response.body)?;
    }

    report_acme_order(
        "order",
        &order,
        &location,
        &args.account,
        args.output.as_deref(),
    );

    Ok(())
}

fn report_acme_order(
    action: &str,
    order: &OrderResponseBody,
    location: &str,
    account_path: &Path,
    output: Option<&Path>,
) {
    println!(
        "acme {action}: status={} | location={} | identifiers={} | expires={}",
        order.status,
        location,
        order.identifiers.len(),
        order.expires,
    );
    if !order.identifiers.is_empty() {
        println!("  identifiers:");
        for item in &order.identifiers {
            println!("    - {} = {}", item.ty, item.value);
        }
    }
    if let Some(not_before) = &order.not_before {
        println!("  notBefore={not_before}");
    }
    if let Some(not_after) = &order.not_after {
        println!("  notAfter={not_after}");
    }
    if !order.authorizations.is_empty() {
        println!("  authorizations:");
        for auth in &order.authorizations {
            println!("    - {auth}");
        }
    }
    println!("  finalize={}", order.finalize);
    if let Some(certificate) = &order.certificate {
        println!("  certificate={certificate}");
    }
    println!("  durum dosyası: {}", account_path.display());
    if let Some(path) = output {
        println!("  order JSON: {}", path.display());
    }
}

fn handle_acme_finalize(args: &AcmeFinalizeArgs) -> CliResult<()> {
    let (mut state, key) = load_account_state(&args.account)?;
    let kid = state
        .kid
        .as_deref()
        .ok_or_else(|| CliError::AcmeState("hesap dosyasında kid alanı bulunamadı".to_string()))?;

    let (order_location, finalize_url) = {
        let snapshot = state.last_order.as_ref().ok_or_else(|| {
            CliError::AcmeState("hesap dosyasında finalize edilecek order bulunamadı".to_string())
        })?;
        let url =
            Url::parse(&snapshot.finalize).map_err(|err| CliError::InvalidUrl(err.to_string()))?;
        (snapshot.location.clone(), url)
    };

    let csr_der = read_csr_der(&args.csr)?;
    let csr_encoded = URL_SAFE_NO_PAD.encode(csr_der);

    let mut client = AcmeClient::new(&args.server)?;
    let nonce = client.next_nonce()?;
    let request = FinalizeRequest { csr: &csr_encoded };
    let jws = key.sign_json(&request, &nonce, &finalize_url, KeyBinding::Kid(kid))?;
    let response = client.post_jose(&finalize_url, &jws)?;
    if response.status != StatusCode::OK && response.status != StatusCode::CREATED {
        return Err(CliError::AcmeHttp {
            message: format!("ACME finalize beklenmeyen durum: {}", response.status),
        });
    }

    let order: OrderResponseBody = serde_json::from_str(&response.body)?;
    if let Some(path) = &args.output {
        write_response_json(path, &response.body)?;
    }

    let location = response
        .headers
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map_or(order_location, std::string::ToString::to_string);
    state.record_last_order(location.clone(), &order);
    save_account_state(&args.account, &state)?;

    report_acme_order(
        "finalize",
        &order,
        &location,
        &args.account,
        args.output.as_deref(),
    );

    Ok(())
}

fn handle_acme_fetch_cert(args: &AcmeFetchCertArgs) -> CliResult<()> {
    let (state, _) = load_account_state(&args.account)?;
    let snapshot = state.last_order.as_ref().ok_or_else(|| {
        CliError::AcmeState("hesap dosyasında indirilecek order bulunamadı".to_string())
    })?;
    let certificate_url = snapshot.certificate.as_deref().ok_or_else(|| {
        CliError::AcmeState(
            "order henüz sertifika URL'si döndürmedi; finalize adımını tamamlayın".to_string(),
        )
    })?;
    let certificate_url =
        Url::parse(certificate_url).map_err(|err| CliError::InvalidUrl(err.to_string()))?;

    let mut client = AcmeClient::new(&args.server)?;
    let response = client.get(&certificate_url)?;
    if response.status != StatusCode::OK {
        return Err(CliError::AcmeHttp {
            message: format!(
                "ACME sertifika uç noktası beklenmeyen durum döndürdü: {}",
                response.status
            ),
        });
    }

    write_text_file(&args.output, &response.body)?;
    let bundle_len = response.body.len();
    let location = snapshot.location.clone();
    println!(
        "acme fetch-cert: certificate={} | bytes={} | order={location}",
        args.output.display(),
        bundle_len,
    );

    Ok(())
}

fn handle_acme_revoke(args: &AcmeRevokeArgs) -> CliResult<()> {
    let (state, key) = load_account_state(&args.account)?;
    let kid = state
        .kid
        .as_deref()
        .ok_or_else(|| CliError::AcmeState("hesap dosyasında kid alanı bulunamadı".to_string()))?;

    let certificate_der = read_certificate_der(&args.certificate)?;
    let encoded = URL_SAFE_NO_PAD.encode(certificate_der);

    let mut client = AcmeClient::new(&args.server)?;
    let nonce = client.next_nonce()?;
    let revoke_url = client.revoke_cert_url().clone();
    let request = RevokeRequest {
        certificate: encoded.as_str(),
        reason: args.reason,
    };
    let jws = key.sign_json(&request, &nonce, &revoke_url, KeyBinding::Kid(kid))?;
    let response = client.post_jose(&revoke_url, &jws)?;
    if response.status != StatusCode::OK {
        return Err(CliError::AcmeHttp {
            message: format!("ACME revoke-cert beklenmeyen durum: {}", response.status),
        });
    }

    let payload: RevokeResponseBody = serde_json::from_str(&response.body)?;
    let reason = payload
        .reason
        .map_or_else(|| "(yok)".to_string(), |value| value.to_string());
    println!(
        "acme revoke: status={} | revoked_at={} | reason={}",
        payload.status, payload.revoked_at, reason
    );
    println!("  certificate: {}", args.certificate.display());
    println!("  account: {}", args.account.display());

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn handle_validate_endpoints(args: EndpointValidatorArgs) -> CliResult<()> {
    let EndpointValidatorArgs {
        base_url,
        auth_bearer,
        auth_basic,
        headers,
        seeds,
        concurrency,
        rate_limit_per_second,
        include_destructive,
        allowlist,
        markdown_report,
        json_output,
        timeout_secs,
        retries,
        backoff_ms,
    } = args;

    if auth_bearer.is_some() && auth_basic.is_some() {
        return Err(CliError::EndpointValidator(
            "--auth-bearer ve --auth-basic aynı anda kullanılamaz".to_string(),
        ));
    }

    let base_url = Url::parse(&base_url).map_err(|err| CliError::InvalidUrl(err.to_string()))?;
    let mut config = ValidatorConfig::with_base_url(base_url);
    if let Some(token) = auth_bearer {
        config.auth = Some(EndpointAuth::Bearer(token));
    }
    if let Some(creds) = auth_basic {
        let (username, password) = creds.split_once(':').ok_or_else(|| {
            CliError::EndpointValidator(
                "Basic kimlik bilgisi 'kullanici:sifre' formatında olmalıdır".to_string(),
            )
        })?;
        config.auth = Some(EndpointAuth::Basic {
            username: username.to_string(),
            password: password.to_string(),
        });
    }

    for header in headers {
        let (name, value) = parse_header_pair(&header)?;
        config.additional_headers.push((name, value));
    }

    config.seed_paths = seeds;
    config.include_destructive = include_destructive;
    config.concurrency = concurrency.max(1);
    config.rate_limit_per_second = rate_limit_per_second;
    config.timeout = Duration::from_secs(timeout_secs.max(1));
    config.retries = retries;
    config.backoff_base = Duration::from_millis(backoff_ms.max(1));
    if let Some(path) = allowlist {
        config.allowlist = load_allowlist(&path)?;
    }

    let runtime = Runtime::new().map_err(|err| {
        CliError::EndpointValidator(format!("Tokio runtime oluşturulamadı: {err}"))
    })?;
    let report = runtime
        .block_on(validate(config))
        .map_err(|err| CliError::EndpointValidator(err.to_string()))?;

    if let Some(path) = markdown_report.as_ref() {
        fs::write(path, report.to_markdown())?;
    }
    if let Some(path) = json_output.as_ref() {
        let json_output = serde_json::to_string_pretty(&report.to_json())?;
        fs::write(path, json_output)?;
    }

    let summary = report.summary();
    let failures = report.failures();
    println!(
        "endpoint-validator: {total} kontrol, {} başarısız (allowlist dışı), {allowlisted} allowlist",
        failures.len(),
        total = summary.total,
        allowlisted = summary.allowed_failures
    );

    if !failures.is_empty() {
        for failure in &failures {
            let status = failure
                .status
                .map_or_else(|| "-".to_string(), |value| value.to_string());
            let latency = failure
                .latency_ms
                .map_or_else(|| "-".to_string(), |value| value.to_string());
            let cause = failure
                .likely_cause
                .clone()
                .unwrap_or_else(|| "neden belirtilmedi".to_string());
            println!(
                "- {} {} → status={} latency={}ms | {}",
                failure.method, failure.path, status, latency, cause
            );
            if let Some(suggested) = &failure.suggested_fix {
                println!("  öneri: {suggested}");
            }
            if let Some(excerpt) = &failure.response_excerpt {
                println!("  örnek: {excerpt}");
            }
        }
        return Err(CliError::EndpointValidator(format!(
            "{} endpoint hatası bulundu",
            failures.len()
        )));
    }

    println!("Tüm endpoint kontrolleri başarıyla tamamlandı.");
    Ok(())
}

fn load_allowlist(path: &Path) -> CliResult<Vec<AllowlistedFailure>> {
    let data = fs::read(path)?;
    let mut entries: Vec<AllowlistedFailure> = serde_json::from_slice(&data)?;
    entries.sort();
    Ok(entries)
}

fn parse_header_pair(input: &str) -> CliResult<(HeaderName, HeaderValue)> {
    let (name, value) = input
        .split_once(':')
        .ok_or_else(|| CliError::InvalidHeader(input.to_string()))?;
    let header_name = HeaderName::from_bytes(name.trim().as_bytes())
        .map_err(|_| CliError::InvalidHeader(input.to_string()))?;
    let header_value = HeaderValue::from_str(value.trim())
        .map_err(|_| CliError::InvalidHeader(input.to_string()))?;
    Ok((header_name, header_value))
}

#[derive(Serialize)]
struct FinalizeRequest<'a> {
    csr: &'a str,
}

#[derive(Serialize)]
struct RevokeRequest<'a> {
    certificate: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<u8>,
}

fn read_csr_der(path: &Path) -> CliResult<Vec<u8>> {
    let data = fs::read(path)?;
    if data.is_empty() {
        return Err(CliError::AcmeState("CSR dosyası boş".to_string()));
    }
    let iter = data
        .iter()
        .copied()
        .skip_while(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'));
    let is_pem = iter.clone().take(10).eq("-----BEGIN".bytes());
    if is_pem {
        let pem_block = pem::parse(&data)
            .map_err(|err| CliError::AcmeState(format!("CSR PEM ayrıştırılamadı: {err}")))?;
        let tag = pem_block.tag().to_owned();
        let contents = pem_block.into_contents();
        if tag != "CERTIFICATE REQUEST" && tag != "NEW CERTIFICATE REQUEST" {
            return Err(CliError::AcmeState(format!(
                "CSR PEM etiketi geçersiz: {tag}"
            )));
        }
        if contents.is_empty() {
            return Err(CliError::AcmeState("CSR PEM içeriği boş".to_string()));
        }
        Ok(contents)
    } else {
        Ok(data)
    }
}

fn read_certificate_der(path: &Path) -> CliResult<Vec<u8>> {
    let data = fs::read(path)?;
    if data.is_empty() {
        return Err(CliError::AcmeState("Sertifika dosyası boş".to_string()));
    }
    let iter = data
        .iter()
        .copied()
        .skip_while(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'));
    let is_pem = iter.clone().take(10).eq("-----BEGIN".bytes());
    if is_pem {
        let blocks = pem::parse_many(&data)
            .map_err(|err| CliError::AcmeState(format!("Sertifika PEM ayrıştırılamadı: {err}")))?;
        let certificate = blocks
            .into_iter()
            .find(|block| block.tag() == "CERTIFICATE")
            .ok_or_else(|| {
                CliError::AcmeState("PEM içeriğinde CERTIFICATE bloğu bulunamadı".to_string())
            })?;
        let contents = certificate.into_contents();
        if contents.is_empty() {
            return Err(CliError::AcmeState("Sertifika PEM içeriği boş".to_string()));
        }
        Ok(contents)
    } else {
        Ok(data)
    }
}

fn build_acme_contacts(args: &AcmeRegisterArgs) -> CliResult<Vec<AccountContact>> {
    let mut contacts = Vec::new();
    for email in &args.email {
        contacts.push(AccountContact::email(email)?);
    }
    for uri in &args.contact {
        contacts.push(AccountContact::from_uri(uri)?);
    }
    Ok(contacts)
}

fn load_or_create_account_state(
    path: &Path,
) -> CliResult<(AcmeAccountState, Ed25519AccountKey, bool)> {
    if path.exists() {
        let state: AcmeAccountState = read_json_file(path)?;
        let key = state.account_key()?;
        Ok((state, key, false))
    } else {
        ensure_parent_dir(path)?;
        let (state, key) = AcmeAccountState::generate_ed25519();
        save_account_state(path, &state)?;
        Ok((state, key, true))
    }
}

fn load_account_state(path: &Path) -> CliResult<(AcmeAccountState, Ed25519AccountKey)> {
    if !path.exists() {
        return Err(CliError::AcmeState(format!(
            "hesap dosyası bulunamadı: {}",
            path.display()
        )));
    }
    let state: AcmeAccountState = read_json_file(path)?;
    let key = state.account_key()?;
    Ok((state, key))
}

fn save_account_state(path: &Path, state: &AcmeAccountState) -> CliResult<()> {
    write_json_pretty(path, state)
}

fn write_response_json(path: &Path, body: &str) -> CliResult<()> {
    let value: Value = serde_json::from_str(body)?;
    write_json_pretty(path, &value)
}

struct DirectoryDiscovery {
    directory: AcmeDirectory,
    raw_json: String,
}

struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

#[derive(Debug, Deserialize)]
struct AccountResponseBody {
    status: String,
    contact: Vec<String>,
    orders: String,
    #[serde(rename = "termsOfServiceAgreed")]
    terms_of_service_agreed: bool,
    kid: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct OrderResponseBody {
    status: String,
    identifiers: Vec<OrderIdentifierBody>,
    authorizations: Vec<String>,
    finalize: String,
    expires: String,
    #[serde(rename = "notBefore")]
    not_before: Option<String>,
    #[serde(rename = "notAfter")]
    not_after: Option<String>,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OrderIdentifierBody {
    #[serde(rename = "type")]
    ty: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct RevokeResponseBody {
    status: String,
    #[serde(rename = "revokedAt")]
    revoked_at: String,
    #[serde(default)]
    reason: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct ProblemResponseBody {
    #[serde(rename = "type")]
    problem_type: String,
    detail: String,
    status: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct AcmeOrderSnapshot {
    location: String,
    status: String,
    finalize: String,
    expires: String,
    #[serde(rename = "notBefore", default)]
    not_before: Option<String>,
    #[serde(rename = "notAfter", default)]
    not_after: Option<String>,
    identifiers: Vec<AcmeOrderIdentifierSnapshot>,
    authorizations: Vec<String>,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AcmeOrderIdentifierSnapshot {
    #[serde(rename = "type")]
    ty: String,
    value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum AcmeAccountAlgorithm {
    Ed25519,
}

#[derive(Debug, Serialize, Deserialize)]
struct AcmeAccountState {
    algorithm: AcmeAccountAlgorithm,
    #[serde(rename = "privateKey")]
    private_key: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    orders: Option<String>,
    #[serde(default)]
    contacts: Vec<String>,
    #[serde(rename = "createdAt", default)]
    created_at: Option<String>,
    #[serde(rename = "termsOfServiceAgreed", default)]
    terms_of_service_agreed: bool,
    #[serde(default)]
    last_order: Option<AcmeOrderSnapshot>,
}

impl AcmeAccountState {
    fn generate_ed25519() -> (Self, Ed25519AccountKey) {
        let mut seed = Zeroizing::new([0_u8; 32]);
        let mut rng = AunsormNativeRng::new();
        rng.fill_bytes(seed.as_mut());
        let key = Ed25519AccountKey::from_bytes(&seed);
        let encoded = URL_SAFE_NO_PAD.encode(seed.as_slice());
        let state = Self {
            algorithm: AcmeAccountAlgorithm::Ed25519,
            private_key: encoded,
            kid: None,
            orders: None,
            contacts: Vec::new(),
            created_at: None,
            terms_of_service_agreed: false,
            last_order: None,
        };
        (state, key)
    }

    fn account_key(&self) -> CliResult<Ed25519AccountKey> {
        match self.algorithm {
            AcmeAccountAlgorithm::Ed25519 => {
                let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(self.private_key.trim())?);
                if decoded.len() != 32 {
                    return Err(CliError::InvalidLength {
                        context: "acme account key",
                        expected: 32,
                        actual: decoded.len(),
                    });
                }
                let mut seed = Zeroizing::new([0_u8; 32]);
                seed.copy_from_slice(&decoded);
                Ok(Ed25519AccountKey::from_bytes(&seed))
            }
        }
    }

    fn update_from_account_response(&mut self, response: &AccountResponseBody) {
        self.kid = Some(response.kid.clone());
        self.orders = Some(response.orders.clone());
        self.contacts.clone_from(&response.contact);
        self.created_at = Some(response.created_at.clone());
        self.terms_of_service_agreed = response.terms_of_service_agreed;
    }

    fn record_last_order(&mut self, location: String, response: &OrderResponseBody) {
        let identifiers = response
            .identifiers
            .iter()
            .map(|item| AcmeOrderIdentifierSnapshot {
                ty: item.ty.clone(),
                value: item.value.clone(),
            })
            .collect();
        self.last_order = Some(AcmeOrderSnapshot {
            location,
            status: response.status.clone(),
            finalize: response.finalize.clone(),
            expires: response.expires.clone(),
            not_before: response.not_before.clone(),
            not_after: response.not_after.clone(),
            identifiers,
            authorizations: response.authorizations.clone(),
            certificate: response.certificate.clone(),
        });
    }
}

struct AcmeClient {
    agent: Agent,
    directory_url: Url,
    new_account_url: Url,
    new_order_url: Url,
    revoke_cert_url: Url,
    nonce_manager: NonceManager<NewNonceTransport>,
}

#[derive(Clone)]
struct NewNonceTransport {
    agent: Agent,
}

impl NewNonceRequester for NewNonceTransport {
    fn request_new_nonce(&self, url: &Url) -> Result<HeaderMap, NonceRequestError> {
        let response = self
            .agent
            .get(url.as_str())
            .call()
            .map_err(NonceRequestError::transport)?;

        let mut headers = HeaderMap::new();
        if let Some(value) = response.header(REPLAY_NONCE_HEADER) {
            let header_value =
                HeaderValue::from_str(value).map_err(NonceRequestError::transport)?;
            headers.insert(HeaderName::from_static("replay-nonce"), header_value);
        }
        Ok(headers)
    }
}

impl AcmeClient {
    fn new(server: &str) -> CliResult<Self> {
        let base = Url::parse(server).map_err(|err| CliError::InvalidUrl(err.to_string()))?;
        let directory_url = base
            .join("acme/directory")
            .map_err(|err| CliError::InvalidUrl(err.to_string()))?;
        let new_nonce_url = base
            .join("acme/new-nonce")
            .map_err(|err| CliError::InvalidUrl(err.to_string()))?;
        let new_account_url = base
            .join("acme/new-account")
            .map_err(|err| CliError::InvalidUrl(err.to_string()))?;
        let new_order_url = base
            .join("acme/new-order")
            .map_err(|err| CliError::InvalidUrl(err.to_string()))?;
        let revoke_cert_url = base
            .join("acme/revoke-cert")
            .map_err(|err| CliError::InvalidUrl(err.to_string()))?;

        let agent = Agent::new();
        let nonce_transport = NewNonceTransport {
            agent: agent.clone(),
        };
        let nonce_manager = NonceManager::new(nonce_transport, new_nonce_url);

        Ok(Self {
            agent,
            directory_url,
            new_account_url,
            new_order_url,
            revoke_cert_url,
            nonce_manager,
        })
    }

    const fn new_account_url(&self) -> &Url {
        &self.new_account_url
    }

    const fn new_order_url(&self) -> &Url {
        &self.new_order_url
    }

    const fn revoke_cert_url(&self) -> &Url {
        &self.revoke_cert_url
    }

    fn next_nonce(&mut self) -> CliResult<ReplayNonce> {
        Ok(self.nonce_manager.pop_or_fetch()?)
    }

    fn fetch_directory(&mut self) -> CliResult<DirectoryDiscovery> {
        let directory_url = self.directory_url.clone();
        let response = self.get(&directory_url)?;
        let directory = AcmeDirectory::from_json_slice(response.body.as_bytes())?;
        Ok(DirectoryDiscovery {
            directory,
            raw_json: response.body,
        })
    }

    fn post_jose(&mut self, url: &Url, payload: &AcmeJws) -> CliResult<HttpResponse> {
        let json = serde_json::to_string(payload)?;
        let request = self
            .agent
            .post(url.as_str())
            .set("Content-Type", "application/jose+json");
        self.map_response(request.send_string(&json))
    }

    fn get(&mut self, url: &Url) -> CliResult<HttpResponse> {
        self.map_response(self.agent.get(url.as_str()).call())
    }

    fn map_response(
        &mut self,
        result: Result<ureq::Response, UreqError>,
    ) -> CliResult<HttpResponse> {
        match result {
            Ok(response) => {
                let headers = header_map_from_response(&response)?;
                self.absorb_nonce(&headers)?;
                let status = status_from_code(response.status())?;
                let body = response.into_string()?;
                Ok(HttpResponse {
                    status,
                    headers,
                    body,
                })
            }
            Err(UreqError::Status(status, response)) => {
                let headers = header_map_from_response(&response)?;
                self.absorb_nonce(&headers)?;
                let body = response.into_string()?;
                if let Ok(problem) = serde_json::from_str::<ProblemResponseBody>(&body) {
                    return Err(CliError::AcmeProblem {
                        status: problem.status,
                        problem_type: problem.problem_type,
                        detail: problem.detail,
                    });
                }
                Err(CliError::AcmeHttp {
                    message: format!("HTTP {status} yanıtı: {body}"),
                })
            }
            Err(err) => Err(CliError::AcmeHttp {
                message: err.to_string(),
            }),
        }
    }

    fn absorb_nonce(&mut self, headers: &HeaderMap) -> CliResult<()> {
        let _ = self.nonce_manager.absorb_response(headers)?;
        Ok(())
    }
}

fn header_map_from_response(response: &ureq::Response) -> CliResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    for name in response.headers_names() {
        let header_name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|err| CliError::AcmeHttp {
                message: format!("HTTP başlığı geçersiz ({name}): {err}"),
            })?;
        for value in response.all(&name) {
            let header_value =
                HeaderValue::from_bytes(value.as_bytes()).map_err(|err| CliError::AcmeHttp {
                    message: format!("HTTP başlık değeri geçersiz ({name}): {err}"),
                })?;
            headers.append(header_name.clone(), header_value);
        }
    }
    Ok(headers)
}

fn status_from_code(code: u16) -> CliResult<StatusCode> {
    StatusCode::from_u16(code).map_err(|err| CliError::AcmeHttp {
        message: format!("HTTP durum kodu geçersiz: {err}"),
    })
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

fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> CliResult<()> {
    if is_stdout_path(path) {
        let json = serde_json::to_string_pretty(value)?;
        println!("{json}");
        return Ok(());
    }
    ensure_parent_dir(path)?;
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json.as_bytes())?;
    Ok(())
}

fn write_text_file(path: &Path, contents: &str) -> CliResult<()> {
    if is_stdout_path(path) {
        println!("{contents}");
        return Ok(());
    }
    ensure_parent_dir(path)?;
    fs::write(path, contents.as_bytes())?;
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

fn strip_utf8_bom_mut(text: &mut String) {
    const UTF8_BOM: char = '\u{feff}';
    if text.starts_with(UTF8_BOM) {
        text.drain(..UTF8_BOM.len_utf8());
    }
}

fn load_password(
    password: Option<&str>,
    password_file: Option<&Path>,
) -> CliResult<Zeroizing<String>> {
    match (password, password_file) {
        (Some(pw), None) => {
            let mut owned = pw.to_owned();
            strip_utf8_bom_mut(&mut owned);
            if owned.is_empty() {
                return Err(CliError::EmptySecret("parola"));
            }
            Ok(Zeroizing::new(owned))
        }
        (None, Some(path)) => {
            let mut secret = Zeroizing::new(fs::read_to_string(path)?);
            strip_utf8_bom_mut(&mut secret);
            while secret.ends_with('\n') || secret.ends_with('\r') {
                secret.pop();
            }
            if secret.is_empty() {
                return Err(CliError::EmptySecret("parola"));
            }
            Ok(secret)
        }
        (None, None) => Err(CliError::MissingParam("password")),
        (Some(_), Some(_)) => unreachable!("clap enforces mutual exclusion"),
    }
}

fn load_calibration_text(calib_text: Option<&str>, calib_file: Option<&Path>) -> CliResult<String> {
    match (calib_text, calib_file) {
        (Some(text), None) => {
            let mut owned = text.to_owned();
            strip_utf8_bom_mut(&mut owned);
            if owned.trim().is_empty() {
                return Err(CliError::EmptySecret("kalibrasyon metni"));
            }
            Ok(owned)
        }
        (None, Some(path)) => {
            let mut content = fs::read_to_string(path)?;
            strip_utf8_bom_mut(&mut content);
            let trimmed = content.trim_end_matches(['\n', '\r']);
            if trimmed.trim().is_empty() {
                return Err(CliError::EmptySecret("kalibrasyon metni"));
            }
            Ok(trimmed.to_owned())
        }
        (None, None) => Err(CliError::MissingParam("calib_text")),
        (Some(_), Some(_)) => unreachable!("clap enforces mutual exclusion"),
    }
}

fn load_aad(aad_text: Option<&str>, aad_file: Option<&Path>) -> CliResult<Vec<u8>> {
    match (aad_text, aad_file) {
        (Some(_), Some(_)) => Err(CliError::AadConflict),
        (Some(text), None) => Ok(text.as_bytes().to_vec()),
        (None, Some(path)) => Ok(fs::read(path)?),
        (None, None) => Ok(Vec::new()),
    }
}

const MIN_ORG_SALT_LEN: usize = 8;

fn decode_org_salt(value: &str) -> CliResult<Vec<u8>> {
    let trimmed = value.trim();
    let decoded = STANDARD.decode(trimmed)?;
    if decoded.len() < MIN_ORG_SALT_LEN {
        return Err(CliError::InvalidLength {
            context: "org-salt",
            expected: MIN_ORG_SALT_LEN,
            actual: decoded.len(),
        });
    }
    Ok(decoded)
}

fn parse_ip_addrs(values: &[String]) -> CliResult<Vec<IpAddr>> {
    let mut result = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let addr: IpAddr = trimmed
            .parse()
            .map_err(|_| CliError::InvalidIpAddress(trimmed.to_owned()))?;
        result.push(addr);
    }
    Ok(result)
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
    StrictMode::from_env().is_strict()
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
    let mut staged: Vec<(String, Value)> = Vec::with_capacity(map.len());
    for (key, val) in map {
        match key.as_str() {
            "iss" | "sub" | "aud" | "exp" | "nbf" | "iat" | "jti" => {
                return Err(CliError::ClaimReserved(key.clone()))
            }
            _ => {}
        }
        if !is_camel_case(key) {
            return Err(CliError::ClaimInvalidFormat(key.clone()));
        }
        if let Some(invalid_path) = find_invalid_nested_key(val, key) {
            return Err(CliError::ClaimInvalidFormat(invalid_path));
        }
        staged.push((key.clone(), val.clone()));
    }
    for (key, val) in staged {
        claims.extra.insert(key, val);
    }
    Ok(())
}

fn is_camel_case(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() && ch != '_')
}

fn extend_path(parent: &str, segment: &str) -> String {
    if parent.is_empty() {
        segment.to_owned()
    } else if segment.starts_with('[') {
        format!("{parent}{segment}")
    } else {
        format!("{parent}.{segment}")
    }
}

fn find_invalid_nested_key(value: &Value, parent: &str) -> Option<String> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if !is_camel_case(key) {
                    return Some(extend_path(parent, key));
                }
                if let Some(invalid) = find_invalid_nested_key(child, &extend_path(parent, key)) {
                    return Some(invalid);
                }
            }
            None
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let segment = format!("[{index}]");
                if let Some(invalid) = find_invalid_nested_key(item, &extend_path(parent, &segment))
                {
                    return Some(invalid);
                }
            }
            None
        }
        _ => None,
    }
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
    use pem::Pem;
    use serde_json::{json, Value};
    use std::thread;
    use tempfile::{tempdir, NamedTempFile};
    use tiny_http::{Header, Method, Request, Response, Server};

    #[test]
    fn host_to_server_url_formats_ipv6_hosts() {
        assert_eq!(host_to_server_url("::1"), "http://[::1]:8080");
        assert_eq!(
            host_to_server_url("  fd00::feed  "),
            "http://[fd00::feed]:8080"
        );
    }

    #[test]
    fn host_to_server_url_handles_ipv4_hostnames_and_empty_input() {
        assert_eq!(
            host_to_server_url("192.168.1.10"),
            "http://192.168.1.10:8080"
        );
        assert_eq!(
            host_to_server_url("aunsorm.local"),
            "http://aunsorm.local:8080"
        );
        assert_eq!(host_to_server_url("   "), "http://localhost:8080");
    }

    #[test]
    fn acme_account_state_roundtrip_key() {
        let (state, key) = AcmeAccountState::generate_ed25519();
        assert!(matches!(state.algorithm, AcmeAccountAlgorithm::Ed25519));
        let restored = state.account_key().expect("account key");
        assert_eq!(
            restored.verifying_key().as_bytes(),
            key.verifying_key().as_bytes()
        );
        assert_eq!(
            state.private_key.len(),
            URL_SAFE_NO_PAD.encode([0_u8; 32]).len()
        );
    }

    #[test]
    fn load_or_create_account_state_persists_file() {
        let dir = tempdir().expect("dir");
        let path = dir.path().join("account.json");

        let (_state, key, created) = load_or_create_account_state(&path).expect("create");
        assert!(created);
        assert!(path.exists());
        let raw = fs::read_to_string(&path).expect("raw");
        assert!(raw.contains("privateKey"));

        drop(key);
        let (loaded_state, loaded_key, created_again) =
            load_or_create_account_state(&path).expect("reload");
        assert!(!created_again);
        let derived = loaded_state.account_key().expect("derived");
        assert_eq!(
            derived.verifying_key().as_bytes(),
            loaded_key.verifying_key().as_bytes()
        );
    }

    #[test]
    fn read_csr_der_accepts_pem() {
        let file = NamedTempFile::new().expect("pem csr");
        let der = vec![0x01_u8, 0x02, 0xA5, 0xFF];
        let pem = Pem::new("CERTIFICATE REQUEST", der.clone());
        fs::write(file.path(), pem::encode(&pem)).expect("write pem");

        let parsed = read_csr_der(file.path()).expect("csr");
        assert_eq!(parsed, der);
    }

    #[test]
    fn read_csr_der_accepts_der_bytes() {
        let file = NamedTempFile::new().expect("der csr");
        let der = vec![0xAA_u8, 0xBB, 0xCC, 0xDD];
        fs::write(file.path(), &der).expect("write der");

        let parsed = read_csr_der(file.path()).expect("csr");
        assert_eq!(parsed, der);
    }

    #[test]
    fn read_csr_der_rejects_invalid_pem_tag() {
        let file = NamedTempFile::new().expect("invalid pem");
        let pem = Pem::new("CERTIFICATE", vec![0x01_u8; 8]);
        fs::write(file.path(), pem::encode(&pem)).expect("write pem");

        let err = read_csr_der(file.path()).expect_err("should fail");
        match err {
            CliError::AcmeState(message) => {
                assert!(message.contains("etiketi"), "unexpected message: {message}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    struct FinalizeServerParams {
        finalize_path: String,
        expected_csr: String,
        base_url: String,
        finalize_url: String,
        certificate_url: String,
        order_location: String,
        nonce0: String,
        nonce1: String,
    }

    fn spawn_finalize_server(
        server: Server,
        params: FinalizeServerParams,
    ) -> thread::JoinHandle<()> {
        let FinalizeServerParams {
            finalize_path,
            expected_csr,
            base_url,
            finalize_url,
            certificate_url,
            order_location,
            nonce0,
            nonce1,
        } = params;
        thread::spawn(move || {
            for request in server.incoming_requests() {
                let method = request.method().clone();
                let url = request.url().to_string();
                if method == Method::Get && url == "/acme/new-nonce" {
                    respond_with_nonce(request, &nonce0);
                } else if method == Method::Post && url == finalize_path {
                    respond_finalize(
                        request,
                        &expected_csr,
                        &base_url,
                        &finalize_url,
                        &certificate_url,
                        &order_location,
                        &nonce1,
                    );
                    break;
                } else {
                    respond_not_found(request);
                }
            }
        })
    }

    fn respond_with_nonce(request: Request, nonce: &str) {
        let mut response = Response::from_string("");
        response.add_header(Header::from_bytes("Replay-Nonce", nonce).unwrap());
        request.respond(response).expect("respond nonce");
    }

    #[allow(clippy::too_many_arguments)] // test helper wires full ACME response fields
    fn respond_finalize(
        mut request: Request,
        expected_csr: &str,
        base_url: &str,
        finalize_url: &str,
        certificate_url: &str,
        order_location: &str,
        nonce: &str,
    ) {
        let mut body = String::new();
        request
            .as_reader()
            .read_to_string(&mut body)
            .expect("read finalize body");
        let envelope: Value = serde_json::from_str(&body).expect("envelope json");
        let payload_b64 = envelope
            .get("payload")
            .and_then(Value::as_str)
            .expect("payload field");
        let payload_json = URL_SAFE_NO_PAD.decode(payload_b64).expect("decode payload");
        let payload: Value = serde_json::from_slice(&payload_json).expect("payload json");
        let received = payload
            .get("csr")
            .and_then(Value::as_str)
            .expect("csr field");
        assert_eq!(received, expected_csr);

        let response_body = json!({
            "status": "valid",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "authorizations": [format!("{base_url}/acme/authz/order123-00")],
            "finalize": finalize_url,
            "expires": "2025-11-02T00:00:00Z",
            "certificate": certificate_url,
        });
        let mut response = Response::from_string(response_body.to_string());
        response.add_header(Header::from_bytes("content-type", "application/json").unwrap());
        response.add_header(Header::from_bytes("Replay-Nonce", nonce).unwrap());
        response.add_header(Header::from_bytes("Location", order_location).unwrap());
        request.respond(response).expect("respond finalize");
    }

    fn respond_certificate(request: Request, body: &str, nonce: &str) {
        let mut response = Response::from_string(body.to_string());
        response
            .add_header(Header::from_bytes("content-type", "text/plain; charset=utf-8").unwrap());
        response.add_header(Header::from_bytes("Replay-Nonce", nonce).unwrap());
        request.respond(response).expect("respond certificate");
    }

    fn respond_not_found(request: Request) {
        let response = Response::from_string("not found").with_status_code(404);
        request.respond(response).expect("respond fallback");
    }

    #[test]
    fn handle_acme_finalize_updates_state() {
        let server = Server::http(("127.0.0.1", 0)).expect("server");
        let base_url = format!("http://{}", server.server_addr());
        let order_location = format!("{base_url}/acme/order/order123");
        let finalize_url = format!("{order_location}/finalize");
        let certificate_url = format!("{base_url}/acme/cert/order123");

        let account_file = NamedTempFile::new().expect("account");
        let account_path = account_file.path().to_path_buf();
        let (mut state, _key) = AcmeAccountState::generate_ed25519();
        state.kid = Some(format!("{base_url}/acme/account/acct123"));
        let initial_order = OrderResponseBody {
            status: "pending".to_string(),
            identifiers: vec![OrderIdentifierBody {
                ty: "dns".to_string(),
                value: "example.com".to_string(),
            }],
            authorizations: vec![format!("{}/acme/authz/order123-00", base_url)],
            finalize: finalize_url.clone(),
            expires: "2025-11-01T00:00:00Z".to_string(),
            not_before: None,
            not_after: None,
            certificate: None,
        };
        state.record_last_order(order_location.clone(), &initial_order);
        save_account_state(account_file.path(), &state).expect("save state");
        drop(state);

        let csr_file = NamedTempFile::new().expect("csr");
        let csr_der = vec![0x10_u8, 0x20, 0x30, 0x40];
        let csr_pem = Pem::new("CERTIFICATE REQUEST", csr_der.clone());
        fs::write(csr_file.path(), pem::encode(&csr_pem)).expect("write csr");
        let expected_csr = URL_SAFE_NO_PAD.encode(&csr_der);

        let output_file = NamedTempFile::new().expect("order json");
        let output_path = output_file.path().to_path_buf();

        let finalize_path = String::from("/acme/order/order123/finalize");
        let nonce0 = URL_SAFE_NO_PAD.encode(b"nonce-value-0000");
        let nonce1 = URL_SAFE_NO_PAD.encode(b"nonce-value-0001");
        let params = FinalizeServerParams {
            finalize_path,
            expected_csr,
            base_url: base_url.clone(),
            finalize_url,
            certificate_url: certificate_url.clone(),
            order_location: order_location.clone(),
            nonce0,
            nonce1,
        };
        let handle = spawn_finalize_server(server, params);

        let args = AcmeFinalizeArgs {
            server: base_url,
            account: account_path.clone(),
            csr: csr_file.path().to_path_buf(),
            output: Some(output_path.clone()),
        };
        handle_acme_finalize(&args).expect("finalize");

        handle.join().expect("server thread");

        let updated: AcmeAccountState = read_json_file(account_path.as_path()).expect("state");
        let snapshot = updated.last_order.expect("last order snapshot");
        assert_eq!(snapshot.status, "valid");
        assert_eq!(snapshot.location, order_location);
        assert_eq!(
            snapshot.certificate.as_deref(),
            Some(certificate_url.as_str())
        );

        let response_json: Value = read_json_file(output_path.as_path()).expect("order json");
        assert_eq!(response_json["status"], "valid");
        assert_eq!(response_json["certificate"], certificate_url);
    }

    #[test]
    fn handle_acme_fetch_cert_downloads_bundle() {
        let server = Server::http(("127.0.0.1", 0)).expect("server");
        let base_url = format!("http://{}", server.server_addr());
        let order_location = format!("{base_url}/acme/order/order123");
        let certificate_url = format!("{base_url}/acme/cert/order123");

        let account_file = NamedTempFile::new().expect("account");
        let account_path = account_file.path().to_path_buf();
        let (mut state, _key) = AcmeAccountState::generate_ed25519();
        state.kid = Some(format!("{base_url}/acme/account/acct123"));
        state.last_order = Some(AcmeOrderSnapshot {
            location: order_location.clone(),
            status: "valid".to_string(),
            finalize: format!("{order_location}/finalize"),
            expires: "2025-11-02T00:00:00Z".to_string(),
            not_before: None,
            not_after: None,
            identifiers: vec![AcmeOrderIdentifierSnapshot {
                ty: "dns".to_string(),
                value: "example.com".to_string(),
            }],
            authorizations: vec![format!("{base_url}/acme/authz/order123-00")],
            certificate: Some(certificate_url.clone()),
        });
        save_account_state(account_file.path(), &state).expect("save state");

        let certificate_body = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n";
        let bundle_path = NamedTempFile::new().expect("bundle");
        let output_path = bundle_path.path().to_path_buf();
        let nonce = URL_SAFE_NO_PAD.encode(b"nonce-value-0002");
        let handle = thread::spawn(move || {
            for request in server.incoming_requests() {
                let method = request.method().clone();
                let url = request.url().to_string();
                if method == Method::Get && url == "/acme/cert/order123" {
                    respond_certificate(request, certificate_body, &nonce);
                    break;
                }
                respond_not_found(request);
            }
        });

        let args = AcmeFetchCertArgs {
            server: base_url,
            account: account_path.clone(),
            output: output_path.clone(),
        };
        handle_acme_fetch_cert(&args).expect("fetch");
        handle.join().expect("server thread");

        let downloaded = fs::read_to_string(output_path.as_path()).expect("bundle read");
        assert_eq!(downloaded, certificate_body);

        let persisted: AcmeAccountState =
            read_json_file(account_path.as_path()).expect("state persisted");
        let stored_certificate = persisted
            .last_order
            .expect("last order snapshot")
            .certificate
            .expect("certificate url");
        assert_eq!(stored_certificate, certificate_url);
    }

    #[test]
    fn pq_status_marks_default_algorithms_available() {
        let ctx = StrictContext {
            cli_flag: false,
            env_active: false,
        };
        let report = build_pq_status_report(ctx);
        assert!(report.readiness.kem_ready);
        assert!(report.readiness.signature_ready);
        assert!(report.readiness.strict_compliant);
        assert!(report.warnings.is_empty());
        assert!(report
            .kem
            .iter()
            .any(|status| status.name == "ml-kem-768" && status.available));
        assert!(report
            .signatures
            .iter()
            .any(|status| status.name == "ml-dsa-65" && status.available));
    }

    #[test]
    fn pq_status_text_output_is_human_readable() {
        let ctx = StrictContext {
            cli_flag: true,
            env_active: true,
        };
        let report = build_pq_status_report(ctx);
        let rendered = render_pq_status_text(&report);
        assert!(rendered.contains("Strict flag (--strict): yes"));
        assert!(rendered.contains("ml-kem-768"));
        assert!(rendered.contains("Warnings:"));
    }

    #[test]
    fn pq_checklist_text_is_actionable() {
        let strict = StrictContext {
            cli_flag: true,
            env_active: false,
        };
        let checklist = SignatureAlgorithm::MlDsa65.checklist();
        let report = build_signature_checklist_report(&checklist, strict);
        let rendered = render_signature_checklist_text(&report);
        assert!(rendered.contains("Algorithm: ml-dsa-65"));
        assert!(rendered.contains("Client hardening steps"));
        assert!(rendered.contains("Strict active: yes"));
        assert!(rendered.contains("NIST category: 5"));
    }

    #[test]
    fn pq_checklist_json_includes_metadata() {
        let strict = StrictContext {
            cli_flag: false,
            env_active: false,
        };
        let checklist = SignatureAlgorithm::Falcon512.checklist();
        let report = build_signature_checklist_report(&checklist, strict);
        let value = serde_json::to_value(&report).expect("json value");
        assert_eq!(value["algorithm"], "falcon-512");
        assert_eq!(value["nist_category"], "3");
        assert!(value["client_actions"]
            .as_array()
            .is_some_and(|arr| arr.len() >= 3));
    }

    #[test]
    fn salts_are_deterministic() {
        let org = STANDARD.decode("V2VBcmVLdXQuZXU=").expect("org salt");
        let (calibration, _) = calib_from_text(&org, "demo calib").expect("calibration");
        let (pwd_a, salts_a) = derive_salts(&org, calibration.id.as_str()).expect("salts");
        let (pwd_b, salts_b) = derive_salts(&org, calibration.id.as_str()).expect("salts");
        assert_eq!(pwd_a.as_slice(), pwd_b.as_slice());
        assert_eq!(salts_a, salts_b);
    }

    #[test]
    fn calibration_report_reflects_calibration() {
        let (calibration, _) = calib_from_text(b"org-salt", "note").expect("calibration");
        let report = build_calibration_report(&calibration);
        assert_eq!(report.calibration_id, calibration.id.as_str());
        assert_eq!(report.note_text, calibration.note_text());
        assert_eq!(report.alpha_long, calibration.alpha_long);
        assert_eq!(report.ranges[0].start, calibration.ranges[0].start);
        assert_eq!(report.fingerprint, calibration.fingerprint_b64());
        assert_eq!(report.fingerprint_hex, calibration.fingerprint_hex());
    }

    #[test]
    fn calibration_text_report_is_human_readable() {
        let (calibration, _) = calib_from_text(b"org-salt", "note").expect("calibration");
        let report = build_calibration_report(&calibration);
        let rendered = render_calibration_report_text(&report);
        assert!(rendered.contains("Kalibrasyon Kimliği"));
        assert!(rendered.contains(calibration.id.as_str()));
        assert!(rendered.contains(calibration.note_text()));
        assert!(rendered.contains("Aralıklar:"));
        assert!(rendered.contains(report.fingerprint.as_str()));
        assert!(rendered.contains(report.fingerprint_hex.as_str()));
    }

    #[test]
    fn calibration_fingerprint_report_is_consistent() {
        let (calibration, _) = calib_from_text(b"org-salt", "note").expect("calibration");
        let report = build_calibration_fingerprint_report(&calibration);
        assert_eq!(report.calibration_id, calibration.id.as_str());
        assert_eq!(report.fingerprint_b64, calibration.fingerprint_b64());
        assert_eq!(report.fingerprint_hex, calibration.fingerprint_hex());
    }

    #[test]
    fn calibration_fingerprint_text_is_human_readable() {
        let (calibration, _) = calib_from_text(b"org-salt", "note").expect("calibration");
        let report = build_calibration_fingerprint_report(&calibration);
        let rendered = render_calibration_fingerprint_report_text(&report);
        assert!(rendered.contains("Kalibrasyon Kimliği"));
        assert!(rendered.contains(report.fingerprint_b64.as_str()));
        assert!(rendered.contains(report.fingerprint_hex.as_str()));
    }

    #[test]
    fn coordinate_report_reflects_inputs() {
        let org = STANDARD.decode("V2VBcmVLdXQuZXU=").expect("org salt");
        let (calibration, _) = calib_from_text(&org, "demo calib").expect("calibration");
        let (password_salt, salts) = derive_salts(&org, calibration.id.as_str()).expect("salts");
        let profile = ProfileArg::Low;
        let (seed, _pdk, info) = derive_seed64_and_pdk(
            "correct horse battery staple",
            password_salt.as_slice(),
            salts.calibration(),
            salts.chain(),
            profile.as_profile(),
        )
        .expect("seed");
        let (coord_id, coord) = coord32_derive(seed.as_ref(), &calibration, &salts).expect("coord");
        let report = build_coordinate_report(&calibration, coord_id.clone(), coord, profile, &info);
        assert_eq!(report.calibration_id, calibration.id.as_str());
        assert_eq!(report.coord_id, coord_id);
        assert_eq!(report.coord, STANDARD.encode(coord));
        assert_eq!(report.profile, profile.to_string());
        assert_eq!(
            report.password_salt_digest,
            STANDARD.encode(info.password_salt_digest)
        );
        assert_eq!(
            report.calibration_salt_digest,
            STANDARD.encode(info.calibration_salt_digest)
        );
        assert_eq!(
            report.chain_salt_digest,
            STANDARD.encode(info.chain_salt_digest)
        );
    }

    #[test]
    fn write_coord_raw_writes_exact_bytes() {
        let tmp = NamedTempFile::new().expect("tmp");
        let coord = [0xAA_u8; 32];
        write_coord_raw(Some(tmp.path()), &coord).expect("write");
        let raw = fs::read(tmp.path()).expect("raw");
        assert_eq!(raw, coord);
    }

    #[test]
    fn write_bytes_creates_parent_directories() {
        let tmpdir = tempdir().expect("tmpdir");
        let nested = tmpdir
            .path()
            .join("artifacts")
            .join("raw")
            .join("coord.bin");
        let payload = [0x42_u8; 16];
        write_bytes(&nested, &payload).expect("write bytes");
        let raw = fs::read(&nested).expect("raw nested");
        assert_eq!(raw, payload);
    }

    #[test]
    fn handle_calib_coord_respects_raw_output() {
        let password = "correct horse battery staple";
        let org_salt_b64 = "V2VBcmVLdXQuZXU=";
        let calibration_text = "Neudzulab | Prod | 2025-08";
        let tmp = NamedTempFile::new().expect("tmp");

        let args = CalibCoordArgs {
            password: Some(password.to_string()),
            password_file: None,
            org_salt: org_salt_b64.to_string(),
            calib_text: Some(calibration_text.to_string()),
            calib_file: None,
            kdf: ProfileArg::Low,
            format: ReportFormat::Json,
            out: None,
            coord_raw_out: Some(tmp.path().to_path_buf()),
        };

        handle_calib_coord(&args).expect("coord");

        let raw = fs::read(tmp.path()).expect("raw");
        assert_eq!(raw.len(), 32);

        let org_salt = decode_org_salt(org_salt_b64).expect("salt");
        let (calibration, _) = calib_from_text(&org_salt, calibration_text).expect("calib");
        let (password_salt, salts) =
            derive_salts(&org_salt, calibration.id.as_str()).expect("salts");
        let (seed64, _, _) = derive_seed64_and_pdk(
            password,
            password_salt.as_slice(),
            salts.calibration(),
            salts.chain(),
            args.kdf.as_profile(),
        )
        .expect("seed");
        let (_, expected_coord) =
            coord32_derive(seed64.as_ref(), &calibration, &salts).expect("coord");
        assert_eq!(raw, expected_coord);
    }

    #[test]
    fn coordinate_text_report_lists_salts() {
        let org = STANDARD.decode("V2VBcmVLdXQuZXU=").expect("org salt");
        let (calibration, _) = calib_from_text(&org, "demo calib").expect("calibration");
        let (password_salt, salts) = derive_salts(&org, calibration.id.as_str()).expect("salts");
        let profile = ProfileArg::Medium;
        let (seed, _pdk, info) = derive_seed64_and_pdk(
            "correct horse battery staple",
            password_salt.as_slice(),
            salts.calibration(),
            salts.chain(),
            profile.as_profile(),
        )
        .expect("seed");
        let (coord_id, coord) = coord32_derive(seed.as_ref(), &calibration, &salts).expect("coord");
        let report = build_coordinate_report(&calibration, coord_id, coord, profile, &info);
        let rendered = render_coordinate_report_text(&report);
        assert!(rendered.contains("Tuz Özetleri:"));
        assert!(rendered.contains(report.password_salt_digest.as_str()));
        assert!(rendered.contains(report.calibration_salt_digest.as_str()));
        assert!(rendered.contains(report.chain_salt_digest.as_str()));
    }

    #[test]
    fn emit_json_pretty_writes_to_file_when_requested() {
        let tmp = NamedTempFile::new().expect("tmp");
        let payload = json!({ "key": "value" });
        emit_json_pretty(&payload, Some(tmp.path())).expect("emit");
        let written = fs::read_to_string(tmp.path()).expect("read");
        assert_eq!(
            written,
            serde_json::to_string_pretty(&payload).expect("json")
        );
    }

    #[test]
    fn emit_text_writes_to_file_when_requested() {
        let tmp = NamedTempFile::new().expect("tmp");
        emit_text("deneme çıktısı", Some(tmp.path())).expect("emit text");
        let written = fs::read_to_string(tmp.path()).expect("read");
        assert_eq!(written, "deneme çıktısı\n");
    }

    #[test]
    fn emit_text_creates_parent_directories() {
        let tmpdir = tempdir().expect("tmpdir");
        let nested = tmpdir.path().join("reports").join("pq").join("status.txt");
        emit_text("durum", Some(&nested)).expect("emit text");
        let written = fs::read_to_string(&nested).expect("read nested");
        assert_eq!(written, "durum\n");
    }

    #[test]
    fn aad_conflict_is_rejected() {
        let err = load_aad(Some("demo"), Some(Path::new("/tmp/demo"))).unwrap_err();
        assert!(matches!(err, CliError::AadConflict));
    }

    #[test]
    fn password_from_cli_is_validated() {
        let err = load_password(Some(""), None).unwrap_err();
        assert!(matches!(err, CliError::EmptySecret("parola")));
    }

    #[test]
    fn password_file_trims_newline() {
        let file = NamedTempFile::new().expect("tmp");
        fs::write(file.path(), "sekret\n").expect("write");
        let password = load_password(None, Some(file.path())).expect("password");
        assert_eq!(&*password, "sekret");
    }

    #[test]
    fn password_file_rejects_empty() {
        let file = NamedTempFile::new().expect("tmp");
        fs::write(file.path(), "\n").expect("write");
        let err = load_password(None, Some(file.path())).unwrap_err();
        assert!(matches!(err, CliError::EmptySecret("parola")));
    }

    #[test]
    fn password_cli_strips_utf8_bom() {
        let password = load_password(Some("\u{feff}sekret"), None).expect("password");
        assert_eq!(&*password, "sekret");
    }

    #[test]
    fn password_file_strips_utf8_bom() {
        let file = NamedTempFile::new().expect("tmp");
        fs::write(file.path(), "\u{feff}sekret\r\n").expect("write");
        let password = load_password(None, Some(file.path())).expect("password");
        assert_eq!(&*password, "sekret");
    }

    #[test]
    fn calibration_text_rejects_blank() {
        let err = load_calibration_text(Some("   \t"), None).unwrap_err();
        assert!(matches!(err, CliError::EmptySecret("kalibrasyon metni")));
    }

    #[test]
    fn calibration_file_trims_newline() {
        let file = NamedTempFile::new().expect("tmp");
        fs::write(file.path(), "Context\n").expect("write");
        let text = load_calibration_text(None, Some(file.path())).expect("calib");
        assert_eq!(text, "Context");
    }

    #[test]
    fn calibration_file_rejects_empty() {
        let file = NamedTempFile::new().expect("tmp");
        fs::write(file.path(), "\n").expect("write");
        let err = load_calibration_text(None, Some(file.path())).unwrap_err();
        assert!(matches!(err, CliError::EmptySecret("kalibrasyon metni")));
    }

    #[test]
    fn calibration_cli_strips_utf8_bom() {
        let text = load_calibration_text(Some("\u{feff}Context"), None).expect("calib");
        assert_eq!(text, "Context");
    }

    #[test]
    fn calibration_file_strips_utf8_bom() {
        let file = NamedTempFile::new().expect("tmp");
        fs::write(file.path(), "\u{feff}Context\r\n").expect("write");
        let text = load_calibration_text(None, Some(file.path())).expect("calib");
        assert_eq!(text, "Context");
    }

    #[test]
    fn ca_init_and_issue_commands_produce_artifacts() {
        let dir = tempdir().expect("tempdir");
        let profile_yaml = r"
profile_id: demo
org_salt: ZGVtb3NhbHQ=
root:
  common_name: Demo Root
  calibration_text: Demo Root Calibration
  validity_days: 365
intermediates:
  issuing:
    common_name: Demo Issuing
    calibration_text: Demo Issuing Calibration
    validity_days: 120
";
        let profile_path = dir.path().join("profile.yaml");
        fs::write(&profile_path, profile_yaml).expect("write profile");

        let root_cert = dir.path().join("root.pem");
        let root_key = dir.path().join("root.key");
        let init_summary = dir.path().join("init.json");
        let bundle_path = dir.path().join("bundle.json");

        let init_args = X509CaInitArgs {
            profile: profile_path.clone(),
            cert_out: root_cert.clone(),
            key_out: root_key.clone(),
            algorithm: KeyAlgorithmArg::Ed25519,
            summary_out: Some(init_summary.clone()),
            bundle_out: Some(bundle_path.clone()),
        };

        handle_x509_ca_init(&init_args).expect("ca init");
        assert!(root_cert.exists());
        assert!(root_key.exists());
        assert!(init_summary.exists());
        assert!(bundle_path.exists());

        let init_report: CaInitReport = read_json_file(&init_summary).expect("init report");
        assert_eq!(init_report.profile_id, "demo");
        assert_eq!(init_report.root_common_name, "Demo Root");
        assert!(init_report.serial_hex.len() >= 10);
        assert!(init_report.key_id.len() >= 10);
        assert_eq!(
            init_report.bundle_path,
            Some(bundle_path.display().to_string())
        );

        let issue_cert = dir.path().join("issuing.pem");
        let issue_key = dir.path().join("issuing.key");
        let issue_summary = dir.path().join("issue.json");

        let issue_args = X509CaIssueArgs {
            profile: profile_path,
            intermediate: "issuing".to_owned(),
            issuer_cert: root_cert,
            issuer_key: root_key,
            cert_out: issue_cert.clone(),
            key_out: issue_key.clone(),
            summary_out: Some(issue_summary.clone()),
            bundle_out: Some(bundle_path.clone()),
        };

        handle_x509_ca_issue(&issue_args).expect("ca issue");
        assert!(issue_cert.exists());
        assert!(issue_key.exists());
        assert!(issue_summary.exists());

        let issue_report: CaIssueReport = read_json_file(&issue_summary).expect("issue report");
        assert_eq!(issue_report.profile_id, "demo");
        assert_eq!(issue_report.intermediate, "issuing");
        assert!(issue_report.serial_hex.len() >= 10);
        assert!(issue_report.key_id.len() >= 10);
        assert_eq!(
            issue_report.bundle_path,
            Some(bundle_path.display().to_string())
        );

        let bundle: CaBundle = read_json_file(&bundle_path).expect("bundle");
        assert_eq!(bundle.profile_id, "demo");
        assert!(bundle.intermediates.contains_key("issuing"));
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
    fn decode_org_salt_rejects_short_values() {
        let err = decode_org_salt("YQ==").unwrap_err();
        if let CliError::InvalidLength {
            context,
            expected,
            actual,
        } = err
        {
            assert_eq!(context, "org-salt");
            assert_eq!(expected, MIN_ORG_SALT_LEN);
            assert_eq!(actual, 1);
        } else {
            panic!("beklenen InvalidLength hatası");
        }
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
    fn jwt_extra_claims_rejects_snake_case_keys() {
        let file = NamedTempFile::new().expect("tmp");
        fs::write(file.path(), "{\"custom_claim\":42}").expect("write");
        let mut claims = Claims::new();
        let err = merge_extra_claims(&mut claims, file.path()).unwrap_err();
        assert!(matches!(err, CliError::ClaimInvalidFormat(key) if key == "custom_claim"));
    }

    #[test]
    fn jwt_extra_claims_rejects_nested_invalid_keys() {
        let file = NamedTempFile::new().expect("tmp");
        let json = json!({
            "metadata": {
                "calibration_context": "demo"
            }
        });
        let json_bytes = serde_json::to_vec(&json).expect("json bytes");
        fs::write(file.path(), json_bytes).expect("write json");
        let mut claims = Claims::new();
        let err = merge_extra_claims(&mut claims, file.path()).unwrap_err();
        assert!(
            matches!(err, CliError::ClaimInvalidFormat(path) if path == "metadata.calibration_context")
        );
    }

    #[test]
    fn jwt_sign_verify_roundtrip() {
        let key = Ed25519KeyPair::generate("cli-flow").expect("key");
        let key_file = NamedTempFile::new().expect("key file");
        write_jwt_key_file(key_file.path(), &key).expect("write key");

        let token_file = NamedTempFile::new().expect("token file");
        let store_file = NamedTempFile::new().expect("store file");
        let sign_args = JwtSignArgs {
            key: Some(key_file.path().to_path_buf()),
            out: token_file.path().to_path_buf(),
            issuer: Some("aunsorm".to_string()),
            subject: Some("user-123".to_string()),
            audience: vec!["cli".to_string()],
            expires_in: Some(Duration::from_secs(60)),
            not_before_in: None,
            no_issued_at: false,
            jti: None,
            claims: None,
            kms_backend: None,
            kms_key_id: None,
            kms_fallback_backend: None,
            kms_fallback_key_id: None,
            kms_store: None,
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
            sqlite_store: Some(store_file.path().to_path_buf()),
        };
        handle_jwt_verify(&verify_args).expect("verify");

        let claims_json = fs::read_to_string(claims_out.path()).expect("read claims");
        let claims: Claims = serde_json::from_str(&claims_json).expect("claims json");
        assert_eq!(claims.issuer.as_deref(), Some("aunsorm"));
        assert!(claims.jwt_id.is_some());
    }
}
