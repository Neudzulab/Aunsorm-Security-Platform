#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use std::error::Error as _;
use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use aunsorm_core::{calib_from_text, salts::Salts, KdfPreset, KdfProfile};
use aunsorm_packet::{
    decrypt_one_shot, encrypt_one_shot, peek_header, AeadAlgorithm, DecryptParams, EncryptParams,
    KemPayload,
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
}

#[derive(Args)]
struct PeekArgs {
    /// Girdi Base64 paket dosyası
    #[arg(long, value_name = "PATH")]
    r#in: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    Mobile,
    Low,
    Medium,
    High,
    Ultra,
}

impl ProfileArg {
    const fn as_profile(self) -> KdfProfile {
        KdfProfile::preset(match self {
            Self::Mobile => KdfPreset::Mobile,
            Self::Low => KdfPreset::Low,
            Self::Medium => KdfPreset::Medium,
            Self::High => KdfPreset::High,
            Self::Ultra => KdfPreset::Ultra,
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

    println!(
        "deşifre başarılı: çıktı={} | calib_id={} | coord_id={} | aead={} | strict={} | msg_len={}B",
        args.out.display(),
        decrypted.header.calib_id,
        decrypted.coord_id,
        decrypted.header.aead.alg,
        strict,
        decrypted.plaintext.len(),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
