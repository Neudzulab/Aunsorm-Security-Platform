#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use std::fs;
use std::path::PathBuf;
use std::process;

use anyhow::{anyhow, Context, Result};
use aunsorm_core::{
    calib_from_text,
    kdf::{KdfPreset, KdfProfile},
    salts::Salts,
};
use aunsorm_packet::{
    decrypt_one_shot, encrypt_one_shot, peek_header, AeadAlgorithm, DecryptParams, EncryptParams,
    KemPayload,
};
use aunsorm_pqc::kem::{self, KemAlgorithm, KemPublicKey};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use clap::{Args, Parser, Subcommand, ValueEnum};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt(args) => handle_encrypt(args),
        Commands::Decrypt(args) => handle_decrypt(args),
        Commands::Peek(args) => handle_peek(&args),
    }
}

#[derive(Parser)]
#[command(
    name = "aunsorm-cli",
    version,
    about = "Aunsorm güvenlik aracının referans CLI katmanı"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Düz metni EXTERNAL kalibrasyon bağlamı ile şifreler ve JSON zarfı üretir.
    Encrypt(EncryptArgs),
    /// JSON zarfından paketi çözer.
    Decrypt(DecryptArgs),
    /// Paket başlığını çözmeden incele.
    Peek(PeekArgs),
}

#[derive(Args)]
struct EncryptArgs {
    /// Parola girdisi (Zeroizing ile korunur)
    #[arg(long)]
    password: String,
    /// Şifrelenecek girdi dosyası
    #[arg(long = "in", value_name = "FILE")]
    input: PathBuf,
    /// Üretilen JSON zarfı
    #[arg(long = "out", value_name = "FILE")]
    output: PathBuf,
    /// Base64 (STD veya URL) kodlu organizasyon tuzu
    #[arg(long = "org-salt", value_name = "B64")]
    org_salt: String,
    /// EXTERNAL kalibrasyon metni
    #[arg(long = "calib-text", value_name = "TEXT")]
    calib_text: String,
    /// Ek bağlamsal veri (AAD)
    #[arg(long, value_name = "STRING")]
    aad: Option<String>,
    /// KDF profili
    #[arg(long, value_enum, default_value_t = ProfileArg::Medium)]
    profile: ProfileArg,
    /// AEAD algoritması
    #[arg(long, value_enum, default_value_t = AeadArg::AesGcm)]
    aead: AeadArg,
    /// Strict kipini etkinleştir
    #[arg(long)]
    strict: bool,
    /// PQC KEM algoritması
    #[arg(long, value_enum, default_value_t = KemArg::None)]
    kem: KemArg,
    /// PQC açık anahtar dosyası (base64). `kem != none` olduğunda zorunlu.
    #[arg(long = "kem-public-key", value_name = "FILE")]
    kem_public_key: Option<PathBuf>,
}

#[derive(Args)]
struct DecryptArgs {
    /// Parola girdisi (Zeroizing ile korunur)
    #[arg(long)]
    password: String,
    /// JSON zarfı
    #[arg(long = "in", value_name = "FILE")]
    input: PathBuf,
    /// Çıkış düz metin dosyası
    #[arg(long = "out", value_name = "FILE")]
    output: PathBuf,
    /// Base64 (STD veya URL) kodlu organizasyon tuzu
    #[arg(long = "org-salt", value_name = "B64")]
    org_salt: String,
    /// EXTERNAL kalibrasyon metni
    #[arg(long = "calib-text", value_name = "TEXT")]
    calib_text: String,
    /// AAD override (varsayılan: zarftaki değer)
    #[arg(long, value_name = "STRING")]
    aad: Option<String>,
    /// Strict kipini zorla (zarf strict olsa dahi ek koruma sağlar)
    #[arg(long)]
    strict: bool,
}

#[derive(Args)]
struct PeekArgs {
    /// JSON zarfı
    #[arg(long = "in", value_name = "FILE")]
    input: PathBuf,
}

#[derive(Copy, Clone, Eq, PartialEq, ValueEnum)]
enum ProfileArg {
    Mobile,
    Low,
    Medium,
    High,
    Ultra,
}

impl ProfileArg {
    const fn to_profile(self) -> KdfProfile {
        match self {
            Self::Mobile => KdfProfile::preset(KdfPreset::Mobile),
            Self::Low => KdfProfile::preset(KdfPreset::Low),
            Self::Medium => KdfProfile::preset(KdfPreset::Medium),
            Self::High => KdfProfile::preset(KdfPreset::High),
            Self::Ultra => KdfProfile::preset(KdfPreset::Ultra),
        }
    }
}

impl Default for ProfileArg {
    fn default() -> Self {
        Self::Medium
    }
}

#[derive(Copy, Clone, Eq, PartialEq, ValueEnum)]
enum AeadArg {
    #[clap(alias = "aes-gcm")]
    AesGcm,
    #[clap(alias = "chacha20poly1305", alias = "chacha20-poly1305")]
    Chacha20Poly1305,
}

impl AeadArg {
    const fn to_algorithm(self) -> AeadAlgorithm {
        match self {
            Self::AesGcm => AeadAlgorithm::AesGcm,
            Self::Chacha20Poly1305 => AeadAlgorithm::Chacha20Poly1305,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::AesGcm => "aes-gcm",
            Self::Chacha20Poly1305 => "chacha20poly1305",
        }
    }
}

impl Default for AeadArg {
    fn default() -> Self {
        Self::AesGcm
    }
}

#[derive(Copy, Clone, Eq, PartialEq, ValueEnum)]
enum KemArg {
    None,
    #[clap(alias = "ml-kem-768")]
    MlKem768,
    #[clap(alias = "ml-kem-1024")]
    MlKem1024,
}

impl KemArg {
    const fn algorithm(self) -> Option<KemAlgorithm> {
        match self {
            Self::None => None,
            Self::MlKem768 => Some(KemAlgorithm::MlKem768),
            Self::MlKem1024 => Some(KemAlgorithm::MlKem1024),
        }
    }
}

struct KemHolder {
    algorithm: String,
    public_key: Vec<u8>,
    ciphertext: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
}

fn handle_encrypt(args: EncryptArgs) -> Result<()> {
    let password = Zeroizing::new(args.password);
    let plaintext = fs::read(&args.input)
        .with_context(|| format!("{} dosyası okunamadı", args.input.display()))?;
    let aad = args.aad.map(|aad| Zeroizing::new(aad.into_bytes()));
    let aad_ref = aad.as_deref().map_or(&[][..], Vec::as_slice);

    let org_salt = decode_any_base64("org-salt", &args.org_salt)?;
    let (calibration, calib_id) = calib_from_text(&org_salt, &args.calib_text);

    let mut password_salt = Zeroizing::new(vec![0_u8; 16]);
    OsRng.fill_bytes(password_salt.as_mut_slice());
    let salts = Salts::new(random_bytes(16), random_bytes(16), random_bytes(16))
        .map_err(|err| anyhow!(err))?;

    let profile = args.profile.to_profile();
    let algorithm = args.aead.to_algorithm();

    let mut kem_holder: Option<KemHolder> = None;
    let kem_payload = if let Some(algorithm_choice) = args.kem.algorithm() {
        let public_key_path = args
            .kem_public_key
            .as_ref()
            .context("PQC etkinken --kem-public-key zorunludur")?;
        let public_key_b64 = fs::read_to_string(public_key_path)
            .with_context(|| format!("{} dosyası okunamadı", public_key_path.display()))?;
        let public_key_raw = decode_any_base64("kem-public-key", &public_key_b64)?;
        let public_key = KemPublicKey::from_bytes(algorithm_choice, &public_key_raw)
            .map_err(|err| anyhow!(err))?;
        let encapsulation =
            kem::encapsulate(algorithm_choice, &public_key).map_err(|err| anyhow!(err))?;
        let holder = KemHolder {
            algorithm: algorithm_choice.name().to_owned(),
            public_key: public_key_raw,
            ciphertext: encapsulation.ciphertext().to_vec(),
            shared_secret: Zeroizing::new(encapsulation.shared_secret().to_vec()),
        };
        kem_holder = Some(holder);
        let holder_ref = kem_holder
            .as_ref()
            .expect("kem_holder must contain a value at this point");
        Some(KemPayload {
            kem: holder_ref.algorithm.as_str(),
            pk: Some(holder_ref.public_key.as_slice()),
            ctkem: Some(holder_ref.ciphertext.as_slice()),
            rbkem: None,
            ss: Some(holder_ref.shared_secret.as_slice()),
        })
    } else {
        None
    };

    let packet = encrypt_one_shot(EncryptParams {
        password: password.as_str(),
        password_salt: password_salt.as_slice(),
        calibration: &calibration,
        salts: &salts,
        plaintext: &plaintext,
        aad: aad_ref,
        profile,
        algorithm,
        strict: args.strict,
        kem: kem_payload,
    })
    .map_err(|err| anyhow!(err))?;

    let encoded_packet = packet.to_base64().map_err(|err| anyhow!(err))?;

    let envelope = PacketEnvelope {
        packet: encoded_packet,
        password_salt: encode_base64(password_salt.as_slice()),
        salts: EnvelopeSalts::from_salts(&salts),
        profile: EnvelopeProfile::from_profile(&profile),
        aead: args.aead.label().to_owned(),
        strict: args.strict,
        kem: EnvelopeKem::from_header(&packet.header.kem),
        calibration_id: calib_id,
        aad: aad.as_deref().map(|bytes| encode_base64(bytes)),
    };

    let json = serde_json::to_string_pretty(&envelope)?;
    fs::write(&args.output, json)
        .with_context(|| format!("{} dosyasına yazılamadı", args.output.display()))?;

    println!(
        "[encrypt] {} bayt girdi şifrelendi → {}",
        plaintext.len(),
        args.output.display()
    );
    println!("[encrypt] calibration id: {}", envelope.calibration_id);
    println!(
        "[encrypt] profile: t={} m_kib={} p={}",
        profile.t, profile.m_kib, profile.p
    );

    // Zeroize kritik veriler.
    drop(password_salt);
    drop(aad);
    drop(kem_holder);

    Ok(())
}

fn handle_decrypt(args: DecryptArgs) -> Result<()> {
    let password = Zeroizing::new(args.password);
    let data = fs::read(&args.input)
        .with_context(|| format!("{} dosyası okunamadı", args.input.display()))?;
    let envelope: PacketEnvelope =
        serde_json::from_slice(&data).context("JSON zarfı ayrıştırılamadı")?;

    let profile = envelope.profile.to_profile()?;
    let password_salt =
        Zeroizing::new(decode_any_base64("password_salt", &envelope.password_salt)?);
    let salts = envelope.salts.to_salts()?;

    let org_salt = decode_any_base64("org-salt", &args.org_salt)?;
    let (calibration, expected_calib_id) = calib_from_text(&org_salt, &args.calib_text);

    if expected_calib_id != envelope.calibration_id {
        return Err(anyhow!(
            "Zarf kalibrasyon kimliği uyuşmadı (zarf={}, beklenen={})",
            envelope.calibration_id,
            expected_calib_id
        ));
    }

    let aad = match args.aad {
        Some(value) => Some(Zeroizing::new(value.into_bytes())),
        None => envelope
            .aad
            .as_ref()
            .map(|encoded| decode_any_base64("aad", encoded))
            .transpose()?
            .map(Zeroizing::new),
    };
    let aad_ref = aad.as_deref().map_or(&[][..], Vec::as_slice);

    let strict = args.strict || envelope.strict;
    let packet = &envelope.packet;

    let decrypted = decrypt_one_shot(&DecryptParams {
        password: password.as_str(),
        password_salt: password_salt.as_slice(),
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: aad_ref,
        strict,
        packet,
    })
    .map_err(|err| anyhow!(err))?;

    fs::write(&args.output, &decrypted.plaintext)
        .with_context(|| format!("{} dosyasına yazılamadı", args.output.display()))?;

    println!(
        "[decrypt] {} bayt çıktı üretildi → {}",
        decrypted.plaintext.len(),
        args.output.display()
    );
    println!(
        "[decrypt] header calib_id doğrulandı: {}",
        decrypted.header.calib_id
    );

    drop(password_salt);
    drop(aad);

    Ok(())
}

fn handle_peek(args: &PeekArgs) -> Result<()> {
    let data = fs::read(&args.input)
        .with_context(|| format!("{} dosyası okunamadı", args.input.display()))?;
    let envelope: PacketEnvelope =
        serde_json::from_slice(&data).context("JSON zarfı ayrıştırılamadı")?;

    let header = peek_header(&envelope.packet).map_err(|err| anyhow!(err))?;
    println!("version: {}", header.version);
    println!("calib_id: {}", header.calib_id);
    println!("aead: {}", header.aead.alg);
    println!("kem: {}", header.kem.kem);
    if let Some(session) = header.session {
        println!(
            "session: id={} msg_no={} new={}",
            session.id, session.message_no, session.new
        );
    } else {
        println!("session: none");
    }
    println!(
        "sizes: plaintext={} ciphertext={}",
        header.sizes.plaintext, header.sizes.ciphertext
    );

    Ok(())
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0_u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn encode_base64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

fn decode_any_base64(label: &str, value: &str) -> Result<Vec<u8>> {
    let cleaned: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err(anyhow!("{label} değeri boş olamaz"));
    }
    let padded = pad_base64(&cleaned);
    STANDARD
        .decode(padded.as_bytes())
        .or_else(|_| URL_SAFE.decode(padded.as_bytes()))
        .or_else(|_| URL_SAFE_NO_PAD.decode(cleaned.as_bytes()))
        .map_err(|_| anyhow!("{label} base64 çözümlenemedi"))
}

fn pad_base64(input: &str) -> String {
    let mut owned = input.to_owned();
    while owned.len() % 4 != 0 {
        owned.push('=');
    }
    owned
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PacketEnvelope {
    packet: String,
    password_salt: String,
    salts: EnvelopeSalts,
    profile: EnvelopeProfile,
    aead: String,
    strict: bool,
    kem: EnvelopeKem,
    calibration_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    aad: Option<String>,
}

impl PacketEnvelope {
    #[cfg(test)]
    fn example() -> Self {
        Self {
            packet: "cGFja2V0".to_owned(),
            password_salt: "c2FsdA".to_owned(),
            salts: EnvelopeSalts {
                calibration: "Y2Fs".to_owned(),
                chain: "Y2hu".to_owned(),
                coord: "Y29v".to_owned(),
            },
            profile: EnvelopeProfile {
                t: 1,
                m_kib: 1024,
                p: 1,
            },
            aead: "aes-gcm".to_owned(),
            strict: true,
            kem: EnvelopeKem {
                algorithm: "none".to_owned(),
                pk: None,
                ctkem: None,
                rbkem: None,
            },
            calibration_id: "cid".to_owned(),
            aad: Some("YWFk".to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EnvelopeSalts {
    calibration: String,
    chain: String,
    coord: String,
}

impl EnvelopeSalts {
    fn from_salts(salts: &Salts) -> Self {
        Self {
            calibration: encode_base64(salts.calibration()),
            chain: encode_base64(salts.chain()),
            coord: encode_base64(salts.coord()),
        }
    }

    fn to_salts(&self) -> Result<Salts> {
        let calibration = decode_any_base64("salts.calibration", &self.calibration)?;
        let chain = decode_any_base64("salts.chain", &self.chain)?;
        let coord = decode_any_base64("salts.coord", &self.coord)?;
        Salts::new(calibration, chain, coord).map_err(|err| anyhow!(err))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct EnvelopeProfile {
    t: u32,
    m_kib: u32,
    p: u32,
}

impl EnvelopeProfile {
    const fn from_profile(profile: &KdfProfile) -> Self {
        Self {
            t: profile.t,
            m_kib: profile.m_kib,
            p: profile.p,
        }
    }

    fn to_profile(self) -> Result<KdfProfile> {
        KdfProfile::new(self.t, self.m_kib, self.p).map_err(|err| anyhow!(err))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EnvelopeKem {
    algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ctkem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rbkem: Option<String>,
}

impl EnvelopeKem {
    fn from_header(header: &aunsorm_packet::HeaderKem) -> Self {
        Self {
            algorithm: header.kem.clone(),
            pk: header.pk.clone(),
            ctkem: header.ctkem.clone(),
            rbkem: header.rbkem.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let env = PacketEnvelope::example();
        let json = serde_json::to_string_pretty(&env).expect("serialize");
        let parsed: PacketEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(env, parsed);
    }
}
