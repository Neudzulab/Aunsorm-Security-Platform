use zeroize::Zeroizing;

use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

use crate::error::{PqcError, Result};
use crate::strict::StrictMode;

#[cfg(feature = "sig-mldsa-65")]
const ML_DSA_65_PUBLIC_KEY_BYTES: usize = pqcrypto_dilithium::dilithium5::public_key_bytes();
#[cfg(not(feature = "sig-mldsa-65"))]
const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 2_592;

#[cfg(feature = "sig-mldsa-65")]
const ML_DSA_65_SECRET_KEY_BYTES: usize = pqcrypto_dilithium::dilithium5::secret_key_bytes();
#[cfg(not(feature = "sig-mldsa-65"))]
const ML_DSA_65_SECRET_KEY_BYTES: usize = 4_896;

#[cfg(feature = "sig-mldsa-65")]
const ML_DSA_65_SIGNATURE_BYTES: usize = pqcrypto_dilithium::dilithium5::signature_bytes();
#[cfg(not(feature = "sig-mldsa-65"))]
const ML_DSA_65_SIGNATURE_BYTES: usize = 4_595;

/// ML-DSA özel sertleştirme yardımcıları.
pub mod mldsa {
    use super::{
        ensure_ml_dsa_length, ensure_ml_dsa_not_uniform, ml_dsa_algorithm,
        ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    };
    use crate::error::Result;

    /// ML-DSA-65 açık anahtar uzunluğu (bayt).
    pub const PUBLIC_KEY_BYTES: usize = ML_DSA_65_PUBLIC_KEY_BYTES;
    /// ML-DSA-65 gizli anahtar uzunluğu (bayt).
    pub const SECRET_KEY_BYTES: usize = ML_DSA_65_SECRET_KEY_BYTES;
    /// ML-DSA-65 imza uzunluğu (bayt).
    pub const SIGNATURE_BYTES: usize = ML_DSA_65_SIGNATURE_BYTES;

    /// Açık anahtarın sertleştirme kontrollerini gerçekleştirir.
    ///
    /// # Errors
    /// Anahtar uzunluğu beklenen aralığın dışındaysa veya segmentler
    /// entropi denetiminden geçemezse `PqcError` döner.
    pub fn validate_public_key(bytes: &[u8]) -> Result<()> {
        ensure_ml_dsa_length(bytes, PUBLIC_KEY_BYTES, "public key")?;
        // İlk 32 bayt (rho) tamamıyla sıfır veya tekrar eden değer olmamalı.
        let (rho, rest) = bytes.split_at(32);
        ensure_ml_dsa_not_uniform(rho, "rho seed")?;
        ensure_ml_dsa_not_uniform(rest, "t1 vector")
    }

    /// Gizli anahtarın sertleştirme kontrollerini gerçekleştirir.
    ///
    /// # Errors
    /// Uzunluk veya segment entropisi kontrolleri başarısız olduğunda
    /// `PqcError` döner.
    pub fn validate_secret_key(bytes: &[u8]) -> Result<()> {
        ensure_ml_dsa_length(bytes, SECRET_KEY_BYTES, "secret key")?;
        let (rho, remainder) = bytes.split_at(32);
        let (key, remainder) = remainder.split_at(32);
        let (tr, packed) = remainder.split_at(48);
        ensure_ml_dsa_not_uniform(rho, "rho seed")?;
        ensure_ml_dsa_not_uniform(key, "K seed")?;
        ensure_ml_dsa_not_uniform(tr, "tr hash")?;
        ensure_ml_dsa_not_uniform(packed, "packed polynomial body")
    }

    /// Üretilen imzaların boyut ve entropi kontrollerini yapar.
    ///
    /// # Errors
    /// İmza boyutu hatalıysa veya tekdüze bir tampon tespit edilirse
    /// `PqcError` döner.
    pub fn validate_signature(bytes: &[u8]) -> Result<()> {
        ensure_ml_dsa_length(bytes, SIGNATURE_BYTES, "signature")?;
        ensure_ml_dsa_not_uniform(bytes, "signature byte pattern")
    }

    /// Açık ve gizli anahtarın birlikte kullanılabilirliğini doğrular.
    ///
    /// # Errors
    /// Anahtarlar uzunluk veya entropi kontrollerini geçemezse ya da rho
    /// segmentleri uyuşmazsa `PqcError` döner.
    pub fn validate_keypair(public_key: &[u8], secret_key: &[u8]) -> Result<()> {
        validate_public_key(public_key)?;
        validate_secret_key(secret_key)?;
        let (pk_rho, _) = public_key.split_at(32);
        let (sk_rho, _) = secret_key.split_at(32);
        if pk_rho != sk_rho {
            return Err(super::PqcError::invalid(
                ml_dsa_algorithm().name(),
                "rho seed mismatch between public and secret key",
            ));
        }
        Ok(())
    }
}

const fn ml_dsa_algorithm() -> SignatureAlgorithm {
    SignatureAlgorithm::MlDsa65
}

fn ensure_ml_dsa_length(bytes: &[u8], expected: usize, label: &str) -> Result<()> {
    if bytes.len() != expected {
        return Err(PqcError::invalid(
            ml_dsa_algorithm().name(),
            format!(
                "{label} must be exactly {expected} bytes (got {})",
                bytes.len()
            ),
        ));
    }
    Ok(())
}

fn ensure_ml_dsa_not_uniform(bytes: &[u8], label: &str) -> Result<()> {
    if bytes.is_empty() {
        return Err(PqcError::invalid(
            ml_dsa_algorithm().name(),
            format!("{label} slice is empty"),
        ));
    }
    if bytes.iter().all(|&byte| byte == bytes[0]) {
        return Err(PqcError::invalid(
            ml_dsa_algorithm().name(),
            format!(
                "{label} is uniform (0x{:02x}); refusing weak material",
                bytes[0]
            ),
        ));
    }
    Ok(())
}

/// Desteklenen PQC imza algoritmaları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ML-DSA 65 (Dilithium5).
    MlDsa65,
    /// Falcon-512.
    Falcon512,
    /// SPHINCS+-SHAKE-128f (simple).
    SphincsShake128f,
}

impl SignatureAlgorithm {
    /// Algoritma adını döndürür.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml-dsa-65",
            Self::Falcon512 => "falcon-512",
            Self::SphincsShake128f => "sphincs+-shake-128f",
        }
    }

    /// Algoritmanın bu derlemede mevcut olup olmadığını belirtir.
    #[must_use]
    pub const fn is_available(self) -> bool {
        match self {
            Self::MlDsa65 => cfg!(feature = "sig-mldsa-65"),
            Self::Falcon512 => cfg!(feature = "sig-falcon-512"),
            Self::SphincsShake128f => cfg!(feature = "sig-sphincs-shake-128f"),
        }
    }

    /// İstemci sertleştirme kontrol listesini döndürür.
    #[must_use]
    pub const fn checklist(self) -> SignatureChecklist {
        match self {
            Self::MlDsa65 => SignatureChecklist {
                algorithm: Self::MlDsa65,
                nist_category: "5",
                public_key_bytes: ML_DSA_65_PUBLIC_KEY_BYTES,
                secret_key_bytes: ML_DSA_65_SECRET_KEY_BYTES,
                signature_bytes: ML_DSA_65_SIGNATURE_BYTES,
                deterministic: true,
                client_actions: &[
                    "Build with the `sig-mldsa-65` feature enabled and document the flag in release notes.",
                    "Pin pqcrypto-dilithium to the audited version and require reproducible builds in CI.",
                    "Validate transparency log entries for Dilithium5 public keys before trusting remote peers.",
                    "Reject provisioning bundles whose rho/key/tr segments are uniform using `mldsa::validate_secret_key`.",
                    "Call `mldsa::validate_keypair` before enrolling ML-DSA credentials in HSM inventories.",
                ],
                runtime_assertions: &[
                    "Reject handshake transcripts that omit `ml-dsa-65` when `AUNSORM_STRICT=1`.",
                    "Abort if the peer advertises a key shorter than 2592 bytes for ML-DSA public keys.",
                    "Bind calibration identifiers to the Dilithium5 public key hash prior to accepting sessions.",
                    "Drop signatures that fail `mldsa::validate_signature` prior to verification attempts.",
                ],
                references: &[
                    "NIST FIPS 204 — Module-Lattice-based Digital Signature Standard (ML-DSA) §4",
                    "Aunsorm Threat Model — External calibration binding requirements",
                    "NIST ML-DSA Implementation Guidance — Seed domain separation checks",
                ],
            },
            Self::Falcon512 => SignatureChecklist {
                algorithm: Self::Falcon512,
                nist_category: "3",
                public_key_bytes: 897,
                secret_key_bytes: 1_281,
                signature_bytes: 690,
                deterministic: false,
                client_actions: &[
                    "Confirm the `sig-falcon-512` feature flag is enabled in production builds.",
                    "Ensure the floating-point implementation passes the vendor conformance vectors.",
                    "Document fallback to ML-DSA in strict environments where Falcon is unavailable.",
                ],
                runtime_assertions: &[
                    "Monitor for unusually small Falcon signatures (expected 690 bytes).",
                    "Fail closed if lattice trapdoor sampling errors are reported by the runtime.",
                    "Record Falcon public key fingerprints in the transparency log for auditability.",
                ],
                references: &[
                    "RFC 9180 §7.1 — Guidance on PQ signature algorithm agility",
                    "Falcon submission to NIST PQC Round 4 — Implementation considerations",
                ],
            },
            Self::SphincsShake128f => SignatureChecklist {
                algorithm: Self::SphincsShake128f,
                nist_category: "1",
                public_key_bytes: 32,
                secret_key_bytes: 64,
                signature_bytes: 17_088,
                deterministic: true,
                client_actions: &[
                    "Enable the `sig-sphincs-shake-128f` feature flag for deployments requiring stateless hash signatures.",
                    "Budget for 17KB signatures in transport limits and document MTU considerations.",
                    "Protect long-term seeds with hardware-backed key wrapping where available.",
                ],
                runtime_assertions: &[
                    "Reject peers advertising truncated SPHINCS+ signatures (<17088 bytes).",
                    "Log calibration identifiers together with SPHINCS+ tree heights for incident response.",
                    "Alert when strict mode is active but SPHINCS+ is negotiated, signalling a potential downgrade.",
                ],
                references: &[
                    "NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard",
                    "SPHINCS+ specification §5 — Parameter set SHAKE-128f-simple",
                ],
            },
        }
    }
}

/// İmza algoritması müzakeresi sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureSelection {
    /// Seçilen algoritma; `None` klasik imza fallback'ini temsil eder.
    pub algorithm: Option<SignatureAlgorithm>,
    /// Strict kip durumunu taşır.
    pub strict: StrictMode,
}

impl SignatureSelection {
    /// Fallback'e izin verilip verilmediğini döndürür.
    #[must_use]
    pub const fn allows_fallback(self) -> bool {
        !self.strict.is_strict()
    }

    /// PQC algoritması seçilip seçilmediğini belirtir.
    #[must_use]
    pub const fn is_pqc(self) -> bool {
        self.algorithm.is_some()
    }
}

/// İstenen PQC imza algoritmaları arasından seçim yapar.
///
/// # Errors
/// Strict kip etkin ve hiçbir aday algoritma desteklenmiyorsa `PqcError::StrictRequired` döner.
pub fn negotiate_signature(
    preferred: &[SignatureAlgorithm],
    strict: StrictMode,
) -> Result<SignatureSelection> {
    for &algorithm in preferred {
        if algorithm.is_available() {
            return Ok(SignatureSelection {
                algorithm: Some(algorithm),
                strict,
            });
        }
    }

    if strict.is_strict() {
        Err(PqcError::StrictRequired)
    } else {
        Ok(SignatureSelection {
            algorithm: None,
            strict,
        })
    }
}

/// PQC imza algoritmaları için sertleştirme kontrol listesi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureChecklist {
    algorithm: SignatureAlgorithm,
    nist_category: &'static str,
    public_key_bytes: usize,
    secret_key_bytes: usize,
    signature_bytes: usize,
    deterministic: bool,
    client_actions: &'static [&'static str],
    runtime_assertions: &'static [&'static str],
    references: &'static [&'static str],
}

impl SignatureChecklist {
    /// İlgili algoritmayı döndürür.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// NIST güvenlik kategorisini döndürür.
    #[must_use]
    pub const fn nist_category(&self) -> &'static str {
        self.nist_category
    }

    /// Açık anahtar boyutunu bayt cinsinden döndürür.
    #[must_use]
    pub const fn public_key_bytes(&self) -> usize {
        self.public_key_bytes
    }

    /// Gizli anahtar boyutunu bayt cinsinden döndürür.
    #[must_use]
    pub const fn secret_key_bytes(&self) -> usize {
        self.secret_key_bytes
    }

    /// İmza boyutunu bayt cinsinden döndürür.
    #[must_use]
    pub const fn signature_bytes(&self) -> usize {
        self.signature_bytes
    }

    /// Algoritmanın deterministik imza üretip üretmediğini belirtir.
    #[must_use]
    pub const fn deterministic(&self) -> bool {
        self.deterministic
    }

    /// İstemci tarafında uygulanması önerilen aksiyonları iteratör olarak döndürür.
    pub fn client_actions(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.client_actions.iter().copied()
    }

    /// Çalışma zamanında zorunlu kontrolleri iteratör olarak döndürür.
    pub fn runtime_assertions(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.runtime_assertions.iter().copied()
    }

    /// Referans dokümanları iteratör olarak döndürür.
    pub fn references(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.references.iter().copied()
    }
}

/// İmza anahtar çifti.
#[derive(Debug, Clone)]
pub struct SignatureKeyPair {
    public_key: SignaturePublicKey,
    secret_key: SignatureSecretKey,
}

impl SignatureKeyPair {
    /// Yeni anahtar çifti üretir.
    ///
    /// # Errors
    /// Desteklenmeyen bir algoritma veya kapalı bir özellik seçilirse `PqcError` döner.
    pub fn generate(algorithm: SignatureAlgorithm) -> Result<Self> {
        ensure_available(algorithm)?;
        match algorithm {
            SignatureAlgorithm::MlDsa65 => {
                #[cfg(feature = "sig-mldsa-65")]
                {
                    let (pk, sk) = pqcrypto_dilithium::dilithium5::keypair();
                    mldsa::validate_keypair(pk.as_bytes(), sk.as_bytes())?;
                    Ok(Self {
                        public_key: SignaturePublicKey::new(algorithm, pk.as_bytes().to_vec()),
                        secret_key: SignatureSecretKey::new(algorithm, sk.as_bytes().to_vec()),
                    })
                }
                #[cfg(not(feature = "sig-mldsa-65"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
            SignatureAlgorithm::Falcon512 => {
                #[cfg(feature = "sig-falcon-512")]
                {
                    let (pk, sk) = pqcrypto_falcon::falcon512::keypair();
                    Ok(Self {
                        public_key: SignaturePublicKey::new(algorithm, pk.as_bytes().to_vec()),
                        secret_key: SignatureSecretKey::new(algorithm, sk.as_bytes().to_vec()),
                    })
                }
                #[cfg(not(feature = "sig-falcon-512"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
            SignatureAlgorithm::SphincsShake128f => {
                #[cfg(feature = "sig-sphincs-shake-128f")]
                {
                    let (pk, sk) = pqcrypto_sphincsplus::sphincsshake128fsimple::keypair();
                    Ok(Self {
                        public_key: SignaturePublicKey::new(algorithm, pk.as_bytes().to_vec()),
                        secret_key: SignatureSecretKey::new(algorithm, sk.as_bytes().to_vec()),
                    })
                }
                #[cfg(not(feature = "sig-sphincs-shake-128f"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
        }
    }

    /// Açık anahtarı döndürür.
    #[must_use]
    pub const fn public_key(&self) -> &SignaturePublicKey {
        &self.public_key
    }

    /// Gizli anahtarı döndürür.
    #[must_use]
    pub const fn secret_key(&self) -> &SignatureSecretKey {
        &self.secret_key
    }
}

/// İmza açık anahtarı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignaturePublicKey {
    algorithm: SignatureAlgorithm,
    bytes: Vec<u8>,
}

impl SignaturePublicKey {
    #[allow(clippy::missing_const_for_fn)]
    fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Byte dizisinden açık anahtar oluşturur.
    ///
    /// # Errors
    /// Anahtar kodu beklenen biçimde değilse `PqcError` döner.
    pub fn from_bytes(algorithm: SignatureAlgorithm, bytes: &[u8]) -> Result<Self> {
        ensure_available(algorithm)?;
        match algorithm {
            SignatureAlgorithm::MlDsa65 => {
                #[cfg(feature = "sig-mldsa-65")]
                {
                    mldsa::validate_public_key(bytes)?;
                    pqcrypto_dilithium::dilithium5::PublicKey::from_bytes(bytes).map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-DSA public key")
                    })?;
                    Ok(Self::new(algorithm, bytes.to_vec()))
                }
                #[cfg(not(feature = "sig-mldsa-65"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
            SignatureAlgorithm::Falcon512 => {
                #[cfg(feature = "sig-falcon-512")]
                {
                    pqcrypto_falcon::falcon512::PublicKey::from_bytes(bytes).map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid Falcon public key")
                    })?;
                    Ok(Self::new(algorithm, bytes.to_vec()))
                }
                #[cfg(not(feature = "sig-falcon-512"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
            SignatureAlgorithm::SphincsShake128f => {
                #[cfg(feature = "sig-sphincs-shake-128f")]
                {
                    pqcrypto_sphincsplus::sphincsshake128fsimple::PublicKey::from_bytes(bytes)
                        .map_err(|_| {
                            PqcError::invalid(algorithm.name(), "invalid SPHINCS+ public key")
                        })?;
                    Ok(Self::new(algorithm, bytes.to_vec()))
                }
                #[cfg(not(feature = "sig-sphincs-shake-128f"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
        }
    }

    /// Anahtar byte dilimini döndürür.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Algoritmayı döndürür.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// İmza gizli anahtarı.
#[derive(Debug, Clone)]
pub struct SignatureSecretKey {
    algorithm: SignatureAlgorithm,
    bytes: Zeroizing<Vec<u8>>,
}

impl SignatureSecretKey {
    #[allow(clippy::missing_const_for_fn)]
    fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        Self {
            algorithm,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Byte dizisinden gizli anahtar oluşturur.
    ///
    /// # Errors
    /// Anahtar kodu geçersizse `PqcError` döner.
    pub fn from_bytes(algorithm: SignatureAlgorithm, bytes: &[u8]) -> Result<Self> {
        ensure_available(algorithm)?;
        match algorithm {
            SignatureAlgorithm::MlDsa65 => {
                #[cfg(feature = "sig-mldsa-65")]
                {
                    mldsa::validate_secret_key(bytes)?;
                    pqcrypto_dilithium::dilithium5::SecretKey::from_bytes(bytes).map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-DSA secret key")
                    })?;
                    Ok(Self::new(algorithm, bytes.to_vec()))
                }
                #[cfg(not(feature = "sig-mldsa-65"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
            SignatureAlgorithm::Falcon512 => {
                #[cfg(feature = "sig-falcon-512")]
                {
                    pqcrypto_falcon::falcon512::SecretKey::from_bytes(bytes).map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid Falcon secret key")
                    })?;
                    Ok(Self::new(algorithm, bytes.to_vec()))
                }
                #[cfg(not(feature = "sig-falcon-512"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
            SignatureAlgorithm::SphincsShake128f => {
                #[cfg(feature = "sig-sphincs-shake-128f")]
                {
                    pqcrypto_sphincsplus::sphincsshake128fsimple::SecretKey::from_bytes(bytes)
                        .map_err(|_| {
                            PqcError::invalid(algorithm.name(), "invalid SPHINCS+ secret key")
                        })?;
                    Ok(Self::new(algorithm, bytes.to_vec()))
                }
                #[cfg(not(feature = "sig-sphincs-shake-128f"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
        }
    }

    /// Anahtar byte dilimini döndürür.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Algoritmayı döndürür.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// Mesaj imzalar.
///
/// # Errors
/// Gizli anahtar geçersizse veya algoritma desteklenmiyorsa `PqcError` döner.
pub fn sign(
    algorithm: SignatureAlgorithm,
    secret_key: &SignatureSecretKey,
    message: &[u8],
) -> Result<Vec<u8>> {
    ensure_available(algorithm)?;
    match algorithm {
        SignatureAlgorithm::MlDsa65 => {
            #[cfg(feature = "sig-mldsa-65")]
            {
                let sk =
                    pqcrypto_dilithium::dilithium5::SecretKey::from_bytes(secret_key.as_bytes())
                        .map_err(|_| {
                            PqcError::invalid(algorithm.name(), "invalid ML-DSA secret key")
                        })?;
                let signature = pqcrypto_dilithium::dilithium5::detached_sign(message, &sk);
                let signature = signature.as_bytes().to_vec();
                mldsa::validate_signature(&signature)?;
                Ok(signature)
            }
            #[cfg(not(feature = "sig-mldsa-65"))]
            {
                unreachable!("feature gate should have prevented this branch")
            }
        }
        SignatureAlgorithm::Falcon512 => {
            #[cfg(feature = "sig-falcon-512")]
            {
                let sk = pqcrypto_falcon::falcon512::SecretKey::from_bytes(secret_key.as_bytes())
                    .map_err(|_| {
                    PqcError::invalid(algorithm.name(), "invalid Falcon secret key")
                })?;
                let signature = pqcrypto_falcon::falcon512::detached_sign(message, &sk);
                Ok(signature.as_bytes().to_vec())
            }
            #[cfg(not(feature = "sig-falcon-512"))]
            {
                unreachable!("feature gate should have prevented this branch")
            }
        }
        SignatureAlgorithm::SphincsShake128f => {
            #[cfg(feature = "sig-sphincs-shake-128f")]
            {
                let sk = pqcrypto_sphincsplus::sphincsshake128fsimple::SecretKey::from_bytes(
                    secret_key.as_bytes(),
                )
                .map_err(|_| PqcError::invalid(algorithm.name(), "invalid SPHINCS+ secret key"))?;
                let signature =
                    pqcrypto_sphincsplus::sphincsshake128fsimple::detached_sign(message, &sk);
                Ok(signature.as_bytes().to_vec())
            }
            #[cfg(not(feature = "sig-sphincs-shake-128f"))]
            {
                unreachable!("feature gate should have prevented this branch")
            }
        }
    }
}

/// İmza doğrular.
///
/// # Errors
/// Açık anahtar veya imza geçersiz olduğunda `PqcError` döner.
pub fn verify(
    algorithm: SignatureAlgorithm,
    public_key: &SignaturePublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    ensure_available(algorithm)?;
    match algorithm {
        SignatureAlgorithm::MlDsa65 => {
            #[cfg(feature = "sig-mldsa-65")]
            {
                mldsa::validate_signature(signature)?;
                let pk =
                    pqcrypto_dilithium::dilithium5::PublicKey::from_bytes(public_key.as_bytes())
                        .map_err(|_| {
                            PqcError::invalid(algorithm.name(), "invalid ML-DSA public key")
                        })?;
                let sig = pqcrypto_dilithium::dilithium5::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::invalid(algorithm.name(), "invalid ML-DSA signature"))?;
                pqcrypto_dilithium::dilithium5::verify_detached_signature(&sig, message, &pk)
                    .map_err(|_| PqcError::crypto(algorithm.name(), "verification failed"))
            }
            #[cfg(not(feature = "sig-mldsa-65"))]
            {
                unreachable!("feature gate should have prevented this branch")
            }
        }
        SignatureAlgorithm::Falcon512 => {
            #[cfg(feature = "sig-falcon-512")]
            {
                let pk = pqcrypto_falcon::falcon512::PublicKey::from_bytes(public_key.as_bytes())
                    .map_err(|_| {
                    PqcError::invalid(algorithm.name(), "invalid Falcon public key")
                })?;
                let sig = pqcrypto_falcon::falcon512::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::invalid(algorithm.name(), "invalid Falcon signature"))?;
                pqcrypto_falcon::falcon512::verify_detached_signature(&sig, message, &pk)
                    .map_err(|_| PqcError::crypto(algorithm.name(), "verification failed"))
            }
            #[cfg(not(feature = "sig-falcon-512"))]
            {
                unreachable!("feature gate should have prevented this branch")
            }
        }
        SignatureAlgorithm::SphincsShake128f => {
            #[cfg(feature = "sig-sphincs-shake-128f")]
            {
                let pk = pqcrypto_sphincsplus::sphincsshake128fsimple::PublicKey::from_bytes(
                    public_key.as_bytes(),
                )
                .map_err(|_| PqcError::invalid(algorithm.name(), "invalid SPHINCS+ public key"))?;
                let sig =
                    pqcrypto_sphincsplus::sphincsshake128fsimple::DetachedSignature::from_bytes(
                        signature,
                    )
                    .map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid SPHINCS+ signature")
                    })?;
                pqcrypto_sphincsplus::sphincsshake128fsimple::verify_detached_signature(
                    &sig, message, &pk,
                )
                .map_err(|_| PqcError::crypto(algorithm.name(), "verification failed"))
            }
            #[cfg(not(feature = "sig-sphincs-shake-128f"))]
            {
                unreachable!("feature gate should have prevented this branch")
            }
        }
    }
}

fn ensure_available(algorithm: SignatureAlgorithm) -> Result<()> {
    if algorithm.is_available() {
        Ok(())
    } else {
        Err(PqcError::unavailable(algorithm.name()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"Aunsorm PQC test vector";

    #[test]
    fn negotiation_selects_first_available_algorithm() {
        let selection =
            negotiate_signature(&[SignatureAlgorithm::MlDsa65], StrictMode::Relaxed).unwrap();
        assert!(selection.is_pqc());
        assert_eq!(selection.algorithm, Some(SignatureAlgorithm::MlDsa65));
        assert!(selection.allows_fallback());
    }

    #[test]
    fn negotiation_allows_fallback_when_relaxed() {
        let selection =
            negotiate_signature(&[SignatureAlgorithm::Falcon512], StrictMode::Relaxed).unwrap();
        if SignatureAlgorithm::Falcon512.is_available() {
            assert_eq!(selection.algorithm, Some(SignatureAlgorithm::Falcon512));
            assert!(selection.is_pqc());
        } else {
            assert_eq!(selection.algorithm, None);
            assert!(!selection.is_pqc());
        }
    }

    #[test]
    fn negotiation_errors_when_strict_without_pqc() {
        let result = negotiate_signature(&[SignatureAlgorithm::Falcon512], StrictMode::Strict);
        if SignatureAlgorithm::Falcon512.is_available() {
            let selection = result.expect("falcon must negotiate when available");
            assert_eq!(selection.algorithm, Some(SignatureAlgorithm::Falcon512));
        } else {
            let err = result.expect_err("strict negotiation should fail without PQ signatures");
            assert!(matches!(err, PqcError::StrictRequired));
        }
    }

    #[test]
    fn sign_verify_ml_dsa() {
        if !SignatureAlgorithm::MlDsa65.is_available() {
            return;
        }
        let pair = SignatureKeyPair::generate(SignatureAlgorithm::MlDsa65).unwrap();
        let signature = sign(SignatureAlgorithm::MlDsa65, pair.secret_key(), MESSAGE).unwrap();
        verify(
            SignatureAlgorithm::MlDsa65,
            pair.public_key(),
            MESSAGE,
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn sign_verify_falcon() {
        if !SignatureAlgorithm::Falcon512.is_available() {
            return;
        }
        let pair = SignatureKeyPair::generate(SignatureAlgorithm::Falcon512).unwrap();
        let signature = sign(SignatureAlgorithm::Falcon512, pair.secret_key(), MESSAGE).unwrap();
        verify(
            SignatureAlgorithm::Falcon512,
            pair.public_key(),
            MESSAGE,
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn sign_verify_sphincs() {
        if !SignatureAlgorithm::SphincsShake128f.is_available() {
            return;
        }
        let pair = SignatureKeyPair::generate(SignatureAlgorithm::SphincsShake128f).unwrap();
        let signature = sign(
            SignatureAlgorithm::SphincsShake128f,
            pair.secret_key(),
            MESSAGE,
        )
        .unwrap();
        verify(
            SignatureAlgorithm::SphincsShake128f,
            pair.public_key(),
            MESSAGE,
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn verification_fails_on_tampering() {
        if !SignatureAlgorithm::MlDsa65.is_available() {
            return;
        }
        let pair = SignatureKeyPair::generate(SignatureAlgorithm::MlDsa65).unwrap();
        let mut signature = sign(SignatureAlgorithm::MlDsa65, pair.secret_key(), MESSAGE).unwrap();
        if let Some(byte) = signature.first_mut() {
            *byte ^= 0xAA;
        }
        let err = verify(
            SignatureAlgorithm::MlDsa65,
            pair.public_key(),
            MESSAGE,
            &signature,
        )
        .expect_err("verification must fail for tampered signature");
        assert!(matches!(
            err,
            PqcError::CryptoFailure { .. } | PqcError::InvalidInput { .. }
        ));
    }

    #[test]
    fn checklist_metadata_for_ml_dsa_matches_expectations() {
        let checklist = SignatureAlgorithm::MlDsa65.checklist();
        assert_eq!(checklist.algorithm(), SignatureAlgorithm::MlDsa65);
        assert_eq!(checklist.nist_category(), "5");
        assert_eq!(checklist.public_key_bytes(), super::mldsa::PUBLIC_KEY_BYTES);
        assert_eq!(checklist.secret_key_bytes(), super::mldsa::SECRET_KEY_BYTES);
        assert_eq!(checklist.signature_bytes(), super::mldsa::SIGNATURE_BYTES);
        assert!(checklist.deterministic());
        let actions: Vec<_> = checklist.client_actions().collect();
        assert!(actions.len() >= 5);
        assert!(actions[0].contains("sig-mldsa-65"));
        assert!(actions.iter().any(|item| item.contains("validate_keypair")));
        let runtime: Vec<_> = checklist.runtime_assertions().collect();
        assert!(runtime.iter().any(|item| item.contains("AUNSORM_STRICT")));
        assert!(runtime
            .iter()
            .any(|item| item.contains("validate_signature")));
        let references: Vec<_> = checklist.references().collect();
        assert!(references.iter().any(|item| item.contains("ML-DSA")));
        assert!(references
            .iter()
            .any(|item| item.contains("Implementation Guidance")));
    }

    #[test]
    fn checklist_distinguishes_falcon_and_sphincs() {
        let falcon = SignatureAlgorithm::Falcon512.checklist();
        assert_eq!(falcon.nist_category(), "3");
        assert!(!falcon.deterministic());
        assert_eq!(falcon.signature_bytes(), 690);
        assert!(falcon
            .runtime_assertions()
            .any(|item| item.contains("Falcon")));

        let sphincs = SignatureAlgorithm::SphincsShake128f.checklist();
        assert_eq!(sphincs.nist_category(), "1");
        assert!(sphincs.deterministic());
        assert!(sphincs.signature_bytes() >= 17_000);
        assert!(sphincs
            .client_actions()
            .any(|item| item.contains("17KB signatures")));
    }

    #[test]
    fn mldsa_keypair_validation_accepts_generated_material() {
        if !SignatureAlgorithm::MlDsa65.is_available() {
            return;
        }
        let pair = SignatureKeyPair::generate(SignatureAlgorithm::MlDsa65).unwrap();
        super::mldsa::validate_keypair(pair.public_key().as_bytes(), pair.secret_key().as_bytes())
            .unwrap();
    }

    #[test]
    fn mldsa_keypair_validation_rejects_rho_mismatch() {
        if !SignatureAlgorithm::MlDsa65.is_available() {
            return;
        }
        let pair = SignatureKeyPair::generate(SignatureAlgorithm::MlDsa65).unwrap();
        let mut corrupted_pk = pair.public_key().as_bytes().to_vec();
        corrupted_pk[0] ^= 0xFF;
        let err = super::mldsa::validate_keypair(&corrupted_pk, pair.secret_key().as_bytes())
            .expect_err("rho mismatch must be rejected");
        assert!(matches!(err, super::PqcError::InvalidInput { .. }));
    }

    #[test]
    fn mldsa_secret_key_validator_rejects_uniform_segments() {
        let mut bad_secret = vec![0u8; super::mldsa::SECRET_KEY_BYTES];
        assert!(super::mldsa::validate_secret_key(&bad_secret).is_err());
        bad_secret[0] = 0xAA;
        bad_secret[1..33].fill(0xAA);
        assert!(super::mldsa::validate_secret_key(&bad_secret).is_err());
    }

    #[test]
    fn mldsa_signature_validator_flags_uniform_buffers() {
        let signature = vec![0x42; super::mldsa::SIGNATURE_BYTES];
        assert!(super::mldsa::validate_signature(&signature).is_err());
    }
}
