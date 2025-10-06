use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use zeroize::Zeroizing;

use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

use crate::error::{PqcError, Result};
use crate::strict::StrictMode;

/// Desteklenen KEM algoritmaları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    /// KEM kullanılmıyor; klasik fallback.
    None,
    /// ML-KEM-768 (Kyber768).
    MlKem768,
    /// ML-KEM-1024 (Kyber1024).
    MlKem1024,
}

impl KemAlgorithm {
    /// Algoritmanın kısa adını döndürür.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MlKem768 => "ml-kem-768",
            Self::MlKem1024 => "ml-kem-1024",
        }
    }

    /// Algoritmanın bu derlemede mevcut olup olmadığını belirtir.
    #[must_use]
    pub const fn is_available(self) -> bool {
        match self {
            Self::None => true,
            Self::MlKem768 => cfg!(feature = "kem-mlkem-768"),
            Self::MlKem1024 => cfg!(feature = "kem-mlkem-1024"),
        }
    }
}

/// Negotiation çıktısı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KemSelection {
    pub algorithm: KemAlgorithm,
    pub strict: StrictMode,
}

impl KemSelection {
    /// Fallback'e izin verilip verilmediğini döndürür.
    #[must_use]
    pub const fn allows_fallback(self) -> bool {
        !self.strict.is_strict()
    }
}

/// PQC anahtar çifti.
#[derive(Debug, Clone)]
pub struct KemKeyPair {
    algorithm: KemAlgorithm,
    public_key: KemPublicKey,
    secret_key: KemSecretKey,
}

impl KemKeyPair {
    /// Anahtar çiftini üretir.
    ///
    /// # Errors
    /// Desteklenmeyen bir algoritma seçilirse veya özellik kapalıysa `PqcError` döner.
    pub fn generate(algorithm: KemAlgorithm) -> Result<Self> {
        ensure_available(algorithm)?;
        match algorithm {
            KemAlgorithm::None => Err(PqcError::invalid(
                algorithm.name(),
                "kem::generate called with KemAlgorithm::None",
            )),
            KemAlgorithm::MlKem768 => {
                #[cfg(feature = "kem-mlkem-768")]
                {
                    let (pk, sk) = pqcrypto_kyber::kyber768::keypair();
                    Ok(Self {
                        algorithm,
                        public_key: KemPublicKey::new(algorithm, pk.as_bytes().to_vec()),
                        secret_key: KemSecretKey::new(algorithm, sk.as_bytes().to_vec()),
                    })
                }
                #[cfg(not(feature = "kem-mlkem-768"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
            KemAlgorithm::MlKem1024 => {
                #[cfg(feature = "kem-mlkem-1024")]
                {
                    let (pk, sk) = pqcrypto_kyber::kyber1024::keypair();
                    Ok(Self {
                        algorithm,
                        public_key: KemPublicKey::new(algorithm, pk.as_bytes().to_vec()),
                        secret_key: KemSecretKey::new(algorithm, sk.as_bytes().to_vec()),
                    })
                }
                #[cfg(not(feature = "kem-mlkem-1024"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
        }
    }

    /// Açık anahtarı döndürür.
    #[must_use]
    pub const fn public_key(&self) -> &KemPublicKey {
        &self.public_key
    }

    /// Gizli anahtarı döndürür.
    #[must_use]
    pub const fn secret_key(&self) -> &KemSecretKey {
        &self.secret_key
    }

    /// Algoritmayı döndürür.
    #[must_use]
    pub const fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// KEM açık anahtarı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemPublicKey {
    algorithm: KemAlgorithm,
    bytes: Vec<u8>,
}

impl KemPublicKey {
    #[allow(clippy::missing_const_for_fn)]
    fn new(algorithm: KemAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Byte dizisinden açık anahtar oluşturur.
    ///
    /// # Errors
    /// Girdi anahtarı geçersizse veya algoritma bu derlemede mevcut değilse `PqcError` döner.
    pub fn from_bytes(algorithm: KemAlgorithm, bytes: &[u8]) -> Result<Self> {
        ensure_available(algorithm)?;
        match algorithm {
            KemAlgorithm::None => Err(PqcError::invalid(
                algorithm.name(),
                "KemAlgorithm::None cannot build a public key",
            )),
            KemAlgorithm::MlKem768 => {
                #[cfg(feature = "kem-mlkem-768")]
                {
                    pqcrypto_kyber::kyber768::PublicKey::from_bytes(bytes).map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-KEM-768 public key")
                    })?;
                    Ok(Self::new(algorithm, bytes.to_vec()))
                }
                #[cfg(not(feature = "kem-mlkem-768"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
            KemAlgorithm::MlKem1024 => {
                #[cfg(feature = "kem-mlkem-1024")]
                {
                    pqcrypto_kyber::kyber1024::PublicKey::from_bytes(bytes).map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-KEM-1024 public key")
                    })?;
                    Ok(Self::new(algorithm, bytes.to_vec()))
                }
                #[cfg(not(feature = "kem-mlkem-1024"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
        }
    }

    /// Anahtar baytlarını döndürür.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Algoritmayı döndürür.
    #[must_use]
    pub const fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// KEM gizli anahtarı.
#[derive(Debug, Clone)]
pub struct KemSecretKey {
    algorithm: KemAlgorithm,
    bytes: Zeroizing<Vec<u8>>,
}

impl KemSecretKey {
    #[allow(clippy::missing_const_for_fn)]
    fn new(algorithm: KemAlgorithm, bytes: Vec<u8>) -> Self {
        Self {
            algorithm,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Byte dizisinden gizli anahtar oluşturur.
    ///
    /// # Errors
    /// Anahtar kodu geçersizse veya algoritma desteklenmiyorsa `PqcError` döner.
    pub fn from_bytes(algorithm: KemAlgorithm, bytes: &[u8]) -> Result<Self> {
        ensure_available(algorithm)?;
        match algorithm {
            KemAlgorithm::None => Err(PqcError::invalid(
                algorithm.name(),
                "KemAlgorithm::None cannot build a secret key",
            )),
            KemAlgorithm::MlKem768 => {
                #[cfg(feature = "kem-mlkem-768")]
                {
                    pqcrypto_kyber::kyber768::SecretKey::from_bytes(bytes).map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-KEM-768 secret key")
                    })?;
                    Ok(Self::new(algorithm, bytes.to_vec()))
                }
                #[cfg(not(feature = "kem-mlkem-768"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
            KemAlgorithm::MlKem1024 => {
                #[cfg(feature = "kem-mlkem-1024")]
                {
                    pqcrypto_kyber::kyber1024::SecretKey::from_bytes(bytes).map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-KEM-1024 secret key")
                    })?;
                    Ok(Self::new(algorithm, bytes.to_vec()))
                }
                #[cfg(not(feature = "kem-mlkem-1024"))]
                {
                    unreachable!("feature gate should have prevented this branch")
                }
            }
        }
    }

    /// Bayt dilimini döndürür.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Algoritmayı döndürür.
    #[must_use]
    pub const fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// Kapsülleme çıktısı.
#[derive(Debug, Clone)]
pub struct KemEncapsulation {
    algorithm: KemAlgorithm,
    ciphertext: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
}

impl KemEncapsulation {
    fn new(algorithm: KemAlgorithm, ciphertext: Vec<u8>, shared_secret: Vec<u8>) -> Self {
        Self {
            algorithm,
            ciphertext,
            shared_secret: Zeroizing::new(shared_secret),
        }
    }

    /// Paket için kullanılabilir alanları döndürür.
    #[must_use]
    pub fn packet_payload<'a>(&'a self, public_key: &'a KemPublicKey) -> PacketKemPayload<'a> {
        PacketKemPayload {
            kem: self.algorithm.name(),
            public_key: Some(public_key.as_bytes()),
            ciphertext: Some(self.ciphertext.as_slice()),
            responder_key: None,
            shared_secret: Some(self.shared_secret.as_slice()),
        }
    }

    /// Şifreli kapsülü döndürür.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Paylaşılan sırrı döndürür.
    #[must_use]
    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }

    /// Algoritmayı döndürür.
    #[must_use]
    pub const fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

/// Paket başlığına dönüştürülebilir KEM alanları.
#[derive(Debug, Clone, Copy)]
pub struct PacketKemPayload<'a> {
    pub kem: &'a str,
    pub public_key: Option<&'a [u8]>,
    pub ciphertext: Option<&'a [u8]>,
    pub responder_key: Option<&'a [u8]>,
    pub shared_secret: Option<&'a [u8]>,
}

impl PacketKemPayload<'_> {
    /// Base64 dizgilerine dönüştürür.
    #[must_use]
    pub fn to_base64(self) -> PacketKemFields {
        PacketKemFields {
            kem: self.kem.to_owned(),
            pk: self.public_key.map(encode_b64),
            ctkem: self.ciphertext.map(encode_b64),
            rbkem: self.responder_key.map(encode_b64),
            ss: self.shared_secret.map(encode_b64),
        }
    }
}

/// JSON başlığı için base64 alanları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketKemFields {
    pub kem: String,
    pub pk: Option<String>,
    pub ctkem: Option<String>,
    pub rbkem: Option<String>,
    pub ss: Option<String>,
}

impl PacketKemFields {
    /// Başlığı string gösterimine çevirir.
    #[must_use]
    pub fn kem_name(&self) -> &str {
        &self.kem
    }
}

fn encode_b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

fn ensure_available(algorithm: KemAlgorithm) -> Result<()> {
    if algorithm.is_available() {
        Ok(())
    } else {
        Err(PqcError::unavailable(algorithm.name()))
    }
}

/// İstenen algoritmalar arasında seçim yapar.
///
/// # Errors
/// Strict kip etkin ve hiçbir aday algoritma desteklenmiyorsa `PqcError::StrictRequired` döner.
pub fn negotiate_kem(preferred: &[KemAlgorithm], strict: StrictMode) -> Result<KemSelection> {
    for &algorithm in preferred {
        if algorithm.is_available() {
            return Ok(KemSelection { algorithm, strict });
        }
    }

    if strict.is_strict() {
        Err(PqcError::StrictRequired)
    } else {
        Ok(KemSelection {
            algorithm: KemAlgorithm::None,
            strict,
        })
    }
}

/// Açık anahtarla kapsülleme yapar.
///
/// # Errors
/// Algoritma desteklenmiyorsa veya açık anahtar geçersiz ise `PqcError` döner.
pub fn encapsulate(algorithm: KemAlgorithm, public_key: &KemPublicKey) -> Result<KemEncapsulation> {
    ensure_available(algorithm)?;
    match algorithm {
        KemAlgorithm::None => Err(PqcError::invalid(
            algorithm.name(),
            "KemAlgorithm::None cannot encapsulate",
        )),
        KemAlgorithm::MlKem768 => {
            #[cfg(feature = "kem-mlkem-768")]
            {
                let pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(public_key.as_bytes())
                    .map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-KEM-768 public key")
                    })?;
                let (shared, ciphertext) = pqcrypto_kyber::kyber768::encapsulate(&pk);
                Ok(KemEncapsulation::new(
                    algorithm,
                    ciphertext.as_bytes().to_vec(),
                    shared.as_bytes().to_vec(),
                ))
            }
            #[cfg(not(feature = "kem-mlkem-768"))]
            {
                unreachable!("feature gate should have prevented this branch")
            }
        }
        KemAlgorithm::MlKem1024 => {
            #[cfg(feature = "kem-mlkem-1024")]
            {
                let pk = pqcrypto_kyber::kyber1024::PublicKey::from_bytes(public_key.as_bytes())
                    .map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-KEM-1024 public key")
                    })?;
                let (shared, ciphertext) = pqcrypto_kyber::kyber1024::encapsulate(&pk);
                Ok(KemEncapsulation::new(
                    algorithm,
                    ciphertext.as_bytes().to_vec(),
                    shared.as_bytes().to_vec(),
                ))
            }
            #[cfg(not(feature = "kem-mlkem-1024"))]
            {
                unreachable!("feature gate should have prevented this branch")
            }
        }
    }
}

/// Kapsülü çözer.
///
/// # Errors
/// Algoritma desteklenmiyorsa veya girişler geçersizse `PqcError` döner.
pub fn decapsulate(
    algorithm: KemAlgorithm,
    secret_key: &KemSecretKey,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    ensure_available(algorithm)?;
    match algorithm {
        KemAlgorithm::None => Err(PqcError::invalid(
            algorithm.name(),
            "KemAlgorithm::None cannot decapsulate",
        )),
        KemAlgorithm::MlKem768 => {
            #[cfg(feature = "kem-mlkem-768")]
            {
                let sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(secret_key.as_bytes())
                    .map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-KEM-768 secret key")
                    })?;
                let ct =
                    pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext).map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-KEM-768 ciphertext")
                    })?;
                let shared = pqcrypto_kyber::kyber768::decapsulate(&ct, &sk);
                Ok(Zeroizing::new(shared.as_bytes().to_vec()))
            }
            #[cfg(not(feature = "kem-mlkem-768"))]
            {
                unreachable!("feature gate should have prevented this branch")
            }
        }
        KemAlgorithm::MlKem1024 => {
            #[cfg(feature = "kem-mlkem-1024")]
            {
                let sk = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(secret_key.as_bytes())
                    .map_err(|_| {
                        PqcError::invalid(algorithm.name(), "invalid ML-KEM-1024 secret key")
                    })?;
                let ct = pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(ciphertext).map_err(
                    |_| PqcError::invalid(algorithm.name(), "invalid ML-KEM-1024 ciphertext"),
                )?;
                let shared = pqcrypto_kyber::kyber1024::decapsulate(&ct, &sk);
                Ok(Zeroizing::new(shared.as_bytes().to_vec()))
            }
            #[cfg(not(feature = "kem-mlkem-1024"))]
            {
                unreachable!("feature gate should have prevented this branch")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_falls_back_when_relaxed() {
        let selection = negotiate_kem(&[KemAlgorithm::MlKem1024], StrictMode::Relaxed).unwrap();
        if selection.algorithm == KemAlgorithm::MlKem1024 {
            assert!(selection.algorithm.is_available());
        } else {
            assert_eq!(selection.algorithm, KemAlgorithm::None);
        }
    }

    #[test]
    fn negotiation_errors_when_strict() {
        let result = negotiate_kem(&[KemAlgorithm::MlKem1024], StrictMode::Strict);
        if KemAlgorithm::MlKem1024.is_available() {
            let selection = result.expect("mlkem-1024 must negotiate successfully");
            assert_eq!(selection.algorithm, KemAlgorithm::MlKem1024);
        } else {
            let err = result.expect_err("strict negotiation should fail without PQC");
            assert!(matches!(err, PqcError::StrictRequired));
        }
    }

    #[test]
    fn keygen_encapsulation_roundtrip() {
        if !KemAlgorithm::MlKem768.is_available() {
            return;
        }
        let kp = KemKeyPair::generate(KemAlgorithm::MlKem768).unwrap();
        let encapsulation = encapsulate(KemAlgorithm::MlKem768, kp.public_key()).unwrap();
        let expected_len = pqcrypto_kyber::kyber768::ciphertext_bytes();
        assert_eq!(encapsulation.ciphertext().len(), expected_len);
        pqcrypto_kyber::kyber768::Ciphertext::from_bytes(encapsulation.ciphertext())
            .expect("ciphertext roundtrip");
        let secret = decapsulate(
            KemAlgorithm::MlKem768,
            kp.secret_key(),
            encapsulation.ciphertext(),
        )
        .unwrap();
        assert_eq!(secret.as_slice(), encapsulation.shared_secret());
    }
}
