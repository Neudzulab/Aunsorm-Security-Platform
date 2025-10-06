use zeroize::Zeroizing;

use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

use crate::error::{PqcError, Result};

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
                Ok(signature.as_bytes().to_vec())
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
}
