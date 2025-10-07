use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SecretKey, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use zeroize::Zeroize;

use crate::error::{JwtError, Result};

/// Ed25519 anahtar çifti.
pub struct Ed25519KeyPair {
    kid: String,
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl Clone for Ed25519KeyPair {
    fn clone(&self) -> Self {
        let secret = self.signing.to_bytes();
        let signing = SigningKey::from_bytes(&secret);
        let verifying = signing.verifying_key();
        Self {
            kid: self.kid.clone(),
            signing,
            verifying,
        }
    }
}

impl Ed25519KeyPair {
    /// Rastgele anahtar üretir.
    ///
    /// # Errors
    ///
    /// RNG'den seed alınırken veya seed doğrulanırken hata oluşursa `JwtError` döner.
    pub fn generate(kid: impl Into<String>) -> Result<Self> {
        let mut rng = OsRng;
        Self::generate_with_rng(kid, &mut rng)
    }

    /// Harici RNG ile anahtar üretir.
    ///
    /// # Errors
    ///
    /// RNG kaynaklı hatalar `from_seed` tarafından döndürülen hatalara aktarılır.
    pub fn generate_with_rng(
        kid: impl Into<String>,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self> {
        let mut seed = [0_u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(kid, seed)
    }

    /// 32 baytlık seed'den anahtar oluşturur.
    ///
    /// # Errors
    ///
    /// Geçersiz bir Ed25519 gizli anahtarı sağlanırsa `JwtError::InvalidClaim` döner.
    pub fn from_seed(kid: impl Into<String>, mut seed: [u8; 32]) -> Result<Self> {
        let secret = SecretKey::try_from(&seed[..])
            .map_err(|_| JwtError::InvalidClaim("seed", "invalid ed25519 secret key"))?;
        seed.zeroize();
        let signing = SigningKey::from(&secret);
        let verifying = signing.verifying_key();
        Ok(Self {
            kid: kid.into(),
            signing,
            verifying,
        })
    }

    /// Anahtar kimliğini döndürür.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// İmza anahtarını döndürür.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// Doğrulama anahtarını döndürür.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// Public anahtarı döndürür.
    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            kid: self.kid.clone(),
            verifying: self.verifying,
        }
    }

    /// JWK olarak dışa aktarır.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn to_jwk(&self) -> Jwk {
        self.public_key().to_jwk()
    }
}

/// Ed25519 doğrulama anahtarı.
#[derive(Clone, Debug)]
pub struct Ed25519PublicKey {
    kid: String,
    verifying: VerifyingKey,
}

impl Ed25519PublicKey {
    /// Anahtar kimliği.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Doğrulama anahtarı.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// JWK çıktısı.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn to_jwk(&self) -> Jwk {
        Jwk {
            kid: self.kid.clone(),
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            x: URL_SAFE_NO_PAD.encode(self.verifying.as_bytes()),
        }
    }

    /// JWK'tan doğrulama anahtarı oluşturur.
    ///
    /// # Errors
    ///
    /// Anahtar alanları beklenen formatta değilse `JwtError::UnsupportedAlgorithm`
    /// veya `JwtError::InvalidClaim` döner.
    pub fn from_jwk(value: &Jwk) -> Result<Self> {
        if value.kty != "OKP" || value.crv != "Ed25519" || value.alg != "EdDSA" {
            return Err(JwtError::UnsupportedAlgorithm(value.crv.clone()));
        }
        let mut buf = [0_u8; 32];
        let decoded = URL_SAFE_NO_PAD.decode(&value.x)?;
        if decoded.len() != buf.len() {
            return Err(JwtError::InvalidClaim("x", "invalid length"));
        }
        buf.copy_from_slice(&decoded);
        let verifying = VerifyingKey::from_bytes(&buf)
            .map_err(|_| JwtError::InvalidClaim("x", "invalid key"))?;
        Ok(Self {
            kid: value.kid.clone(),
            verifying,
        })
    }
}

/// Tekil JWK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(rename = "kid")]
    pub kid: String,
    #[serde(rename = "kty")]
    pub kty: String,
    #[serde(rename = "crv")]
    pub crv: String,
    #[serde(rename = "alg")]
    pub alg: String,
    #[serde(rename = "x")]
    pub x: String,
}

impl From<Ed25519PublicKey> for Jwk {
    fn from(value: Ed25519PublicKey) -> Self {
        value.to_jwk()
    }
}

/// JWKS koleksiyonu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Map yapısı döndürür.
    ///
    /// # Errors
    ///
    /// JWKS içindeki anahtarlar geçerli Ed25519 parametreleri değilse hata döner.
    pub fn to_map(&self) -> Result<HashMap<String, Ed25519PublicKey>> {
        let mut map = HashMap::with_capacity(self.keys.len());
        for jwk in &self.keys {
            let key = Ed25519PublicKey::from_jwk(jwk)?;
            map.insert(jwk.kid.clone(), key);
        }
        Ok(map)
    }
}
