use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use serde_json::json;

use crate::claims::Claims;
use crate::error::Result;
use crate::jwk::Ed25519KeyPair;

/// JWT imzalayıcı.
#[derive(Clone)]
pub struct JwtSigner {
    key: Ed25519KeyPair,
}

impl JwtSigner {
    /// Yeni bir imzalayıcı oluşturur.
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn new(key: Ed25519KeyPair) -> Self {
        Self { key }
    }

    /// Claims'i imzalayıp JWT üretir.
    ///
    /// # Errors
    ///
    /// Zaman alanları tutarsız ise veya serileştirme hatası oluşursa `JwtError` döner.
    pub fn sign(&self, claims: &Claims) -> Result<String> {
        claims.validate_temporal_consistency()?;
        let header = json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": self.key.kid(),
        });
        let header_encoded = encode_part(&header)?;
        let payload_encoded = encode_part(claims)?;
        let signing_input = format!("{header_encoded}.{payload_encoded}");
        let signature = self
            .key
            .signing_key()
            .sign(signing_input.as_bytes())
            .to_bytes();
        let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
        Ok(token)
    }
}

fn encode_part<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_vec(value)?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

// ed25519-dalek Signer trait
use ed25519_dalek::Signer as _;
