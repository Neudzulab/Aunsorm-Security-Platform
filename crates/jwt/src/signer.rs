use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use serde_json::json;

use crate::claims::Claims;
use crate::error::Result;
use crate::jwk::Ed25519KeyPair;

#[cfg(feature = "kms")]
use aunsorm_kms::{KeyDescriptor as KmsKeyDescriptor, KmsClient};
#[cfg(feature = "kms")]
use ed25519_dalek::VerifyingKey;

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

    /// Kullanılan `kid` değerini döndürür.
    #[must_use]
    pub fn kid(&self) -> &str {
        self.key.kid()
    }

    /// Claims'i imzalayıp JWT üretir.
    ///
    /// # Errors
    ///
    /// Zaman alanları tutarsız ise veya serileştirme hatası oluşursa `JwtError` döner.
    pub fn sign(&self, claims: &mut Claims) -> Result<String> {
        claims.ensure_jwt_id();
        claims.validate_custom_claims()?;
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

/// KMS tabanlı JWT imzalayıcı.
#[cfg(feature = "kms")]
pub struct KmsJwtSigner<'a> {
    client: &'a KmsClient,
    descriptor: KmsKeyDescriptor,
    kid: String,
}

#[cfg(feature = "kms")]
impl<'a> KmsJwtSigner<'a> {
    /// Yeni bir KMS imzalayıcısı oluşturur.
    ///
    /// # Errors
    ///
    /// `KeyDescriptor` çözümlenemediğinde veya backend erişilemez olduğunda
    /// `JwtError` döner.
    pub fn new(client: &'a KmsClient, descriptor: KmsKeyDescriptor) -> Result<Self> {
        let kid = client.key_kid(&descriptor)?;
        Ok(Self {
            client,
            descriptor,
            kid,
        })
    }

    /// Kullanılan `kid` değerini döndürür.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Ed25519 public anahtarını döndürür.
    ///
    /// # Errors
    ///
    /// Backend public anahtarı sağlayamazsa `JwtError` döner.
    pub fn public_key(&self) -> Result<VerifyingKey> {
        let bytes = self.client.public_ed25519(&self.descriptor)?;
        let mut buf = [0_u8; 32];
        if bytes.len() != buf.len() {
            return Err(crate::error::JwtError::InvalidClaim(
                "public",
                "invalid length",
            ));
        }
        buf.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&buf)
            .map_err(|_| crate::error::JwtError::InvalidClaim("public", "invalid key"))
    }

    /// Claims'i imzalayıp JWT döndürür.
    ///
    /// # Errors
    ///
    /// Zaman alanları veya KMS imzalama işlemi başarısız olursa `JwtError`
    /// döner.
    pub fn sign(&self, claims: &mut Claims) -> Result<String> {
        claims.ensure_jwt_id();
        claims.validate_custom_claims()?;
        claims.validate_temporal_consistency()?;
        let header = json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": self.kid,
        });
        let header_encoded = encode_part(&header)?;
        let payload_encoded = encode_part(claims)?;
        let signing_input = format!("{header_encoded}.{payload_encoded}");
        let signature = self
            .client
            .sign_ed25519(&self.descriptor, signing_input.as_bytes())?;
        let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
        Ok(token)
    }
}
