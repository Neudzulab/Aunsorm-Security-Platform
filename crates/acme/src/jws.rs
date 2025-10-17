use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;

use crate::nonce::ReplayNonce;

/// ACME JWS üretimi sırasında oluşabilecek hatalar.
#[derive(Debug, Error)]
pub enum JwsError {
    /// `kid` bağlamı boş bırakıldığında döner.
    #[error("ACME kid değeri boş olamaz")]
    EmptyKid,
    /// JSON yükü serileştirilirken hata meydana geldiğinde döner.
    #[error("ACME JWS yükü serileştirilemedi: {0}")]
    SerializePayload(#[from] serde_json::Error),
}

/// İmzalanmış ACME JWS çıktısı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeJws {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

/// JWS başlığında kullanılacak anahtar referansı türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBinding<'a> {
    /// Mevcut bir ACME hesabının `kid` değerini kullanır.
    Kid(&'a str),
    /// Yeni hesap kayıtlarında olduğu gibi JWK içerir.
    Jwk,
}

/// Ed25519 doğrulama anahtarını JWK formatında temsil eder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

impl Ed25519Jwk {
    #[must_use]
    fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: URL_SAFE_NO_PAD.encode(key.as_bytes()),
        }
    }
}

/// Ed25519 tabanlı ACME hesap anahtarı.
#[derive(Clone)]
pub struct Ed25519AccountKey {
    signing_key: SigningKey,
}

impl fmt::Debug for Ed25519AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519AccountKey").finish_non_exhaustive()
    }
}

impl Ed25519AccountKey {
    /// ACME JWS başlığında kullanılacak algoritma adı.
    pub const ALGORITHM: &'static str = "EdDSA";

    /// 32 baytlık gizli anahtardan yeni hesap anahtarı oluşturur.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// 32 baytlık seed'i tüketerek hesap anahtarı oluşturur.
    #[must_use]
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let key = Self::from_bytes(&seed);
        seed.zeroize();
        key
    }

    /// Ed25519 doğrulama anahtarını döndürür.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Ed25519 doğrulama anahtarını JWK formatında döndürür.
    #[must_use]
    pub fn jwk(&self) -> Ed25519Jwk {
        Ed25519Jwk::from_verifying_key(&self.verifying_key())
    }

    /// Ham payload byte dizisini imzalayıp ACME JWS çıktısı üretir.
    ///
    /// # Errors
    ///
    /// * `JwsError::EmptyKid` - `KeyBinding::Kid` seçildiğinde boş bir değer sağlandığında.
    /// * `JwsError::SerializePayload` - korumalı başlık serileştirilirken hata oluşursa.
    pub fn sign_payload(
        &self,
        payload: &[u8],
        nonce: &ReplayNonce,
        url: &Url,
        binding: KeyBinding<'_>,
    ) -> Result<AcmeJws, JwsError> {
        let (kid, jwk) = match binding {
            KeyBinding::Kid(value) => {
                if value.trim().is_empty() {
                    return Err(JwsError::EmptyKid);
                }
                (Some(value.trim().to_owned()), None)
            }
            KeyBinding::Jwk => (None, Some(self.jwk())),
        };

        let header = ProtectedHeader {
            alg: Self::ALGORITHM,
            nonce: nonce.as_str().to_owned(),
            url: url.as_str().to_owned(),
            kid,
            jwk,
        };

        let protected_json = serde_json::to_vec(&header)?;
        let protected = URL_SAFE_NO_PAD.encode(protected_json);
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{protected}.{payload}");
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(AcmeJws {
            protected,
            payload,
            signature,
        })
    }

    /// JSON seri hale getirilebilir payload'ı ACME JWS olarak imzalar.
    ///
    /// # Errors
    ///
    /// * `JwsError::EmptyKid` - `KeyBinding::Kid` seçildiğinde boş bir değer sağlandığında.
    /// * `JwsError::SerializePayload` - JSON serileştirme işlemi başarısız olduğunda.
    pub fn sign_json<T: Serialize>(
        &self,
        payload: &T,
        nonce: &ReplayNonce,
        url: &Url,
        binding: KeyBinding<'_>,
    ) -> Result<AcmeJws, JwsError> {
        let bytes = serde_json::to_vec(payload)?;
        self.sign_payload(&bytes, nonce, url, binding)
    }
}

#[derive(Debug, Serialize)]
struct ProtectedHeader {
    alg: &'static str,
    nonce: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Ed25519Jwk>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::ReplayNonce;
    use ed25519_dalek::{Signature, Verifier, SIGNATURE_LENGTH};
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::convert::TryInto;

    fn sample_key() -> Ed25519AccountKey {
        Ed25519AccountKey::from_seed([42_u8; 32])
    }

    fn sample_nonce() -> ReplayNonce {
        ReplayNonce::parse("z9lqO7iAJ6T4tO4Hq8xPRA").expect("nonce parse edilmedi")
    }

    fn sample_url() -> Url {
        Url::parse("https://acme.example/new-account").unwrap()
    }

    #[test]
    fn sign_payload_with_jwk_binding() {
        let key = sample_key();
        let payload = br#"{"resource":"newAccount"}"#;
        let signed = key
            .sign_payload(payload, &sample_nonce(), &sample_url(), KeyBinding::Jwk)
            .expect("jws üretimi");

        let protected_bytes = URL_SAFE_NO_PAD
            .decode(signed.protected.as_bytes())
            .expect("base64 decode");
        let protected: serde_json::Value = serde_json::from_slice(&protected_bytes).unwrap();

        let key_jwk = key.jwk();
        assert_eq!(protected["alg"], Ed25519AccountKey::ALGORITHM);
        assert_eq!(protected["nonce"], sample_nonce().as_str());
        assert_eq!(protected["url"], sample_url().as_str());
        assert!(protected.get("kid").is_none());

        let jwk = protected["jwk"].as_object().expect("jwk nesnesi");
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(
            jwk.get("x").and_then(serde_json::Value::as_str),
            Some(key_jwk.x.as_str()),
        );

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(signed.payload.as_bytes())
            .expect("payload decode");
        assert_eq!(payload_bytes, payload);

        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signed.signature.as_bytes())
            .expect("signature decode");
        assert_eq!(signature_bytes.len(), SIGNATURE_LENGTH);
        let signature = Signature::from_bytes(
            &signature_bytes
                .try_into()
                .expect("signature uzunluğu sabit"),
        );
        let signing_input = format!("{}.{}", signed.protected, signed.payload);
        key.verifying_key()
            .verify(signing_input.as_bytes(), &signature)
            .expect("imza doğrulama");
    }

    #[test]
    fn sign_payload_with_kid_binding() {
        let key = sample_key();
        let payload = b"{}";
        let kid = "https://acme.example/acct/123";
        let signed = key
            .sign_payload(
                payload,
                &sample_nonce(),
                &sample_url(),
                KeyBinding::Kid(kid),
            )
            .expect("jws üretimi");

        let protected_bytes = URL_SAFE_NO_PAD
            .decode(signed.protected.as_bytes())
            .expect("decode");
        let protected: serde_json::Value = serde_json::from_slice(&protected_bytes).unwrap();

        assert_eq!(protected["kid"], kid);
        assert!(protected.get("jwk").is_none());
    }

    #[test]
    fn empty_kid_rejected() {
        let key = sample_key();
        let err = key
            .sign_payload(
                b"{}",
                &sample_nonce(),
                &sample_url(),
                KeyBinding::Kid(" \t"),
            )
            .unwrap_err();
        assert!(matches!(err, JwsError::EmptyKid));
    }

    #[test]
    fn sign_json_serializes_payload() {
        let key = sample_key();
        let payload = json!({"type": "challenge", "status": "pending"});
        let signed = key
            .sign_json(&payload, &sample_nonce(), &sample_url(), KeyBinding::Jwk)
            .expect("jws üretimi");

        let decoded = URL_SAFE_NO_PAD
            .decode(signed.payload.as_bytes())
            .expect("payload decode");
        let value: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(value, payload);
    }

    #[test]
    fn jwk_matches_verifying_key() {
        let key = sample_key();
        let jwk = key.jwk();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        let decoded = URL_SAFE_NO_PAD.decode(jwk.x.as_bytes()).unwrap();
        assert_eq!(decoded, key.verifying_key().as_bytes());
    }
}
