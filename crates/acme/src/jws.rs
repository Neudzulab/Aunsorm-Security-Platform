use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey, VerifyingKey};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::elliptic_curve;
use p256::SecretKey as P256SecretKey;
use rsa::errors::Error as RsaError;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use signature::Error as SignatureError;
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
    /// ECDSA tabanlı hesap anahtarı hatalı olduğunda döner.
    #[error("ACME ECDSA P-256 anahtarı geçersiz: {0}")]
    InvalidEcdsaKey(#[from] elliptic_curve::Error),
    /// RSA tabanlı hesap anahtarı hatalı olduğunda döner.
    #[error("ACME RSA anahtarı geçersiz: {0}")]
    InvalidRsaKey(#[from] RsaError),
    /// İmza üretimi sırasında hata oluştuğunda döner.
    #[error("ACME JWS imzası üretilemedi: {0}")]
    Signature(#[from] SignatureError),
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
        sign_payload_internal(
            Self::ALGORITHM,
            payload,
            nonce,
            url,
            binding,
            || self.jwk(),
            |signing_input| {
                let signature = self.signing_key.sign(signing_input);
                Ok(signature.to_bytes().to_vec())
            },
        )
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

/// ECDSA P-256 doğrulama anahtarını JWK formatında temsil eder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdsaP256Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl EcdsaP256Jwk {
    #[must_use]
    fn from_verifying_key(key: &P256VerifyingKey) -> Self {
        let point = key.to_encoded_point(false);
        let x = point
            .x()
            .expect("verifying key must expose affine x-coordinate");
        let y = point
            .y()
            .expect("verifying key must expose affine y-coordinate");

        Self {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        }
    }
}

/// ECDSA P-256 tabanlı ACME hesap anahtarı.
#[derive(Clone)]
pub struct EcdsaP256AccountKey {
    signing_key: P256SigningKey,
}

impl fmt::Debug for EcdsaP256AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaP256AccountKey")
            .finish_non_exhaustive()
    }
}

impl EcdsaP256AccountKey {
    /// ACME JWS başlığında kullanılacak algoritma adı.
    pub const ALGORITHM: &'static str = "ES256";

    /// Doğrudan `p256` gizli anahtarından hesap anahtarı oluşturur.
    #[must_use]
    pub fn from_secret_key(secret_key: P256SecretKey) -> Self {
        Self {
            signing_key: P256SigningKey::from(secret_key),
        }
    }

    /// 32 baytlık büyük-endian özel anahtardan hesap anahtarı üretir.
    ///
    /// # Errors
    ///
    /// Anahtar materyali eğri alanı dışında kaldığında `JwsError::InvalidEcdsaKey`
    /// döner.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, JwsError> {
        let secret_key = P256SecretKey::from_slice(bytes)?;
        Ok(Self::from_secret_key(secret_key))
    }

    /// 32 baytlık özel anahtar materyalini tüketip belleği sıfırlar.
    ///
    /// # Errors
    ///
    /// Anahtar materyali geçersizse `JwsError::InvalidEcdsaKey` döner.
    pub fn from_be_bytes(mut bytes: [u8; 32]) -> Result<Self, JwsError> {
        let key = Self::from_bytes(&bytes)?;
        bytes.zeroize();
        Ok(key)
    }

    /// ECDSA doğrulama anahtarını döndürür.
    #[must_use]
    pub fn verifying_key(&self) -> P256VerifyingKey {
        *self.signing_key.verifying_key()
    }

    /// ECDSA doğrulama anahtarını JWK formatında döndürür.
    #[must_use]
    pub fn jwk(&self) -> EcdsaP256Jwk {
        EcdsaP256Jwk::from_verifying_key(&self.verifying_key())
    }

    /// Ham payload byte dizisini imzalayıp ACME JWS çıktısı üretir.
    ///
    /// # Errors
    ///
    /// `binding` için boş `kid` verildiğinde veya imza üretimi başarısız
    /// olduğunda ilgili `JwsError` varyantı döner.
    pub fn sign_payload(
        &self,
        payload: &[u8],
        nonce: &ReplayNonce,
        url: &Url,
        binding: KeyBinding<'_>,
    ) -> Result<AcmeJws, JwsError> {
        sign_payload_internal(
            Self::ALGORITHM,
            payload,
            nonce,
            url,
            binding,
            || self.jwk(),
            |signing_input| {
                let signature: P256Signature = self.signing_key.sign(signing_input);
                Ok(signature.to_bytes().to_vec())
            },
        )
    }

    /// JSON payload'ı ACME JWS olarak imzalar.
    ///
    /// # Errors
    ///
    /// JSON serileştirme veya imza üretimi başarısız olursa `JwsError`
    /// döndürülür.
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

/// RSA doğrulama anahtarını JWK formatında temsil eder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaJwk {
    pub kty: String,
    pub n: String,
    pub e: String,
}

impl RsaJwk {
    #[must_use]
    fn from_public_key(key: &RsaPublicKey) -> Self {
        Self {
            kty: "RSA".to_string(),
            n: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
        }
    }
}

/// RSA PKCS#1 v1.5 (RS256) tabanlı ACME hesap anahtarı.
#[derive(Clone)]
pub struct RsaAccountKey {
    signing_key: RsaSigningKey<Sha256>,
}

impl fmt::Debug for RsaAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaAccountKey").finish_non_exhaustive()
    }
}

impl RsaAccountKey {
    /// ACME JWS başlığında kullanılacak algoritma adı.
    pub const ALGORITHM: &'static str = "RS256";

    /// RSA özel anahtarından hesap anahtarı oluşturur.
    ///
    /// # Errors
    ///
    /// Sağlanan anahtar doğrulama kontrollerinden geçemezse
    /// `JwsError::InvalidRsaKey` döner.
    pub fn new(private_key: RsaPrivateKey) -> Result<Self, JwsError> {
        private_key.validate()?;
        Ok(Self {
            signing_key: RsaSigningKey::<Sha256>::new(private_key),
        })
    }

    /// RSA doğrulama anahtarını döndürür.
    #[must_use]
    pub fn verifying_key(&self) -> rsa::pkcs1v15::VerifyingKey<Sha256> {
        signature::Keypair::verifying_key(&self.signing_key)
    }

    /// RSA doğrulama anahtarını JWK formatında döndürür.
    #[must_use]
    pub fn jwk(&self) -> RsaJwk {
        RsaJwk::from_public_key(self.verifying_key().as_ref())
    }

    /// Ham payload byte dizisini imzalayıp ACME JWS çıktısı üretir.
    ///
    /// # Errors
    ///
    /// `binding` için boş `kid` verildiğinde veya imza üretimi başarısız
    /// olduğunda `JwsError` döner.
    pub fn sign_payload(
        &self,
        payload: &[u8],
        nonce: &ReplayNonce,
        url: &Url,
        binding: KeyBinding<'_>,
    ) -> Result<AcmeJws, JwsError> {
        sign_payload_internal(
            Self::ALGORITHM,
            payload,
            nonce,
            url,
            binding,
            || self.jwk(),
            |signing_input| {
                let signature = signature::Signer::try_sign(&self.signing_key, signing_input)?;
                let bytes: Box<[u8]> = signature::SignatureEncoding::to_bytes(&signature);
                Ok(bytes.into_vec())
            },
        )
    }

    /// JSON payload'ı ACME JWS olarak imzalar.
    ///
    /// # Errors
    ///
    /// JSON serileştirme veya imza üretimi başarısız olursa `JwsError`
    /// döndürülür.
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
struct ProtectedHeader<J>
where
    J: Serialize,
{
    alg: &'static str,
    nonce: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<J>,
}

fn build_protected_header<J: Serialize>(
    algorithm: &'static str,
    nonce: &ReplayNonce,
    url: &Url,
    binding: KeyBinding<'_>,
    jwk_supplier: impl FnOnce() -> J,
) -> Result<Vec<u8>, JwsError> {
    let (kid, jwk) = match binding {
        KeyBinding::Kid(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(JwsError::EmptyKid);
            }
            (Some(trimmed.to_owned()), None)
        }
        KeyBinding::Jwk => (None, Some(jwk_supplier())),
    };

    let header = ProtectedHeader {
        alg: algorithm,
        nonce: nonce.as_str().to_owned(),
        url: url.as_str().to_owned(),
        kid,
        jwk,
    };

    serde_json::to_vec(&header).map_err(Into::into)
}

fn sign_payload_internal<J: Serialize>(
    algorithm: &'static str,
    payload: &[u8],
    nonce: &ReplayNonce,
    url: &Url,
    binding: KeyBinding<'_>,
    jwk_supplier: impl FnOnce() -> J,
    signer: impl FnOnce(&[u8]) -> Result<Vec<u8>, JwsError>,
) -> Result<AcmeJws, JwsError> {
    let protected_json = build_protected_header(algorithm, nonce, url, binding, jwk_supplier)?;
    let protected = URL_SAFE_NO_PAD.encode(protected_json);
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{protected}.{payload}");
    let signature = signer(signing_input.as_bytes())?;
    let signature = URL_SAFE_NO_PAD.encode(signature);

    Ok(AcmeJws {
        protected,
        payload,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::ReplayNonce;
    use ed25519_dalek::{Signature, Verifier, SIGNATURE_LENGTH};
    use p256::ecdsa::Signature as P256Signature;
    use p256::SecretKey as P256SecretKey;
    use pretty_assertions::assert_eq;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use rsa::pkcs1v15::Signature as RsaSignature;
    use rsa::RsaPrivateKey;
    use serde_json::json;
    use std::convert::{TryFrom, TryInto};

    fn sample_key() -> Ed25519AccountKey {
        Ed25519AccountKey::from_seed([42_u8; 32])
    }

    fn sample_p256_key() -> EcdsaP256AccountKey {
        let secret = P256SecretKey::from_slice(&[7_u8; 32]).expect("geçerli p256 anahtarı");
        EcdsaP256AccountKey::from_secret_key(secret)
    }

    fn sample_rsa_key() -> RsaAccountKey {
        let mut rng = ChaCha20Rng::from_seed([11_u8; 32]);
        let private_key = RsaPrivateKey::new(&mut rng, 1024).expect("rsa anahtarı üretimi");
        RsaAccountKey::new(private_key).expect("geçerli rsa anahtarı")
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

    #[test]
    fn ecdsa_sign_payload_with_jwk_binding() {
        let key = sample_p256_key();
        let payload = br#"{"resource":"newOrder"}"#;
        let signed = key
            .sign_payload(payload, &sample_nonce(), &sample_url(), KeyBinding::Jwk)
            .expect("ecdsa jws üretimi");

        let protected_bytes = URL_SAFE_NO_PAD
            .decode(signed.protected.as_bytes())
            .expect("protected decode");
        let protected: serde_json::Value = serde_json::from_slice(&protected_bytes).unwrap();

        let jwk = protected["jwk"].as_object().expect("jwk nesnesi");
        assert_eq!(protected["alg"], EcdsaP256AccountKey::ALGORITHM);
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(signed.payload.as_bytes())
            .expect("payload decode");
        assert_eq!(payload_bytes, payload);

        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signed.signature.as_bytes())
            .expect("signature decode");
        let signature = P256Signature::try_from(signature_bytes.as_slice()).expect("imza boyutu");
        let signing_input = format!("{}.{}", signed.protected, signed.payload);
        let verifying_key = key.verifying_key();
        signature::Verifier::verify(&verifying_key, signing_input.as_bytes(), &signature)
            .expect("ecdsa imza doğrulama");
    }

    #[test]
    fn ecdsa_sign_payload_with_kid_binding() {
        let key = sample_p256_key();
        let payload = b"{}";
        let kid = "https://acme.example/acct/456";
        let signed = key
            .sign_payload(
                payload,
                &sample_nonce(),
                &sample_url(),
                KeyBinding::Kid(kid),
            )
            .expect("ecdsa jws üretimi");

        let protected_bytes = URL_SAFE_NO_PAD
            .decode(signed.protected.as_bytes())
            .expect("protected decode");
        let protected: serde_json::Value = serde_json::from_slice(&protected_bytes).unwrap();

        assert_eq!(protected["kid"], kid);
        assert!(protected.get("jwk").is_none());
    }

    #[test]
    fn ecdsa_jwk_matches_verifying_key() {
        let key = sample_p256_key();
        let jwk = key.jwk();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        let decoded_x = URL_SAFE_NO_PAD.decode(jwk.x.as_bytes()).unwrap();
        let decoded_y = URL_SAFE_NO_PAD.decode(jwk.y.as_bytes()).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let expected_x: Vec<u8> = point.x().unwrap().iter().copied().collect();
        let expected_y: Vec<u8> = point.y().unwrap().iter().copied().collect();
        assert_eq!(decoded_x, expected_x);
        assert_eq!(decoded_y, expected_y);
    }

    #[test]
    fn ecdsa_from_bytes_rejects_zero_scalar() {
        let err = EcdsaP256AccountKey::from_bytes(&[0_u8; 32]).unwrap_err();
        assert!(matches!(err, JwsError::InvalidEcdsaKey(_)));
    }

    #[test]
    fn rsa_sign_payload_with_jwk_binding() {
        let key = sample_rsa_key();
        let payload = br#"{"resource":"revokeCert"}"#;
        let signed = key
            .sign_payload(payload, &sample_nonce(), &sample_url(), KeyBinding::Jwk)
            .expect("rsa jws üretimi");

        let protected_bytes = URL_SAFE_NO_PAD
            .decode(signed.protected.as_bytes())
            .expect("protected decode");
        let protected: serde_json::Value = serde_json::from_slice(&protected_bytes).unwrap();
        assert_eq!(protected["alg"], RsaAccountKey::ALGORITHM);
        assert!(protected.get("kid").is_none());

        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signed.signature.as_bytes())
            .expect("signature decode");
        let signature = RsaSignature::try_from(signature_bytes.as_slice()).expect("rsa imza");
        let signing_input = format!("{}.{}", signed.protected, signed.payload);
        let verifying_key = key.verifying_key();
        signature::Verifier::verify(&verifying_key, signing_input.as_bytes(), &signature)
            .expect("rsa imza doğrulama");
    }

    #[test]
    fn rsa_sign_payload_with_kid_binding() {
        let key = sample_rsa_key();
        let kid = "https://acme.example/acct/789";
        let signed = key
            .sign_payload(b"{}", &sample_nonce(), &sample_url(), KeyBinding::Kid(kid))
            .expect("rsa jws üretimi");

        let protected_bytes = URL_SAFE_NO_PAD
            .decode(signed.protected.as_bytes())
            .expect("protected decode");
        let protected: serde_json::Value = serde_json::from_slice(&protected_bytes).unwrap();

        assert_eq!(protected["kid"], kid);
        assert!(protected.get("jwk").is_none());
    }

    #[test]
    fn rsa_jwk_matches_public_key() {
        let key = sample_rsa_key();
        let jwk = key.jwk();
        assert_eq!(jwk.kty, "RSA");
        let decoded_n = URL_SAFE_NO_PAD.decode(jwk.n.as_bytes()).unwrap();
        let decoded_e = URL_SAFE_NO_PAD.decode(jwk.e.as_bytes()).unwrap();
        let verifying = key.verifying_key();
        assert_eq!(decoded_n, verifying.as_ref().n().to_bytes_be());
        assert_eq!(decoded_e, verifying.as_ref().e().to_bytes_be());
    }
}
