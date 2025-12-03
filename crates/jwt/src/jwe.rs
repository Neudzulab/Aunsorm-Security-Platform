use std::convert::TryFrom;
use std::fmt;

use aunsorm_core::{
    calibration::{calib_from_text, Calibration},
    salts::Salts,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, Verifier};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{
    error::{JwtError, Result},
    jwk::{Ed25519KeyPair, Ed25519PublicKey},
    AunsormNativeRng,
};

const TAG_SIZE: usize = 16;
const CONTENT_DERIVATION_INFO: &[u8] = b"Aunsorm/1.01/jwe/cek";

/// Kalibrasyon metadatasını taşıyan descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationDescriptor {
    #[serde(rename = "calibration_id")]
    pub calibration_id: String,
    #[serde(rename = "calibration_fingerprint")]
    pub calibration_fingerprint: String,
    #[serde(rename = "salt_calibration")]
    pub salt_calibration: String,
    #[serde(rename = "salt_chain")]
    pub salt_chain: String,
    #[serde(rename = "salt_coord")]
    pub salt_coord: String,
}

impl CalibrationDescriptor {
    /// Kalibrasyon ve salt verilerinden descriptor üretir.
    #[must_use]
    pub fn from_parts(calibration: &Calibration, salts: &Salts) -> Self {
        Self {
            calibration_id: calibration.id.as_str().to_owned(),
            calibration_fingerprint: calibration.fingerprint_b64(),
            salt_calibration: URL_SAFE_NO_PAD.encode(salts.calibration()),
            salt_chain: URL_SAFE_NO_PAD.encode(salts.chain()),
            salt_coord: URL_SAFE_NO_PAD.encode(salts.coord()),
        }
    }

    fn validate(&self, calibration: &Calibration, salts: &Salts) -> Result<()> {
        if self.calibration_id != calibration.id.as_str() {
            return Err(JwtError::InvalidJwe("calibration_id"));
        }
        if self.calibration_fingerprint != calibration.fingerprint_b64() {
            return Err(JwtError::InvalidJwe("calibration_fingerprint"));
        }
        if self.salt_calibration != URL_SAFE_NO_PAD.encode(salts.calibration()) {
            return Err(JwtError::InvalidJwe("salt_calibration"));
        }
        if self.salt_chain != URL_SAFE_NO_PAD.encode(salts.chain()) {
            return Err(JwtError::InvalidJwe("salt_chain"));
        }
        if self.salt_coord != URL_SAFE_NO_PAD.encode(salts.coord()) {
            return Err(JwtError::InvalidJwe("salt_coord"));
        }
        Ok(())
    }
}

/// JWE protected header içeriği.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JweProtectedHeader {
    pub alg: String,
    pub enc: String,
    pub typ: String,
    pub kid: String,
    #[serde(rename = "apu")]
    pub calibration: CalibrationDescriptor,
}

impl JweProtectedHeader {
    /// Kalibrasyon bilgisiyle yeni protected header oluşturur.
    #[must_use]
    pub fn new(kid: impl Into<String>, calibration: &Calibration, salts: &Salts) -> Self {
        Self {
            alg: "Ed25519-XC20P".to_string(),
            enc: "XC20P".to_string(),
            typ: "JWE".to_string(),
            kid: kid.into(),
            calibration: CalibrationDescriptor::from_parts(calibration, salts),
        }
    }

    fn validate(
        &self,
        verifying_key: &Ed25519PublicKey,
        calibration: &Calibration,
        salts: &Salts,
    ) -> Result<()> {
        if self.kid != verifying_key.kid() {
            return Err(JwtError::InvalidJwe("kid"));
        }
        if self.alg != "Ed25519-XC20P" || self.enc != "XC20P" || self.typ != "JWE" {
            return Err(JwtError::InvalidJwe("alg"));
        }
        self.calibration.validate(calibration, salts)
    }
}

/// Ed25519 + XChaCha20-Poly1305 hibrit JWE çıktısı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridJwe {
    pub protected: String,
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
    pub signature: String,
}

impl HybridJwe {
    /// Protected header'ı çözümler.
    ///
    /// # Errors
    /// Base64 çözülememesi veya JSON serileştirmesi başarısız olduğunda hata döner.
    pub fn protected_header(&self) -> Result<JweProtectedHeader> {
        let data = URL_SAFE_NO_PAD.decode(&self.protected)?;
        Ok(serde_json::from_slice(&data)?)
    }

    /// Kalibrasyon metninden türetilmiş verilerle JWE üretir.
    ///
    /// # Errors
    /// Kalibrasyon üretimi veya şifreleme sırasında hata oluşursa `JwtError` döner.
    pub fn encrypt_with_calibration_text(
        payload: &[u8],
        key_pair: &Ed25519KeyPair,
        org_salt: &[u8],
        calibration_note: &str,
        salts: &Salts,
    ) -> Result<Self> {
        let (calibration, _) = calib_from_text(org_salt, calibration_note)?;
        Self::encrypt(payload, key_pair, &calibration, salts)
    }

    /// Aunsorm Native RNG kullanarak JWE üretir.
    ///
    /// # Errors
    /// İçte kullanılan şifreleme ve imzalama adımları başarısız olursa hata üretir.
    pub fn encrypt(
        payload: &[u8],
        key_pair: &Ed25519KeyPair,
        calibration: &Calibration,
        salts: &Salts,
    ) -> Result<Self> {
        let mut rng = AunsormNativeRng::new();
        Self::encrypt_with_rng(payload, key_pair, calibration, salts, &mut rng)
    }

    /// Harici RNG ile JWE üretir.
    ///
    /// # Errors
    /// Şifreleme, anahtar türetimi veya imzalama işlemleri başarısız olursa hata döner.
    pub fn encrypt_with_rng(
        payload: &[u8],
        key_pair: &Ed25519KeyPair,
        calibration: &Calibration,
        salts: &Salts,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self> {
        let header = JweProtectedHeader::new(key_pair.kid().to_owned(), calibration, salts);
        let header_json = serde_json::to_vec(&header)?;
        let protected = URL_SAFE_NO_PAD.encode(header_json);

        let mut cek = derive_content_key(calibration, salts)?;
        let mut key = Key::default();
        key.copy_from_slice(&cek);
        let cipher = XChaCha20Poly1305::new(&key);

        let mut nonce = [0_u8; 24];
        rng.fill_bytes(&mut nonce);
        let mut nonce_ga = XNonce::default();
        nonce_ga.copy_from_slice(&nonce);

        let mut ciphertext = cipher
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: payload,
                    aad: protected.as_bytes(),
                },
            )
            .map_err(|_| JwtError::Encryption("aead failure"))?;

        let mut auth_tag = ciphertext.split_off(ciphertext.len() - TAG_SIZE);
        let ciphertext_b64 = URL_SAFE_NO_PAD.encode(&ciphertext);
        let tag_b64 = URL_SAFE_NO_PAD.encode(&auth_tag);
        let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);

        let signing_input = SigningInput::new(&protected, &nonce_b64, &ciphertext_b64, &tag_b64);
        let mut signature = key_pair
            .signing_key()
            .sign(signing_input.as_bytes())
            .to_bytes();
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

        cek.zeroize();
        key.iter_mut().for_each(|byte| *byte = 0);
        ciphertext.zeroize();
        auth_tag.zeroize();
        nonce.zeroize();
        nonce_ga.iter_mut().for_each(|byte| *byte = 0);
        signature.zeroize();

        Ok(Self {
            protected,
            nonce: nonce_b64,
            ciphertext: ciphertext_b64,
            tag: tag_b64,
            signature: signature_b64,
        })
    }

    /// JWE çıktısını doğrulayarak plaintext'i döndürür.
    ///
    /// # Errors
    /// İmza doğrulaması, şifre çözme veya kalibrasyon doğrulaması başarısız olursa hata döner.
    pub fn decrypt(
        &self,
        verifying_key: &Ed25519PublicKey,
        calibration: &Calibration,
        salts: &Salts,
    ) -> Result<Vec<u8>> {
        let header = self.protected_header()?;
        header.validate(verifying_key, calibration, salts)?;

        let mut signature_bytes = URL_SAFE_NO_PAD.decode(&self.signature)?;
        let signature = Signature::try_from(signature_bytes.as_slice()).map_err(|_| {
            signature_bytes.zeroize();
            JwtError::InvalidJwe("signature")
        })?;

        let signing_input =
            SigningInput::new(&self.protected, &self.nonce, &self.ciphertext, &self.tag);
        verifying_key
            .verifying_key()
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| JwtError::Signature)?;
        signature_bytes.zeroize();

        let mut nonce_bytes = URL_SAFE_NO_PAD
            .decode(&self.nonce)
            .map_err(|_| JwtError::InvalidJwe("nonce"))?;
        if nonce_bytes.len() != 24 {
            nonce_bytes.zeroize();
            return Err(JwtError::InvalidJwe("nonce_length"));
        }
        let mut nonce_ga = XNonce::default();
        nonce_ga.copy_from_slice(&nonce_bytes);

        let mut ciphertext_bytes = URL_SAFE_NO_PAD
            .decode(&self.ciphertext)
            .map_err(|_| JwtError::InvalidJwe("ciphertext"))?;
        let mut tag_bytes = URL_SAFE_NO_PAD
            .decode(&self.tag)
            .map_err(|_| JwtError::InvalidJwe("tag"))?;
        if tag_bytes.len() != TAG_SIZE {
            tag_bytes.zeroize();
            return Err(JwtError::InvalidJwe("tag_length"));
        }
        ciphertext_bytes.extend_from_slice(&tag_bytes);
        tag_bytes.zeroize();

        let mut cek = derive_content_key(calibration, salts)?;
        let mut key = Key::default();
        key.copy_from_slice(&cek);
        let cipher = XChaCha20Poly1305::new(&key);
        let plaintext = cipher
            .decrypt(
                &nonce_ga,
                Payload {
                    msg: &ciphertext_bytes,
                    aad: self.protected.as_bytes(),
                },
            )
            .map_err(|_| JwtError::Decryption("aead failure"))?;
        cek.zeroize();
        key.iter_mut().for_each(|byte| *byte = 0);
        ciphertext_bytes.zeroize();
        nonce_bytes.zeroize();
        nonce_ga.iter_mut().for_each(|byte| *byte = 0);

        Ok(plaintext)
    }

    /// Kalibrasyon metni üzerinden çözme işlemi.
    ///
    /// # Errors
    /// Kalibrasyon üretimi veya şifre çözme başarısız olduğunda hata döner.
    pub fn decrypt_with_calibration_text(
        &self,
        verifying_key: &Ed25519PublicKey,
        org_salt: &[u8],
        calibration_note: &str,
        salts: &Salts,
    ) -> Result<Vec<u8>> {
        let (calibration, _) = calib_from_text(org_salt, calibration_note)?;
        self.decrypt(verifying_key, &calibration, salts)
    }
}

fn derive_content_key(calibration: &Calibration, salts: &Salts) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(
        Some(calibration.fingerprint()),
        calibration.id.as_str().as_bytes(),
    );
    let mut info = Vec::with_capacity(
        CONTENT_DERIVATION_INFO.len()
            + salts.calibration().len()
            + salts.chain().len()
            + salts.coord().len(),
    );
    info.extend_from_slice(CONTENT_DERIVATION_INFO);
    info.extend_from_slice(salts.calibration());
    info.extend_from_slice(salts.chain());
    info.extend_from_slice(salts.coord());

    let mut key = [0_u8; 32];
    let expand_result = hk.expand(&info, &mut key);
    info.zeroize();
    expand_result.map_err(|_| JwtError::Encryption("hkdf failure"))?;
    Ok(key)
}

struct SigningInput {
    buffer: String,
}

impl SigningInput {
    fn new(protected: &str, nonce: &str, ciphertext: &str, tag: &str) -> Self {
        let mut buffer =
            String::with_capacity(protected.len() + nonce.len() + ciphertext.len() + tag.len() + 3);
        buffer.push_str(protected);
        buffer.push('.');
        buffer.push_str(nonce);
        buffer.push('.');
        buffer.push_str(ciphertext);
        buffer.push('.');
        buffer.push_str(tag);
        Self { buffer }
    }

    fn as_bytes(&self) -> &[u8] {
        self.buffer.as_bytes()
    }
}

impl fmt::Display for SigningInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.buffer)
    }
}
