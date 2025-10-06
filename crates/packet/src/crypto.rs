use aead::{Aead, KeyInit, Payload};
use aes::Aes256;
use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pmac::{Mac as PmacTrait, Pmac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::error::PacketError;
use crate::header::{AeadAlgorithm, Header};

pub const VERSION: &str = "1.01";

pub struct KeyMaterial {
    pub aead: [u8; 32],
    pub header_mac: [u8; 32],
    pub body_mac: [u8; 32],
}

pub fn derive_keys(base: &[u8], label: &str) -> Result<KeyMaterial, PacketError> {
    let hk = Hkdf::<Sha256>::new(Some(label.as_bytes()), base);
    let mut aead = [0_u8; 32];
    let mut header_mac = [0_u8; 32];
    let mut body_mac = [0_u8; 32];
    hk.expand(b"Aunsorm/1.01/aead-key", &mut aead)
        .map_err(|_| PacketError::Aead("hkdf expand failed"))?;
    hk.expand(b"Aunsorm/1.01/header-mac", &mut header_mac)
        .map_err(|_| PacketError::Aead("hkdf expand failed"))?;
    hk.expand(b"Aunsorm/1.01/body-mac", &mut body_mac)
        .map_err(|_| PacketError::Aead("hkdf expand failed"))?;
    Ok(KeyMaterial {
        aead,
        header_mac,
        body_mac,
    })
}

pub fn random_nonce() -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt_aead(
    algorithm: AeadAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match algorithm {
        AeadAlgorithm::AesGcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| PacketError::Aead("invalid key"))?;
            cipher
                .encrypt(nonce.into(), payload)
                .map_err(|_| PacketError::Aead("encryption failure"))
        }
        AeadAlgorithm::Chacha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| PacketError::Aead("invalid key"))?;
            cipher
                .encrypt(nonce.into(), payload)
                .map_err(|_| PacketError::Aead("encryption failure"))
        }
    }
}

pub fn decrypt_aead(
    algorithm: AeadAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match algorithm {
        AeadAlgorithm::AesGcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| PacketError::Aead("invalid key"))?;
            cipher
                .decrypt(nonce.into(), payload)
                .map_err(|_| PacketError::Aead("decryption failure"))
        }
        AeadAlgorithm::Chacha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| PacketError::Aead("invalid key"))?;
            cipher
                .decrypt(nonce.into(), payload)
                .map_err(|_| PacketError::Aead("decryption failure"))
        }
    }
}

pub fn compute_header_mac(header: &Header, key: &[u8]) -> Result<String, PacketError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| PacketError::Aead("invalid mac key"))?;
    let json = serde_json::to_vec(&header.without_mac())?;
    mac.update(&json);
    let tag = mac.finalize().into_bytes();
    Ok(STANDARD_NO_PAD.encode(tag))
}

pub fn verify_header_mac(header: &Header, key: &[u8]) -> Result<(), PacketError> {
    let expected = compute_header_mac(header, key)?;
    if constant_time_eq(expected.as_bytes(), header.hdrmac.as_bytes()) {
        Ok(())
    } else {
        Err(PacketError::Integrity("header mac mismatch"))
    }
}

pub fn compute_body_pmac(key: &[u8; 32], ciphertext: &[u8]) -> Result<[u8; 16], PacketError> {
    let mut pmac = <Pmac<Aes256> as PmacTrait>::new_from_slice(key)
        .map_err(|_| PacketError::Aead("invalid pmac key"))?;
    pmac.update(ciphertext);
    let result = pmac.finalize().into_bytes();
    Ok(result.into())
}

pub fn verify_body_pmac(key: &[u8; 32], ciphertext: &[u8], tag: &[u8]) -> Result<(), PacketError> {
    let expected = compute_body_pmac(key, ciphertext)?;
    if constant_time_eq(&expected, tag) {
        Ok(())
    } else {
        Err(PacketError::Integrity("body pmac mismatch"))
    }
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

pub fn digest_bytes(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"Aunsorm/1.01/header-digest");
    hasher.update(input);
    STANDARD_NO_PAD.encode(hasher.finalize())
}

pub fn coord_digest(coord: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"Aunsorm/1.01/coord-digest");
    hasher.update(coord);
    STANDARD_NO_PAD.encode(hasher.finalize())
}

pub fn aad_digest(aad: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(b"Aunsorm/1.01/aad-digest");
    hasher.update(aad);
    STANDARD_NO_PAD.encode(hasher.finalize())
}

pub fn base64_encode(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>, PacketError> {
    STANDARD_NO_PAD.decode(input).map_err(PacketError::Base64)
}
