//! Fixed-format AES-GCM seed decoder shared by production and fuzz drivers.

use aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum SeedDecodeError {
    EncodedLength,
    Base64,
    EnvelopeLength,
    Key,
    Authentication,
}

/// Decode exactly one nonce/seed/tag envelope and authenticate its caller AAD.
///
/// Fixed output buffers are owned before decoding/decryption. On failure the
/// seed owner is dropped and zeroized; no plaintext vector is allocated.
pub fn unwrap(
    wrap_key: &[u8; 32],
    wrapped: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SeedDecodeError> {
    if wrapped.len() != 80 {
        return Err(SeedDecodeError::EncodedLength);
    }
    let mut bytes = [0u8; 60];
    let decoded = STANDARD
        .decode_slice(wrapped, &mut bytes)
        .map_err(|_| SeedDecodeError::Base64)?;
    if decoded != bytes.len() {
        return Err(SeedDecodeError::EnvelopeLength);
    }
    let cipher = Aes256Gcm::new_from_slice(wrap_key).map_err(|_| SeedDecodeError::Key)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&bytes[44..]);
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes[12..44]);
    cipher
        .decrypt_in_place_detached(&Nonce::from(nonce), aad, &mut seed[..], &Tag::from(tag))
        .map_err(|_| SeedDecodeError::Authentication)?;
    Ok(seed)
}
