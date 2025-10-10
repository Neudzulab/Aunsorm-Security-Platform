use std::fmt;

use hex::ToHex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::PacketError;
use crate::header::Header;

/// Paket transcript karması.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptHash(#[serde(with = "crate::util::serde_bytes32")] pub [u8; 32]);

impl TranscriptHash {
    /// Ham baytları döndürür.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex gösterimini üretir.
    #[must_use]
    pub fn to_hex(self) -> String {
        self.0.encode_hex::<String>()
    }
}

impl fmt::Display for TranscriptHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

fn feed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn header_bytes(header: &Header) -> Result<Vec<u8>, PacketError> {
    let json = serde_json::to_vec(header)?;
    Ok(json)
}

/// Transcript karmasını hesaplar.
///
/// # Errors
/// JSON serileştirmesi başarısız olursa `PacketError::Serialization` döner.
pub fn compute_transcript(
    header: &Header,
    aad: &[u8],
    ciphertext: &[u8],
    body_pmac: &[u8; 16],
) -> Result<TranscriptHash, PacketError> {
    let mut hasher = Sha256::new();
    hasher.update(b"Aunsorm/1.01/packet-transcript");
    let header_bytes = header_bytes(header)?;
    feed(&mut hasher, &header_bytes);
    feed(&mut hasher, aad);
    feed(&mut hasher, ciphertext);
    hasher.update(body_pmac);
    Ok(TranscriptHash(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{
        AeadAlgorithm, HeaderAead, HeaderKem, HeaderProfile, HeaderSalts, HeaderSizes,
    };

    fn sample_header() -> Header {
        Header {
            version: "1.01".to_string(),
            profile: HeaderProfile {
                t: 2,
                m_kib: 4096,
                p: 1,
            },
            calib_id: "cal-123".to_string(),
            coord_digest: "abc".to_string(),
            salts: HeaderSalts {
                password: "pw".to_string(),
                calibration: "cal".to_string(),
                chain: "chain".to_string(),
                coord: "coord".to_string(),
            },
            kem: HeaderKem::none(),
            aead: HeaderAead {
                alg: AeadAlgorithm::AesGcm,
                nonce: "nonce".to_string(),
                aad_digest: "aad".to_string(),
            },
            session: None,
            sizes: HeaderSizes {
                plaintext: 11,
                ciphertext: 16,
            },
            hdrmac: "mac".to_string(),
        }
    }

    #[test]
    fn transcript_is_deterministic() {
        let header = sample_header();
        let aad = b"aad";
        let ciphertext = b"ciphertext";
        let body_pmac = [0xAA_u8; 16];
        let first = compute_transcript(&header, aad, ciphertext, &body_pmac).expect("hash");
        let second = compute_transcript(&header, aad, ciphertext, &body_pmac).expect("hash");
        assert_eq!(first, second);
    }
}
