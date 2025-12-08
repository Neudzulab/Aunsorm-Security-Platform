use serde::Deserialize;
use serde_json::from_slice;

use crate::crypto::base64_decode;
use crate::error::PacketError;
use crate::header::Header;

#[derive(Deserialize)]
struct HeaderEnvelope {
    header: Header,
}

/// Paket başlığını çözmeden incelemek için kullanılır.
///
/// # Errors
/// Base64 veya JSON ayrıştırma işlemleri başarısız olursa `PacketError` döner.
pub fn peek_header(packet_b64: &str) -> Result<Header, PacketError> {
    let data = base64_decode(packet_b64)?;
    let envelope: HeaderEnvelope = from_slice(&data)?;
    Ok(envelope.header)
}

pub mod serde_bytes32 {
    use hex::{FromHex, ToHex};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.encode_hex::<String>())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        <[u8; 32]>::from_hex(text).map_err(serde::de::Error::custom)
    }
}
