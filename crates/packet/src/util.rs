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
