#![no_main]

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;

type PacketResult = Result<aunsorm_packet::Packet, aunsorm_packet::PacketError>;

fn fuzz_input(data: &[u8]) -> std::borrow::Cow<'_, str> {
    std::str::from_utf8(data)
        .map(std::borrow::Cow::Borrowed)
        .unwrap_or_else(|_| std::borrow::Cow::Owned(STANDARD.encode(data)))
}

fuzz_target!(|data: &[u8]| {
    let candidate = fuzz_input(data);
    let _ = aunsorm_packet::peek_header(&candidate);
    let _: PacketResult = aunsorm_packet::Packet::from_base64(&candidate);
});
