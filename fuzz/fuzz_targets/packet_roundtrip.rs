#![no_main]

use aunsorm_packet::{peek_header, Packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(encoded) = std::str::from_utf8(data) {
        let _ = peek_header(encoded);
        if let Ok(packet) = Packet::from_base64(encoded) {
            let _ = packet.to_base64();
        }
    }
});
