#![no_main]

use aunsorm_core::SessionRatchet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 49 {
        return;
    }

    let mut root_key = [0_u8; 32];
    root_key.copy_from_slice(&data[..32]);
    let mut session_id = [0_u8; 16];
    session_id.copy_from_slice(&data[32..48]);
    let strict = data[48] & 1 == 1;
    let steps = data.get(49).copied().unwrap_or(0) as usize % 32;

    let mut ratchet = SessionRatchet::new(root_key, session_id, strict);

    for _ in 0..steps {
        if ratchet.next_step().is_err() {
            break;
        }
    }
});
