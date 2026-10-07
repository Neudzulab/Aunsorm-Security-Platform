#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/kms/src/wrapped_seed.rs"]
mod wrapped_seed;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1104 {
        return;
    }
    let split = data.len().min(80);
    let (envelope, aad) = data.split_at(split);
    if let Ok(seed) = wrapped_seed::unwrap(&[7u8; 32], envelope, aad) {
        assert_eq!(seed.len(), 32);
        assert!(wrapped_seed::unwrap(&[8u8; 32], envelope, aad).is_err());
        let mut changed_aad = aad.to_vec();
        changed_aad.push(0);
        assert!(wrapped_seed::unwrap(&[7u8; 32], envelope, &changed_aad).is_err());
    }
});
