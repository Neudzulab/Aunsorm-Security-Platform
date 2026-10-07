#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/kms/src/pkcs11_point.rs"]
mod pkcs11_point;

fuzz_target!(|data: &[u8]| {
    if let Ok(public) = pkcs11_point::parse_ed25519_point(data) {
        assert!(data.len() == 34 || data.len() == 36);
        let mut canonical = vec![4, 32];
        canonical.extend_from_slice(&public);
        assert_eq!(pkcs11_point::parse_ed25519_point(&canonical), Ok(public));
        if data.len() == 34 {
            assert_eq!(data, canonical.as_slice());
        } else {
            let mut double = vec![4, 34];
            double.extend_from_slice(&canonical);
            assert_eq!(data, double.as_slice());
        }
    }
});
