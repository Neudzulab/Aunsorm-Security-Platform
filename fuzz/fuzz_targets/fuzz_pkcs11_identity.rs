#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/kms/src/pkcs11_identity.rs"]
mod pkcs11_identity;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 || data.len() > 1120 {
        return;
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&data[..32]);
    let end = data.len().min(96);
    let signature = &data[32..end];
    let message = &data[end..];
    if pkcs11_identity::verify_response(&public, message, signature).is_ok() {
        let mut changed = message.to_vec();
        changed.push(0);
        assert!(pkcs11_identity::verify_response(&public, &changed, signature).is_err());
        assert!(pkcs11_identity::validate_public(&public).is_ok());
    }
});
