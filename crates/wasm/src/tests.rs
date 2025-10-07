use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::internal::{self, DecryptRequest, EncryptRequest};

fn sample_encrypt_request() -> EncryptRequest {
    EncryptRequest {
        password: "correct horse battery staple".to_string(),
        plaintext: b"lorem ipsum".to_vec(),
        org_salt_b64: STANDARD.encode(b"WeAreKut.eu"),
        calib_text: "Neudzulab | Prod | 2025-08".to_string(),
        profile: Some("medium".to_string()),
        aead: Some("aes-gcm".to_string()),
        aad: None,
        strict: Some(false),
        kem: None,
    }
}

#[test]
fn encrypt_then_decrypt_roundtrip() {
    let encrypt_req = sample_encrypt_request();
    let packet = internal::encrypt(encrypt_req).expect("encrypt");

    let decrypt_req = DecryptRequest {
        password: "correct horse battery staple".to_string(),
        packet_b64: packet,
        org_salt_b64: STANDARD.encode(b"WeAreKut.eu"),
        calib_text: "Neudzulab | Prod | 2025-08".to_string(),
        profile: Some("medium".to_string()),
        aad: None,
        strict: Some(false),
    };

    let plaintext = internal::decrypt(decrypt_req).expect("decrypt");
    assert_eq!(plaintext, b"lorem ipsum");
}

#[test]
fn peek_header_returns_calibration() {
    let packet = internal::encrypt(sample_encrypt_request()).expect("encrypt");
    let header = internal::peek_header(&packet).expect("peek header");
    assert_eq!(header.calib_id.len(), 24);
}

#[test]
fn rejects_unknown_profile() {
    let mut request = sample_encrypt_request();
    request.profile = Some("unknown".to_string());
    let err = internal::encrypt(request).expect_err("should fail");
    let message = err.to_string();
    assert!(message.contains("invalid kdf profile"));
}
