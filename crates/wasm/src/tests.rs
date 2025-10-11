use base64::{engine::general_purpose::STANDARD, Engine as _};

use aunsorm_packet::PacketError;

use crate::internal::{self, DecryptRequest, EncryptRequest, WasmError};

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

fn sample_decrypt_request(packet: String) -> DecryptRequest {
    DecryptRequest {
        password: "correct horse battery staple".to_string(),
        packet_b64: packet,
        org_salt_b64: STANDARD.encode(b"WeAreKut.eu"),
        calib_text: "Neudzulab | Prod | 2025-08".to_string(),
        profile: Some("medium".to_string()),
        aad: None,
        strict: Some(false),
    }
}

#[test]
fn encrypt_then_decrypt_roundtrip() {
    let encrypt_req = sample_encrypt_request();
    let packet = internal::encrypt(encrypt_req).expect("encrypt");

    let decrypt_req = sample_decrypt_request(packet);
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

#[test]
fn decrypt_requires_matching_external_calibration() {
    let packet = internal::encrypt(sample_encrypt_request()).expect("encrypt");
    let mut request = sample_decrypt_request(packet);
    request.calib_text = "Wrong note".to_string();

    let err = internal::decrypt(request).expect_err("calibration should mismatch");
    match err {
        WasmError::Packet(PacketError::Integrity(message)) => {
            assert!(message.contains("calibration id mismatch"));
        }
        WasmError::Packet(PacketError::Invalid(message)) => {
            assert!(
                message.contains("salt mismatch"),
                "unexpected invalid message: {message}"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}
