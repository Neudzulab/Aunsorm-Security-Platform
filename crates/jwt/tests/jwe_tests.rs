use aunsorm_core::{calibration::calib_from_text, salts::Salts};
use aunsorm_jwt::{CalibrationDescriptor, Ed25519KeyPair, HybridJwe, JweProtectedHeader, JwtError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn encrypt_decrypt_roundtrip_fixture() {
    let (calibration, _) =
        calib_from_text(b"org-salt-123", "Aunsorm Prod 2025").expect("calibration");
    let salts = Salts::from_slices(
        b"calibration-salt-1234",
        b"chain-salt-123456",
        b"coord-salt-abcdef",
    )
    .expect("salts");
    let mut seed = [7_u8; 32];
    let key_pair = Ed25519KeyPair::from_seed("test-key", seed).expect("seeded key");
    seed.fill(0);

    let plaintext = b"Hybrid envelope payload";
    let mut rng = StdRng::from_seed([0_u8; 32]);
    let envelope =
        HybridJwe::encrypt_with_rng(plaintext, &key_pair, &calibration, &salts, &mut rng)
            .expect("encrypt");

    let header = envelope.protected_header().expect("header");
    let expected_header = JweProtectedHeader::new(key_pair.kid().to_string(), &calibration, &salts);
    assert_eq!(header, expected_header);

    assert_eq!(envelope.nonce, "m_SaagdV-VOBH84SXyaD1QQpw7tJ4HQU");
    assert_eq!(envelope.ciphertext, "sSqPnKadzkoADunmrSEje9DUNt-b20s");
    assert_eq!(envelope.tag, "m_J458mCMTgK8_N7_K_uJw");

    let decrypted = envelope
        .decrypt(&key_pair.public_key(), &calibration, &salts)
        .expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn reject_invalid_calibration_text() {
    let salts = Salts::from_slices(
        b"calibration-salt-1234",
        b"chain-salt-123456",
        b"coord-salt-abcdef",
    )
    .expect("salts");
    let key_pair = Ed25519KeyPair::from_seed("test-key", [3_u8; 32]).expect("seeded key");
    let result = HybridJwe::encrypt_with_calibration_text(
        b"payload",
        &key_pair,
        b"org-salt-123",
        "\u{0007}invalid",
        &salts,
    );
    match result {
        Err(JwtError::Calibration(err)) => {
            assert!(err.to_string().contains("control characters"));
        }
        other => panic!("unexpected result: {:?}", other),
    }
}

#[test]
fn header_descriptor_encodes_calibration() {
    let (calibration, _) =
        calib_from_text(b"org-salt-123", "Aunsorm Prod 2025").expect("calibration");
    let salts = Salts::from_slices(
        b"calibration-salt-1234",
        b"chain-salt-123456",
        b"coord-salt-abcdef",
    )
    .expect("salts");

    let descriptor = CalibrationDescriptor::from_parts(&calibration, &salts);
    assert_eq!(descriptor.calibration_id, calibration.id.as_str());
    assert_eq!(
        descriptor.calibration_fingerprint,
        calibration.fingerprint_b64()
    );
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&descriptor.salt_coord).expect("b64"),
        salts.coord()
    );
}
