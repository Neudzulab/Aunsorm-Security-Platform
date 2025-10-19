#![no_main]

use std::borrow::Cow;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;

type DecryptResult = Result<
    (
        aunsorm_packet::DecryptOk,
        aunsorm_packet::SessionStepOutcome,
    ),
    aunsorm_packet::PacketError,
>;

struct SessionHarness {
    metadata: aunsorm_packet::SessionMetadata,
}

static HARNESS: Lazy<SessionHarness> = Lazy::new(|| {
    let profile = aunsorm_core::KdfProfile::preset(aunsorm_core::KdfPreset::Low);
    let salts = aunsorm_core::Salts::new(
        b"fuzz-calib-salt-123".to_vec(),
        b"fuzz-chain-salt-456".to_vec(),
        b"fuzz-coord-salt-789".to_vec(),
    )
    .expect("salts");
    let (calibration, _) =
        aunsorm_core::calib_from_text(b"fuzz-org", "fuzz-note").expect("calibration");
    let handshake_packet = aunsorm_packet::encrypt_one_shot(aunsorm_packet::EncryptParams {
        password: "fuzz-password",
        password_salt: b"fuzz-password-salt",
        calibration: &calibration,
        salts: &salts,
        plaintext: b"handshake",
        aad: b"handshake-aad",
        profile,
        algorithm: aunsorm_packet::AeadAlgorithm::AesGcm,
        strict: false,
        kem: None,
    })
    .expect("handshake packet");
    let encoded = handshake_packet
        .to_base64()
        .expect("handshake base64 conversion");
    let handshake = aunsorm_packet::decrypt_one_shot(&aunsorm_packet::DecryptParams {
        password: "fuzz-password",
        password_salt: b"fuzz-password-salt",
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"handshake-aad",
        strict: false,
        packet: &encoded,
    })
    .expect("handshake decrypt");

    SessionHarness {
        metadata: handshake.metadata,
    }
});

fuzz_target!(|data: &[u8]| {
    let mut ratchet = aunsorm_core::SessionRatchet::new([7_u8; 32], [9_u8; 16], false);
    let mut store = aunsorm_packet::SessionStore::new();

    let candidate: Cow<'_, str> = std::str::from_utf8(data)
        .map(Cow::Borrowed)
        .unwrap_or_else(|_| Cow::Owned(STANDARD.encode(data)));

    let _: DecryptResult = aunsorm_packet::decrypt_session(aunsorm_packet::SessionDecryptParams {
        ratchet: &mut ratchet,
        metadata: &HARNESS.metadata,
        store: &mut store,
        aad: b"fuzz-session-aad",
        packet: &candidate,
    });
});
