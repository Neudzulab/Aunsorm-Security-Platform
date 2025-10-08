#![no_main]

use aunsorm_core::{calib_from_text, KdfPreset, KdfProfile, Salts, SessionRatchet};
use aunsorm_packet::{
    decrypt_one_shot, decrypt_session, encrypt_one_shot, encrypt_session, AeadAlgorithm,
    DecryptParams, DecryptOk, EncryptParams, SessionDecryptParams, SessionEncryptParams,
    SessionStore,
};
use libfuzzer_sys::fuzz_target;

fn build_handshake() -> Option<DecryptOk> {
    let profile = KdfProfile::preset(KdfPreset::Low);
    let salts = Salts::new(
        b"fuzz-calib-salt-123".to_vec(),
        b"fuzz-chain-salt-456".to_vec(),
        b"fuzz-coord-salt-789".to_vec(),
    )
    .ok()?;
    let (calibration, _) = calib_from_text(b"fuzz-org", "fuzz-note");
    let password = "fuzz-password";
    let password_salt = b"fuzz-password-salt";

    let packet = encrypt_one_shot(EncryptParams {
        password,
        password_salt,
        calibration: &calibration,
        salts: &salts,
        plaintext: b"handshake",
        aad: b"handshake-aad",
        profile,
        algorithm: AeadAlgorithm::AesGcm,
        strict: false,
        kem: None,
    })
    .ok()?;
    let encoded = packet.to_base64().ok()?;
    decrypt_one_shot(&DecryptParams {
        password,
        password_salt,
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"handshake-aad",
        strict: false,
        packet: &encoded,
    })
    .ok()
}

fuzz_target!(|data: &[u8]| {
    let handshake = match build_handshake() {
        Some(value) => value,
        None => return,
    };

    let mut sender = SessionRatchet::new([11_u8; 32], [7_u8; 16], false);
    let mut receiver = SessionRatchet::new([11_u8; 32], [7_u8; 16], false);
    let mut store = SessionStore::new();

    for (index, chunk) in data.chunks(64).enumerate() {
        let aad = &data[..index.min(data.len())];
        let plaintext = chunk;

        let (packet, outcome) = match encrypt_session(SessionEncryptParams {
            ratchet: &mut sender,
            metadata: &handshake.metadata,
            aad,
            plaintext,
        }) {
            Ok(value) => value,
            Err(_) => break,
        };
        let encoded = match packet.to_base64() {
            Ok(value) => value,
            Err(_) => break,
        };
        match decrypt_session(SessionDecryptParams {
            ratchet: &mut receiver,
            metadata: &handshake.metadata,
            store: &mut store,
            aad,
            packet: &encoded,
        }) {
            Ok((decrypted, received)) => {
                if decrypted.plaintext != plaintext {
                    panic!("plaintext mismatch: expected {:?} got {:?}", plaintext, decrypted.plaintext);
                }
                if outcome.message_no != received.message_no {
                    panic!(
                        "message number diverged: sender {} receiver {}",
                        outcome.message_no, received.message_no
                    );
                }
            }
            Err(_) => break,
        }
    }
});
