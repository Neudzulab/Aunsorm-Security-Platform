use std::convert::TryInto;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use aunsorm_core::{calib_from_text, KdfPreset, KdfProfile, Salts, SessionRatchet};
use aunsorm_kms::{BackendKind, BackendLocator, KeyDescriptor, KmsClient, KmsConfig};
use aunsorm_packet::{
    decrypt_one_shot, decrypt_session, encrypt_one_shot, encrypt_session, AeadAlgorithm,
    DecryptParams, EncryptParams, SessionDecryptParams, SessionEncryptParams, SessionStore,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const DEFAULT_SESSION_ITERATIONS: usize = 256;
const DEFAULT_KMS_ITERATIONS: usize = 128;

fn parse_iterations(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn build_handshake() -> aunsorm_packet::DecryptOk {
    let profile = KdfProfile::preset(KdfPreset::Low);
    let salts = Salts::new(
        b"soak-calib-salt".to_vec(),
        b"soak-chain-salt".to_vec(),
        b"soak-coord-salt".to_vec(),
    )
    .expect("salts");
    let (calibration, _) = calib_from_text(b"soak-org", "session-soak").expect("calibration");

    let packet = encrypt_one_shot(EncryptParams {
        password: "session-password",
        password_salt: b"session-salt",
        calibration: &calibration,
        salts: &salts,
        plaintext: b"handshake",
        aad: b"handshake-aad",
        profile,
        algorithm: AeadAlgorithm::AesGcm,
        strict: false,
        kem: None,
    })
    .expect("handshake encrypt");
    let encoded = packet.to_base64().expect("handshake encode");

    decrypt_one_shot(&DecryptParams {
        password: "session-password",
        password_salt: b"session-salt",
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"handshake-aad",
        strict: false,
        packet: &encoded,
    })
    .expect("handshake decrypt")
}

#[test]
#[ignore]
fn session_ratchet_roundtrip_soak() {
    let iterations = parse_iterations("AUNSORM_SESSION_SOAK", DEFAULT_SESSION_ITERATIONS);

    for cycle in 0..iterations {
        let handshake = build_handshake();
        let mut sender = SessionRatchet::new([cycle as u8; 32], [cycle as u8; 16], false);
        let mut receiver = SessionRatchet::new([cycle as u8; 32], [cycle as u8; 16], false);
        let mut store = SessionStore::new();

        for message_no in 0..8_u8 {
            let mut payload = vec![cycle as u8; usize::from(message_no) + 1];
            payload.push(message_no);
            let aad = [cycle as u8, message_no];

            let (packet, outcome) = encrypt_session(SessionEncryptParams {
                ratchet: &mut sender,
                metadata: &handshake.metadata,
                plaintext: &payload,
                aad: &aad,
            })
            .expect("session encrypt");
            let encoded = packet.to_base64().expect("session encode");
            let (decrypted, received) = decrypt_session(SessionDecryptParams {
                ratchet: &mut receiver,
                metadata: &handshake.metadata,
                store: &mut store,
                aad: &aad,
                packet: &encoded,
            })
            .expect("session decrypt");
            assert_eq!(decrypted.plaintext, payload);
            assert_eq!(outcome.message_no, received.message_no);
        }
    }
}

fn write_local_store_file() -> PathBuf {
    let mut path = std::env::temp_dir();
    let unique = format!(
        "aunsorm-soak-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    path.push(unique);
    let mut file = File::create(&path).expect("local store file");
    let signing_secret = STANDARD.encode([0x42u8; 32]);
    let wrap_secret = STANDARD.encode([0x24u8; 32]);
    let json = format!(
        "{{\n  \"keys\": [\n    {{\n      \"id\": \"jwt-sign\",\n      \"purpose\": \"ed25519-sign\",\n      \"secret\": \"{signing_secret}\"\n    }},\n    {{\n      \"id\": \"wrap\",\n      \"purpose\": \"aes256-wrap\",\n      \"secret\": \"{wrap_secret}\"\n    }}\n  ]\n}}"
    );
    file.write_all(json.as_bytes()).expect("write local store");
    file.flush().expect("flush local store");
    path
}

#[test]
#[ignore]
fn kms_local_roundtrip_soak() {
    let iterations = parse_iterations("AUNSORM_KMS_SOAK", DEFAULT_KMS_ITERATIONS);
    let path = write_local_store_file();
    let config = KmsConfig::local_only(&path).expect("local config");
    let client = KmsClient::from_config(config).expect("kms client");
    let sign_descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Local, "jwt-sign"));
    let wrap_locator = BackendLocator::new(BackendKind::Local, "wrap");

    let public = client.public_ed25519(&sign_descriptor).expect("public key");
    let verifying =
        VerifyingKey::from_bytes(&public.try_into().expect("public len")).expect("verifying");
    let expected_kid = hex::encode(Sha256::digest(verifying.as_bytes()));
    assert_eq!(client.key_kid(&sign_descriptor).expect("kid"), expected_kid);

    for counter in 0..iterations {
        let message = format!("kms-soak-{counter}");
        let aad = format!("kms-aad-{counter}");
        let signature = client
            .sign_ed25519(&sign_descriptor, message.as_bytes())
            .expect("sign");
        assert_eq!(signature.len(), 64);
        let signature = Signature::from_bytes(&signature.as_slice().try_into().expect("sig len"));
        verifying
            .verify_strict(message.as_bytes(), &signature)
            .expect("verify");

        let wrapped = client
            .wrap_key(&wrap_locator, message.as_bytes(), aad.as_bytes())
            .expect("wrap");
        let unwrapped = client
            .unwrap_key(&wrap_locator, &wrapped, aad.as_bytes())
            .expect("unwrap");
        assert_eq!(unwrapped, message.as_bytes());
    }

    fs::remove_file(path).ok();
}
