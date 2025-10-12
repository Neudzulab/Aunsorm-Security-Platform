//! Beyaz şapka saldırı senaryosu: başlıktaki AEAD algoritmasını aşağı seviyeye
//! düşürmeye çalışan saldırganın tespit edildiğini doğrular.

use aunsorm_core::{
    calib_from_text, session::SessionRatchet, Calibration, KdfPreset, KdfProfile, Salts,
};
use aunsorm_packet::{
    decrypt_one_shot, decrypt_session, encrypt_one_shot, encrypt_session, AeadAlgorithm,
    DecryptParams, EncryptParams, Packet, PacketError, SessionDecryptParams, SessionEncryptParams,
    SessionStore,
};

fn build_safe_packet() -> (String, Salts, Calibration, KdfProfile) {
    let salts = Salts::new(
        b"hacker-calib-salt".to_vec(),
        b"hacker-chain-salt".to_vec(),
        b"hacker-coord-salt".to_vec(),
    )
    .expect("salts satisfy minimum entropy");
    let profile = KdfProfile::preset(KdfPreset::Low);
    let (calibration, _) =
        calib_from_text(b"white-hat-org", "penetration-test").expect("calibration");

    let packet = encrypt_one_shot(EncryptParams {
        password: "penetration-password",
        password_salt: b"penetration-salt",
        calibration: &calibration,
        salts: &salts,
        plaintext: b"classified payload",
        aad: b"classified aad",
        profile,
        algorithm: AeadAlgorithm::AesGcm,
        strict: false,
        kem: None,
    })
    .expect("encryption succeeds in baseline scenario");

    let encoded = packet
        .to_base64()
        .expect("packet serializes without issues");

    (encoded, salts, calibration, profile)
}

#[test]
fn hacker_agent_detects_aead_downgrade_attempt() {
    let (encoded, salts, calibration, profile) = build_safe_packet();

    let mut tampered = Packet::from_base64(&encoded).expect("original packet decodes");
    // Saldırgan AEAD algoritmasını Chacha20Poly1305'e düşürüp zayıf bir mod dayatmaya çalışıyor.
    tampered.header.aead.alg = AeadAlgorithm::Chacha20Poly1305;
    let tampered_encoded = tampered
        .to_base64()
        .expect("tampered packet still encodes as base64");

    let result = decrypt_one_shot(&DecryptParams {
        password: "penetration-password",
        password_salt: b"penetration-salt",
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"classified aad",
        strict: false,
        packet: &tampered_encoded,
    });

    assert!(matches!(
        result,
        Err(PacketError::Integrity(_)) | Err(PacketError::Invalid(_))
    ));
}

#[test]
fn tampered_coord_digest_is_detected() {
    let (encoded, salts, calibration, profile) = build_safe_packet();

    let mut tampered = Packet::from_base64(&encoded).expect("original packet decodes");
    tampered.header.coord_digest =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
    let tampered_encoded = tampered
        .to_base64()
        .expect("tampered packet still encodes as base64");

    let result = decrypt_one_shot(&DecryptParams {
        password: "penetration-password",
        password_salt: b"penetration-salt",
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"classified aad",
        strict: false,
        packet: &tampered_encoded,
    });

    assert!(matches!(
        result,
        Err(PacketError::Integrity(message)) if message == "coord digest mismatch"
    ));
}

#[test]
fn ciphertext_truncation_is_detected() {
    let (encoded, salts, calibration, profile) = build_safe_packet();

    let mut tampered = Packet::from_base64(&encoded).expect("original packet decodes");
    assert!(
        !tampered.ciphertext.is_empty(),
        "ciphertext must not be empty"
    );
    tampered.ciphertext.truncate(tampered.ciphertext.len() - 1);
    let tampered_encoded = tampered
        .to_base64()
        .expect("tampered packet still encodes as base64");

    let result = decrypt_one_shot(&DecryptParams {
        password: "penetration-password",
        password_salt: b"penetration-salt",
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"classified aad",
        strict: false,
        packet: &tampered_encoded,
    });

    assert!(matches!(
        result,
        Err(PacketError::Integrity(message)) if message == "ciphertext size mismatch"
    ));
}

#[test]
fn forged_aad_digest_is_rejected() {
    let (encoded, salts, calibration, profile) = build_safe_packet();

    // Saldırgan farklı bir AAD bağlamı kullanarak başlık özetini tutarsız hale getiriyor.
    let result = decrypt_one_shot(&DecryptParams {
        password: "penetration-password",
        password_salt: b"penetration-salt",
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"different aad context",
        strict: false,
        packet: &encoded,
    });

    assert!(matches!(
        result,
        Err(PacketError::Invalid(message)) if message == "aad mismatch"
    ));
}

#[test]
fn strict_mode_rejects_packets_without_kem_material() {
    let (encoded, salts, calibration, profile) = build_safe_packet();

    let result = decrypt_one_shot(&DecryptParams {
        password: "penetration-password",
        password_salt: b"penetration-salt",
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"classified aad",
        strict: true,
        packet: &encoded,
    });

    assert!(
        matches!(result, Err(PacketError::Strict(message)) if message == "kem material required in strict mode")
    );
}

#[test]
fn session_message_number_tamper_is_detected() {
    let salts = Salts::new(
        b"session-calib-salt".to_vec(),
        b"session-chain-salt".to_vec(),
        b"session-coord-salt".to_vec(),
    )
    .expect("salts satisfy minimum entropy");
    let profile = KdfProfile::preset(KdfPreset::Low);
    let (calibration, _) =
        calib_from_text(b"white-hat-org", "penetration-test").expect("calibration");

    let bootstrap_packet = encrypt_one_shot(EncryptParams {
        password: "penetration-password",
        password_salt: b"penetration-salt",
        calibration: &calibration,
        salts: &salts,
        plaintext: b"bootstrap payload",
        aad: b"bootstrap aad",
        profile,
        algorithm: AeadAlgorithm::Chacha20Poly1305,
        strict: false,
        kem: None,
    })
    .expect("bootstrap encryption succeeds");

    let bootstrap_encoded = bootstrap_packet
        .to_base64()
        .expect("bootstrap packet encodes to base64");
    let bootstrap_ok = decrypt_one_shot(&DecryptParams {
        password: "penetration-password",
        password_salt: b"penetration-salt",
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"bootstrap aad",
        strict: false,
        packet: &bootstrap_encoded,
    })
    .expect("bootstrap decrypts successfully");

    let metadata = bootstrap_ok.metadata;
    let mut sender = SessionRatchet::new([5_u8; 32], [7_u8; 16], false);
    let mut receiver = SessionRatchet::new([5_u8; 32], [7_u8; 16], false);

    let encrypt_params = SessionEncryptParams {
        ratchet: &mut sender,
        metadata: &metadata,
        plaintext: b"session secret",
        aad: b"session aad",
    };
    let (packet, _) = encrypt_session(encrypt_params).expect("session encryption produces packet");

    let mut tampered = packet.clone();
    let session_header = tampered
        .header
        .session
        .as_mut()
        .expect("session header is present");
    session_header.message_no += 1;
    let tampered_encoded = tampered
        .to_base64()
        .expect("tampered packet still encodes as base64");

    let mut store = SessionStore::new();
    let decrypt_params = SessionDecryptParams {
        ratchet: &mut receiver,
        metadata: &metadata,
        store: &mut store,
        aad: b"session aad",
        packet: &tampered_encoded,
    };
    let err =
        decrypt_session(decrypt_params).expect_err("tampered message number must be rejected");

    assert!(matches!(err, PacketError::Invalid(message) if message == "unexpected message number"));
}

#[test]
fn replayed_session_packet_is_rejected() {
    let salts = Salts::new(
        b"replay-calib-salt".to_vec(),
        b"replay-chain-salt".to_vec(),
        b"replay-coord-salt".to_vec(),
    )
    .expect("salts satisfy minimum entropy");
    let profile = KdfProfile::preset(KdfPreset::Low);
    let (calibration, _) =
        calib_from_text(b"white-hat-org", "penetration-test").expect("calibration");

    let bootstrap_packet = encrypt_one_shot(EncryptParams {
        password: "penetration-password",
        password_salt: b"penetration-salt",
        calibration: &calibration,
        salts: &salts,
        plaintext: b"bootstrap payload",
        aad: b"bootstrap aad",
        profile,
        algorithm: AeadAlgorithm::Chacha20Poly1305,
        strict: false,
        kem: None,
    })
    .expect("bootstrap encryption succeeds");

    let bootstrap_encoded = bootstrap_packet
        .to_base64()
        .expect("bootstrap packet encodes to base64");
    let bootstrap_ok = decrypt_one_shot(&DecryptParams {
        password: "penetration-password",
        password_salt: b"penetration-salt",
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"bootstrap aad",
        strict: false,
        packet: &bootstrap_encoded,
    })
    .expect("bootstrap decrypts successfully");

    let metadata = bootstrap_ok.metadata;
    let mut sender = SessionRatchet::new([5_u8; 32], [9_u8; 16], false);

    let encrypt_params = SessionEncryptParams {
        ratchet: &mut sender,
        metadata: &metadata,
        plaintext: b"session replay secret",
        aad: b"session aad",
    };
    let (packet, _) = encrypt_session(encrypt_params).expect("session encryption succeeds");
    let encoded_packet = packet
        .to_base64()
        .expect("session packet encodes to base64");

    let mut store = SessionStore::new();
    let mut receiver_first = SessionRatchet::new([5_u8; 32], [9_u8; 16], false);
    let decrypt_params_first = SessionDecryptParams {
        ratchet: &mut receiver_first,
        metadata: &metadata,
        store: &mut store,
        aad: b"session aad",
        packet: &encoded_packet,
    };

    let (ok, _) = decrypt_session(decrypt_params_first).expect("initial decrypt succeeds");
    assert_eq!(ok.plaintext.as_slice(), b"session replay secret");

    let mut receiver_replay = SessionRatchet::new([5_u8; 32], [9_u8; 16], false);
    let decrypt_params_replay = SessionDecryptParams {
        ratchet: &mut receiver_replay,
        metadata: &metadata,
        store: &mut store,
        aad: b"session aad",
        packet: &encoded_packet,
    };

    let err = decrypt_session(decrypt_params_replay)
        .expect_err("replayed packet must be rejected by session store");
    assert!(matches!(err, PacketError::Replay));
}
