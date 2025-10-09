//! Beyaz şapka saldırı senaryosu: başlıktaki AEAD algoritmasını aşağı seviyeye
//! düşürmeye çalışan saldırganın tespit edildiğini doğrular.

use aunsorm_core::{calib_from_text, Calibration, KdfPreset, KdfProfile, Salts};
use aunsorm_packet::{
    decrypt_one_shot, encrypt_one_shot, AeadAlgorithm, DecryptParams, EncryptParams, Packet,
    PacketError,
};

fn build_safe_packet() -> (String, Salts, Calibration, KdfProfile) {
    let salts = Salts::new(
        b"hacker-calib-salt".to_vec(),
        b"hacker-chain-salt".to_vec(),
        b"hacker-coord-salt".to_vec(),
    )
    .expect("salts satisfy minimum entropy");
    let profile = KdfProfile::preset(KdfPreset::Low);
    let (calibration, _) = calib_from_text(b"white-hat-org", "penetration-test");

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
