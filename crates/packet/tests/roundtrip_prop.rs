use aunsorm_core::{
    calibration::calib_from_text,
    kdf::{KdfPreset, KdfProfile},
    salts::Salts,
};
use aunsorm_packet::{
    decrypt_one_shot, encrypt_one_shot, AeadAlgorithm, DecryptOk, DecryptParams, EncryptParams,
    PacketError,
};
use proptest::{
    prelude::{prop, *},
    test_runner::Config as ProptestConfig,
};

fn algorithms() -> Vec<AeadAlgorithm> {
    #[cfg(feature = "aes-siv")]
    {
        vec![
            AeadAlgorithm::AesGcm,
            AeadAlgorithm::Chacha20Poly1305,
            AeadAlgorithm::AesSiv,
        ]
    }
    #[cfg(not(feature = "aes-siv"))]
    {
        vec![AeadAlgorithm::AesGcm, AeadAlgorithm::Chacha20Poly1305]
    }
}

fn build_salts(calibration_salt: Vec<u8>, chain_salt: Vec<u8>, coord_salt: Vec<u8>) -> Salts {
    Salts::new(calibration_salt, chain_salt, coord_salt).expect("valid salts")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]
    #[test]
    fn encrypt_decrypt_roundtrip(
        password_chars in prop::collection::vec(prop::char::range('\u{20}', '\u{7e}'), 8..24),
        org_salt in prop::collection::vec(any::<u8>(), 8..33),
        note_chars in prop::collection::vec(prop::char::range('\u{20}', '\u{7e}'), 1..33),
        password_salt in prop::collection::vec(any::<u8>(), 8..33),
        calibration_salt in prop::collection::vec(any::<u8>(), 8..33),
        chain_salt in prop::collection::vec(any::<u8>(), 8..33),
        coord_salt in prop::collection::vec(any::<u8>(), 8..33),
        aad in prop::collection::vec(any::<u8>(), 0..64),
        plaintext in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let password: String = password_chars.into_iter().collect();
        let note_text: String = note_chars.into_iter().collect();
        let (calibration, _) =
            calib_from_text(&org_salt, &note_text).expect("calibration");
        let salts = build_salts(calibration_salt.clone(), chain_salt.clone(), coord_salt.clone());
        let profile = KdfProfile::preset(KdfPreset::Low);

        for algorithm in algorithms() {
            let packet = encrypt_one_shot(EncryptParams {
                password: &password,
                password_salt: &password_salt,
                calibration: &calibration,
                salts: &salts,
                plaintext: &plaintext,
                aad: &aad,
                profile,
                algorithm,
                strict: false,
                kem: None,
            }).expect("encryption succeeds");

            let transcript = packet
                .transcript_hash(&aad)
                .expect("transcript hash");
            let encoded = packet.to_base64().expect("base64 encoding");
            let decrypt_params = DecryptParams {
                password: &password,
                password_salt: &password_salt,
                calibration: &calibration,
                salts: &salts,
                profile,
                aad: &aad,
                strict: false,
                packet: &encoded,
            };
            let decrypted = decrypt_one_shot(&decrypt_params).expect("decryption succeeds");
            let DecryptOk {
                plaintext: output,
                header,
                transcript: decoded_transcript,
                ..
            } = decrypted;
            let header_plaintext = header.sizes.plaintext;

            prop_assert_eq!(header_plaintext, output.len());
            prop_assert_eq!(output.as_slice(), plaintext.as_slice());
            prop_assert_eq!(decoded_transcript, transcript);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]
    #[test]
    fn decrypt_rejects_wrong_calibration(
        password_chars in prop::collection::vec(prop::char::range('\u{20}', '\u{7e}'), 8..24),
        org_salt in prop::collection::vec(any::<u8>(), 8..33),
        note_chars in prop::collection::vec(prop::char::range('\u{20}', '\u{7e}'), 1..33),
        wrong_note_chars in prop::collection::vec(prop::char::range('\u{20}', '\u{7e}'), 1..33),
        password_salt in prop::collection::vec(any::<u8>(), 8..33),
        calibration_salt in prop::collection::vec(any::<u8>(), 8..33),
        chain_salt in prop::collection::vec(any::<u8>(), 8..33),
        coord_salt in prop::collection::vec(any::<u8>(), 8..33),
        aad in prop::collection::vec(any::<u8>(), 0..64),
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let password: String = password_chars.into_iter().collect();
        let note_text: String = note_chars.into_iter().collect();
        let wrong_note: String = wrong_note_chars.into_iter().collect();
        prop_assume!(note_text != wrong_note);

        let (calibration, _) =
            calib_from_text(&org_salt, &note_text).expect("calibration");
        let salts = build_salts(calibration_salt.clone(), chain_salt.clone(), coord_salt.clone());
        let profile = KdfProfile::preset(KdfPreset::Low);

        for algorithm in algorithms() {
            let packet = encrypt_one_shot(EncryptParams {
                password: &password,
                password_salt: &password_salt,
                calibration: &calibration,
                salts: &salts,
                plaintext: &plaintext,
                aad: &aad,
                profile,
                algorithm,
                strict: false,
                kem: None,
            }).expect("encryption succeeds");

            let encoded = packet.to_base64().expect("base64 encoding");
            let (wrong_calibration, _) =
                calib_from_text(&org_salt, &wrong_note).expect("calibration");
            let decrypt_params = DecryptParams {
                password: &password,
                password_salt: &password_salt,
                calibration: &wrong_calibration,
                salts: &salts,
                profile,
                aad: &aad,
                strict: false,
                packet: &encoded,
            };
            let result = decrypt_one_shot(&decrypt_params);
            prop_assert!(matches!(result, Err(PacketError::Invalid(_))));
        }
    }
}
