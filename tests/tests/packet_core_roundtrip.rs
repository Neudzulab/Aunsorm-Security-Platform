//! Entegrasyon ve property testleri: çekirdek ve paket katmanının
//! birlikte çalışmasını doğrular.

use aunsorm_core::{
    calib_from_text, coord32_derive, derive_seed64_and_pdk, salts::Salts, KdfPreset, KdfProfile,
};
use aunsorm_packet::{
    decrypt_one_shot, encrypt_one_shot, AeadAlgorithm, DecryptParams, EncryptParams, PacketError,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use proptest::test_runner::{Config as ProptestConfig, TestCaseError};
use proptest::{char, prelude::*};
use sha2::{Digest, Sha256};

fn printable_string(min: usize, max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(char::range(' ', '~'), min..=max)
        .prop_map(|chars| chars.into_iter().collect())
}

fn bounded_bytes(min: usize, max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), min..=max)
}

fn salts_strategy() -> impl Strategy<Value = Salts> {
    (
        bounded_bytes(8, 32),
        bounded_bytes(8, 32),
        bounded_bytes(8, 32),
    )
        .prop_map(|(calibration, chain, coord)| {
            Salts::new(calibration, chain, coord).expect("salts meet minimum length")
        })
}

fn profile_strategy() -> impl Strategy<Value = KdfProfile> {
    let profiles = vec![
        KdfProfile::preset(KdfPreset::Mobile),
        KdfProfile::preset(KdfPreset::Low),
    ];
    prop::sample::select(profiles)
}

fn algorithm_strategy() -> impl Strategy<Value = AeadAlgorithm> {
    #[cfg(feature = "aes-siv")]
    let algorithms = {
        let mut variants = vec![AeadAlgorithm::AesGcm, AeadAlgorithm::Chacha20Poly1305];
        variants.push(AeadAlgorithm::AesSiv);
        variants
    };

    #[cfg(not(feature = "aes-siv"))]
    let algorithms = vec![AeadAlgorithm::AesGcm, AeadAlgorithm::Chacha20Poly1305];

    prop::sample::select(algorithms)
}

fn to_test_error<E: std::fmt::Display>(err: E, ctx: &str) -> TestCaseError {
    TestCaseError::fail(format!("{ctx}: {err}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]
    #[test]
    fn one_shot_roundtrip(
        password in printable_string(1, 32),
        password_salt in bounded_bytes(8, 32),
        org_salt in bounded_bytes(8, 32),
        note_text in printable_string(1, 48),
        plaintext in bounded_bytes(0, 256),
        aad in bounded_bytes(0, 64),
        profile in profile_strategy(),
        algorithm in algorithm_strategy(),
        salts in salts_strategy(),
    ) {
        let (calibration, _) =
            calib_from_text(&org_salt, &note_text).expect("calibration");
        let packet = encrypt_one_shot(EncryptParams {
            password: &password,
            password_salt: password_salt.as_slice(),
            calibration: &calibration,
            salts: &salts,
            plaintext: plaintext.as_slice(),
            aad: aad.as_slice(),
            profile,
            algorithm,
            strict: false,
            kem: None,
        }).map_err(|err| to_test_error(err, "encrypt"))?;

        let encoded = packet
            .to_base64()
            .map_err(|err| to_test_error(err, "encode"))?;
        let expected_header = packet.header.clone();
        let expected_packet_id = packet.packet_id().map_err(|err| to_test_error(err, "packet id"))?;
        let decrypted = decrypt_one_shot(&DecryptParams {
            password: &password,
            password_salt: password_salt.as_slice(),
            calibration: &calibration,
            salts: &salts,
            profile,
            aad: aad.as_slice(),
            strict: false,
            packet: &encoded,
        })
        .map_err(|err| to_test_error(err, "decrypt"))?;

        let (seed64, _, _) = derive_seed64_and_pdk(
            &password,
            password_salt.as_slice(),
            salts.calibration(),
            salts.chain(),
            profile,
        )
        .map_err(|err| to_test_error(err, "derive seed"))?;

        let (expected_coord_id, expected_coord) =
            coord32_derive(seed64.as_ref(), &calibration, &salts)
                .map_err(|err| to_test_error(err, "derive coord"))?;

        let mut digest_hasher = Sha256::new();
        digest_hasher.update(b"Aunsorm/1.01/coord-digest");
        digest_hasher.update(expected_coord);
        let expected_digest = STANDARD_NO_PAD.encode(digest_hasher.finalize());

        prop_assert_eq!(decrypted.plaintext.as_slice(), plaintext.as_slice());
        prop_assert_eq!(&decrypted.header, &expected_header);
        prop_assert_eq!(decrypted.header.aead.alg, algorithm);
        prop_assert_eq!(decrypted.header.sizes.plaintext, plaintext.len());
        prop_assert_eq!(
            decrypted.metadata.coord_id.as_deref(),
            Some(expected_coord_id.as_str())
        );
        prop_assert_eq!(decrypted.metadata.coord.as_ref(), Some(&expected_coord));
        prop_assert_eq!(decrypted.metadata.coord_digest, expected_digest);
        prop_assert_eq!(decrypted.packet_id, expected_packet_id);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]
    #[test]
    fn decrypt_rejects_wrong_calibration(
        password in printable_string(1, 16),
        password_salt in bounded_bytes(8, 24),
        org_salt in bounded_bytes(8, 24),
        note_text in printable_string(1, 24),
        tamper_suffix in printable_string(1, 8),
        plaintext in bounded_bytes(0, 128),
        aad in bounded_bytes(0, 32),
        profile in profile_strategy(),
        algorithm in algorithm_strategy(),
        salts in salts_strategy(),
    ) {
        let (calibration, _) =
            calib_from_text(&org_salt, &note_text).expect("calibration");
        let packet = encrypt_one_shot(EncryptParams {
            password: &password,
            password_salt: password_salt.as_slice(),
            calibration: &calibration,
            salts: &salts,
            plaintext: plaintext.as_slice(),
            aad: aad.as_slice(),
            profile,
            algorithm,
            strict: false,
            kem: None,
        }).map_err(|err| to_test_error(err, "encrypt"))?;

        let encoded = packet
            .to_base64()
            .map_err(|err| to_test_error(err, "encode"))?;

        let alt_text = format!("{note_text}-{tamper_suffix}");
        let (wrong_calibration, _) =
            calib_from_text(&org_salt, &alt_text).expect("calibration");
        let result = decrypt_one_shot(&DecryptParams {
            password: &password,
            password_salt: password_salt.as_slice(),
            calibration: &wrong_calibration,
            salts: &salts,
            profile,
            aad: aad.as_slice(),
            strict: false,
            packet: &encoded,
        });

        prop_assert!(matches!(
            result,
            Err(PacketError::Integrity(_)) | Err(PacketError::Invalid(_))
        ));
    }
}
