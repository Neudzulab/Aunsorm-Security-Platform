use aunsorm_core::{calibration::calib_from_text, coord32_derive, salts::Salts};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use proptest::{
    prelude::{prop, *},
    test_runner::Config as ProptestConfig,
};
use sha2::{Digest, Sha256};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn coord_digest_matches_seed_and_calibration(
        seed_bytes in prop::collection::vec(any::<u8>(), 64),
        org_salt in prop::collection::vec(any::<u8>(), 8..33),
        note_chars in prop::collection::vec(prop::char::range('\u{20}', '\u{7e}'), 1..33),
        calibration_salt in prop::collection::vec(any::<u8>(), 8..33),
        chain_salt in prop::collection::vec(any::<u8>(), 8..33),
        coord_salt in prop::collection::vec(any::<u8>(), 8..33),
    ) {
        let mut seed = [0_u8; 64];
        seed.copy_from_slice(&seed_bytes);

        let note_text: String = note_chars.into_iter().collect();
        prop_assume!(!note_text.trim().is_empty());
        let (calibration, _) =
            calib_from_text(&org_salt, &note_text).expect("calibration");
        let salts = Salts::new(calibration_salt, chain_salt, coord_salt).expect("valid salts");

        let (coord_id, coord) = coord32_derive(&seed, &calibration, &salts).expect("coord derivation");

        let mut digest_hasher = Sha256::new();
        digest_hasher.update(b"Aunsorm/1.01/coord-digest");
        digest_hasher.update(coord);
        let digest = digest_hasher.finalize();
        let expected = URL_SAFE_NO_PAD.encode(digest);

        prop_assert_eq!(coord_id, expected);
    }
}
