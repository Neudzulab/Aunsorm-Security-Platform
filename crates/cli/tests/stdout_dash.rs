use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use predicates::prelude::*;
use serde_json::Value;
use sha2::Sha256;
use tempfile::NamedTempFile;

use aunsorm_core::{
    calib_from_text, coord32_derive, derive_seed64_and_pdk, salts::Salts, KdfPreset, KdfProfile,
};

fn derive_salts(org_salt: &[u8], calibration_id: &str) -> (Vec<u8>, Salts) {
    let hk = Hkdf::<Sha256>::new(Some(org_salt), calibration_id.as_bytes());
    let mut password_salt = vec![0_u8; 32];
    let mut calibration_salt = vec![0_u8; 32];
    let mut chain_salt = vec![0_u8; 32];
    let mut coord_salt = vec![0_u8; 32];

    hk.expand(b"Aunsorm/1.01/password-salt", &mut password_salt)
        .expect("password salt");
    hk.expand(b"Aunsorm/1.01/calibration-salt", &mut calibration_salt)
        .expect("calibration salt");
    hk.expand(b"Aunsorm/1.01/chain-salt", &mut chain_salt)
        .expect("chain salt");
    hk.expand(b"Aunsorm/1.01/coord-salt", &mut coord_salt)
        .expect("coord salt");

    let salts = Salts::new(calibration_salt, chain_salt, coord_salt).expect("salts");
    (password_salt, salts)
}

fn cli_command() -> Command {
    Command::cargo_bin("aunsorm-cli").expect("cli bin")
}

#[test]
fn calib_fingerprint_out_dash_json_streams_stdout() {
    let mut cmd = cli_command();
    cmd.args([
        "calib",
        "fingerprint",
        "--org-salt",
        "V2VBcmVLdXQuZXU=",
        "--calib-text",
        "Neudzulab | Prod | 2025-08",
        "--format",
        "json",
        "--out",
        "-",
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"calibration_id\""));
}

#[test]
fn calib_fingerprint_out_dash_text_streams_stdout() {
    let mut cmd = cli_command();
    cmd.args([
        "calib",
        "fingerprint",
        "--org-salt",
        "V2VBcmVLdXQuZXU=",
        "--calib-text",
        "Neudzulab | Prod | 2025-08",
        "--format",
        "text",
        "--out",
        "-",
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Kalibrasyon Kimliği"));
}

#[test]
fn calib_verify_out_dash_text_reports_success() {
    let org = STANDARD.decode("V2VBcmVLdXQuZXU=").expect("org salt");
    let (calibration, _) =
        calib_from_text(&org, "Neudzulab | Prod | 2025-08").expect("calibration");

    let expected_id = calibration.id.as_str().to_owned();
    let expected_b64 = calibration.fingerprint_b64();
    let expected_hex = calibration.fingerprint_hex();

    let mut cmd = cli_command();
    cmd.arg("calib")
        .arg("verify")
        .arg("--org-salt")
        .arg("V2VBcmVLdXQuZXU=")
        .arg("--calib-text")
        .arg("Neudzulab | Prod | 2025-08")
        .arg("--expect-id")
        .arg(&expected_id)
        .arg("--expect-fingerprint-b64")
        .arg(&expected_b64)
        .arg("--expect-fingerprint-hex")
        .arg(&expected_hex)
        .arg("--format")
        .arg("text")
        .arg("--out")
        .arg("-");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Kimlik Doğrulaması       : OK"))
        .stdout(predicate::str::contains("Base64 Doğrulaması       : OK"))
        .stdout(predicate::str::contains("Hex Doğrulaması          : OK"));
}

#[test]
fn calib_verify_out_dash_json_failure_sets_exit_code() {
    let mut cmd = cli_command();
    cmd.args([
        "calib",
        "verify",
        "--org-salt",
        "V2VBcmVLdXQuZXU=",
        "--calib-text",
        "Neudzulab | Prod | 2025-08",
        "--expect-id",
        "wrong-id",
        "--format",
        "json",
        "--out",
        "-",
    ]);

    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("\"id\": false"))
        .stderr(predicate::str::contains(
            "kalibrasyon doğrulaması başarısız",
        ));
}

#[test]
fn coord_raw_out_dash_writes_expected_bytes() {
    let report_out = NamedTempFile::new().expect("report out");
    let report_path: PathBuf = report_out.path().into();

    let mut cmd = cli_command();
    cmd.args([
        "calib",
        "derive-coord",
        "--password",
        "correct horse battery staple",
        "--org-salt",
        "V2VBcmVLdXQuZXU=",
        "--calib-text",
        "Neudzulab | Prod | 2025-08",
        "--kdf",
        "low",
        "--coord-raw-out",
        "-",
        "--out",
        report_path.to_str().expect("path"),
        "--format",
        "json",
    ]);

    let assert = cmd.assert().success();
    let stdout = assert.get_output().stdout.clone();
    assert_eq!(stdout.len(), 32);

    let org = STANDARD.decode("V2VBcmVLdXQuZXU=").expect("org salt");
    let (calibration, _) =
        calib_from_text(&org, "Neudzulab | Prod | 2025-08").expect("calibration");
    let (password_salt, salts) = derive_salts(&org, calibration.id.as_str());
    let (seed, _pdk, _info) = derive_seed64_and_pdk(
        "correct horse battery staple",
        password_salt.as_slice(),
        salts.calibration(),
        salts.chain(),
        KdfProfile::preset(KdfPreset::Low),
    )
    .expect("seed");
    let (_, expected_coord) = coord32_derive(seed.as_ref(), &calibration, &salts).expect("coord");

    assert_eq!(stdout, expected_coord);
}

#[test]
fn decrypt_metadata_out_dash_streams_stdout() {
    let plaintext = NamedTempFile::new().expect("plaintext");
    fs::write(plaintext.path(), b"sensitive-bytes").expect("write plaintext");

    let packet = NamedTempFile::new().expect("packet");
    let mut encrypt = cli_command();
    encrypt.args([
        "encrypt",
        "--password",
        "correct horse battery staple",
        "--in",
        plaintext.path().to_str().expect("plaintext path"),
        "--out",
        packet.path().to_str().expect("packet path"),
        "--org-salt",
        "V2VBcmVLdXQuZXU=",
        "--calib-text",
        "Neudzulab | Prod | 2025-08",
        "--kdf",
        "low",
    ]);
    encrypt.assert().success();

    let decrypted = NamedTempFile::new().expect("decrypted");
    let mut decrypt = cli_command();
    decrypt.args([
        "decrypt",
        "--password",
        "correct horse battery staple",
        "--in",
        packet.path().to_str().expect("packet path"),
        "--out",
        decrypted.path().to_str().expect("decrypted path"),
        "--org-salt",
        "V2VBcmVLdXQuZXU=",
        "--calib-text",
        "Neudzulab | Prod | 2025-08",
        "--kdf",
        "low",
        "--metadata-out",
        "-",
    ]);

    let assert = decrypt
        .assert()
        .success()
        .stdout(predicate::str::contains("\"metadata\""));
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout utf8");
    let json: Value = serde_json::from_str(&stdout).expect("metadata json");
    let metadata = json
        .get("metadata")
        .and_then(Value::as_object)
        .expect("metadata object");

    let org = STANDARD
        .decode("V2VBcmVLdXQuZXU=")
        .expect("org salt decode");
    let (calibration, _) =
        calib_from_text(&org, "Neudzulab | Prod | 2025-08").expect("calibration");
    assert_eq!(
        metadata.get("calib_id").and_then(Value::as_str),
        Some(calibration.id.as_str()),
    );

    let decrypted_bytes = fs::read(decrypted.path()).expect("decrypted bytes");
    assert_eq!(decrypted_bytes, b"sensitive-bytes");
}

#[test]
fn calib_verify_succeeds_with_matching_expectations() {
    let org = STANDARD
        .decode("V2VBcmVLdXQuZXU=")
        .expect("org salt decode");
    let (calibration, _) =
        calib_from_text(&org, "Neudzulab | Prod | 2025-08").expect("calibration");
    let expected_id = calibration.id.as_str().to_string();
    let expected_b64 = calibration.fingerprint_b64();
    let expected_hex = calibration.fingerprint_hex();

    let mut cmd = cli_command();
    cmd.arg("calib")
        .arg("verify")
        .arg("--org-salt")
        .arg("V2VBcmVLdXQuZXU=")
        .arg("--calib-text")
        .arg("Neudzulab | Prod | 2025-08")
        .arg("--expect-id")
        .arg(&expected_id)
        .arg("--expect-fingerprint-b64")
        .arg(&expected_b64)
        .arg("--expect-fingerprint-hex")
        .arg(&expected_hex)
        .arg("--format")
        .arg("text");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Kimlik Doğrulaması       : OK"))
        .stdout(predicate::str::contains("Base64 Doğrulaması       : OK"))
        .stdout(predicate::str::contains("Hex Doğrulaması          : OK"));
}

#[test]
fn calib_verify_reports_failure_when_expectations_do_not_match() {
    let mut cmd = cli_command();
    cmd.arg("calib")
        .arg("verify")
        .arg("--org-salt")
        .arg("V2VBcmVLdXQuZXU=")
        .arg("--calib-text")
        .arg("Neudzulab | Prod | 2025-08")
        .arg("--expect-id")
        .arg("AAAAAAAAAAAAAAAA")
        .arg("--format")
        .arg("text");

    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("Kimlik Doğrulaması       : HATA"))
        .stderr(predicate::str::contains(
            "kalibrasyon doğrulaması başarısız",
        ));
}
