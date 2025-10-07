use std::io::Write;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::{BackendKind, BackendLocator, KeyDescriptor, KmsClient, KmsConfig, LocalStoreConfig};

fn write_local_store() -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("tempfile");
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let secret_b64 = STANDARD.encode([42u8; 32]);
    let wrap_key = STANDARD.encode([7u8; 32]);
    let json = serde_json::json!({
        "keys": [
            {
                "id": "jwt-sign",
                "purpose": "ed25519-sign",
                "secret": secret_b64,
            },
            {
                "id": "wrap",
                "purpose": "aes256-wrap",
                "secret": wrap_key,
            }
        ]
    });
    write!(file, "{}", serde_json::to_string_pretty(&json).unwrap()).expect("write");
    file.flush().expect("flush");
    // ensure deterministic kid matches expectation
    let verifying = VerifyingKey::from(&signing_key);
    let expected_kid = hex::encode(Sha256::digest(verifying.as_bytes()));
    let config = KmsConfig {
        strict: false,
        allow_fallback: true,
        local_store: Some(LocalStoreConfig::new(file.path().to_path_buf())),
    };
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Local, "jwt-sign"));
    assert_eq!(client.key_kid(&descriptor).unwrap(), expected_kid);
    file
}

#[test]
fn local_sign_roundtrip() {
    let store = write_local_store();
    let config = KmsConfig::local_only(store.path()).expect("config");
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Local, "jwt-sign"));
    let message = b"aunsorm";
    let signature = client.sign_ed25519(&descriptor, message).expect("sign");
    assert_eq!(signature.len(), 64);
    let public = client.public_ed25519(&descriptor).expect("public");
    let verifying = VerifyingKey::from_bytes(&public.try_into().expect("len")).expect("verify");
    let sig_bytes: [u8; 64] = signature.as_slice().try_into().expect("sig");
    let sig = Signature::from_bytes(&sig_bytes);
    verifying.verify_strict(message, &sig).expect("valid");
}

#[test]
fn wrap_and_unwrap_roundtrip() {
    let store = write_local_store();
    let config = KmsConfig::local_only(store.path()).expect("config");
    let client = KmsClient::from_config(config).expect("client");
    let locator = BackendLocator::new(BackendKind::Local, "wrap");
    let plaintext = b"top-secret";
    let wrapped = client.wrap_key(&locator, plaintext, b"aad").expect("wrap");
    assert!(wrapped.len() > plaintext.len());
    let unwrapped = client
        .unwrap_key(&locator, &wrapped, b"aad")
        .expect("unwrap");
    assert_eq!(unwrapped, plaintext);
}

#[test]
fn fallback_respects_strict_mode() {
    let store = write_local_store();
    let config = KmsConfig::local_only(store.path()).expect("config");
    let client = KmsClient::from_config(config.clone()).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Gcp, "projects/demo"))
        .with_fallback(BackendLocator::new(BackendKind::Local, "jwt-sign"));
    let message = b"ratchet";
    // fallback succeeds when strict kapalı ve fallback açık
    let signature = client
        .sign_ed25519(&descriptor, message)
        .expect("fallback sign");
    assert_eq!(signature.len(), 64);

    // strict kip fallback'ı reddeder
    let strict_client = KmsClient::from_config(config.clone().with_strict(true)).expect("strict");
    let err = strict_client
        .sign_ed25519(&descriptor, message)
        .unwrap_err();
    assert!(matches!(err, crate::KmsError::StrictFallback { .. }));

    // fallback kapatıldığında ilk hata döner
    let no_fallback_client =
        KmsClient::from_config(config.with_fallback(false)).expect("nofallback");
    let err = no_fallback_client
        .sign_ed25519(&descriptor, message)
        .unwrap_err();
    assert!(matches!(err, crate::KmsError::Unsupported { .. }));
}
