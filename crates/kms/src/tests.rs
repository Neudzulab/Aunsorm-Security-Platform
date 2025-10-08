use std::io::Write;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::{BackendKind, BackendLocator, KeyDescriptor, KmsClient, KmsConfig};

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
    let config = KmsConfig::default().with_local_store(file.path().to_path_buf());
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Local, "jwt-sign"));
    assert_eq!(client.key_kid(&descriptor).unwrap(), expected_kid);
    file
}

#[cfg(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11"))]
fn write_remote_store(sign_id: &str, wrap_id: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("remote tempfile");
    let secret_b64 = STANDARD.encode([99u8; 32]);
    let wrap_key = STANDARD.encode([5u8; 32]);
    let json = serde_json::json!({
        "keys": [
            {
                "id": sign_id,
                "purpose": "ed25519-sign",
                "secret": secret_b64,
            },
            {
                "id": wrap_id,
                "purpose": "aes256-wrap",
                "secret": wrap_key,
            }
        ]
    });
    write!(file, "{}", serde_json::to_string_pretty(&json).unwrap()).expect("write remote");
    file.flush().expect("flush remote");
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
    assert!(matches!(
        err,
        crate::KmsError::BackendNotConfigured {
            backend: BackendKind::Gcp
        }
    ));
}

#[test]
fn fallback_when_primary_key_missing() {
    let store = write_local_store();
    let config = KmsConfig::local_only(store.path()).expect("config");
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Local, "missing"))
        .with_fallback(BackendLocator::new(BackendKind::Local, "jwt-sign"));
    let signature = client
        .sign_ed25519(&descriptor, b"fallback")
        .expect("fallback sign");
    assert_eq!(signature.len(), 64);
}

#[cfg(feature = "kms-gcp")]
#[test]
fn gcp_backend_end_to_end() {
    let sign_id = "projects/demo/locations/us/keyRings/main/cryptoKeys/jwt";
    let wrap_id = "projects/demo/locations/us/keyRings/main/cryptoKeys/wrap";
    let store = write_remote_store(sign_id, wrap_id);
    let config = KmsConfig::default().with_gcp_store(store.path().to_path_buf());
    let client = KmsClient::from_config(config).expect("gcp client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Gcp, sign_id));
    let message = b"remote";
    let signature = client.sign_ed25519(&descriptor, message).expect("gcp sign");
    assert_eq!(signature.len(), 64);
    let public = client.public_ed25519(&descriptor).expect("public");
    let verifying = VerifyingKey::from_bytes(&public.try_into().expect("len")).expect("verify");
    let sig_bytes: [u8; 64] = signature.as_slice().try_into().expect("sig");
    let sig = Signature::from_bytes(&sig_bytes);
    verifying.verify_strict(message, &sig).expect("valid");
    let kid = client.key_kid(&descriptor).expect("kid");
    let expected_kid = {
        let verifying = VerifyingKey::from(&SigningKey::from_bytes(&[99u8; 32]));
        hex::encode(Sha256::digest(verifying.as_bytes()))
    };
    assert_eq!(kid, expected_kid);

    let wrap_locator = BackendLocator::new(BackendKind::Gcp, wrap_id);
    let wrapped = client
        .wrap_key(&wrap_locator, b"payload", b"aad")
        .expect("wrap");
    let unwrapped = client
        .unwrap_key(&wrap_locator, &wrapped, b"aad")
        .expect("unwrap");
    assert_eq!(unwrapped, b"payload");
}

#[cfg(feature = "kms-azure")]
#[test]
fn azure_backend_end_to_end() {
    let sign_id = "vaults/demo/keys/jwt/1";
    let wrap_id = "vaults/demo/keys/wrap/1";
    let store = write_remote_store(sign_id, wrap_id);
    let config = KmsConfig::default().with_azure_store(store.path().to_path_buf());
    let client = KmsClient::from_config(config).expect("azure client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Azure, sign_id));
    let signature = client
        .sign_ed25519(&descriptor, b"azure")
        .expect("azure sign");
    assert_eq!(signature.len(), 64);
    let kid = client.key_kid(&descriptor).expect("kid");
    assert!(!kid.is_empty());
    let wrap_locator = BackendLocator::new(BackendKind::Azure, wrap_id);
    let wrapped = client
        .wrap_key(&wrap_locator, b"payload", b"aad")
        .expect("wrap");
    let unwrapped = client
        .unwrap_key(&wrap_locator, &wrapped, b"aad")
        .expect("unwrap");
    assert_eq!(unwrapped, b"payload");
}

#[cfg(feature = "kms-pkcs11")]
#[test]
fn pkcs11_backend_end_to_end() {
    let sign_id = "slot/1/token/jwt";
    let wrap_id = "slot/1/token/wrap";
    let store = write_remote_store(sign_id, wrap_id);
    let config = KmsConfig::default().with_pkcs11_store(store.path().to_path_buf());
    let client = KmsClient::from_config(config).expect("pkcs11 client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Pkcs11, sign_id));
    let signature = client
        .sign_ed25519(&descriptor, b"pkcs11")
        .expect("pkcs sign");
    assert_eq!(signature.len(), 64);
    let kid = client.key_kid(&descriptor).expect("kid");
    assert!(!kid.is_empty());
    let wrap_locator = BackendLocator::new(BackendKind::Pkcs11, wrap_id);
    let wrapped = client
        .wrap_key(&wrap_locator, b"payload", b"aad")
        .expect("wrap");
    let unwrapped = client
        .unwrap_key(&wrap_locator, &wrapped, b"aad")
        .expect("unwrap");
    assert_eq!(unwrapped, b"payload");
}
