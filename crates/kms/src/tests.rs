use std::io::Write;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
#[cfg(any(feature = "kms-gcp", feature = "kms-azure"))]
use ed25519_dalek::Signer as _;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use tempfile::NamedTempFile;
use time::OffsetDateTime;

use crate::local::LocalBackend;
use crate::util::compute_kid;
#[cfg(feature = "kms-azure")]
use crate::{AzureBackendConfig, AzureKeyConfig};
use crate::{BackendKind, BackendLocator, KeyDescriptor, KmsClient, KmsConfig};
use crate::{BackupMetadata, EncryptedBackup};
#[cfg(feature = "kms-gcp")]
use crate::{GcpBackendConfig, GcpKeyConfig};
#[cfg(feature = "kms-pkcs11")]
use crate::{Pkcs11BackendConfig, Pkcs11KeyConfig};
#[cfg(any(feature = "kms-gcp", feature = "kms-azure"))]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
#[cfg(any(feature = "kms-gcp", feature = "kms-azure"))]
use std::thread;
#[cfg(any(feature = "kms-gcp", feature = "kms-azure"))]
use tiny_http::{Header, Method, Response, Server};

#[cfg(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11"))]
fn empty_config() -> KmsConfig {
    KmsConfig {
        strict: false,
        allow_fallback: false,
        local_store: None,
        #[cfg(feature = "kms-gcp")]
        gcp: None,
        #[cfg(feature = "kms-azure")]
        azure: None,
        #[cfg(feature = "kms-pkcs11")]
        pkcs11: None,
    }
}

struct LocalStoreFixture {
    file: NamedTempFile,
    key_b64: String,
    expected_kid: String,
}

impl LocalStoreFixture {
    fn path(&self) -> &Path {
        self.file.path()
    }

    fn install_env(&self) {
        std::env::set_var("AUNSORM_KMS_LOCAL_STORE_KEY", &self.key_b64);
    }
}

fn write_local_store() -> LocalStoreFixture {
    let mut file = NamedTempFile::new().expect("tempfile");
    let signing_seed = [42u8; 32];
    let wrap_seed = [7u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifying = VerifyingKey::from(&signing_key);
    let expected_kid = compute_kid(&verifying.to_bytes());
    let created_at = OffsetDateTime::from_unix_timestamp(1).expect("timestamp");
    let document = serde_json::json!({
        "version": 2,
        "keys": [
            {
                "id": "jwt-sign",
                "purpose": "ed25519-sign",
                "material": STANDARD.encode(signing_seed),
                "kid": expected_kid,
                "public_key": STANDARD.encode(verifying.to_bytes()),
                "metadata": {
                    "created_at": created_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .expect("format timestamp"),
                },
            },
            {
                "id": "wrap",
                "purpose": "aes256-wrap",
                "material": STANDARD.encode(wrap_seed),
            }
        ]
    });
    let plaintext = serde_json::to_vec(&document).expect("local json");
    let encryption_key = [9u8; 32];
    let metadata = BackupMetadata::new(
        OffsetDateTime::from_unix_timestamp(10).expect("metadata timestamp"),
        vec!["jwt-sign".to_string(), "wrap".to_string()],
        2,
    );
    let backup = EncryptedBackup::seal(&plaintext, &encryption_key, metadata).expect("seal");
    let bytes = backup.to_bytes().expect("serialise backup");
    file.write_all(&bytes).expect("write backup");
    file.flush().expect("flush backup");
    let key_b64 = STANDARD.encode(encryption_key);

    let backend = LocalBackend::from_encrypted_bytes(&bytes, &encryption_key).expect("backend");
    let _ = backend.store_version();
    let _ = backend.key_kids("jwt-sign").expect("key ids");
    let _ = backend
        .rotation_policy("jwt-sign")
        .expect("rotation policy");
    let _ = backend.create_backup(&encryption_key).expect("backup");

    LocalStoreFixture {
        file,
        key_b64,
        expected_kid,
    }
}

#[test]
fn local_sign_roundtrip() {
    let store = write_local_store();
    store.install_env();
    let config = KmsConfig::local_only(store.path()).expect("config");
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Local, "jwt-sign"));
    assert_eq!(
        client.key_kid(&descriptor).expect("kid"),
        store.expected_kid
    );
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
    store.install_env();
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
    store.install_env();
    let base_config = KmsConfig::local_only(store.path()).expect("config");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Gcp, "projects/demo"))
        .with_fallback(BackendLocator::new(BackendKind::Local, "jwt-sign"));
    let message = b"ratchet";

    // Varsayılan yapılandırmada fallback devre dışıdır.
    let default_client = KmsClient::from_config(base_config.clone()).expect("client");
    let err = default_client
        .sign_ed25519(&descriptor, message)
        .unwrap_err();
    assert!(matches!(err, crate::KmsError::BackendNotConfigured { .. }));

    // Fallback yalnızca açıkça etkinleştirildiğinde başarılı olur.
    let fallback_config = base_config.with_fallback(true);
    let fallback_client = KmsClient::from_config(fallback_config.clone()).expect("client");
    let signature = fallback_client
        .sign_ed25519(&descriptor, message)
        .expect("fallback sign");
    assert_eq!(signature.len(), 64);

    // strict kip fallback'ı reddeder
    let strict_client =
        KmsClient::from_config(fallback_config.clone().with_strict(true)).expect("strict");
    let err = strict_client
        .sign_ed25519(&descriptor, message)
        .unwrap_err();
    assert!(matches!(err, crate::KmsError::StrictFallback { .. }));

    // fallback kapatıldığında ilk hata döner
    let no_fallback_client =
        KmsClient::from_config(fallback_config.with_fallback(false)).expect("nofallback");
    let err = no_fallback_client
        .sign_ed25519(&descriptor, message)
        .unwrap_err();
    assert!(matches!(err, crate::KmsError::BackendNotConfigured { .. }));
}

#[test]
fn fallback_when_primary_key_missing() {
    let store = write_local_store();
    store.install_env();
    let config = KmsConfig::local_only(store.path())
        .expect("config")
        .with_fallback(true);
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
fn gcp_remote_sign_and_public_with_retry() {
    use serde_json::json;

    let signing = SigningKey::from_bytes(&[5u8; 32]);
    let verifying = VerifyingKey::from(&signing);
    let verifying_bytes = verifying.to_bytes();
    let verifying_array: [u8; 32] = verifying_bytes
        .as_slice()
        .try_into()
        .expect("verifying len");
    let kid = compute_kid(&verifying_array);
    let server = Server::http(("127.0.0.1", 0)).expect("server");
    let base_url = format!("http://{}", server.server_addr());
    let get_attempts = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));
    let get_attempts_thread = Arc::clone(&get_attempts);
    let total_thread = Arc::clone(&total);
    let verifying_vec = verifying_bytes.to_vec();
    let verifying_vec_thread = verifying_vec.clone();
    let kid_thread = kid.clone();
    let signing_thread = signing;
    let handle = thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let url = request.url().to_string();
            let method = request.method().clone();
            if method == Method::Get
                && url
                    == "/v1/projects/demo/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
            {
                let attempt = get_attempts_thread.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    let response = Response::from_string("temporary error").with_status_code(500);
                    request.respond(response).expect("respond");
                } else {
                    let body = json!({
                        "public_key": STANDARD.encode(&verifying_vec_thread),
                        "kid": kid_thread.clone(),
                    });
                    let mut response = Response::from_string(body.to_string());
                    response
                        .add_header(Header::from_bytes("content-type", "application/json").unwrap());
                    request.respond(response).expect("respond");
                }
            } else if method == Method::Post
                && url
                    == "/v1/projects/demo/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1:signEd25519"
            {
                let mut buf = String::new();
                let mut reader = request.as_reader();
                std::io::Read::read_to_string(&mut reader, &mut buf).expect("read body");
                let payload: serde_json::Value = serde_json::from_str(&buf).expect("json");
                let message_b64 = payload
                    .get("message")
                    .and_then(|value| value.as_str())
                    .expect("message field");
                let message = STANDARD.decode(message_b64.as_bytes()).expect("decode message");
                let signature = signing_thread.sign(&message);
                let body = json!({
                    "signature": STANDARD.encode(signature.to_bytes()),
                    "public_key": STANDARD.encode(&verifying_vec_thread),
                    "kid": kid_thread.clone(),
                });
                let mut response = Response::from_string(body.to_string());
                response
                    .add_header(Header::from_bytes("content-type", "application/json").unwrap());
                request.respond(response).expect("respond");
            } else {
                let response = Response::from_string("not found").with_status_code(404);
                request.respond(response).expect("respond");
            }
            let served_requests = total_thread.fetch_add(1, Ordering::SeqCst) + 1;
            if served_requests >= 3 {
                break;
            }
        }
    });

    let resource =
        "projects/demo/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1";
    let gcp_config = GcpBackendConfig {
        base_url,
        access_token: None,
        max_retries: 2,
        retry_backoff_ms: 1,
        keys: vec![GcpKeyConfig {
            key_id: "gcp-key".into(),
            resource: Some(resource.into()),
            public_key: None,
            kid: None,
        }],
    };

    let mut config = empty_config();
    config.gcp = Some(gcp_config);
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Gcp, "gcp-key"));

    let public = client.public_ed25519(&descriptor).expect("public");
    assert_eq!(public, verifying_vec);

    let signature = client.sign_ed25519(&descriptor, b"payload").expect("sign");
    assert_eq!(signature.len(), 64);

    let kid_value = client.key_kid(&descriptor).expect("kid");
    assert_eq!(kid_value, kid);

    handle.join().expect("join");
}

#[cfg(feature = "kms-azure")]
#[test]
fn azure_local_fallback_uses_private_key() {
    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let verifying = VerifyingKey::from(&signing);
    let private_b64 = STANDARD.encode([9u8; 32]);

    let azure_config = AzureBackendConfig {
        base_url: "https://example.com".into(),
        access_token: None,
        max_retries: 1,
        retry_backoff_ms: 1,
        keys: vec![AzureKeyConfig {
            key_id: "azure-local".into(),
            resource: Some("keys/local/1".into()),
            key_name: None,
            key_version: None,
            public_key: None,
            kid: None,
            local_private_key: Some(private_b64),
        }],
    };

    let mut config = empty_config();
    config.azure = Some(azure_config);
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Azure, "azure-local"));

    let signature = client.sign_ed25519(&descriptor, b"payload").expect("sign");
    assert_eq!(signature.len(), 64);

    let public = client.public_ed25519(&descriptor).expect("public");
    assert_eq!(public, verifying.to_bytes().to_vec());

    let kid_value = client.key_kid(&descriptor).expect("kid");
    let expected_kid = compute_kid(verifying.as_bytes());
    assert_eq!(kid_value, expected_kid);
}

#[cfg(feature = "kms-azure")]
#[test]
fn azure_missing_public_strict_fails() {
    let private_b64 = STANDARD.encode([11u8; 32]);
    let azure_config = AzureBackendConfig {
        base_url: "https://example.com".into(),
        access_token: None,
        max_retries: 1,
        retry_backoff_ms: 1,
        keys: vec![AzureKeyConfig {
            key_id: "azure-strict".into(),
            resource: Some("keys/strict/1".into()),
            key_name: None,
            key_version: None,
            public_key: None,
            kid: None,
            local_private_key: Some(private_b64),
        }],
    };

    let mut config = empty_config();
    config.strict = true;
    config.azure = Some(azure_config);
    let err = KmsClient::from_config(config)
        .err()
        .expect("config should fail");
    assert!(matches!(err, crate::KmsError::Config(_)));
}

#[cfg(feature = "kms-azure")]
#[test]
fn azure_remote_sign_and_public() {
    use serde_json::json;

    let signing = SigningKey::from_bytes(&[13u8; 32]);
    let verifying = VerifyingKey::from(&signing);
    let verifying_bytes = verifying.to_bytes();
    let verifying_array: [u8; 32] = verifying_bytes
        .as_slice()
        .try_into()
        .expect("verifying len");
    let kid = compute_kid(&verifying_array);
    let server = Server::http(("127.0.0.1", 0)).expect("server");
    let base_url = format!("http://{}", server.server_addr());
    let total = Arc::new(AtomicUsize::new(0));
    let total_thread = Arc::clone(&total);
    let verifying_vec = verifying_bytes.to_vec();
    let verifying_vec_thread = verifying_vec.clone();
    let kid_thread = kid.clone();
    let signing_thread = signing;
    let handle = thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let url = request.url().to_string();
            let method = request.method().clone();
            if method == Method::Get && url == "/keys/demo/123" {
                let body = json!({
                    "public_key": STANDARD.encode(&verifying_vec_thread),
                    "kid": kid_thread.clone(),
                });
                let mut response = Response::from_string(body.to_string());
                response
                    .add_header(Header::from_bytes("content-type", "application/json").unwrap());
                request.respond(response).expect("respond");
            } else if method == Method::Post && url == "/keys/demo/123/sign" {
                let mut buf = String::new();
                let mut reader = request.as_reader();
                std::io::Read::read_to_string(&mut reader, &mut buf).expect("read body");
                let payload: serde_json::Value = serde_json::from_str(&buf).expect("json");
                let message_b64 = payload
                    .get("message")
                    .and_then(|value| value.as_str())
                    .expect("message field");
                let message = STANDARD
                    .decode(message_b64.as_bytes())
                    .expect("decode message");
                let signature = signing_thread.sign(&message);
                let body = json!({
                    "signature": STANDARD.encode(signature.to_bytes()),
                    "public_key": STANDARD.encode(&verifying_vec_thread),
                    "kid": kid_thread.clone(),
                });
                let mut response = Response::from_string(body.to_string());
                response
                    .add_header(Header::from_bytes("content-type", "application/json").unwrap());
                request.respond(response).expect("respond");
            } else {
                let response = Response::from_string("not found").with_status_code(404);
                request.respond(response).expect("respond");
            }
            let served_requests = total_thread.fetch_add(1, Ordering::SeqCst) + 1;
            if served_requests >= 2 {
                break;
            }
        }
    });

    let azure_config = AzureBackendConfig {
        base_url,
        access_token: None,
        max_retries: 1,
        retry_backoff_ms: 1,
        keys: vec![AzureKeyConfig {
            key_id: "azure-remote".into(),
            resource: Some("keys/demo/123".into()),
            key_name: None,
            key_version: None,
            public_key: None,
            kid: None,
            local_private_key: None,
        }],
    };

    let mut config = empty_config();
    config.azure = Some(azure_config);
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Azure, "azure-remote"));

    let public = client.public_ed25519(&descriptor).expect("public");
    assert_eq!(public, verifying_vec);

    let signature = client.sign_ed25519(&descriptor, b"payload").expect("sign");
    assert_eq!(signature.len(), 64);

    let kid_value = client.key_kid(&descriptor).expect("kid");
    assert_eq!(kid_value, kid);

    handle.join().expect("join");
}

#[cfg(feature = "kms-azure")]
#[test]
fn azure_duplicate_identifier_rejected() {
    let secret = STANDARD.encode([0xAAu8; 32]);
    let azure_config = AzureBackendConfig {
        base_url: "https://example.com".into(),
        access_token: None,
        max_retries: 1,
        retry_backoff_ms: 1,
        keys: vec![
            AzureKeyConfig {
                key_id: "dup".into(),
                resource: Some("keys/dup/1".into()),
                key_name: None,
                key_version: None,
                public_key: None,
                kid: None,
                local_private_key: Some(secret.clone()),
            },
            AzureKeyConfig {
                key_id: " dup ".into(),
                resource: Some("keys/dup/2".into()),
                key_name: None,
                key_version: None,
                public_key: None,
                kid: None,
                local_private_key: Some(secret),
            },
        ],
    };

    let mut config = empty_config();
    config.azure = Some(azure_config);
    let Err(err) = KmsClient::from_config(config) else {
        panic!("config should fail");
    };
    match err {
        crate::KmsError::Config(message) => {
            assert!(message.contains("duplicate azure key identifier"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[cfg(feature = "kms-gcp")]
#[test]
fn gcp_resource_validation_rejected() {
    let gcp_config = GcpBackendConfig {
        base_url: "https://gcp.example".into(),
        access_token: None,
        max_retries: 1,
        retry_backoff_ms: 1,
        keys: vec![GcpKeyConfig {
            key_id: "dup".into(),
            resource: Some("///".into()),
            public_key: None,
            kid: None,
        }],
    };

    let mut config = empty_config();
    config.gcp = Some(gcp_config);
    let Err(err) = KmsClient::from_config(config) else {
        panic!("config should fail");
    };
    match err {
        crate::KmsError::Config(message) => {
            assert!(message.contains("cannot be empty") || message.contains("resource"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[cfg(feature = "kms-pkcs11")]
#[test]
fn pkcs11_sign_and_public_roundtrip() {
    let signing = SigningKey::from_bytes(&[21u8; 32]);
    let verifying = VerifyingKey::from(&signing);
    let private_b64 = STANDARD.encode([21u8; 32]);
    let public_b64 = STANDARD.encode(verifying.to_bytes());

    let pkcs11_config = Pkcs11BackendConfig {
        keys: vec![Pkcs11KeyConfig {
            key_id: "pkcs-key".into(),
            private_key: private_b64,
            public_key: Some(public_b64),
            kid: None,
        }],
    };

    let mut config = empty_config();
    config.pkcs11 = Some(pkcs11_config);
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Pkcs11, "pkcs-key"));

    let signature = client.sign_ed25519(&descriptor, b"payload").expect("sign");
    assert_eq!(signature.len(), 64);

    let public = client.public_ed25519(&descriptor).expect("public");
    assert_eq!(public, verifying.to_bytes().to_vec());

    let kid_value = client.key_kid(&descriptor).expect("kid");
    let expected_kid = compute_kid(verifying.as_bytes());
    assert_eq!(kid_value, expected_kid);
}

#[cfg(feature = "kms-pkcs11")]
#[test]
fn pkcs11_requires_public_in_strict_mode() {
    let private_b64 = STANDARD.encode([31u8; 32]);
    let pkcs11_config = Pkcs11BackendConfig {
        keys: vec![Pkcs11KeyConfig {
            key_id: "pkcs-strict".into(),
            private_key: private_b64,
            public_key: None,
            kid: None,
        }],
    };

    let mut config = empty_config();
    config.strict = true;
    config.pkcs11 = Some(pkcs11_config);
    let err = KmsClient::from_config(config)
        .err()
        .expect("config should fail");
    assert!(matches!(err, crate::KmsError::Config(_)));
}
