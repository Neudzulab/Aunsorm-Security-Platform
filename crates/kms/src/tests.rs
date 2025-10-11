use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
#[cfg(any(feature = "kms-gcp", feature = "kms-azure"))]
use ed25519_dalek::Signer as _;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

#[cfg(any(feature = "kms-gcp", feature = "kms-azure", feature = "kms-pkcs11"))]
use serde::Deserialize;

#[cfg(feature = "kms-azure")]
use crate::{AzureBackendConfig, AzureKeyConfig};
use crate::{BackendKind, BackendLocator, KeyDescriptor, KmsClient, KmsConfig, LocalStoreConfig};
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

fn empty_config() -> KmsConfig {
    KmsConfig {
        strict: false,
        allow_fallback: true,
        local_store: None,
        #[cfg(feature = "kms-gcp")]
        gcp: None,
        #[cfg(feature = "kms-azure")]
        azure: None,
        #[cfg(feature = "kms-pkcs11")]
        pkcs11: None,
    }
}

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
    let mut config = empty_config();
    config.local_store = Some(LocalStoreConfig::new(file.path().to_path_buf()));
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Local, "jwt-sign"));
    assert_eq!(client.key_kid(&descriptor).unwrap(), expected_kid);
    file
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn read_fixture(path: &Path) -> serde_json::Value {
    let data = fs::read(path).expect("fixture read");
    serde_json::from_slice(&data).expect("fixture json")
}

#[cfg(feature = "kms-gcp")]
#[derive(Debug, Deserialize)]
struct RemoteFixture {
    provider: String,
    description: String,
    resource: String,
    public_endpoint: String,
    sign_endpoint: String,
    message_b64: String,
    message_hex: String,
    signature_b64: String,
    public_key_b64: String,
    private_seed_b64: String,
    kid: String,
    #[serde(default)]
    notes: Option<String>,
}

#[cfg(feature = "kms-gcp")]
fn load_remote_fixture(name: &str) -> RemoteFixture {
    let path = fixtures_dir().join(name);
    let value = read_fixture(&path);
    serde_json::from_value(value).expect("remote fixture")
}

#[cfg(feature = "kms-azure")]
#[derive(Debug, Deserialize)]
struct AzureFixture {
    provider: String,
    description: String,
    resource: String,
    public_endpoint: String,
    sign_endpoint: String,
    message_b64: String,
    message_hex: String,
    signature_b64: String,
    public_key_b64: String,
    private_seed_b64: String,
    kid: String,
    #[serde(default)]
    notes: Option<String>,
}

#[cfg(feature = "kms-azure")]
fn load_azure_fixture(name: &str) -> AzureFixture {
    let path = fixtures_dir().join(name);
    let value = read_fixture(&path);
    serde_json::from_value(value).expect("azure fixture")
}

#[cfg(feature = "kms-pkcs11")]
#[derive(Debug, Deserialize)]
struct Pkcs11Fixture {
    provider: String,
    description: String,
    key_id: String,
    slot_label: String,
    private_key_b64: String,
    public_key_b64: String,
    message_b64: String,
    message_hex: String,
    signature_b64: String,
    kid: String,
    #[serde(default)]
    notes: Option<String>,
}

#[cfg(feature = "kms-pkcs11")]
fn load_pkcs11_fixture(name: &str) -> Pkcs11Fixture {
    let path = fixtures_dir().join(name);
    let value = read_fixture(&path);
    serde_json::from_value(value).expect("pkcs11 fixture")
}

#[cfg(any(feature = "kms-gcp", feature = "kms-azure"))]
fn spawn_fixture_server(
    public_endpoint: String,
    sign_endpoint: String,
    verifying_bytes: &[u8],
    kid: &str,
    message: &[u8],
    expected_signature: &[u8],
    signing: SigningKey,
) -> (String, std::thread::JoinHandle<()>) {
    use serde_json::json;

    let server = Server::http(("127.0.0.1", 0)).expect("server");
    let base_url = format!("http://{}", server.server_addr());
    let verifying_thread = verifying_bytes.to_owned();
    let kid_thread = kid.to_string();
    let message_thread = message.to_owned();
    let expected_signature_thread = expected_signature.to_owned();
    let handle = thread::spawn(move || {
        let mut handled_requests = 0_u8;
        for mut request in server.incoming_requests() {
            let url = request.url().to_string();
            let method = request.method().clone();
            if method == Method::Get && url == public_endpoint {
                let body = json!({
                    "public_key": STANDARD.encode(&verifying_thread),
                    "kid": kid_thread.clone(),
                });
                let mut response = Response::from_string(body.to_string());
                response
                    .add_header(Header::from_bytes("content-type", "application/json").unwrap());
                request.respond(response).expect("respond");
            } else if method == Method::Post && url == sign_endpoint {
                let mut buf = String::new();
                let mut reader = request.as_reader();
                std::io::Read::read_to_string(&mut reader, &mut buf).expect("read body");
                let payload: serde_json::Value = serde_json::from_str(&buf).expect("json");
                let message_b64 = payload
                    .get("message")
                    .and_then(|value| value.as_str())
                    .expect("message field");
                let decoded = STANDARD
                    .decode(message_b64.as_bytes())
                    .expect("decode message");
                assert_eq!(decoded, message_thread);
                let signature = signing.sign(&decoded);
                assert_eq!(signature.to_bytes().as_slice(), expected_signature_thread);
                let body = json!({
                    "signature": STANDARD.encode(signature.to_bytes()),
                    "public_key": STANDARD.encode(&verifying_thread),
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
            handled_requests = handled_requests.saturating_add(1);
            if handled_requests >= 2 {
                break;
            }
        }
    });

    (base_url, handle)
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
    assert!(matches!(err, crate::KmsError::BackendNotConfigured { .. }));
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
fn gcp_remote_sign_and_public_with_retry() {
    use serde_json::json;

    let signing = SigningKey::from_bytes(&[5u8; 32]);
    let verifying = VerifyingKey::from(&signing);
    let verifying_bytes = verifying.to_bytes();
    let kid = hex::encode(Sha256::digest(verifying_bytes));
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

#[cfg(feature = "kms-gcp")]
#[test]
fn gcp_conformance_fixture_vectors() {
    let RemoteFixture {
        provider,
        description,
        resource,
        public_endpoint,
        sign_endpoint,
        message_b64,
        message_hex,
        signature_b64,
        public_key_b64,
        private_seed_b64,
        kid,
        notes,
    } = load_remote_fixture("gcp_conformance.json");

    assert_eq!(provider, "gcp");
    assert!(!description.trim().is_empty());
    if let Some(text) = notes.as_deref() {
        assert!(!text.trim().is_empty());
    }

    let seed_bytes = STANDARD
        .decode(private_seed_b64.as_bytes())
        .expect("seed decode");
    let seed: [u8; 32] = seed_bytes.as_slice().try_into().expect("seed length");
    let signing = SigningKey::from_bytes(&seed);
    let verifying = VerifyingKey::from(&signing);
    let verifying_bytes = verifying.to_bytes();
    assert_eq!(
        STANDARD.encode(verifying_bytes),
        public_key_b64,
        "fixture public key mismatch",
    );

    let message = STANDARD
        .decode(message_b64.as_bytes())
        .expect("message decode");
    assert_eq!(hex::encode(&message), message_hex);

    let expected_signature = STANDARD
        .decode(signature_b64.as_bytes())
        .expect("signature decode");

    let verifying_vec = verifying_bytes.to_vec();
    let (base_url, handle) = spawn_fixture_server(
        public_endpoint,
        sign_endpoint,
        &verifying_vec,
        &kid,
        &message,
        &expected_signature,
        signing,
    );

    let gcp_config = GcpBackendConfig {
        base_url,
        access_token: None,
        max_retries: 1,
        retry_backoff_ms: 1,
        keys: vec![GcpKeyConfig {
            key_id: "gcp-conformance".into(),
            resource: Some(resource),
            public_key: None,
            kid: None,
        }],
    };

    let mut config = empty_config();
    config.gcp = Some(gcp_config);
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Gcp, "gcp-conformance"));

    let public = client.public_ed25519(&descriptor).expect("public");
    assert_eq!(public, verifying_vec);

    let signature = client.sign_ed25519(&descriptor, &message).expect("sign");
    assert_eq!(signature, expected_signature);

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
    let expected_kid = hex::encode(Sha256::digest(verifying.as_bytes()));
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
    let kid = hex::encode(Sha256::digest(verifying_bytes));
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
fn azure_conformance_fixture_vectors() {
    let AzureFixture {
        provider,
        description,
        resource,
        public_endpoint,
        sign_endpoint,
        message_b64,
        message_hex,
        signature_b64,
        public_key_b64,
        private_seed_b64,
        kid,
        notes,
    } = load_azure_fixture("azure_conformance.json");

    assert_eq!(provider, "azure");
    assert!(!description.trim().is_empty());
    if let Some(text) = notes.as_deref() {
        assert!(!text.trim().is_empty());
    }

    let seed_bytes = STANDARD
        .decode(private_seed_b64.as_bytes())
        .expect("seed decode");
    let seed: [u8; 32] = seed_bytes.as_slice().try_into().expect("seed length");
    let signing = SigningKey::from_bytes(&seed);
    let verifying = VerifyingKey::from(&signing);
    let verifying_bytes = verifying.to_bytes();
    assert_eq!(
        STANDARD.encode(verifying_bytes),
        public_key_b64,
        "fixture public key mismatch",
    );

    let message = STANDARD
        .decode(message_b64.as_bytes())
        .expect("message decode");
    assert_eq!(hex::encode(&message), message_hex);

    let expected_signature = STANDARD
        .decode(signature_b64.as_bytes())
        .expect("signature decode");

    let verifying_vec = verifying_bytes.to_vec();
    let (base_url, handle) = spawn_fixture_server(
        public_endpoint,
        sign_endpoint,
        &verifying_vec,
        &kid,
        &message,
        &expected_signature,
        signing,
    );

    let azure_config = AzureBackendConfig {
        base_url,
        access_token: None,
        max_retries: 1,
        retry_backoff_ms: 1,
        keys: vec![AzureKeyConfig {
            key_id: "azure-conformance".into(),
            resource: Some(resource),
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
    let descriptor =
        KeyDescriptor::new(BackendLocator::new(BackendKind::Azure, "azure-conformance"));

    let public = client.public_ed25519(&descriptor).expect("public");
    assert_eq!(public, verifying_vec);

    let signature = client.sign_ed25519(&descriptor, &message).expect("sign");
    assert_eq!(signature, expected_signature);

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
fn pkcs11_conformance_fixture_vectors() {
    let Pkcs11Fixture {
        provider,
        description,
        key_id,
        slot_label,
        private_key_b64,
        public_key_b64,
        message_b64,
        message_hex,
        signature_b64,
        kid,
        notes,
    } = load_pkcs11_fixture("pkcs11_conformance.json");

    assert_eq!(provider, "pkcs11");
    assert!(!description.trim().is_empty());
    assert!(!slot_label.trim().is_empty());
    if let Some(text) = notes.as_deref() {
        assert!(!text.trim().is_empty());
    }

    let message = STANDARD
        .decode(message_b64.as_bytes())
        .expect("message decode");
    assert_eq!(hex::encode(&message), message_hex);

    let expected_signature = STANDARD
        .decode(signature_b64.as_bytes())
        .expect("signature decode");
    let expected_public = STANDARD
        .decode(public_key_b64.as_bytes())
        .expect("public decode");

    let pkcs11_config = Pkcs11BackendConfig {
        keys: vec![Pkcs11KeyConfig {
            key_id: key_id.clone(),
            private_key: private_key_b64,
            public_key: Some(public_key_b64),
            kid: Some(kid.clone()),
        }],
    };

    let mut config = empty_config();
    config.pkcs11 = Some(pkcs11_config);
    let client = KmsClient::from_config(config).expect("client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Pkcs11, key_id));

    let signature = client.sign_ed25519(&descriptor, &message).expect("sign");
    assert_eq!(signature, expected_signature);

    let public = client.public_ed25519(&descriptor).expect("public");
    assert_eq!(public, expected_public);

    let derived_kid = client.key_kid(&descriptor).expect("kid");
    assert_eq!(derived_kid, kid);
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
    let expected_kid = hex::encode(Sha256::digest(verifying.as_bytes()));
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
