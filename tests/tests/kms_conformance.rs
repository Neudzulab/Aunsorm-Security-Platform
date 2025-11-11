#![cfg(any(feature = "kms-gcp", feature = "kms-azure"))]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::thread;

use aunsorm_kms::{BackendKind, BackendLocator, KeyDescriptor, KmsClient, KmsConfig};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Method, Response, Server};

#[allow(dead_code)]
#[derive(Deserialize)]
struct Certificate {
    report_id: String,
    auditor: String,
    issued: String,
    expires: String,
    summary: String,
}

#[derive(Deserialize)]
struct KeyMaterial {
    private_key: String,
    public_key: String,
    kid: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct MessageCase {
    name: String,
    message: String,
    signature: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct Fixture {
    provider: String,
    key_id: String,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    certificate: Certificate,
    key_material: KeyMaterial,
    messages: Vec<MessageCase>,
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("data/kms")
        .join(name)
}

fn load_fixture(name: &str) -> Fixture {
    let path = fixture_path(name);
    let data = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read fixture {}: {err}", path.display());
    });
    serde_json::from_str(&data).unwrap_or_else(|err| {
        panic!("failed to parse fixture {}: {err}", path.display());
    })
}

fn decode_base64(value: &str) -> Vec<u8> {
    STANDARD
        .decode(value.as_bytes())
        .unwrap_or_else(|err| panic!("base64 decode failed: {err}"))
}

fn signing_from_fixture(fixture: &Fixture) -> SigningKey {
    let secret = decode_base64(&fixture.key_material.private_key);
    let seed: [u8; 32] = secret
        .try_into()
        .unwrap_or_else(|_| panic!("fixture {} private key must be 32 bytes", fixture.provider));
    SigningKey::from_bytes(&seed)
}

fn validate_key_material(fixture: &Fixture, signing: &SigningKey) -> VerifyingKey {
    let verifying = VerifyingKey::from(signing);
    let public = decode_base64(&fixture.key_material.public_key);
    assert_eq!(public, verifying.to_bytes());
    let expected_kid = format!("{:x}", Sha256::digest(verifying.as_bytes()));
    assert_eq!(expected_kid, fixture.key_material.kid);
    verifying
}

fn verify_signature_case(signing: &SigningKey, case: &MessageCase) -> (Vec<u8>, Vec<u8>) {
    let message = decode_base64(&case.message);
    let expected_signature = decode_base64(&case.signature);
    let produced = signing.sign(&message);
    assert_eq!(expected_signature, produced.to_bytes());
    (message, expected_signature)
}

fn config_from_env_json(var: &str, payload: Value) -> KmsConfig {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock");

    let json_text = serde_json::to_string(&payload).expect("serialize config json");
    let previous = std::env::var(var).ok();
    std::env::set_var(var, &json_text);
    let local_previous = std::env::var("AUNSORM_KMS_LOCAL_STORE").ok();
    std::env::remove_var("AUNSORM_KMS_LOCAL_STORE");

    let config = KmsConfig::from_env().expect("config from env");

    if let Some(value) = previous {
        std::env::set_var(var, value);
    } else {
        std::env::remove_var(var);
    }
    match local_previous {
        Some(value) => std::env::set_var("AUNSORM_KMS_LOCAL_STORE", value),
        None => std::env::remove_var("AUNSORM_KMS_LOCAL_STORE"),
    }

    drop(guard);
    config
}

#[cfg(feature = "kms-gcp")]
#[test]
fn gcp_conformance_fixture_roundtrip() {
    let fixture = load_fixture("gcp_ed25519_conformance.json");
    let signing = signing_from_fixture(&fixture);
    let verifying = validate_key_material(&fixture, &signing);
    let case = fixture
        .messages
        .first()
        .expect("fixture must contain at least one message");
    let (message, expected_signature) = verify_signature_case(&signing, case);

    let verifying_vec = verifying.to_bytes().to_vec();
    let verifying_for_thread = verifying_vec.clone();
    let kid_expected = fixture.key_material.kid.clone();
    let key_id = fixture.key_id.clone();
    let message_clone = message.clone();
    let expected_signature_clone = expected_signature.clone();
    let resource = fixture
        .resource
        .clone()
        .expect("gcp fixture must provide resource");

    let server = Server::http(("127.0.0.1", 0)).expect("server");
    let base_url = format!("http://{}", server.server_addr());
    let total = Arc::new(AtomicUsize::new(0));
    let total_thread = Arc::clone(&total);
    let resource_thread = resource.clone();
    let kid_thread = kid_expected.clone();
    let handle = thread::spawn(move || {
        let verifying_vec = verifying_for_thread;
        for mut request in server.incoming_requests() {
            let method = request.method().clone();
            let url = request.url().to_string();
            if method == Method::Get && url == format!("/v1/{}", resource_thread) {
                let body = json!({
                    "public_key": STANDARD.encode(&verifying_vec),
                    "kid": kid_thread.clone(),
                });
                let mut response = Response::from_string(body.to_string());
                response
                    .add_header(Header::from_bytes("content-type", "application/json").unwrap());
                request.respond(response).expect("respond");
            } else if method == Method::Post
                && url == format!("/v1/{}:signEd25519", resource_thread)
            {
                let mut buf = String::new();
                let mut reader = request.as_reader();
                std::io::Read::read_to_string(&mut reader, &mut buf).expect("read body");
                let payload: Value = serde_json::from_str(&buf).expect("parse payload");
                let received = payload
                    .get("message")
                    .and_then(|value| value.as_str())
                    .expect("message field");
                let decoded = decode_base64(received);
                assert_eq!(decoded, message_clone);
                let body = json!({
                    "signature": STANDARD.encode(&expected_signature_clone),
                    "public_key": STANDARD.encode(&verifying_vec),
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
            if total_thread.fetch_add(1, Ordering::SeqCst) + 1 >= 2 {
                break;
            }
        }
    });

    let config = config_from_env_json(
        "AUNSORM_KMS_GCP_CONFIG",
        json!({
            "base_url": base_url,
            "max_retries": 1,
            "retry_backoff_ms": 1,
            "keys": [{
                "key_id": key_id.clone(),
                "resource": resource.clone(),
            }],
        }),
    );

    let client = KmsClient::from_config(config).expect("kms client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Gcp, key_id.as_str()));

    let public = client.public_ed25519(&descriptor).expect("public key");
    assert_eq!(public, verifying_vec);

    let signature = client
        .sign_ed25519(&descriptor, &message)
        .expect("sign message");
    assert_eq!(signature, expected_signature);

    let verifying_key =
        VerifyingKey::from_bytes(&public.try_into().expect("public length")).unwrap();
    let signature_obj =
        Signature::from_bytes(&signature.as_slice().try_into().expect("signature length"));
    verifying_key
        .verify_strict(&message, &signature_obj)
        .expect("verify");

    let kid = client.key_kid(&descriptor).expect("kid");
    assert_eq!(kid, kid_expected);

    handle.join().expect("server thread");
}

#[cfg(feature = "kms-azure")]
#[test]
fn azure_conformance_fixture_roundtrip() {
    let fixture = load_fixture("azure_ed25519_conformance.json");
    let signing = signing_from_fixture(&fixture);
    let verifying = validate_key_material(&fixture, &signing);
    let case = fixture
        .messages
        .first()
        .expect("fixture must contain at least one message");
    let (message, expected_signature) = verify_signature_case(&signing, case);

    let verifying_vec = verifying.to_bytes().to_vec();
    let verifying_for_thread = verifying_vec.clone();
    let kid_expected = fixture.key_material.kid.clone();
    let key_id = fixture.key_id.clone();
    let resource = fixture
        .resource
        .clone()
        .expect("azure fixture must provide resource");
    let resource_sign = format!("{}/sign", resource);

    let message_clone = message.clone();
    let expected_signature_clone = expected_signature.clone();

    let server = Server::http(("127.0.0.1", 0)).expect("server");
    let base_url = format!("http://{}", server.server_addr());
    let total = Arc::new(AtomicUsize::new(0));
    let total_thread = Arc::clone(&total);
    let resource_thread = resource.clone();
    let resource_sign_thread = resource_sign.clone();
    let kid_thread = kid_expected.clone();
    let handle = thread::spawn(move || {
        let verifying_vec = verifying_for_thread;
        for mut request in server.incoming_requests() {
            let method = request.method().clone();
            let url = request.url().to_string();
            if method == Method::Get && url == format!("/{}", resource_thread) {
                let body = json!({
                    "public_key": STANDARD.encode(&verifying_vec),
                    "kid": kid_thread.clone(),
                });
                let mut response = Response::from_string(body.to_string());
                response
                    .add_header(Header::from_bytes("content-type", "application/json").unwrap());
                request.respond(response).expect("respond");
            } else if method == Method::Post && url == format!("/{}", resource_sign_thread) {
                let mut buf = String::new();
                let mut reader = request.as_reader();
                std::io::Read::read_to_string(&mut reader, &mut buf).expect("read body");
                let payload: Value = serde_json::from_str(&buf).expect("parse payload");
                assert_eq!(
                    payload.get("algorithm").and_then(Value::as_str),
                    Some("EdDSA")
                );
                let received = payload
                    .get("message")
                    .and_then(|value| value.as_str())
                    .expect("message field");
                let decoded = decode_base64(received);
                assert_eq!(decoded, message_clone);
                let body = json!({
                    "signature": STANDARD.encode(&expected_signature_clone),
                    "public_key": STANDARD.encode(&verifying_vec),
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
            if total_thread.fetch_add(1, Ordering::SeqCst) + 1 >= 2 {
                break;
            }
        }
    });

    let config = config_from_env_json(
        "AUNSORM_KMS_AZURE_CONFIG",
        json!({
            "base_url": base_url,
            "max_retries": 1,
            "retry_backoff_ms": 1,
            "keys": [{
                "key_id": key_id.clone(),
                "resource": resource.clone(),
            }],
        }),
    );

    let client = KmsClient::from_config(config).expect("kms client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Azure, key_id.as_str()));

    let public = client.public_ed25519(&descriptor).expect("public key");
    assert_eq!(public, verifying_vec);

    let signature = client
        .sign_ed25519(&descriptor, &message)
        .expect("sign message");
    assert_eq!(signature, expected_signature);

    let verifying_key =
        VerifyingKey::from_bytes(&public.try_into().expect("public length")).unwrap();
    let signature_obj =
        Signature::from_bytes(&signature.as_slice().try_into().expect("signature length"));
    verifying_key
        .verify_strict(&message, &signature_obj)
        .expect("verify");

    let kid = client.key_kid(&descriptor).expect("kid");
    assert_eq!(kid, kid_expected);

    handle.join().expect("server thread");
}

#[cfg(feature = "kms-pkcs11")]
#[test]
#[ignore = "PKCS11 requires HSM hardware or proper key wrapping"]
fn pkcs11_conformance_fixture_roundtrip() {
    let fixture = load_fixture("pkcs11_ed25519_conformance.json");
    let signing = signing_from_fixture(&fixture);
    let verifying = validate_key_material(&fixture, &signing);
    let case = fixture
        .messages
        .first()
        .expect("fixture must contain at least one message");
    let (message, expected_signature) = verify_signature_case(&signing, case);
    let key_id = fixture.key_id.clone();
    let private_key = fixture.key_material.private_key.clone();
    let public_key = fixture.key_material.public_key.clone();
    let kid_expected = fixture.key_material.kid.clone();

    let config = config_from_env_json(
        "AUNSORM_KMS_PKCS11_CONFIG",
        json!({
            "keys": [{
                "key_id": key_id.clone(),
                "private_key": private_key,
                "public_key": public_key,
                "kid": kid_expected.clone(),
            }],
        }),
    );

    let client = KmsClient::from_config(config).expect("kms client");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Pkcs11, key_id.as_str()));

    let public = client.public_ed25519(&descriptor).expect("public key");
    assert_eq!(public, verifying.to_bytes().to_vec());

    let signature = client
        .sign_ed25519(&descriptor, &message)
        .expect("sign message");
    assert_eq!(signature, expected_signature);

    let verifying_key =
        VerifyingKey::from_bytes(&public.try_into().expect("public length")).unwrap();
    let signature_obj =
        Signature::from_bytes(&signature.as_slice().try_into().expect("signature length"));
    verifying_key
        .verify_strict(&message, &signature_obj)
        .expect("verify");

    let kid = client.key_kid(&descriptor).expect("kid");
    assert_eq!(kid, kid_expected);
}
