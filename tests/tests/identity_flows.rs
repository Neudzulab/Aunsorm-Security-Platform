#![allow(clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aunsorm_core::calib_from_text;
use aunsorm_jwt::KmsJwtSigner;
use aunsorm_jwt::{
    Audience, Claims, Ed25519PublicKey, InMemoryJtiStore, JtiStore, Jwk, JwtError, JwtVerifier,
    VerificationOptions,
};
use aunsorm_kms::{
    BackendKind, BackendLocator, BackupMetadata, EncryptedBackup, KeyDescriptor, KmsClient,
    KmsConfig,
};
use aunsorm_x509::{generate_self_signed, SelfSignedCertParams, SubjectAltName};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pem::parse;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use time::OffsetDateTime;
use x509_parser::{
    extensions::ParsedExtension,
    prelude::{FromDer, X509Certificate},
};

#[derive(Debug, Deserialize)]
struct IdentityFlowFixture {
    flow_id: String,
    kms: KmsFixture,
    jwt: JwtFixture,
    x509: X509Fixture,
    expectations: FixtureExpectations,
}

#[derive(Debug, Deserialize)]
struct KmsFixture {
    signing_key_id: String,
    signing_seed_b64: String,
    wrap_key_id: String,
    wrap_seed_b64: String,
}

#[derive(Debug, Deserialize)]
struct JwtFixture {
    issuer: String,
    subject: String,
    audience: String,
    scope: Vec<String>,
    ttl_seconds: u64,
    extra_claims: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct X509Fixture {
    common_name: String,
    org_salt_b64: String,
    calibration_text: String,
    cps_uris: Vec<String>,
    policy_oids: Vec<String>,
    validity_days: u32,
    subject_alt_names: SubjectAltNameFixture,
}

#[derive(Debug, Deserialize)]
struct SubjectAltNameFixture {
    dns: Vec<String>,
    ips: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureExpectations {
    calibration_id: String,
    fingerprint_hex: String,
    kms_signing_kid: String,
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("data/identity")
        .join(name)
}

fn load_fixture(name: &str) -> IdentityFlowFixture {
    let path = fixture_path(name);
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("failed to parse fixture {}: {err}", path.display()))
}

fn decode_b64(value: &str) -> Vec<u8> {
    STANDARD
        .decode(value.as_bytes())
        .unwrap_or_else(|err| panic!("base64 decode error: {err}"))
}

fn build_subject_alt_names(fixture: &SubjectAltNameFixture) -> Vec<SubjectAltName> {
    let mut sans = Vec::new();
    for dns in &fixture.dns {
        if !dns.trim().is_empty() {
            sans.push(SubjectAltName::Dns(dns.clone()));
        }
    }
    for value in &fixture.ips {
        if !value.trim().is_empty() {
            let ip: IpAddr = value
                .parse()
                .unwrap_or_else(|err| panic!("invalid ip address {value}: {err}"));
            sans.push(SubjectAltName::Ip(ip));
        }
    }
    sans
}

struct LocalStoreHandle {
    file: NamedTempFile,
    key_b64: String,
}

impl LocalStoreHandle {
    fn path(&self) -> &std::path::Path {
        self.file.path()
    }

    fn install_env(&self) {
        std::env::set_var("AUNSORM_KMS_LOCAL_STORE_KEY", &self.key_b64);
    }
}

fn write_local_store(fixture: &KmsFixture) -> LocalStoreHandle {
    let mut file = NamedTempFile::new().expect("local store file");
    let signing_seed = decode_b64(&fixture.signing_seed_b64)
        .try_into()
        .unwrap_or_else(|_| {
            panic!(
                "signing seed must be 32 bytes for {}",
                fixture.signing_key_id
            )
        });
    let wrap_seed = decode_b64(&fixture.wrap_seed_b64)
        .try_into()
        .unwrap_or_else(|_| panic!("wrap seed must be 32 bytes for {}", fixture.wrap_key_id));
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifying = VerifyingKey::from(&signing_key);
    let created_at = OffsetDateTime::from_unix_timestamp(1).expect("timestamp");
    let document = serde_json::json!({
        "version": 2,
        "keys": [
            {
                "id": fixture.signing_key_id.clone(),
                "purpose": "ed25519-sign",
                "material": STANDARD.encode(signing_seed),
                "kid": hex::encode(Sha256::digest(verifying.as_bytes())),
                "public_key": STANDARD.encode(verifying.to_bytes()),
                "metadata": {
                    "created_at": created_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .expect("format timestamp"),
                },
            },
            {
                "id": fixture.wrap_key_id.clone(),
                "purpose": "aes256-wrap",
                "material": STANDARD.encode(wrap_seed),
            }
        ]
    });
    let plaintext = serde_json::to_vec(&document).expect("store json");
    let encryption_key = [21u8; 32];
    let metadata = BackupMetadata::new(
        OffsetDateTime::from_unix_timestamp(5).expect("metadata timestamp"),
        vec![fixture.signing_key_id.clone(), fixture.wrap_key_id.clone()],
        2,
    );
    let backup = EncryptedBackup::seal(&plaintext, &encryption_key, metadata).expect("seal");
    let bytes = backup.to_bytes().expect("serialise backup");
    file.write_all(&bytes).expect("write backup");
    file.flush().expect("flush local store");
    let key_b64 = STANDARD.encode(encryption_key);

    LocalStoreHandle { file, key_b64 }
}

fn import_extra_claims(claims: &mut Claims, extras: &Map<String, Value>) {
    let mut map = BTreeMap::new();
    for (key, value) in extras {
        map.insert(key.clone(), value.clone());
    }
    claims.extras = map;
}

#[test]
fn identity_flow_alpha_roundtrip() {
    let fixture = load_fixture("identity_flow_alpha.json");
    assert_eq!(fixture.flow_id, "alpha");

    // Prepare KMS local store and client.
    let local_store = write_local_store(&fixture.kms);
    local_store.install_env();
    let config = KmsConfig::local_only(local_store.path()).expect("kms config");
    let client = KmsClient::from_config(config).expect("kms client");

    let signing_locator =
        BackendLocator::new(BackendKind::Local, fixture.kms.signing_key_id.clone());
    let descriptor = KeyDescriptor::new(signing_locator.clone());
    let signer = KmsJwtSigner::new(&client, descriptor.clone()).expect("kms signer");

    let signing_seed = decode_b64(&fixture.kms.signing_seed_b64);
    let seed: [u8; 32] = signing_seed
        .try_into()
        .unwrap_or_else(|_| panic!("signing seed must be 32 bytes"));
    let signing = SigningKey::from_bytes(&seed);
    let offline_verifying = signing.verifying_key();
    let kms_verifying = signer.public_key().expect("public key");
    assert_eq!(offline_verifying.as_bytes(), kms_verifying.as_bytes());

    let expected_kid = hex::encode(Sha256::digest(offline_verifying.as_bytes()));
    assert_eq!(expected_kid, fixture.expectations.kms_signing_kid);
    let jwk = Jwk {
        kid: fixture.expectations.kms_signing_kid.clone(),
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        alg: "EdDSA".to_string(),
        x: URL_SAFE_NO_PAD.encode(offline_verifying.as_bytes()),
    };
    let offline_public = Ed25519PublicKey::from_jwk(&jwk).expect("offline public");
    let kid_from_client = client.key_kid(&descriptor).expect("kid from client");
    assert_eq!(kid_from_client, fixture.expectations.kms_signing_kid);

    let wrap_locator = BackendLocator::new(BackendKind::Local, fixture.kms.wrap_key_id.clone());
    let wrapped = client
        .wrap_key(&wrap_locator, b"symmetric-secret", b"aad-alpha")
        .expect("wrap key");
    let unwrapped = client
        .unwrap_key(&wrap_locator, &wrapped, b"aad-alpha")
        .expect("unwrap key");
    assert_eq!(unwrapped, b"symmetric-secret");

    // Build claims from fixture.
    let mut claims = Claims::new();
    claims.issuer = Some(fixture.jwt.issuer.clone());
    claims.subject = Some(fixture.jwt.subject.clone());
    claims.audience = Some(Audience::Single(fixture.jwt.audience.clone()));
    claims.set_issued_now();
    claims.set_expiration_from_now(Duration::from_secs(fixture.jwt.ttl_seconds));
    import_extra_claims(&mut claims, &fixture.jwt.extra_claims);
    claims.extras.insert(
        "scope".to_string(),
        Value::Array(
            fixture
                .jwt
                .scope
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );

    let token = signer.sign(&mut claims).expect("jwt token");

    let store = Arc::new(InMemoryJtiStore::default());
    let verifier = JwtVerifier::new([offline_public.clone()]).with_store(store.clone());
    let options = VerificationOptions {
        issuer: Some(fixture.jwt.issuer.clone()),
        subject: Some(fixture.jwt.subject.clone()),
        audience: Some(fixture.jwt.audience.clone()),
        require_jti: true,
        ..VerificationOptions::default()
    };
    let verified = verifier.verify(&token, &options).expect("verified token");
    assert_eq!(
        verified.subject.as_deref(),
        Some(fixture.jwt.subject.as_str())
    );
    assert_eq!(
        verified
            .extras
            .get("scope")
            .and_then(Value::as_array)
            .map(|values| values.iter().map(Value::as_str).collect::<Vec<_>>()),
        Some(vec![Some("packet:read"), Some("session:manage")])
    );
    let calibration_context = verified
        .extras
        .get("calibrationContext")
        .or_else(|| verified.extras.get("calibration_context"))
        .and_then(Value::as_str);
    assert_eq!(
        calibration_context,
        Some(fixture.x509.calibration_text.as_str())
    );

    let replay = verifier
        .verify(&token, &options)
        .expect_err("replay must fail");
    assert!(matches!(replay, JwtError::Replay));

    store
        .purge_expired(std::time::SystemTime::now() + Duration::from_secs(3600))
        .expect("purge store");

    // Verify calibration metadata and certificate extension.
    let org_salt = decode_b64(&fixture.x509.org_salt_b64);
    let (calibration, calibration_id) =
        calib_from_text(&org_salt, &fixture.x509.calibration_text).expect("calibration");
    assert_eq!(calibration_id.as_str(), fixture.expectations.calibration_id);
    assert_eq!(
        calibration.fingerprint_hex(),
        fixture.expectations.fingerprint_hex
    );

    let mut subject_alt_names = build_subject_alt_names(&fixture.x509.subject_alt_names);
    let params = SelfSignedCertParams {
        common_name: &fixture.x509.common_name,
        org_salt: &org_salt,
        calibration_text: &fixture.x509.calibration_text,
        cps_uris: &fixture.x509.cps_uris,
        policy_oids: &fixture.x509.policy_oids,
        validity_days: fixture.x509.validity_days,
        subject_alt_names: std::mem::take(&mut subject_alt_names),
    };
    let cert = generate_self_signed(&params).expect("self-signed cert");
    assert_eq!(cert.calibration_id, fixture.expectations.calibration_id);

    let der = parse(cert.certificate_pem)
        .expect("pem parse")
        .contents()
        .to_vec();
    let (_, parsed) = X509Certificate::from_der(&der).expect("parse cert");
    let calibration_ext = parsed
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string().starts_with("1.3.6.1.4.1.61012.1"))
        .expect("calibration extension");
    match calibration_ext.parsed_extension() {
        ParsedExtension::UnsupportedExtension { .. } | ParsedExtension::Unparsed => {
            let metadata: Value =
                serde_json::from_slice(calibration_ext.value).expect("calibration metadata json");
            assert_eq!(
                metadata["calibration_id"],
                fixture.expectations.calibration_id
            );
            assert_eq!(
                metadata["fingerprint_hex"],
                fixture.expectations.fingerprint_hex
            );
        }
        other => panic!("unexpected extension variant: {other:?}"),
    }
}
