use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::json;

use crate::{
    Claims, Ed25519KeyPair, InMemoryJtiStore, JtiStore, JwtError, JwtSigner, JwtVerifier,
    VerificationOptions,
};

#[cfg(feature = "kms")]
use aunsorm_kms::{
    BackendKind, BackendLocator, BackupMetadata, EncryptedBackup, KeyDescriptor, KmsClient,
    KmsConfig,
};
#[cfg(feature = "kms")]
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
#[cfg(feature = "kms")]
use ed25519_dalek::{SigningKey, VerifyingKey};
#[cfg(feature = "kms")]
use sha2::{Digest, Sha256};
#[cfg(feature = "kms")]
use tempfile::NamedTempFile;
#[cfg(feature = "kms")]
use time::OffsetDateTime;

#[cfg(feature = "sqlite")]
use crate::SqliteJtiStore;

#[test]
fn sign_and_verify_roundtrip() {
    let mut rng = StdRng::seed_from_u64(42);
    let key = Ed25519KeyPair::generate_with_rng("kid-1", &mut rng).expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.issuer = Some("https://issuer".into());
    claims.subject = Some("user-1".into());
    claims.audience = Some(crate::Audience::Single("api".into()));
    claims.set_issued_now();
    claims.set_expiration_from_now(Duration::from_secs(600));
    claims.ensure_jwt_id();
    claims.extras.insert("role".into(), json!("admin"));

    let token = signer.sign(&mut claims).expect("jwt");

    let store = Arc::new(InMemoryJtiStore::default());
    let verifier =
        JwtVerifier::new([key.public_key()]).with_store(Arc::clone(&store) as Arc<dyn JtiStore>);
    let verified_claims = verifier
        .verify(&token, &VerificationOptions::default())
        .expect("verified");
    assert_eq!(verified_claims.subject, claims.subject);
    assert_eq!(verified_claims.extras.get("role"), Some(&json!("admin")));
}

#[test]
fn signer_generates_missing_jti() {
    let key = Ed25519KeyPair::generate("kid-auto").expect("key");
    let signer = JwtSigner::new(key);
    let mut claims = Claims::new();
    assert!(claims.jwt_id.is_none(), "jti must start empty");

    let token = signer.sign(&mut claims).expect("jwt");

    let jti = claims.jwt_id.as_ref().expect("signer populated jti");
    assert_eq!(jti.len(), 32, "jti should be 16-byte hex");
    assert!(jti.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(token.split('.').count(), 3, "token must be JWT format");
}

#[test]
fn signer_rejects_blank_jti() {
    let key = Ed25519KeyPair::generate("kid-blank").expect("key");
    let signer = JwtSigner::new(key);
    let mut claims = Claims::new();
    claims.jwt_id = Some("  \t".into());

    let err = signer
        .sign(&mut claims)
        .expect_err("blank jti must be rejected before signing");
    assert!(matches!(
        err,
        JwtError::InvalidClaim("jti", "must not be blank")
    ));
}

#[test]
fn signer_rejects_reserved_extra_claims() {
    let key = Ed25519KeyPair::generate("kid-extra-res").expect("key");
    let signer = JwtSigner::new(key);
    let mut claims = Claims::new();
    claims.extras.insert("iss".into(), json!("override"));

    let err = signer
        .sign(&mut claims)
        .expect_err("reserved claim must be rejected");
    assert!(matches!(
        err,
        JwtError::InvalidClaim("extras", "reserved claim name must not appear in extras")
    ));
}

#[test]
fn signer_rejects_non_camel_case_custom_claims() {
    let key = Ed25519KeyPair::generate("kid-extra-format").expect("key");
    let signer = JwtSigner::new(key);
    let mut claims = Claims::new();
    claims.extras.insert(
        "metadata".into(),
        json!({
            "codec": "vp9",
            "app_data": {"role": "host"}
        }),
    );

    let err = signer
        .sign(&mut claims)
        .expect_err("non-camelCase key must be rejected");
    assert!(matches!(
        err,
        JwtError::InvalidClaim("extras", "custom claim keys must be camelCase alphanumeric")
    ));
}

#[test]
fn verifier_rejects_invalid_custom_claims() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    let mut rng = StdRng::seed_from_u64(1337);
    let key = Ed25519KeyPair::generate_with_rng("kid-verify-extra", &mut rng).expect("key");

    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": key.kid(),
    });

    let mut claims = Claims::new();
    claims.ensure_jwt_id();
    claims
        .extras
        .insert("app_data".into(), json!({"role": "host"}));

    let header_encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
    let payload_encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims json"));
    let signing_input = format!("{header_encoded}.{payload_encoded}");
    let signature = key.signing_key().sign(signing_input.as_bytes()).to_bytes();
    let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));

    let store: Arc<dyn JtiStore> = Arc::new(InMemoryJtiStore::default());
    let verifier = JwtVerifier::new([key.public_key()]).with_store(store);
    let err = verifier
        .verify(&token, &VerificationOptions::default())
        .expect_err("invalid custom claims must be rejected");
    assert!(matches!(
        err,
        JwtError::InvalidClaim("extras", "custom claim keys must be camelCase alphanumeric")
    ));
}

#[test]
fn verifier_rejects_blank_jti() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    let mut rng = StdRng::seed_from_u64(4242);
    let key = Ed25519KeyPair::generate_with_rng("kid-blank-jti", &mut rng).expect("key");

    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": key.kid(),
    });

    let mut claims = Claims::new();
    claims.jwt_id = Some("   ".into());

    let header_encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
    let payload_encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims json"));
    let signing_input = format!("{header_encoded}.{payload_encoded}");
    let signature = key.signing_key().sign(signing_input.as_bytes()).to_bytes();
    let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));

    let store: Arc<dyn JtiStore> = Arc::new(InMemoryJtiStore::default());
    let verifier = JwtVerifier::new([key.public_key()]).with_store(store);
    let err = verifier
        .verify(&token, &VerificationOptions::default())
        .expect_err("blank jti must be rejected");
    assert!(matches!(
        err,
        JwtError::InvalidClaim("jti", "must not be blank")
    ));
}

#[test]
fn rejects_replay_in_memory_store() {
    let key = Ed25519KeyPair::generate("kid-replay").expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.set_expiration_from_now(Duration::from_secs(60));
    claims.ensure_jwt_id();
    let token = signer.sign(&mut claims).expect("jwt");
    let store = Arc::new(InMemoryJtiStore::default());
    let verifier = JwtVerifier::new([key.public_key()]).with_store(store.clone());
    verifier
        .verify(&token, &VerificationOptions::default())
        .expect("first ok");
    let err = verifier
        .verify(&token, &VerificationOptions::default())
        .expect_err("replay");
    assert!(matches!(err, JwtError::Replay));
    // purge expired entries should be no-op since token still valid
    let _ = store
        .purge_expired(SystemTime::now() + Duration::from_secs(3600))
        .expect("purge");
}

#[test]
fn purge_expired_allows_reuse_after_expiration() {
    let store = Arc::new(InMemoryJtiStore::default());

    let jti = "replay-id";
    let expires_soon = SystemTime::now() + Duration::from_millis(50);

    assert!(
        store
            .check_and_insert(jti, Some(expires_soon))
            .expect("first insert"),
        "initial insert must succeed"
    );

    assert!(
        !store
            .check_and_insert(jti, Some(expires_soon))
            .expect("second insert"),
        "duplicate insert before expiration must be rejected"
    );

    // Purging before expiration should leave the entry intact.
    assert_eq!(
        store
            .purge_expired(SystemTime::now())
            .expect("purge before expiration"),
        0,
        "entry should remain until it actually expires"
    );

    // Wait slightly past the expiration boundary and purge again.
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(
        store
            .purge_expired(SystemTime::now())
            .expect("purge after expiration"),
        1,
        "expired entry must be removed"
    );

    assert!(
        store
            .check_and_insert(jti, Some(SystemTime::now() + Duration::from_secs(1)))
            .expect("insert after purge"),
        "JTI should be reusable after purge removes expired entry"
    );
}

#[test]
fn audience_and_claim_validation() {
    let key = Ed25519KeyPair::generate("kid-claim").expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.issuer = Some("https://issuer".into());
    claims.subject = Some("user-123".into());
    claims.audience = Some(crate::Audience::Multiple(vec![
        "aud-a".into(),
        "aud-b".into(),
    ]));
    claims.set_expiration_from_now(Duration::from_secs(120));
    claims.ensure_jwt_id();
    let token = signer.sign(&mut claims).expect("jwt");
    let store: Arc<dyn JtiStore> = Arc::new(InMemoryJtiStore::default());
    let verifier = JwtVerifier::new([key.public_key()]).with_store(store);
    let options = VerificationOptions {
        issuer: Some("https://issuer".into()),
        subject: Some("user-123".into()),
        audience: Some("aud-b".into()),
        require_jti: true,
        ..VerificationOptions::default()
    };
    let verified_claims = verifier.verify(&token, &options).expect("valid token");
    assert_eq!(verified_claims.subject.as_deref(), Some("user-123"));

    let mut wrong = options;
    wrong.audience = Some("aud-x".into());
    let err = verifier
        .verify(&token, &wrong)
        .expect_err("audience mismatch");
    assert!(matches!(err, JwtError::ClaimMismatch("aud")));
}

#[test]
fn expired_token_is_rejected() {
    let key = Ed25519KeyPair::generate("kid-exp").expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.set_expiration_from_now(Duration::from_secs(1));
    claims.ensure_jwt_id();
    let token = signer.sign(&mut claims).expect("jwt");
    let store: Arc<dyn JtiStore> = Arc::new(InMemoryJtiStore::default());
    let verifier = JwtVerifier::new([key.public_key()])
        .with_store(store)
        .with_leeway(Duration::from_secs(0));
    std::thread::sleep(Duration::from_millis(1500));
    let err = verifier
        .verify(&token, &VerificationOptions::default())
        .expect_err("expired");
    assert!(matches!(err, JwtError::Expired));
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_store_roundtrip() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("jti.db");
    let store = Arc::new(SqliteJtiStore::open(&path).expect("store"));
    let key = Ed25519KeyPair::generate("kid-sqlite").expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.set_expiration_from_now(Duration::from_secs(120));
    claims.ensure_jwt_id();
    let token = signer.sign(&mut claims).expect("jwt");
    let verifier = JwtVerifier::new([key.public_key()]).with_store(store.clone());
    verifier
        .verify(&token, &VerificationOptions::default())
        .expect("verified");
    let err = verifier
        .verify(&token, &VerificationOptions::default())
        .expect_err("replay");
    assert!(matches!(err, JwtError::Replay));
    let _ = store
        .purge_expired(SystemTime::now() + Duration::from_secs(3600))
        .expect("purge");
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_store_creates_parent_directories() {
    let dir = tempfile::tempdir().expect("tmp");
    let nested = dir.path().join("nested").join("levels");
    let path = nested.join("jti.db");

    assert!(
        !nested.exists(),
        "parent directory should not exist before open"
    );

    {
        let store = SqliteJtiStore::open(&path).expect("store");
        drop(store);
    }

    assert!(nested.exists(), "parent directory must be created");
    assert!(path.exists(), "database file should be created");
}

#[cfg(feature = "kms")]
#[test]
fn kms_signer_roundtrip() {
    use std::io::Write;

    let mut file = NamedTempFile::new().expect("tmp");
    let signing_seed = [5u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifying = VerifyingKey::from(&signing_key);
    let kid = hex::encode(Sha256::digest(verifying.as_bytes()));
    let created_at = OffsetDateTime::from_unix_timestamp(1).expect("timestamp");
    let document = serde_json::json!({
        "version": 2,
        "keys": [{
            "id": "jwt-kms",
            "purpose": "ed25519-sign",
            "material": STANDARD.encode(signing_seed),
            "kid": kid,
            "public_key": STANDARD.encode(verifying.to_bytes()),
            "metadata": {
                "created_at": created_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .expect("format timestamp"),
            },
        }]
    });
    let plaintext = serde_json::to_vec(&document).expect("local json");
    let encryption_key = [11u8; 32];
    let metadata = BackupMetadata::new(
        OffsetDateTime::from_unix_timestamp(5).expect("metadata timestamp"),
        vec!["jwt-kms".to_string()],
        2,
    );
    let backup = EncryptedBackup::seal(&plaintext, &encryption_key, metadata).expect("seal");
    let bytes = backup.to_bytes().expect("serialise backup");
    file.write_all(&bytes).expect("write backup");
    file.flush().expect("flush");
    std::env::set_var(
        "AUNSORM_KMS_LOCAL_STORE_KEY",
        STANDARD.encode(encryption_key),
    );

    let config = KmsConfig::local_only(file.path()).expect("config");
    let client = KmsClient::from_config(config).expect("kms");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Local, "jwt-kms"));
    let signer = crate::KmsJwtSigner::new(&client, descriptor).expect("kms signer");
    let mut claims = Claims::new();
    claims.ensure_jwt_id();
    claims.set_expiration_from_now(Duration::from_secs(30));
    let token = signer.sign(&mut claims).expect("jwt");
    let verifying = signer.public_key().expect("public");
    let jwk = crate::Jwk {
        kid: signer.kid().to_string(),
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        alg: "EdDSA".into(),
        x: URL_SAFE_NO_PAD.encode(verifying.as_bytes()),
    };
    let public = crate::Ed25519PublicKey::from_jwk(&jwk).expect("public jwk");
    let store: Arc<dyn JtiStore> = Arc::new(InMemoryJtiStore::default());
    let verifier = JwtVerifier::new([public]).with_store(store);
    verifier
        .verify(&token, &VerificationOptions::default())
        .expect("verify");
}

#[test]
fn verify_requires_store_when_jti_enforced() {
    let key = Ed25519KeyPair::generate("kid-no-store").expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.set_expiration_from_now(Duration::from_secs(60));
    claims.ensure_jwt_id();
    let token = signer.sign(&mut claims).expect("jwt");
    let verifier = JwtVerifier::new([key.public_key()]);
    let err = verifier
        .verify(&token, &VerificationOptions::default())
        .expect_err("store required");
    assert!(matches!(err, JwtError::MissingJtiStore));
}
