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
use aunsorm_kms::{BackendKind, BackendLocator, KeyDescriptor, KmsClient, KmsConfig};
#[cfg(feature = "kms")]
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
#[cfg(feature = "kms")]
use tempfile::NamedTempFile;

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
    claims.extra.insert("role".into(), json!("admin"));

    let token = signer.sign(&claims).expect("jwt");

    let store = Arc::new(InMemoryJtiStore::default());
    let verifier =
        JwtVerifier::new([key.public_key()]).with_store(Arc::clone(&store) as Arc<dyn JtiStore>);
    let verified_claims = verifier
        .verify(&token, &VerificationOptions::default())
        .expect("verified");
    assert_eq!(verified_claims.subject, claims.subject);
    assert_eq!(verified_claims.extra.get("role"), Some(&json!("admin")));
}

#[test]
fn rejects_replay_in_memory_store() {
    let key = Ed25519KeyPair::generate("kid-replay").expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.set_expiration_from_now(Duration::from_secs(60));
    claims.ensure_jwt_id();
    let token = signer.sign(&claims).expect("jwt");
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
    let token = signer.sign(&claims).expect("jwt");
    let verifier = JwtVerifier::new([key.public_key()]);
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
    let token = signer.sign(&claims).expect("jwt");
    let verifier = JwtVerifier::new([key.public_key()]).with_leeway(Duration::from_secs(0));
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
    let token = signer.sign(&claims).expect("jwt");
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

#[cfg(feature = "kms")]
#[test]
fn kms_signer_roundtrip() {
    use std::io::Write;

    let mut file = NamedTempFile::new().expect("tmp");
    let json = serde_json::json!({
        "keys": [{
            "id": "jwt-kms",
            "purpose": "ed25519-sign",
            "secret": STANDARD.encode([5u8; 32]),
        }]
    });
    write!(file, "{}", serde_json::to_string(&json).unwrap()).expect("write");
    file.flush().expect("flush");

    let config = KmsConfig::local_only(file.path()).expect("config");
    let client = KmsClient::from_config(config).expect("kms");
    let descriptor = KeyDescriptor::new(BackendLocator::new(BackendKind::Local, "jwt-kms"));
    let signer = crate::KmsJwtSigner::new(&client, descriptor).expect("kms signer");
    let mut claims = Claims::new();
    claims.ensure_jwt_id();
    claims.set_expiration_from_now(Duration::from_secs(30));
    let token = signer.sign(&claims).expect("jwt");
    let verifying = signer.public_key().expect("public");
    let jwk = crate::Jwk {
        kid: signer.kid().to_string(),
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        alg: "EdDSA".into(),
        x: URL_SAFE_NO_PAD.encode(verifying.as_bytes()),
    };
    let public = crate::Ed25519PublicKey::from_jwk(&jwk).expect("public jwk");
    let verifier = JwtVerifier::new([public]);
    verifier
        .verify(&token, &VerificationOptions::default())
        .expect("verify");
}
